"""Session management service with caching and failover support."""

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.cache import get_cache
from app.core.circuit_breaker import circuit_breaker
from app.core.errors import AuthenticationError, NotFoundError
from app.models.session import Session
from app.models.user import User
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository

logger = get_logger(__name__)


class SessionService:
    """Service for managing user sessions with caching."""

    # Cache key prefixes
    CACHE_PREFIX = "session"
    USER_SESSIONS_PREFIX = "user_sessions"

    # Default session duration
    DEFAULT_SESSION_DURATION = timedelta(hours=24)
    DEFAULT_REMEMBER_ME_DURATION = timedelta(days=30)

    def __init__(self, db_session: AsyncSession):
        """Initialize session service."""
        self.db_session = db_session
        self.session_repo = SessionRepository(db_session)
        self.user_repo = UserRepository(db_session)

    async def create_session(
        self,
        user: User,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        remember_me: bool = False,
        device_info: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """
        Create a new session for a user.

        Args:
            user: User to create session for
            user_agent: Client user agent
            ip_address: Client IP address
            remember_me: Whether to extend session duration
            device_info: Additional device information

        Returns:
            Created session
        """
        # Generate session token
        session_token = secrets.token_urlsafe(32)

        # Set expiration
        duration = self.DEFAULT_REMEMBER_ME_DURATION if remember_me else self.DEFAULT_SESSION_DURATION
        expires_at = datetime.now(timezone.utc) + duration

        # Create session using repository interface method
        session = await self.session_repo.create_session(
            user_id=str(user.id),
            token=session_token,
            expires_at=expires_at.isoformat(),
            ip_address=ip_address,
            user_agent=user_agent,  # This will be mapped to device_info in the repository
        )

        # Cache session data
        await self._cache_session(session, user)

        # Add to user's active sessions cache
        await self._add_to_user_sessions(user.id, session.id)

        logger.info(
            "Session created",
            user_id=str(user.id),
            session_id=str(session.id),
            remember_me=remember_me,
        )

        return session

    @circuit_breaker(
        name="session_validation",
        failure_threshold=10,
        recovery_timeout=30,
    )
    async def validate_session(
        self,
        session_token: str,
        update_last_activity: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate session token and return session data.

        Args:
            session_token: Session token to validate
            update_last_activity: Whether to update last activity

        Returns:
            Session data if valid, None otherwise
        """
        # Try cache first
        cache = await get_cache()
        cache_key = self._get_cache_key(session_token)
        cached_data = await cache.get(cache_key)

        if cached_data:
            # Validate expiration
            expires_at = datetime.fromisoformat(cached_data["expires_at"])
            if expires_at > datetime.now(timezone.utc):
                if update_last_activity:
                    # Update last activity asynchronously
                    await self._update_last_activity(cached_data["session_id"])
                return cached_data
            else:
                # Session expired, remove from cache
                await cache.delete(cache_key)
                await self._remove_from_user_sessions(cached_data["user_id"], cached_data["session_id"])
                return None

        # Cache miss, check database using repository
        session = await self.session_repo.get_by_token(session_token)

        if not session:
            return None

        # Check expiration
        if session.expires_at <= datetime.now(timezone.utc):
            await self.session_repo.update(session.id, is_active=False)
            return None

        # Get user data using repository
        user = await self.user_repo.get_by_id(session.user_id)
        if not user or not user.is_active:
            await self.session_repo.update(session.id, is_active=False)
            return None

        # Update last activity using repository
        if update_last_activity:
            await self.session_repo.update(session.id, last_activity_at=datetime.now(timezone.utc))

        # Cache session data
        await self._cache_session(session, user)

        return self._build_session_data(session, user)

    async def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidate a session.

        Args:
            session_token: Session token to invalidate

        Returns:
            True if session was invalidated
        """
        # Remove from cache first
        cache = await get_cache()
        cache_key = self._get_cache_key(session_token)
        cached_data = await cache.get(cache_key)

        if cached_data:
            await cache.delete(cache_key)
            await self._remove_from_user_sessions(cached_data["user_id"], cached_data["session_id"])

        # Update database using repository
        session = await self.session_repo.get_by_token(session_token)

        if session:
            await self.session_repo.update(session.id, is_active=False, revoked_at=datetime.now(timezone.utc))

            logger.info(
                "Session invalidated",
                session_id=str(session.id),
                user_id=str(session.user_id),
            )
            return True

        return False

    async def invalidate_user_sessions(
        self,
        user_id: str,
        except_session_id: Optional[str] = None,
    ) -> int:
        """
        Invalidate all sessions for a user.

        Args:
            user_id: User ID
            except_session_id: Session ID to keep active

        Returns:
            Number of sessions invalidated
        """
        # Get user's sessions from cache
        cache = await get_cache()
        sessions_key = f"{self.USER_SESSIONS_PREFIX}:{user_id}"
        session_ids = await cache.get(sessions_key, default=[])

        # Clear cache entries
        count = 0
        for session_id in session_ids:
            if session_id != except_session_id:
                # Get session using repository to clear cache
                session = await self.session_repo.get_by_id(session_id)

                if session:
                    cache_key = self._get_cache_key(session.session_token)
                    await cache.delete(cache_key)
                    count += 1

        # Clear user sessions cache
        await cache.delete(sessions_key)

        # Update database using repository
        sessions = await self.session_repo.get_user_sessions(user_id, include_inactive=False)

        if except_session_id:
            sessions = [s for s in sessions if str(s.id) != except_session_id]

        for session in sessions:
            await self.session_repo.update(session.id, is_active=False, revoked_at=datetime.now(timezone.utc))

        logger.info(
            "User sessions invalidated",
            user_id=user_id,
            count=len(sessions),
        )

        return len(sessions)

    async def get_active_sessions(self, user_id: str) -> list[Dict[str, Any]]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active sessions
        """
        # Try cache first
        cache = await get_cache()
        sessions_key = f"{self.USER_SESSIONS_PREFIX}:{user_id}"
        session_ids = await cache.get(sessions_key, default=[])

        if session_ids:
            # Get session details from cache
            sessions = []
            for session_id in session_ids:
                # Need to get session token to fetch from cache
                session = await self.session_repo.get_by_id(session_id)
                if session and not session.is_active:
                    session = None

                if session:
                    cache_key = self._get_cache_key(session.session_token)
                    session_data = await cache.get(cache_key)
                    if session_data:
                        sessions.append(session_data)

            if sessions:
                return sessions

        # Cache miss or incomplete, query database using repository
        sessions = await self.session_repo.get_user_sessions(user_id, include_inactive=False)

        # Filter out expired sessions
        now = datetime.now(timezone.utc)
        sessions = [s for s in sessions if s.expires_at > now]

        # Get user for building session data using repository
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            return []

        # Build session data and update cache
        session_data_list = []
        active_session_ids = []

        for session in sessions:
            session_data = self._build_session_data(session, user)
            session_data_list.append(session_data)
            active_session_ids.append(str(session.id))

            # Cache individual session
            await self._cache_session(session, user)

        # Update user sessions cache
        if active_session_ids:
            await cache.set(sessions_key, active_session_ids, ttl=3600)

        return session_data_list

    async def extend_session(
        self,
        session_token: str,
        duration: Optional[timedelta] = None,
    ) -> bool:
        """
        Extend session expiration.

        Args:
            session_token: Session token
            duration: Extension duration (default: 24 hours)

        Returns:
            True if extended successfully
        """
        if duration is None:
            duration = self.DEFAULT_SESSION_DURATION

        # Get session using repository
        session = await self.session_repo.get_by_token(session_token)

        if not session or not session.is_active:
            return False

        # Extend expiration using repository
        new_expires_at = datetime.now(timezone.utc) + duration
        await self.session_repo.update(
            session.id,
            expires_at=new_expires_at,
            last_activity_at=datetime.now(timezone.utc),
        )

        # Update cache
        user = await self.user_repo.get_by_id(session.user_id)
        if user:
            # Refresh session object with updated data
            session.expires_at = new_expires_at
            await self._cache_session(session, user)

        logger.info(
            "Session extended",
            session_id=str(session.id),
            new_expiration=new_expires_at.isoformat(),
        )

        return True

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        # Use repository method for cleanup
        expired_count = await self.session_repo.cleanup_expired_sessions()

        if expired_count > 0:
            logger.info("Expired sessions cleaned up", count=expired_count)

        return expired_count

    # Private helper methods

    def _get_cache_key(self, session_token: str) -> str:
        """Get cache key for session."""
        return f"{self.CACHE_PREFIX}:{session_token}"

    def _build_session_data(self, session: Session, user: User) -> Dict[str, Any]:
        """Build session data dictionary."""
        return {
            "session_id": str(session.id),
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": user.roles or [],
            "is_superuser": user.is_superuser,
            "organization_id": (str(user.organization_id) if user.organization_id else None),
            "expires_at": session.expires_at.isoformat(),
            "created_at": session.created_at.isoformat(),
            "last_activity_at": (session.last_activity_at.isoformat() if session.last_activity_at else None),
            "ip_address": session.ip_address,
            "user_agent": session.device_info,
        }

    async def _cache_session(self, session: Session, user: User) -> None:
        """Cache session data."""
        cache = await get_cache()
        cache_key = self._get_cache_key(session.session_token)
        session_data = self._build_session_data(session, user)

        # Calculate TTL based on expiration
        ttl = int((session.expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl > 0:
            await cache.set(cache_key, session_data, ttl=ttl)

    async def _add_to_user_sessions(self, user_id: str, session_id: str) -> None:
        """Add session to user's active sessions cache."""
        cache = await get_cache()
        sessions_key = f"{self.USER_SESSIONS_PREFIX}:{user_id}"

        session_ids = await cache.get(sessions_key, default=[])
        if str(session_id) not in session_ids:
            session_ids.append(str(session_id))
            await cache.set(sessions_key, session_ids, ttl=86400)  # 24 hours

    async def _remove_from_user_sessions(self, user_id: str, session_id: str) -> None:
        """Remove session from user's active sessions cache."""
        cache = await get_cache()
        sessions_key = f"{self.USER_SESSIONS_PREFIX}:{user_id}"

        session_ids = await cache.get(sessions_key, default=[])
        if str(session_id) in session_ids:
            session_ids.remove(str(session_id))
            if session_ids:
                await cache.set(sessions_key, session_ids, ttl=86400)
            else:
                await cache.delete(sessions_key)

    async def _update_last_activity(self, session_id: str) -> None:
        """Update session last activity timestamp."""
        try:
            await self.session_repo.update(session_id, last_activity_at=datetime.now(timezone.utc))
        except Exception as e:
            logger.error("Failed to update last activity", session_id=session_id, error=str(e))

    async def _get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID using repository."""
        return await self.user_repo.get_by_id(user_id)
