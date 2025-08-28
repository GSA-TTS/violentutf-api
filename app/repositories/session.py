"""Session repository with authentication and session management methods."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ..models.session import Session
from .base import BaseRepository
from .interfaces.session import ISessionRepository

logger = get_logger(__name__)


class SessionRepository(BaseRepository[Session], ISessionRepository):
    """
    Session repository with authentication and session management.

    Extends base repository with session-specific functionality
    for managing user authentication sessions.
    """

    def __init__(self, session: AsyncSession):
        """Initialize session repository."""
        super().__init__(session, Session)

    async def get_by_session_token(self, session_token: str) -> Optional[Session]:
        """
        Get session by token hash.

        Args:
            session_token: Session token (hashed)

        Returns:
            Session if found and valid, None otherwise
        """
        try:
            query = select(self.model).where(
                and_(self.model.session_token == session_token, self.model.is_deleted == False)  # noqa: E712
            )

            result = await self.session.execute(query)
            session_obj = result.scalar_one_or_none()

            if session_obj:
                # Check if session is still valid
                if not session_obj.is_valid():
                    self.logger.debug(
                        "Session found but invalid",
                        session_id=str(session_obj.id),
                        is_active=session_obj.is_active,
                        is_expired=session_obj.is_expired(),
                        revoked_at=session_obj.revoked_at,
                    )
                    return None

                self.logger.debug("Valid session found", session_id=str(session_obj.id))
            else:
                self.logger.debug("Session not found", token_prefix=session_token[:8] + "...")

            return session_obj

        except Exception as e:
            self.logger.error("Failed to get session by token", token_prefix=session_token[:8] + "...", error=str(e))
            raise

    async def get_user_sessions(self, user_id: uuid.UUID, include_inactive: bool = False) -> List[Session]:
        """
        Get all sessions for a user.

        Args:
            user_id: User ID
            include_inactive: Whether to include inactive/expired sessions

        Returns:
            List of user sessions
        """
        try:
            query = select(self.model).where(
                and_(self.model.user_id == user_id, self.model.is_deleted == False)  # noqa: E712
            )

            # Filter to active sessions only if requested
            if not include_inactive:
                query = query.where(
                    and_(
                        self.model.is_active == True,  # noqa: E712
                        self.model.expires_at > datetime.now(timezone.utc),
                        self.model.revoked_at.is_(None),
                    )
                )

            query = query.order_by(self.model.last_activity_at.desc())

            result = await self.session.execute(query)
            sessions = list(result.scalars().all())

            self.logger.debug(
                "Retrieved user sessions", user_id=str(user_id), count=len(sessions), include_inactive=include_inactive
            )

            return sessions

        except Exception as e:
            self.logger.error("Failed to get user sessions", user_id=str(user_id), error=str(e))
            raise

    async def get_all_active_sessions(self, limit: int = 100) -> List[Session]:
        """
        Get all currently active sessions.

        Args:
            limit: Maximum number of sessions to return

        Returns:
            List of active sessions
        """
        try:
            query = (
                select(self.model)
                .where(
                    and_(
                        self.model.is_active == True,  # noqa: E712
                        self.model.expires_at > datetime.now(timezone.utc),
                        self.model.revoked_at.is_(None),
                        self.model.is_deleted == False,  # noqa: E712
                    )
                )
                .order_by(self.model.last_activity_at.desc())
                .limit(limit)
            )

            result = await self.session.execute(query)
            sessions = list(result.scalars().all())

            self.logger.debug("Retrieved active sessions", count=len(sessions))
            return sessions

        except Exception as e:
            self.logger.error("Failed to get active sessions", error=str(e))
            raise

    async def revoke_session(self, session_id: uuid.UUID, revoked_by: str, reason: str = "Manual revocation") -> bool:
        """
        Revoke a specific session.

        Args:
            session_id: Session ID to revoke
            revoked_by: Who is revoking the session
            reason: Reason for revocation

        Returns:
            True if session was revoked, False if not found
        """
        try:
            # Get the session
            session_obj = await self.get(session_id)
            if not session_obj:
                self.logger.warning("Session not found for revocation", session_id=str(session_id))
                return False

            # Check if already revoked
            if session_obj.revoked_at is not None:
                self.logger.info("Session already revoked", session_id=str(session_id))
                return False

            # Revoke the session
            session_obj.revoke(revoked_by, reason)
            await self.session.commit()

            self.logger.info(
                "Session revoked",
                session_id=str(session_id),
                user_id=str(session_obj.user_id),
                revoked_by=revoked_by,
                reason=reason,
            )

            return True

        except Exception as e:
            self.logger.error("Failed to revoke session", session_id=str(session_id), error=str(e))
            await self.session.rollback()
            raise

    async def revoke_user_sessions(
        self, user_id: uuid.UUID, revoked_by: str, reason: str = "All sessions revoked"
    ) -> int:
        """
        Revoke all active sessions for a user.

        Args:
            user_id: User ID
            revoked_by: Who is revoking the sessions
            reason: Reason for revocation

        Returns:
            Number of sessions revoked
        """
        try:
            now = datetime.now(timezone.utc)

            # Update all active sessions for the user
            update_stmt = (
                update(self.model)
                .where(
                    and_(
                        self.model.user_id == user_id,
                        self.model.is_active == True,  # noqa: E712
                        self.model.revoked_at.is_(None),
                        self.model.is_deleted == False,  # noqa: E712
                    )
                )
                .values(
                    is_active=False,
                    revoked_at=now,
                    revoked_by=revoked_by,
                    revocation_reason=reason,
                    updated_at=now,
                    updated_by=revoked_by,
                )
            )

            result = await self.session.execute(update_stmt)
            revoked_count = result.rowcount

            await self.session.commit()

            self.logger.info(
                "User sessions revoked",
                user_id=str(user_id),
                revoked_count=revoked_count,
                revoked_by=revoked_by,
                reason=reason,
            )

            return revoked_count

        except Exception as e:
            self.logger.error("Failed to revoke user sessions", user_id=str(user_id), error=str(e))
            await self.session.rollback()
            raise

    async def cleanup_expired_sessions(self, batch_size: int = 1000) -> int:
        """
        Clean up expired sessions by marking them as inactive.

        Args:
            batch_size: Number of sessions to process in one batch

        Returns:
            Number of sessions cleaned up
        """
        try:
            now = datetime.now(timezone.utc)

            # Update expired active sessions
            update_stmt = (
                update(self.model)
                .where(
                    and_(
                        self.model.is_active == True,  # noqa: E712
                        self.model.expires_at <= now,
                        self.model.revoked_at.is_(None),
                        self.model.is_deleted == False,  # noqa: E712
                    )
                )
                .values(
                    is_active=False,
                    revoked_at=now,
                    revoked_by="system",
                    revocation_reason="Session expired",
                    updated_at=now,
                    updated_by="system",
                )
            )

            result = await self.session.execute(update_stmt)
            cleaned_count = result.rowcount

            await self.session.commit()

            if cleaned_count > 0:
                self.logger.info("Expired sessions cleaned up", cleaned_count=cleaned_count)

            return cleaned_count

        except Exception as e:
            self.logger.error("Failed to cleanup expired sessions", error=str(e))
            await self.session.rollback()
            raise

    async def update_session_activity(self, session_token: str, ip_address: Optional[str] = None) -> bool:
        """
        Update session last activity timestamp.

        Args:
            session_token: Session token
            ip_address: Optional IP address to record

        Returns:
            True if session was updated, False if not found
        """
        try:
            # Get the session
            session_obj = await self.get_by_token(session_token)
            if not session_obj:
                return False

            # Update activity
            session_obj.update_activity(ip_address)
            await self.session.commit()

            return True

        except Exception as e:
            self.logger.error("Failed to update session activity", token_prefix=session_token[:8] + "...", error=str(e))
            await self.session.rollback()
            raise

    async def extend_session_by_token(self, session_token: str, extension_minutes: int = 60) -> bool:
        """
        Extend session expiration time.

        Args:
            session_token: Session token
            extension_minutes: Minutes to extend the session

        Returns:
            True if session was extended, False if not found
        """
        try:
            # Get the session
            session_obj = await self.get_by_token(session_token)
            if not session_obj:
                return False

            # Extend the session
            new_expires_at = datetime.now(timezone.utc) + timedelta(minutes=extension_minutes)
            session_obj.extend_session(new_expires_at)
            await self.session.commit()

            self.logger.info("Session extended", session_id=str(session_obj.id), new_expires_at=new_expires_at)

            return True

        except Exception as e:
            self.logger.error("Failed to extend session", token_prefix=session_token[:8] + "...", error=str(e))
            await self.session.rollback()
            raise

    async def get_sessions_by_ip(self, ip_address: str, limit: int = 50) -> List[Session]:
        """
        Get sessions by IP address (for security monitoring).

        Args:
            ip_address: IP address to search for
            limit: Maximum number of sessions to return

        Returns:
            List of sessions from the IP address
        """
        try:
            query = (
                select(self.model)
                .where(
                    and_(
                        (self.model.ip_address == ip_address) | (self.model.last_activity_ip == ip_address),
                        self.model.is_deleted == False,  # noqa: E712
                    )
                )
                .order_by(self.model.created_at.desc())
                .limit(limit)
            )

            result = await self.session.execute(query)
            sessions = list(result.scalars().all())

            self.logger.debug("Retrieved sessions by IP", ip_address=ip_address, count=len(sessions))

            return sessions

        except Exception as e:
            self.logger.error("Failed to get sessions by IP", ip_address=ip_address, error=str(e))
            raise

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get session statistics.

        Returns:
            Dictionary with session statistics
        """
        try:
            now = datetime.now(timezone.utc)

            # Total sessions
            total_query = select(self.model).where(self.model.is_deleted == False)  # noqa: E712
            total_result = await self.session.execute(total_query)
            total_sessions = len(list(total_result.scalars().all()))

            # Active sessions
            active_query = select(self.model).where(
                and_(
                    self.model.is_active == True,  # noqa: E712
                    self.model.expires_at > now,
                    self.model.revoked_at.is_(None),
                    self.model.is_deleted == False,  # noqa: E712
                )
            )
            active_result = await self.session.execute(active_query)
            active_sessions = len(list(active_result.scalars().all()))

            # Expired sessions
            expired_query = select(self.model).where(
                and_(self.model.expires_at <= now, self.model.is_deleted == False)  # noqa: E712
            )
            expired_result = await self.session.execute(expired_query)
            expired_sessions = len(list(expired_result.scalars().all()))

            # Revoked sessions
            revoked_query = select(self.model).where(
                and_(self.model.revoked_at.is_not(None), self.model.is_deleted == False)  # noqa: E712
            )
            revoked_result = await self.session.execute(revoked_query)
            revoked_sessions = len(list(revoked_result.scalars().all()))

            # Sessions created today
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_query = select(self.model).where(
                and_(self.model.created_at >= today_start, self.model.is_deleted == False)  # noqa: E712
            )
            today_result = await self.session.execute(today_query)
            sessions_today = len(list(today_result.scalars().all()))

            return {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "expired_sessions": expired_sessions,
                "revoked_sessions": revoked_sessions,
                "sessions_created_today": sessions_today,
            }

        except Exception as e:
            self.logger.error("Failed to get session statistics", error=str(e))
            raise

    # Interface methods implementation
    async def get_active_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user (interface method)."""
        user_uuid = uuid.UUID(user_id)
        return await self.get_user_sessions(user_uuid, include_inactive=False)

    async def get_user_sessions_interface(self, user_id: str, limit: int = 10) -> List[Session]:
        """Get user sessions with optional limit (interface method)."""
        user_uuid = uuid.UUID(user_id)
        sessions = await self.get_user_sessions(user_uuid, include_inactive=True)
        return sessions[:limit]

    async def create_session(
        self,
        user_id: str,
        token: str,
        expires_at: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new session (interface method)."""
        # Convert expires_at string to datetime if provided
        expires_datetime = None
        if expires_at:
            expires_datetime = datetime.fromisoformat(expires_at)

        # Create session data
        session_data = {
            "user_id": uuid.UUID(user_id),
            "session_token": token,
            "expires_at": expires_datetime,
            "ip_address": ip_address,
            "device_info": user_agent,  # Map user_agent to device_info field
            "is_active": True,
        }

        return await self.create(session_data)

    async def get_by_token(self, token: str) -> Optional[Session]:
        """Get session by token (interface method - delegates to get_by_session_token)."""
        return await self.get_by_session_token(token)

    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a specific session (interface method)."""
        session_uuid = uuid.UUID(session_id)
        return await self.revoke_session(session_uuid, "system", "Session invalidated")

    async def invalidate_user_sessions(self, user_id: str, exclude_session_id: Optional[str] = None) -> int:
        """Invalidate all sessions for a user, optionally excluding one session (interface method)."""
        user_uuid = uuid.UUID(user_id)

        if exclude_session_id:
            # Get all user sessions and revoke individually (excluding one)
            sessions = await self.get_user_sessions(user_uuid, include_inactive=False)
            exclude_uuid = uuid.UUID(exclude_session_id)
            revoked_count = 0

            for session in sessions:
                if session.id != exclude_uuid:
                    if await self.revoke_session(session.id, "system", "User session invalidation"):
                        revoked_count += 1

            return revoked_count
        else:
            # Revoke all user sessions
            return await self.revoke_user_sessions(user_uuid, "system", "All sessions invalidated")

    async def extend_session(self, session_id: str, extension: timedelta) -> Optional[Session]:
        """Extend session expiration time (interface method)."""
        try:
            session_uuid = uuid.UUID(session_id)
            session_obj = await self.get(session_uuid)

            if session_obj:
                new_expires_at = datetime.now(timezone.utc) + extension
                session_obj.extend_session(new_expires_at)
                await self.session.commit()
                return session_obj

            return None
        except Exception as e:
            self.logger.error("Failed to extend session", session_id=session_id, error=str(e))
            raise

    async def get_session_statistics(self) -> Dict[str, Any]:
        """Get session statistics (interface method - already implemented)."""
        return await self.get_statistics()
