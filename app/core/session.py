"""Secure session management for ViolentUTF API."""

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from structlog.stdlib import get_logger

from ..core.config import settings
from ..utils.cache import get_cache_client

logger = get_logger(__name__)

# Session configuration
SESSION_KEY_PREFIX = "session:"
SESSION_ID_LENGTH = 32
SESSION_COOKIE_NAME = "violentutf_session"


class SessionManager:
    """Secure session management with Redis backend."""

    def __init__(self) -> None:
        """Initialize session manager."""
        self.cache = get_cache_client()
        self.session_ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Convert to seconds

    async def create_session(
        self,
        user_id: str,
        user_data: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """Create a new session with secure ID generation.

        Args:
            user_id: User identifier
            user_data: Additional user data to store
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Session ID
        """
        # Generate cryptographically secure session ID
        session_id = secrets.token_urlsafe(SESSION_ID_LENGTH)

        # Prepare session data
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_accessed": datetime.now(timezone.utc).isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "rotated": False,
            **user_data,
        }

        # Store in Redis with TTL
        if self.cache:
            try:
                await self.cache.set(
                    f"{SESSION_KEY_PREFIX}{session_id}",
                    json.dumps(session_data),
                    ex=self.session_ttl,
                )
                logger.info(
                    "session_created",
                    session_id=session_id[:8] + "...",
                    user_id=user_id,
                )
            except Exception as e:
                logger.error("session_creation_failed", error=str(e))
                raise
        else:
            logger.warning("session_storage_unavailable", session_id=session_id[:8] + "...")

        return session_id

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data by ID.

        Args:
            session_id: Session identifier

        Returns:
            Session data or None if not found/expired
        """
        if not self.cache:
            logger.warning("session_storage_unavailable")
            return None

        try:
            session_str = await self.cache.get(f"{SESSION_KEY_PREFIX}{session_id}")
            if session_str:
                session_data: Dict[str, Any] = json.loads(session_str)
                # Update last accessed time
                session_data["last_accessed"] = datetime.now(timezone.utc).isoformat()
                await self.cache.set(
                    f"{SESSION_KEY_PREFIX}{session_id}",
                    json.dumps(session_data),
                    ex=self.session_ttl,
                )
                return session_data
        except Exception as e:
            logger.error("session_retrieval_failed", error=str(e))

        return None

    async def rotate_session(
        self,
        old_session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[str]:
        """Rotate session ID for security (prevent session fixation).

        Args:
            old_session_id: Current session ID
            ip_address: New IP address (if changed)
            user_agent: New user agent (if changed)

        Returns:
            New session ID or None if rotation failed
        """
        # Get existing session
        session_data = await self.get_session(old_session_id)
        if not session_data:
            logger.warning(
                "session_rotation_failed_not_found",
                session_id=old_session_id[:8] + "...",
            )
            return None

        # Generate new session ID
        new_session_id = secrets.token_urlsafe(SESSION_ID_LENGTH)

        # Update session data
        session_data["session_id"] = new_session_id
        session_data["rotated"] = True
        session_data["rotated_at"] = datetime.now(timezone.utc).isoformat()
        session_data["previous_session_id"] = old_session_id[:8] + "..."

        # Update IP/UA if provided
        if ip_address:
            session_data["ip_address"] = ip_address
        if user_agent:
            session_data["user_agent"] = user_agent

        # Store new session
        if self.cache:
            try:
                # Create new session
                await self.cache.set(
                    f"{SESSION_KEY_PREFIX}{new_session_id}",
                    json.dumps(session_data),
                    ex=self.session_ttl,
                )
                # Delete old session
                await self.cache.delete(f"{SESSION_KEY_PREFIX}{old_session_id}")

                logger.info(
                    "session_rotated",
                    old_session_id=old_session_id[:8] + "...",
                    new_session_id=new_session_id[:8] + "...",
                    user_id=session_data.get("user_id"),
                )
                return new_session_id
            except Exception as e:
                logger.error("session_rotation_failed", error=str(e))

        return None

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session (logout).

        Args:
            session_id: Session to delete

        Returns:
            True if deleted, False otherwise
        """
        if not self.cache:
            logger.warning("session_storage_unavailable")
            return False

        try:
            result = await self.cache.delete(f"{SESSION_KEY_PREFIX}{session_id}")
            if result:
                logger.info("session_deleted", session_id=session_id[:8] + "...")
            return bool(result)
        except Exception as e:
            logger.error("session_deletion_failed", error=str(e))
            return False

    async def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user.

        Args:
            user_id: User whose sessions to delete

        Returns:
            Number of sessions deleted
        """
        if not self.cache:
            logger.warning("session_storage_unavailable")
            return 0

        deleted_count = 0
        try:
            # Get all session keys (this is inefficient, consider using Redis SCAN)
            # In production, maintain a user->sessions index
            # pattern = f"{SESSION_KEY_PREFIX}*"  # noqa: F841 - placeholder for future implementation
            # Note: This is a simplified implementation
            # Production should use SCAN or maintain proper indexes

            logger.info("user_sessions_deletion_requested", user_id=user_id)
            # For now, we'll need to implement a more efficient solution
            # This is a placeholder that demonstrates the interface
            return deleted_count
        except Exception as e:
            logger.error("user_sessions_deletion_failed", error=str(e))
            return 0

    async def extend_session(self, session_id: str, additional_minutes: int = 30) -> bool:
        """Extend session expiration time.

        Args:
            session_id: Session to extend
            additional_minutes: Minutes to add to expiration

        Returns:
            True if extended, False otherwise
        """
        if not self.cache:
            return False

        try:
            session_data = await self.get_session(session_id)
            if session_data:
                new_ttl = self.session_ttl + (additional_minutes * 60)
                await self.cache.set(
                    f"{SESSION_KEY_PREFIX}{session_id}",
                    json.dumps(session_data),
                    ex=new_ttl,
                )
                logger.info(
                    "session_extended",
                    session_id=session_id[:8] + "...",
                    additional_minutes=additional_minutes,
                )
                return True
        except Exception as e:
            logger.error("session_extension_failed", error=str(e))

        return False

    async def validate_session(
        self,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Validate session with optional IP/UA checking.

        Args:
            session_id: Session to validate
            ip_address: Client IP to verify
            user_agent: Client UA to verify

        Returns:
            True if valid, False otherwise
        """
        session_data = await self.get_session(session_id)
        if not session_data:
            return False

        # Check IP address if strict mode enabled
        if settings.CSRF_PROTECTION and ip_address:
            if session_data.get("ip_address") != ip_address:
                logger.warning(
                    "session_ip_mismatch",
                    session_id=session_id[:8] + "...",
                    expected=session_data.get("ip_address"),
                    actual=ip_address,
                )
                # In strict mode, this would return False
                # For now, just log the warning

        # Check session age for rotation
        created_at = datetime.fromisoformat(session_data["created_at"])
        age_minutes = (datetime.now(timezone.utc) - created_at).total_seconds() / 60

        # Recommend rotation after half the session lifetime
        if age_minutes > (settings.ACCESS_TOKEN_EXPIRE_MINUTES / 2):
            session_data["rotation_recommended"] = True
            # Save updated session data to cache
            if self.cache:
                try:
                    await self.cache.set(
                        f"{SESSION_KEY_PREFIX}{session_id}",
                        json.dumps(session_data),
                        ex=self.session_ttl,
                    )
                except Exception as e:
                    logger.error(
                        "session_rotation_flag_save_failed",
                        session_id=session_id[:8] + "...",
                        error=str(e),
                    )

        return True

    async def cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions (called periodically)."""
        # Redis handles TTL automatically, but this method is here
        # for future enhancements like session activity logging
        logger.info("session_cleanup_triggered")


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get or create session manager instance.

    Returns:
        SessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
