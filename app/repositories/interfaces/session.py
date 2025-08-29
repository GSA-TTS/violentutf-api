"""Session repository interface contract."""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any, Dict, List, Optional

from ...models.session import Session


class ISessionRepository(ABC):
    """Interface contract for session repository operations."""

    @abstractmethod
    async def get_active_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user."""
        pass

    @abstractmethod
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of sessions removed."""
        pass

    @abstractmethod
    async def get_user_sessions(self, user_id: str, limit: int = 10) -> List[Session]:
        """Get user sessions with optional limit."""
        pass

    @abstractmethod
    async def create_session(
        self,
        user_id: str,
        token: str,
        expires_at: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new session."""
        pass

    @abstractmethod
    async def get_by_token(self, token: str) -> Optional[Session]:
        """Get session by token."""
        pass

    @abstractmethod
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a specific session."""
        pass

    @abstractmethod
    async def invalidate_user_sessions(self, user_id: str, exclude_session_id: Optional[str] = None) -> int:
        """Invalidate all sessions for a user, optionally excluding one session."""
        pass

    @abstractmethod
    async def extend_session(self, session_id: str, extension: timedelta) -> Optional[Session]:
        """Extend session expiration time."""
        pass

    @abstractmethod
    async def get_session_statistics(self) -> Dict[str, Any]:
        """Get session statistics."""
        pass
