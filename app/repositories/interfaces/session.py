"""Session repository interface."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.session import Session

from .base import IBaseRepository


class ISessionRepository(IBaseRepository[Session]):
    """Interface for session repository operations."""

    @abstractmethod
    async def get_active_sessions(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[Session]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of active sessions
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_token(
        self, token: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[Session]:
        """
        Get session by token with optional organization filtering.

        Args:
            token: Session token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Session if found and active, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_refresh_token(
        self, refresh_token: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[Session]:
        """
        Get session by refresh token with optional organization filtering.

        Args:
            refresh_token: Refresh token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Session if found and active, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_expired_sessions(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> int:
        """
        Clean up expired sessions.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of sessions cleaned up
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_session(
        self,
        session_id: Union[str, uuid.UUID],
        revoked_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Revoke a session.

        Args:
            session_id: Session ID
            revoked_by: User who revoked the session
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if revocation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_all_user_sessions(
        self,
        user_id: Union[str, uuid.UUID],
        except_session_id: Optional[Union[str, uuid.UUID]] = None,
        revoked_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> int:
        """
        Revoke all sessions for a user.

        Args:
            user_id: User ID
            except_session_id: Optional session ID to exclude from revocation
            revoked_by: User who revoked the sessions
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of sessions revoked
        """
        raise NotImplementedError

    @abstractmethod
    async def update_session_activity(
        self,
        session_id: Union[str, uuid.UUID],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update session activity information.

        Args:
            session_id: Session ID
            ip_address: Optional IP address
            user_agent: Optional user agent
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def refresh_session(
        self,
        session_id: Union[str, uuid.UUID],
        new_token: str,
        new_refresh_token: str,
        expires_at: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> Optional[Session]:
        """
        Refresh session with new tokens and expiration.

        Args:
            session_id: Session ID
            new_token: New session token
            new_refresh_token: New refresh token
            expires_at: New expiration time
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Updated session if successful, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_session_statistics(
        self,
        user_id: Optional[Union[str, uuid.UUID]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_expired: bool = False,
    ) -> Dict[str, Any]:
        """
        Get session statistics.

        Args:
            user_id: Optional user ID to filter by
            organization_id: Optional organization ID for multi-tenant filtering
            include_expired: Whether to include expired sessions

        Returns:
            Dictionary containing session statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def bulk_revoke_sessions(
        self,
        session_ids: List[Union[str, uuid.UUID]],
        revoked_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> int:
        """
        Bulk revoke multiple sessions.

        Args:
            session_ids: List[Any] of session IDs to revoke
            revoked_by: User who revoked the sessions
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of sessions revoked
        """
        raise NotImplementedError
