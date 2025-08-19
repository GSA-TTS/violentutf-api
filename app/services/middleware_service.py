"""Service layer for middleware to avoid direct database access."""

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository
from app.services.audit_service import AuditService


class MiddlewareService:
    """Service layer for middleware operations."""

    def __init__(self, session: AsyncSession):
        """Initialize middleware service.

        Args:
            session: Database session
        """
        self.session = session
        self.audit_repo = AuditLogRepository(session)
        self.api_key_repo = APIKeyRepository(session)
        self.session_repo = SessionRepository(session)
        self.user_repo = UserRepository(session)
        self.audit_service = AuditService(session)

    async def log_audit_event(
        self,
        action: str,
        resource: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> None:
        """Log an audit event.

        Args:
            action: Action performed
            resource: Resource accessed
            user_id: User ID if authenticated
            details: Additional details
            status: Status of the action
            error_message: Error message if failed
        """
        await self.audit_service.log_event(
            action=action,
            resource=resource,
            user_id=user_id,
            details=details,
            status=status,
            error_message=error_message,
        )

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key.

        Args:
            api_key: API key to validate

        Returns:
            API key data if valid, None otherwise
        """
        return await self.api_key_repo.get_by_key(api_key)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data.

        Args:
            session_id: Session ID

        Returns:
            Session data if exists, None otherwise
        """
        return await self.session_repo.get(session_id)

    async def update_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Update session data.

        Args:
            session_id: Session ID
            data: Session data to update
        """
        await self.session_repo.update(session_id, data)

    async def get_user_permissions(self, user_id: int) -> list[str]:
        """Get user permissions.

        Args:
            user_id: User ID

        Returns:
            List of permission names
        """
        user = await self.user_repo.get(user_id)
        if not user:
            return []

        # Get permissions from user roles
        permissions = []
        if hasattr(user, "roles"):
            for role in user.roles:
                if hasattr(role, "permissions"):
                    permissions.extend([p.name for p in role.permissions])

        return permissions
