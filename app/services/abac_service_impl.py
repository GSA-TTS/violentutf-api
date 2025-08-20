"""
ABAC service implementation for dependency injection.

This service implements ABAC interfaces while coordinating with the core ABAC engine
and providing user permission resolution.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.abac import check_abac_permission, explain_abac_decision
from app.core.interfaces.abac_interface import (
    IABACService,
    IUserPermissionProvider,
)
from app.services.rbac_service import RBACService

logger = get_logger(__name__)


class UserPermissionProvider(IUserPermissionProvider):
    """User permission provider implementation."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: Database session for operations
        """
        self.session = session
        self.rbac_service = RBACService(session)

    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get effective permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            Set of permission strings
        """
        try:
            return await self.rbac_service.get_user_permissions(user_id)
        except Exception as e:
            logger.error("Failed to get user permissions", user_id=user_id, error=str(e))
            return set()

    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get roles for a user.

        Args:
            user_id: User identifier

        Returns:
            List of role names
        """
        try:
            return await self.rbac_service.get_user_roles(user_id)
        except Exception as e:
            logger.error("Failed to get user roles", user_id=user_id, error=str(e))
            return []


class ABACServiceImpl(IABACService):
    """ABAC service implementation using core ABAC engine."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: Database session for operations
        """
        self.session = session
        self.permission_provider = UserPermissionProvider(session)

    async def check_permission(
        self,
        subject_id: str,
        resource_type: str,
        action: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Check if subject has permission for action on resource.

        Args:
            subject_id: ID of the user making the request
            resource_type: Type of resource being accessed
            action: Action being performed
            organization_id: Organization context
            resource_id: Specific resource ID
            resource_owner_id: Owner of the resource
            context: Additional context

        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            return await check_abac_permission(
                subject_id=subject_id,
                resource_type=resource_type,
                action=action,
                permission_provider=self.permission_provider,
                organization_id=organization_id,
                resource_id=resource_id,
                resource_owner_id=resource_owner_id,
                environment=context,
            )
        except Exception as e:
            logger.error(
                "ABAC permission check failed",
                subject_id=subject_id,
                resource_type=resource_type,
                action=action,
                error=str(e),
            )
            # Fail-safe: deny access on errors
            return False, f"Permission check error: {str(e)}"

    async def explain_decision(
        self,
        subject_id: str,
        resource_type: str,
        action: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get detailed explanation of access decision.

        Args:
            subject_id: ID of the user making the request
            resource_type: Type of resource being accessed
            action: Action being performed
            organization_id: Organization context
            resource_id: Specific resource ID
            resource_owner_id: Owner of the resource
            context: Additional context

        Returns:
            Detailed explanation dictionary
        """
        try:
            return await explain_abac_decision(
                subject_id=subject_id,
                resource_type=resource_type,
                action=action,
                permission_provider=self.permission_provider,
                organization_id=organization_id,
                resource_id=resource_id,
                resource_owner_id=resource_owner_id,
                environment=context,
            )
        except Exception as e:
            logger.error(
                "ABAC decision explanation failed",
                subject_id=subject_id,
                resource_type=resource_type,
                action=action,
                error=str(e),
            )
            return {
                "decision": "DENY",
                "reason": f"Explanation error: {str(e)}",
                "error": True,
            }
