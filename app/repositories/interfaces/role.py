"""Role repository interface."""

import uuid
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Union

from app.models.role import Role

from .base import IBaseRepository


class IRoleRepository(IBaseRepository[Role]):
    """Interface for role repository operations."""

    @abstractmethod
    async def get_by_name(self, name: str, organization_id: Optional[Union[str, uuid.UUID]] = None) -> Optional[Role]:
        """
        Get role by name with optional organization filtering.

        Args:
            name: Role name
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Role if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_system_roles(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[Role]:
        """
        Get all system-defined roles.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of system roles
        """
        raise NotImplementedError

    @abstractmethod
    async def get_custom_roles(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[Role]:
        """
        Get all custom-defined roles.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of custom roles
        """
        raise NotImplementedError

    @abstractmethod
    async def get_roles_with_permission(
        self, permission: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[Role]:
        """
        Get roles that have a specific permission.

        Args:
            permission: Permission to search for
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of roles with the permission
        """
        raise NotImplementedError

    @abstractmethod
    async def add_permission_to_role(
        self,
        role_id: Union[str, uuid.UUID],
        permission: str,
        granted_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Add permission to a role.

        Args:
            role_id: Role ID
            permission: Permission to add
            granted_by: User who granted the permission
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if permission added successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def remove_permission_from_role(
        self,
        role_id: Union[str, uuid.UUID],
        permission: str,
        removed_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Remove permission from a role.

        Args:
            role_id: Role ID
            permission: Permission to remove
            removed_by: User who removed the permission
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if permission removed successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_role_permissions(
        self, role_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[str]:
        """
        Get all permissions for a role.

        Args:
            role_id: Role ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of permissions
        """
        raise NotImplementedError

    @abstractmethod
    async def check_role_permission(
        self, role_id: Union[str, uuid.UUID], permission: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Check if a role has a specific permission.

        Args:
            role_id: Role ID
            permission: Permission to check
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if role has permission, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_roles(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[Role]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of user roles
        """
        raise NotImplementedError

    @abstractmethod
    async def assign_role_to_user(
        self,
        user_id: Union[str, uuid.UUID],
        role_id: Union[str, uuid.UUID],
        assigned_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: User ID
            role_id: Role ID
            assigned_by: User who assigned the role
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if role assigned successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def remove_role_from_user(
        self,
        user_id: Union[str, uuid.UUID],
        role_id: Union[str, uuid.UUID],
        removed_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Remove a role from a user.

        Args:
            user_id: User ID
            role_id: Role ID
            removed_by: User who removed the role
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if role removed successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def search_roles(
        self, query: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[Role]:
        """
        Search roles by name or description.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching roles
        """
        raise NotImplementedError

    @abstractmethod
    async def get_role_hierarchy(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[Dict[str, Any]]:
        """
        Get role hierarchy information.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of role hierarchy data
        """
        raise NotImplementedError
