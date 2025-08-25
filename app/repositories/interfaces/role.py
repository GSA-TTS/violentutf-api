"""Role repository interface contract."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ...models.role import Role


class IRoleRepository(ABC):
    """Interface contract for role repository operations."""

    @abstractmethod
    async def get_by_name(self, name: str, organization_id: Optional[str] = None) -> Optional[Role]:
        """Get role by name."""
        pass

    @abstractmethod
    async def create_role(
        self,
        name: str,
        description: str,
        permissions: List[str],
        organization_id: Optional[str] = None,
        created_by: str = "system",
    ) -> Role:
        """Create a new role."""
        pass

    @abstractmethod
    async def update_role_permissions(
        self,
        role_id: str,
        permissions: List[str],
        updated_by: str = "system",
    ) -> Optional[Role]:
        """Update role permissions."""
        pass

    @abstractmethod
    async def get_user_roles(self, user_id: str) -> List[Role]:
        """Get all roles for a user."""
        pass

    @abstractmethod
    async def assign_role_to_user(self, user_id: str, role_id: str, assigned_by: str) -> bool:
        """Assign a role to a user."""
        pass

    @abstractmethod
    async def remove_role_from_user(self, user_id: str, role_id: str, removed_by: str) -> bool:
        """Remove a role from a user."""
        pass

    @abstractmethod
    async def get_role_users(self, role_id: str) -> List[Dict[str, Any]]:
        """Get all users assigned to a role."""
        pass

    @abstractmethod
    async def get_default_roles(self) -> List[Role]:
        """Get default system roles."""
        pass

    @abstractmethod
    async def is_role_name_available(self, name: str, exclude_role_id: Optional[str] = None) -> bool:
        """Check if role name is available."""
        pass
