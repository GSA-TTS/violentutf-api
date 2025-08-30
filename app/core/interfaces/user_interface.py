"""User service interface for dependency injection."""

from abc import ABC, abstractmethod
from typing import List, Optional, Set

from pydantic import BaseModel


class UserData(BaseModel):
    """User data transfer object."""

    id: str
    username: str
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: List[str]
    organization_id: Optional[str] = None


class IUserService(ABC):
    """Abstract interface for user services."""

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[UserData]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            User data if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_superusers(self) -> List[UserData]:
        """Get all superusers.

        Returns:
            List of superuser data
        """
        pass

    @abstractmethod
    async def is_user_active(self, user_id: str) -> bool:
        """Check if user is active.

        Args:
            user_id: User identifier

        Returns:
            True if user is active, False otherwise
        """
        pass


class IUserPermissionProvider(ABC):
    """Abstract interface for user permission providers."""

    @abstractmethod
    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get user permissions.

        Args:
            user_id: User identifier

        Returns:
            Set of user permissions
        """
        pass

    @abstractmethod
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles.

        Args:
            user_id: User identifier

        Returns:
            List of user roles
        """
        pass

    @abstractmethod
    async def get_user_data(self, user_id: str) -> Optional[UserData]:
        """Get complete user data.

        Args:
            user_id: User identifier

        Returns:
            Complete user data if found, None otherwise
        """
        pass
