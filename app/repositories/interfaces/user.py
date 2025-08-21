"""User repository interface."""

import uuid
from abc import abstractmethod
from typing import List, Optional, Union

from app.models.user import User

from .base import IBaseRepository


class IUserRepository(IBaseRepository[User]):
    """Interface for user repository operations."""

    @abstractmethod
    async def get_by_email(self, email: str, organization_id: Optional[Union[str, uuid.UUID]] = None) -> Optional[User]:
        """
        Get user by email address with optional organization filtering.

        Args:
            email: User email address
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            User if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_username(
        self, username: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[User]:
        """
        Get user by username with optional organization filtering.

        Args:
            username: Username
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            User if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_active_users(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[User]:
        """
        Get all active users with optional organization filtering.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of active users
        """
        raise NotImplementedError

    @abstractmethod
    async def authenticate(
        self, username_or_email: str, password: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[User]:
        """
        Authenticate user with username/email and password.

        Args:
            username_or_email: Username or email address
            password: Password
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            User if authentication successful, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_organization(self, organization_id: Union[str, uuid.UUID]) -> List[User]:
        """
        Get all users in a specific organization.

        Args:
            organization_id: Organization ID

        Returns:
            List of users in the organization
        """
        raise NotImplementedError

    @abstractmethod
    async def update_last_login(
        self,
        user_id: Union[str, uuid.UUID],
        ip_address: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update user's last login timestamp and IP address.

        Args:
            user_id: User ID
            ip_address: Optional IP address
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def set_password(
        self,
        user_id: Union[str, uuid.UUID],
        password_hash: str,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Set user password hash.

        Args:
            user_id: User ID
            password_hash: Hashed password
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def activate_user(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Activate a user account.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if activation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def deactivate_user(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Deactivate a user account.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if deactivation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def search_users(
        self, query: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[User]:
        """
        Search users by name, email, or username.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching users
        """
        raise NotImplementedError
