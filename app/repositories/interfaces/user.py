"""User repository interface contract."""

from abc import ABC, abstractmethod
from typing import List, Optional

from ...models.user import User
from ..base import Page


class IUserRepository(ABC):
    """Interface contract for user repository operations."""

    @abstractmethod
    async def get_by_username(self, username: str, organization_id: Optional[str] = None) -> Optional[User]:
        """Get user by username with optional organization filtering."""
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        pass

    @abstractmethod
    async def authenticate(self, username: str, password: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Authenticate user with username and password."""
        pass

    @abstractmethod
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        is_superuser: bool = False,
        created_by: str = "system",
    ) -> User:
        """Create a new user with password hashing."""
        pass

    @abstractmethod
    async def update_password(
        self, user_id: str, old_password: str, new_password: str, updated_by: str = "system"
    ) -> bool:
        """Update user password."""
        pass

    @abstractmethod
    async def activate_user(self, user_id: str, activated_by: str = "system") -> bool:
        """Activate a user account."""
        pass

    @abstractmethod
    async def deactivate_user(self, user_id: str, deactivated_by: str = "system") -> bool:
        """Deactivate a user account."""
        pass

    @abstractmethod
    async def is_username_available(self, username: str, exclude_user_id: Optional[str] = None) -> bool:
        """Check if username is available."""
        pass

    @abstractmethod
    async def is_email_available(self, email: str, exclude_user_id: Optional[str] = None) -> bool:
        """Check if email address is available."""
        pass

    @abstractmethod
    async def verify_user(self, user_id: str, verified_by: str = "system") -> bool:
        """Verify a user account (mark email as verified)."""
        pass

    @abstractmethod
    async def get_active_users(
        self, page: int = 1, size: int = 50, order_by: str = "created_at", order_desc: bool = True
    ) -> Page[User]:
        """Get active users with pagination."""
        pass

    @abstractmethod
    async def get_unverified_users(self, include_inactive: bool = False, limit: int = 100) -> List[User]:
        """Get unverified users."""
        pass

    @abstractmethod
    async def verify_email(self, user_id: str) -> Optional[User]:
        """Verify user email by setting email_verified to True."""
        pass

    @abstractmethod
    async def revoke(self, user_id: str, reason: str = "Manual revocation") -> bool:
        """Revoke user access by deactivating the account."""
        pass

    @abstractmethod
    async def update_last_login(self, user_id: str) -> Optional[User]:
        """Update user's last login timestamp."""
        pass

    @abstractmethod
    async def change_password(self, user_id: str, new_password_hash: str) -> Optional[User]:
        """Change user password."""
        pass
