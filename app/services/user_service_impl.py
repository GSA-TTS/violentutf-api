"""
User service implementation for dependency injection.

This service implements user interfaces to maintain Clean Architecture
compliance while providing user data operations.
"""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.interfaces.user_interface import IUserService, UserData
from app.repositories.user import UserRepository

logger = get_logger(__name__)


class UserServiceImpl(IUserService):
    """User service implementation using repository pattern."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session.

        Args:
            session: Database session for operations
        """
        self.session = session
        self.user_repo = UserRepository(session)

    async def get_user_by_id(self, user_id: str) -> Optional[UserData]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            User data if found, None otherwise
        """
        try:
            user = await self.user_repo.get(user_id)
            if user:
                return UserData(
                    id=str(user.id),
                    username=user.username,
                    email=user.email,
                    is_active=user.is_active,
                    is_verified=getattr(user, "is_verified", False),
                    is_superuser=getattr(user, "is_superuser", False),
                    roles=getattr(user, "roles", []),
                    organization_id=(str(user.organization_id) if getattr(user, "organization_id", None) else None),
                )
            return None
        except Exception as e:
            logger.error("Failed to get user by ID", user_id=user_id, error=str(e))
            return None

    async def get_superusers(self) -> List[UserData]:
        """Get all superusers.

        Returns:
            List of superuser data
        """
        try:
            users = await self.user_repo.get_superusers()
            return [
                UserData(
                    id=str(user.id),
                    username=user.username,
                    email=user.email,
                    is_active=user.is_active,
                    is_verified=getattr(user, "is_verified", False),
                    is_superuser=getattr(user, "is_superuser", False),
                    roles=getattr(user, "roles", []),
                    organization_id=(str(user.organization_id) if getattr(user, "organization_id", None) else None),
                )
                for user in users
            ]
        except Exception as e:
            logger.error("Failed to get superusers", error=str(e))
            return []

    async def is_user_active(self, user_id: str) -> bool:
        """Check if user is active.

        Args:
            user_id: User identifier

        Returns:
            True if user is active, False otherwise
        """
        try:
            user = await self.user_repo.get(user_id)
            return user.is_active if user else False
        except Exception as e:
            logger.error("Failed to check user active status", user_id=user_id, error=str(e))
            return False
