"""Authentication service for core operations."""

from typing import TYPE_CHECKING, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.repositories.user import UserRepository

if TYPE_CHECKING:
    from app.models.user import User

logger = get_logger(__name__)


class AuthService:
    """Service for authentication operations."""

    def __init__(self, session: AsyncSession):
        """Initialize auth service.

        Args:
            session: Database session
        """
        self.session = session
        self.user_repo = UserRepository(session)

    async def get_user_by_id(self, user_id: int) -> Optional["User"]:
        """Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User object if found and active, None otherwise
        """
        user = await self.user_repo.get(user_id)
        if user and user.is_active:
            return user
        return None

    async def get_user_by_email(self, email: str) -> Optional["User"]:
        """Get user by email.

        Args:
            email: User email

        Returns:
            User object if found and active, None otherwise
        """
        user = await self.user_repo.get_by_email(email)
        if user and user.is_active:
            return user
        return None

    async def authenticate_user(
        self, user_id: Optional[int] = None, oauth_user: Optional[object] = None
    ) -> Optional["User"]:
        """Authenticate user by ID or OAuth.

        Args:
            user_id: User ID from JWT
            oauth_user: OAuth user object

        Returns:
            Authenticated user or None
        """
        # Try user ID first
        if user_id:
            user = await self.get_user_by_id(user_id)
            if user:
                return user

        # Try OAuth user
        if oauth_user and hasattr(oauth_user, "is_active") and oauth_user.is_active:
            return oauth_user

        return None
