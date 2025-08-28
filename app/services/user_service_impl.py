"""
User service implementation for dependency injection.

This service implements user interfaces to maintain Clean Architecture
compliance while providing user data operations.
"""

from typing import List, Optional, Union

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.interfaces.user_interface import IUserService, UserData
from app.core.security import verify_password
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserUpdate, UserUpdatePassword

logger = get_logger(__name__)


class UserServiceImpl(IUserService):
    """User service implementation using repository pattern."""

    def __init__(self, repository_or_session: Union[UserRepository, AsyncSession]):
        """Initialize with user repository or database session.

        Args:
            repository_or_session: User repository or AsyncSession
        """
        if isinstance(repository_or_session, AsyncSession):
            self.user_repo = UserRepository(repository_or_session)
        else:
            self.user_repo = repository_or_session

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

    async def create_user(self, user_data: UserCreate, created_by: Optional[str] = None) -> User:
        """Create a new user with transaction management.

        Args:
            user_data: User creation data
            created_by: ID of user creating this user

        Returns:
            Created user instance

        Raises:
            ConflictError: If username or email already exists
            ValidationError: If user data is invalid
        """
        try:
            # Validate username and email availability
            existing_user = await self.user_repo.get_by_username(user_data.username)
            if existing_user:
                raise ConflictError(f"Username '{user_data.username}' already exists")

            existing_user = await self.user_repo.get_by_email(user_data.email)
            if existing_user:
                raise ConflictError(f"Email '{user_data.email}' already exists")

            # Create user using repository method
            user = await self.user_repo.create_user(
                username=user_data.username,
                email=user_data.email,
                password=user_data.password,
                full_name=user_data.full_name,
                is_superuser=user_data.is_superuser,
                created_by=created_by,
            )

            logger.info(
                "user_created",
                user_id=str(user.id),
                username=user.username,
                email=user.email,
                created_by=created_by,
            )

            return user

        except (ConflictError, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "user_creation_error",
                error=str(e),
                username=user_data.username,
                email=user_data.email,
                exc_info=True,
            )
            raise

    async def update_user_profile(self, user_id: str, user_data: UserUpdate, updated_by: Optional[str] = None) -> User:
        """Update user profile with transaction management.

        Args:
            user_id: User ID to update
            user_data: Update data
            updated_by: ID of user performing the update

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
            ConflictError: If email already exists
        """
        try:
            # Get existing user
            user = await self.user_repo.get(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")

            # Check email uniqueness if email is being changed
            if user_data.email and user_data.email != user.email:
                existing_user = await self.user_repo.get_by_email(user_data.email)
                if existing_user and str(existing_user.id) != user_id:
                    raise ConflictError(f"Email '{user_data.email}' already exists")

            # Update user using base update method
            update_data = user_data.model_dump(exclude_unset=True)
            if updated_by:
                update_data["updated_by"] = updated_by
            updated_user = await self.user_repo.update(user_id, **update_data)

            logger.info(
                "user_profile_updated",
                user_id=user_id,
                updated_by=updated_by,
            )

            return updated_user

        except (NotFoundError, ConflictError):
            raise
        except Exception as e:
            logger.error(
                "user_profile_update_error",
                user_id=user_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def change_user_password(
        self, user_id: str, password_data: UserUpdatePassword, updated_by: Optional[str] = None
    ) -> User:
        """Change user password with transaction management.

        Args:
            user_id: User ID
            password_data: Password change data
            updated_by: ID of user performing the change

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
            ValidationError: If current password is incorrect
        """
        try:
            # Get existing user
            user = await self.user_repo.get(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")

            # Change password using repository method
            updated_user = await self.user_repo.change_password(user_id, password_data, updated_by)

            logger.info(
                "user_password_changed",
                user_id=user_id,
                updated_by=updated_by,
            )

            return updated_user

        except (NotFoundError, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "user_password_change_error",
                user_id=user_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def verify_user_email(self, user_id: str, updated_by: Optional[str] = None) -> User:
        """Verify user email with transaction management.

        Args:
            user_id: User ID
            updated_by: ID of user performing the verification

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        try:
            user = await self.user_repo.get(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")

            # Verify email using repository method
            updated_user = await self.user_repo.verify_email(user_id, updated_by)

            logger.info(
                "user_email_verified",
                user_id=user_id,
                updated_by=updated_by,
            )

            return updated_user

        except NotFoundError:
            raise
        except Exception as e:
            logger.error(
                "user_email_verification_error",
                user_id=user_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def activate_user(self, user_id: str, updated_by: Optional[str] = None) -> User:
        """Activate user account with transaction management.

        Args:
            user_id: User ID
            updated_by: ID of user performing the activation

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        try:
            user = await self.user_repo.get(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")

            # Activate user using repository method
            success = await self.user_repo.activate_user(user_id, updated_by or "system")
            if not success:
                raise ValidationError(f"Failed to activate user {user_id}")

            # Get updated user
            updated_user = await self.user_repo.get(user_id)

            logger.info(
                "user_activated",
                user_id=user_id,
                updated_by=updated_by,
            )

            return updated_user

        except NotFoundError:
            raise
        except Exception as e:
            logger.error(
                "user_activation_error",
                user_id=user_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def deactivate_user(self, user_id: str, updated_by: Optional[str] = None) -> User:
        """Deactivate user account with transaction management.

        Args:
            user_id: User ID
            updated_by: ID of user performing the deactivation

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        try:
            user = await self.user_repo.get(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")

            # Deactivate user using repository method
            success = await self.user_repo.deactivate_user(user_id, updated_by or "system")
            if not success:
                raise ValidationError(f"Failed to deactivate user {user_id}")

            # Get updated user
            updated_user = await self.user_repo.get(user_id)

            logger.info(
                "user_deactivated",
                user_id=user_id,
                updated_by=updated_by,
            )

            return updated_user

        except NotFoundError:
            raise
        except Exception as e:
            logger.error(
                "user_deactivation_error",
                user_id=user_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username.

        Args:
            username: Username to search for

        Returns:
            User instance if found, None otherwise
        """
        try:
            return await self.user_repo.get_by_username(username)
        except Exception as e:
            logger.error(
                "get_user_by_username_error",
                username=username,
                error=str(e),
                exc_info=True,
            )
            return None

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email.

        Args:
            email: Email to search for

        Returns:
            User instance if found, None otherwise
        """
        try:
            return await self.user_repo.get_by_email(email)
        except Exception as e:
            logger.error(
                "get_user_by_email_error",
                email=email,
                error=str(e),
                exc_info=True,
            )
            return None

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> Optional[User]:
        """Authenticate user with username and password.

        Args:
            username: Username or email to authenticate
            password: Plain text password to verify
            ip_address: Client IP address for logging

        Returns:
            User instance if authentication successful, None otherwise
        """
        try:
            # Try to get user by username first
            user = await self.get_user_by_username(username)

            # If not found by username, try email
            if not user:
                user = await self.get_user_by_email(username)

            if not user:
                logger.warning(
                    "authentication_failed_user_not_found",
                    username=username,
                    ip_address=ip_address,
                )
                return None

            # Check if user is active
            if not user.is_active:
                logger.warning(
                    "authentication_failed_user_inactive",
                    username=username,
                    user_id=user.id,
                    ip_address=ip_address,
                )
                return None

            # Verify password
            if not verify_password(password, user.password_hash):
                logger.warning(
                    "authentication_failed_invalid_password",
                    username=username,
                    user_id=user.id,
                    ip_address=ip_address,
                )
                return None

            logger.info(
                "authentication_successful",
                username=username,
                user_id=user.id,
                ip_address=ip_address,
            )
            return user

        except Exception as e:
            logger.error(
                "authentication_error",
                username=username,
                ip_address=ip_address,
                error=str(e),
                exc_info=True,
            )
            return None
