"""User repository with authentication and user management methods."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ..core.security import hash_password, verify_password
from ..models.user import User
from .base import BaseRepository, Page

logger = get_logger(__name__)


class UserRepository(BaseRepository[User]):
    """
    User repository with authentication-specific methods.

    Extends base repository with user authentication and management features
    following patterns from original ViolentUTF repository.
    """

    def __init__(self, session: AsyncSession):
        """Initialize user repository."""
        super().__init__(session, User)

    @property
    def db(self) -> AsyncSession:
        """Access to database session for transaction management."""
        return self.session

    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to search for

        Returns:
            User if found, None otherwise
        """
        try:
            # Case-sensitive username lookup
            query = select(self.model).where(
                and_(self.model.username == username, self.model.is_deleted == False)  # noqa: E712
            )

            result = await self.session.execute(query)
            user = result.scalar_one_or_none()

            if user:
                self.logger.debug("User found by username", username=username)
            else:
                self.logger.debug("User not found by username", username=username)

            return user

        except Exception as e:
            self.logger.error("Failed to get user by username", username=username, error=str(e))
            raise

    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.

        Args:
            email: Email address to search for

        Returns:
            User if found, None otherwise
        """
        try:
            # Case-insensitive email lookup
            query = select(self.model).where(
                and_(self.model.email.ilike(email.lower()), self.model.is_deleted == False)  # noqa: E712
            )

            result = await self.session.execute(query)
            user = result.scalar_one_or_none()

            if user:
                self.logger.debug("User found by email", email=email)
            else:
                self.logger.debug("User not found by email", email=email)

            return user

        except Exception as e:
            self.logger.error("Failed to get user by email", email=email, error=str(e))
            raise

    async def authenticate(self, username: str, password: str, ip_address: Optional[str] = None) -> Optional[User]:
        """
        Authenticate user with username and password.

        Args:
            username: Username or email address
            password: Plain text password
            ip_address: Optional IP address for login tracking

        Returns:
            User if authentication successful, None otherwise
        """
        try:
            # Try to find user by username first, then by email
            user = await self.get_by_username(username)
            if not user:
                user = await self.get_by_email(username)

            # Always run password verification to prevent timing attacks
            # Use a dummy hash if user not found
            if not user:
                self.logger.debug("User not found for authentication", username=username)
                # Use a consistent dummy hash to prevent timing attacks
                # This hash is for "dummy_password_for_timing_attack_prevention"
                dummy_hash = "$2b$12$7qK8hQgzR3V3XgZLddQJyOWPZPL1GQ3nPGhcQd3cZkYFRZeG.0a.a"
                verify_password(password, dummy_hash)  # Run verification anyway
                return None

            # Check if user is active
            if not user.is_active:
                self.logger.warning("Inactive user attempted login", username=username, user_id=user.id)
                # Still verify password to maintain consistent timing
                verify_password(password, user.password_hash)
                return None

            # Verify password
            if verify_password(password, user.password_hash):
                # Update last login timestamp and IP
                user.last_login_at = datetime.now(timezone.utc)
                if ip_address:
                    user.last_login_ip = ip_address
                await self.session.commit()

                self.logger.info(
                    "User authenticated successfully", username=username, user_id=user.id, ip_address=ip_address
                )
                return user
            else:
                self.logger.warning("Invalid password for user", username=username, user_id=user.id)
                return None

        except Exception as e:
            self.logger.error("Failed to authenticate user", username=username, error=str(e))
            raise

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        is_superuser: bool = False,
        created_by: str = "system",
    ) -> User:
        """
        Create a new user with password hashing.

        Args:
            username: Unique username
            email: Unique email address
            password: Plain text password (will be hashed)
            full_name: Optional full display name
            is_superuser: Whether user has admin privileges
            created_by: User who created this account

        Returns:
            Created user

        Raises:
            ValueError: If username or email already exists or password is empty
            IntegrityError: If database constraints are violated
        """
        try:
            # Validate password
            if not password or not password.strip():
                raise ValueError("Password cannot be empty")

            # Check if username already exists
            existing_user = await self.get_by_username(username)
            if existing_user:
                raise ValueError(f"Username '{username}' already exists")

            # Check if email already exists
            existing_email = await self.get_by_email(email)
            if existing_email:
                raise ValueError(f"Email '{email}' already exists")

            # Create user with hashed password
            user_data: Dict[str, Any] = {
                "username": username,  # Store username as provided
                "email": email.lower(),  # Store email in lowercase
                "password_hash": hash_password(password),
                "full_name": full_name,
                "is_superuser": is_superuser,
                "is_active": True,
                "created_by": created_by,
                "updated_by": created_by,
            }

            user = await self.create(user_data)

            self.logger.info(
                "User created successfully",
                user_id=user.id,
                username=username,
                email=email,
                is_superuser=is_superuser,
                created_by=created_by,
            )

            return user

        except Exception as e:
            self.logger.error("Failed to create user", username=username, email=email, error=str(e))
            raise

    async def update_password(
        self, user_id: str, old_password: str, new_password: str, updated_by: str = "system"
    ) -> bool:
        """
        Update user password.

        Args:
            user_id: User identifier
            old_password: Current password for verification
            new_password: New plain text password (will be hashed)
            updated_by: User who updated the password

        Returns:
            True if password was updated, False if user not found or old password incorrect

        Raises:
            ValueError: If new password is empty
        """
        try:
            # Validate new password
            if not new_password or not new_password.strip():
                raise ValueError("New password cannot be empty")

            # Get user and verify old password
            user = await self.get_by_id(user_id)
            if not user:
                self.logger.warning("User not found for password update", user_id=user_id)
                return False

            # Verify old password
            if not verify_password(old_password, user.password_hash):
                self.logger.warning("Invalid old password for user", user_id=user_id)
                return False

            # Hash the new password
            password_hash = hash_password(new_password)

            # Update user password
            updated_user = await self.update(user_id, password_hash=password_hash, updated_by=updated_by)

            success = updated_user is not None

            if success:
                self.logger.info("User password updated", user_id=user_id, updated_by=updated_by)
            else:
                self.logger.warning("User not found for password update", user_id=user_id)

            return success

        except Exception as e:
            self.logger.error("Failed to update user password", user_id=user_id, error=str(e))
            raise

    async def activate_user(self, user_id: str, activated_by: str = "system") -> bool:
        """
        Activate a user account.

        Args:
            user_id: User identifier
            activated_by: User who activated the account

        Returns:
            True if user was activated, False if not found or already active
        """
        try:
            # Check current state
            user = await self.get_by_id(user_id)
            if not user:
                self.logger.warning("User not found for activation", user_id=user_id)
                return False

            if user.is_active:
                self.logger.debug("User already active", user_id=user_id)
                return False

            # Activate user
            updated_user = await self.update(user_id, is_active=True, updated_by=activated_by)
            success = updated_user is not None
            if success:
                self.logger.info("User activated", user_id=user_id, activated_by=activated_by)

            return success

        except Exception as e:
            self.logger.error("Failed to activate user", user_id=user_id, error=str(e))
            raise

    async def deactivate_user(self, user_id: str, deactivated_by: str = "system") -> bool:
        """
        Deactivate a user account.

        Args:
            user_id: User identifier
            deactivated_by: User who deactivated the account

        Returns:
            True if user was deactivated, False if not found or already inactive
        """
        try:
            # Check current state
            user = await self.get_by_id(user_id)
            if not user:
                self.logger.warning("User not found for deactivation", user_id=user_id)
                return False

            if not user.is_active:
                self.logger.debug("User already inactive", user_id=user_id)
                return False

            # Deactivate user
            updated_user = await self.update(user_id, is_active=False, updated_by=deactivated_by)
            success = updated_user is not None
            if success:
                self.logger.info("User deactivated", user_id=user_id, deactivated_by=deactivated_by)

            return success

        except Exception as e:
            self.logger.error("Failed to deactivate user", user_id=user_id, error=str(e))
            raise

    async def is_username_available(self, username: str, exclude_user_id: Optional[str] = None) -> bool:
        """
        Check if username is available.

        Args:
            username: Username to check
            exclude_user_id: Optional user ID to exclude from check (for updates)

        Returns:
            True if username is available, False otherwise
        """
        try:
            query = select(self.model).where(
                and_(self.model.username.ilike(username.lower()), self.model.is_deleted == False)  # noqa: E712
            )

            # Exclude specific user ID if provided (useful for updates)
            if exclude_user_id:
                query = query.where(self.model.id != exclude_user_id)

            result = await self.session.execute(query)
            existing_user = result.scalar_one_or_none()

            available = existing_user is None
            self.logger.debug("Username availability checked", username=username, available=available)
            return available

        except Exception as e:
            self.logger.error("Failed to check username availability", username=username, error=str(e))
            raise

    async def is_email_available(self, email: str, exclude_user_id: Optional[str] = None) -> bool:
        """
        Check if email address is available.

        Args:
            email: Email address to check
            exclude_user_id: Optional user ID to exclude from check (for updates)

        Returns:
            True if email is available, False otherwise
        """
        try:
            query = select(self.model).where(
                and_(self.model.email.ilike(email.lower()), self.model.is_deleted == False)  # noqa: E712
            )

            # Exclude specific user ID if provided (useful for updates)
            if exclude_user_id:
                query = query.where(self.model.id != exclude_user_id)

            result = await self.session.execute(query)
            existing_user = result.scalar_one_or_none()

            available = existing_user is None
            self.logger.debug("Email availability checked", email=email, available=available)
            return available

        except Exception as e:
            self.logger.error("Failed to check email availability", email=email, error=str(e))
            raise

    async def verify_user(self, user_id: str, verified_by: str = "system") -> bool:
        """
        Verify a user account (mark email as verified).

        Args:
            user_id: User identifier
            verified_by: User who verified the account

        Returns:
            True if user was verified, False if not found or already verified
        """
        try:
            # Get the user
            user = await self.get_by_id(user_id)
            if not user:
                self.logger.warning("User not found for verification", user_id=user_id)
                return False

            # Check if already verified
            if user.is_verified:
                self.logger.info("User already verified", user_id=user_id)
                return False

            # Update verification status
            from datetime import datetime, timezone

            updated_user = await self.update(
                user_id, is_verified=True, verified_at=datetime.now(timezone.utc), updated_by=verified_by
            )

            success = updated_user is not None

            if success:
                self.logger.info("User verified", user_id=user_id, verified_by=verified_by)
            else:
                self.logger.error("Failed to verify user", user_id=user_id)

            return success

        except Exception as e:
            self.logger.error("Failed to verify user", user_id=user_id, error=str(e))
            raise

    async def get_active_users(
        self, page: int = 1, size: int = 50, order_by: str = "created_at", order_desc: bool = True
    ) -> Page[User]:
        """
        Get active users with pagination.

        Args:
            page: Page number
            size: Page size
            order_by: Field to order by
            order_desc: Whether to order descending

        Returns:
            Page of active users
        """
        try:
            # Use list_with_pagination with active filter
            return await self.list_with_pagination(
                page=page, size=size, order_by=order_by, order_desc=order_desc, filters={"is_active": True}
            )

        except Exception as e:
            self.logger.error("Failed to get active users", error=str(e))
            raise

    async def get_unverified_users(self, include_inactive: bool = False, limit: int = 100) -> List[User]:
        """
        Get unverified users.

        Args:
            include_inactive: Whether to include inactive users
            limit: Maximum number of users to return

        Returns:
            List of unverified users
        """
        try:
            # Build query
            query = select(self.model).where(
                and_(self.model.is_verified == False, self.model.is_deleted == False)  # noqa: E712  # noqa: E712
            )

            # Filter by active status unless including inactive
            if not include_inactive:
                query = query.where(self.model.is_active == True)  # noqa: E712

            # Order by creation date (oldest first) and limit
            query = query.order_by(self.model.created_at).limit(limit)

            result = await self.session.execute(query)
            users = list(result.scalars().all())

            self.logger.debug("Retrieved unverified users", count=len(users), include_inactive=include_inactive)

            return users

        except Exception as e:
            self.logger.error("Failed to get unverified users", error=str(e))
            raise

    async def verify_email(self, user_id: str) -> Optional[User]:
        """Verify user email by setting email_verified to True.

        Args:
            user_id: User ID to verify

        Returns:
            Updated user or None if not found
        """
        try:
            # Get user
            user = await self.get_by_id(user_id)
            if not user:
                logger.warning("verify_email_user_not_found", user_id=user_id)
                return None

            # Update email verification status
            user.is_verified = True
            user.updated_at = datetime.utcnow()

            await self.db.commit()
            await self.db.refresh(user)

            logger.info("user_email_verified", user_id=user_id, email=user.email)
            return user

        except Exception as e:
            logger.error("verify_email_error", user_id=user_id, error=str(e))
            await self.db.rollback()
            raise

    async def revoke(self, user_id: str, reason: str = "Manual revocation") -> bool:
        """Revoke user access by deactivating the account.

        Args:
            user_id: User ID to revoke
            reason: Reason for revocation

        Returns:
            True if revoked successfully
        """
        try:
            # Get user
            user = await self.get_by_id(user_id)
            if not user:
                logger.warning("revoke_user_not_found", user_id=user_id)
                return False

            # Deactivate user
            user.is_active = False
            user.updated_at = datetime.utcnow()

            await self.db.commit()

            logger.info("user_revoked", user_id=user_id, reason=reason)
            return True

        except Exception as e:
            logger.error("revoke_user_error", user_id=user_id, error=str(e))
            await self.db.rollback()
            raise

    async def update_last_login(self, user_id: str) -> Optional[User]:
        """Update user's last login timestamp.

        Args:
            user_id: User ID

        Returns:
            Updated user or None if not found
        """
        try:
            # Get user
            user = await self.get_by_id(user_id)
            if not user:
                return None

            # Update last login
            user.last_login_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()

            await self.db.commit()
            await self.db.refresh(user)

            return user

        except Exception as e:
            logger.error("update_last_login_error", user_id=user_id, error=str(e))
            await self.db.rollback()
            raise

    async def change_password(self, user_id: str, new_password_hash: str) -> Optional[User]:
        """Change user password.

        Args:
            user_id: User ID
            new_password_hash: New password hash

        Returns:
            Updated user or None if not found
        """
        try:
            # Get user
            user = await self.get_by_id(user_id)
            if not user:
                return None

            # Update password
            user.password_hash = new_password_hash
            user.updated_at = datetime.utcnow()

            await self.db.commit()
            await self.db.refresh(user)

            logger.info("password_changed", user_id=user_id)
            return user

        except Exception as e:
            logger.error("change_password_error", user_id=user_id, error=str(e))
            await self.db.rollback()
            raise
