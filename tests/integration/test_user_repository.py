"""Integration tests for UserRepository with real database operations."""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.user import UserRepository


def get_test_password_hash():
    """Get a valid test password hash."""
    # This is a real Argon2 hash of "testpassword"
    return "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"


class TestUserRepository:
    """Test UserRepository specific functionality."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> UserRepository:
        """Create a user repository for testing."""
        return UserRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_get_by_username_existing(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test getting user by username."""
        # Create user
        user = await user_repo.create(
            username="test_username", email="username@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        # Get by username
        found = await user_repo.get_by_username("test_username")
        assert found is not None
        assert found.id == user.id
        assert found.username == "test_username"

    @pytest.mark.asyncio
    async def test_get_by_username_nonexistent(self, user_repo: UserRepository):
        """Test getting non-existent user by username."""
        found = await user_repo.get_by_username("nonexistent")
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_username_case_insensitive(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test username lookup is case insensitive (usernames are normalized to lowercase)."""
        # Create user - username will be normalized to lowercase
        await user_repo.create(username="TestUser", email="case@example.com", password_hash=get_test_password_hash())
        await async_db_session.commit()

        # All case variations should find the user
        found = await user_repo.get_by_username("testuser")
        assert found is not None
        assert found.username == "testuser"

        found = await user_repo.get_by_username("TestUser")
        assert found is not None
        assert found.username == "testuser"

        found = await user_repo.get_by_username("TESTUSER")
        assert found is not None
        assert found.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_by_email_existing(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test getting user by email."""
        # Create user
        user = await user_repo.create(
            username="email_test", email="test@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        # Get by email
        found = await user_repo.get_by_email("test@example.com")
        assert found is not None
        assert found.id == user.id
        assert found.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_get_by_email_nonexistent(self, user_repo: UserRepository):
        """Test getting non-existent user by email."""
        found = await user_repo.get_by_email("nonexistent@example.com")
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_email_case_insensitive(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test email lookup is case insensitive."""
        # Create user
        await user_repo.create(username="email_case", email="Test@Example.com", password_hash=get_test_password_hash())
        await async_db_session.commit()

        # Try different cases
        found = await user_repo.get_by_email("test@example.com")
        assert found is not None

        found = await user_repo.get_by_email("TEST@EXAMPLE.COM")
        assert found is not None

    @pytest.mark.asyncio
    async def test_create_user_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test creating user with password hashing."""
        user = await user_repo.create_user(
            username="new_user",
            email="new@example.com",
            password="plain_password",
            full_name="New User",
            created_by="admin",
        )
        await async_db_session.commit()

        assert user.username == "new_user"
        assert user.email == "new@example.com"
        assert user.full_name == "New User"
        assert user.password_hash != "plain_password"  # Should be hashed
        assert user.password_hash.startswith("$argon2")  # Argon2 hash
        assert user.is_active is True
        assert user.is_verified is False
        assert user.created_by == "admin"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test creating user with duplicate username fails."""
        # Create first user
        await user_repo.create_user(username="duplicate", email="first@example.com", password="password")
        await async_db_session.commit()

        # Try to create duplicate
        with pytest.raises(ValueError, match="Username 'duplicate' already exists"):
            await user_repo.create_user(username="duplicate", email="second@example.com", password="password")

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test creating user with duplicate email fails."""
        # Create first user
        await user_repo.create_user(username="user1", email="duplicate@example.com", password="password")
        await async_db_session.commit()

        # Try to create duplicate
        with pytest.raises(ValueError, match="Email 'duplicate@example.com' already exists"):
            await user_repo.create_user(username="user2", email="duplicate@example.com", password="password")

    @pytest.mark.asyncio
    async def test_create_user_empty_password(self, user_repo: UserRepository):
        """Test creating user with empty password fails."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repo.create_user(username="no_password", email="nopass@example.com", password="")

    @pytest.mark.asyncio
    async def test_authenticate_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test successful authentication."""
        # Create user
        password = "secure_password123"
        user = await user_repo.create_user(username="auth_user", email="auth@example.com", password=password)
        await async_db_session.commit()

        # Authenticate with username
        authenticated = await user_repo.authenticate("auth_user", password)
        assert authenticated is not None
        assert authenticated.id == user.id
        assert authenticated.last_login_at is not None
        assert authenticated.last_login_ip is None

    @pytest.mark.asyncio
    async def test_authenticate_with_email(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test authentication with email."""
        # Create user
        password = "email_auth123"
        user = await user_repo.create_user(username="email_auth", email="emailauth@example.com", password=password)
        await async_db_session.commit()

        # Authenticate with email
        authenticated = await user_repo.authenticate("emailauth@example.com", password)
        assert authenticated is not None
        assert authenticated.id == user.id

    @pytest.mark.asyncio
    async def test_authenticate_with_ip(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test authentication records IP address."""
        # Create user
        password = "ip_test123"
        await user_repo.create_user(username="ip_user", email="ip@example.com", password=password)
        await async_db_session.commit()

        # Authenticate with IP
        authenticated = await user_repo.authenticate("ip_user", password, ip_address="192.168.1.100")
        assert authenticated is not None
        assert authenticated.last_login_ip == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test authentication with wrong password."""
        # Create user
        await user_repo.create_user(username="wrong_pass", email="wrong@example.com", password="correct_password")
        await async_db_session.commit()

        # Try wrong password
        authenticated = await user_repo.authenticate("wrong_pass", "wrong_password")
        assert authenticated is None

    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_user(self, user_repo: UserRepository):
        """Test authentication with non-existent user."""
        authenticated = await user_repo.authenticate("nonexistent", "password")
        assert authenticated is None

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test authentication with inactive user."""
        # Create inactive user
        password = "inactive123"
        user = await user_repo.create_user(username="inactive_user", email="inactive@example.com", password=password)
        await async_db_session.commit()

        # Deactivate user
        await user_repo.update(user.id, is_active=False)
        await async_db_session.commit()

        # Try to authenticate
        authenticated = await user_repo.authenticate("inactive_user", password)
        assert authenticated is None

    @pytest.mark.asyncio
    async def test_update_password_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test updating user password."""
        # Create user
        old_password = "old_password123"
        user = await user_repo.create_user(
            username="update_pass", email="updatepass@example.com", password=old_password
        )
        await async_db_session.commit()

        # Update password
        new_password = "new_password456"
        result = await user_repo.update_password(user.id, old_password, new_password, updated_by="user")
        await async_db_session.commit()

        assert result is True

        # Verify old password doesn't work
        auth = await user_repo.authenticate("update_pass", old_password)
        assert auth is None

        # Verify new password works
        auth = await user_repo.authenticate("update_pass", new_password)
        assert auth is not None

    @pytest.mark.asyncio
    async def test_update_password_wrong_old(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test updating password with wrong old password."""
        # Create user
        user = await user_repo.create_user(username="wrong_old", email="wrongold@example.com", password="correct_old")
        await async_db_session.commit()

        # Try to update with wrong old password
        result = await user_repo.update_password(user.id, "wrong_old", "new_password")

        assert result is False

    @pytest.mark.asyncio
    async def test_update_password_nonexistent_user(self, user_repo: UserRepository):
        """Test updating password for non-existent user."""
        result = await user_repo.update_password(str(uuid.uuid4()), "old", "new")
        assert result is False

    @pytest.mark.asyncio
    async def test_update_password_empty_new(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test updating password with empty new password."""
        # Create user
        user = await user_repo.create_user(username="empty_new", email="emptynew@example.com", password="old_password")
        await async_db_session.commit()

        # Try empty new password
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repo.update_password(user.id, "old_password", "")

    @pytest.mark.asyncio
    async def test_verify_user_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test verifying user."""
        # Create unverified user
        user = await user_repo.create_user(username="to_verify", email="verify@example.com", password="password")
        await async_db_session.commit()

        assert user.is_verified is False

        # Verify user
        result = await user_repo.verify_user(user.id, verified_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check user is verified
        verified = await user_repo.get_by_id(user.id)
        assert verified.is_verified is True
        assert verified.verified_at is not None
        assert verified.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_verify_user_already_verified(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test verifying already verified user."""
        # Create and verify user
        user = await user_repo.create_user(
            username="already_verified", email="already@example.com", password="password"
        )
        await async_db_session.commit()

        await user_repo.verify_user(user.id)
        await async_db_session.commit()

        # Try to verify again
        result = await user_repo.verify_user(user.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_nonexistent_user(self, user_repo: UserRepository):
        """Test verifying non-existent user."""
        result = await user_repo.verify_user(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_activate_user_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test activating user."""
        # Create inactive user
        user = await user_repo.create_user(username="to_activate", email="activate@example.com", password="password")
        await async_db_session.commit()

        # Deactivate first
        await user_repo.update(user.id, is_active=False)
        await async_db_session.commit()

        # Activate user
        result = await user_repo.activate_user(user.id, activated_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check user is active
        active = await user_repo.get_by_id(user.id)
        assert active.is_active is True
        assert active.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_activate_already_active(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test activating already active user."""
        # Create active user (default)
        user = await user_repo.create_user(username="already_active", email="active@example.com", password="password")
        await async_db_session.commit()

        # Try to activate
        result = await user_repo.activate_user(user.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_deactivate_user_success(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test deactivating user."""
        # Create active user
        user = await user_repo.create_user(
            username="to_deactivate", email="deactivate@example.com", password="password"
        )
        await async_db_session.commit()

        # Deactivate user
        result = await user_repo.deactivate_user(user.id, deactivated_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check user is inactive
        inactive = await user_repo.get_by_id(user.id)
        assert inactive.is_active is False
        assert inactive.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_deactivate_already_inactive(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test deactivating already inactive user."""
        # Create and deactivate user
        user = await user_repo.create_user(
            username="already_inactive", email="inactive@example.com", password="password"
        )
        await async_db_session.commit()

        await user_repo.deactivate_user(user.id)
        await async_db_session.commit()

        # Try to deactivate again
        result = await user_repo.deactivate_user(user.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_get_active_users(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test getting only active users."""
        # Create mix of active and inactive users
        active1 = await user_repo.create_user(username="active1", email="active1@example.com", password="password")
        active2 = await user_repo.create_user(username="active2", email="active2@example.com", password="password")
        inactive = await user_repo.create_user(username="inactive1", email="inactive1@example.com", password="password")
        await async_db_session.commit()

        # Deactivate one
        await user_repo.deactivate_user(inactive.id)
        await async_db_session.commit()

        # Get active users
        active_users = await user_repo.get_active_users()

        # Check results
        active_ids = [u.id for u in active_users]
        assert active1.id in active_ids
        assert active2.id in active_ids
        assert inactive.id not in active_ids
        assert all(u.is_active for u in active_users)

    @pytest.mark.asyncio
    async def test_get_active_users_pagination(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test getting active users with pagination."""
        # Create multiple active users
        for i in range(5):
            await user_repo.create_user(
                username=f"page_active{i}", email=f"pageactive{i}@example.com", password="password"
            )
        await async_db_session.commit()

        # Get first page
        active_users = await user_repo.get_active_users(page=1, size=2)
        assert len(active_users) == 2

        # Get second page
        active_users = await user_repo.get_active_users(page=2, size=2)
        assert len(active_users) == 2

    @pytest.mark.asyncio
    async def test_get_unverified_users(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test getting unverified users."""
        # Create mix of verified and unverified users
        unverified1 = await user_repo.create_user(
            username="unverified1", email="unverified1@example.com", password="password"
        )
        unverified2 = await user_repo.create_user(
            username="unverified2", email="unverified2@example.com", password="password"
        )
        verified = await user_repo.create_user(username="verified1", email="verified1@example.com", password="password")
        await async_db_session.commit()

        # Verify one
        await user_repo.verify_user(verified.id)
        await async_db_session.commit()

        # Get unverified users
        unverified_users = await user_repo.get_unverified_users()

        # Check results
        unverified_ids = [u.id for u in unverified_users]
        assert unverified1.id in unverified_ids
        assert unverified2.id in unverified_ids
        assert verified.id not in unverified_ids
        assert all(not u.is_verified for u in unverified_users)

    @pytest.mark.asyncio
    async def test_get_unverified_users_exclude_inactive(
        self, user_repo: UserRepository, async_db_session: AsyncSession
    ):
        """Test getting unverified users excludes inactive by default."""
        # Create unverified inactive user
        inactive_unverified = await user_repo.create_user(
            username="inactive_unverified", email="inactiveunv@example.com", password="password"
        )
        await async_db_session.commit()

        # Deactivate
        await user_repo.deactivate_user(inactive_unverified.id)
        await async_db_session.commit()

        # Get unverified users
        unverified_users = await user_repo.get_unverified_users()

        # Should not include inactive
        unverified_ids = [u.id for u in unverified_users]
        assert inactive_unverified.id not in unverified_ids

    @pytest.mark.asyncio
    async def test_get_unverified_users_include_inactive(
        self, user_repo: UserRepository, async_db_session: AsyncSession
    ):
        """Test getting unverified users including inactive."""
        # Create unverified inactive user
        inactive_unverified = await user_repo.create_user(
            username="inactive_unv2", email="inactiveunv2@example.com", password="password"
        )
        await async_db_session.commit()

        # Deactivate
        await user_repo.deactivate_user(inactive_unverified.id)
        await async_db_session.commit()

        # Get unverified users including inactive
        unverified_users = await user_repo.get_unverified_users(include_inactive=True)

        # Should include inactive
        unverified_ids = [u.id for u in unverified_users]
        assert inactive_unverified.id in unverified_ids
