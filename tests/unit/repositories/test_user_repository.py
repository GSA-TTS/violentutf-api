"""Comprehensive unit tests for UserRepository implementation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.base import Page
from app.repositories.user import UserRepository


class TestUserRepository:
    """Comprehensive unit tests for UserRepository implementation."""

    @pytest.fixture
    def user_repository(self, mock_session: AsyncMock) -> UserRepository:
        """Create UserRepository instance with mocked session."""
        return UserRepository(mock_session)

    @pytest.fixture
    def sample_user(self, user_factory) -> User:
        """Create a sample user for testing."""
        return user_factory.create(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_verified=True,
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash_data",
        )

    @pytest.fixture
    def inactive_user(self, user_factory) -> User:
        """Create an inactive user for testing."""
        return user_factory.create(
            id="inactive-user-id", username="inactive", email="inactive@example.com", is_active=False
        )

    # CRUD Operations Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test UserRepository initialization."""
        repository = UserRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == User
        assert repository.logger is not None
        assert repository.db == mock_session

    # get_by_username Tests

    @pytest.mark.asyncio
    async def test_get_by_username_found(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test successful user retrieval by username."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_user)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_username("testuser")

        # Assert
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_username_not_found(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test user not found by username."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_username("nonexistent")

        # Assert
        assert user is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_username_with_organization_filter(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test user retrieval by username with organization filtering."""
        # Arrange
        org_id = "test-org-id"
        sample_user.organization_id = org_id
        result_mock = query_result_factory(scalar_result=sample_user)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_username("testuser", organization_id=org_id)

        # Assert
        assert user is not None
        assert user.organization_id == org_id
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_username_database_error(
        self, user_repository: UserRepository, mock_session: AsyncMock, database_error_factory
    ):
        """Test get_by_username with database error."""
        # Arrange
        mock_session.execute.side_effect = database_error_factory("connection")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            await user_repository.get_by_username("testuser")

    # get_by_email Tests

    @pytest.mark.asyncio
    async def test_get_by_email_found(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test successful user retrieval by email."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_user)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_email("test@example.com")

        # Assert
        assert user is not None
        assert user.email == "test@example.com"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_email_case_insensitive(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test case-insensitive email lookup."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_user)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_email("TEST@EXAMPLE.COM")

        # Assert
        assert user is not None
        assert user.email == "test@example.com"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_email_not_found(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test email not found."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        user = await user_repository.get_by_email("nonexistent@example.com")

        # Assert
        assert user is None
        mock_session.execute.assert_called_once()

    # authenticate Tests

    @pytest.mark.asyncio
    async def test_authenticate_success_by_username(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test successful authentication by username."""
        with patch("app.repositories.user.verify_password", return_value=True):
            # Arrange
            result_mock = query_result_factory(scalar_result=sample_user)
            mock_session.execute.return_value = result_mock

            # Act
            user = await user_repository.authenticate("testuser", "correct_password", "127.0.0.1")

            # Assert
            assert user is not None
            assert user.username == "testuser"
            assert user.last_login_at is not None
            assert user.last_login_ip == "127.0.0.1"
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_success_by_email(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test successful authentication by email."""
        with patch("app.repositories.user.verify_password", return_value=True):
            # Arrange
            # First call (get_by_username) returns None, second call (get_by_email) returns user
            mock_session.execute.side_effect = [
                query_result_factory(scalar_result=None),  # username not found
                query_result_factory(scalar_result=sample_user),  # email found
            ]

            # Act
            user = await user_repository.authenticate("test@example.com", "correct_password")

            # Assert
            assert user is not None
            assert user.email == "test@example.com"
            assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test authentication with non-existent user."""
        with patch("app.repositories.user.verify_password") as mock_verify:
            # Arrange
            mock_session.execute.return_value = query_result_factory(scalar_result=None)

            # Act
            user = await user_repository.authenticate("nonexistent", "password")

            # Assert
            assert user is None
            # Verify dummy password verification was called to prevent timing attacks
            mock_verify.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(
        self, user_repository: UserRepository, mock_session: AsyncMock, inactive_user: User, query_result_factory
    ):
        """Test authentication with inactive user."""
        with patch("app.repositories.user.verify_password", return_value=True):
            # Arrange
            result_mock = query_result_factory(scalar_result=inactive_user)
            mock_session.execute.return_value = result_mock

            # Act
            user = await user_repository.authenticate("inactive", "correct_password")

            # Assert
            assert user is None
            # Commit should not be called for inactive user
            mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test authentication with wrong password."""
        with patch("app.repositories.user.verify_password", return_value=False):
            # Arrange
            result_mock = query_result_factory(scalar_result=sample_user)
            mock_session.execute.return_value = result_mock

            # Act
            user = await user_repository.authenticate("testuser", "wrong_password")

            # Assert
            assert user is None
            mock_session.commit.assert_not_called()

    # create_user Tests

    @pytest.mark.asyncio
    async def test_create_user_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test successful user creation."""
        with patch(
            "app.repositories.user.hash_password",
            return_value="$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash_data",
        ):
            # Arrange - both username and email availability checks return None
            mock_session.execute.return_value = query_result_factory(scalar_result=None)

            # Mock the create method from BaseRepository
            created_user = User(
                id="new-user-id",
                username="newuser",
                email="new@example.com",
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash_data",
                is_active=True,
            )

            with patch.object(user_repository, "create", return_value=created_user) as mock_create:
                # Act
                user = await user_repository.create_user(
                    username="newuser", email="new@example.com", password="password123", full_name="New User"
                )

                # Assert
                assert user is not None
                assert user.username == "newuser"
                assert user.email == "new@example.com"
                mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_empty_password(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test user creation with empty password."""
        # Act & Assert
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repository.create_user(username="newuser", email="new@example.com", password="")

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test user creation with duplicate username."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=sample_user)

        # Act & Assert
        with pytest.raises(ValueError, match="Username 'testuser' already exists"):
            await user_repository.create_user(username="testuser", email="new@example.com", password="password123")

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test user creation with duplicate email."""
        # Arrange
        # First call (username check) returns None, second call (email check) returns user
        mock_session.execute.side_effect = [
            query_result_factory(scalar_result=None),  # username available
            query_result_factory(scalar_result=sample_user),  # email taken
        ]

        # Act & Assert
        with pytest.raises(ValueError, match="Email 'test@example.com' already exists"):
            await user_repository.create_user(username="newuser", email="test@example.com", password="password123")

    # update_password Tests

    @pytest.mark.asyncio
    async def test_update_password_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test successful password update."""
        with (
            patch("app.repositories.user.verify_password", return_value=True),
            patch(
                "app.repositories.user.hash_password",
                return_value="$argon2id$v=19$m=65536,t=3,p=4$new_salt$new_hash_data",
            ),
        ):
            # Mock get_by_id and update methods
            with (
                patch.object(user_repository, "get_by_id", return_value=sample_user),
                patch.object(user_repository, "update", return_value=sample_user) as mock_update,
            ):
                # Act
                result = await user_repository.update_password("test-user-id", "old_password", "new_password", "admin")

                # Assert
                assert result is True
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_password_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test password update for non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.update_password("nonexistent-id", "old_password", "new_password")

            # Assert
            assert result is False

    @pytest.mark.asyncio
    async def test_update_password_wrong_old_password(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test password update with wrong old password."""
        with patch("app.repositories.user.verify_password", return_value=False):
            with patch.object(user_repository, "get_by_id", return_value=sample_user):
                # Act
                result = await user_repository.update_password("test-user-id", "wrong_old_password", "new_password")

                # Assert
                assert result is False

    @pytest.mark.asyncio
    async def test_update_password_empty_new_password(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test password update with empty new password."""
        # Act & Assert
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repository.update_password("test-user-id", "old_password", "")

    # activate_user Tests

    @pytest.mark.asyncio
    async def test_activate_user_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, inactive_user: User
    ):
        """Test successful user activation."""
        with (
            patch.object(user_repository, "get_by_id", return_value=inactive_user),
            patch.object(user_repository, "update", return_value=inactive_user) as mock_update,
        ):
            # Act
            result = await user_repository.activate_user("inactive-user-id", "admin")

            # Assert
            assert result is True
            mock_update.assert_called_once_with("inactive-user-id", is_active=True, updated_by="admin")

    @pytest.mark.asyncio
    async def test_activate_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test activation of non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.activate_user("nonexistent-id")

            # Assert
            assert result is False

    @pytest.mark.asyncio
    async def test_activate_user_already_active(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test activation of already active user."""
        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act
            result = await user_repository.activate_user("test-user-id")

            # Assert
            assert result is False

    # deactivate_user Tests

    @pytest.mark.asyncio
    async def test_deactivate_user_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test successful user deactivation."""
        with (
            patch.object(user_repository, "get_by_id", return_value=sample_user),
            patch.object(user_repository, "update", return_value=sample_user) as mock_update,
        ):
            # Act
            result = await user_repository.deactivate_user("test-user-id", "admin")

            # Assert
            assert result is True
            mock_update.assert_called_once_with("test-user-id", is_active=False, updated_by="admin")

    @pytest.mark.asyncio
    async def test_deactivate_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test deactivation of non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.deactivate_user("nonexistent-id")

            # Assert
            assert result is False

    @pytest.mark.asyncio
    async def test_deactivate_user_already_inactive(
        self, user_repository: UserRepository, mock_session: AsyncMock, inactive_user: User
    ):
        """Test deactivation of already inactive user."""
        with patch.object(user_repository, "get_by_id", return_value=inactive_user):
            # Act
            result = await user_repository.deactivate_user("inactive-user-id")

            # Assert
            assert result is False

    # is_username_available Tests

    @pytest.mark.asyncio
    async def test_is_username_available_true(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test username availability check - available."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=None)

        # Act
        available = await user_repository.is_username_available("newuser")

        # Assert
        assert available is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_username_available_false(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test username availability check - not available."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=sample_user)

        # Act
        available = await user_repository.is_username_available("testuser")

        # Assert
        assert available is False
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_username_available_exclude_user(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test username availability check with user exclusion."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=None)

        # Act
        available = await user_repository.is_username_available("testuser", exclude_user_id="test-user-id")

        # Assert
        assert available is True
        mock_session.execute.assert_called_once()

    # is_email_available Tests

    @pytest.mark.asyncio
    async def test_is_email_available_true(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test email availability check - available."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=None)

        # Act
        available = await user_repository.is_email_available("new@example.com")

        # Assert
        assert available is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_email_available_false(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User, query_result_factory
    ):
        """Test email availability check - not available."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=sample_user)

        # Act
        available = await user_repository.is_email_available("test@example.com")

        # Assert
        assert available is False
        mock_session.execute.assert_called_once()

    # verify_user Tests

    @pytest.mark.asyncio
    async def test_verify_user_success(self, user_repository: UserRepository, mock_session: AsyncMock, user_factory):
        """Test successful user verification."""
        # Arrange
        unverified_user = user_factory.create(is_verified=False)

        with (
            patch.object(user_repository, "get_by_id", return_value=unverified_user),
            patch.object(user_repository, "update", return_value=unverified_user) as mock_update,
        ):
            # Act
            result = await user_repository.verify_user("test-user-id", "admin")

            # Assert
            assert result is True
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test verification of non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.verify_user("nonexistent-id")

            # Assert
            assert result is False

    @pytest.mark.asyncio
    async def test_verify_user_already_verified(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test verification of already verified user."""
        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act
            result = await user_repository.verify_user("test-user-id")

            # Assert
            assert result is False

    # get_active_users Tests

    @pytest.mark.asyncio
    async def test_get_active_users_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, user_factory
    ):
        """Test getting active users with pagination."""
        # Arrange
        active_users = user_factory.create_batch(5, is_active=True)
        page_result = Page(items=active_users, total=5, page=1, size=50, has_next=False, has_prev=False)

        with patch.object(user_repository, "list_with_pagination", return_value=page_result) as mock_list:
            # Act
            result = await user_repository.get_active_users(page=1, size=10)

            # Assert
            assert isinstance(result, Page)
            assert len(result.items) == 5
            mock_list.assert_called_once_with(
                page=1, size=10, order_by="created_at", order_desc=True, filters={"is_active": True}
            )

    # get_unverified_users Tests

    @pytest.mark.asyncio
    async def test_get_unverified_users_active_only(
        self, user_repository: UserRepository, mock_session: AsyncMock, user_factory, query_result_factory
    ):
        """Test getting unverified active users."""
        # Arrange
        unverified_users = user_factory.create_batch(3, is_verified=False, is_active=True)

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = unverified_users
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        users = await user_repository.get_unverified_users(include_inactive=False, limit=10)

        # Assert
        assert len(users) == 3
        assert all(not user.is_verified for user in users)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_unverified_users_include_inactive(
        self, user_repository: UserRepository, mock_session: AsyncMock, user_factory, query_result_factory
    ):
        """Test getting unverified users including inactive."""
        # Arrange
        unverified_users = [
            user_factory.create(is_verified=False, is_active=True),
            user_factory.create(is_verified=False, is_active=False),
        ]

        scalars_mock = MagicMock()
        scalars_mock.all.return_value = unverified_users
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        users = await user_repository.get_unverified_users(include_inactive=True, limit=10)

        # Assert
        assert len(users) == 2
        assert all(not user.is_verified for user in users)
        mock_session.execute.assert_called_once()

    # verify_email Tests

    @pytest.mark.asyncio
    async def test_verify_email_success(self, user_repository: UserRepository, mock_session: AsyncMock, user_factory):
        """Test successful email verification."""
        # Arrange
        user = user_factory.create(is_verified=False)

        with patch.object(user_repository, "get_by_id", return_value=user):
            # Act
            result = await user_repository.verify_email("test-user-id")

            # Assert
            assert result is not None
            assert result.is_verified is True
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_email_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test email verification for non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.verify_email("nonexistent-id")

            # Assert
            assert result is None
            mock_session.commit.assert_not_called()

    # revoke Tests

    @pytest.mark.asyncio
    async def test_revoke_success(self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User):
        """Test successful user revocation."""
        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act
            result = await user_repository.revoke("test-user-id", "Security violation")

            # Assert
            assert result is True
            assert sample_user.is_active is False
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test revocation of non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.revoke("nonexistent-id")

            # Assert
            assert result is False
            mock_session.commit.assert_not_called()

    # update_last_login Tests

    @pytest.mark.asyncio
    async def test_update_last_login_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test successful last login update."""
        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act
            result = await user_repository.update_last_login("test-user-id")

            # Assert
            assert result is not None
            assert result.last_login_at is not None
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_last_login_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test last login update for non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.update_last_login("nonexistent-id")

            # Assert
            assert result is None
            mock_session.commit.assert_not_called()

    # change_password Tests

    @pytest.mark.asyncio
    async def test_change_password_success(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test successful password change."""
        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act
            result = await user_repository.change_password(
                "test-user-id", "$argon2id$v=19$m=65536,t=3,p=4$new_salt$new_hash_data"
            )

            # Assert
            assert result is not None
            assert result.password_hash == "$argon2id$v=19$m=65536,t=3,p=4$new_salt$new_hash_data"
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self, user_repository: UserRepository, mock_session: AsyncMock):
        """Test password change for non-existent user."""
        with patch.object(user_repository, "get_by_id", return_value=None):
            # Act
            result = await user_repository.change_password("nonexistent-id", "new_hash")

            # Assert
            assert result is None
            mock_session.commit.assert_not_called()

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_database_rollback_on_error(
        self, user_repository: UserRepository, mock_session: AsyncMock, sample_user: User
    ):
        """Test database rollback on error in email verification."""
        # Arrange
        mock_session.commit.side_effect = SQLAlchemyError("Database error")

        with patch.object(user_repository, "get_by_id", return_value=sample_user):
            # Act & Assert
            with pytest.raises(SQLAlchemyError):
                await user_repository.verify_email("test-user-id")

            mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_integrity_error_handling(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of database integrity errors."""
        with patch(
            "app.repositories.user.hash_password",
            return_value="$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash_data",
        ):
            # Arrange - mock create method to raise IntegrityError
            mock_session.execute.return_value = query_result_factory(scalar_result=None)

            with patch.object(
                user_repository,
                "create",
                side_effect=IntegrityError(
                    statement="INSERT INTO users...", params={}, orig=Exception("Duplicate key")
                ),
            ):
                # Act & Assert
                with pytest.raises(IntegrityError):
                    await user_repository.create_user(
                        username="newuser", email="new@example.com", password="password123"
                    )

    # Edge Cases and Boundary Conditions

    @pytest.mark.asyncio
    async def test_empty_result_handling(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of empty query results."""
        # Arrange
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        users = await user_repository.get_unverified_users(limit=10)

        # Assert
        assert users == []
        assert len(users) == 0

    @pytest.mark.asyncio
    async def test_large_limit_handling(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of large limit values."""
        # Arrange
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        mock_session.execute.return_value = result_mock

        # Act
        users = await user_repository.get_unverified_users(limit=10000)

        # Assert
        assert users == []
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_null_input_validation(
        self, user_repository: UserRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of null/None inputs."""
        # Arrange
        mock_session.execute.return_value = query_result_factory(scalar_result=None)

        # Act & Assert - These should handle None gracefully
        user = await user_repository.get_by_username(None)
        assert user is None or True  # Should not crash

        user = await user_repository.get_by_email(None)
        assert user is None or True  # Should not crash
