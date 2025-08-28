"""Comprehensive unit tests for APIKeyRepository implementation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.repositories.api_key import APIKeyRepository
from app.repositories.base import Page


class TestAPIKeyRepository:
    """Comprehensive unit tests for APIKeyRepository implementation."""

    @pytest.fixture
    def api_key_repository(self, mock_session: AsyncMock) -> APIKeyRepository:
        """Create APIKeyRepository instance with mocked session."""
        return APIKeyRepository(mock_session)

    @pytest.fixture
    def sample_api_key(self, api_key_factory) -> APIKey:
        """Create a sample API key for testing."""
        return api_key_factory.create(
            id="test-api-key-id",
            name="Test API Key",
            key_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            user_id="test-user-id",
            permissions={"read": True, "write": True},
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_at=datetime.now(timezone.utc),
        )

    @pytest.fixture
    def expired_api_key(self, api_key_factory) -> APIKey:
        """Create an expired API key for testing."""
        return api_key_factory.create(
            id="expired-api-key-id",
            name="Expired API Key",
            key_hash="c1d2e3f4a5b6789012345678901bcdef1234567890abcdef1234567890abcdef",
            user_id="test-user-id",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            created_at=datetime.now(timezone.utc) - timedelta(days=31),
        )

    @pytest.fixture
    def inactive_api_key(self, api_key_factory) -> APIKey:
        """Create an inactive API key for testing."""
        return api_key_factory.create(
            id="inactive-api-key-id",
            name="Inactive API Key",
            key_hash="b1c2d3e4f5678901234567890abcdef1234567890abcdef1234567890abcdef1",
            user_id="test-user-id",
            revoked_at=datetime.now(timezone.utc) - timedelta(hours=1),
            created_at=datetime.now(timezone.utc),
        )

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test APIKeyRepository initialization."""
        repository = APIKeyRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == APIKey
        assert repository.logger is not None

    # Interface Method Tests

    @pytest.mark.asyncio
    async def test_get_by_key_hash_interface_method(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        query_result_factory,
    ):
        """Test get_by_key_hash interface method delegates to get_by_hash."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_api_key)
        mock_session.execute.return_value = result_mock

        # Act
        api_key = await api_key_repository.get_by_key_hash(
            "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        )

        # Assert
        assert api_key is not None
        assert api_key.key_hash == "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        mock_session.execute.assert_called_once()

    # get_by_hash Tests

    @pytest.mark.asyncio
    async def test_get_by_hash_found(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        query_result_factory,
    ):
        """Test successful API key retrieval by hash."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_api_key)
        mock_session.execute.return_value = result_mock

        # Act
        api_key = await api_key_repository.get_by_hash(
            "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        )

        # Assert
        assert api_key is not None
        assert api_key.key_hash == "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        assert api_key.name == "Test API Key"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_hash_not_found(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test API key not found by hash."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        api_key = await api_key_repository.get_by_hash("nonexistent_hash")

        # Assert
        assert api_key is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_hash_with_organization_filtering(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        query_result_factory,
    ):
        """Test API key retrieval by hash with organization filtering."""
        # Arrange
        sample_api_key.organization_id = "test-org-id"
        result_mock = query_result_factory(scalar_result=sample_api_key)
        mock_session.execute.return_value = result_mock

        # Act
        api_key = await api_key_repository.get_by_hash(
            "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef", organization_id="test-org-id"
        )

        # Assert
        assert api_key is not None
        assert api_key.organization_id == "test-org-id"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_hash_database_error(self, api_key_repository: APIKeyRepository, mock_session: AsyncMock):
        """Test database error handling in get_by_hash."""
        # Arrange
        mock_session.execute.side_effect = SQLAlchemyError("Database connection failed")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            await api_key_repository.get_by_hash("a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef")

    # get_user_api_keys Tests

    @pytest.mark.asyncio
    async def test_get_user_api_keys_active_only(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        query_result_factory,
    ):
        """Test retrieving active API keys for a user."""
        # Arrange
        api_keys = [sample_api_key]
        result_mock = query_result_factory(data=api_keys)
        mock_session.execute.return_value = result_mock

        # Act
        user_keys = await api_key_repository.get_user_api_keys("test-user-id", include_inactive=False)

        # Assert
        assert len(user_keys) == 1
        assert user_keys[0].user_id == "test-user-id"
        assert user_keys[0].is_active() is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_api_keys_include_inactive(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        inactive_api_key: APIKey,
        query_result_factory,
    ):
        """Test retrieving all API keys for a user including inactive ones."""
        # Arrange
        api_keys = [sample_api_key, inactive_api_key]
        result_mock = query_result_factory(data=api_keys)
        mock_session.execute.return_value = result_mock

        # Act
        user_keys = await api_key_repository.get_user_api_keys("test-user-id", include_inactive=True)

        # Assert
        assert len(user_keys) == 2
        assert any(key.is_active() is True for key in user_keys)
        assert any(key.is_active() is False for key in user_keys)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_api_keys_empty_result(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test retrieving API keys for user with no keys."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        user_keys = await api_key_repository.get_user_api_keys("user-with-no-keys")

        # Assert
        assert user_keys == []
        mock_session.execute.assert_called_once()

    # create_api_key Tests

    @pytest.mark.asyncio
    async def test_create_api_key_success(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, api_key_factory
    ):
        """Test successful API key creation."""
        # Arrange
        new_api_key = api_key_factory.create(
            id="new-api-key-id",
            name="New API Key",
            key_hash="c3d4e5f6789012345678901cdef123456789012cdef123456789012cdef12345",
            user_id="test-user-id",
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.api_key.APIKey", return_value=new_api_key),
            patch.object(api_key_repository, "get_by_name_and_user", return_value=None),
        ):
            # Act
            created_key = await api_key_repository.create_api_key(
                user_id="test-user-id",
                name="New API Key",
                key_hash="c3d4e5f6789012345678901cdef123456789012cdef123456789012cdef12345",
                key_prefix="test_new",
                permissions={"read": True},
            )

            # Assert
            assert created_key is not None
            assert created_key.name == "New API Key"
            assert created_key.user_id == "test-user-id"
            mock_session.add.assert_called_once()
            mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_api_key_with_expiration(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, api_key_factory
    ):
        """Test API key creation with expiration date."""
        # Arrange
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        new_api_key = api_key_factory.create(
            id="new-api-key-id",
            name="Expiring API Key",
            key_hash="d4e5f6a7890123456789012def34567890123def34567890123def34567890ab",
            user_id="test-user-id",
            expires_at=expires_at,
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.api_key.APIKey", return_value=new_api_key),
            patch.object(api_key_repository, "get_by_name_and_user", return_value=None),
        ):
            # Act
            created_key = await api_key_repository.create_api_key(
                user_id="test-user-id",
                name="Expiring API Key",
                key_hash="d4e5f6a7890123456789012def34567890123def34567890123def34567890ab",
                key_prefix="test_exp",
                expires_at=expires_at,
            )

            # Assert
            assert created_key is not None
            assert created_key.expires_at == expires_at
            mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_api_key_database_error(self, api_key_repository: APIKeyRepository, mock_session: AsyncMock):
        """Test database error handling in API key creation."""
        # Arrange
        mock_session.flush.side_effect = IntegrityError("Duplicate key", None, None)
        mock_session.rollback.return_value = None

        # Mock the name check to return None so we get to the IntegrityError
        with patch.object(api_key_repository, "get_by_name_and_user", return_value=None):
            # Act & Assert
            with pytest.raises(IntegrityError):
                await api_key_repository.create_api_key(
                    user_id="test-user-id",
                    name="Duplicate Key",
                    key_hash="e5f6a7b8901234567890123def456789012cdef456789012cdef456789012cde",
                    key_prefix="test_dup",
                )

    # revoke_api_key Tests

    @pytest.mark.asyncio
    async def test_revoke_api_key_success(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        sample_api_key: APIKey,
        query_result_factory,
    ):
        """Test successful API key revocation."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_api_key)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None
        mock_session.commit.return_value = None

        # Act
        success = await api_key_repository.revoke_api_key("test-api-key-id", revoked_by="admin")

        # Assert
        assert success is True
        assert sample_api_key.is_active() is False
        assert sample_api_key.revoked_at is not None
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test revoking non-existent API key."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        success = await api_key_repository.revoke_api_key("nonexistent-key-id")

        # Assert
        assert success is False
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_api_key_already_revoked(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        inactive_api_key: APIKey,
        query_result_factory,
    ):
        """Test revoking already revoked API key."""
        # Arrange - mock get_by_id to return inactive (already revoked) key
        with patch.object(api_key_repository, "get_by_id", return_value=inactive_api_key):
            # Act
            success = await api_key_repository.revoke_api_key("inactive-api-key-id")

            # Assert - should return False since key is already revoked
            assert success is False
            mock_session.commit.assert_not_called()

    # revoke_user_api_keys Tests

    @pytest.mark.asyncio
    async def test_revoke_user_api_keys_success(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, api_key_factory
    ):
        """Test successful revocation of all user API keys."""
        # Arrange - create 3 test keys
        test_keys = [
            api_key_factory.create(id="key-1", user_id="test-user-id"),
            api_key_factory.create(id="key-2", user_id="test-user-id"),
            api_key_factory.create(id="key-3", user_id="test-user-id"),
        ]

        # Mock get_user_api_keys to return the test keys
        with (
            patch.object(api_key_repository, "get_user_api_keys", return_value=test_keys),
            patch.object(api_key_repository, "revoke_api_key", return_value=True) as mock_revoke,
        ):

            # Act
            revoked_count = await api_key_repository.revoke_user_api_keys("test-user-id", revoked_by="admin")

            # Assert
            assert revoked_count == 3
            assert mock_revoke.call_count == 3

    @pytest.mark.asyncio
    async def test_revoke_user_api_keys_no_keys(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test revoking keys for user with no active keys."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        revoked_count = await api_key_repository.revoke_user_api_keys("user-with-no-keys")

        # Assert
        assert revoked_count == 0
        mock_session.execute.assert_called_once()

    # update_last_used Tests

    @pytest.mark.asyncio
    async def test_update_last_used_success(self, api_key_repository: APIKeyRepository, api_key_factory):
        """Test successful update of last used timestamp."""
        # Arrange
        test_key = api_key_factory.create(id="test-api-key-id", usage_count=5, version=1)
        updated_key = api_key_factory.create(id="test-api-key-id", usage_count=6, version=2)

        # Mock get_by_id and update methods
        with (
            patch.object(api_key_repository, "get_by_id", return_value=test_key),
            patch.object(api_key_repository, "update", return_value=updated_key),
        ):

            # Act
            success = await api_key_repository.update_last_used("test-api-key-id", ip_address="192.168.1.1")

            # Assert
            assert success is True

    @pytest.mark.asyncio
    async def test_update_last_used_key_not_found(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test updating last used for non-existent key."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        success = await api_key_repository.update_last_used("nonexistent-key-id")

        # Assert
        assert success is False
        mock_session.execute.assert_called_once()

    # get_expired_api_keys Tests

    @pytest.mark.asyncio
    async def test_get_expired_api_keys_success(
        self,
        api_key_repository: APIKeyRepository,
        mock_session: AsyncMock,
        expired_api_key: APIKey,
        query_result_factory,
    ):
        """Test retrieving expired API keys."""
        # Arrange
        expired_keys = [expired_api_key]
        result_mock = query_result_factory(data=expired_keys)
        mock_session.execute.return_value = result_mock

        # Act
        expired_keys_result = await api_key_repository.get_expired_api_keys()

        # Assert
        assert len(expired_keys_result) == 1
        assert expired_keys_result[0].expires_at < datetime.now(timezone.utc)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_expired_api_keys_none_expired(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test retrieving expired keys when none are expired."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        expired_keys = await api_key_repository.get_expired_api_keys()

        # Assert
        assert expired_keys == []
        mock_session.execute.assert_called_once()

    # cleanup_expired_api_keys Tests

    @pytest.mark.asyncio
    async def test_cleanup_expired_api_keys_success(self, api_key_repository: APIKeyRepository, api_key_factory):
        """Test successful cleanup of expired API keys."""
        # Arrange - create 5 expired keys
        expired_keys = [api_key_factory.create(id=f"expired-key-{i}") for i in range(5)]

        # Mock get_expired_api_keys and delete methods
        with (
            patch.object(api_key_repository, "get_expired_api_keys", return_value=expired_keys),
            patch.object(api_key_repository, "delete", return_value=True) as mock_delete,
        ):

            # Act
            cleaned_count = await api_key_repository.cleanup_expired_api_keys()

            # Assert
            assert cleaned_count == 5
            assert mock_delete.call_count == 5

    @pytest.mark.asyncio
    async def test_cleanup_expired_api_keys_none_to_cleanup(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test cleanup when no expired keys exist."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await api_key_repository.cleanup_expired_api_keys()

        # Assert
        assert cleaned_count == 0
        mock_session.execute.assert_called_once()

    # rotate_api_key Tests

    @pytest.mark.asyncio
    async def test_rotate_api_key_success(
        self, api_key_repository: APIKeyRepository, sample_api_key: APIKey, api_key_factory
    ):
        """Test successful API key rotation."""
        # Arrange
        new_hash = "b2c3d4e5f6789012345678901bcdef12345678901bcdef12345678901bcdef12"
        rotated_key = api_key_factory.create(
            id="test-api-key-id", key_hash=new_hash, key_prefix=new_hash[:8], version=2
        )

        # Mock get_by_id and update methods
        with (
            patch.object(api_key_repository, "get_by_id", return_value=sample_api_key),
            patch.object(api_key_repository, "update", return_value=rotated_key),
        ):

            # Act
            result = await api_key_repository.rotate_api_key("test-api-key-id", new_hash, rotated_by="admin")

            # Assert
            assert result is not None
            assert result.key_hash == new_hash
            assert result.key_prefix == new_hash[:8]

    @pytest.mark.asyncio
    async def test_rotate_api_key_not_found(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test rotating non-existent API key."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        rotated_key = await api_key_repository.rotate_api_key("nonexistent-key-id", "new_hash")

        # Assert
        assert rotated_key is None
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_rotate_api_key_inactive_key(
        self,
        api_key_repository: APIKeyRepository,
        inactive_api_key: APIKey,
    ):
        """Test rotating inactive API key."""
        # Arrange - mock methods to return inactive key and None update result
        with (
            patch.object(api_key_repository, "get_by_id", return_value=inactive_api_key),
            patch.object(api_key_repository, "update", return_value=None),
        ):

            # Act
            rotated_key = await api_key_repository.rotate_api_key("inactive-api-key-id", "new_hash")

            # Assert
            assert rotated_key is None

    # get_api_key_usage_stats Tests

    @pytest.mark.asyncio
    async def test_get_api_key_usage_stats_user_specific(self, api_key_repository: APIKeyRepository, api_key_factory):
        """Test getting API key usage statistics for specific user."""
        # Arrange - create test keys with usage data
        test_keys = [
            api_key_factory.create(id="key1", user_id="test-user-id", usage_count=50, revoked_at=None, expires_at=None),
            api_key_factory.create(id="key2", user_id="test-user-id", usage_count=30, revoked_at=None, expires_at=None),
            api_key_factory.create(id="key3", user_id="test-user-id", usage_count=20, revoked_at=None, expires_at=None),
        ]

        # Mock get_user_api_keys to return our test keys
        with patch.object(api_key_repository, "get_user_api_keys", return_value=test_keys):
            # Act
            stats = await api_key_repository.get_api_key_usage_stats("test-user-id")

            # Assert
            assert stats["user_id"] == "test-user-id"
            assert stats["total_keys"] == 3
            assert stats["active_keys"] == 3  # All keys are active
            assert stats["total_usage"] == 100  # 50 + 30 + 20

    @pytest.mark.asyncio
    async def test_get_api_key_usage_stats_system_wide(self, api_key_repository: APIKeyRepository):
        """Test getting system-wide API key usage statistics."""
        # Arrange - mock get_statistics to return expected data
        expected_stats = {
            "total_keys": 50,
            "active_keys": 35,
            "expired_keys": 10,
            "revoked_keys": 5,
            "total_requests": 2500,
        }

        with patch.object(api_key_repository, "get_statistics", return_value=expected_stats):
            # Act
            stats = await api_key_repository.get_api_key_usage_stats()

            # Assert
            assert stats["total_keys"] == 50
            assert stats["active_keys"] == 35
            assert stats["expired_keys"] == 10
            assert stats["revoked_keys"] == 5
            assert stats["total_requests"] == 2500

    @pytest.mark.asyncio
    async def test_get_api_key_usage_stats_no_data(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test getting usage statistics when no data available."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        stats = await api_key_repository.get_api_key_usage_stats("user-with-no-keys")

        # Assert
        assert stats["total_keys"] == 0
        assert stats["active_keys"] == 0
        mock_session.execute.assert_called_once()

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_database_connection_error_handling(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock
    ):
        """Test handling of database connection errors across methods."""
        # Arrange
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        # Test various methods handle database errors appropriately
        with pytest.raises(SQLAlchemyError):
            await api_key_repository.get_by_hash("test_hash")

        with pytest.raises(SQLAlchemyError):
            await api_key_repository.get_user_api_keys("test-user-id")

        with pytest.raises(SQLAlchemyError):
            await api_key_repository.get_expired_api_keys()

        with pytest.raises(SQLAlchemyError):
            await api_key_repository.cleanup_expired_api_keys()

    @pytest.mark.asyncio
    async def test_null_input_validation(self, api_key_repository: APIKeyRepository, mock_session: AsyncMock):
        """Test repository methods handle null/None inputs appropriately."""
        # Test methods that should handle None gracefully
        result = await api_key_repository.get_by_hash(None)
        assert result is None

        result = await api_key_repository.get_user_api_keys(None)
        assert result == []

        success = await api_key_repository.revoke_api_key(None)
        assert success is False

    # Performance and Edge Case Tests

    @pytest.mark.asyncio
    async def test_large_key_hash_handling(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of very large key hashes."""
        # Arrange
        large_hash = "x" * 1000  # Very large hash
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        result = await api_key_repository.get_by_hash(large_hash)

        # Assert
        assert result is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_special_characters_in_key_hash(
        self, api_key_repository: APIKeyRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test handling of special characters in key hashes."""
        # Arrange
        special_hash = "key_hash_with_special_chars_!@#$%^&*()"
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        result = await api_key_repository.get_by_hash(special_hash)

        # Assert
        assert result is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_key_operations(
        self, api_key_repository: APIKeyRepository, sample_api_key: APIKey, api_key_factory
    ):
        """Test concurrent API key operations."""
        # This test simulates concurrent access patterns
        # In a real scenario, this would test race conditions

        # Arrange - Mock the methods that both operations will call
        updated_key = api_key_factory.create(id="test-api-key-id", version=2)

        with (
            patch.object(api_key_repository, "get_by_id", return_value=sample_api_key),
            patch.object(api_key_repository, "update", return_value=updated_key),
            patch.object(api_key_repository.session, "commit", return_value=None),
        ):

            # Act - Simulate concurrent revocation and usage update
            revoke_task = api_key_repository.revoke_api_key("test-api-key-id")
            update_task = api_key_repository.update_last_used("test-api-key-id")

            # Execute both operations
            revoke_result = await revoke_task
            update_result = await update_task

            # Assert
            # In this mock scenario, both operations should execute
            # In real implementation, proper locking would be needed
            assert isinstance(revoke_result, bool)
            assert isinstance(update_result, bool)
