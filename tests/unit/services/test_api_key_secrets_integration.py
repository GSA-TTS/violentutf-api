"""Comprehensive tests for API Key Service secrets manager integration.

This module tests the enhanced security features including:
- Secrets manager integration for secure hash storage
- Migration from database to secrets manager
- Backward compatibility with database storage
- Argon2 hashing with SHA256 fallback
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from passlib.hash import argon2

from app.core.errors import ForbiddenError, NotFoundError, ValidationError
from app.core.secrets_manager import SecretsManager
from app.models.api_key import APIKey
from app.schemas.api_key import APIKeyCreate
from app.services.api_key_service import APIKeyService


@pytest.fixture
def mock_secrets_manager():
    """Mock secrets manager for testing."""
    mock = Mock(spec=SecretsManager)
    mock.store_api_key_hash = AsyncMock(return_value=True)
    mock.get_api_key_hash = AsyncMock(return_value=None)
    mock.store_api_key_metadata = AsyncMock(return_value=True)
    mock.get_api_key_metadata = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def sample_api_key():
    """Create a sample API key for testing."""
    api_key = Mock(spec=APIKey)
    api_key.id = "test-key-456"
    api_key.user_id = "12345678-1234-1234-1234-123456789abc"
    api_key.name = "Test Key"
    api_key.key_hash = "$argon2id$v=19$m=65536,t=3,p=4$abcdefghijklmnop$abcdefghijklmnopqrstuvwxyz1234567890"
    api_key.key_prefix = "vutf_test_"
    api_key.permissions = {"users:read": True}
    api_key.expires_at = None
    api_key.is_active = Mock(return_value=True)
    return api_key


class TestAPIKeySecretsManagerIntegration:
    """Test API Key service integration with secrets manager."""

    # Mark all test methods in this class as async
    pytestmark = pytest.mark.asyncio

    @pytest.fixture
    def api_key_service_with_secrets(self, mock_session, mock_secrets_manager):
        """Create API key service with secrets manager."""
        return APIKeyService(mock_session, secrets_manager=mock_secrets_manager)

    @pytest.fixture
    def api_key_service_without_secrets(self, mock_session):
        """Create API key service without secrets manager."""
        return APIKeyService(mock_session, secrets_manager=None)

    async def test_create_api_key_with_secrets_manager(self, api_key_service_with_secrets, mock_secrets_manager):
        """Test API key creation stores hash in secrets manager."""
        # Mock repository
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "new-key-123"
        mock_api_key.name = "Test Key"
        mock_api_key.key_hash = ""  # Add key_hash attribute
        api_key_service_with_secrets.repository.create = AsyncMock(return_value=mock_api_key)
        api_key_service_with_secrets.repository.delete = AsyncMock(return_value=True)
        api_key_service_with_secrets.repository.list_user_keys = AsyncMock(return_value=[])
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=mock_api_key)
        api_key_service_with_secrets.repository.get_by_id = AsyncMock(return_value=mock_api_key)

        # Test data
        key_data = APIKeyCreate(
            name="Test Key",
            description="Test Description",
            permissions={"users:read": True},
        )

        # Execute
        created_key, full_key = await api_key_service_with_secrets.create_api_key(
            "12345678-1234-1234-1234-123456789abc", key_data
        )

        # Verify hash stored in secrets manager
        mock_secrets_manager.store_api_key_hash.assert_called_once()
        args, kwargs = mock_secrets_manager.store_api_key_hash.call_args
        assert args[0] == "new-key-123"  # key_id
        assert args[1].startswith("$argon2")  # Argon2 hash

        # Verify metadata stored
        mock_secrets_manager.store_api_key_metadata.assert_called_once()

        # Verify key creation
        assert created_key == mock_api_key
        assert full_key.startswith("vutf_")

    async def test_create_api_key_secrets_manager_failure_rollback(
        self, api_key_service_with_secrets, mock_secrets_manager
    ):
        """Test API key creation rollback when secrets manager fails."""
        # Mock repository
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "new-key-123"
        mock_api_key.key_hash = ""  # Add key_hash attribute
        api_key_service_with_secrets.repository.create = AsyncMock(return_value=mock_api_key)
        api_key_service_with_secrets.repository.delete = AsyncMock(return_value=True)
        api_key_service_with_secrets.repository.list_user_keys = AsyncMock(return_value=[])
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=mock_api_key)
        api_key_service_with_secrets.repository.get_by_id = AsyncMock(return_value=mock_api_key)

        # Mock secrets manager failure
        mock_secrets_manager.store_api_key_hash.return_value = False

        # Test data
        key_data = APIKeyCreate(
            name="Test Key",
            description="Test Description",
            permissions={"users:read": True},
        )

        # Execute and expect failure
        with pytest.raises(ValidationError, match="Failed to securely store API key hash"):
            await api_key_service_with_secrets.create_api_key("12345678-1234-1234-1234-123456789abc", key_data)

        # Verify rollback
        api_key_service_with_secrets.repository.delete.assert_called_once_with("new-key-123")

    async def test_create_api_key_without_secrets_manager_fallback(self, api_key_service_without_secrets):
        """Test API key creation falls back to database storage when no secrets manager."""
        # Mock repository
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "new-key-123"
        mock_api_key.key_hash = ""
        api_key_service_without_secrets.repository.create = AsyncMock(return_value=mock_api_key)
        api_key_service_without_secrets.repository.update = AsyncMock(return_value=mock_api_key)
        api_key_service_without_secrets.repository.list_user_keys = AsyncMock(return_value=[])
        api_key_service_without_secrets.repository.get_by_id = AsyncMock(return_value=mock_api_key)

        # Test data
        key_data = APIKeyCreate(
            name="Test Key",
            description="Test Description",
            permissions={"users:read": True},
        )

        # Execute
        created_key, full_key = await api_key_service_without_secrets.create_api_key(
            "12345678-1234-1234-1234-123456789abc", key_data
        )

        # Verify fallback to database storage (hash stored directly in create, no update needed)
        api_key_service_without_secrets.repository.create.assert_called_once()
        args, kwargs = api_key_service_without_secrets.repository.create.call_args
        assert "key_hash" in args[0]  # First argument contains the data dict
        assert args[0]["key_hash"].startswith("$argon2")

        # Verify no update call (hash stored directly during creation)
        api_key_service_without_secrets.repository.update.assert_not_called()

    async def test_validate_api_key_from_secrets_manager(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test API key validation retrieves hash from secrets manager."""
        # Mock repository - return key with empty database hash
        sample_api_key.key_hash = ""  # No hash in database
        api_key_service_with_secrets.repository.get_by_prefix = AsyncMock(return_value=[sample_api_key])

        # Mock secrets manager returns hash
        stored_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
        mock_secrets_manager.get_api_key_hash.return_value = stored_hash

        # Mock hash verification
        with patch.object(api_key_service_with_secrets, "_verify_key_hash", return_value=True) as mock_verify:
            # Execute
            result = await api_key_service_with_secrets.validate_api_key("vutf_test_12345")

            # Verify
            assert result == sample_api_key
            mock_secrets_manager.get_api_key_hash.assert_called_once_with("test-key-456")
            mock_verify.assert_called_once_with("vutf_test_12345", stored_hash)

    async def test_validate_api_key_fallback_to_database(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test API key validation falls back to database when secrets manager fails."""
        # Mock repository - return key with database hash
        database_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$database_hash"
        sample_api_key.key_hash = database_hash
        api_key_service_with_secrets.repository.get_by_prefix = AsyncMock(return_value=[sample_api_key])

        # Mock secrets manager failure
        mock_secrets_manager.get_api_key_hash.side_effect = Exception("Secrets manager unavailable")

        # Mock hash verification
        with patch.object(api_key_service_with_secrets, "_verify_key_hash", return_value=True) as mock_verify:
            # Execute
            result = await api_key_service_with_secrets.validate_api_key("vutf_test_12345")

            # Verify fallback to database
            assert result == sample_api_key
            mock_verify.assert_called_once_with("vutf_test_12345", database_hash)

    async def test_migrate_hash_to_secrets_manager(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test migration of hash from database to secrets manager."""
        # Setup
        database_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$database_hash"
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=True)

        # Execute migration
        result = await api_key_service_with_secrets._migrate_hash_to_secrets_manager(sample_api_key, database_hash)

        # Verify
        assert result is True
        mock_secrets_manager.store_api_key_hash.assert_called_once_with("test-key-456", database_hash)
        api_key_service_with_secrets.repository.update.assert_called_once_with("test-key-456", key_hash="")

    async def test_migrate_hash_to_secrets_manager_failure(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test hash migration failure handling."""
        # Setup failure
        mock_secrets_manager.store_api_key_hash.return_value = False
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=True)

        # Execute migration
        result = await api_key_service_with_secrets._migrate_hash_to_secrets_manager(sample_api_key, "test_hash")

        # Verify failure handling
        assert result is False
        api_key_service_with_secrets.repository.update.assert_not_called()

    async def test_migrate_legacy_key_to_secrets_manager(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test migration of legacy SHA256 key to Argon2 in secrets manager."""
        # Setup legacy SHA256 key
        sample_api_key.key_hash = "a" * 64  # SHA256 hash format
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=True)

        # Execute migration
        result = await api_key_service_with_secrets._migrate_legacy_key(sample_api_key, "test_key_value")

        # Verify Argon2 hash stored in secrets manager
        assert result is True
        mock_secrets_manager.store_api_key_hash.assert_called_once()
        args, kwargs = mock_secrets_manager.store_api_key_hash.call_args
        assert args[0] == "test-key-456"  # key_id
        assert args[1].startswith("$argon2")  # Argon2 hash

        # Verify database hash cleared
        api_key_service_with_secrets.repository.update.assert_called_once_with("test-key-456", key_hash="")

    async def test_migrate_legacy_key_fallback_to_database(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test legacy key migration falls back to database when secrets manager fails."""
        # Setup legacy SHA256 key and secrets manager failure
        sample_api_key.key_hash = "a" * 64  # SHA256 hash format
        mock_secrets_manager.store_api_key_hash.return_value = False
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=True)

        # Execute migration
        result = await api_key_service_with_secrets._migrate_legacy_key(sample_api_key, "test_key_value")

        # Verify fallback to database storage
        assert result is True
        api_key_service_with_secrets.repository.update.assert_called_once()
        args, kwargs = api_key_service_with_secrets.repository.update.call_args
        assert "key_hash" in kwargs
        assert kwargs["key_hash"].startswith("$argon2")

    async def test_rotate_api_key_enhanced_with_secrets_manager(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test enhanced API key rotation using secrets manager."""
        # Setup
        api_key_service_with_secrets.repository.get = AsyncMock(return_value=sample_api_key)
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=sample_api_key)

        # Execute rotation
        rotated_key, new_key = await api_key_service_with_secrets.rotate_api_key_enhanced(
            "test-key-456", "12345678-1234-1234-1234-123456789abc"
        )

        # Verify hash stored in secrets manager
        mock_secrets_manager.store_api_key_hash.assert_called_once()
        args, kwargs = mock_secrets_manager.store_api_key_hash.call_args
        assert args[0] == "test-key-456"  # key_id
        assert args[1].startswith("$argon2")  # Argon2 hash

        # Verify database hash cleared
        api_key_service_with_secrets.repository.update.assert_called_once()
        update_args = api_key_service_with_secrets.repository.update.call_args[1]
        assert update_args["key_hash"] == ""  # Cleared for security

        # Verify metadata stored
        mock_secrets_manager.store_api_key_metadata.assert_called_once()

        assert rotated_key == sample_api_key
        assert new_key.startswith("vutf_")

    async def test_rotate_api_key_enhanced_secrets_manager_failure(
        self, api_key_service_with_secrets, mock_secrets_manager, sample_api_key
    ):
        """Test API key rotation fallback when secrets manager fails."""
        # Setup
        api_key_service_with_secrets.repository.get = AsyncMock(return_value=sample_api_key)
        api_key_service_with_secrets.repository.update = AsyncMock(return_value=sample_api_key)
        mock_secrets_manager.store_api_key_hash.return_value = False  # Secrets manager failure

        # Execute rotation
        rotated_key, new_key = await api_key_service_with_secrets.rotate_api_key_enhanced(
            "test-key-456", "12345678-1234-1234-1234-123456789abc"
        )

        # Verify fallback to database storage
        api_key_service_with_secrets.repository.update.assert_called_once()
        update_args = api_key_service_with_secrets.repository.update.call_args[1]
        assert update_args["key_hash"].startswith("$argon2")  # Hash stored in database as fallback

        assert rotated_key == sample_api_key
        assert new_key.startswith("vutf_")

    async def test_rotate_api_key_enhanced_validation_errors(self, api_key_service_with_secrets):
        """Test rotation validation errors."""
        # Test key not found
        api_key_service_with_secrets.repository.get = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError):
            await api_key_service_with_secrets.rotate_api_key_enhanced(
                "nonexistent-key", "12345678-1234-1234-1234-123456789abc"
            )

        # Test wrong owner
        wrong_owner_key = Mock(spec=APIKey)
        wrong_owner_key.user_id = "87654321-4321-4321-4321-cba987654321"
        api_key_service_with_secrets.repository.get = AsyncMock(return_value=wrong_owner_key)

        with pytest.raises(ForbiddenError):
            await api_key_service_with_secrets.rotate_api_key_enhanced(
                "test-key", "12345678-1234-1234-1234-123456789abc"
            )

        # Test inactive key
        inactive_key = Mock(spec=APIKey)
        inactive_key.user_id = "12345678-1234-1234-1234-123456789abc"
        inactive_key.is_active = Mock(return_value=False)
        api_key_service_with_secrets.repository.get = AsyncMock(return_value=inactive_key)

        with pytest.raises(ValidationError):
            await api_key_service_with_secrets.rotate_api_key_enhanced(
                "test-key", "12345678-1234-1234-1234-123456789abc"
            )


class TestSecurityEnhancements:
    """Test specific security enhancements."""

    def test_argon2_hash_generation(self):
        """Test that new API keys use Argon2 hashing."""
        service = APIKeyService(Mock(), None)

        # Generate secure key
        full_key, prefix, hash_value = service._generate_secure_key()

        # Verify Argon2 hash
        assert hash_value.startswith("$argon2")
        assert len(full_key) > 32  # Strong entropy
        assert prefix == full_key[:10]

        # Verify hash can be verified
        assert argon2.verify(full_key, hash_value)

    @pytest.mark.asyncio
    async def test_hash_verification_argon2_and_sha256(self):
        """Test hash verification supports both Argon2 and SHA256."""
        service = APIKeyService(Mock(), None)

        test_key = "vutf_test_key_12345"

        # Test Argon2 verification
        argon2_hash = argon2.hash(test_key)
        assert await service._verify_key_hash(test_key, argon2_hash) is True
        assert await service._verify_key_hash("wrong_key", argon2_hash) is False

        # Test SHA256 verification (legacy)
        import hashlib

        sha256_hash = hashlib.sha256(test_key.encode()).hexdigest()
        assert await service._verify_key_hash(test_key, sha256_hash) is True
        assert await service._verify_key_hash("wrong_key", sha256_hash) is False

        # Test invalid hash format
        assert await service._verify_key_hash(test_key, "invalid_hash") is False

    @pytest.mark.asyncio
    async def test_automatic_migration_triggers(self, mock_session, mock_secrets_manager):
        """Test that various operations trigger appropriate migrations."""
        service = APIKeyService(mock_session, mock_secrets_manager)

        # Mock a key with database hash that should trigger migration
        api_key = Mock(spec=APIKey)
        api_key.id = "test-key"
        api_key.key_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"  # Database hash
        api_key.is_active = Mock(return_value=True)

        service.repository.get_by_prefix = AsyncMock(return_value=[api_key])
        mock_secrets_manager.get_api_key_hash.return_value = None  # No hash in secrets manager

        # Mock migration method
        service._migrate_hash_to_secrets_manager = AsyncMock(return_value=True)

        with patch.object(service, "_verify_key_hash", return_value=True):
            # Execute validation - should trigger migration
            result = await service.validate_api_key("vutf_test_12345")

            # Verify migration was triggered
            service._migrate_hash_to_secrets_manager.assert_called_once_with(api_key, api_key.key_hash)


class TestErrorHandling:
    """Test comprehensive error handling scenarios."""

    # Mark all test methods in this class as async
    pytestmark = pytest.mark.asyncio

    async def test_secrets_manager_unavailable_scenarios(self, mock_session):
        """Test graceful degradation when secrets manager is unavailable."""
        # Test with None secrets manager
        service = APIKeyService(mock_session, secrets_manager=None)

        # Should not attempt to use secrets manager
        migration_result = await service._migrate_hash_to_secrets_manager(Mock(), "test_hash")
        assert migration_result is False

    async def test_secrets_manager_exceptions(self, mock_session):
        """Test handling of secrets manager exceptions."""
        # Create failing secrets manager
        failing_secrets_manager = Mock()
        failing_secrets_manager.store_api_key_hash = AsyncMock(side_effect=Exception("Network error"))
        failing_secrets_manager.get_api_key_hash = AsyncMock(side_effect=Exception("Network error"))

        service = APIKeyService(mock_session, failing_secrets_manager)

        # Test hash storage exception handling
        api_key = Mock(spec=APIKey)
        api_key.id = "test-key"

        migration_result = await service._migrate_hash_to_secrets_manager(api_key, "test_hash")
        assert migration_result is False

    async def test_validation_edge_cases(self, mock_session, mock_secrets_manager):
        """Test API key validation edge cases."""
        service = APIKeyService(mock_session, mock_secrets_manager)

        # Test invalid key format
        assert await service.validate_api_key("") is None
        assert await service.validate_api_key("invalid_key") is None
        assert await service.validate_api_key("wrong_prefix_123") is None

        # Test no matching keys found
        service.repository.get_by_prefix = AsyncMock(return_value=[])
        assert await service.validate_api_key("vutf_test_123") is None


@pytest.fixture
def mock_session():
    """Mock database session for testing."""
    return Mock()
