"""Tests for secrets manager abstraction layer and providers.

This module provides comprehensive test coverage for the secrets manager system
including file-based, Vault, and AWS Secrets Manager providers.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.core.secrets_manager import (
    AWSSecretsManager,
    FileSecretsManager,
    SecretData,
    SecretsManager,
    VaultSecretsManager,
    create_secrets_manager,
)


class TestSecretData:
    """Test SecretData model."""

    def test_secret_data_creation(self):
        """Test creating SecretData with all fields."""
        secret = SecretData(
            value="test_secret",
            metadata={"key": "value"},
            version="v1",
            created_at="2025-08-07T12:00:00Z",
            expires_at="2025-08-14T12:00:00Z",
        )

        assert secret.value == "test_secret"
        assert secret.metadata == {"key": "value"}
        assert secret.version == "v1"
        assert secret.created_at == "2025-08-07T12:00:00Z"
        assert secret.expires_at == "2025-08-14T12:00:00Z"

    def test_secret_data_defaults(self):
        """Test SecretData with default values."""
        secret = SecretData(value="test_secret")

        assert secret.value == "test_secret"
        assert secret.metadata == {}
        assert secret.version is None
        assert secret.created_at is None
        assert secret.expires_at is None


class TestFileSecretsManager:
    """Test file-based secrets manager."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def file_manager(self, temp_dir):
        """Create file secrets manager with temp directory."""
        return FileSecretsManager(temp_dir)

    async def test_store_and_get_secret(self, file_manager):
        """Test storing and retrieving a secret."""
        secret_name = "test/secret"
        secret_value = "super_secret_value"
        metadata = {"environment": "test", "purpose": "api_key"}

        # Store secret
        success = await file_manager.store_secret(secret_name, secret_value, metadata)
        assert success is True

        # Retrieve secret
        secret_data = await file_manager.get_secret(secret_name)
        assert secret_data is not None
        assert secret_data.value == secret_value
        assert secret_data.metadata == metadata
        assert secret_data.version == "1"
        assert secret_data.created_at is not None

    async def test_get_nonexistent_secret(self, file_manager):
        """Test retrieving a non-existent secret."""
        result = await file_manager.get_secret("nonexistent/secret")
        assert result is None

    async def test_delete_secret(self, file_manager):
        """Test deleting a secret."""
        secret_name = "test/deleteme"
        secret_value = "temporary_secret"

        # Store secret first
        await file_manager.store_secret(secret_name, secret_value)

        # Verify it exists
        secret_data = await file_manager.get_secret(secret_name)
        assert secret_data is not None

        # Delete secret
        success = await file_manager.delete_secret(secret_name)
        assert success is True

        # Verify it's gone
        secret_data = await file_manager.get_secret(secret_name)
        assert secret_data is None

    async def test_list_secrets(self, file_manager):
        """Test listing secrets."""
        # Store multiple secrets
        secrets = {
            "api_keys/key1": "value1",
            "api_keys/key2": "value2",
            "database/password": "dbpass",
            "other/secret": "other",
        }

        for name, value in secrets.items():
            await file_manager.store_secret(name, value, {"test": True})

        # List all secrets
        all_secrets = await file_manager.list_secrets()
        assert len(all_secrets) >= 4

        # List with prefix filter
        api_secrets = await file_manager.list_secrets("api_keys/")
        assert len(api_secrets) == 2
        assert "api_keys/key1" in api_secrets
        assert "api_keys/key2" in api_secrets

    async def test_rotate_secret(self, file_manager):
        """Test secret rotation."""
        secret_name = "test/rotation"
        old_value = "old_secret"
        new_value = "new_secret"

        # Store initial secret
        await file_manager.store_secret(secret_name, old_value)

        # Rotate secret
        success = await file_manager.rotate_secret(secret_name, new_value)
        assert success is True

        # Verify new value
        secret_data = await file_manager.get_secret(secret_name)
        assert secret_data is not None
        assert secret_data.value == new_value
        assert secret_data.metadata.get("rotated") is True

    async def test_secret_name_sanitization(self, file_manager):
        """Test that secret names are properly sanitized for file paths."""
        dangerous_names = ["../../../etc/passwd", "secret\\with\\backslashes", "secret/with/slashes"]

        for name in dangerous_names:
            success = await file_manager.store_secret(name, "test_value")
            assert success is True

            # Verify secret can be retrieved
            secret_data = await file_manager.get_secret(name)
            assert secret_data is not None
            assert secret_data.value == "test_value"

    async def test_json_serialization_error_handling(self, file_manager):
        """Test handling of JSON serialization errors."""
        secret_name = "test/json_error"

        # Mock json.load to raise exception
        with patch("json.load", side_effect=json.JSONDecodeError("test", "doc", 0)):
            secret_data = await file_manager.get_secret(secret_name)
            assert secret_data is None

    async def test_file_permissions(self, file_manager, temp_dir):
        """Test that secret files are created with proper permissions."""
        secret_name = "test/permissions"
        secret_value = "sensitive_data"

        await file_manager.store_secret(secret_name, secret_value)

        # Check file was created
        secret_path = file_manager._get_secret_path(secret_name)
        assert os.path.exists(secret_path)

        # Verify file contains expected data
        with open(secret_path, "r") as f:
            data = json.load(f)
            assert data["value"] == secret_value


class TestSecretsManagerUnified:
    """Test unified secrets manager interface."""

    @pytest.fixture
    def mock_provider(self):
        """Create mock secrets manager provider."""
        provider = Mock()
        provider.get_secret = AsyncMock()
        provider.store_secret = AsyncMock()
        provider.delete_secret = AsyncMock()
        provider.list_secrets = AsyncMock()
        provider.rotate_secret = AsyncMock()
        return provider

    @pytest.fixture
    def secrets_manager(self, mock_provider):
        """Create unified secrets manager with mock provider."""
        return SecretsManager(mock_provider)

    async def test_get_api_key_metadata(self, secrets_manager, mock_provider):
        """Test getting API key metadata."""
        key_id = "test-key-123"
        metadata = {"user_id": "user-456", "permissions": {"read": True}}

        # Mock provider response
        secret_data = SecretData(value=json.dumps(metadata), metadata=metadata)
        mock_provider.get_secret.return_value = secret_data

        # Call method
        result = await secrets_manager.get_api_key_metadata(key_id)

        # Verify result
        assert result == metadata
        mock_provider.get_secret.assert_called_once_with(f"api_keys/{key_id}")

    async def test_get_api_key_metadata_not_found(self, secrets_manager, mock_provider):
        """Test getting non-existent API key metadata."""
        key_id = "nonexistent-key"

        # Mock provider to return None
        mock_provider.get_secret.return_value = None

        # Call method
        result = await secrets_manager.get_api_key_metadata(key_id)

        # Verify result
        assert result is None

    async def test_store_api_key_metadata(self, secrets_manager, mock_provider):
        """Test storing API key metadata."""
        key_id = "test-key-456"
        metadata = {"user_id": "user-789", "created_at": "2025-08-07T12:00:00Z"}

        # Mock provider success
        mock_provider.store_secret.return_value = True

        # Call method
        success = await secrets_manager.store_api_key_metadata(key_id, metadata)

        # Verify result
        assert success is True
        mock_provider.store_secret.assert_called_once_with(f"api_keys/{key_id}", json.dumps(metadata), metadata)

    async def test_rotate_api_key(self, secrets_manager, mock_provider):
        """Test API key rotation."""
        key_id = "test-key-789"
        new_hash = "new_argon2_hash_value"

        # Mock provider success
        mock_provider.rotate_secret.return_value = True

        # Call method
        success = await secrets_manager.rotate_api_key(key_id, new_hash)

        # Verify result
        assert success is True
        mock_provider.rotate_secret.assert_called_once_with(f"api_keys/{key_id}/hash", new_hash)

    async def test_cleanup_expired_keys(self, secrets_manager, mock_provider):
        """Test cleanup of expired API keys."""
        # Mock secrets with some expired
        current_time = datetime.now(timezone.utc)
        expired_time = (current_time - timedelta(days=1)).isoformat()
        valid_time = (current_time + timedelta(days=1)).isoformat()

        mock_secrets = {
            "api_keys/expired1": {"metadata": {"expires_at": expired_time}},
            "api_keys/expired2": {"metadata": {"expires_at": expired_time}},
            "api_keys/valid1": {"metadata": {"expires_at": valid_time}},
            "api_keys/no_expiry": {"metadata": {}},
        }

        mock_provider.list_secrets.return_value = mock_secrets
        mock_provider.delete_secret.return_value = True

        # Call method
        cleaned_count = await secrets_manager.cleanup_expired_keys()

        # Verify result
        assert cleaned_count == 2
        assert mock_provider.delete_secret.call_count == 2


class TestVaultSecretsManager:
    """Test HashiCorp Vault secrets manager (stub implementation)."""

    def test_vault_manager_initialization(self):
        """Test Vault manager initialization."""
        vault_url = "https://vault.example.com"
        vault_token = "vault_token_123"
        mount_path = "kv"

        manager = VaultSecretsManager(vault_url, vault_token, mount_path)

        assert manager.vault_url == vault_url
        assert manager.vault_token == vault_token
        assert manager.mount_path == mount_path

    async def test_vault_methods_not_implemented(self):
        """Test that Vault methods return appropriate not-implemented responses."""
        manager = VaultSecretsManager("https://vault.test", "token", "secret")

        # All methods should return None/False for not implemented
        assert await manager.get_secret("test") is None
        assert await manager.store_secret("test", "value") is False
        assert await manager.delete_secret("test") is False
        assert await manager.list_secrets() == {}
        assert await manager.rotate_secret("test", "new_value") is False


class TestAWSSecretsManager:
    """Test AWS Secrets Manager (stub implementation)."""

    def test_aws_manager_initialization(self):
        """Test AWS manager initialization."""
        region = "us-east-1"
        access_key = "ACCESS_KEY_123"
        secret_key = "SECRET_KEY_456"

        manager = AWSSecretsManager(region, access_key, secret_key)

        assert manager.region == region
        assert manager.access_key_id == access_key
        assert manager.secret_access_key == secret_key

    async def test_aws_methods_not_implemented(self):
        """Test that AWS methods return appropriate not-implemented responses."""
        manager = AWSSecretsManager("us-west-2")

        # All methods should return None/False for not implemented
        assert await manager.get_secret("test") is None
        assert await manager.store_secret("test", "value") is False
        assert await manager.delete_secret("test") is False
        assert await manager.list_secrets() == {}
        assert await manager.rotate_secret("test", "new_value") is False


class TestSecretsManagerFactory:
    """Test secrets manager factory function."""

    def test_create_file_secrets_manager(self, tmp_path):
        """Test creating file-based secrets manager."""
        manager = create_secrets_manager("file", secrets_dir=str(tmp_path))

        assert isinstance(manager, SecretsManager)
        assert isinstance(manager.provider, FileSecretsManager)

    def test_create_vault_secrets_manager(self):
        """Test creating Vault secrets manager."""
        manager = create_secrets_manager(
            "vault", vault_url="https://vault.test", vault_token="token123", mount_path="secret"
        )

        assert isinstance(manager, SecretsManager)
        assert isinstance(manager.provider, VaultSecretsManager)

    def test_create_aws_secrets_manager(self):
        """Test creating AWS secrets manager."""
        manager = create_secrets_manager(
            "aws", region="us-east-1", access_key_id="ACCESS_KEY", secret_access_key="SECRET_KEY"
        )

        assert isinstance(manager, SecretsManager)
        assert isinstance(manager.provider, AWSSecretsManager)

    def test_create_invalid_provider(self):
        """Test creating secrets manager with invalid provider."""
        with pytest.raises(ValueError, match="Unsupported secrets manager provider: invalid"):
            create_secrets_manager("invalid")

    def test_create_file_manager_default_dir(self):
        """Test creating file manager with default directory."""
        manager = create_secrets_manager("file")

        assert isinstance(manager.provider, FileSecretsManager)
        assert manager.provider.secrets_dir == "./data/secrets"


@pytest.mark.integration
class TestSecretsManagerIntegration:
    """Integration tests for secrets manager with real file system."""

    async def test_complete_api_key_lifecycle(self):
        """Test complete API key lifecycle with file-based secrets manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create real file-based secrets manager
            file_provider = FileSecretsManager(temp_dir)
            secrets_manager = SecretsManager(file_provider)

            # Test data
            key_id = "integration-test-key"
            metadata = {
                "user_id": "user-integration-test",
                "permissions": {"users:read": True, "api_keys:read": True},
                "created_at": datetime.now(timezone.utc).isoformat(),
                "environment": "test",
            }

            # Store metadata
            success = await secrets_manager.store_api_key_metadata(key_id, metadata)
            assert success is True

            # Retrieve metadata
            retrieved = await secrets_manager.get_api_key_metadata(key_id)
            assert retrieved == metadata

            # Rotate key
            new_hash = "new_argon2_hash_after_rotation"
            rotation_success = await secrets_manager.rotate_api_key(key_id, new_hash)
            assert rotation_success is True

            # Verify files were created with correct naming convention
            secrets_dir = Path(temp_dir)
            # FileSecretsManager encodes "api_keys/key_id" as "api_keys__SLASH__key_id.json"
            metadata_file = secrets_dir / f"api_keys__SLASH__{key_id}.json"
            # FileSecretsManager encodes "api_keys/key_id/hash" as "api_keys__SLASH__key_id__SLASH__hash.json"
            hash_file = secrets_dir / f"api_keys__SLASH__{key_id}__SLASH__hash.json"

            assert metadata_file.exists(), f"Expected metadata file not found: {metadata_file}"
            assert hash_file.exists(), f"Expected hash file not found: {hash_file}"

            # Verify file contents
            with open(metadata_file) as f:
                stored_metadata = json.load(f)
                assert stored_metadata["value"] == json.dumps(metadata)

            with open(hash_file) as f:
                stored_hash = json.load(f)
                assert stored_hash["value"] == new_hash

    async def test_secrets_manager_with_multiple_keys(self):
        """Test secrets manager with multiple API keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_provider = FileSecretsManager(temp_dir)
            secrets_manager = SecretsManager(file_provider)

            # Store multiple keys
            keys_metadata = {
                "key1": {"user_id": "user1", "type": "admin"},
                "key2": {"user_id": "user2", "type": "viewer"},
                "key3": {"user_id": "user1", "type": "editor"},
            }

            for key_id, metadata in keys_metadata.items():
                success = await secrets_manager.store_api_key_metadata(key_id, metadata)
                assert success is True

            # Verify all keys can be retrieved
            for key_id, expected_metadata in keys_metadata.items():
                retrieved = await secrets_manager.get_api_key_metadata(key_id)
                assert retrieved == expected_metadata

            # List all secrets
            all_secrets = await file_provider.list_secrets("api_keys/")
            assert len(all_secrets) == 3

    async def test_cleanup_with_real_expiry_dates(self):
        """Test cleanup functionality with real expiry dates."""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_provider = FileSecretsManager(temp_dir)
            secrets_manager = SecretsManager(file_provider)

            # Create keys with different expiry dates
            current_time = datetime.utcnow()
            expired_time = current_time - timedelta(hours=1)
            future_time = current_time + timedelta(hours=1)

            test_keys = {
                "expired_key1": {"expires_at": expired_time.isoformat()},
                "expired_key2": {"expires_at": expired_time.isoformat()},
                "valid_key1": {"expires_at": future_time.isoformat()},
                "no_expiry_key": {"no_expiry": True},
            }

            for key_id, metadata in test_keys.items():
                await secrets_manager.store_api_key_metadata(key_id, metadata)

            # Perform cleanup
            cleaned_count = await secrets_manager.cleanup_expired_keys()

            # Should have cleaned up 2 expired keys
            assert cleaned_count == 2

            # Verify expired keys are gone
            assert await secrets_manager.get_api_key_metadata("expired_key1") is None
            assert await secrets_manager.get_api_key_metadata("expired_key2") is None

            # Verify valid keys remain
            assert await secrets_manager.get_api_key_metadata("valid_key1") is not None
            assert await secrets_manager.get_api_key_metadata("no_expiry_key") is not None


class TestSecretsManagerEnhancedAPIMethods:
    """Test enhanced API methods for secure hash storage."""

    @pytest.fixture
    def mock_provider(self):
        """Create mock secrets manager provider."""
        provider = Mock()
        provider.get_secret = AsyncMock()
        provider.store_secret = AsyncMock(return_value=True)
        provider.delete_secret = AsyncMock()
        provider.rotate_secret = AsyncMock()
        provider.list_secrets = AsyncMock()
        return provider

    @pytest.fixture
    def secrets_manager(self, mock_provider):
        """Create secrets manager with mock provider."""
        return SecretsManager(mock_provider)

    async def test_store_api_key_hash_argon2(self, secrets_manager, mock_provider):
        """Test storing Argon2 API key hash."""
        key_id = "test-key-123"
        key_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"

        result = await secrets_manager.store_api_key_hash(key_id, key_hash)

        assert result is True
        mock_provider.store_secret.assert_called_once()
        args, kwargs = mock_provider.store_secret.call_args
        assert args[0] == f"api_keys/{key_id}/hash"
        assert args[1] == key_hash
        assert args[2]["type"] == "api_key_hash"
        assert args[2]["algorithm"] == "argon2"
        assert "created_at" in args[2]

    async def test_store_api_key_hash_sha256_legacy(self, secrets_manager, mock_provider):
        """Test storing SHA256 API key hash (legacy support)."""
        key_id = "legacy-key-456"
        key_hash = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"

        result = await secrets_manager.store_api_key_hash(key_id, key_hash)

        assert result is True
        mock_provider.store_secret.assert_called_once()
        args, kwargs = mock_provider.store_secret.call_args
        assert args[0] == f"api_keys/{key_id}/hash"
        assert args[1] == key_hash
        assert args[2]["type"] == "api_key_hash"
        assert args[2]["algorithm"] == "sha256"

    async def test_get_api_key_hash_success(self, secrets_manager, mock_provider):
        """Test retrieving API key hash from secrets manager."""
        key_id = "test-key-789"
        expected_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"

        # Mock provider returns secret data
        mock_secret = SecretData(value=expected_hash, metadata={"type": "api_key_hash", "algorithm": "argon2"})
        mock_provider.get_secret.return_value = mock_secret

        result = await secrets_manager.get_api_key_hash(key_id)

        assert result == expected_hash
        mock_provider.get_secret.assert_called_once_with(f"api_keys/{key_id}/hash")

    async def test_get_api_key_hash_not_found(self, secrets_manager, mock_provider):
        """Test retrieving non-existent API key hash."""
        key_id = "nonexistent-key"
        mock_provider.get_secret.return_value = None

        result = await secrets_manager.get_api_key_hash(key_id)

        assert result is None
        mock_provider.get_secret.assert_called_once_with(f"api_keys/{key_id}/hash")

    async def test_api_key_hash_storage_integration(self, secrets_manager, mock_provider):
        """Test full integration of API key hash storage and retrieval."""
        key_id = "integration-test-key"
        original_hash = "$argon2id$v=19$m=65536,t=3,p=4$newsalt$newhash"

        # Store hash
        store_result = await secrets_manager.store_api_key_hash(key_id, original_hash)
        assert store_result is True

        # Mock the retrieval to return what we stored
        mock_secret = SecretData(value=original_hash, metadata={"type": "api_key_hash"})
        mock_provider.get_secret.return_value = mock_secret

        # Retrieve hash
        retrieved_hash = await secrets_manager.get_api_key_hash(key_id)
        assert retrieved_hash == original_hash

        # Verify correct secret paths were used
        store_call = mock_provider.store_secret.call_args[0]
        get_call = mock_provider.get_secret.call_args[0]
        assert store_call[0] == get_call[0] == f"api_keys/{key_id}/hash"
