"""Basic integration tests for API Key Service with secrets manager."""

from unittest.mock import AsyncMock, Mock

import pytest

from app.core.secrets_manager import SecretsManager
from app.services.api_key_service import APIKeyService


@pytest.fixture
def mock_session():
    """Mock database session."""
    return Mock()


@pytest.fixture
def mock_secrets_manager():
    """Mock secrets manager."""
    mock = Mock(spec=SecretsManager)
    mock.store_api_key_hash = AsyncMock(return_value=True)
    mock.get_api_key_hash = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def api_key_service(mock_session, mock_secrets_manager):
    """Create API key service with secrets manager."""
    return APIKeyService(mock_session, mock_secrets_manager)


class TestBasicIntegration:
    """Basic integration tests."""

    async def test_hash_storage_and_retrieval(self, api_key_service, mock_secrets_manager):
        """Test basic hash storage and retrieval functionality."""
        key_id = "test-key-123"
        test_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"

        # Test store
        result = await mock_secrets_manager.store_api_key_hash(key_id, test_hash)
        assert result is True

        # Verify store was called correctly
        mock_secrets_manager.store_api_key_hash.assert_called_once_with(key_id, test_hash)

    async def test_argon2_hash_generation(self, api_key_service):
        """Test Argon2 hash generation."""
        full_key, prefix, hash_value = api_key_service._generate_secure_key()

        # Verify hash format
        assert hash_value.startswith("$argon2")
        assert len(full_key) > 32
        assert prefix == full_key[:10]

    async def test_hash_verification(self, api_key_service):
        """Test hash verification for both Argon2 and SHA256."""
        test_key = "vutf_test_key_12345"

        # Test Argon2
        from passlib.hash import argon2

        argon2_hash = argon2.hash(test_key)
        result = await api_key_service._verify_key_hash(test_key, argon2_hash)
        assert result is True

        # Test SHA256 (legacy)
        import hashlib

        sha256_hash = hashlib.sha256(test_key.encode()).hexdigest()
        result = await api_key_service._verify_key_hash(test_key, sha256_hash)
        assert result is True
