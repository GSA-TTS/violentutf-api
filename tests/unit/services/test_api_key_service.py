"""Comprehensive tests for API Key service."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.models.api_key import APIKey
from app.models.user import User
from app.services.api_key_service_simple import APIKeyService


@pytest.fixture
def mock_session():
    """Create mock database session."""
    session = AsyncMock(spec=AsyncSession)
    return session


@pytest.fixture
def mock_user():
    """Create mock user."""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "test@example.com"
    user.is_active = True
    return user


@pytest.fixture
def api_key_service(mock_session):
    """Create API Key service instance."""
    return APIKeyService(mock_session)


class TestAPIKeyService:
    """Test API Key service."""

    @pytest.mark.asyncio
    async def test_create_api_key_success(self, api_key_service, mock_user):
        """Test successful API key creation."""
        # Arrange
        name = "Test API Key"
        scopes = ["users:read", "users:write"]
        expires_in_days = 30

        with patch.object(api_key_service, "_generate_secure_key", return_value="test_key_123"):
            with patch.object(api_key_service.session, "add"):
                with patch.object(api_key_service.session, "flush"):
                    # Act
                    api_key, plain_key = await api_key_service.create_api_key(
                        user_id=str(mock_user.id),
                        name=name,
                        scopes=scopes,
                        expires_in_days=expires_in_days,
                    )

                    # Assert
                    assert api_key.name == name
                    # Check permissions dict instead of scopes
                    expected_permissions = {scope: True for scope in scopes}
                    assert api_key.permissions == expected_permissions
                    assert api_key.user_id == mock_user.id
                    assert plain_key == "test_key_123"
                    # is_active is a method, not a property
                    assert api_key.is_active() is True
                    assert api_key.expires_at is not None

    @pytest.mark.asyncio
    async def test_create_api_key_with_invalid_name(self, api_key_service, mock_user):
        """Test API key creation with invalid name."""
        # Arrange
        invalid_names = ["", "a", "a" * 256]

        # Act & Assert
        for name in invalid_names:
            with pytest.raises(ValidationError):
                await api_key_service.create_api_key(
                    user_id=str(mock_user.id),
                    name=name,
                    scopes=["users:read"],
                )

    @pytest.mark.asyncio
    async def test_create_api_key_with_no_scopes(self, api_key_service, mock_user):
        """Test API key creation with no scopes."""
        # Act & Assert
        with pytest.raises(ValidationError, match="At least one scope is required"):
            await api_key_service.create_api_key(
                user_id=str(mock_user.id),
                name="Test Key",
                scopes=[],
            )

    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, api_key_service):
        """Test successful API key validation."""
        # Arrange
        plain_key = "test_key_123"
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=True)
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        mock_api_key.last_used_at = None
        mock_api_key.user = mock_user = MagicMock(spec=User)
        mock_user.is_active = True

        with patch.object(api_key_service, "_hash_key", return_value="hashed_key"):
            with patch.object(api_key_service.repository, "get_by_hash", return_value=mock_api_key):
                with patch.object(api_key_service.session, "flush"):
                    # Act
                    result = await api_key_service.validate_api_key(plain_key)

                    # Assert
                    assert result == (mock_api_key, mock_user)
                    assert mock_api_key.last_used_at is not None

    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, api_key_service):
        """Test API key validation when key not found."""
        # Arrange
        plain_key = "invalid_key"

        with patch.object(api_key_service, "_hash_key", return_value="hashed_key"):
            with patch.object(api_key_service.repository, "get_by_hash", return_value=None):
                # Act & Assert
                with pytest.raises(AuthenticationError, match="Invalid API key"):
                    await api_key_service.validate_api_key(plain_key)

    @pytest.mark.asyncio
    async def test_validate_api_key_inactive(self, api_key_service):
        """Test API key validation when key is inactive."""
        # Arrange
        plain_key = "test_key_123"
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=False)

        with patch.object(api_key_service, "_hash_key", return_value="hashed_key"):
            with patch.object(api_key_service.repository, "get_by_hash", return_value=mock_api_key):
                # Act & Assert
                with pytest.raises(AuthenticationError, match="API key is not active"):
                    await api_key_service.validate_api_key(plain_key)

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self, api_key_service):
        """Test API key validation when key is expired."""
        # Arrange
        plain_key = "test_key_123"
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=True)
        mock_api_key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)

        with patch.object(api_key_service, "_hash_key", return_value="hashed_key"):
            with patch.object(api_key_service.repository, "get_by_hash", return_value=mock_api_key):
                # Act & Assert
                with pytest.raises(AuthenticationError, match="API key has expired"):
                    await api_key_service.validate_api_key(plain_key)

    @pytest.mark.asyncio
    async def test_validate_api_key_user_inactive(self, api_key_service):
        """Test API key validation when user is inactive."""
        # Arrange
        plain_key = "test_key_123"
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=True)
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        mock_api_key.user = mock_user = MagicMock(spec=User)
        mock_user.is_active = False

        with patch.object(api_key_service, "_hash_key", return_value="hashed_key"):
            with patch.object(api_key_service.repository, "get_by_hash", return_value=mock_api_key):
                # Act & Assert
                with pytest.raises(AuthenticationError, match="User account is not active"):
                    await api_key_service.validate_api_key(plain_key)

    @pytest.mark.asyncio
    async def test_rotate_api_key_success(self, api_key_service):
        """Test successful API key rotation."""
        # Arrange
        api_key_id = str(uuid.uuid4())
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.id = uuid.UUID(api_key_id)
        mock_api_key.name = "Test Key"
        mock_api_key.permissions = {"users:read": True}
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        mock_api_key.user_id = uuid.uuid4()

        with patch.object(api_key_service.repository, "get", return_value=mock_api_key):
            with patch.object(api_key_service, "_generate_secure_key", return_value="new_key_123"):
                with patch.object(api_key_service.session, "add"):
                    with patch.object(api_key_service.session, "flush"):
                        # Act
                        new_api_key, plain_key = await api_key_service.rotate_api_key(api_key_id)

                        # Assert
                        assert new_api_key.name == f"{mock_api_key.name} (Rotated)"
                        assert new_api_key.permissions == mock_api_key.permissions
                        assert plain_key == "new_key_123"
                        assert mock_api_key.is_deleted is True

    @pytest.mark.asyncio
    async def test_rotate_api_key_not_found(self, api_key_service):
        """Test API key rotation when key not found."""
        # Arrange
        api_key_id = str(uuid.uuid4())

        with patch.object(api_key_service.repository, "get", return_value=None):
            # Act & Assert
            with pytest.raises(NotFoundError, match="API key not found"):
                await api_key_service.rotate_api_key(api_key_id)

    @pytest.mark.asyncio
    async def test_revoke_api_key_success(self, api_key_service):
        """Test successful API key revocation."""
        # Arrange
        api_key_id = str(uuid.uuid4())
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=True)
        mock_api_key.is_deleted = False

        with patch.object(api_key_service.repository, "get", return_value=mock_api_key):
            with patch.object(api_key_service.session, "flush"):
                # Act
                result = await api_key_service.revoke_api_key(api_key_id)

                # Assert
                assert result is True
                assert mock_api_key.is_deleted is True
                assert mock_api_key.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_api_key_already_revoked(self, api_key_service):
        """Test API key revocation when already revoked."""
        # Arrange
        api_key_id = str(uuid.uuid4())
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.is_active = MagicMock(return_value=False)

        with patch.object(api_key_service.repository, "get", return_value=mock_api_key):
            # Act
            result = await api_key_service.revoke_api_key(api_key_id)

            # Assert
            assert result is False

    @pytest.mark.asyncio
    async def test_list_user_api_keys(self, api_key_service):
        """Test listing user API keys."""
        # Arrange
        user_id = str(uuid.uuid4())
        mock_keys = [
            MagicMock(spec=APIKey, name="Key 1", is_active=MagicMock(return_value=True)),
            MagicMock(spec=APIKey, name="Key 2", is_active=MagicMock(return_value=False)),
        ]

        with patch.object(api_key_service.repository, "list_user_keys", return_value=mock_keys):
            # Act
            result = await api_key_service.list_user_api_keys(user_id, include_revoked=True)

            # Assert
            assert len(result) == 2
            assert result == mock_keys

    @pytest.mark.asyncio
    async def test_list_user_api_keys_active_only(self, api_key_service):
        """Test listing only active user API keys."""
        # Arrange
        user_id = str(uuid.uuid4())
        mock_key1 = MagicMock(spec=APIKey)
        mock_key1.name = "Key 1"
        mock_key1.is_active = MagicMock(return_value=True)

        mock_key2 = MagicMock(spec=APIKey)
        mock_key2.name = "Key 2"
        mock_key2.is_active = MagicMock(return_value=False)

        mock_keys = [mock_key1, mock_key2]

        with patch.object(api_key_service.repository, "list_user_keys", return_value=mock_keys):
            # Act
            result = await api_key_service.list_user_api_keys(user_id, include_revoked=False)

            # Assert
            assert len(result) == 1
            assert result[0].name == "Key 1"

    @pytest.mark.asyncio
    async def test_check_api_key_permissions(self, api_key_service):
        """Test checking API key permissions."""
        # Arrange
        api_key = MagicMock(spec=APIKey)
        api_key.permissions = {"users:read": True, "users:write": True, "admin:system": True}

        # Act & Assert
        # Single permission check
        assert api_key_service.check_api_key_permissions(api_key, ["users:read"]) is True
        assert api_key_service.check_api_key_permissions(api_key, ["delete:users"]) is False

        # Multiple permissions check
        assert api_key_service.check_api_key_permissions(api_key, ["users:read", "users:write"]) is True
        assert api_key_service.check_api_key_permissions(api_key, ["users:read", "users:delete"]) is False

        # Wildcard check - the API key doesn't have admin:* permission, so it should be False
        assert api_key_service.check_api_key_permissions(api_key, ["admin:*"]) is False

        # Add a test with wildcard permission in the key
        api_key_with_wildcard = MagicMock(spec=APIKey)
        api_key_with_wildcard.permissions = {"users:*": True}
        assert api_key_service.check_api_key_permissions(api_key_with_wildcard, ["users:read"]) is True
        assert api_key_service.check_api_key_permissions(api_key_with_wildcard, ["users:write"]) is True
        assert api_key_service.check_api_key_permissions(api_key_with_wildcard, ["users:delete"]) is True

    @pytest.mark.asyncio
    async def test_cleanup_expired_keys(self, api_key_service):
        """Test cleanup of expired API keys."""
        # Arrange
        mock_expired_keys = [
            MagicMock(spec=APIKey, id=uuid.uuid4(), is_deleted=False),
            MagicMock(spec=APIKey, id=uuid.uuid4(), is_deleted=False),
        ]
        # Mock is_active to return True so they get cleaned up
        for key in mock_expired_keys:
            key.is_active = MagicMock(return_value=True)

        with patch.object(api_key_service.repository, "get_expired_keys", return_value=mock_expired_keys):
            with patch.object(api_key_service.session, "flush"):
                # Act
                count = await api_key_service.cleanup_expired_keys()

                # Assert
                assert count == 2
                for key in mock_expired_keys:
                    assert key.is_deleted is True

    def test_generate_secure_key(self, api_key_service):
        """Test secure key generation."""
        # Act
        key1 = api_key_service._generate_secure_key()
        key2 = api_key_service._generate_secure_key()

        # Assert
        assert len(key1) >= 32
        assert len(key2) >= 32
        assert key1 != key2
        assert key1.startswith(api_key_service.KEY_PREFIX)
        assert key2.startswith(api_key_service.KEY_PREFIX)

    def test_hash_key(self, api_key_service):
        """Test key hashing."""
        # Arrange
        key = "test_key_123"

        # Act
        hash1 = api_key_service._hash_key(key)
        hash2 = api_key_service._hash_key(key)
        hash3 = api_key_service._hash_key("different_key")

        # Assert
        assert hash1 == hash2  # Same key produces same hash
        assert hash1 != hash3  # Different keys produce different hashes
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
