"""Comprehensive tests for enhanced API key endpoints and service."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.services.api_key_service import APIKeyService
from tests.utils.api_key import create_test_api_key, create_test_user


class TestAPIKeyService:
    """Test suite for the enhanced API key service."""

    @pytest.fixture
    async def api_key_service(self, clean_db_session: AsyncSession) -> APIKeyService:
        """Create API key service instance."""
        return APIKeyService(clean_db_session)

    @pytest.fixture
    async def test_user(self, clean_db_session: AsyncSession) -> Dict[str, Any]:
        """Create a test user."""
        return await create_test_user(clean_db_session)

    async def test_create_api_key_with_enhanced_security(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test creating API key with enhanced security features."""
        from app.schemas.api_key import APIKeyCreate

        # Create API key data
        key_data = APIKeyCreate(
            name="Test Enhanced Key",
            description="Test key with enhanced security",
            permissions={"users:read": True, "api_keys:read": True},
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        # Create API key with high entropy
        api_key, full_key = await api_key_service.create_api_key(
            user_id=str(test_user["id"]), key_data=key_data, entropy_bits=512
        )
        await clean_db_session.commit()

        # Verify API key properties
        assert api_key.name == "Test Enhanced Key"
        assert api_key.description == "Test key with enhanced security"
        assert api_key.user_id == test_user["id"]
        assert api_key.permissions == {"users:read": True, "api_keys:read": True}
        assert full_key.startswith("vutf_")
        assert len(full_key) > 20  # Should be longer with high entropy

        # Verify hash matches
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        assert api_key.key_hash == key_hash

    async def test_rotate_api_key(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test API key rotation functionality."""
        # Create initial API key
        api_key = await create_test_api_key(clean_db_session, test_user["id"], name="Rotation Test Key")
        original_hash = api_key.key_hash
        original_prefix = api_key.key_prefix

        # Rotate the key
        rotated_key, new_full_key = await api_key_service.rotate_api_key(str(api_key.id), str(test_user["id"]))
        await clean_db_session.commit()

        # Verify rotation
        assert rotated_key.id == api_key.id
        assert rotated_key.name == api_key.name
        assert rotated_key.key_hash != original_hash
        assert rotated_key.key_prefix != original_prefix
        assert new_full_key.startswith("vutf_")

        # Verify new hash matches
        new_hash = hashlib.sha256(new_full_key.encode()).hexdigest()
        assert rotated_key.key_hash == new_hash

    async def test_validate_api_key(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test API key validation."""
        # Create API key
        api_key = await create_test_api_key(clean_db_session, test_user["id"], name="Validation Test Key")

        # Generate a valid key for testing
        full_key = "vutf_test_key_value"
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        api_key.key_hash = key_hash
        await clean_db_session.commit()

        # Test valid key
        validated_key = await api_key_service.validate_api_key(full_key)
        assert validated_key is not None
        assert validated_key.id == api_key.id

        # Test invalid key
        invalid_key = await api_key_service.validate_api_key("invalid_key")
        assert invalid_key is None

    async def test_get_key_analytics(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test API key analytics functionality."""
        # Create multiple API keys with different states
        active_key = await create_test_api_key(clean_db_session, test_user["id"], name="Active Key")
        expired_key = await create_test_api_key(
            clean_db_session,
            test_user["id"],
            name="Expired Key",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        revoked_key = await create_test_api_key(clean_db_session, test_user["id"], name="Revoked Key")
        revoked_key.revoked_at = datetime.now(timezone.utc)

        # Add some usage
        active_key.usage_count = 100
        expired_key.usage_count = 50
        await clean_db_session.commit()

        # Get analytics
        analytics = await api_key_service.get_key_analytics(str(test_user["id"]))

        # Verify analytics
        assert analytics["total_keys"] == 3
        assert analytics["active_keys"] == 1
        assert analytics["revoked_keys"] == 1
        assert analytics["expired_keys"] == 1
        assert analytics["total_usage"] == 150
        assert "keys_by_permissions" in analytics
        assert "recent_usage" in analytics

    async def test_record_key_usage(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test recording API key usage."""
        # Create API key
        api_key = await create_test_api_key(clean_db_session, test_user["id"], name="Usage Test Key")
        original_count = api_key.usage_count

        # Record usage
        await api_key_service.record_key_usage(api_key, ip_address="192.168.1.1")

        # Verify usage was recorded
        await clean_db_session.refresh(api_key)
        assert api_key.usage_count == original_count + 1
        assert api_key.last_used_ip == "192.168.1.1"
        assert api_key.last_used_at is not None


class TestAPIKeyEndpoints:
    """Test suite for enhanced API key endpoints."""

    @pytest.fixture
    async def authenticated_client(
        self, client: TestClient, clean_db_session: AsyncSession
    ) -> tuple[TestClient, Dict[str, Any]]:
        """Create authenticated test client."""
        user = await create_test_user(clean_db_session)

        # Mock authentication
        client.headers["Authorization"] = f"Bearer test_token_{user['id']}"

        return client, user

    async def test_create_api_key_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test API key creation endpoint."""
        client, user = authenticated_client

        # Create API key
        key_data = {
            "name": "Test Endpoint Key",
            "description": "Test key via endpoint",
            "permissions": {"users:read": True, "api_keys:read": True},
        }

        response = await client.post("/api/v1/api-keys/", json=key_data)
        assert response.status_code == status.HTTP_201_CREATED

        data = response.json()
        assert data["success"] is True
        assert data["data"]["name"] == "Test Endpoint Key"
        assert data["data"]["key"].startswith("vutf_")
        assert "warning" in data["data"]

    async def test_rotate_api_key_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test API key rotation endpoint."""
        client, user = authenticated_client

        # Create API key first
        api_key = await create_test_api_key(clean_db_session, user["id"], name="Rotation Endpoint Test")
        original_key = api_key.key_hash

        # Rotate the key
        response = await client.post(f"/api/v1/api-keys/{api_key.id}/rotate")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert data["data"]["key"].startswith("vutf_")
        assert data["data"]["id"] == str(api_key.id)

        # Verify the key changed
        await clean_db_session.refresh(api_key)
        assert api_key.key_hash != original_key

    async def test_get_analytics_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test API key analytics endpoint."""
        client, user = authenticated_client

        # Create some test keys
        await create_test_api_key(clean_db_session, user["id"], name="Analytics Key 1")
        await create_test_api_key(clean_db_session, user["id"], name="Analytics Key 2")

        # Get analytics
        response = await client.get("/api/v1/api-keys/my-analytics")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert "total_keys" in data["data"]
        assert "active_keys" in data["data"]
        assert "keys_by_permissions" in data["data"]
        assert "recent_usage" in data["data"]

    async def test_validate_api_key_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test API key validation endpoint."""
        client, user = authenticated_client

        # Create API key
        api_key = await create_test_api_key(clean_db_session, user["id"], name="Validation Endpoint Test")

        # Test validation
        response = await client.post(f"/api/v1/api-keys/{api_key.id}/validate")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert "valid" in data["data"]["message"]

    async def test_revoke_api_key_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test API key revocation endpoint."""
        client, user = authenticated_client

        # Create API key
        api_key = await create_test_api_key(clean_db_session, user["id"], name="Revocation Endpoint Test")

        # Revoke the key
        response = await client.post(f"/api/v1/api-keys/{api_key.id}/revoke")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert "revoked successfully" in data["data"]["message"]

        # Verify key is revoked
        await clean_db_session.refresh(api_key)
        assert api_key.revoked_at is not None

    async def test_get_my_keys_endpoint(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test get my API keys endpoint."""
        client, user = authenticated_client

        # Create test keys
        active_key = await create_test_api_key(clean_db_session, user["id"], name="Active Key")
        revoked_key = await create_test_api_key(clean_db_session, user["id"], name="Revoked Key")
        revoked_key.revoked_at = datetime.now(timezone.utc)
        await clean_db_session.commit()

        # Get keys (excluding revoked)
        response = await client.get("/api/v1/api-keys/my-keys")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert len(data["data"]) == 1
        assert data["data"][0]["name"] == "Active Key"

        # Get keys (including revoked)
        response = await client.get("/api/v1/api-keys/my-keys?include_revoked=true")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert len(data["data"]) == 2

    async def test_permission_templates_endpoint(self, authenticated_client: tuple[TestClient, Dict[str, Any]]):
        """Test permission templates endpoint."""
        client, user = authenticated_client

        response = await client.get("/api/v1/api-keys/permission-templates")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["success"] is True
        assert "read_only" in data["data"]
        assert "admin" in data["data"]
        assert "user_management" in data["data"]


class TestAPIKeySecurityValidation:
    """Test suite for API key security validation."""

    @pytest.fixture
    async def api_key_service(self, clean_db_session: AsyncSession) -> APIKeyService:
        """Create API key service instance."""
        return APIKeyService(clean_db_session)

    @pytest.fixture
    async def test_user(self, clean_db_session: AsyncSession) -> Dict[str, Any]:
        """Create a test user."""
        return await create_test_user(clean_db_session)

    async def test_validate_permissions_invalid_scope(self, api_key_service: APIKeyService, test_user: Dict[str, Any]):
        """Test permission validation with invalid scope."""
        from app.core.errors import ValidationError
        from app.schemas.api_key import APIKeyCreate

        key_data = APIKeyCreate(name="Invalid Permissions Key", permissions={"invalid:scope": True})  # Invalid scope

        with pytest.raises(ValidationError, match="Invalid permission scope"):
            await api_key_service.create_api_key(str(test_user["id"]), key_data)

    async def test_validate_permissions_non_boolean_value(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any]
    ):
        """Test permission validation with non-boolean value."""
        from app.core.errors import ValidationError
        from app.schemas.api_key import APIKeyCreate

        key_data = APIKeyCreate(
            name="Invalid Permission Value Key", permissions={"users:read": "true"}  # Should be boolean, not string
        )

        with pytest.raises(ValidationError, match="must be boolean"):
            await api_key_service.create_api_key(str(test_user["id"]), key_data)

    async def test_duplicate_key_name_validation(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test validation of duplicate key names."""
        from app.core.errors import ConflictError
        from app.schemas.api_key import APIKeyCreate

        # Create first key
        key_data = APIKeyCreate(name="Duplicate Name Test", permissions={"users:read": True})
        await api_key_service.create_api_key(str(test_user["id"]), key_data)
        await clean_db_session.commit()

        # Try to create second key with same name
        with pytest.raises(ConflictError, match="already exists"):
            await api_key_service.create_api_key(str(test_user["id"]), key_data)

    async def test_key_entropy_generation(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test that keys generated with different entropy are actually different."""
        from app.schemas.api_key import APIKeyCreate

        key_data = APIKeyCreate(name="Entropy Test Key", permissions={"users:read": True})

        # Generate multiple keys and ensure they're different
        keys = []
        for i in range(5):
            key_data.name = f"Entropy Test Key {i}"
            api_key, full_key = await api_key_service.create_api_key(str(test_user["id"]), key_data)
            keys.append(full_key)

        # Ensure all keys are unique
        assert len(set(keys)) == 5

        # Ensure all keys have proper format
        for key in keys:
            assert key.startswith("vutf_")
            assert len(key) > 20  # Should have sufficient length

    async def test_inactive_key_validation(
        self, api_key_service: APIKeyService, test_user: Dict[str, Any], clean_db_session: AsyncSession
    ):
        """Test that inactive keys cannot be validated."""
        # Create expired key
        api_key = await create_test_api_key(
            clean_db_session,
            test_user["id"],
            name="Expired Key",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        # Generate a valid key for testing
        full_key = "vutf_expired_test_key"
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        api_key.key_hash = key_hash
        await clean_db_session.commit()

        # Test that expired key validation fails
        validated_key = await api_key_service.validate_api_key(full_key)
        assert validated_key is None


class TestAPIKeyErrorHandling:
    """Test suite for API key error handling."""

    @pytest.fixture
    async def authenticated_client(
        self, client: TestClient, clean_db_session: AsyncSession
    ) -> tuple[TestClient, Dict[str, Any]]:
        """Create authenticated test client."""
        user = await create_test_user(clean_db_session)

        # Mock authentication
        client.headers["Authorization"] = f"Bearer test_token_{user['id']}"

        return client, user

    async def test_rotate_nonexistent_key(self, authenticated_client: tuple[TestClient, Dict[str, Any]]):
        """Test rotating a non-existent API key."""
        client, user = authenticated_client

        fake_id = str(uuid.uuid4())
        response = await client.post(f"/api/v1/api-keys/{fake_id}/rotate")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_rotate_other_users_key(
        self, authenticated_client: tuple[TestClient, Dict[str, Any]], clean_db_session: AsyncSession
    ):
        """Test rotating another user's API key."""
        client, user = authenticated_client

        # Create key for different user
        other_user = await create_test_user(clean_db_session, email="other@example.com")
        other_key = await create_test_api_key(clean_db_session, other_user["id"], name="Other User Key")

        response = await client.post(f"/api/v1/api-keys/{other_key.id}/rotate")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_invalid_permission_in_create(self, authenticated_client: tuple[TestClient, Dict[str, Any]]):
        """Test creating API key with invalid permissions."""
        client, user = authenticated_client

        key_data = {"name": "Invalid Permissions Key", "permissions": {"invalid:scope": True}}

        response = await client.post("/api/v1/api-keys/", json=key_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_malformed_key_data(self, authenticated_client: tuple[TestClient, Dict[str, Any]]):
        """Test creating API key with malformed data."""
        client, user = authenticated_client

        # Missing required fields
        key_data = {"description": "Missing name field"}

        response = await client.post("/api/v1/api-keys/", json=key_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
