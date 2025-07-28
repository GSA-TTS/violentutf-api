"""Comprehensive tests for API Key CRUD endpoints."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.models.api_key import APIKey
from app.repositories.api_key import APIKeyRepository
from app.schemas.api_key import APIKeyCreate, APIKeyPermissionTemplate, APIKeyResponse, APIKeyUpdate


class TestAPIKeyEndpoints:
    """Test suite for API Key CRUD endpoints."""

    def create_test_jwt_token(
        self,
        user_id: str = "test-user-123",
        roles: list = None,
        organization_id: str = None,
        token_type: str = "access",
        exp_delta: timedelta = None,
    ) -> str:
        """Create test JWT token with proper structure."""
        if roles is None:
            roles = ["viewer"]
        if exp_delta is None:
            exp_delta = timedelta(hours=1)

        payload = {
            "sub": user_id,
            "roles": roles,
            "organization_id": organization_id,
            "type": token_type,
            "exp": datetime.now(timezone.utc) + exp_delta,
        }

        encoded_jwt = jwt.encode(
            payload,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )
        return str(encoded_jwt)

    def create_admin_jwt_token(self, user_id: str = "admin-user-123") -> str:
        """Create test JWT token with admin privileges."""
        return self.create_test_jwt_token(user_id=user_id, roles=["admin"])

    @pytest.fixture
    def mock_api_key(self) -> APIKey:
        """Create a mock API key for testing."""
        api_key = MagicMock(spec=APIKey)
        api_key.id = uuid.uuid4()
        api_key.name = "Test API Key"
        api_key.description = "Test API key for unit tests"
        api_key.key_prefix = "vutf_test123"
        api_key.key_hash = hashlib.sha256("vutf_test123_full_key".encode()).hexdigest()
        api_key.permissions = {"read": True, "write": False}
        api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        api_key.user_id = uuid.uuid4()
        api_key.is_active = MagicMock(return_value=True)
        api_key.mask_key = MagicMock(return_value="vutf_test...123")
        api_key.usage_count = 42
        api_key.last_used_at = datetime.now(timezone.utc)
        api_key.last_used_ip = "192.168.1.1"
        api_key.revoked_at = None
        api_key.created_at = datetime.now(timezone.utc)
        api_key.updated_at = datetime.now(timezone.utc)
        api_key.created_by = str(api_key.user_id)
        api_key.updated_by = str(api_key.user_id)
        api_key.version = 1
        return api_key

    @pytest.fixture
    def mock_api_key_repo(self, mock_api_key: APIKey) -> AsyncMock:
        """Create a mock API key repository."""
        repo = AsyncMock(spec=APIKeyRepository)
        repo.get.return_value = mock_api_key
        repo.list_paginated.return_value = ([mock_api_key], 1)
        repo.list_user_keys.return_value = [mock_api_key]
        repo.create.return_value = mock_api_key
        repo.update.return_value = mock_api_key
        repo.delete.return_value = True
        repo.revoke.return_value = True
        repo.get_statistics.return_value = {
            "total_keys": 100,
            "active_keys": 85,
            "expired_keys": 10,
            "revoked_keys": 5,
            "keys_used_today": 25,
            "total_requests": 1000,
        }
        return repo

    @pytest.fixture
    def auth_headers(self) -> Dict[str, str]:
        """Create authentication headers."""
        token = self.create_test_jwt_token()
        return {"Authorization": f"Bearer {token}"}

    @pytest.fixture
    def admin_headers(self) -> Dict[str, str]:
        """Create admin authentication headers."""
        token = self.create_admin_jwt_token()
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.asyncio
    async def test_list_api_keys(
        self,
        async_client: AsyncClient,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test listing API keys with pagination."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.get(
                "/api/v1/api-keys/",
                headers=auth_headers,
                params={"page": 1, "per_page": 20},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "data" in data
        assert "total" in data
        assert len(data["data"]) == 1
        assert data["data"][0]["name"] == "Test API Key"
        mock_api_key_repo.list_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_api_key_by_id(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting an API key by ID."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.get(
                f"/api/v1/api-keys/{mock_api_key.id}",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_api_key.id)
        assert data["data"]["name"] == mock_api_key.name
        assert data["data"]["key_prefix"] == mock_api_key.key_prefix
        assert "key" not in data["data"]  # Full key should not be exposed
        mock_api_key_repo.get.assert_called_once_with(mock_api_key.id)

    @pytest.mark.asyncio
    async def test_create_api_key(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test creating a new API key."""
        api_key_data = {
            "name": "New API Key",
            "description": "A new test API key",
            "permissions": {"read": True, "write": True},
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        }

        # Mock that no key with this name exists
        mock_api_key_repo.list_user_keys.return_value = []

        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            # Mock the key generation
            with patch("app.api.endpoints.api_keys.APIKeyCRUDRouter._generate_api_key") as mock_generate:
                mock_generate.return_value = ("vutf_fullkey123", "vutf_full", "hash123")

                response = await async_client.post(
                    "/api/v1/api-keys",
                    json=api_key_data,
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["message"] == "API key created successfully"
        assert "key" in data["data"]  # Full key shown only on creation
        assert data["data"]["warning"] == "Store this API key securely. It will not be shown again."
        mock_api_key_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_api_key_duplicate_name(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test creating an API key with duplicate name."""
        api_key_data = {
            "name": "Test API Key",  # Same as mock_api_key.name
            "permissions": {"read": True},
        }

        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.post(
                "/api/v1/api-keys",
                json=api_key_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_api_key(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating an API key."""
        update_data = {
            "name": "Updated API Key",
            "permissions": {"read": True, "write": True, "delete": False},
        }

        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.put(
                f"/api/v1/api-keys/{mock_api_key.id}",
                json=update_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "APIKey updated successfully"
        mock_api_key_repo.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_api_key(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test deleting an API key."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.delete(
                f"/api/v1/api-keys/{mock_api_key.id}",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert data["data"]["affected_rows"] == 1
        mock_api_key_repo.delete.assert_called_once_with(mock_api_key.id)

    @pytest.mark.asyncio
    async def test_get_my_api_keys(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting current user's API keys."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.get(
                "/api/v1/api-keys/my-keys",
                headers=auth_headers,
                params={"include_revoked": False},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["name"] == mock_api_key.name
        mock_api_key_repo.list_user_keys.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_api_key(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test revoking an API key."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.post(
                f"/api/v1/api-keys/{mock_api_key.id}/revoke",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "revoked successfully" in data["data"]["message"]
        mock_api_key_repo.revoke.assert_called_once_with(mock_api_key.id)

    @pytest.mark.asyncio
    async def test_validate_api_key(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test validating an API key."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.post(
                f"/api/v1/api-keys/{mock_api_key.id}/validate",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "valid" in data["data"]["message"]

    @pytest.mark.asyncio
    async def test_get_permission_templates(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting permission templates."""
        response = await async_client.get(
            "/api/v1/api-keys/permission-templates",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "read_only" in data["data"]
        assert "user_management" in data["data"]
        assert "admin" in data["data"]

        # Check template structure
        read_only = data["data"]["read_only"]
        assert read_only["name"] == "Read Only"
        assert "permissions" in read_only
        assert read_only["permissions"]["users:read"] is True

    @pytest.mark.asyncio
    async def test_get_usage_statistics_admin_only(
        self,
        async_client: AsyncClient,
        mock_api_key_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting API key usage statistics (admin only)."""
        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.get(
                "/api/v1/api-keys/usage-stats",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        stats = data["data"]
        assert stats["total_keys"] == 100
        assert stats["active_keys"] == 85
        assert stats["expired_keys"] == 10
        assert stats["revoked_keys"] == 5
        assert stats["keys_used_today"] == 25
        assert stats["total_requests"] == 1000
        mock_api_key_repo.get_statistics.assert_called_once()

    @pytest.mark.asyncio
    async def test_usage_statistics_unauthorized(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that usage statistics requires admin privileges."""
        response = await async_client.get(
            "/api/v1/api-keys/usage-stats",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Administrator privileges required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_permission_validation(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test permission validation in API key creation."""
        invalid_permissions = [
            # Invalid scope
            {"invalid_scope": True},
            # Non-boolean value
            {"read": "yes"},
            # Mixed valid and invalid
            {"read": True, "invalid": True},
        ]

        for permissions in invalid_permissions:
            api_key_data = {
                "name": "Test Key",
                "permissions": permissions,
            }

            response = await async_client.post(
                "/api/v1/api-keys",
                json=api_key_data,
                headers=auth_headers,
            )

            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_api_key_expiration(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test API key with expiration date."""
        # Set key as expired
        mock_api_key.is_active.return_value = False
        mock_api_key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)

        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            response = await async_client.post(
                f"/api/v1/api-keys/{mock_api_key.id}/validate",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is False
        assert "invalid" in data["data"]["message"]

    @pytest.mark.asyncio
    async def test_api_key_ownership_check(
        self,
        async_client: AsyncClient,
        mock_api_key: APIKey,
        mock_api_key_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that users can only modify their own API keys."""
        # Set different user ID
        mock_api_key.user_id = uuid.uuid4()

        with patch("app.api.endpoints.api_keys.APIKeyRepository", return_value=mock_api_key_repo):
            # Try to revoke someone else's key
            response = await async_client.post(
                f"/api/v1/api-keys/{mock_api_key.id}/revoke",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "only revoke your own API keys" in response.json()["detail"]
