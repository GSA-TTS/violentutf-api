"""Comprehensive tests for User CRUD endpoints."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.endpoints.users import user_crud_router
from app.core.config import settings
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserResponse, UserUpdate, UserUpdatePassword

# Import test fixtures
from tests.test_fixtures import admin_token, auth_token  # noqa: F401


class TestUserEndpoints:
    """Test suite for User CRUD endpoints."""

    def create_test_jwt_token(
        self,
        user_id: str = "12345678-1234-5678-9abc-123456789abc",
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

        # Use the test SECRET_KEY directly
        encoded_jwt = jwt.encode(
            payload,
            "test-secret-key-for-testing-only-32chars",
            algorithm="HS256",
        )
        return str(encoded_jwt)

    def create_admin_jwt_token(self, user_id: str = "87654321-4321-8765-cba9-987654321cba") -> str:
        """Create test JWT token with admin privileges."""
        return self.create_test_jwt_token(user_id=user_id, roles=["admin"])

    @pytest.fixture
    def mock_user(self) -> User:
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = str(uuid.uuid4())  # Convert to string for UserResponse
        user.username = "testuser"
        user.email = "test@example.com"
        user.full_name = "Test User"
        user.is_active = True
        user.is_superuser = False
        user.is_verified = True
        user.last_login_at = None
        user.last_login_ip = "192.168.1.1"  # String value instead of MagicMock
        user.created_at = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        user.created_by = "system"
        user.updated_by = "system"
        user.version = 1
        return user

    @pytest.fixture
    def mock_user_repo(self, mock_user: User) -> AsyncMock:
        """Create a mock user repository."""
        repo = AsyncMock(spec=UserRepository)
        repo.get.return_value = mock_user
        repo.get_by_username.return_value = mock_user
        repo.list_paginated.return_value = ([mock_user], 1)
        repo.create_user.return_value = mock_user
        repo.update.return_value = mock_user
        repo.delete.return_value = True
        repo.is_username_available.return_value = True
        repo.is_email_available.return_value = True
        repo.update_password.return_value = True
        repo.verify_user.return_value = True
        repo.activate_user.return_value = True
        repo.deactivate_user.return_value = True
        return repo

    @pytest.fixture
    def auth_headers(self, auth_token: str) -> Dict[str, str]:
        """Create authentication headers using test fixture token."""
        return {"Authorization": f"Bearer {auth_token}"}

    @pytest.fixture
    def admin_headers(self, admin_token: str) -> Dict[str, str]:
        """Create admin authentication headers using test fixture token."""
        return {"Authorization": f"Bearer {admin_token}"}

    @pytest.mark.asyncio
    async def test_list_users(
        self,
        async_client: AsyncClient,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test listing users with pagination."""
        # Patch the repository class attribute on the router
        original_repo = user_crud_router.repository
        user_crud_router.repository = lambda session: mock_user_repo
        try:
            response = await async_client.get(
                "/api/v1/users/",
                headers=auth_headers,
                params={"page": 1, "per_page": 20},
            )
        finally:
            # Restore original repository
            user_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "data" in data
        assert "total_count" in data
        assert "pagination" in data
        assert "page" in data["pagination"]
        assert "per_page" in data["pagination"]
        assert len(data["data"]) == 1
        mock_user_repo.list_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_by_id(
        self,
        async_client: AsyncClient,
        test_user: User,  # Use the real test user that matches the auth token
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting a user by ID."""
        # Get own user - no need to mock since we're testing the real endpoint
        response = await async_client.get(
            f"/api/v1/users/{test_user.id}",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(test_user.id)
        assert data["data"]["username"] == test_user.username
        assert data["data"]["email"] == test_user.email

    @pytest.mark.asyncio
    async def test_get_user_not_found(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting a non-existent user."""
        # Try to get a random user ID (not owned by auth user)
        user_id = uuid.uuid4()
        response = await async_client.get(
            f"/api/v1/users/{user_id}",
            headers=auth_headers,
        )

        # Due to ownership check, non-owned users return 404
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_create_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test creating a new user."""
        user_data = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!",
            "full_name": "New User",
            "is_superuser": False,
        }

        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                "/api/v1/users/",
                json=user_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["message"] == "User created successfully"
        mock_user_repo.is_username_available.assert_called_once_with(user_data["username"])
        mock_user_repo.is_email_available.assert_called_once_with(user_data["email"])
        mock_user_repo.create_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(
        self,
        async_client: AsyncClient,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test creating a user with duplicate username."""
        mock_user_repo.is_username_available.return_value = False

        user_data = {
            "username": "existing",
            "email": "new@example.com",
            "password": "SecurePass123!",
        }

        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                "/api/v1/users/",
                json=user_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already taken" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_update_user(
        self,
        async_client: AsyncClient,
        test_user: User,  # Use the real test user that matches the auth token
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating a user."""
        update_data = {
            "full_name": "Updated Name",
            "email": f"updated_{test_user.email}",  # Keep email unique
        }

        # Update own user - no need to mock since we're testing the real endpoint
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}",
            json=update_data,
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "User updated successfully"

    @pytest.mark.asyncio
    async def test_delete_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test deleting a user (admin only)."""
        # Patch the repository class attribute on the router (base CRUD endpoint)
        original_repo = user_crud_router.repository
        user_crud_router.repository = lambda session: mock_user_repo
        try:
            response = await async_client.delete(
                f"/api/v1/users/{mock_user.id}",
                headers=admin_headers,
            )
        finally:
            # Restore original repository
            user_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert data["data"]["affected_rows"] == 1
        mock_user_repo.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_current_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting current user profile."""
        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.get(
                "/api/v1/users/me",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_user.id)
        assert data["data"]["username"] == mock_user.username
        mock_user_repo.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_current_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating current user profile."""
        update_data = {"full_name": "My New Name"}

        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.put(
                "/api/v1/users/me",
                json=update_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Profile updated successfully"
        mock_user_repo.get.assert_called_once()
        mock_user_repo.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test changing user password."""
        password_data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!",
        }

        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                "/api/v1/users/me/change-password",
                json=password_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert data["data"]["message"] == "Password changed successfully"
        mock_user_repo.update_password.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_incorrect_current(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test changing password with incorrect current password."""
        mock_user_repo.update_password.return_value = False

        password_data = {
            "current_password": "WrongPass123!",
            "new_password": "NewPass123!",
        }

        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                "/api/v1/users/me/change-password",
                json=password_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Current password is incorrect" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_get_user_by_username(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting user by username."""
        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.get(
                f"/api/v1/users/username/{mock_user.username}",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["username"] == mock_user.username
        mock_user_repo.get_by_username.assert_called_once_with(mock_user.username)

    @pytest.mark.asyncio
    async def test_verify_user_email(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test verifying user email (admin only)."""
        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                f"/api/v1/users/{mock_user.id}/verify",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "verified successfully" in data["data"]["message"]
        mock_user_repo.verify_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_activate_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test activating a user (admin only)."""
        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                f"/api/v1/users/{mock_user.id}/activate",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "activated successfully" in data["data"]["message"]
        mock_user_repo.activate_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_deactivate_user(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test deactivating a user (admin only)."""
        # Patch the UserRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_user_repo
            response = await async_client.post(
                f"/api/v1/users/{mock_user.id}/deactivate",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "deactivated successfully" in data["data"]["message"]
        mock_user_repo.deactivate_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_admin_only_endpoints_unauthorized(
        self,
        async_client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that admin-only endpoints require admin privileges."""
        endpoints = [
            ("POST", f"/api/v1/users/{mock_user.id}/verify"),
            ("POST", f"/api/v1/users/{mock_user.id}/activate"),
            ("POST", f"/api/v1/users/{mock_user.id}/deactivate"),
            ("DELETE", f"/api/v1/users/{mock_user.id}"),
        ]

        for method, endpoint in endpoints:
            if method == "POST":
                # Custom endpoints - patch UserRepository class
                with patch("app.api.endpoints.users.UserRepository") as mock_repo_class:
                    mock_repo_class.return_value = mock_user_repo

                    # Mock the _check_admin_permission to raise ForbiddenError (simulate non-admin user)
                    with patch.object(user_crud_router, "_check_admin_permission") as mock_admin_check:
                        mock_admin_check.side_effect = ForbiddenError(message="Administrator privileges required")
                        response = await async_client.post(endpoint, headers=auth_headers)
            else:
                # Base CRUD endpoints - patch router repository
                original_repo = user_crud_router.repository
                user_crud_router.repository = lambda session: mock_user_repo
                try:
                    # Mock admin permission check for base CRUD endpoints too
                    with patch.object(user_crud_router, "_check_admin_permission") as mock_admin_check:
                        mock_admin_check.side_effect = ForbiddenError(message="Administrator privileges required")
                        response = await async_client.delete(endpoint, headers=auth_headers)
                finally:
                    user_crud_router.repository = original_repo

            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "Administrator privileges required" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_input_validation(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test input validation for user creation."""
        invalid_data = [
            # Empty username
            {"username": "", "email": "test@example.com", "password": "Pass123!"},
            # Invalid email
            {"username": "user", "email": "invalid-email", "password": "Pass123!"},
            # Weak password
            {"username": "user", "email": "test@example.com", "password": "weak"},
            # Username too long
            {"username": "u" * 101, "email": "test@example.com", "password": "Pass123!"},
        ]

        for data in invalid_data:
            response = await async_client.post(
                "/api/v1/users/",
                json=data,
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
