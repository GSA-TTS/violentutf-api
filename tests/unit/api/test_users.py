"""Comprehensive tests for User CRUD endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.user import UserCreate, UserResponse, UserUpdate, UserUpdatePassword


class TestUserEndpoints:
    """Test suite for User CRUD endpoints."""

    @pytest.fixture
    def mock_user(self) -> User:
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = uuid.uuid4()
        user.username = "testuser"
        user.email = "test@example.com"
        user.full_name = "Test User"
        user.is_active = True
        user.is_superuser = False
        user.is_verified = True
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
    def auth_headers(self) -> Dict[str, str]:
        """Create authentication headers."""
        return {"Authorization": "Bearer test-token"}

    @pytest.fixture
    def admin_headers(self) -> Dict[str, str]:
        """Create admin authentication headers."""
        return {"Authorization": "Bearer admin-token"}

    @pytest.mark.asyncio
    async def test_list_users(
        self,
        client: AsyncClient,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test listing users with pagination."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.get(
                "/api/v1/users",
                headers=auth_headers,
                params={"page": 1, "per_page": 20},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "data" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert len(data["data"]) == 1
        mock_user_repo.list_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_by_id(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting a user by ID."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.get(
                f"/api/v1/users/{mock_user.id}",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_user.id)
        assert data["data"]["username"] == mock_user.username
        assert data["data"]["email"] == mock_user.email
        mock_user_repo.get.assert_called_once_with(mock_user.id)

    @pytest.mark.asyncio
    async def test_get_user_not_found(
        self,
        client: AsyncClient,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting a non-existent user."""
        mock_user_repo.get.return_value = None
        user_id = uuid.uuid4()

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.get(
                f"/api/v1/users/{user_id}",
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user(
        self,
        client: AsyncClient,
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

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
                "/api/v1/users",
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
        client: AsyncClient,
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

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
                "/api/v1/users",
                json=user_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already taken" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating a user."""
        update_data = {
            "full_name": "Updated Name",
            "email": "updated@example.com",
        }

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.put(
                f"/api/v1/users/{mock_user.id}",
                json=update_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "User updated successfully"
        mock_user_repo.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_user(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test deleting a user (admin only)."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.delete(
                f"/api/v1/users/{mock_user.id}",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert data["data"]["affected_rows"] == 1
        mock_user_repo.delete.assert_called_once_with(mock_user.id)

    @pytest.mark.asyncio
    async def test_get_current_user(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting current user profile."""
        # Mock the request state
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            with patch("app.api.endpoints.users.Request") as mock_request:
                mock_request.state.user_id = mock_user.id
                response = await client.get(
                    "/api/v1/users/me",
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_user.id)
        assert data["data"]["username"] == mock_user.username

    @pytest.mark.asyncio
    async def test_update_current_user(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating current user profile."""
        update_data = {"full_name": "My New Name"}

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.put(
                "/api/v1/users/me",
                json=update_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Profile updated successfully"

    @pytest.mark.asyncio
    async def test_change_password(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test changing user password."""
        password_data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!",
        }

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
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
        client: AsyncClient,
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

        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
                "/api/v1/users/me/change-password",
                json=password_data,
                headers=auth_headers,
            )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Current password is incorrect" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_user_by_username(
        self,
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting user by username."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.get(
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
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test verifying user email (admin only)."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
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
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test activating a user (admin only)."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
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
        client: AsyncClient,
        mock_user: User,
        mock_user_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test deactivating a user (admin only)."""
        with patch("app.api.endpoints.users.UserRepository", return_value=mock_user_repo):
            response = await client.post(
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
        client: AsyncClient,
        mock_user: User,
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
                response = await client.post(endpoint, headers=auth_headers)
            else:
                response = await client.delete(endpoint, headers=auth_headers)

            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "Administrator privileges required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_input_validation(
        self,
        client: AsyncClient,
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
            response = await client.post(
                "/api/v1/users",
                json=data,
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
