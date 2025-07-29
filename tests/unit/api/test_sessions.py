"""Comprehensive tests for Session CRUD endpoints."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import status
from httpx import AsyncClient

from app.api.endpoints.sessions import session_crud_router
from app.core.config import settings
from app.core.errors import ForbiddenError
from app.models.session import Session
from app.repositories.session import SessionRepository
from app.schemas.session import (
    SessionCreate,
    SessionExtendRequest,
    SessionResponse,
    SessionRevokeRequest,
    SessionStatistics,
    SessionUpdate,
)


class TestSessionEndpoints:
    """Test suite for Session CRUD endpoints."""

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

        encoded_jwt = jwt.encode(
            payload,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )
        return str(encoded_jwt)

    def create_admin_jwt_token(self, user_id: str = "87654321-4321-8765-cba9-987654321cba") -> str:
        """Create test JWT token with admin privileges."""
        return self.create_test_jwt_token(user_id=user_id, roles=["admin"])

    @pytest.fixture
    def mock_session(self) -> Session:
        """Create a mock session for testing."""
        session = MagicMock(spec=Session)
        # Set actual UUID and datetime values for Pydantic validation
        session_id = uuid.uuid4()
        # Use same user ID as JWT token for ownership checks - keep as UUID for comparison
        user_id = uuid.UUID("12345678-1234-5678-9abc-123456789abc")
        now = datetime.now(timezone.utc)

        session.id = session_id
        session.session_token = "hashed_token_123"
        session.refresh_token = "hashed_refresh_123"
        session.user_id = user_id
        session.device_info = "Mozilla/5.0 Chrome/91.0"
        session.ip_address = "192.168.1.100"
        session.location = "San Francisco, CA"
        session.is_active = True
        session.expires_at = now + timedelta(hours=24)
        session.last_activity_at = now
        session.last_activity_ip = "192.168.1.100"
        session.revoked_at = None
        session.revoked_by = None
        session.revocation_reason = None
        session.security_metadata = {"mfa": True, "risk_score": 0.1}

        # BaseModelSchema required fields - actual values for Pydantic validation
        session.created_at = now
        session.updated_at = now
        session.created_by = str(user_id)
        session.updated_by = str(user_id)
        session.version = 1

        # SessionResponse required fields - actual values for Pydantic validation
        session.is_expired = False

        # Mock methods that need to be callable
        session.is_valid = MagicMock(return_value=True)
        session.mask_token = MagicMock(return_value="hash...123")
        session.masked_token = "hash...123"  # Required by SessionResponse schema
        return session

    @pytest.fixture
    def mock_session_repo(self, mock_session: Session) -> AsyncMock:
        """Create a mock session repository."""
        repo = AsyncMock(spec=SessionRepository)
        repo.get.return_value = mock_session
        repo.get_by_token.return_value = mock_session
        repo.list_paginated.return_value = ([mock_session], 1)
        repo.get_user_sessions.return_value = [mock_session]
        repo.get_active_sessions.return_value = [mock_session]
        repo.create.return_value = mock_session
        repo.update.return_value = mock_session
        repo.delete.return_value = True
        repo.revoke_session.return_value = True
        repo.revoke_user_sessions.return_value = 3
        repo.cleanup_expired_sessions.return_value = 5
        repo.update_session_activity.return_value = True
        repo.extend_session.return_value = True
        repo.get_statistics.return_value = {
            "total_sessions": 150,
            "active_sessions": 100,
            "expired_sessions": 30,
            "revoked_sessions": 20,
            "sessions_created_today": 15,
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
    async def test_list_sessions(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test listing sessions with pagination."""
        # Patch the repository class attribute on the router (base CRUD endpoint)
        original_repo = session_crud_router.repository
        session_crud_router.repository = lambda session: mock_session_repo
        try:
            response = await async_client.get(
                "/api/v1/sessions/",
                headers=auth_headers,
                params={"page": 1, "per_page": 20},
            )
        finally:
            # Restore original repository
            session_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "data" in data
        assert "total_count" in data
        assert "pagination" in data
        assert len(data["data"]) == 1
        assert data["data"][0]["masked_token"] == "hash...123"
        mock_session_repo.list_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_by_id(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting a session by ID."""
        # Patch the repository class attribute on the router (base CRUD endpoint)
        original_repo = session_crud_router.repository
        session_crud_router.repository = lambda session: mock_session_repo
        try:
            response = await async_client.get(
                f"/api/v1/sessions/{mock_session.id}",
                headers=auth_headers,
            )
        finally:
            # Restore original repository
            session_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_session.id)
        assert data["data"]["user_id"] == str(mock_session.user_id)
        assert data["data"]["is_valid"] is True
        assert "session_token" not in data["data"]  # Token should be masked
        mock_session_repo.get.assert_called_once_with(mock_session.id)

    @pytest.mark.asyncio
    async def test_create_session(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test creating a new session."""
        # Use the same user_id as in the JWT token to pass permission check
        jwt_user_id = "12345678-1234-5678-9abc-123456789abc"
        session_data = {
            "user_id": jwt_user_id,
            "session_token": "new_session_token_123456789012345678901234567890",  # At least 32 chars
            "refresh_token": "new_refresh_token_123456789012345678901234567890",  # At least 32 chars
            "device_info": "Mozilla/5.0 Safari/14.0",
            "ip_address": "10.0.0.1",
            "location": "New York, NY",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat(),
            "security_metadata": {"mfa": False},
        }

        # Mock that no session with this token exists
        mock_session_repo.get_by_token.return_value = None

        # Create a properly configured session for the create method return
        created_session = MagicMock(spec=Session)
        created_session_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        created_session.id = created_session_id
        created_session.session_token = "new_session_token_123456789012345678901234567890"
        created_session.refresh_token = "new_refresh_token_123456789012345678901234567890"
        created_session.user_id = uuid.UUID(jwt_user_id)  # Convert string to UUID
        created_session.device_info = "Mozilla/5.0 Safari/14.0"
        created_session.ip_address = "10.0.0.1"
        created_session.location = "New York, NY"
        created_session.is_active = True
        created_session.expires_at = now + timedelta(hours=48)
        created_session.last_activity_at = now
        created_session.last_activity_ip = "10.0.0.1"
        created_session.revoked_at = None
        created_session.revoked_by = None
        created_session.revocation_reason = None
        created_session.security_metadata = {"mfa": False}

        # BaseModelSchema required fields - actual values for Pydantic validation
        created_session.created_at = now
        created_session.updated_at = now
        created_session.created_by = jwt_user_id
        created_session.updated_by = jwt_user_id
        created_session.version = 1

        # SessionResponse required fields - actual values for Pydantic validation
        created_session.is_expired = False

        # Mock methods that need to be callable
        created_session.is_valid = MagicMock(return_value=True)
        created_session.mask_token = MagicMock(return_value="hash...123")
        created_session.masked_token = "hash...123"

        # Override the create method to return the properly configured session
        mock_session_repo.create.return_value = created_session

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo
            response = await async_client.post(
                "/api/v1/sessions/",
                json=session_data,
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["message"] == "Session created successfully"
        assert data["data"]["masked_token"] == "hash...123"
        mock_session_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_duplicate_token(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test creating a session with duplicate token."""
        session_data = {
            "user_id": str(mock_session.user_id),
            "session_token": "existing_token_123456789012345678901234567890",  # At least 32 chars
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        }

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo
            response = await async_client.post(
                "/api/v1/sessions/",
                json=session_data,
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already exists" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_update_session(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test updating a session."""
        update_data = {
            "device_info": "Updated device info",
            "location": "Los Angeles, CA",
        }

        # Patch the repository class attribute on the router (base CRUD endpoint)
        original_repo = session_crud_router.repository
        session_crud_router.repository = lambda session: mock_session_repo
        try:
            response = await async_client.put(
                f"/api/v1/sessions/{mock_session.id}",
                json=update_data,
                headers=auth_headers,
            )
        finally:
            # Restore original repository
            session_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Session updated successfully"
        mock_session_repo.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_session(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test deleting a session."""
        # Patch the repository class attribute on the router (base CRUD endpoint)
        original_repo = session_crud_router.repository
        session_crud_router.repository = lambda session: mock_session_repo
        try:
            response = await async_client.delete(
                f"/api/v1/sessions/{mock_session.id}",
                headers=auth_headers,
            )
        finally:
            # Restore original repository
            session_crud_router.repository = original_repo

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert data["data"]["affected_rows"] == 1
        mock_session_repo.delete.assert_called_once_with(mock_session.id)

    @pytest.mark.asyncio
    async def test_get_my_sessions(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test getting current user's sessions."""
        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo
            response = await async_client.get(
                "/api/v1/sessions/my-sessions",
                headers=auth_headers,
                params={"include_inactive": False},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["is_active"] is True
        mock_session_repo.get_user_sessions.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_session(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test revoking a session."""
        revoke_data = {"reason": "Security concern"}

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo

            # Mock the _get_current_user_id and _check_session_ownership methods
            with (
                patch.object(
                    session_crud_router, "_get_current_user_id", return_value="12345678-1234-5678-9abc-123456789abc"
                ),
                patch.object(session_crud_router, "_check_session_ownership", return_value=None),
            ):
                response = await async_client.post(
                    f"/api/v1/sessions/{mock_session.id}/revoke",
                    json=revoke_data,
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "revoked successfully" in data["data"]["message"]
        mock_session_repo.revoke_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(
        self,
        async_client: AsyncClient,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test revoking all sessions for current user."""
        revoke_data = {"reason": "Account security reset"}

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo

            # Mock the _get_current_user_id method to return the expected user_id
            with patch.object(
                session_crud_router, "_get_current_user_id", return_value="12345678-1234-5678-9abc-123456789abc"
            ):
                response = await async_client.post(
                    "/api/v1/sessions/revoke-all",
                    json=revoke_data,
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "Revoked 3 sessions" in data["data"]["message"]
        mock_session_repo.revoke_user_sessions.assert_called_once()

    @pytest.mark.asyncio
    async def test_extend_session(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test extending session expiration."""
        extend_data = {"extension_minutes": 120}

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo

            # Mock the _get_current_user_id and _check_session_ownership methods
            with (
                patch.object(
                    session_crud_router, "_get_current_user_id", return_value="12345678-1234-5678-9abc-123456789abc"
                ),
                patch.object(session_crud_router, "_check_session_ownership", return_value=None),
            ):
                response = await async_client.post(
                    f"/api/v1/sessions/{mock_session.id}/extend",
                    json=extend_data,
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["success"] is True
        assert "extended by 120 minutes" in data["data"]["message"]

    @pytest.mark.asyncio
    async def test_get_active_sessions_admin_only(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting all active sessions (admin only)."""
        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo
            response = await async_client.get(
                "/api/v1/sessions/active",
                headers=admin_headers,
                params={"limit": 50},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["is_active"] is True
        mock_session_repo.get_active_sessions.assert_called_once_with(50)

    @pytest.mark.asyncio
    async def test_get_session_statistics_admin_only(
        self,
        async_client: AsyncClient,
        mock_session_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting session statistics (admin only)."""
        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo
            response = await async_client.get(
                "/api/v1/sessions/statistics",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        stats = data["data"]
        assert stats["total_sessions"] == 150
        assert stats["active_sessions"] == 100
        assert stats["expired_sessions"] == 30
        assert stats["revoked_sessions"] == 20
        assert stats["sessions_created_today"] == 15
        mock_session_repo.get_statistics.assert_called_once()

    @pytest.mark.asyncio
    async def test_admin_endpoints_unauthorized(
        self,
        async_client: AsyncClient,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that admin-only endpoints require admin privileges."""
        endpoints = [
            "/api/v1/sessions/active",
            "/api/v1/sessions/statistics",
        ]

        for endpoint in endpoints:
            # Patch the SessionRepository class itself since the endpoint creates its own instance
            with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_session_repo

                # Mock the _check_admin_permission to raise ForbiddenError (simulate non-admin user)
                with patch.object(session_crud_router, "_check_admin_permission") as mock_admin_check:
                    mock_admin_check.side_effect = ForbiddenError(message="Administrator privileges required")
                    response = await async_client.get(endpoint, headers=auth_headers)

            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "Administrator privileges required" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_session_ownership_check(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        mock_session_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that users can only modify their own sessions."""
        # Set different user ID to test ownership check
        mock_session.user_id = uuid.uuid4()

        # Patch the SessionRepository class itself since the endpoint creates its own instance
        with patch("app.api.endpoints.sessions.SessionRepository") as mock_repo_class:
            mock_repo_class.return_value = mock_session_repo

            # Mock the _get_current_user_id method to return the expected user_id
            with patch.object(
                session_crud_router, "_get_current_user_id", return_value="12345678-1234-5678-9abc-123456789abc"
            ):
                # Try to revoke someone else's session
                response = await async_client.post(
                    f"/api/v1/sessions/{mock_session.id}/revoke",
                    json={"reason": "Test"},
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "only access your own sessions" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_session_token_validation(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test session token validation."""
        invalid_tokens = [
            # Too short
            {
                "session_token": "short",
                "user_id": str(uuid.uuid4()),
                "expires_at": datetime.now(timezone.utc).isoformat(),
            },
            # Contains invalid characters
            {
                "session_token": "token<script>alert()</script>",
                "user_id": str(uuid.uuid4()),
                "expires_at": datetime.now(timezone.utc).isoformat(),
            },
        ]

        for data in invalid_tokens:
            response = await async_client.post(
                "/api/v1/sessions/",
                json=data,
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_extend_session_validation(
        self,
        async_client: AsyncClient,
        mock_session: Session,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test session extension validation."""
        invalid_extensions = [
            {"extension_minutes": 0},  # Too small
            {"extension_minutes": 20000},  # Too large (> 1 week)
            {"extension_minutes": -60},  # Negative
        ]

        for data in invalid_extensions:
            response = await async_client.post(
                f"/api/v1/sessions/{mock_session.id}/extend",
                json=data,
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
