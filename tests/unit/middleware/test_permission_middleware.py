"""Comprehensive tests for permission checking middleware."""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.permissions import get_current_user_permissions, require_any_permission, require_permission
from app.middleware.permissions import PermissionChecker
from app.models.permission import Permission
from app.models.user import User


@pytest.fixture
def mock_request():
    """Create mock request."""
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.state.user_id = str(uuid.uuid4())
    request.state.user = MagicMock(spec=User)
    request.state.user.id = uuid.UUID(request.state.user_id)
    request.state.user.is_superuser = False
    request.url = MagicMock()
    request.url.path = "/api/v1/users/123"
    request.method = "GET"
    request.path_params = {"user_id": "123"}
    request.headers = {}
    request.state.trace_id = "test-trace-id"  # Add trace_id
    return request


@pytest.fixture
def mock_session():
    """Create mock database session."""
    return AsyncMock()


class TestPermissionMiddleware:
    """Test permission checking middleware."""

    @pytest.mark.asyncio
    async def test_permission_checker_public_endpoint(self, mock_request):
        """Test middleware allows public endpoints."""
        # Arrange
        mock_request.url.path = "/api/v1/health"
        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Act
        permission_checker = PermissionChecker()
        response = await permission_checker(mock_request, call_next)

        # Assert
        assert response.status_code == 200
        call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_no_user(self, mock_request):
        """Test middleware denies access when no user."""
        # Arrange
        mock_request.state.user_id = None
        mock_request.state.user = None
        call_next = AsyncMock()

        # Act
        permission_checker = PermissionChecker()
        response = await permission_checker(mock_request, call_next)

        # Assert
        assert response.status_code == 401
        response_data = json.loads(response.body)
        assert response_data["error"] == "Unauthorized"
        assert response_data["message"] == "Authentication required"
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_permission_checker_superuser_bypass(self, mock_request):
        """Test middleware allows superuser to bypass checks."""
        # Arrange
        mock_request.state.user.is_superuser = True
        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Act
        permission_checker = PermissionChecker()
        response = await permission_checker(mock_request, call_next)

        # Assert
        assert response.status_code == 200
        call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_with_valid_permission(self, mock_request):
        """Test middleware with valid permission."""
        # Arrange
        mock_request.url.path = "/api/v1/users"
        mock_request.method = "GET"

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Mock RBACService to return True for permission check
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = True
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 200
            call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_insufficient_permission(self, mock_request):
        """Test middleware denies with insufficient permission."""
        # Arrange
        mock_request.url.path = "/api/v1/users"
        mock_request.method = "DELETE"  # Requires delete permission

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Import AsyncSession to mock it properly
        from sqlalchemy.ext.asyncio import AsyncSession

        # Mock database session in request state as a real AsyncSession instance
        mock_db_session = MagicMock(spec=AsyncSession)
        mock_request.state.db_session = mock_db_session

        # Mock RBACService to return False for permission check
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = False
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 403
            response_data = json.loads(response.body)
            assert response_data["error"] == "Forbidden"
            assert "Permission" in response_data["message"]
            call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_permission_checker_ownership_check_own_resource(self, mock_request):
        """Test middleware allows access to own resource."""
        # Arrange
        user_id = mock_request.state.user_id
        mock_request.url.path = f"/api/v1/users/{user_id}"
        mock_request.method = "PUT"
        mock_request.path_params = {"user_id": user_id}

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Mock RBACService to return True for permission check (user owns resource)
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = True
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 200
            call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_ownership_check_other_resource(self, mock_request):
        """Test middleware denies access to other's resource."""
        # Arrange
        other_user_id = str(uuid.uuid4())
        mock_request.url.path = f"/api/v1/users/{other_user_id}"
        mock_request.method = "PUT"
        mock_request.path_params = {"user_id": other_user_id}

        call_next = AsyncMock()

        # Import AsyncSession to mock it properly
        from sqlalchemy.ext.asyncio import AsyncSession

        # Mock database session in request state as a real AsyncSession instance
        mock_db_session = MagicMock(spec=AsyncSession)
        mock_request.state.db_session = mock_db_session

        # Mock RBACService to return False for permission check (user doesn't own resource)
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = False
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 403
            response_data = json.loads(response.body)
            assert response_data["error"] == "Forbidden"
            assert "Permission" in response_data["message"]
            call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_current_user_permissions(self, mock_request, mock_session):
        """Test getting current user permissions."""
        # Arrange
        # The function returns a set of permission names (strings)
        mock_permissions = {"users:read:all", "users:write:own"}

        # Create an async generator for get_db
        async def mock_get_db():
            yield mock_session

        with patch("app.core.permissions.get_db", return_value=mock_get_db()):
            with patch("app.core.permissions.RBACService") as MockRBACService:
                mock_rbac = MockRBACService.return_value
                # Mock as an async method that returns the set
                mock_rbac.get_user_permissions = AsyncMock(return_value=mock_permissions)

                # Act
                permissions = await get_current_user_permissions(mock_request)

                # Assert
                assert len(permissions) == 2
                # The function returns a sorted list
                assert permissions == sorted(list(mock_permissions))
                mock_rbac.get_user_permissions.assert_called_once_with(mock_request.state.user_id)

    @pytest.mark.asyncio
    async def test_require_permission_decorator_allowed(self, mock_request, mock_session):
        """Test require_permission decorator when allowed."""

        # Arrange
        # Test the dependency function directly
        permission_dep = require_permission("users:read:all")

        # Mock the user as authenticated with the required permission
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_superuser = False
        mock_request.state.user = mock_user
        mock_request.state.user_id = str(mock_user.id)

        # Mock RBAC service to return True for permission check
        with patch("app.core.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission = AsyncMock(return_value=True)
            mock_rbac_class.return_value = mock_rbac_instance

            # Act - should not raise exception
            await permission_dep(mock_request, mock_session)

    @pytest.mark.asyncio
    async def test_require_permission_decorator_denied(self, mock_request, mock_session):
        """Test require_permission decorator when denied."""

        # Arrange
        # Test the dependency function directly
        permission_dep = require_permission("users:delete:all")

        # Mock the user as authenticated but without the required permission
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_superuser = False
        mock_request.state.user = mock_user
        mock_request.state.user_id = str(mock_user.id)

        # Mock RBAC service to return False for permission check
        with patch("app.core.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission = AsyncMock(return_value=False)
            mock_rbac_class.return_value = mock_rbac_instance

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await permission_dep(mock_request, mock_session)

            assert exc_info.value.status_code == 403
            assert "users:delete:all" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_require_any_permission_decorator_allowed(self, mock_request, mock_session):
        """Test require_any_permission decorator when one permission matches."""

        # Arrange
        # Test the dependency function directly
        permission_dep = require_any_permission(["users:delete:all", "users:write:all", "users:read:all"])

        # Mock the user as authenticated
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_superuser = False
        mock_request.state.user = mock_user
        mock_request.state.user_id = str(mock_user.id)

        # Mock RBAC service to return False for first two, True for the third
        with patch("app.core.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission = AsyncMock(side_effect=[False, False, True])
            mock_rbac_class.return_value = mock_rbac_instance

            # Act - should not raise exception
            await permission_dep(mock_request, mock_session)

    @pytest.mark.asyncio
    async def test_require_any_permission_decorator_denied(self, mock_request, mock_session):
        """Test require_any_permission decorator when no permission matches."""

        # Arrange
        # Test the dependency function directly
        permission_dep = require_any_permission(["users:delete:all", "users:write:all"])

        # Mock the user as authenticated but without any required permission
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_superuser = False
        mock_request.state.user = mock_user
        mock_request.state.user_id = str(mock_user.id)

        # Mock RBAC service to return False for all permissions
        with patch("app.core.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission = AsyncMock(return_value=False)
            mock_rbac_class.return_value = mock_rbac_instance

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await permission_dep(mock_request, mock_session)

            assert exc_info.value.status_code == 403
            assert "users:delete:all" in str(exc_info.value.detail) or "users:write:all" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_permission_checker_wildcard_permissions(self, mock_request):
        """Test middleware with wildcard permissions."""
        # Arrange
        mock_request.url.path = "/api/v1/users"
        mock_request.method = "DELETE"

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Mock RBACService to return True for wildcard permission check
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = True
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 200
            call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_api_key_endpoints(self, mock_request):
        """Test middleware for API key endpoints."""
        # Arrange
        mock_request.url.path = "/api/v1/api-keys"
        mock_request.method = "POST"

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Mock RBACService to return True for API key permission check
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = True
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 200
            call_next.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_permission_checker_custom_resource_mapping(self, mock_request):
        """Test middleware with custom resource mapping."""
        # Arrange
        mock_request.url.path = "/api/v1/audit-logs"
        mock_request.method = "GET"

        call_next = AsyncMock(return_value=JSONResponse({"status": "ok"}))

        # Mock RBACService to return True for audit log permission check
        with patch("app.middleware.permissions.RBACService") as mock_rbac_class:
            mock_rbac_instance = AsyncMock()
            mock_rbac_instance.check_user_permission.return_value = True
            mock_rbac_class.return_value = mock_rbac_instance

            # Act
            permission_checker = PermissionChecker()
            response = await permission_checker(mock_request, call_next)

            # Assert
            assert response.status_code == 200
            call_next.assert_called_once_with(mock_request)
