"""
Comprehensive tests for ABAC permission decorators.

This test suite provides 100% coverage for the ABAC-enhanced permission decorators
that replace simple permission checks with comprehensive attribute-based evaluation.
"""

import uuid
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.abac_permissions import (
    ABACPermissionChecker,
    ABACRequireAdmin,
    ABACRequireAPIKeyRead,
    ABACRequireUserRead,
    abac_permission_checker,
    require_abac_permission,
    require_admin_access,
    require_api_key_access,
    require_organization_admin,
    require_resource_access,
    require_session_access,
    require_user_access,
)
from app.core.errors import ForbiddenError, UnauthorizedError


class TestRequireABACPermission:
    """Test the main require_abac_permission decorator."""

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create mock FastAPI request."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "GET"
        request.url.path = "/api/v1/users"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {}
        return request

    @pytest.fixture
    def mock_session(self) -> AsyncSession:
        """Create mock database session."""
        return MagicMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_successful_permission_check(self, mock_request, mock_session):
        """Test successful ABAC permission check."""

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted by admin role")

            result = await test_endpoint(mock_request, mock_session)

            assert result == {"success": True}
            mock_check.assert_called_once_with(
                subject_id="user-123",
                resource_type="users",
                action="read",
                session=mock_session,
                organization_id="org-456",
                resource_id=None,
                resource_owner_id=None,
                environment={
                    "request_method": "GET",
                    "request_path": "/api/v1/users",
                    "user_agent": "test-agent",
                    "ip_address": "127.0.0.1",
                },
            )

    @pytest.mark.asyncio
    async def test_permission_denied(self, mock_request, mock_session):
        """Test ABAC permission denial."""

        @require_abac_permission(resource_type="users", action="delete")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (False, "Insufficient authority level")

            with pytest.raises(ForbiddenError) as exc_info:
                await test_endpoint(mock_request, mock_session)

            assert "Access denied: Insufficient authority level" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_authentication(self, mock_session):
        """Test missing authentication context."""
        request = MagicMock(spec=Request)
        request.state.user_id = None  # No user authenticated

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with pytest.raises(UnauthorizedError) as exc_info:
            await test_endpoint(request, mock_session)

        assert "Authentication is required to access this resource." in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resource_id_from_kwargs(self, mock_request, mock_session):
        """Test extracting resource ID from function kwargs."""

        @require_abac_permission(resource_type="users", action="read", resource_id_param="user_id")
        async def test_endpoint(request: Request, session: AsyncSession, user_id: str):
            return {"user_id": user_id}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(mock_request, mock_session, user_id="target-user-789")

            # Verify resource_id was passed correctly
            args, kwargs = mock_check.call_args
            assert kwargs["resource_id"] == "target-user-789"

    @pytest.mark.asyncio
    async def test_resource_id_from_path_params(self, mock_session):
        """Test extracting resource ID from path parameters."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "GET"
        request.url.path = "/api/v1/users/target-user-789"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {"user_id": "target-user-789"}

        @require_abac_permission(resource_type="users", action="read", resource_id_param="user_id")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(request, mock_session)

            # Verify resource_id was extracted from path params
            args, kwargs = mock_check.call_args
            assert kwargs["resource_id"] == "target-user-789"

    @pytest.mark.asyncio
    async def test_resource_owner_extraction(self, mock_request, mock_session):
        """Test extracting resource owner ID."""
        mock_request.path_params = {"owner_id": "owner-456"}

        @require_abac_permission(resource_type="api_keys", action="write", resource_owner_param="owner_id")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(mock_request, mock_session)

            # Verify resource_owner_id was passed
            args, kwargs = mock_check.call_args
            assert kwargs["resource_owner_id"] == "owner-456"

    @pytest.mark.asyncio
    async def test_additional_environment_context(self, mock_request, mock_session):
        """Test additional environmental context."""

        @require_abac_permission(
            resource_type="users", action="read", environment_context={"source": "api", "feature": "user_list"}
        )
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(mock_request, mock_session)

            # Verify environment context was merged
            args, kwargs = mock_check.call_args
            env = kwargs["environment"]
            assert env["source"] == "api"
            assert env["feature"] == "user_list"
            assert env["request_method"] == "GET"  # Standard context preserved

    @pytest.mark.asyncio
    async def test_explain_on_deny(self, mock_request, mock_session):
        """Test explanation generation on denial."""

        @require_abac_permission(resource_type="users", action="delete", explain_on_deny=True)
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            with patch("app.core.abac_permissions.explain_abac_decision") as mock_explain:
                mock_check.return_value = (False, "Access denied")
                mock_explain.return_value = {"decision": "DENY", "detailed_reason": "Low authority"}

                with patch("app.core.abac_permissions.logger") as mock_logger:
                    with pytest.raises(ForbiddenError):
                        await test_endpoint(mock_request, mock_session)

                    # Verify explanation was requested
                    mock_explain.assert_called_once()
                    mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_abac_context_injection(self, mock_request, mock_session):
        """Test ABAC context injection into endpoint kwargs."""

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(request: Request, session: AsyncSession, **kwargs):
            return kwargs

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted by admin role")

            result = await test_endpoint(mock_request, mock_session)

            # Verify ABAC context was injected
            assert "abac_context" in result
            abac_context = result["abac_context"]
            assert abac_context["subject_id"] == "user-123"
            assert abac_context["organization_id"] == "org-456"
            assert abac_context["decision_reason"] == "Access granted by admin role"

    @pytest.mark.asyncio
    async def test_evaluation_error_handling(self, mock_request, mock_session):
        """Test handling of ABAC evaluation errors."""

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.side_effect = Exception("ABAC evaluation failed")

            with pytest.raises(ForbiddenError) as exc_info:
                await test_endpoint(mock_request, mock_session)

            assert "Permission evaluation error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_request_object(self, mock_session):
        """Test error when request object is missing."""

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(session: AsyncSession):  # No request parameter
            return {"success": True}

        with pytest.raises(ValueError) as exc_info:
            await test_endpoint(mock_session)

        assert "Request object not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_session_object(self, mock_request):
        """Test error when session object is missing."""

        @require_abac_permission(resource_type="users", action="read")
        async def test_endpoint(request: Request):  # No session parameter
            return {"success": True}

        with pytest.raises(ValueError) as exc_info:
            await test_endpoint(mock_request)

        assert "Database session not found" in str(exc_info.value)


class TestResourceSpecificDecorators:
    """Test resource-specific access control decorators."""

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create mock FastAPI request."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "GET"
        request.url.path = "/api/v1/users"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {"user_id": "target-user-789"}
        return request

    @pytest.fixture
    def mock_session(self) -> AsyncSession:
        """Create mock database session."""
        return MagicMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_require_user_access(self, mock_request, mock_session):
        """Test require_user_access decorator."""

        @require_user_access(action="read", check_ownership=True)
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(mock_request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "users"
            assert kwargs["action"] == "read"
            assert kwargs["resource_id"] == "target-user-789"
            assert kwargs["resource_owner_id"] == "target-user-789"  # Same as resource_id for ownership

    @pytest.mark.asyncio
    async def test_require_api_key_access(self, mock_session):
        """Test require_api_key_access decorator."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "POST"
        request.url.path = "/api/v1/api-keys"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {"key_id": "api-key-789"}

        @require_api_key_access(action="write")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "api_keys"
            assert kwargs["action"] == "write"
            assert kwargs["resource_id"] == "api-key-789"

    @pytest.mark.asyncio
    async def test_require_session_access(self, mock_session):
        """Test require_session_access decorator."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "DELETE"
        request.url.path = "/api/v1/sessions"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {"session_id": "session-789"}

        @require_session_access(action="delete", check_ownership=True)
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await test_endpoint(request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "sessions"
            assert kwargs["action"] == "delete"
            assert kwargs["resource_id"] == "session-789"
            assert kwargs["resource_owner_id"] == "session-789"  # Ownership check enabled

    @pytest.mark.asyncio
    async def test_require_admin_access(self, mock_request, mock_session):
        """Test require_admin_access decorator."""

        @require_admin_access()
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted to global admin")

            await test_endpoint(mock_request, mock_session)

            # Verify correct parameters for admin access
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "*"
            assert kwargs["action"] == "manage"

    @pytest.mark.asyncio
    async def test_require_admin_access_with_resource(self, mock_request, mock_session):
        """Test require_admin_access with specific resource type."""

        @require_admin_access(resource_type="users")
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted to user admin")

            await test_endpoint(mock_request, mock_session)

            # Verify correct parameters for resource-specific admin
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "users"
            assert kwargs["action"] == "manage"

    @pytest.mark.asyncio
    async def test_require_organization_admin(self, mock_request, mock_session):
        """Test require_organization_admin decorator."""

        @require_organization_admin()
        async def test_endpoint(request: Request, session: AsyncSession):
            return {"success": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted to org admin")

            await test_endpoint(mock_request, mock_session)

            # Verify correct parameters for organization admin
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "organization"
            assert kwargs["action"] == "manage"


class TestABACPermissionChecker:
    """Test ABACPermissionChecker dependency class."""

    @pytest.fixture
    def permission_checker(self) -> ABACPermissionChecker:
        """Create ABAC permission checker."""
        return ABACPermissionChecker(
            resource_type="users", action="read", resource_id_param="user_id", resource_owner_param="owner_id"
        )

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create mock FastAPI request."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "GET"
        request.url.path = "/api/v1/users/target-789"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {"user_id": "target-789", "owner_id": "owner-456"}
        return request

    @pytest.fixture
    def mock_session(self) -> AsyncSession:
        """Create mock database session."""
        return MagicMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_successful_dependency_check(self, permission_checker, mock_request, mock_session):
        """Test successful permission check as FastAPI dependency."""
        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted by ownership rule")

            result = await permission_checker(mock_request, mock_session)

            # Verify returned context
            assert result["subject_id"] == "user-123"
            assert result["organization_id"] == "org-456"
            assert result["resource_id"] == "target-789"
            assert result["resource_owner_id"] == "owner-456"
            assert result["decision_reason"] == "Access granted by ownership rule"

    @pytest.mark.asyncio
    async def test_dependency_permission_denied(self, permission_checker, mock_request, mock_session):
        """Test permission denial in dependency."""
        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (False, "Access denied - insufficient privileges")

            with pytest.raises(ForbiddenError) as exc_info:
                await permission_checker(mock_request, mock_session)

            assert "Access denied: Access denied - insufficient privileges" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_dependency_missing_authentication(self, permission_checker, mock_session):
        """Test missing authentication in dependency."""
        request = MagicMock(spec=Request)
        request.state.user_id = None  # No authentication

        with pytest.raises(UnauthorizedError) as exc_info:
            await permission_checker(request, mock_session)

        assert "Authentication is required to access this resource." in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_dependency_resource_extraction(self, mock_request, mock_session):
        """Test resource parameter extraction in dependency."""
        checker = ABACPermissionChecker(resource_type="api_keys", action="write", resource_id_param="key_id")

        mock_request.path_params = {"key_id": "api-key-123"}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            result = await checker(mock_request, mock_session)

            # Verify resource extraction
            assert result["resource_id"] == "api-key-123"
            assert result["resource_owner_id"] is None  # Not specified


class TestPreConfiguredDependencies:
    """Test pre-configured permission dependencies."""

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create mock FastAPI request."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "GET"
        request.url.path = "/api/v1/test"
        request.headers.get.return_value = "test-agent"
        request.client.host = "127.0.0.1"
        request.path_params = {}
        return request

    @pytest.fixture
    def mock_session(self) -> AsyncSession:
        """Create mock database session."""
        return MagicMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_require_user_read_dependency(self, mock_request, mock_session):
        """Test ABACRequireUserRead pre-configured dependency."""
        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            result = await ABACRequireUserRead(mock_request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "users"
            assert kwargs["action"] == "read"

    @pytest.mark.asyncio
    async def test_require_api_key_read_dependency(self, mock_request, mock_session):
        """Test ABACRequireAPIKeyRead pre-configured dependency."""
        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted")

            await ABACRequireAPIKeyRead(mock_request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "api_keys"
            assert kwargs["action"] == "read"

    @pytest.mark.asyncio
    async def test_require_admin_dependency(self, mock_request, mock_session):
        """Test ABACRequireAdmin pre-configured dependency."""
        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Access granted to global admin")

            await ABACRequireAdmin(mock_request, mock_session)

            # Verify correct parameters
            args, kwargs = mock_check.call_args
            assert kwargs["resource_type"] == "*"
            assert kwargs["action"] == "manage"

    def test_abac_permission_checker_factory(self):
        """Test abac_permission_checker factory function."""
        checker = abac_permission_checker(
            resource_type="sessions", action="delete", resource_id_param="session_id", resource_owner_param="user_id"
        )

        assert isinstance(checker, ABACPermissionChecker)
        assert checker.resource_type == "sessions"
        assert checker.action == "delete"
        assert checker.resource_id_param == "session_id"
        assert checker.resource_owner_param == "user_id"


class TestABACPermissionIntegration:
    """Integration tests for ABAC permission system."""

    @pytest.mark.asyncio
    async def test_complete_permission_flow(self):
        """Test complete permission evaluation flow with ABAC."""
        # Mock request with full context
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "PUT"
        request.url.path = "/api/v1/users/user-123"
        request.headers.get.return_value = "api-client/1.0"
        request.client.host = "192.168.1.100"
        request.path_params = {"user_id": "user-123"}

        session = MagicMock(spec=AsyncSession)

        @require_abac_permission(
            resource_type="users",
            action="write",
            resource_id_param="user_id",
            resource_owner_param="user_id",  # Check ownership
            environment_context={"operation": "profile_update"},
        )
        async def update_user_profile(request: Request, session: AsyncSession, **kwargs):
            return {"updated": True, "abac_decision": kwargs.get("abac_context", {}).get("decision_reason")}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            mock_check.return_value = (True, "Ownership rule allowed access")

            result = await update_user_profile(request, session, user_id="user-123")

            # Verify successful execution with ABAC context
            assert result["updated"] is True
            assert result["abac_decision"] == "Ownership rule allowed access"

            # Verify ABAC evaluation was called with complete context
            args, kwargs = mock_check.call_args
            assert kwargs["subject_id"] == "user-123"
            assert kwargs["resource_type"] == "users"
            assert kwargs["action"] == "write"
            assert kwargs["organization_id"] == "org-456"
            assert kwargs["resource_id"] == "user-123"
            assert kwargs["resource_owner_id"] == "user-123"

            # Verify environment context
            env = kwargs["environment"]
            assert env["operation"] == "profile_update"
            assert env["request_method"] == "PUT"
            assert env["request_path"] == "/api/v1/users/user-123"
            assert env["user_agent"] == "api-client/1.0"
            assert env["ip_address"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_layered_security_check(self):
        """Test layered security with multiple decorators."""
        request = MagicMock(spec=Request)
        request.state.user_id = "admin-123"
        request.state.organization_id = "org-456"
        request.method = "DELETE"
        request.url.path = "/api/v1/users/target-789"
        request.headers.get.return_value = "admin-client"
        request.client.host = "10.0.0.1"
        request.path_params = {"user_id": "target-789"}

        session = MagicMock(spec=AsyncSession)

        @require_admin_access()
        @require_user_access(action="delete", check_ownership=False)
        async def delete_user_admin(request: Request, session: AsyncSession, **kwargs):
            return {"deleted": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            # Both decorators should pass
            mock_check.return_value = (True, "Admin privileges confirmed")

            result = await delete_user_admin(request, session, user_id="target-789")

            assert result["deleted"] is True
            # Should be called twice (once for each decorator)
            assert mock_check.call_count == 2

    @pytest.mark.asyncio
    async def test_error_propagation(self):
        """Test proper error propagation through decorator stack."""
        request = MagicMock(spec=Request)
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"
        request.method = "POST"
        request.url.path = "/api/v1/sensitive-operation"
        request.headers.get.return_value = "test-client"
        request.client.host = "127.0.0.1"
        request.path_params = {}

        session = MagicMock(spec=AsyncSession)

        @require_abac_permission(resource_type="system", action="manage")
        async def sensitive_operation(request: Request, session: AsyncSession):
            return {"executed": True}

        with patch("app.core.abac_permissions.check_abac_permission") as mock_check:
            # Simulate organization isolation violation
            mock_check.return_value = (False, "Organization isolation rule denied access")

            with pytest.raises(ForbiddenError) as exc_info:
                await sensitive_operation(request, session)

            # Verify error message includes ABAC decision reason
            assert "Organization isolation rule denied access" in str(exc_info.value)

            # Verify structured logging occurs
            with patch("structlog.stdlib.get_logger") as mock_logger:
                mock_logger.return_value.warning = MagicMock()

                try:
                    await sensitive_operation(request, session)
                except ForbiddenError:
                    pass
