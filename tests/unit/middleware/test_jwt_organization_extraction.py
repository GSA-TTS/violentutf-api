"""Tests for JWT organization_id extraction in authentication middleware.

This module tests the critical security fix for multi-tenant isolation in JWT authentication.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response
from fastapi.testclient import TestClient

from app.middleware.authentication import JWTAuthenticationMiddleware


class TestJWTOrganizationExtraction:
    """Test JWT middleware organization_id extraction."""

    @pytest.fixture
    def middleware(self):
        """Create JWT authentication middleware."""
        app_mock = Mock()
        return JWTAuthenticationMiddleware(app_mock)

    @pytest.fixture
    def mock_request(self):
        """Create mock request with proper state."""
        request = Mock(spec=Request)

        # Use a simple object for state that allows attribute assignment
        class StateObject:
            pass

        request.state = StateObject()
        request.url = Mock()
        request.url.path = "/api/v1/users"
        request.method = "GET"
        request.headers = {}
        request.client = Mock()
        request.client.host = "127.0.0.1"
        return request

    @pytest.fixture
    def valid_jwt_payload(self):
        """Create valid JWT payload with organization_id."""
        return {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "roles": ["user"],
            "organization_id": "org-123e4567-e89b-12d3-a456-426614174000",
            "type": "access",
            "exp": 9999999999,  # Far future
        }

    @pytest.fixture
    def jwt_payload_without_org(self):
        """Create JWT payload missing organization_id."""
        return {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "roles": ["user"],
            "type": "access",
            "exp": 9999999999,
        }

    async def test_organization_id_extracted_from_valid_jwt(self, middleware, mock_request, valid_jwt_payload):
        """Test that organization_id is properly extracted from JWT payload."""
        # Setup
        mock_request.headers["Authorization"] = "Bearer valid.jwt.token"
        mock_call_next = AsyncMock(return_value=Response())

        with patch("app.middleware.authentication.decode_token", return_value=valid_jwt_payload):
            # Execute
            await middleware.dispatch(mock_request, mock_call_next)

            # Verify organization_id was extracted and set
            assert hasattr(mock_request.state, "organization_id")
            assert mock_request.state.organization_id == "org-123e4567-e89b-12d3-a456-426614174000"
            assert mock_request.state.user_id == "550e8400-e29b-41d4-a716-446655440000"

    async def test_organization_id_none_when_missing_from_jwt(self, middleware, mock_request, jwt_payload_without_org):
        """Test that organization_id is None when missing from JWT payload."""
        # Setup
        mock_request.headers["Authorization"] = "Bearer valid.jwt.token"
        mock_call_next = AsyncMock(return_value=Response())

        with patch(
            "app.middleware.authentication.decode_token",
            return_value=jwt_payload_without_org,
        ):
            # Execute
            await middleware.dispatch(mock_request, mock_call_next)

            # Verify organization_id is None when missing from JWT
            assert hasattr(mock_request.state, "organization_id")
            assert mock_request.state.organization_id is None
            assert mock_request.state.user_id == "550e8400-e29b-41d4-a716-446655440000"

    async def test_organization_id_not_set_without_authentication(self, middleware, mock_request):
        """Test that organization_id is not set when no authentication is provided."""
        # Setup - exempt path that doesn't require auth
        mock_request.url.path = "/api/v1/health"
        mock_call_next = AsyncMock(return_value=Response())

        # Execute
        await middleware.dispatch(mock_request, mock_call_next)

        # Verify no organization_id is set for unauthenticated requests
        assert not hasattr(mock_request.state, "organization_id")
        assert not hasattr(mock_request.state, "user_id")

    async def test_organization_id_helper_function(self, mock_request):
        """Test the get_current_organization_id helper function."""
        from app.middleware.authentication import get_current_organization_id

        # Test with organization_id set
        mock_request.state.organization_id = "org-456"
        result = get_current_organization_id(mock_request)
        assert result == "org-456"

        # Test with None
        mock_request.state.organization_id = None
        result = get_current_organization_id(mock_request)
        assert result is None

        # Test with missing attribute
        delattr(mock_request.state, "organization_id")
        result = get_current_organization_id(mock_request)
        assert result is None

    async def test_critical_security_fix_verification(self, middleware, mock_request, valid_jwt_payload):
        """Test that verifies the critical security fix is properly implemented.

        This test specifically validates that the JWT middleware now extracts
        organization_id from JWT tokens, fixing the critical multi-tenant
        isolation vulnerability identified in the security audit.
        """
        # Setup with organization_id in JWT
        mock_request.headers["Authorization"] = "Bearer secure.jwt.token"
        mock_call_next = AsyncMock(return_value=Response())

        with patch("app.middleware.authentication.decode_token", return_value=valid_jwt_payload):
            # Execute middleware
            response = await middleware.dispatch(mock_request, mock_call_next)

            # CRITICAL: Verify the security fix is implemented
            assert hasattr(
                mock_request.state, "organization_id"
            ), "CRITICAL SECURITY BUG: organization_id not extracted from JWT payload"

            assert (
                mock_request.state.organization_id is not None
            ), "CRITICAL SECURITY BUG: organization_id is None despite being in JWT"

            assert (
                mock_request.state.organization_id == valid_jwt_payload["organization_id"]
            ), "CRITICAL SECURITY BUG: organization_id mismatch between JWT and request state"

            # Verify other fields still work
            assert mock_request.state.user_id == valid_jwt_payload["sub"]
            assert hasattr(mock_request.state, "token_payload")

    @pytest.mark.parametrize(
        "org_id",
        [
            "org-123",
            "550e8400-e29b-41d4-a716-446655440000",
            None,
            "",
        ],
    )
    async def test_organization_id_extraction_edge_cases(self, middleware, mock_request, org_id):
        """Test organization_id extraction with various edge cases."""
        # Setup JWT payload with different organization_id values
        jwt_payload = {
            "sub": "user-123",
            "roles": ["user"],
            "organization_id": org_id,
            "type": "access",
            "exp": 9999999999,
        }

        mock_request.headers["Authorization"] = "Bearer test.jwt.token"
        mock_call_next = AsyncMock(return_value=Response())

        with patch("app.middleware.authentication.decode_token", return_value=jwt_payload):
            # Execute
            await middleware.dispatch(mock_request, mock_call_next)

            # Verify organization_id handling
            assert hasattr(mock_request.state, "organization_id")
            assert mock_request.state.organization_id == org_id

    async def test_backward_compatibility_with_existing_code(self, middleware, mock_request, valid_jwt_payload):
        """Test that existing code still works after organization_id addition."""
        # Setup
        mock_request.headers["Authorization"] = "Bearer compat.test.token"
        mock_call_next = AsyncMock(return_value=Response())

        with patch("app.middleware.authentication.decode_token", return_value=valid_jwt_payload):
            # Execute
            await middleware.dispatch(mock_request, mock_call_next)

            # Verify all existing fields still work
            assert mock_request.state.user_id == valid_jwt_payload["sub"]
            assert hasattr(mock_request.state, "token_payload")
            assert hasattr(mock_request.state, "user")

            # Verify new organization_id field
            assert mock_request.state.organization_id == valid_jwt_payload["organization_id"]
