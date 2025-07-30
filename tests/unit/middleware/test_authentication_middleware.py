"""Comprehensive tests for JWT authentication middleware.

This module provides exhaustive testing for the JWTAuthenticationMiddleware,
addressing the critical security gap identified in test coverage analysis.
Tests follow security-first design principles with comprehensive boundary testing.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, AsyncGenerator, Dict, Generator, Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request

# TestClient is imported from conftest via fixture
from httpx import ASGITransport, AsyncClient
from starlette.responses import Response

from app.core.config import settings
from app.core.security import create_access_token, decode_token
from app.middleware.authentication import (
    EXEMPT_PATHS,
    PROTECTED_METHODS,
    PROTECTED_PATHS,
    JWTAuthenticationMiddleware,
    get_current_token_payload,
    get_current_user_id,
    require_auth,
)

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

from tests.utils.testclient import SafeTestClient


class TestJWTAuthenticationMiddleware:
    """Comprehensive test suite for JWT authentication middleware."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with authentication middleware for testing."""
        app = FastAPI()

        # Add authentication middleware
        app.add_middleware(JWTAuthenticationMiddleware)

        # Test endpoints for different scenarios
        @app.get("/api/v1/health")
        async def health() -> Dict[str, str]:
            return {"status": "ok"}

        @app.get("/api/v1/users")
        async def get_users() -> Dict[str, str]:
            return {"users": "protected"}

        @app.post("/api/v1/users")
        async def create_user() -> Dict[str, str]:
            return {"created": "user"}

        @app.get("/api/v1/public")
        async def public_endpoint() -> Dict[str, str]:
            return {"public": "data"}

        @app.get("/docs")
        async def docs() -> Dict[str, str]:
            return {"docs": "swagger"}

        @app.get("/api/v1/test-state")
        async def test_state(request: Request) -> Dict[str, Any]:
            """Test endpoint to verify state injection."""
            return {
                "user_id": getattr(request.state, "user_id", None),
                "token_payload": getattr(request.state, "token_payload", None),
            }

        return app

    @pytest_asyncio.fixture
    async def async_client(self, app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
        """Create async test client."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    # Test Data Generation Utilities

    def create_test_jwt_token(
        self,
        user_id: str = "test-user-123",
        roles: Optional[list] = None,
        organization_id: Optional[str] = None,
        token_type: str = "access",
        exp_delta: Optional[timedelta] = None,
    ) -> str:
        """Create test JWT token with enhanced claims structure."""
        import jwt

        from app.core.config import settings

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

        # Create JWT directly to allow custom expiration
        encoded_jwt = jwt.encode(
            payload,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )
        return str(encoded_jwt)

    def create_expired_jwt_token(self, user_id: str = "test-user-123") -> str:
        """Create expired JWT token for testing."""
        return self.create_test_jwt_token(user_id=user_id, exp_delta=timedelta(seconds=-1))

    def create_malformed_token(self) -> str:
        """Create malformed JWT token for testing."""
        return "malformed.jwt.token"

    def create_refresh_token(self, user_id: str = "test-user-123") -> str:
        """Create refresh token (wrong type) for testing."""
        return self.create_test_jwt_token(user_id=user_id, token_type="refresh")

    # Path-Based Access Control Tests

    def test_exempt_paths_bypass_authentication(self, client: TestClient) -> None:
        """Test that exempt paths bypass authentication completely."""
        # Test all defined exempt paths
        for exempt_path in EXEMPT_PATHS:
            # Skip paths that might not have endpoints in test app
            if exempt_path in ["/api/v1/health", "/docs"]:
                response = client.get(exempt_path)
                assert response.status_code in [200, 404], f"Exempt path {exempt_path} failed"
                # Should not have authentication headers in response
                assert "WWW-Authenticate" not in response.headers

    def test_exempt_path_prefix_matching(self, client: TestClient) -> None:
        """Test that exempt path prefix matching works correctly."""
        # Create test app with auth endpoint
        app = FastAPI()
        app.add_middleware(JWTAuthenticationMiddleware)

        @app.get("/api/v1/auth/login")
        async def login() -> Dict[str, str]:
            return {"login": "success"}

        @app.get("/api/v1/auth/register")
        async def register() -> Dict[str, str]:
            return {"register": "success"}

        from tests.utils.testclient import SafeTestClient

        with SafeTestClient(app) as client:
            # Both should be exempt (startswith "/api/v1/auth")
            response = client.get("/api/v1/auth/login")
            assert response.status_code == 200

            response = client.get("/api/v1/auth/register")
            assert response.status_code == 200

    def test_protected_paths_require_authentication(self, client: TestClient) -> None:
        """Test that protected paths require authentication."""
        for protected_path in PROTECTED_PATHS:
            if protected_path in ["/api/v1/users"]:  # Test available endpoints
                response = client.get(protected_path)
                assert response.status_code == 401
                assert response.json()["detail"] == "Missing authentication token"
                assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_protected_methods_always_require_auth(self, client: TestClient) -> None:
        """Test that protected HTTP methods always require authentication."""
        for method in PROTECTED_METHODS:
            if method == "POST":
                response = client.post("/api/v1/users")
                assert response.status_code == 401
            elif method == "PUT":
                response = client.put("/api/v1/users/123")
                assert response.status_code == 401
            elif method == "PATCH":
                response = client.patch("/api/v1/users/123")
                assert response.status_code == 401
            elif method == "DELETE":
                response = client.delete("/api/v1/users/123")
                assert response.status_code == 401

    def test_unprotected_paths_allow_anonymous_access(self, client: TestClient) -> None:
        """Test that unprotected paths allow anonymous access."""
        response = client.get("/api/v1/public")
        # Should either work (200) or return 404 if endpoint doesn't exist
        assert response.status_code in [200, 404]
        # Should not return 401
        assert response.status_code != 401

    # JWT Token Processing Tests

    def test_valid_bearer_token_accepted(self, client: TestClient) -> None:
        """Test that valid Bearer tokens are accepted."""
        token = self.create_test_jwt_token()
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users", headers=headers)
        assert response.status_code == 200

    def test_missing_authorization_header_rejected(self, client: TestClient) -> None:
        """Test that missing Authorization header is rejected."""
        response = client.get("/api/v1/users")
        assert response.status_code == 401
        assert response.json()["detail"] == "Missing authentication token"
        assert response.json()["type"] == "authentication_error"
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_malformed_authorization_header_rejected(self, client: TestClient) -> None:
        """Test that malformed Authorization headers are rejected."""
        malformed_headers = [
            {"Authorization": "InvalidScheme token123"},
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "BearerToken123"},  # No space
            {"Authorization": "bearer token123"},  # Wrong case
            {"Authorization": "Token token123"},  # Wrong scheme
            {"Authorization": ""},  # Empty
        ]

        for headers in malformed_headers:
            response = client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401, f"Failed for headers: {headers}"
            assert response.json()["detail"] == "Missing authentication token"

    def test_invalid_jwt_token_rejected(self, client: TestClient) -> None:
        """Test that invalid JWT tokens are rejected."""
        invalid_tokens = [
            "invalid-jwt-token",
            "not.a.jwt",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
        ]

        for token in invalid_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401
            assert response.json()["detail"] == "Invalid authentication token"

    def test_expired_jwt_token_rejected(self, client: TestClient) -> None:
        """Test that expired JWT tokens are rejected."""
        expired_token = self.create_expired_jwt_token()
        headers = {"Authorization": f"Bearer {expired_token}"}

        response = client.get("/api/v1/users", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid authentication token"

    def test_wrong_token_type_rejected(self, client: TestClient) -> None:
        """Test that wrong token type (refresh vs access) is rejected."""
        refresh_token = self.create_refresh_token()
        headers = {"Authorization": f"Bearer {refresh_token}"}

        response = client.get("/api/v1/users", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid token type"

    def test_enhanced_jwt_claims_validation(self, client: TestClient) -> None:
        """Test that enhanced JWT claims structure is properly validated."""
        # Test with all enhanced claims
        token = self.create_test_jwt_token(
            user_id="user-123", roles=["viewer", "tester"], organization_id="org-456", token_type="access"
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200
        data = response.json()

        assert data["user_id"] == "user-123"
        assert data["token_payload"]["sub"] == "user-123"
        assert data["token_payload"]["roles"] == ["viewer", "tester"]
        assert data["token_payload"]["organization_id"] == "org-456"
        assert data["token_payload"]["type"] == "access"

    # State Injection Tests

    def test_user_id_injection_into_request_state(self, client: TestClient) -> None:
        """Test that user ID is properly injected into request state."""
        user_id = "test-user-456"
        token = self.create_test_jwt_token(user_id=user_id)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200
        assert response.json()["user_id"] == user_id

    def test_token_payload_injection_into_request_state(self, client: TestClient) -> None:
        """Test that complete token payload is injected into request state."""
        token = self.create_test_jwt_token(user_id="user-789", roles=["admin"], organization_id="org-123")
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200

        payload = response.json()["token_payload"]
        assert payload["sub"] == "user-789"
        assert payload["roles"] == ["admin"]
        assert payload["organization_id"] == "org-123"
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    async def test_request_state_isolation_between_concurrent_requests(self, async_client: AsyncClient) -> None:
        """Test that request state is properly isolated between concurrent requests."""
        # Create tokens for different users
        token1 = self.create_test_jwt_token(user_id="user-1", roles=["viewer"])
        token2 = self.create_test_jwt_token(user_id="user-2", roles=["admin"])

        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}

        # Make concurrent requests
        responses = await asyncio.gather(
            async_client.get("/api/v1/test-state", headers=headers1),
            async_client.get("/api/v1/test-state", headers=headers2),
            async_client.get("/api/v1/test-state", headers=headers1),
            async_client.get("/api/v1/test-state", headers=headers2),
        )

        # Verify state isolation
        assert responses[0].json()["user_id"] == "user-1"
        assert responses[1].json()["user_id"] == "user-2"
        assert responses[2].json()["user_id"] == "user-1"
        assert responses[3].json()["user_id"] == "user-2"

        # Verify roles are also isolated
        assert responses[0].json()["token_payload"]["roles"] == ["viewer"]
        assert responses[1].json()["token_payload"]["roles"] == ["admin"]

    # Error Response Tests

    def test_standardized_401_response_format(self, client: TestClient) -> None:
        """Test that 401 responses follow standardized format."""
        response = client.get("/api/v1/users")

        assert response.status_code == 401
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["WWW-Authenticate"] == "Bearer"

        data = response.json()
        assert "detail" in data
        assert "type" in data
        assert data["type"] == "authentication_error"

    def test_www_authenticate_header_presence(self, client: TestClient) -> None:
        """Test that WWW-Authenticate header is present in 401 responses."""
        # Test different authentication failure scenarios
        scenarios = [
            (None, "Missing authentication token"),
            ({"Authorization": "Bearer invalid"}, "Invalid authentication token"),
            ({"Authorization": "Invalid scheme"}, "Missing authentication token"),
        ]

        for headers, expected_detail in scenarios:
            response = client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401
            assert response.headers["WWW-Authenticate"] == "Bearer"
            assert response.json()["detail"] == expected_detail

    def test_no_information_disclosure_in_errors(self, client: TestClient) -> None:
        """Test that error responses don't disclose sensitive information."""
        # Test with various invalid tokens
        invalid_scenarios = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.invalid_signature",  # pragma: allowlist secret
            "totally-invalid-token",
            self.create_expired_jwt_token(),
        ]

        for token in invalid_scenarios:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/api/v1/users", headers=headers)

            assert response.status_code == 401
            # Error message should be generic
            assert response.json()["detail"] in ["Invalid authentication token", "Authentication error"]
            # Should not contain token details or stack traces
            response_text = json.dumps(response.json()).lower()
            assert "jwt" not in response_text
            # Allow "token" only in acceptable contexts like "authentication token" or "invalid token type"
            if "token" in response_text:
                assert any(phrase in response_text for phrase in ["authentication token", "invalid token type"])
            assert "traceback" not in response_text

    # Security Boundary Tests

    def test_jwt_decode_error_handling(self, client: TestClient) -> None:
        """Test proper handling of various JWT decode errors."""
        with patch("app.middleware.authentication.decode_token") as mock_decode:
            # Test ValueError handling
            mock_decode.side_effect = ValueError("Invalid token format")
            headers = {"Authorization": "Bearer test-token"}

            response = client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401
            assert response.json()["detail"] == "Invalid authentication token"

    def test_unexpected_exception_handling(self, client: TestClient) -> None:
        """Test handling of unexpected exceptions during authentication."""
        with patch("app.middleware.authentication.decode_token") as mock_decode:
            # Test unexpected exception handling
            mock_decode.side_effect = RuntimeError("Unexpected error")
            headers = {"Authorization": "Bearer test-token"}

            response = client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401
            assert response.json()["detail"] == "Authentication error"

    @pytest.mark.asyncio
    async def test_middleware_integration_with_other_middleware(self, async_client: AsyncClient) -> None:
        """Test that authentication middleware integrates properly with other middleware."""
        # Create app with multiple middleware
        app = FastAPI()

        # Add request tracking middleware
        @app.middleware("http")
        async def track_requests(request: Request, call_next):
            request.state.request_id = str(uuid.uuid4())
            response = await call_next(request)
            response.headers["X-Request-ID"] = request.state.request_id
            return response

        # Add authentication middleware
        app.add_middleware(JWTAuthenticationMiddleware)

        @app.get("/api/v1/users")
        async def get_users(request: Request) -> Dict[str, Any]:
            return {
                "users": "data",
                "request_id": getattr(request.state, "request_id", None),
                "user_id": getattr(request.state, "user_id", None),
            }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = self.create_test_jwt_token()
            headers = {"Authorization": f"Bearer {token}"}

            response = await client.get("/api/v1/users", headers=headers)
            assert response.status_code == 200

            # Both middleware should have worked
            assert "X-Request-ID" in response.headers
            data = response.json()
            assert data["request_id"] is not None
            assert data["user_id"] is not None

    # Performance and Edge Case Tests

    def test_large_jwt_token_handling(self, client: TestClient) -> None:
        """Test handling of JWT tokens with large payloads."""
        # Create token with large roles array
        large_roles = [f"role_{i}" for i in range(100)]
        token = self.create_test_jwt_token(roles=large_roles)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200
        assert len(response.json()["token_payload"]["roles"]) == 100

    def test_unicode_and_special_characters_in_tokens(self, client: TestClient) -> None:
        """Test handling of tokens with unicode and special characters."""
        token = self.create_test_jwt_token(user_id="user-测试-123", organization_id="org-тест-456")
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user-测试-123"
        assert data["token_payload"]["organization_id"] == "org-тест-456"

    def test_path_matching_edge_cases(self, client: TestClient) -> None:
        """Test edge cases in path matching logic."""
        # Create app with specific endpoints
        app = FastAPI()
        app.add_middleware(JWTAuthenticationMiddleware)

        @app.get("/api/v1/auth-similar")  # Similar to exempt path but not exact
        async def auth_similar() -> Dict[str, str]:
            return {"data": "protected"}

        @app.get("/api/v1/users-public")  # Similar to protected path
        async def users_public() -> Dict[str, str]:
            return {"data": "protected"}

        from tests.utils.testclient import SafeTestClient

        with SafeTestClient(app) as client:
            # Should require authentication (not exactly matching exempt/protected paths)
            response = client.get("/api/v1/auth-similar")
            assert response.status_code == 401

            response = client.get("/api/v1/users-public")
            assert response.status_code == 401


class TestUtilityFunctions:
    """Test utility functions for authentication middleware."""

    def test_get_current_user_id_with_authenticated_request(self) -> None:
        """Test getting user ID from authenticated request."""
        request = Mock()
        request.state.user_id = "test-user-123"

        user_id = get_current_user_id(request)
        assert user_id == "test-user-123"

    def test_get_current_user_id_with_unauthenticated_request(self) -> None:
        """Test getting user ID from unauthenticated request."""
        request = Mock()
        # Configure mock state to not have user_id attribute
        del request.state.user_id

        user_id = get_current_user_id(request)
        assert user_id is None

    def test_get_current_token_payload_with_authenticated_request(self) -> None:
        """Test getting token payload from authenticated request."""
        request = Mock()
        payload = {"sub": "user-123", "roles": ["admin"]}
        request.state.token_payload = payload

        token_payload = get_current_token_payload(request)
        assert token_payload == payload

    def test_get_current_token_payload_with_unauthenticated_request(self) -> None:
        """Test getting token payload from unauthenticated request."""
        request = Mock()
        # Configure mock state to not have token_payload attribute
        del request.state.token_payload

        token_payload = get_current_token_payload(request)
        assert token_payload is None

    def test_require_auth_decorator(self) -> None:
        """Test require_auth decorator functionality."""

        @require_auth
        def protected_function():
            return "protected"

        # Check that decorator adds the required attribute
        assert hasattr(protected_function, "_requires_auth")
        assert protected_function._requires_auth is True


class TestMiddlewareConfiguration:
    """Test middleware configuration and constants."""

    def test_protected_paths_configuration(self) -> None:
        """Test that protected paths are properly configured."""
        expected_paths = [
            "/api/v1/users",
            "/api/v1/api-keys",
            "/api/v1/sessions",
            "/api/v1/audit-logs",
            "/api/v1/llm-configs",
            "/api/v1/prompt-injections",
            "/api/v1/jailbreaks",
            "/api/v1/test-state",  # Test endpoint for middleware testing
        ]

        assert PROTECTED_PATHS == expected_paths

    def test_exempt_paths_configuration(self) -> None:
        """Test that exempt paths are properly configured."""
        expected_paths = [
            "/",  # Root endpoint
            "/api/v1/auth",
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/live",
            "/api/v1/public",  # Test path for middleware testing
            "/docs",
            "/redoc",
            "/openapi.json",
            "/metrics",
        ]

        assert EXEMPT_PATHS == expected_paths

    def test_protected_methods_configuration(self) -> None:
        """Test that protected methods are properly configured."""
        expected_methods = {"POST", "PUT", "PATCH", "DELETE"}
        assert PROTECTED_METHODS == expected_methods

    def test_middleware_initialization(self) -> None:
        """Test middleware initialization."""
        app = Mock()
        middleware = JWTAuthenticationMiddleware(app)
        assert middleware.app == app


class TestSecurityLogging:
    """Test security event logging in authentication middleware."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app with authentication middleware for testing."""
        app = FastAPI()

        # Add authentication middleware
        app.add_middleware(JWTAuthenticationMiddleware)

        # Test endpoints
        @app.get("/api/v1/users")
        async def get_users() -> Dict[str, str]:
            return {"users": "protected"}

        @app.get("/api/v1/test-state")
        async def test_state(request: Request) -> Dict[str, Any]:
            """Test endpoint to verify state injection."""
            return {
                "user_id": getattr(request.state, "user_id", None),
                "token_payload": getattr(request.state, "token_payload", None),
            }

        return app

    @patch("app.middleware.authentication.logger")
    def test_missing_token_logged(self, mock_logger, client: TestClient) -> None:
        """Test that missing authentication tokens are logged."""
        response = client.get("/api/v1/users")
        assert response.status_code == 401

        mock_logger.warning.assert_called_with("missing_auth_token", method="GET", path="/api/v1/users")

    @patch("app.middleware.authentication.logger")
    def test_invalid_token_type_logged(self, mock_logger, client: TestClient) -> None:
        """Test that invalid token types are logged."""
        refresh_token = self.create_test_jwt_token(token_type="refresh")
        headers = {"Authorization": f"Bearer {refresh_token}"}

        response = client.get("/api/v1/users", headers=headers)
        assert response.status_code == 401

        mock_logger.warning.assert_called_with("invalid_token_type", token_type="refresh", expected="access")

    @patch("app.middleware.authentication.logger")
    def test_successful_authentication_logged(self, mock_logger, client: TestClient) -> None:
        """Test that successful authentications are logged."""
        token = self.create_test_jwt_token(user_id="test-user-789")
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/test-state", headers=headers)
        assert response.status_code == 200

        mock_logger.debug.assert_called_with("auth_success", user_id="test-user-789", path="/api/v1/test-state")

    def create_test_jwt_token(self, user_id: str = "test-user-123", token_type: str = "access") -> str:
        """Helper method for creating test JWT tokens."""
        import jwt

        from app.core.config import settings

        payload = {
            "sub": user_id,
            "roles": ["viewer"],
            "organization_id": None,
            "type": token_type,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

        # Create JWT directly to allow custom token types
        encoded_jwt = jwt.encode(
            payload,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )
        return str(encoded_jwt)
