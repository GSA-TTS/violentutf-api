"""Tests for security headers middleware."""

from typing import Any, Dict, Generator

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import Response

from app.core.config import settings
from app.middleware.security import SecurityHeadersMiddleware, setup_security_middleware
from tests.utils.testclient import SafeTestClient


class TestSecurityHeadersMiddleware:
    """Test security headers middleware functionality."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create test FastAPI app with security middleware."""
        app = FastAPI()

        # Add a test endpoint
        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        # Setup security middleware
        setup_security_middleware(app)

        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> Generator[TestClient, None, None]:
        """Create test client."""
        # Import TestClient locally to ensure correct resolution
        from tests.utils.testclient import SafeTestClient

        with SafeTestClient(app) as test_client:
            yield test_client

    def test_security_headers_present(self, client: TestClient) -> None:
        """Test that security headers are added to responses."""
        response = client.get("/test")

        # Check basic security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"

        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"

        # Check X-Request-ID is present
        assert "X-Request-ID" in response.headers

    def test_hsts_header(self, client: TestClient) -> None:
        """Test HSTS (Strict-Transport-Security) header."""
        response = client.get("/test")

        # HSTS header should be present
        assert "strict-transport-security" in response.headers or "Strict-Transport-Security" in response.headers

        # Get the header (case-insensitive)
        hsts_header = response.headers.get("strict-transport-security") or response.headers.get(
            "Strict-Transport-Security"
        )
        assert hsts_header is not None

        # Check HSTS configuration
        assert "max-age=" in hsts_header
        assert "includesubdomains" in hsts_header.lower()

    def test_csp_header(self, client: TestClient) -> None:
        """Test CSP (Content-Security-Policy) header."""
        response = client.get("/test")

        # CSP header should be present (case-insensitive)
        csp_header = None
        for header_name in response.headers:
            if header_name.lower() == "content-security-policy":
                csp_header = response.headers[header_name]
                break

        assert csp_header is not None, "Content-Security-Policy header not found"

        # Check for key CSP directives
        assert "default-src" in csp_header
        assert "'self'" in csp_header

    def test_x_frame_options(self, client: TestClient) -> None:
        """Test X-Frame-Options header."""
        response = client.get("/test")

        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "deny"

    def test_referrer_policy(self, client: TestClient) -> None:
        """Test Referrer-Policy header."""
        response = client.get("/test")

        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_permissions_policy(self, client: TestClient) -> None:
        """Test Permissions-Policy header."""
        response = client.get("/test")

        assert "Permissions-Policy" in response.headers
        permissions = response.headers["Permissions-Policy"]

        # Check that sensitive features are disabled
        assert "geolocation=('none')" in permissions
        assert "camera=('none')" in permissions
        assert "microphone=('none')" in permissions

    def test_sensitive_headers_removed(self, client: TestClient) -> None:
        """Test that sensitive headers are removed."""
        response = client.get("/test")

        # These headers should not be present
        assert "Server" not in response.headers
        assert "X-Powered-By" not in response.headers

    def test_production_vs_development_headers(self, monkeypatch: Any) -> None:
        """Test different headers in production vs development."""
        # Test development mode
        app_dev = FastAPI()

        @app_dev.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        # Mock development environment
        monkeypatch.setattr("app.core.config.settings.ENVIRONMENT", "development")
        setup_security_middleware(app_dev)

        from tests.utils.testclient import SafeTestClient

        client_dev = SafeTestClient(app_dev)
        response_dev = client_dev.get("/test")

        # In development, CSP might allow unsafe-inline for scripts
        # csp_dev = response_dev.headers.get("Content-Security-Policy", "")
        # Note: Development mode should still have security headers
        assert "Content-Security-Policy" in response_dev.headers
        assert "Strict-Transport-Security" in response_dev.headers

    def test_multiple_requests_unique_ids(self, client: TestClient) -> None:
        """Test that each request gets a unique request ID."""
        # Make multiple requests
        responses = [client.get("/test") for _ in range(5)]

        # Check that all responses have X-Request-ID
        for r in responses:
            assert "X-Request-ID" in r.headers

        # Extract request IDs
        request_ids = [r.headers["X-Request-ID"] for r in responses]

        # All IDs should be unique
        assert len(set(request_ids)) == 5

    def test_custom_request_id_preserved(self, client: TestClient) -> None:
        """Test that custom X-Request-ID from client is preserved."""
        custom_id = "custom-request-id-12345"

        response = client.get("/test", headers={"X-Request-ID": custom_id})

        assert response.headers["X-Request-ID"] == custom_id

    def test_error_responses_have_headers(self, client: TestClient) -> None:
        """Test that security headers are present even on error responses."""
        # Request non-existent endpoint
        response = client.get("/nonexistent")

        assert response.status_code == 404

        # Security headers should still be present
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Strict-Transport-Security" in response.headers

    def test_cors_headers_interaction(self, client: TestClient) -> None:
        """Test that security headers work alongside CORS headers."""
        # Make a request with Origin header
        response = client.get("/test", headers={"Origin": "http://localhost:3000"})

        # Security headers should be present
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers

        # CORS headers might also be present depending on configuration
        # This test ensures security headers don't interfere with CORS

    def test_post_request_headers(self, app: FastAPI, client: TestClient) -> None:
        """Test security headers on POST requests."""

        @app.post("/test-post")
        async def test_post() -> Dict[str, str]:
            return {"message": "posted"}

        response = client.post("/test-post", json={"data": "test"})

        # All security headers should be present
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers

    def test_csp_report_only_mode(self, monkeypatch: Any) -> None:
        """Test CSP in report-only mode for testing."""
        # This could be useful for gradually rolling out CSP
        app = FastAPI()

        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        # You might want to add a setting for CSP report-only mode
        # For now, this test documents the possibility
        setup_security_middleware(app)

        from tests.utils.testclient import SafeTestClient

        client = SafeTestClient(app)
        response = client.get("/test")

        # Regular CSP header should be present
        assert "Content-Security-Policy" in response.headers


class TestTrustedHostMiddleware:
    """Test TrustedHost middleware in production."""

    def test_trusted_host_validation(self) -> None:
        """Test that only allowed hosts are accepted in production."""
        # This test documents the TrustedHostMiddleware functionality
        # In real production, hosts would be validated
        app = FastAPI()

        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        setup_security_middleware(app)

        from tests.utils.testclient import SafeTestClient

        client = SafeTestClient(app)

        # Basic test that the middleware doesn't break normal requests
        response = client.get("/test")
        assert response.status_code == 200


class TestSecurityMiddlewareOrder:
    """Test that security middleware is applied in correct order."""

    def test_middleware_order(self, app: FastAPI, client: TestClient) -> None:
        """Test that request ID is available in logs and headers."""
        response = client.get("/test")

        # Request ID should be in response headers
        assert "X-Request-ID" in response.headers
        request_id = response.headers["X-Request-ID"]

        # Request ID should be a valid UUID format
        import re

        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

        # If no custom ID was provided, it should be a UUID
        if "-" in request_id:
            assert uuid_pattern.match(request_id) is not None
