"""Test middleware components."""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from tests.utils.testclient import SafeTestClient


@pytest.fixture
def test_app() -> FastAPI:
    """Create a test FastAPI app with middleware."""
    app = FastAPI()

    # Add middleware
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    return app


class TestSecurityHeadersMiddleware:
    """Test security headers middleware."""

    def test_security_headers_added(self, test_app: FastAPI) -> None:
        """Test that security headers are added to responses."""
        client = TestClient(test_app)
        response = client.get("/test")

        assert response.status_code == 200

        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"

        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"

        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "deny"

        # Check that sensitive headers are removed
        assert "Server" not in response.headers
        assert "X-Powered-By" not in response.headers

    def test_request_id_header(self, test_app: FastAPI) -> None:
        """Test that X-Request-ID is added."""
        client = TestClient(test_app)
        response = client.get("/test")

        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0


class TestRequestIDMiddleware:
    """Test request ID tracking middleware."""

    def test_request_id_generated(self, test_app: FastAPI) -> None:
        """Test that request ID is generated when not provided."""
        client = TestClient(test_app)
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers

        # Should be a valid UUID
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) == 36  # UUID v4 format
        assert request_id.count("-") == 4

    def test_request_id_preserved(self, test_app: FastAPI) -> None:
        """Test that provided request ID is preserved."""
        client = TestClient(test_app)
        custom_id = "custom-request-id-123"

        response = client.get("/test", headers={"X-Request-ID": custom_id})

        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id

    def test_different_requests_different_ids(self, test_app: FastAPI) -> None:
        """Test that different requests get different IDs."""
        client = TestClient(test_app)

        response1 = client.get("/test")
        response2 = client.get("/test")

        id1 = response1.headers["X-Request-ID"]
        id2 = response2.headers["X-Request-ID"]

        assert id1 != id2
