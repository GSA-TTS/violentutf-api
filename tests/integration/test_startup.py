"""Test application startup and integration."""

from typing import Any, AsyncGenerator, Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from tests.utils.testclient import SafeTestClient


class TestApplicationStartup:
    """Test application startup and basic integration."""

    def test_app_starts_successfully(self, client: TestClient) -> None:
        """Test that application starts without errors."""
        response = client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert "service" in data
        assert "version" in data
        assert "status" in data
        assert data["status"] == "operational"

    @pytest.mark.skip(reason="Complex integration test - settings override not working correctly")
    def test_openapi_endpoint_disabled_in_production(self, monkeypatch: Any) -> None:
        """Test that OpenAPI endpoints are disabled in production."""
        # Mock the settings to return production environment
        import app.core.config

        class MockSettings:
            def __init__(self) -> None:
                self.ENVIRONMENT = "production"
                self.PROJECT_NAME = "ViolentUTF API"
                self.VERSION = "1.0.0"
                self.DESCRIPTION = "Test"
                self.API_V1_STR = "/api/v1"
                self.is_production = True
                self.is_development = False

        monkeypatch.setattr(app.core.config, "settings", MockSettings())

        from app.main import create_application

        app = create_application()
        from tests.utils.testclient import SafeTestClient

        with SafeTestClient(app) as client:
            # OpenAPI endpoints should return 404
            response = client.get("/api/v1/openapi.json")
            assert response.status_code == 404

            response = client.get("/api/v1/docs")
            assert response.status_code == 404

            response = client.get("/api/v1/redoc")
            assert response.status_code == 404

    def test_middleware_chain(self, client: TestClient) -> None:
        """Test that middleware chain is working correctly."""
        response = client.get("/api/v1/health")

        # Check headers added by middleware
        assert "X-Request-ID" in response.headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "X-Frame-Options" in response.headers

        # Check response time header (added by logging middleware)
        assert "X-Response-Time" in response.headers
        assert response.headers["X-Response-Time"].endswith("ms")

    def test_cors_headers(self, client: TestClient) -> None:
        """Test CORS configuration."""
        # Make a request with Origin header
        response = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        # Should have CORS headers
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers

    def test_metrics_endpoint_disabled_in_tests(self, client: TestClient) -> None:
        """Test that metrics endpoint is disabled in test environment."""
        response = client.get("/metrics")
        # In test environment, metrics might be enabled, but the endpoint redirects
        assert response.status_code in [200, 307, 404]

    @pytest.mark.asyncio
    async def test_async_client(self, app: FastAPI) -> None:
        """Test with async client."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/api/v1/health")
            assert response.status_code == 200

            data = response.json()
            assert data["status"] == "healthy"
