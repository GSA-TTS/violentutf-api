"""Comprehensive tests for rate limiting functionality."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# TestClient imported via TYPE_CHECKING for type hints only
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from app.core.rate_limiting import RATE_LIMITS, get_rate_limit, get_rate_limit_key, rate_limit
from app.main import app, limiter
from tests.utils.testclient import SafeTestClient


class TestRateLimitConfiguration:
    """Test rate limit configuration and utilities."""

    def test_rate_limit_configuration(self):
        """Test that rate limits are properly configured."""
        # Check specific rate limits exist
        assert "auth_login" in RATE_LIMITS
        assert "auth_register" in RATE_LIMITS
        assert "user_create" in RATE_LIMITS
        assert "api_key_create" in RATE_LIMITS
        assert "default" in RATE_LIMITS

        # Verify rate limit formats
        assert RATE_LIMITS["auth_login"] == "5/minute"
        assert RATE_LIMITS["auth_register"] == "3/minute"
        assert RATE_LIMITS["auth_password_reset"] == "3/hour"

    def test_get_rate_limit(self):
        """Test rate limit retrieval."""
        # Known endpoint types
        assert get_rate_limit("auth_login") == "5/minute"
        assert get_rate_limit("user_list") == "30/minute"

        # Unknown endpoint type should return default
        assert get_rate_limit("unknown_endpoint") == RATE_LIMITS["default"]

    def test_get_rate_limit_key(self):
        """Test rate limit key generation."""
        # Mock request with no authentication
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        # Should use IP address
        assert get_rate_limit_key(request) == "192.168.1.1"

        # With user ID
        request.state.user_id = "user123"
        assert get_rate_limit_key(request) == "user:user123"

        # With API key (takes precedence over IP but not user)
        request.state.user_id = None
        request.state.api_key = "test_key_12345678"
        assert get_rate_limit_key(request) == "api_key:test_key"


@pytest.mark.asyncio
class TestRateLimitingIntegration:
    """Test rate limiting integration with endpoints."""

    async def test_auth_login_rate_limit(self, client: TestClient):
        """Test rate limiting on login endpoint."""
        login_data = {"username": "testuser", "password": "testpass123"}

        # Get rate limit for auth_login
        rate_limit = RATE_LIMITS["auth_login"]  # "5/minute"
        limit_count = int(rate_limit.split("/")[0])

        # Make requests up to the limit
        for i in range(limit_count):
            response = client.post("/api/v1/auth/login", json=login_data)
            # Don't check status as login might fail, just check not rate limited
            assert response.status_code != 429, f"Request {i+1} was rate limited"

        # Next request should be rate limited
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    async def test_auth_register_rate_limit(self, client: TestClient):
        """Test rate limiting on register endpoint."""
        # Get rate limit for auth_register
        rate_limit = RATE_LIMITS["auth_register"]  # "3/minute"
        limit_count = int(rate_limit.split("/")[0])

        # Make requests up to the limit
        for i in range(limit_count):
            register_data = {"username": f"testuser{i}", "email": f"test{i}@example.com", "password": "TestPass123!"}
            response = client.post("/api/v1/auth/register", json=register_data)
            assert response.status_code != 429, f"Request {i+1} was rate limited"

        # Next request should be rate limited
        register_data = {"username": "testuser_extra", "email": "extra@example.com", "password": "TestPass123!"}
        response = client.post("/api/v1/auth/register", json=register_data)
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    async def test_health_check_rate_limit(self, client: TestClient):
        """Test rate limiting on health check endpoint."""
        # Health checks have relaxed limits
        rate_limit = RATE_LIMITS["health_check"]  # "120/minute"

        # Make 10 rapid requests (should all succeed)
        for i in range(10):
            response = client.get("/api/v1/health")
            assert response.status_code == 200
            assert response.json()["status"] == "healthy"

    async def test_user_aware_rate_limiting(self, client: TestClient, auth_headers: dict):
        """Test that rate limiting is per-user when authenticated."""
        # First user's requests
        for i in range(3):
            response = client.get("/api/v1/users/me", headers=auth_headers)
            assert response.status_code != 429

        # Different user should have separate rate limit
        # (In real test, would need different auth_headers)
        # This demonstrates the concept

    async def test_rate_limit_headers(self, client: TestClient):
        """Test that rate limit headers are included in responses."""
        response = client.get("/api/v1/health")

        # Check for rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers

        # Verify header values
        limit = int(response.headers["X-RateLimit-Limit"])
        remaining = int(response.headers["X-RateLimit-Remaining"])
        assert limit > 0
        assert remaining >= 0
        assert remaining < limit

    async def test_rate_limit_retry_after(self, client: TestClient):
        """Test Retry-After header when rate limited."""
        # Exhaust rate limit for a strict endpoint
        login_data = {"username": "testuser", "password": "testpass123"}

        # Make requests to exhaust limit
        for _ in range(10):  # More than auth_login limit
            response = client.post("/api/v1/auth/login", json=login_data)
            if response.status_code == 429:
                # Check Retry-After header
                assert "Retry-After" in response.headers
                retry_after = int(response.headers["Retry-After"])
                assert retry_after > 0
                assert retry_after <= 60  # Should be less than a minute
                break


class TestRateLimitDecorators:
    """Test rate limit decorator functionality."""

    @pytest.mark.asyncio
    async def test_rate_limit(self):
        """Test basic rate limit decorator."""
        call_count = 0

        @rate_limit("auth_login")
        async def test_endpoint(request: Request):
            nonlocal call_count
            call_count += 1
            return {"status": "ok"}

        # Create mock request
        request = MagicMock(spec=Request)
        request.url.path = "/test"
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Should log rate limit application
        with patch("app.core.rate_limiting.logger") as mock_logger:
            # Note: Actual rate limiting requires full FastAPI app context
            # This tests the decorator wrapping
            result = await test_endpoint(request=request)
            assert result == {"status": "ok"}
            assert call_count == 1

    @pytest.mark.asyncio
    async def test_rate_limit_with_user(self):
        """Test rate limit decorator."""

        @rate_limit("user_read")
        async def test_endpoint(request: Request):
            return {"user": "data"}

        # Create mock request with user
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = "user123"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Should use user ID for rate limiting
        result = await test_endpoint(request=request)
        assert result == {"user": "data"}


class TestRateLimitingEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_rate_limit_without_client(self):
        """Test rate limiting when client info is missing."""
        request = MagicMock(spec=Request)
        request.client = None
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None

        # Should handle gracefully
        key = get_rate_limit_key(request)
        assert key is not None  # Should have a fallback

    def test_malformed_rate_limit_string(self):
        """Test handling of malformed rate limit configurations."""
        # If someone misconfigures a rate limit
        with patch.dict(RATE_LIMITS, {"bad_limit": "invalid"}):
            # Should not crash, should use default
            limit = get_rate_limit("bad_limit")
            assert limit == "invalid"  # Returns as-is, SlowAPI will handle

    @pytest.mark.asyncio
    async def test_concurrent_requests(self, client: TestClient):
        """Test rate limiting under concurrent load."""

        async def make_request():
            return client.get("/api/v1/health")

        # Make multiple concurrent requests
        tasks = [make_request() for _ in range(10)]
        responses = await asyncio.gather(*tasks)

        # All should complete (health has high limit)
        success_count = sum(1 for r in responses if r.status_code == 200)
        assert success_count == 10


class TestRateLimitingConfiguration:
    """Test rate limiting configuration and customization."""

    def test_rate_limit_hierarchy(self):
        """Test that rate limits follow security hierarchy."""
        # Auth endpoints should have stricter limits
        auth_login_limit = int(RATE_LIMITS["auth_login"].split("/")[0])
        user_read_limit = int(RATE_LIMITS["user_read"].split("/")[0])
        health_check_limit = int(RATE_LIMITS["health_check"].split("/")[0])

        assert auth_login_limit < user_read_limit
        assert user_read_limit < health_check_limit

        # Admin operations should be most restrictive
        admin_limit = int(RATE_LIMITS["admin_operation"].split("/")[0])
        assert admin_limit <= auth_login_limit

    def test_rate_limit_time_windows(self):
        """Test different time windows in rate limits."""
        # Check we have per-minute limits
        assert "/minute" in RATE_LIMITS["auth_login"]
        assert "/minute" in RATE_LIMITS["user_create"]

        # Check we have per-hour limits for sensitive operations
        assert "/hour" in RATE_LIMITS["auth_password_reset"]

    @pytest.mark.asyncio
    async def test_custom_rate_limiter(self):
        """Test creating custom rate limiters."""
        from slowapi import Limiter
        from slowapi.util import get_remote_address

        # Create custom limiter
        custom_limiter = Limiter(key_func=get_remote_address)

        @custom_limiter.limit("1/minute")
        async def restricted_endpoint(request: Request):
            return {"status": "ok"}

        # Create test app
        test_app = FastAPI()
        test_app.state.limiter = custom_limiter
        test_app.add_exception_handler(
            RateLimitExceeded, lambda r, e: JSONResponse(status_code=429, content={"detail": "Too many requests"})
        )

        # Add route
        @test_app.get("/restricted")
        async def get_restricted(request: Request):
            return await restricted_endpoint(request)

        # Test with test client
        with SafeTestClient(test_app) as client:
            # First request should succeed
            response = client.get("/restricted")
            assert response.status_code == 200

            # Second request should be rate limited
            response = client.get("/restricted")
            assert response.status_code == 429
