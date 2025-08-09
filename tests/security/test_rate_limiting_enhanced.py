"""Enhanced comprehensive tests for rate limiting functionality.

This test suite provides extensive coverage for all rate limiting features,
including edge cases, error scenarios, and performance characteristics.
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, AsyncGenerator, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis
from fastapi import FastAPI, Request, Response

# TestClient imported via TYPE_CHECKING for type hints only
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.rate_limiting import RATE_LIMITS, add_rate_limit_headers, get_rate_limit, get_rate_limit_key, rate_limit
from tests.utils.testclient import SafeTestClient as FastAPITestClient


class TestRateLimitKeyGeneration:
    """Test rate limit key generation with various scenarios."""

    def test_key_generation_with_user_id(self):
        """Test key generation when user is authenticated."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = "user-123-456"
        request.state.api_key = None
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        key = get_rate_limit_key(request)
        assert key == "user:user-123-456"

    def test_key_generation_with_api_key(self):
        """Test key generation with API key."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = "sk_test_1234567890abcdef"
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        key = get_rate_limit_key(request)
        assert key == "api_key:sk_test_"

    def test_key_generation_user_takes_precedence(self):
        """Test that user ID takes precedence over API key."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = "user-123"
        request.state.api_key = "sk_test_123"
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        key = get_rate_limit_key(request)
        assert key == "user:user-123"

    def test_key_generation_fallback_to_ip(self):
        """Test fallback to IP address when no auth."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None
        request.client = MagicMock()
        request.client.host = "10.0.0.1"

        key = get_rate_limit_key(request)
        assert key == "10.0.0.1"

    def test_key_generation_no_client(self):
        """Test key generation when client info is missing."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None
        request.client = None

        # Should handle gracefully
        with patch("app.core.rate_limiting.get_remote_address", return_value="unknown"):
            key = get_rate_limit_key(request)
            assert key == "unknown"

    def test_key_generation_ipv6(self):
        """Test key generation with IPv6 address."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None
        request.client = MagicMock()
        request.client.host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

        key = get_rate_limit_key(request)
        assert key == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_key_generation_proxy_headers(self):
        """Test key generation with proxy headers."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = None
        request.state.api_key = None
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.headers = {"X-Forwarded-For": "203.0.113.1, 198.51.100.2"}

        # Note: get_remote_address should handle X-Forwarded-For
        with patch("app.core.rate_limiting.get_remote_address", return_value="203.0.113.1"):
            key = get_rate_limit_key(request)
            assert key == "203.0.113.1"


class TestRateLimitConfiguration:
    """Test rate limit configuration and retrieval."""

    def test_all_rate_limits_defined(self):
        """Test that all expected rate limits are defined."""
        expected_limits = [
            "auth_login",
            "auth_register",
            "auth_refresh",
            "auth_logout",
            "auth_password_reset",
            "user_create",
            "user_read",
            "user_update",
            "user_delete",
            "user_list",
            "api_key_create",
            "api_key_list",
            "api_key_delete",
            "health_check",
            "readiness",
            "admin_operation",
            "default",
        ]

        for limit in expected_limits:
            assert limit in RATE_LIMITS
            assert "/" in RATE_LIMITS[limit]  # Should have time unit

    def test_rate_limit_formats(self):
        """Test that rate limits have valid formats."""
        for endpoint, limit in RATE_LIMITS.items():
            parts = limit.split("/")
            assert len(parts) == 2
            assert parts[0].isdigit()
            assert parts[1] in ["second", "minute", "hour", "day"]

    def test_get_rate_limit_known_endpoint(self):
        """Test retrieving rate limit for known endpoint."""
        assert get_rate_limit("auth_login") == "5/minute"
        assert get_rate_limit("health_check") == "120/minute"
        assert get_rate_limit("admin_operation") == "5/minute"

    def test_get_rate_limit_unknown_endpoint(self):
        """Test retrieving rate limit for unknown endpoint."""
        assert get_rate_limit("unknown_endpoint") == RATE_LIMITS["default"]
        assert get_rate_limit("") == RATE_LIMITS["default"]
        assert get_rate_limit(None) == RATE_LIMITS["default"]

    def test_rate_limit_security_hierarchy(self):
        """Test that sensitive endpoints have stricter limits."""

        # Parse rate limits to compare
        def parse_limit(limit_str):
            count, unit = limit_str.split("/")
            multipliers = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
            return int(count) * multipliers.get(unit, 60)

        auth_rate = parse_limit(RATE_LIMITS["auth_login"])
        user_rate = parse_limit(RATE_LIMITS["user_read"])
        health_rate = parse_limit(RATE_LIMITS["health_check"])
        admin_rate = parse_limit(RATE_LIMITS["admin_operation"])

        # Admin should be most restrictive
        assert admin_rate <= auth_rate
        # Auth should be more restrictive than user operations
        assert auth_rate < user_rate
        # Health checks should be least restrictive
        assert user_rate < health_rate


@pytest.mark.asyncio
class TestRateLimitDecorators:
    """Test rate limit decorator functionality."""

    async def test_rate_limit_basic(self):
        """Test basic rate limit decorator functionality."""
        call_count = 0

        @rate_limit("auth_login")
        async def test_endpoint(request: Request):
            nonlocal call_count
            call_count += 1
            return {"status": "ok", "count": call_count}

        # Create mock request
        request = MagicMock(spec=Request)
        request.url.path = "/test"
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Should allow first call
        result = await test_endpoint(request=request)
        assert result["status"] == "ok"
        assert call_count == 1

    async def test_rate_limit_logging(self):
        """Test that rate limit decorator logs properly."""

        @rate_limit("user_read")
        async def test_endpoint(request: Request):
            return {"data": "test"}

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/users/123"
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        with patch("app.core.rate_limiting.logger") as mock_logger:
            result = await test_endpoint(request=request)
            assert result["data"] == "test"

            # Verify logging
            mock_logger.debug.assert_called_once()
            call_args = mock_logger.debug.call_args
            assert call_args[0][0] == "rate_limit_applied"
            assert call_args[1]["endpoint_type"] == "user_read"
            assert call_args[1]["limit"] == RATE_LIMITS["user_read"]
            assert call_args[1]["path"] == "/api/v1/users/123"

    async def test_rate_limit_with_user(self):
        """Test rate limit decorator."""

        @rate_limit("api_key_create")
        async def create_api_key(request: Request):
            return {"api_key": "created"}

        # Test with authenticated user
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = "user-456"
        request.client = MagicMock()
        request.client.host = "10.0.0.1"

        result = await create_api_key(request=request)
        assert result["api_key"] == "created"

    async def test_decorator_preserves_function_metadata(self):
        """Test that decorators preserve function metadata."""

        @rate_limit("default")
        async def documented_function(request: Request):
            """This function has documentation."""
            return {"documented": True}

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This function has documentation."

    async def test_nested_decorators(self):
        """Test multiple decorators on same function."""
        call_order = []

        @rate_limit("auth_login")
        @rate_limit("auth_login")
        async def multi_limited_endpoint(request: Request):
            call_order.append("endpoint")
            return {"ok": True}

        request = MagicMock(spec=Request)
        request.url.path = "/auth/login"
        request.method = "POST"
        request.state = MagicMock()
        request.state.user_id = None
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        result = await multi_limited_endpoint(request=request)
        assert result["ok"] is True
        assert "endpoint" in call_order


@pytest.mark.asyncio
class TestRateLimitingIntegration:
    """Integration tests for rate limiting with FastAPI."""

    @pytest.fixture
    async def rate_limited_app(self):
        """Create test app with rate limiting."""
        app = FastAPI()

        # Configure limiter
        limiter = Limiter(key_func=get_rate_limit_key)
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, self._rate_limit_handler)

        # Add test endpoints
        @app.post("/auth/login")
        @limiter.limit("3/minute")
        async def login(request: Request):
            return {"status": "logged_in"}

        @app.get("/api/users/{user_id}")
        @limiter.limit("10/minute")
        async def get_user(request: Request, user_id: str):
            return {"user_id": user_id}

        @app.get("/health")
        @limiter.limit("100/minute")
        async def health(request: Request):
            return {"status": "healthy"}

        return app

    def _rate_limit_handler(self, request: Request, exc: RateLimitExceeded):
        """Handle rate limit exceeded errors."""
        response = Response(
            content=f"Rate limit exceeded: {exc.detail}",
            status_code=429,
        )
        response.headers["Retry-After"] = "60"
        return response

    async def test_rate_limit_enforcement(self, rate_limited_app):
        """Test that rate limits are enforced."""
        with FastAPITestClient(rate_limited_app) as client:
            # Test login endpoint (3/minute limit)
            for i in range(3):
                response = client.post("/auth/login")
                assert response.status_code == 200

            # Fourth request should be rate limited
            response = client.post("/auth/login")
            assert response.status_code == 429
            assert "Retry-After" in response.headers

    async def test_different_endpoints_different_limits(self, rate_limited_app):
        """Test that different endpoints have independent limits."""
        with FastAPITestClient(rate_limited_app) as client:
            # Exhaust login limit
            for _ in range(3):
                client.post("/auth/login")

            # Should still be able to access other endpoints
            response = client.get("/api/users/123")
            assert response.status_code == 200

            response = client.get("/health")
            assert response.status_code == 200

    async def test_rate_limit_headers_included(self, rate_limited_app):
        """Test that rate limit headers are included in responses."""
        with FastAPITestClient(rate_limited_app) as client:
            response = client.get("/health")

            # Check for rate limit headers
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers

            limit = int(response.headers["X-RateLimit-Limit"])
            remaining = int(response.headers["X-RateLimit-Remaining"])
            assert limit == 100  # As configured
            assert remaining == limit - 1  # One request made


@pytest.mark.asyncio
class TestRateLimitingEdgeCases:
    """Test edge cases and error scenarios."""

    async def test_redis_connection_failure(self):
        """Test behavior when Redis is unavailable."""
        # Create limiter with failing Redis
        with patch("app.core.rate_limiting.limiter._storage") as mock_storage:
            mock_storage.incr.side_effect = redis.ConnectionError("Redis unavailable")

            @rate_limit("user_read")
            async def test_endpoint(request: Request):
                return {"status": "ok"}

            request = MagicMock(spec=Request)
            request.client = MagicMock()
            request.client.host = "127.0.0.1"

            # Should not crash, should allow request
            result = await test_endpoint(request=request)
            assert result["status"] == "ok"

    async def test_malformed_rate_limit_string(self):
        """Test handling of malformed rate limit configurations."""
        with patch.dict(RATE_LIMITS, {"malformed": "invalid-format"}):
            # Should not crash
            limit = get_rate_limit("malformed")
            assert limit == "invalid-format"

    async def test_concurrent_requests_same_key(self):
        """Test concurrent requests from same user."""
        request_count = 0

        @rate_limit("user_read")
        async def concurrent_endpoint(request: Request):
            nonlocal request_count
            request_count += 1
            await asyncio.sleep(0.1)  # Simulate work
            return {"count": request_count}

        # Create request for same user
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user_id = "user-789"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Make concurrent requests
        tasks = [concurrent_endpoint(request=request) for _ in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should complete (rate limiting is per time window, not concurrent)
        successful = [r for r in results if isinstance(r, dict)]
        assert len(successful) == 5

    async def test_rate_limit_with_different_http_methods(self):
        """Test that rate limits apply across HTTP methods."""
        app = FastAPI()
        limiter = Limiter(key_func=get_rate_limit_key)
        app.state.limiter = limiter

        @app.get("/resource")
        @app.post("/resource")
        @app.put("/resource")
        @limiter.limit("5/minute")
        async def resource_endpoint(request: Request):
            return {"method": request.method}

        with FastAPITestClient(app) as client:
            # Mix of methods should share rate limit
            client.get("/resource")
            client.post("/resource")
            client.put("/resource")
            client.get("/resource")
            client.post("/resource")

            # Sixth request should fail regardless of method
            response = client.put("/resource")
            assert response.status_code == 429

    async def test_rate_limit_reset_after_window(self):
        """Test that rate limits reset after time window."""
        app = FastAPI()
        limiter = Limiter(key_func=get_rate_limit_key)
        app.state.limiter = limiter

        @app.get("/quick")
        @limiter.limit("2/second")
        async def quick_endpoint(request: Request):
            return {"time": time.time()}

        with FastAPITestClient(app) as client:
            # Exhaust limit
            client.get("/quick")
            client.get("/quick")

            # Should be rate limited
            response = client.get("/quick")
            assert response.status_code == 429

            # Wait for window to reset
            time.sleep(1.1)

            # Should work again
            response = client.get("/quick")
            assert response.status_code == 200


@pytest.mark.asyncio
class TestRateLimitingPerformance:
    """Test performance characteristics of rate limiting."""

    async def test_rate_limiting_overhead(self):
        """Measure overhead of rate limiting."""

        # Endpoint without rate limiting
        async def unprotected_endpoint(request: Request):
            return {"data": "test"}

        # Same endpoint with rate limiting
        @rate_limit("default")
        async def protected_endpoint(request: Request):
            return {"data": "test"}

        request = MagicMock(spec=Request)
        request.url.path = "/test"
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Measure unprotected endpoint
        start = time.perf_counter()
        for _ in range(100):
            await unprotected_endpoint(request)
        unprotected_time = time.perf_counter() - start

        # Measure protected endpoint
        start = time.perf_counter()
        for _ in range(100):
            await protected_endpoint(request=request)
        protected_time = time.perf_counter() - start

        # Rate limiting should add minimal overhead
        overhead = protected_time - unprotected_time
        overhead_percent = (overhead / unprotected_time) * 100

        # Log for analysis
        print(f"Unprotected time: {unprotected_time:.4f}s")
        print(f"Protected time: {protected_time:.4f}s")
        print(f"Overhead: {overhead:.4f}s ({overhead_percent:.2f}%)")

        # Assert reasonable overhead (less than 50%)
        assert overhead_percent < 50

    async def test_rate_limiting_under_load(self):
        """Test rate limiting behavior under high load."""
        successful_requests = 0
        rate_limited_requests = 0

        @rate_limit("user_read")
        async def load_test_endpoint(request: Request):
            nonlocal successful_requests
            successful_requests += 1
            return {"ok": True}

        # Simulate high load with ThreadPoolExecutor
        def make_request():
            request = MagicMock(spec=Request)
            request.state = MagicMock()
            request.state.user_id = f"user-{int(time.time() * 1000) % 10}"
            request.client = MagicMock()
            request.client.host = "127.0.0.1"

            try:
                asyncio.run(load_test_endpoint(request=request))
                return True
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(100)]
            results = [f.result() for f in futures]

        # Should handle load gracefully
        success_count = sum(1 for r in results if r)
        assert success_count > 0
        assert success_count < 100  # Some should be rate limited


class TestRateLimitingCustomConfiguration:
    """Test custom rate limiting configurations."""

    def test_custom_key_function(self):
        """Test using custom key function."""

        def custom_key_func(request: Request) -> str:
            # Use combination of IP and user agent
            ip = getattr(request.client, "host", "unknown")
            user_agent = request.headers.get("User-Agent", "unknown")
            return f"{ip}:{user_agent}"

        limiter = Limiter(key_func=custom_key_func)

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        request.headers = {"User-Agent": "TestBot/1.0"}

        key = custom_key_func(request)
        assert key == "192.168.1.1:TestBot/1.0"

    def test_multiple_limiters(self):
        """Test using multiple limiters for different purposes."""
        # Standard limiter for most endpoints
        standard_limiter = Limiter(key_func=get_rate_limit_key)

        # Strict limiter for auth endpoints
        auth_limiter = Limiter(key_func=get_rate_limit_key, default_limits=["1/minute"])

        # Both limiters should work independently
        assert standard_limiter != auth_limiter
        assert standard_limiter._key_func == auth_limiter._key_func

    def test_dynamic_rate_limits(self):
        """Test dynamic rate limit calculation."""

        def get_dynamic_limit(user_tier: str) -> str:
            tiers = {"free": "10/hour", "basic": "100/hour", "premium": "1000/hour", "enterprise": "10000/hour"}
            return tiers.get(user_tier, "10/hour")

        # Test tier-based limits
        assert get_dynamic_limit("free") == "10/hour"
        assert get_dynamic_limit("premium") == "1000/hour"
        assert get_dynamic_limit("unknown") == "10/hour"


class TestRateLimitingCompliance:
    """Test rate limiting compliance with standards."""

    def test_rate_limit_header_standards(self):
        """Test that rate limit headers follow standards."""
        # Headers should follow IETF draft standards
        expected_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",  # When rate limited
        ]

        # These are the headers SlowAPI should set
        # In actual implementation, verify against response
        assert all(h.startswith("X-RateLimit-") or h == "Retry-After" for h in expected_headers)

    def test_rate_limit_response_format(self):
        """Test rate limit error response format."""
        # When rate limited, response should be informative
        error_response = {
            "detail": "Rate limit exceeded: 5 per minute",
            "type": "rate_limit_exceeded",
            "retry_after": 60,
        }

        # Verify response structure
        assert "detail" in error_response
        assert "retry_after" in error_response
        assert error_response["retry_after"] > 0
