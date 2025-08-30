"""Tests for rate limiting middleware."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response
from starlette.responses import JSONResponse

from app.middleware.rate_limiting import RateLimitingMiddleware


class TestRateLimitingMiddleware:
    """Test rate limiting middleware functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app_mock = AsyncMock()
        self.middleware = RateLimitingMiddleware(self.app_mock, enabled=True)

    @pytest.mark.asyncio
    async def test_middleware_disabled(self):
        """Test middleware when rate limiting is disabled."""
        middleware = RateLimitingMiddleware(self.app_mock, enabled=False)

        request = Mock(spec=Request)
        call_next = AsyncMock(return_value=Response())

        response = await middleware.dispatch(request, call_next)

        # Should call next middleware without rate limiting
        call_next.assert_awaited_once_with(request)
        assert isinstance(response, Response)

    @pytest.mark.asyncio
    async def test_get_endpoint_type_auth_login(self):
        """Test endpoint type detection for auth login."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/auth/login", "POST")
        assert endpoint_type == "auth_login"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_auth_register(self):
        """Test endpoint type detection for auth register."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/auth/register", "POST")
        assert endpoint_type == "auth_register"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_user_create(self):
        """Test endpoint type detection for user creation."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/users/", "POST")
        assert endpoint_type == "user_create"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_user_read(self):
        """Test endpoint type detection for user read."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/users/123", "GET")
        assert endpoint_type == "user_read"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_user_list(self):
        """Test endpoint type detection for user list."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/users/", "GET")
        assert endpoint_type == "user_list"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_health_check(self):
        """Test endpoint type detection for health check."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/health", "GET")
        assert endpoint_type == "health_check"

    @pytest.mark.asyncio
    async def test_get_endpoint_type_unknown_defaults_to_default(self):
        """Test endpoint type detection for unknown endpoints."""
        endpoint_type = self.middleware._get_endpoint_type("/api/v1/unknown", "GET")
        assert endpoint_type == "default"

    @pytest.mark.asyncio
    async def test_parse_rate_limit_count(self):
        """Test rate limit count parsing."""
        assert self.middleware._parse_rate_limit_count("5/minute") == 5
        assert self.middleware._parse_rate_limit_count("10/hour") == 10
        assert self.middleware._parse_rate_limit_count("1/second") == 1

    @pytest.mark.asyncio
    async def test_parse_rate_limit_expire(self):
        """Test rate limit expiration parsing."""
        assert self.middleware._parse_rate_limit_expire("5/second") == 1
        assert self.middleware._parse_rate_limit_expire("5/minute") == 60
        assert self.middleware._parse_rate_limit_expire("5/hour") == 3600
        assert self.middleware._parse_rate_limit_expire("5/unknown") == 60  # default

    @pytest.mark.asyncio
    async def test_middleware_adds_rate_limit_headers(self):
        """Test that middleware adds rate limit headers."""
        request = Mock(spec=Request)
        request.url.path = "/api/v1/auth/login"
        request.method = "POST"

        response_mock = Response()
        call_next = AsyncMock(return_value=response_mock)

        with patch.object(self.middleware, "_check_rate_limit") as mock_check:
            response = await self.middleware.dispatch(request, call_next)

            # Should have rate limit headers
            assert "X-RateLimit-Limit-Type" in response.headers
            assert response.headers["X-RateLimit-Limit-Type"] == "auth_login"
            assert "X-RateLimit-Limit" in response.headers
            assert response.headers["X-RateLimit-Limit"] == "5"

    @pytest.mark.asyncio
    async def test_middleware_handles_exceptions_gracefully(self):
        """Test middleware handles exceptions without breaking request flow."""
        request = Mock(spec=Request)
        request.url.path = "/api/v1/auth/login"
        request.method = "POST"

        response_mock = Response()
        call_next = AsyncMock(return_value=response_mock)

        # Simulate an exception in rate limiting logic
        with patch.object(self.middleware, "_get_endpoint_type", side_effect=Exception("Test error")):
            response = await self.middleware.dispatch(request, call_next)

            # Should still call next middleware despite the exception
            call_next.assert_awaited_once_with(request)
            assert response is response_mock

    @pytest.mark.asyncio
    async def test_endpoint_pattern_matching(self):
        """Test various endpoint pattern matching scenarios."""
        test_cases = [
            ("/api/v1/auth/login", "POST", "auth_login"),
            ("/api/v1/auth/register", "POST", "auth_register"),
            ("/api/v1/auth/refresh", "POST", "auth_refresh"),
            ("/api/v1/users/", "POST", "user_create"),
            ("/api/v1/users/", "GET", "user_list"),
            ("/api/v1/users/123", "GET", "user_read"),
            ("/api/v1/users/123", "PUT", "user_update"),
            ("/api/v1/users/123", "DELETE", "user_delete"),
            ("/api/v1/api-keys/", "POST", "api_key_create"),
            ("/api/v1/api-keys/", "GET", "api_key_list"),
            ("/api/v1/api-keys/123", "DELETE", "api_key_delete"),
            ("/api/v1/health", "GET", "health_check"),
            ("/api/v1/ready", "GET", "readiness"),
            ("/api/v1/admin/something", "GET", "admin_operation"),
            ("/unknown/path", "GET", "default"),
        ]

        for path, method, expected_type in test_cases:
            result = self.middleware._get_endpoint_type(path, method)
            assert result == expected_type, f"Failed for {path} {method}: expected {expected_type}, got {result}"

    @pytest.mark.asyncio
    @patch("app.middleware.rate_limiting.logger")
    async def test_rate_limit_check_logs_debug_info(self, mock_logger):
        """Test that rate limit check logs debug information."""
        request = Mock(spec=Request)
        request.url.path = "/api/v1/auth/login"

        await self.middleware._check_rate_limit(request, "5/minute", "user:123")

        # Should log debug information
        mock_logger.debug.assert_called_once_with(
            "rate_limit_check",
            rate_limit_str="5/minute",
            rate_limit_key="user:123",
            path="/api/v1/auth/login",
        )

    @pytest.mark.asyncio
    async def test_create_rate_limit_response(self):
        """Test creation of rate limit exceeded response."""
        # Create a simple exception to test response creation
        exc = Exception("Rate limit exceeded")
        response = self.middleware._create_rate_limit_response(exc, "auth_login")

        assert isinstance(response, JSONResponse)
        assert response.status_code == 429
        assert "auth_login" in response.body.decode()
        assert "Retry-After" in response.headers
        assert response.headers["Retry-After"] == "60"


@pytest.mark.asyncio
class TestRateLimitingMiddlewareIntegration:
    """Integration tests for rate limiting middleware."""

    @pytest.mark.asyncio
    async def test_middleware_full_flow_without_rate_limiting(self):
        """Test full middleware flow when rate limiting is disabled."""
        app_mock = AsyncMock()
        middleware = RateLimitingMiddleware(app_mock, enabled=False)

        request = Mock(spec=Request)
        request.url.path = "/api/v1/auth/login"
        request.method = "POST"

        expected_response = Response(content="success")
        call_next = AsyncMock(return_value=expected_response)

        response = await middleware.dispatch(request, call_next)

        assert response is expected_response
        call_next.assert_awaited_once_with(request)

    @pytest.mark.asyncio
    async def test_middleware_identifies_all_auth_endpoints(self):
        """Test that middleware correctly identifies all authentication endpoints."""
        app_mock = AsyncMock()
        middleware = RateLimitingMiddleware(app_mock, enabled=True)

        auth_endpoints = [
            ("/api/v1/auth/login", "POST", "auth_login"),
            ("/api/v1/auth/register", "POST", "auth_register"),
            ("/api/v1/auth/refresh", "POST", "auth_refresh"),
            ("/api/v1/auth/logout", "POST", "auth_logout"),
            ("/api/v1/auth/password-reset", "POST", "auth_password_reset"),
        ]

        for path, method, expected_type in auth_endpoints:
            endpoint_type = middleware._get_endpoint_type(path, method)
            assert endpoint_type == expected_type

    @pytest.mark.asyncio
    async def test_middleware_processes_request_with_rate_limiting_enabled(self):
        """Test middleware processes requests when rate limiting is enabled."""
        app_mock = AsyncMock()
        middleware = RateLimitingMiddleware(app_mock, enabled=True)

        request = Mock(spec=Request)
        request.url.path = "/api/v1/auth/login"
        request.method = "POST"

        expected_response = Response(content="success")
        call_next = AsyncMock(return_value=expected_response)

        with patch.object(middleware, "_check_rate_limit") as mock_check:
            response = await middleware.dispatch(request, call_next)

            # Should check rate limiting
            mock_check.assert_awaited_once()

            # Should call next middleware
            call_next.assert_awaited_once_with(request)

            # Should add rate limit headers
            assert "X-RateLimit-Limit-Type" in response.headers
            assert response.headers["X-RateLimit-Limit-Type"] == "auth_login"

    @pytest.mark.asyncio
    async def test_middleware_with_different_rate_limits(self):
        """Test middleware applies different rate limits to different endpoints."""
        from app.core.rate_limiting import get_rate_limit

        app_mock = AsyncMock()
        middleware = RateLimitingMiddleware(app_mock, enabled=True)

        test_cases = [
            ("auth_login", "5/minute"),
            ("auth_register", "3/minute"),
            ("health_check", "120/minute"),
            ("default", "30/minute"),
        ]

        for endpoint_type, expected_limit in test_cases:
            actual_limit = get_rate_limit(endpoint_type)
            assert actual_limit == expected_limit
