"""Tests for rate limiting functionality."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, Request
from slowapi.errors import RateLimitExceeded

from app.core.rate_limiting import RATE_LIMITS
from app.core.rate_limiting import RateLimitExceeded as CustomRateLimitExceeded
from app.core.rate_limiting import get_rate_limit, get_rate_limit_key, get_rate_limit_status, ip_rate_limit, rate_limit


class TestRateLimitKey:
    """Test rate limit key generation."""

    def test_get_rate_limit_key_with_organization(self):
        """Test rate limit key uses organization ID when available."""
        request = Mock(spec=Request)
        request.state = Mock()
        request.state.user_id = "user-123"
        request.state.organization_id = "org-456"

        key = get_rate_limit_key(request)
        assert key == "org:org-456"

    def test_get_rate_limit_key_with_user_only(self):
        """Test rate limit key uses user ID when no organization."""
        request = Mock(spec=Request)
        request.state = Mock()
        request.state.user_id = "user-123"
        request.state.organization_id = None

        key = get_rate_limit_key(request)
        assert key == "user:user-123"

    def test_get_rate_limit_key_with_api_key(self):
        """Test rate limit key uses API key when no user context."""
        request = Mock(spec=Request)
        request.state = Mock()
        request.state.user_id = None
        request.state.organization_id = None
        request.state.api_key = "api_key_12345678"

        key = get_rate_limit_key(request)
        assert key == "api_key:api_key_"

    @patch("app.core.rate_limiting.get_remote_address")
    def test_get_rate_limit_key_fallback_to_ip(self, mock_get_remote_address):
        """Test rate limit key falls back to IP address."""
        mock_get_remote_address.return_value = "192.168.1.1"

        request = Mock(spec=Request)
        request.state = Mock()
        request.state.user_id = None
        request.state.organization_id = None
        request.state.api_key = None

        key = get_rate_limit_key(request)
        assert key == "192.168.1.1"
        mock_get_remote_address.assert_called_once_with(request)


class TestRateLimitConfiguration:
    """Test rate limit configuration."""

    def test_get_rate_limit_known_endpoint(self):
        """Test getting rate limit for known endpoint types."""
        assert get_rate_limit("auth_login") == "5/minute"
        assert get_rate_limit("auth_register") == "3/minute"
        assert get_rate_limit("health_check") == "120/minute"

    def test_get_rate_limit_unknown_endpoint(self):
        """Test getting rate limit for unknown endpoint defaults."""
        assert get_rate_limit("unknown_endpoint") == "30/minute"

    def test_rate_limits_configuration(self):
        """Test that all expected rate limits are configured."""
        expected_endpoints = [
            "auth_login",
            "auth_register",
            "auth_refresh",
            "auth_logout",
            "user_create",
            "user_read",
            "user_update",
            "user_delete",
            "api_key_create",
            "api_key_list",
            "api_key_delete",
            "health_check",
            "readiness",
            "default",
        ]

        for endpoint in expected_endpoints:
            assert endpoint in RATE_LIMITS
            assert "/" in RATE_LIMITS[endpoint]  # Format: "X/minute" or "X/hour"


class TestRateLimitDecorator:
    """Test rate limit decorator functionality."""

    @patch("app.core.rate_limiting.settings")
    def test_rate_limit_disabled(self, mock_settings):
        """Test rate limit decorator when rate limiting is disabled."""
        mock_settings.RATE_LIMIT_ENABLED = False

        # Create a mock function
        async def mock_endpoint():
            return "success"

        # Apply rate limit decorator
        decorated = rate_limit("auth_login")(mock_endpoint)

        # Should return the original function unchanged
        assert decorated == mock_endpoint

    @patch("app.core.rate_limiting.settings")
    def test_rate_limit_enabled_no_request_param(self, mock_settings):
        """Test rate limit decorator when rate limiting is enabled but no request parameter."""
        mock_settings.RATE_LIMIT_ENABLED = True

        # Create a mock function without request parameter
        async def mock_endpoint():
            return "success"

        # Apply rate limit decorator
        decorated = rate_limit("auth_login")(mock_endpoint)

        # Should return original function since no request parameter
        assert decorated == mock_endpoint

    @patch("app.core.rate_limiting.settings")
    @patch("app.core.rate_limiting.limiter")
    def test_rate_limit_enabled_with_request_param(self, mock_limiter, mock_settings):
        """Test rate limit decorator when rate limiting is enabled with request parameter."""
        mock_settings.RATE_LIMIT_ENABLED = True

        # Create a mock function with request parameter
        from fastapi import Request

        async def mock_endpoint_with_request(request: Request):
            return "success"

        mock_limited_func = AsyncMock(return_value="success")
        mock_limiter.limit.return_value = lambda func: mock_limited_func

        # Apply rate limit decorator
        decorated = rate_limit("auth_login")(mock_endpoint_with_request)

        # Verify limiter was called with correct rate
        mock_limiter.limit.assert_called_once_with("5/minute")

    @patch("app.core.rate_limiting.settings")
    def test_ip_rate_limit_disabled(self, mock_settings):
        """Test IP rate limit decorator when rate limiting is disabled."""
        mock_settings.RATE_LIMIT_ENABLED = False

        async def mock_endpoint():
            return "success"

        decorated = ip_rate_limit("10/minute")(mock_endpoint)
        assert decorated == mock_endpoint

    @patch("app.core.rate_limiting.settings")
    @patch("app.core.rate_limiting.ip_limiter")
    def test_ip_rate_limit_enabled(self, mock_ip_limiter, mock_settings):
        """Test IP rate limit decorator when rate limiting is enabled."""
        mock_settings.RATE_LIMIT_ENABLED = True

        async def mock_endpoint():
            return "success"

        # Apply IP rate limit decorator
        ip_rate_limit("10/minute")(mock_endpoint)

        # Verify IP limiter was called
        mock_ip_limiter.limit.assert_called_once_with("10/minute")


class TestRateLimitStatus:
    """Test rate limit status functionality."""

    @patch("app.core.rate_limiting.settings")
    def test_get_rate_limit_status_disabled(self, mock_settings):
        """Test rate limit status when rate limiting is disabled."""
        mock_settings.RATE_LIMIT_ENABLED = False

        request = Mock(spec=Request)
        status = get_rate_limit_status(request, "auth_login")

        assert status["enabled"] is False
        assert status["limit"] == "unlimited"
        assert status["remaining"] == "unlimited"
        assert status["reset_time"] is None

    @patch("app.core.rate_limiting.settings")
    @patch("app.core.rate_limiting.get_rate_limit_key")
    def test_get_rate_limit_status_enabled(self, mock_get_key, mock_settings):
        """Test rate limit status when rate limiting is enabled."""
        mock_settings.RATE_LIMIT_ENABLED = True
        mock_get_key.return_value = "user:123"

        request = Mock(spec=Request)
        status = get_rate_limit_status(request, "auth_login")

        assert status["enabled"] is True
        assert status["limit"] == "5/minute"
        assert status["key"] == "user:123"
        assert status["endpoint_type"] == "auth_login"


class TestCustomRateLimitException:
    """Test custom rate limit exception."""

    def test_rate_limit_exceeded_basic(self):
        """Test basic rate limit exceeded exception."""
        exc = CustomRateLimitExceeded()

        assert exc.status_code == 429
        assert exc.detail == "Rate limit exceeded"
        assert exc.headers is None

    def test_rate_limit_exceeded_with_retry_after(self):
        """Test rate limit exceeded exception with retry after."""
        exc = CustomRateLimitExceeded("Custom message", retry_after=60)

        assert exc.status_code == 429
        assert exc.detail == "Custom message"
        assert exc.headers == {"Retry-After": "60"}


class TestRateLimitIntegration:
    """Integration tests for rate limiting components."""

    @pytest.mark.asyncio
    @patch("app.core.rate_limiting.settings")
    @patch("app.core.rate_limiting.limiter")
    async def test_rate_limit_decorator_exception_handling(self, mock_limiter, mock_settings):
        """Test rate limit decorator handles exceptions correctly."""
        mock_settings.RATE_LIMIT_ENABLED = True

        # Create a custom exception for testing
        class TestRateLimitExceeded(Exception):
            pass

        # Create a mock function that raises an exception
        async def mock_endpoint():
            raise TestRateLimitExceeded("Rate limit exceeded")

        mock_limited_func = AsyncMock(side_effect=TestRateLimitExceeded("Rate limit exceeded"))
        mock_limiter.limit.return_value = lambda func: mock_limited_func

        # Apply rate limit decorator
        decorated = rate_limit("auth_login")(mock_endpoint)

        # Should raise the rate limit exception
        with pytest.raises(TestRateLimitExceeded):
            await decorated()

    def test_rate_limit_configuration_completeness(self):
        """Test that rate limit configuration is complete and valid."""
        # Check all rate limits have valid format
        for endpoint_type, rate_str in RATE_LIMITS.items():
            assert isinstance(rate_str, str)
            assert "/" in rate_str

            # Parse rate limit string
            parts = rate_str.split("/")
            assert len(parts) == 2

            # Check numeric part
            count = int(parts[0])
            assert count > 0

            # Check time unit
            time_unit = parts[1]
            assert time_unit in ["minute", "hour", "second"]

    @patch("app.core.rate_limiting.get_remote_address")
    def test_rate_limit_key_without_state(self, mock_get_remote_address):
        """Test rate limit key generation when request has no state."""
        mock_get_remote_address.return_value = "192.168.1.1"

        request = Mock(spec=Request)
        # No state attribute
        delattr(request, "state")

        key = get_rate_limit_key(request)
        assert key == "192.168.1.1"


@pytest.mark.asyncio
class TestRateLimitAsyncBehavior:
    """Test async behavior of rate limiting components."""

    @patch("app.core.rate_limiting.settings")
    async def test_rate_limit_decorator_async_function(self, mock_settings):
        """Test rate limit decorator works with async functions."""
        mock_settings.RATE_LIMIT_ENABLED = False

        @rate_limit("auth_login")
        async def async_endpoint():
            return "async_success"

        result = await async_endpoint()
        assert result == "async_success"

    @patch("app.core.rate_limiting.settings")
    async def test_ip_rate_limit_decorator_async_function(self, mock_settings):
        """Test IP rate limit decorator works with async functions."""
        mock_settings.RATE_LIMIT_ENABLED = False

        @ip_rate_limit("10/minute")
        async def async_endpoint():
            return "async_success"

        result = await async_endpoint()
        assert result == "async_success"
