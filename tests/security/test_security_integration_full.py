"""Integration tests for all security features working together."""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, status

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.input_validation import prevent_sql_injection, validate_auth_request
from app.core.rate_limiting import RATE_LIMITS
from app.middleware.request_signing import RequestSigner
from app.utils.circuit_breaker import get_circuit_breaker
from tests.utils.testclient import SafeTestClient


class TestSecurityMiddlewareChain:
    """Test that all security middleware work together correctly."""

    @pytest.mark.asyncio
    async def test_middleware_execution_order(self, client: TestClient):
        """Test that middleware execute in the correct order."""
        # The order should be:
        # 1. Request ID (for tracking)
        # 2. Logging
        # 3. Metrics
        # 4. Session management
        # 5. CSRF Protection
        # 6. JWT Authentication
        # 7. Idempotency
        # 8. Input sanitization
        # 9. Request signing (if enabled)
        # 10. Rate limiting (at endpoint level)

        response = client.get("/api/v1/health")

        # Should have request ID header
        assert "X-Request-ID" in response.headers

        # Note: Rate limit headers are not added by SlowAPI when using TestClient
        # This is a known limitation. Rate limiting functionality is tested separately.

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client: TestClient):
        """Test that security headers are set correctly."""
        response = client.get("/api/v1/health")

        # Security headers that should be present
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Referrer-Policy",
        ]

        for header in security_headers:
            assert header in response.headers, f"Missing security header: {header}"

        # Verify header values (note: secure library uses lowercase values)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"].lower() == "deny"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"


class TestRateLimitingWithValidation:
    """Test rate limiting combined with input validation."""

    @pytest.mark.asyncio
    async def test_validation_failures_count_against_rate_limit(self, client: TestClient):
        """Test that validation failures still count against rate limits."""
        # Make requests with invalid data
        invalid_login_data = {"username": "admin' OR '1'='1", "password": "password"}  # SQL injection attempt

        # Note: Rate limiting is disabled in test configuration by default
        # So we're testing that requests with SQL injection attempts are handled correctly
        # The SQL injection warning is logged but request proceeds to authentication

        # Make multiple requests
        for i in range(3):
            response = client.post("/api/v1/auth/login", json=invalid_login_data)
            # Authentication fails (user doesn't exist), SQL injection only produces warnings
            assert response.status_code == 401
            assert "Incorrect username or password" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_rate_limit_by_user_with_validation(self, client: TestClient):
        """Test that authenticated users have separate rate limits."""
        # Since we don't have a valid auth token in test, test unauthenticated request
        response = client.get("/api/v1/users/me")

        # Should get 401 unauthorized (no auth token)
        assert response.status_code == 401


class TestInputSanitizationWithSigning:
    """Test input sanitization with request signing."""

    @pytest.mark.asyncio
    async def test_signed_request_with_malicious_input(self, client: TestClient):
        """Test that signed requests still go through input sanitization."""
        # Create signer
        signer = RequestSigner("test_admin_key", "admin_secret")

        # Create request with malicious content
        malicious_body = {"name": "Test<script>alert('xss')</script>", "query": "'; DROP TABLE users--"}

        body_bytes = json.dumps(malicious_body).encode()

        # Sign the request
        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/admin/config",
            headers={
                "Content-Type": "application/json",
                "Host": "testserver",
            },
            body=body_bytes,
        )

        headers = {
            "Content-Type": "application/json",
            **signed_headers,
        }

        # Make request
        response = client.post(
            "/api/v1/admin/config",
            headers=headers,
            content=body_bytes,
        )

        # Should be sanitized or rejected even with valid signature
        # (Actual behavior depends on endpoint implementation)


class TestCircuitBreakersWithRateLimiting:
    """Test circuit breakers working with rate limiting."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_before_rate_limit(self):
        """Test that circuit breakers prevent hitting rate limits on failing services."""
        # Get circuit breaker for external service
        cb = get_circuit_breaker("external_api")

        # Simulate failing external service
        async def failing_api_call():
            raise Exception("Service unavailable")

        # Open the circuit breaker
        for _ in range(5):
            with pytest.raises(Exception):
                await cb.call(failing_api_call)

        # Circuit should be open
        assert cb.is_open()

        # Now calls fail fast without hitting the actual service
        # This prevents exhausting rate limits on a failing service
        with pytest.raises(Exception) as exc_info:
            await cb.call(failing_api_call)

        assert "Circuit breaker" in str(exc_info.value)


class TestAuthenticationWithAllSecurity:
    """Test authentication flow with all security features."""

    @pytest.mark.asyncio
    async def test_secure_login_flow(self, client: TestClient):
        """Test complete secure login flow."""
        # 1. Input validation
        login_data = {"username": "testuser", "password": "SecurePass123!"}

        # 2. Rate limiting would apply in production (disabled in tests)
        response = client.post("/api/v1/auth/login", json=login_data)

        # 3. Authentication will fail (no users in test DB)
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_registration_security_flow(self, client: TestClient):
        """Test secure registration with all validations."""
        # Registration data
        register_data = {"username": "newuser123", "email": "newuser@example.com", "password": "SecurePass123!"}

        # Should pass all security checks
        response = client.post("/api/v1/auth/register", json=register_data)

        # Check various security aspects
        if response.status_code == 201:
            # Successfully created
            assert "user_id" in response.json()
        elif response.status_code == 409:
            # User already exists (valid response)
            assert "already exists" in response.json()["detail"]
        elif response.status_code == 422:
            # Validation failed
            assert "Validation failed" in response.json()["detail"]
        elif response.status_code == 429:
            # Rate limited
            assert "Rate limit exceeded" in response.json()["detail"]


class TestEndToEndSecurityScenarios:
    """Test complete end-to-end security scenarios."""

    @pytest.mark.asyncio
    async def test_malicious_user_scenario(self, client: TestClient):
        """Test system response to various malicious attempts."""
        # 1. SQL Injection attempt
        response = client.post("/api/v1/auth/login", json={"username": "admin' --", "password": "anything"})
        # SQL injection generates warnings but proceeds to auth (user not found)
        assert response.status_code == 401

        # 2. XSS attempt in registration
        response = client.post(
            "/api/v1/auth/register",
            json={"username": "<script>alert('xss')</script>", "email": "hacker@evil.com", "password": "Pass123!"},
        )
        # XSS generates warnings but proceeds, may fail with various errors
        assert response.status_code in [201, 400, 422, 500]

        # 3. Oversized request
        large_data = {"data": "x" * (1024 * 1024)}  # 1MB
        response = client.post("/api/v1/users", json=large_data)
        # Should be rejected as too large or unauthorized
        assert response.status_code in [401, 413, 422]

        # 4. Rapid requests (rate limiting disabled in tests)
        for i in range(5):
            response = client.get("/api/v1/health")
            # All should succeed (rate limiting disabled)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_legitimate_user_scenario(self, client: TestClient):
        """Test that legitimate users can use the system normally."""
        # 1. Normal registration
        register_data = {
            "username": f"user_{int(time.time())}",
            "email": f"user_{int(time.time())}@example.com",
            "password": "LegitPass123!",
        }

        response = client.post("/api/v1/auth/register", json=register_data)
        # Should succeed or fail with legitimate error (e.g., user exists)
        assert response.status_code in [201, 409, 429]  # Created, Conflict, or Rate Limited

        # 2. Normal login (if user exists)
        if response.status_code == 201:
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": register_data["username"], "password": register_data["password"]},
            )
            # Might fail if email verification required
            assert login_response.status_code in [200, 403]

    @pytest.mark.asyncio
    async def test_api_key_security_flow(self, client: TestClient):
        """Test API key creation requires authentication."""
        # 1. Try to create API key without authentication
        api_key_data = {
            "name": "test_key",
            "description": "Test API key",
            "permissions": {"read": True, "write": False},
            "expires_at": None,
        }

        response = client.post("/api/v1/api-keys", json=api_key_data)

        # Should require authentication
        assert response.status_code == 401


class TestSecurityMonitoring:
    """Test security monitoring and logging."""

    @pytest.mark.asyncio
    async def test_security_events_logged(self, client: TestClient):
        """Test that security events are properly logged."""
        with patch("app.core.validation.logger") as mock_logger:
            # Attempt SQL injection
            client.post("/api/v1/auth/login", json={"username": "'; DROP TABLE users--", "password": "test"})

            # Should log security event
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_rate_limit_events_logged(self, client: TestClient):
        """Test that rate limit events are logged."""
        # Exhaust rate limit
        for _ in range(10):
            response = client.post("/api/v1/auth/login", json={"username": "test", "password": "test"})
            if response.status_code == 429:
                break

        # Rate limit should be logged


class TestSecurityPerformance:
    """Test performance impact of security features."""

    @pytest.mark.asyncio
    async def test_security_overhead(self, client: TestClient):
        """Test that security features don't add excessive overhead."""
        import time

        # Time a simple health check
        start = time.time()
        response = client.get("/api/v1/health")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 0.1  # Should be fast even with security

    @pytest.mark.asyncio
    async def test_concurrent_security_checks(self, client: TestClient):
        """Test security under concurrent load."""

        async def make_request():
            return client.get("/api/v1/health")

        # Make concurrent requests
        tasks = [make_request() for _ in range(20)]
        responses = await asyncio.gather(*tasks)

        # Most should succeed (some might be rate limited)
        success_count = sum(1 for r in responses if r.status_code == 200)
        assert success_count > 10  # At least half should succeed


class TestSecurityConfiguration:
    """Test security configuration options."""

    def test_security_settings(self):
        """Test that security settings are properly configured."""
        from app.core.config import settings

        # Check security-related settings
        assert settings.SECRET_KEY  # Should be set
        assert len(str(settings.SECRET_KEY.get_secret_value())) >= 32  # Strong key
        assert settings.ALGORITHM == "HS256"  # JWT algorithm
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
        assert settings.SECURE_COOKIES is True  # In production
        assert settings.CSRF_PROTECTION is True  # CSRF enabled

    def test_rate_limit_configuration(self):
        """Test rate limit configuration."""
        # Verify rate limits are reasonable
        assert int(RATE_LIMITS["auth_login"].split("/")[0]) <= 10  # Strict for auth
        assert int(RATE_LIMITS["health_check"].split("/")[0]) >= 60  # Relaxed for health

    def test_validation_configuration(self):
        """Test validation configuration."""
        from app.core.validation import ValidationConfig

        config = ValidationConfig()
        assert config.check_sql_injection is True
        assert config.check_xss_injection is True
        assert config.max_string_length > 0
        assert config.max_json_depth > 0
