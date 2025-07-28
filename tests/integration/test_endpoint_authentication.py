"""Systematic endpoint authentication testing.

This module provides comprehensive testing to verify that all protected endpoints
require proper authentication. Tests use parametrized approach to systematically
validate authentication requirements across the entire API surface.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.security import create_access_token


class TestSystematicEndpointAuthentication:
    """Systematic testing of authentication requirements for all endpoints."""

    def create_test_jwt_token(
        self,
        user_id: str = "test-user-123",
        roles: List[str] = None,
        organization_id: str = None,
        token_type: str = "access",
    ) -> str:
        """Create test JWT token for authentication."""
        if roles is None:
            roles = ["viewer"]

        payload = {
            "sub": user_id,
            "roles": roles,
            "organization_id": organization_id,
            "type": token_type,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

        return create_access_token(data=payload)

    def create_admin_jwt_token(self) -> str:
        """Create admin JWT token for testing."""
        return self.create_test_jwt_token(user_id="admin-user-456", roles=["admin"], organization_id="test-org-123")

    # Protected Endpoint Test Data

    @pytest.fixture
    def protected_endpoints(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        """List of protected endpoints that require authentication.

        Returns:
            List of tuples: (method, endpoint, optional_payload)
        """
        return [
            # User Management Endpoints
            ("GET", "/api/v1/users", {}),
            (
                "POST",
                "/api/v1/users",
                {
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "TestPass123!",
                    "full_name": "Test User",
                },
            ),
            ("GET", "/api/v1/users/12345", {}),
            ("PUT", "/api/v1/users/12345", {"full_name": "Updated Name"}),
            ("DELETE", "/api/v1/users/12345", {}),
            ("POST", "/api/v1/users/12345/verify", {}),
            ("GET", "/api/v1/users/me", {}),
            ("PUT", "/api/v1/users/me", {"full_name": "My Updated Name"}),
            # API Key Management Endpoints
            ("GET", "/api/v1/api-keys", {}),
            ("POST", "/api/v1/api-keys", {"name": "Test API Key", "permissions": {"read": True, "write": False}}),
            ("GET", "/api/v1/api-keys/12345", {}),
            ("PUT", "/api/v1/api-keys/12345", {"name": "Updated Key Name"}),
            ("DELETE", "/api/v1/api-keys/12345", {}),
            ("POST", "/api/v1/api-keys/12345/revoke", {}),
            ("POST", "/api/v1/api-keys/12345/validate", {}),
            ("GET", "/api/v1/api-keys/my-keys", {}),
            ("GET", "/api/v1/api-keys/usage-stats", {}),
            # Session Management Endpoints
            ("GET", "/api/v1/sessions", {}),
            (
                "POST",
                "/api/v1/sessions",
                {"user_id": "user-123", "session_token": f"token-{uuid.uuid4()}", "device_info": "Test Device"},
            ),
            ("GET", "/api/v1/sessions/12345", {}),
            ("PUT", "/api/v1/sessions/12345", {"device_info": "Updated Device"}),
            ("DELETE", "/api/v1/sessions/12345", {}),
            ("POST", "/api/v1/sessions/12345/revoke", {"reason": "Test revocation"}),
            ("POST", "/api/v1/sessions/12345/extend", {"extension_minutes": 60}),
            ("GET", "/api/v1/sessions/my-sessions", {}),
            ("POST", "/api/v1/sessions/revoke-all", {}),
            ("GET", "/api/v1/sessions/statistics", {}),
            # Audit Log Endpoints
            ("GET", "/api/v1/audit-logs", {}),
            (
                "POST",
                "/api/v1/audit-logs",
                {"action": "test.action", "resource_type": "test", "resource_id": "test-123"},
            ),
            ("GET", "/api/v1/audit-logs/12345", {}),
            ("GET", "/api/v1/audit-logs/resource/user/12345", {}),
            ("GET", "/api/v1/audit-logs/statistics", {}),
            ("POST", "/api/v1/audit-logs/export", {"format": "json", "resource_type": "user"}),
            # LLM Configuration Endpoints
            ("GET", "/api/v1/llm-configs", {}),
            ("POST", "/api/v1/llm-configs", {"name": "Test Config", "provider": "openai", "model": "gpt-4"}),
            ("GET", "/api/v1/llm-configs/12345", {}),
            ("PUT", "/api/v1/llm-configs/12345", {"name": "Updated Config"}),
            ("DELETE", "/api/v1/llm-configs/12345", {}),
            ("POST", "/api/v1/llm-configs/12345/test", {}),
            # Prompt Injection Endpoints
            ("GET", "/api/v1/prompt-injections", {}),
            ("POST", "/api/v1/prompt-injections", {"name": "Test Injection", "prompt": "Test prompt content"}),
            ("GET", "/api/v1/prompt-injections/12345", {}),
            ("PUT", "/api/v1/prompt-injections/12345", {"name": "Updated Injection"}),
            ("DELETE", "/api/v1/prompt-injections/12345", {}),
            ("POST", "/api/v1/prompt-injections/12345/execute", {}),
            # Jailbreak Endpoints
            ("GET", "/api/v1/jailbreaks", {}),
            ("POST", "/api/v1/jailbreaks", {"name": "Test Jailbreak", "technique": "test_technique"}),
            ("GET", "/api/v1/jailbreaks/12345", {}),
            ("PUT", "/api/v1/jailbreaks/12345", {"name": "Updated Jailbreak"}),
            ("DELETE", "/api/v1/jailbreaks/12345", {}),
            ("POST", "/api/v1/jailbreaks/12345/execute", {}),
        ]

    @pytest.fixture
    def exempt_endpoints(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        """List of endpoints that should be exempt from authentication.

        Returns:
            List of tuples: (method, endpoint, optional_payload)
        """
        return [
            # Authentication Endpoints
            ("POST", "/api/v1/auth/login", {"username": "testuser", "password": "testpass"}),
            (
                "POST",
                "/api/v1/auth/register",
                {"username": "newuser", "email": "new@example.com", "password": "NewPass123!"},
            ),
            ("POST", "/api/v1/auth/refresh", {"refresh_token": "test_refresh_token"}),
            ("POST", "/api/v1/auth/logout", {}),
            ("POST", "/api/v1/auth/reset-password", {"email": "test@example.com"}),
            ("POST", "/api/v1/auth/verify-email", {"token": "verify_token"}),
            # Health Check Endpoints
            ("GET", "/api/v1/health", {}),
            ("GET", "/api/v1/ready", {}),
            ("GET", "/api/v1/live", {}),
            # Documentation Endpoints
            ("GET", "/docs", {}),
            ("GET", "/redoc", {}),
            ("GET", "/openapi.json", {}),
            # Metrics Endpoint
            ("GET", "/metrics", {}),
        ]

    # Systematic Authentication Requirement Tests

    @pytest.mark.asyncio
    async def test_protected_endpoints_require_authentication(
        self, client: AsyncClient, protected_endpoints: List[Tuple[str, str, Dict[str, Any]]]
    ) -> None:
        """Test that all protected endpoints require authentication."""
        failures = []

        for method, endpoint, payload in protected_endpoints:
            try:
                if method == "GET":
                    response = await client.get(endpoint)
                elif method == "POST":
                    response = await client.post(endpoint, json=payload)
                elif method == "PUT":
                    response = await client.put(endpoint, json=payload)
                elif method == "PATCH":
                    response = await client.patch(endpoint, json=payload)
                elif method == "DELETE":
                    response = await client.delete(endpoint)
                else:
                    failures.append(f"Unsupported method {method} for {endpoint}")
                    continue

                # Should return 401 for missing authentication
                if response.status_code != 401:
                    failures.append(f"{method} {endpoint} returned {response.status_code}, expected 401")
                else:
                    # Check for proper authentication error format
                    if response.headers.get("WWW-Authenticate") != "Bearer":
                        failures.append(f"{method} {endpoint} missing WWW-Authenticate header")

                    response_data = response.json()
                    if "detail" not in response_data:
                        failures.append(f"{method} {endpoint} missing error detail")

            except Exception as e:
                failures.append(f"{method} {endpoint} raised exception: {str(e)}")

        if failures:
            pytest.fail(f"Authentication requirement failures:\n" + "\n".join(failures))

    @pytest.mark.asyncio
    async def test_exempt_endpoints_allow_anonymous_access(
        self, client: AsyncClient, exempt_endpoints: List[Tuple[str, str, Dict[str, Any]]]
    ) -> None:
        """Test that exempt endpoints allow anonymous access."""
        unexpected_auth_required = []

        for method, endpoint, payload in exempt_endpoints:
            try:
                if method == "GET":
                    response = await client.get(endpoint)
                elif method == "POST":
                    response = await client.post(endpoint, json=payload)
                elif method == "PUT":
                    response = await client.put(endpoint, json=payload)
                elif method == "DELETE":
                    response = await client.delete(endpoint)
                else:
                    continue

                # Should NOT return 401 (authentication required)
                if response.status_code == 401:
                    unexpected_auth_required.append(f"{method} {endpoint}")

                # Accept various status codes (200, 404, 422, etc.) but not 401
                assert response.status_code != 401, f"{method} {endpoint} unexpectedly requires auth"

            except AssertionError:
                raise
            except Exception:
                # Some endpoints may not exist or have other issues, that's OK
                # We're only testing that they don't require authentication
                pass

        if unexpected_auth_required:
            pytest.fail(f"Endpoints unexpectedly requiring authentication:\n" + "\n".join(unexpected_auth_required))

    @pytest.mark.asyncio
    async def test_protected_endpoints_accept_valid_authentication(
        self, client: AsyncClient, protected_endpoints: List[Tuple[str, str, Dict[str, Any]]]
    ) -> None:
        """Test that protected endpoints accept valid authentication tokens."""
        token = self.create_test_jwt_token()
        headers = {"Authorization": f"Bearer {token}"}

        auth_failures = []

        for method, endpoint, payload in protected_endpoints:
            try:
                if method == "GET":
                    response = await client.get(endpoint, headers=headers)
                elif method == "POST":
                    response = await client.post(endpoint, json=payload, headers=headers)
                elif method == "PUT":
                    response = await client.put(endpoint, json=payload, headers=headers)
                elif method == "PATCH":
                    response = await client.patch(endpoint, json=payload, headers=headers)
                elif method == "DELETE":
                    response = await client.delete(endpoint, headers=headers)
                else:
                    continue

                # Should NOT return 401 with valid authentication
                if response.status_code == 401:
                    auth_failures.append(f"{method} {endpoint} returned 401 with valid token")

                # May return 404, 422, 403, etc. for business logic, but not 401
                assert response.status_code != 401, f"{method} {endpoint} rejected valid auth"

            except AssertionError:
                raise
            except Exception as e:
                # Log but don't fail on other exceptions (e.g., validation errors)
                pass

        if auth_failures:
            pytest.fail(f"Valid authentication failures:\n" + "\n".join(auth_failures))

    @pytest.mark.asyncio
    async def test_protected_endpoints_reject_invalid_tokens(
        self, client: AsyncClient, protected_endpoints: List[Tuple[str, str, Dict[str, Any]]]
    ) -> None:
        """Test that protected endpoints reject invalid authentication tokens."""
        invalid_headers = [
            {"Authorization": "Bearer invalid-token"},
            {"Authorization": "Bearer expired.jwt.token"},
            {"Authorization": "Bearer malformed-token"},
            {"Authorization": "InvalidScheme valid-looking-token"},
        ]

        for headers in invalid_headers:
            rejection_failures = []

            # Test a sample of endpoints with each invalid token type
            sample_endpoints = protected_endpoints[:5]  # Test first 5 for efficiency

            for method, endpoint, payload in sample_endpoints:
                try:
                    if method == "GET":
                        response = await client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = await client.post(endpoint, json=payload, headers=headers)
                    else:
                        continue

                    if response.status_code != 401:
                        rejection_failures.append(
                            f"{method} {endpoint} accepted invalid token: {headers['Authorization'][:20]}..."
                        )

                except Exception:
                    # Other exceptions are OK, we're only testing auth rejection
                    pass

            if rejection_failures:
                pytest.fail(f"Invalid token acceptance failures:\n" + "\n".join(rejection_failures))

    # Method-Based Protection Tests

    @pytest.mark.asyncio
    async def test_write_methods_always_require_authentication(self, client: AsyncClient) -> None:
        """Test that write methods (POST, PUT, PATCH, DELETE) always require authentication."""
        write_methods = ["POST", "PUT", "PATCH", "DELETE"]

        # Test paths that might allow GET but should protect write operations
        test_paths = [
            "/api/v1/users",
            "/api/v1/api-keys",
            "/api/v1/sessions",
            "/api/v1/audit-logs",
            "/api/v1/llm-configs",
            "/api/v1/prompt-injections",
            "/api/v1/jailbreaks",
        ]

        write_protection_failures = []

        for path in test_paths:
            for method in write_methods:
                try:
                    if method == "POST":
                        response = await client.post(path, json={})
                    elif method == "PUT":
                        response = await client.put(f"{path}/123", json={})
                    elif method == "PATCH":
                        response = await client.patch(f"{path}/123", json={})
                    elif method == "DELETE":
                        response = await client.delete(f"{path}/123")

                    if response.status_code != 401:
                        write_protection_failures.append(
                            f"{method} {path} did not require authentication (got {response.status_code})"
                        )

                except Exception:
                    # Exceptions are OK, we're only testing auth requirements
                    pass

        if write_protection_failures:
            pytest.fail(f"Write method protection failures:\n" + "\n".join(write_protection_failures))

    # Authorization Level Tests

    @pytest.mark.asyncio
    async def test_admin_only_endpoints_reject_regular_users(self, client: AsyncClient) -> None:
        """Test that admin-only endpoints reject regular user tokens."""
        regular_user_token = self.create_test_jwt_token(roles=["viewer"])
        headers = {"Authorization": f"Bearer {regular_user_token}"}

        # Known admin-only endpoints
        admin_endpoints = [
            ("GET", "/api/v1/users"),  # List all users
            ("POST", "/api/v1/users"),  # Create users
            ("DELETE", "/api/v1/users/123"),  # Delete users
            ("GET", "/api/v1/sessions/statistics"),  # System statistics
            ("GET", "/api/v1/api-keys/usage-stats"),  # Usage statistics
            ("GET", "/api/v1/audit-logs"),  # Audit log access
            ("POST", "/api/v1/users/123/verify"),  # User verification
        ]

        authorization_failures = []

        for method, endpoint in admin_endpoints:
            try:
                if method == "GET":
                    response = await client.get(endpoint, headers=headers)
                elif method == "POST":
                    response = await client.post(endpoint, json={}, headers=headers)
                elif method == "DELETE":
                    response = await client.delete(endpoint, headers=headers)

                # Should return 403 (Forbidden) for insufficient permissions
                # or 401 if endpoint has additional auth requirements
                if response.status_code not in [401, 403]:
                    authorization_failures.append(
                        f"{method} {endpoint} allowed regular user access (got {response.status_code})"
                    )

            except Exception:
                # Other exceptions are acceptable
                pass

        if authorization_failures:
            pytest.fail(f"Authorization failures for regular users:\n" + "\n".join(authorization_failures))

    @pytest.mark.asyncio
    async def test_admin_endpoints_accept_admin_tokens(self, client: AsyncClient) -> None:
        """Test that admin endpoints accept admin tokens."""
        admin_token = self.create_admin_jwt_token()
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Test admin endpoints accept admin tokens (should not get 401/403)
        admin_endpoints = [
            ("GET", "/api/v1/users"),
            ("GET", "/api/v1/sessions/statistics"),
            ("GET", "/api/v1/audit-logs"),
        ]

        admin_access_failures = []

        for method, endpoint in admin_endpoints:
            try:
                if method == "GET":
                    response = await client.get(endpoint, headers=headers)

                # Should not be rejected for authentication/authorization
                if response.status_code in [401, 403]:
                    admin_access_failures.append(
                        f"{method} {endpoint} rejected admin token (got {response.status_code})"
                    )

            except Exception:
                # Other exceptions (404, 422, etc.) are acceptable
                pass

        if admin_access_failures:
            pytest.fail(f"Admin access failures:\n" + "\n".join(admin_access_failures))

    # Edge Case and Security Tests

    @pytest.mark.asyncio
    async def test_case_insensitive_bearer_scheme_rejection(self, client: AsyncClient) -> None:
        """Test that non-standard Bearer scheme cases are rejected."""
        token = self.create_test_jwt_token()

        case_variations = [
            {"Authorization": f"bearer {token}"},  # lowercase
            {"Authorization": f"BEARER {token}"},  # uppercase
            {"Authorization": f"Bearer{token}"},  # no space
            {"Authorization": f"Bearer  {token}"},  # extra space
        ]

        for headers in case_variations:
            response = await client.get("/api/v1/users", headers=headers)
            # Most should be rejected (only "Bearer " with single space is valid)
            if "Bearer " not in headers["Authorization"]:
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_multiple_authorization_headers_handling(self, client: AsyncClient) -> None:
        """Test handling of multiple Authorization headers."""
        token = self.create_test_jwt_token()

        # Test with multiple headers (if framework allows)
        # Most HTTP implementations take the first or last value
        response = await client.get(
            "/api/v1/users",
            headers=[
                ("Authorization", f"Bearer {token}"),
                ("Authorization", "Bearer invalid-token"),
            ],
        )

        # Behavior may vary by implementation, but should be consistent
        assert response.status_code in [200, 401, 404, 403]  # Should not crash

    @pytest.mark.asyncio
    async def test_very_long_bearer_tokens_handling(self, client: AsyncClient) -> None:
        """Test handling of very long Bearer tokens."""
        # Create extremely long token
        long_token = "x" * 10000
        headers = {"Authorization": f"Bearer {long_token}"}

        response = await client.get("/api/v1/users", headers=headers)

        # Should handle gracefully (reject as invalid, not crash)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid authentication token"

    @pytest.mark.asyncio
    async def test_empty_bearer_token_handling(self, client: AsyncClient) -> None:
        """Test handling of empty Bearer tokens."""
        empty_token_headers = [
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer \t"},
            {"Authorization": "Bearer \n"},
        ]

        for headers in empty_token_headers:
            response = await client.get("/api/v1/users", headers=headers)
            assert response.status_code == 401
            assert response.json()["detail"] == "Missing authentication token"
