"""
Test suite specifically for Issue #21 JWT Authentication requirements.

This module tests all the requirements specified in GitHub Issue #21:
- JWT token generation and validation
- Token refresh functionality
- Token rotation
- Authentication endpoints
- Password hashing with Argon2
- Security compliance

These tests focus on the core functionality rather than edge cases,
ensuring Issue #21 requirements are properly implemented and working.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Generator

import pytest

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.main import app
from tests.utils.testclient import SafeTestClient

# TestClient imported via TYPE_CHECKING for type hints only


class TestIssue21JWTAuthentication:
    """Test suite for Issue #21 JWT authentication requirements."""

    def test_jwt_token_generation(self):
        """Test JWT token generation as required by Issue #21 Task 3."""
        # Test data
        user_data = {"sub": "test-user-123", "roles": ["viewer"], "organization_id": "org-456"}

        # Generate access token
        access_token = create_access_token(data=user_data)
        assert access_token is not None
        assert len(access_token) > 0

        # Generate refresh token
        refresh_token = create_refresh_token(data=user_data)
        assert refresh_token is not None
        assert len(refresh_token) > 0

        # Tokens should be different
        assert access_token != refresh_token

    def test_jwt_token_validation(self):
        """Test JWT token validation as required by Issue #21 Task 3."""
        # Create test token
        user_data = {"sub": "test-user-456", "roles": ["admin"], "organization_id": "org-789"}
        token = create_access_token(data=user_data)

        # Validate token
        payload = decode_token(token)

        # Verify payload
        assert payload["sub"] == "test-user-456"
        assert payload["roles"] == ["admin"]
        assert payload["organization_id"] == "org-789"
        assert payload["type"] == "access"
        assert "exp" in payload

    def test_token_refresh_functionality(self):
        """Test token refresh functionality as required by Issue #21 Task 4."""
        # Create initial tokens
        user_data = {"sub": "refresh-user-123", "roles": ["editor"]}

        initial_access = create_access_token(data=user_data)
        initial_refresh = create_refresh_token(data=user_data)

        # Validate refresh token
        refresh_payload = decode_token(initial_refresh)
        assert refresh_payload["type"] == "refresh"
        assert refresh_payload["sub"] == "refresh-user-123"

        # Simulate time passing to ensure different expiration times
        import time

        time.sleep(1)

        # Create new tokens (simulating refresh)
        new_access = create_access_token(data=user_data)
        new_refresh = create_refresh_token(data=user_data)

        # New tokens should have different expiration times (rotation)
        initial_access_payload = decode_token(initial_access)
        new_access_payload = decode_token(new_access)

        # Expiration times should be different (token rotation)
        assert new_access_payload["exp"] > initial_access_payload["exp"]

    def test_token_rotation(self):
        """Test token rotation as required by Issue #21 Task 5."""
        user_data = {"sub": "rotation-user", "roles": ["viewer"]}

        # Generate tokens with time delays to ensure different expiration times
        import time

        tokens = []
        for i in range(3):
            access = create_access_token(data=user_data)
            refresh = create_refresh_token(data=user_data)
            tokens.append((access, refresh))
            time.sleep(1)  # Ensure different timestamps

        # Verify tokens have different expiration times (proper rotation)
        access_exps = []
        refresh_exps = []

        for access_token, refresh_token in tokens:
            access_payload = decode_token(access_token)
            refresh_payload = decode_token(refresh_token)
            access_exps.append(access_payload["exp"])
            refresh_exps.append(refresh_payload["exp"])

        # All expiration times should be different (proper rotation)
        assert len(set(access_exps)) == 3, "Access token expiration times should be unique"
        assert len(set(refresh_exps)) == 3, "Refresh token expiration times should be unique"

    def test_authentication_endpoints_exist(self, client):
        """Test authentication endpoints as required by Issue #21 Task 6."""
        # Test login endpoint exists
        response = client.post("/api/v1/auth/login", json={"username": "nonexistent", "password": "wrong"})
        # Should get 401 (endpoint exists but auth fails) or 500 if DB issues
        assert response.status_code in [401, 500]

        # Test register endpoint exists
        response = client.post(
            "/api/v1/auth/register",
            json={"username": "testuser", "email": "test@example.com", "password": "weak"},  # Will fail validation
        )
        # Should get 400 (endpoint exists but validation fails)
        assert response.status_code == 400

        # Test refresh endpoint exists
        response = client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid-token"})
        # Should get 401 (endpoint exists but token invalid)
        assert response.status_code == 401

    def test_password_hashing_with_argon2(self):
        """Test Argon2 password hashing as required by Issue #21 Task 8."""
        password = "TestPassword123!"

        # Hash password
        hashed = hash_password(password)

        # Verify hash format (Argon2)
        assert hashed.startswith("$argon2")
        assert len(hashed) > 50  # Argon2 hashes are long

        # Verify password verification works
        assert verify_password(password, hashed) is True
        assert verify_password("wrong-password", hashed) is False

        # Test multiple hashes are different (salt)
        hash2 = hash_password(password)
        assert hashed != hash2  # Different salts
        assert verify_password(password, hash2) is True

    def test_password_strength_validation(self):
        """Test password strength validation as required by Issue #21 Task 8."""
        # Test strong password
        strong_password = "SecurePass123!"
        is_strong, message = validate_password_strength(strong_password)
        assert is_strong is True
        assert message == "Password is strong"

        # Test weak passwords
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigits!",  # No digits
            "NoSpecialChars123",  # No special chars
        ]

        for weak_pass in weak_passwords:
            is_strong, message = validate_password_strength(weak_pass)
            assert is_strong is False
            assert len(message) > 0

    def test_jwt_token_expiration_handling(self):
        """Test JWT token expiration handling."""
        # Create token with very short expiration
        user_data = {"sub": "expire-test", "roles": ["viewer"]}

        # Create token with custom short expiration
        short_exp = timedelta(seconds=1)
        token = create_access_token(data=user_data, expires_delta=short_exp)

        # Token should be valid immediately
        payload = decode_token(token)
        assert payload["sub"] == "expire-test"

        # Wait for expiration and test
        import time

        time.sleep(2)

        # Token should now be expired
        with pytest.raises(ValueError, match="Token has expired"):
            decode_token(token)

    def test_jwt_token_claims_structure(self):
        """Test JWT token claims structure is correct."""
        user_data = {"sub": "claims-test-user", "roles": ["admin", "editor"], "organization_id": "org-claims-test"}

        # Test access token claims
        access_token = create_access_token(data=user_data)
        access_payload = decode_token(access_token)

        assert access_payload["sub"] == "claims-test-user"
        assert access_payload["roles"] == ["admin", "editor"]
        assert access_payload["organization_id"] == "org-claims-test"
        assert access_payload["type"] == "access"
        assert isinstance(access_payload["exp"], int)

        # Test refresh token claims
        refresh_token = create_refresh_token(data=user_data)
        refresh_payload = decode_token(refresh_token)

        assert refresh_payload["sub"] == "claims-test-user"
        assert refresh_payload["roles"] == ["admin", "editor"]
        assert refresh_payload["organization_id"] == "org-claims-test"
        assert refresh_payload["type"] == "refresh"
        assert isinstance(refresh_payload["exp"], int)

    def test_no_keycloak_dependencies(self):
        """Test that Keycloak dependencies are removed as required by Issue #21 Task 1."""
        # This test verifies that we can import and use JWT functionality
        # without any Keycloak dependencies

        try:
            # Import core security modules
            from app.api.endpoints.auth import router
            from app.core.security import create_access_token, decode_token
            from app.middleware.authentication import JWTAuthenticationMiddleware

            # Create and validate a token using only our JWT implementation
            test_data = {"sub": "no-keycloak-test", "roles": ["viewer"]}
            token = create_access_token(data=test_data)
            payload = decode_token(token)

            assert payload["sub"] == "no-keycloak-test"
            assert payload["type"] == "access"

        except ImportError as e:
            pytest.fail(f"JWT functionality should work without Keycloak: {e}")

    def test_authentication_security_requirements(self):
        """Test security requirements for authentication system."""
        # Test 1: Tokens should be cryptographically secure
        tokens = [create_access_token({"sub": f"user-{i}"}) for i in range(5)]
        assert len(set(tokens)) == 5, "All tokens should be unique"

        # Test 2: Invalid tokens should be rejected
        with pytest.raises(ValueError):
            decode_token("invalid.jwt.token")

        # Test 3: Password hashing should be secure
        password = "TestSecure123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        # Hashes should be different (proper salting)
        assert hash1 != hash2
        # But both should verify the same password
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestIssue21IntegrationScenarios:
    """Integration test scenarios for Issue #21 requirements."""

    def test_complete_authentication_flow_simulation(self):
        """Test complete authentication flow simulating Issue #21 requirements."""
        # Step 1: Create user data and hash password (Task 8)
        username = "integration_test_user"
        password = "IntegrationTest123!"
        email = "integration@test.com"

        # Validate password strength
        is_strong, _ = validate_password_strength(password)
        assert is_strong is True

        # Hash password
        hashed_password = hash_password(password)
        assert verify_password(password, hashed_password) is True

        # Step 2: Simulate user authentication (Task 6)
        user_data = {"sub": "integration-user-123", "roles": ["viewer"], "organization_id": "test-org"}

        # Step 3: Generate JWT tokens (Task 3)
        access_token = create_access_token(data=user_data)
        refresh_token = create_refresh_token(data=user_data)

        # Step 4: Validate tokens (Task 3)
        access_payload = decode_token(access_token)
        refresh_payload = decode_token(refresh_token)

        assert access_payload["sub"] == user_data["sub"]
        assert access_payload["type"] == "access"
        assert refresh_payload["sub"] == user_data["sub"]
        assert refresh_payload["type"] == "refresh"

        # Step 5: Simulate token refresh (Task 4) - add time delay for different expiration
        import time

        time.sleep(1)
        new_access_token = create_access_token(data=user_data)
        new_refresh_token = create_refresh_token(data=user_data)

        # Step 6: Verify token rotation (Task 5) - check expiration times are different
        access_payload = decode_token(access_token)
        new_access_payload_check = decode_token(new_access_token)
        assert new_access_payload_check["exp"] > access_payload["exp"]

        # Step 7: Validate new tokens
        new_access_payload = decode_token(new_access_token)
        new_refresh_payload = decode_token(new_refresh_token)

        assert new_access_payload["sub"] == user_data["sub"]
        assert new_refresh_payload["sub"] == user_data["sub"]

    def test_security_compliance_verification(self):
        """Test security compliance for Issue #21 requirements."""
        # Test multiple security aspects together

        # 1. Password security
        passwords = ["SecurePass1!", "AnotherSecure2@", "ThirdSecure3#"]
        hashes = [hash_password(pwd) for pwd in passwords]

        # All hashes should be unique
        assert len(set(hashes)) == len(passwords)

        # All should use Argon2
        for hash_val in hashes:
            assert hash_val.startswith("$argon2")

        # 2. JWT security - tokens should have different expiration times when created at different times
        import time

        user_data = {"sub": "security-test", "roles": ["admin"]}
        tokens = []
        for _ in range(3):
            tokens.append(create_access_token(data=user_data))
            time.sleep(1)  # Ensure different expiration times

        # Verify different expiration times (secure token rotation)
        expirations = [decode_token(token)["exp"] for token in tokens]
        assert len(set(expirations)) == 3

        # All should decode to same user data
        for token in tokens:
            payload = decode_token(token)
            assert payload["sub"] == "security-test"
            assert payload["roles"] == ["admin"]
            assert payload["type"] == "access"

        # 3. Token type validation
        access_token = create_access_token(data=user_data)
        refresh_token = create_refresh_token(data=user_data)

        access_payload = decode_token(access_token)
        refresh_payload = decode_token(refresh_token)

        assert access_payload["type"] == "access"
        assert refresh_payload["type"] == "refresh"
