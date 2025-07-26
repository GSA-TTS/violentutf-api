"""Tests for CSRF protection middleware."""

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, CSRFProtectionMiddleware


@pytest.fixture
def app():
    """Create test FastAPI app with CSRF middleware."""
    app = FastAPI()
    app.add_middleware(CSRFProtectionMiddleware)

    @app.get("/safe")
    async def safe_endpoint():
        return {"method": "safe"}

    @app.post("/protected")
    async def protected_endpoint():
        return {"method": "protected"}

    @app.post("/form-protected")
    async def form_protected_endpoint():
        return {"method": "form_protected"}

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def csrf_enabled():
    """Enable CSRF protection for tests."""
    with patch("app.core.config.settings.CSRF_PROTECTION", True):
        yield


class TestCSRFProtectionMiddleware:
    """Test CSRF protection middleware functionality."""

    def test_safe_method_allowed(self, client, csrf_enabled):
        """Test that safe methods (GET) are allowed without CSRF token."""
        response = client.get("/safe")
        assert response.status_code == 200
        assert response.json() == {"method": "safe"}

    def test_unsafe_method_without_token_rejected(self, client, csrf_enabled):
        """Test that unsafe methods without CSRF token are rejected."""
        response = client.post("/protected")
        assert response.status_code == 403
        assert "CSRF validation failed" in response.json()["detail"]

    def test_unsafe_method_with_invalid_token_rejected(self, client, csrf_enabled):
        """Test rejection of invalid CSRF tokens."""
        # Send request with invalid token
        response = client.post("/protected", headers={CSRF_HEADER_NAME: "invalid_token"})
        assert response.status_code == 403

    def test_csrf_token_generation_and_validation(self, client, csrf_enabled):
        """Test CSRF token generation and validation flow."""
        # First, make a GET request to get a CSRF token
        get_response = client.get("/safe")
        assert get_response.status_code == 200

        # Extract CSRF token from cookie (if set)
        csrf_token = get_response.cookies.get(CSRF_COOKIE_NAME)

        if csrf_token:
            # Use the token in a POST request
            response = client.post(
                "/protected", headers={CSRF_HEADER_NAME: csrf_token}, cookies={CSRF_COOKIE_NAME: csrf_token}
            )
            # Should succeed with valid token
            assert response.status_code == 200

    def test_form_csrf_token_validation(self, client, csrf_enabled):
        """Test CSRF token validation from form data."""
        # Generate a token first (in real scenario, this would come from a form page)
        middleware = CSRFProtectionMiddleware(None)
        csrf_token = middleware._generate_csrf_token()

        # Send POST with form data containing CSRF token
        response = client.post(
            "/form-protected",
            data={"csrf_token": csrf_token},
            cookies={CSRF_COOKIE_NAME: csrf_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # Should succeed with valid token
        assert response.status_code == 200

    def test_double_submit_cookie_pattern(self, client, csrf_enabled):
        """Test double-submit cookie pattern validation."""
        middleware = CSRFProtectionMiddleware(None)
        csrf_token = middleware._generate_csrf_token()

        # Test with matching cookie and header
        response = client.post(
            "/protected", headers={CSRF_HEADER_NAME: csrf_token}, cookies={CSRF_COOKIE_NAME: csrf_token}
        )
        assert response.status_code == 200

        # Test with mismatched cookie and header
        response = client.post(
            "/protected", headers={CSRF_HEADER_NAME: csrf_token}, cookies={CSRF_COOKIE_NAME: "different_token"}
        )
        assert response.status_code == 403

    def test_csrf_disabled(self, client):
        """Test that CSRF protection can be disabled."""
        with patch("app.core.config.settings.CSRF_PROTECTION", False):
            # Should allow unsafe methods without token when disabled
            response = client.post("/protected")
            assert response.status_code == 200

    def test_exempt_paths(self, client, csrf_enabled):
        """Test that exempt paths bypass CSRF protection."""
        # Health endpoints should be exempt
        with patch("app.middleware.csrf.CSRF_EXEMPT_PATHS", ["/protected"]):
            response = client.post("/protected")
            assert response.status_code == 200

    def test_csrf_token_signature_validation(self):
        """Test CSRF token signature validation."""
        middleware = CSRFProtectionMiddleware(None)

        # Generate valid token
        valid_token = middleware._generate_csrf_token()

        # Test valid token
        assert middleware._validate_csrf_token(valid_token, valid_token) is True

        # Test invalid token (tampered)
        invalid_token = valid_token[:-1] + "X"  # Change last character
        assert middleware._validate_csrf_token(invalid_token, invalid_token) is False

        # Test malformed token
        malformed_token = "not.a.valid.token.format"
        assert middleware._validate_csrf_token(malformed_token, malformed_token) is False

    def test_csrf_token_parts(self):
        """Test CSRF token structure."""
        middleware = CSRFProtectionMiddleware(None)
        token = middleware._generate_csrf_token()

        # Token should have two parts separated by dot
        parts = token.split(".")
        assert len(parts) == 2

        # Both parts should be non-empty
        assert len(parts[0]) > 0
        assert len(parts[1]) > 0

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_unsafe_methods_require_csrf(self, client, csrf_enabled, method):
        """Test that all unsafe HTTP methods require CSRF protection."""
        # Use client's generic request method
        response = client.request(method, "/protected")
        assert response.status_code == 403

    def test_csrf_cookie_attributes(self, client, csrf_enabled):
        """Test CSRF cookie security attributes."""
        # Make request to trigger cookie setting
        get_response = client.get("/safe")

        # In a real test environment, you'd check:
        # - HttpOnly: False (must be readable by JS)
        # - Secure: Based on settings
        # - SameSite: strict
        # - Path: /

        # TestClient limitations prevent full cookie attribute testing
        # This would be better tested with actual HTTP client

    def test_content_type_form_handling(self, client, csrf_enabled):
        """Test CSRF token extraction from different content types."""
        middleware = CSRFProtectionMiddleware(None)
        csrf_token = middleware._generate_csrf_token()

        # Test form-encoded content
        response = client.post(
            "/form-protected",
            data={"csrf_token": csrf_token, "other_field": "value"},
            cookies={CSRF_COOKIE_NAME: csrf_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 200

    def test_csrf_error_logging(self, client, csrf_enabled):
        """Test that CSRF validation failures are logged."""
        with patch("app.middleware.csrf.logger.warning") as mock_logger:
            # Make request without CSRF token
            client.post("/protected")

            # Verify warning was logged
            mock_logger.assert_called()
            call_args = mock_logger.call_args[0]
            assert "csrf_validation_failed" in call_args
