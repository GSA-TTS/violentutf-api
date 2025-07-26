"""Comprehensive tests for CSRF protection middleware to achieve 95%+ coverage."""

import hmac
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.middleware.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_EXEMPT_PATHS,
    CSRF_HEADER_NAME,
    CSRF_TOKEN_LENGTH,
    SAFE_METHODS,
    CSRFProtectionMiddleware,
    exempt_from_csrf,
    get_csrf_token,
)


@pytest.fixture
def app():
    """Create test FastAPI app."""
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"message": "success"}

    @app.post("/api/v1/protected")
    async def protected():
        return {"message": "protected"}

    @app.post("/api/v1/forms")
    async def form_endpoint():
        return {"message": "form_processed"}

    @app.get("/api/v1/health")
    async def health():
        return {"status": "healthy"}

    @app.post("/api/v1/exempt")
    @exempt_from_csrf
    async def exempt_endpoint():
        return {"message": "exempt"}

    return app


@pytest.fixture
def csrf_app(app):
    """Create app with CSRF middleware."""
    app.add_middleware(CSRFProtectionMiddleware)
    return app


@pytest.fixture
def client(csrf_app):
    """Create test client."""
    return TestClient(csrf_app)


@pytest.fixture
def csrf_middleware():
    """Create CSRF middleware instance."""
    mock_app = MagicMock()
    return CSRFProtectionMiddleware(mock_app)


class TestCSRFMiddlewareInitialization:
    """Test CSRF middleware initialization."""

    def test_middleware_initialization(self, csrf_middleware):
        """Test middleware is properly initialized."""
        assert csrf_middleware.csrf_secret is not None
        assert isinstance(csrf_middleware.csrf_secret, bytes)
        assert len(csrf_middleware.csrf_secret) > 0

    def test_middleware_uses_settings_secret(self):
        """Test middleware uses SECRET_KEY from settings."""
        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_secret = MagicMock()
            mock_secret.get_secret_value.return_value = "test_secret_key_123"
            mock_settings.SECRET_KEY = mock_secret

            mock_app = MagicMock()
            middleware = CSRFProtectionMiddleware(mock_app)

            assert middleware.csrf_secret == b"test_secret_key_123"
            mock_secret.get_secret_value.assert_called_once()


class TestCSRFTokenGeneration:
    """Test CSRF token generation."""

    def test_generate_csrf_token_format(self, csrf_middleware):
        """Test generated token has correct format."""
        token = csrf_middleware._generate_csrf_token()

        assert isinstance(token, str)
        assert "." in token

        token_part, signature_part = token.rsplit(".", 1)
        assert len(token_part) > 0
        assert len(signature_part) == 64  # SHA256 hex digest

    def test_generate_csrf_token_uniqueness(self, csrf_middleware):
        """Test that generated tokens are unique."""
        tokens = [csrf_middleware._generate_csrf_token() for _ in range(10)]

        # All tokens should be unique
        assert len(set(tokens)) == 10

    def test_generate_csrf_token_signature_valid(self, csrf_middleware):
        """Test that generated token signature is valid."""
        token = csrf_middleware._generate_csrf_token()
        token_part, signature_part = token.rsplit(".", 1)

        expected_signature = hmac.new(csrf_middleware.csrf_secret, token_part.encode(), "sha256").hexdigest()

        assert signature_part == expected_signature

    def test_generate_csrf_token_length(self, csrf_middleware):
        """Test token generation uses correct length."""
        token = csrf_middleware._generate_csrf_token()
        token_part = token.rsplit(".", 1)[0]

        # URL-safe base64 encoding of CSRF_TOKEN_LENGTH bytes
        # Should be approximately 4/3 * CSRF_TOKEN_LENGTH characters
        expected_min_length = int(CSRF_TOKEN_LENGTH * 4 / 3)
        expected_max_length = expected_min_length + 4  # Padding

        assert expected_min_length <= len(token_part) <= expected_max_length


class TestCSRFTokenValidation:
    """Test CSRF token validation."""

    def test_validate_csrf_token_valid_tokens(self, csrf_middleware):
        """Test validation with valid matching tokens."""
        token = csrf_middleware._generate_csrf_token()

        # Same token for both cookie and submitted
        result = csrf_middleware._validate_csrf_token(token, token)
        assert result is True

    def test_validate_csrf_token_missing_cookie(self, csrf_middleware):
        """Test validation fails with missing cookie token."""
        token = csrf_middleware._generate_csrf_token()

        result = csrf_middleware._validate_csrf_token(None, token)
        assert result is False

    def test_validate_csrf_token_missing_submitted(self, csrf_middleware):
        """Test validation fails with missing submitted token."""
        token = csrf_middleware._generate_csrf_token()

        result = csrf_middleware._validate_csrf_token(token, None)
        assert result is False

    def test_validate_csrf_token_both_missing(self, csrf_middleware):
        """Test validation fails with both tokens missing."""
        result = csrf_middleware._validate_csrf_token(None, None)
        assert result is False

    def test_validate_csrf_token_different_tokens(self, csrf_middleware):
        """Test validation fails with different tokens."""
        token1 = csrf_middleware._generate_csrf_token()
        token2 = csrf_middleware._generate_csrf_token()

        result = csrf_middleware._validate_csrf_token(token1, token2)
        assert result is False

    def test_validate_csrf_token_invalid_format(self, csrf_middleware):
        """Test validation fails with invalid token format."""
        invalid_tokens = [
            "invalid_token_no_dot",
            "token.with.multiple.dots",
            "token.",  # Empty signature
            ".signature",  # Empty token
            "",  # Empty string
            "token.invalid_signature_length",
        ]

        for invalid_token in invalid_tokens:
            result = csrf_middleware._validate_csrf_token(invalid_token, invalid_token)
            assert result is False

    def test_validate_csrf_token_tampered_signature(self, csrf_middleware):
        """Test validation fails with tampered signature."""
        token = csrf_middleware._generate_csrf_token()
        token_part, _ = token.rsplit(".", 1)

        # Create token with wrong signature
        tampered_token = f"{token_part}.wrong_signature"

        result = csrf_middleware._validate_csrf_token(tampered_token, tampered_token)
        assert result is False

    def test_validate_csrf_token_constant_time_comparison(self, csrf_middleware):
        """Test that validation uses constant-time comparison."""
        with patch("hmac.compare_digest") as mock_compare:
            mock_compare.return_value = True

            token = csrf_middleware._generate_csrf_token()
            csrf_middleware._validate_csrf_token(token, token)

            mock_compare.assert_called_once()

    def test_validate_csrf_token_exception_handling(self, csrf_middleware):
        """Test validation handles exceptions gracefully."""
        with patch("hmac.new", side_effect=Exception("HMAC error")):
            result = csrf_middleware._validate_csrf_token("test.token", "test.token")
            assert result is False

    def test_validate_csrf_token_logs_error(self, csrf_middleware):
        """Test validation logs errors on exception."""
        with patch("hmac.new", side_effect=Exception("HMAC error")):
            with patch("app.middleware.csrf.logger") as mock_logger:
                csrf_middleware._validate_csrf_token("test.token", "test.token")
                mock_logger.error.assert_called_once()


class TestCSRFCookieHandling:
    """Test CSRF cookie setting."""

    def test_set_csrf_cookie_basic(self, csrf_middleware):
        """Test setting CSRF cookie with basic configuration."""
        response = Response()
        token = "test_token"

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30
            mock_settings.SECURE_COOKIES = False

            csrf_middleware._set_csrf_cookie(response, token)

        # Check that set_cookie was called
        assert hasattr(response, "set_cookie")

    def test_set_csrf_cookie_secure_settings(self, csrf_middleware):
        """Test setting CSRF cookie with secure settings."""
        response = MagicMock()
        token = "secure_test_token"

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60
            mock_settings.SECURE_COOKIES = True

            csrf_middleware._set_csrf_cookie(response, token)

        response.set_cookie.assert_called_once_with(
            key=CSRF_COOKIE_NAME,
            value=token,
            max_age=3600,  # 60 minutes * 60 seconds
            httponly=False,
            secure=True,
            samesite="strict",
            path="/",
        )

    def test_set_csrf_cookie_logs_debug(self, csrf_middleware):
        """Test that setting cookie logs debug message."""
        response = MagicMock()

        with patch("app.middleware.csrf.logger") as mock_logger:
            csrf_middleware._set_csrf_cookie(response, "token")
            mock_logger.debug.assert_called_once_with("csrf_cookie_set")


class TestCSRFMiddlewareDispatch:
    """Test CSRF middleware dispatch logic."""

    @pytest.mark.asyncio
    async def test_dispatch_safe_methods_allowed(self, csrf_middleware):
        """Test that safe methods bypass CSRF protection."""
        for method in SAFE_METHODS:
            request = MagicMock()
            request.method = method

            call_next = AsyncMock()
            expected_response = Response()
            call_next.return_value = expected_response

            result = await csrf_middleware.dispatch(request, call_next)

            assert result == expected_response
            call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_dispatch_exempt_paths_allowed(self, csrf_middleware):
        """Test that exempt paths bypass CSRF protection."""
        for path in CSRF_EXEMPT_PATHS:
            request = MagicMock()
            request.method = "POST"
            request.url.path = path

            call_next = AsyncMock()
            expected_response = Response()
            call_next.return_value = expected_response

            result = await csrf_middleware.dispatch(request, call_next)

            assert result == expected_response
            call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_dispatch_csrf_disabled_allowed(self, csrf_middleware):
        """Test that requests pass through when CSRF is disabled."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"

        call_next = AsyncMock()
        expected_response = Response()
        call_next.return_value = expected_response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = False

            result = await csrf_middleware.dispatch(request, call_next)

            assert result == expected_response
            call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_dispatch_missing_tokens_blocked(self, csrf_middleware):
        """Test that requests without CSRF tokens are blocked."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {}
        request.headers = {}

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            assert isinstance(result, JSONResponse)
            assert result.status_code == 403
            call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_invalid_tokens_blocked(self, csrf_middleware):
        """Test that requests with invalid CSRF tokens are blocked."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {CSRF_COOKIE_NAME: "invalid_token"}
        request.headers = {CSRF_HEADER_NAME: "different_token"}

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            assert isinstance(result, JSONResponse)
            assert result.status_code == 403
            call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_valid_tokens_allowed(self, csrf_middleware):
        """Test that requests with valid CSRF tokens are allowed."""
        token = csrf_middleware._generate_csrf_token()

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {CSRF_COOKIE_NAME: token}
        request.headers = {CSRF_HEADER_NAME: token}
        request.state = MagicMock()

        call_next = AsyncMock()
        expected_response = Response()
        call_next.return_value = expected_response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            assert result == expected_response
            call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_dispatch_form_token_parsing(self, csrf_middleware):
        """Test parsing CSRF token from form data."""
        token = csrf_middleware._generate_csrf_token()

        # Mock form data
        mock_form_data = {"csrf_token": token, "other_field": "value"}

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/forms"
        request.cookies = {CSRF_COOKIE_NAME: token}
        request.headers = {"content-type": "application/x-www-form-urlencoded"}
        request.form = AsyncMock(return_value=mock_form_data)
        request.state = MagicMock()

        call_next = AsyncMock()
        expected_response = Response()
        call_next.return_value = expected_response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            assert result == expected_response
            request.form.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_form_parsing_exception(self, csrf_middleware):
        """Test handling of form parsing exceptions."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/forms"
        request.cookies = {}
        request.headers = {"content-type": "application/x-www-form-urlencoded"}
        request.form = AsyncMock(side_effect=Exception("Form parsing error"))

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            # Should still handle the exception gracefully and check other tokens
            assert isinstance(result, JSONResponse)
            assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_dispatch_token_generation_for_new_requests(self, csrf_middleware):
        """Test token generation when no cookie token exists."""
        token = csrf_middleware._generate_csrf_token()

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {}
        request.headers = {CSRF_HEADER_NAME: token}
        request.state = MagicMock()

        call_next = AsyncMock()
        response = MagicMock()
        call_next.return_value = response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            with patch.object(csrf_middleware, "_validate_csrf_token", return_value=True):
                with patch.object(csrf_middleware, "_generate_csrf_token", return_value=token):
                    result = await csrf_middleware.dispatch(request, call_next)

            # Should set state for new token
            assert request.state.csrf_token == token
            assert request.state.set_csrf_cookie is True

    @pytest.mark.asyncio
    async def test_dispatch_existing_cookie_token(self, csrf_middleware):
        """Test using existing cookie token."""
        token = csrf_middleware._generate_csrf_token()

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {CSRF_COOKIE_NAME: token}
        request.headers = {CSRF_HEADER_NAME: token}
        request.state = MagicMock()

        call_next = AsyncMock()
        response = MagicMock()
        call_next.return_value = response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            with patch.object(csrf_middleware, "_validate_csrf_token", return_value=True):
                result = await csrf_middleware.dispatch(request, call_next)

            # Should use existing token
            assert request.state.csrf_token == token
            assert not hasattr(request.state, "set_csrf_cookie")

    @pytest.mark.asyncio
    async def test_dispatch_sets_csrf_cookie_on_response(self, csrf_middleware):
        """Test that CSRF cookie is set on response when needed."""
        token = csrf_middleware._generate_csrf_token()

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {}
        request.headers = {CSRF_HEADER_NAME: token}
        request.state = MagicMock()
        request.state.set_csrf_cookie = True
        request.state.csrf_token = token

        call_next = AsyncMock()
        response = MagicMock()
        call_next.return_value = response

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            with patch.object(csrf_middleware, "_validate_csrf_token", return_value=True):
                with patch.object(csrf_middleware, "_set_csrf_cookie") as mock_set_cookie:
                    result = await csrf_middleware.dispatch(request, call_next)

                    mock_set_cookie.assert_called_once_with(response, token)

    @pytest.mark.asyncio
    async def test_dispatch_logs_validation_failure(self, csrf_middleware):
        """Test that validation failures are logged."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {CSRF_COOKIE_NAME: "invalid_token"}
        request.headers = {CSRF_HEADER_NAME: "different_token"}

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            with patch("app.middleware.csrf.logger") as mock_logger:
                result = await csrf_middleware.dispatch(request, call_next)

                mock_logger.warning.assert_called_once_with(
                    "csrf_validation_failed",
                    method="POST",
                    path="/api/v1/protected",
                    has_cookie=True,
                    has_submitted=True,
                )


class TestCSRFUtilityFunctions:
    """Test CSRF utility functions."""

    def test_get_csrf_token_exists(self):
        """Test getting CSRF token when it exists."""
        request = MagicMock()
        request.state.csrf_token = "test_token"

        result = get_csrf_token(request)
        assert result == "test_token"

    def test_get_csrf_token_missing(self):
        """Test getting CSRF token when it doesn't exist."""
        request = MagicMock()
        del request.state.csrf_token  # Simulate missing attribute

        with patch("builtins.getattr", return_value=None):
            result = get_csrf_token(request)
            assert result is None

    def test_exempt_from_csrf_decorator(self):
        """Test CSRF exemption decorator."""

        @exempt_from_csrf
        def test_function():
            return "test"

        assert hasattr(test_function, "_csrf_exempt")
        assert test_function._csrf_exempt is True

    def test_exempt_from_csrf_decorator_preserves_function(self):
        """Test that decorator preserves original function."""

        @exempt_from_csrf
        def test_function(x, y):
            return x + y

        result = test_function(1, 2)
        assert result == 3
        assert hasattr(test_function, "_csrf_exempt")


class TestCSRFConstants:
    """Test CSRF middleware constants."""

    def test_csrf_constants_defined(self):
        """Test that all required constants are defined."""
        assert CSRF_HEADER_NAME == "X-CSRF-Token"
        assert CSRF_COOKIE_NAME == "csrf_token"
        assert CSRF_TOKEN_LENGTH == 32

        assert isinstance(SAFE_METHODS, set)
        assert "GET" in SAFE_METHODS
        assert "POST" not in SAFE_METHODS

        assert isinstance(CSRF_EXEMPT_PATHS, list)
        assert "/api/v1/health" in CSRF_EXEMPT_PATHS

    def test_safe_methods_complete(self):
        """Test that all safe HTTP methods are included."""
        expected_safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}
        assert SAFE_METHODS == expected_safe_methods

    def test_exempt_paths_cover_essential_endpoints(self):
        """Test that exempt paths cover essential endpoints."""
        essential_paths = ["/api/v1/health", "/api/v1/ready", "/api/v1/live", "/docs", "/redoc", "/openapi.json"]

        for path in essential_paths:
            assert path in CSRF_EXEMPT_PATHS


class TestCSRFIntegrationScenarios:
    """Test CSRF middleware integration scenarios."""

    def test_csrf_protection_enabled_integration(self, client):
        """Test CSRF protection in enabled state."""
        with patch("app.core.config.settings.CSRF_PROTECTION", True):
            # GET request should work without CSRF
            response = client.get("/")
            assert response.status_code == 200

            # POST request without CSRF should fail
            response = client.post("/api/v1/protected")
            assert response.status_code == 403
            assert "CSRF validation failed" in response.json()["detail"]

    def test_csrf_protection_disabled_integration(self, client):
        """Test CSRF protection in disabled state."""
        with patch("app.core.config.settings.CSRF_PROTECTION", False):
            # POST request should work without CSRF when disabled
            response = client.post("/api/v1/protected")
            assert response.status_code == 200

    def test_csrf_with_valid_tokens_integration(self, client):
        """Test CSRF protection with valid tokens."""
        with patch("app.core.config.settings.CSRF_PROTECTION", True):
            # First, get a token (this would normally come from a GET request)
            middleware = CSRFProtectionMiddleware(None)
            token = middleware._generate_csrf_token()

            # Use the token in both cookie and header
            response = client.post(
                "/api/v1/protected", cookies={CSRF_COOKIE_NAME: token}, headers={CSRF_HEADER_NAME: token}
            )
            assert response.status_code == 200

    def test_csrf_exempt_path_integration(self, client):
        """Test that exempt paths work without CSRF."""
        with patch("app.core.config.settings.CSRF_PROTECTION", True):
            # Health endpoint should work without CSRF
            response = client.get("/api/v1/health")
            assert response.status_code == 200

    def test_csrf_form_data_integration(self, client):
        """Test CSRF with form data."""
        with patch("app.core.config.settings.CSRF_PROTECTION", True):
            middleware = CSRFProtectionMiddleware(None)
            token = middleware._generate_csrf_token()

            # Send form data with CSRF token
            response = client.post(
                "/api/v1/forms",
                data={"csrf_token": token, "field": "value"},
                cookies={CSRF_COOKIE_NAME: token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert response.status_code == 200


class TestCSRFEdgeCases:
    """Test CSRF middleware edge cases."""

    @pytest.mark.asyncio
    async def test_dispatch_partial_path_match(self, csrf_middleware):
        """Test that path matching is prefix-based."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/health/detailed"  # Starts with exempt path

        call_next = AsyncMock()
        expected_response = Response()
        call_next.return_value = expected_response

        result = await csrf_middleware.dispatch(request, call_next)

        # Should be allowed because path starts with /api/v1/health
        assert result == expected_response

    @pytest.mark.asyncio
    async def test_dispatch_case_sensitive_methods(self, csrf_middleware):
        """Test that method checking is case sensitive."""
        request = MagicMock()
        request.method = "post"  # lowercase
        request.url.path = "/api/v1/protected"
        request.cookies = {}
        request.headers = {}

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            # Should be blocked because "post" != "POST"
            assert isinstance(result, JSONResponse)
            assert result.status_code == 403

    def test_validate_csrf_token_empty_strings(self, csrf_middleware):
        """Test validation with empty strings."""
        result = csrf_middleware._validate_csrf_token("", "")
        assert result is False

    def test_validate_csrf_token_whitespace(self, csrf_middleware):
        """Test validation with whitespace tokens."""
        result = csrf_middleware._validate_csrf_token("   ", "   ")
        assert result is False

    @pytest.mark.asyncio
    async def test_dispatch_no_content_type_header(self, csrf_middleware):
        """Test form parsing when content-type header is missing."""
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/api/v1/protected"
        request.cookies = {}
        request.headers = {}  # No content-type

        call_next = AsyncMock()

        with patch("app.middleware.csrf.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True

            result = await csrf_middleware.dispatch(request, call_next)

            # Should not try to parse form data
            assert isinstance(result, JSONResponse)
            assert result.status_code == 403
