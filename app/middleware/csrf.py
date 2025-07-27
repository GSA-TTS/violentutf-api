"""CSRF protection middleware for ViolentUTF API."""

import hmac
import secrets
from typing import Any, Awaitable, Callable, List, Optional, Set

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)

# CSRF configuration
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_TOKEN_LENGTH = 32
CSRF_SECRET_LENGTH = 32

# Safe methods that don't require CSRF protection
SAFE_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"}

# Paths to exclude from CSRF protection
CSRF_EXEMPT_PATHS: List[str] = [
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/live",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/metrics",
]


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """Middleware for CSRF protection using double-submit cookie pattern."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize CSRF middleware."""
        super().__init__(app)
        # Generate a secret for signing tokens (in production, this should be persistent)
        self.csrf_secret = settings.SECRET_KEY.get_secret_value().encode()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Process request with CSRF protection.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response or 403 if CSRF validation fails
        """
        # Skip CSRF for safe methods
        if request.method in SAFE_METHODS:
            return await call_next(request)

        # Skip CSRF for exempt paths
        if any(request.url.path.startswith(path) for path in CSRF_EXEMPT_PATHS):
            return await call_next(request)

        # Skip if CSRF protection is disabled
        if not settings.CSRF_PROTECTION:
            return await call_next(request)

        # Get CSRF token from cookie
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

        # Get CSRF token from header or form
        header_token = request.headers.get(CSRF_HEADER_NAME)

        # For forms, check form data (if content-type is form)
        form_token = None
        if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            try:
                form_data = await request.form()
                csrf_value = form_data.get("csrf_token")
                # Ensure it's a string, not an UploadFile
                form_token = csrf_value if isinstance(csrf_value, str) else None
            except Exception:
                pass

        submitted_token = header_token or form_token

        # Validate CSRF token
        if not self._validate_csrf_token(cookie_token, submitted_token):
            logger.warning(
                "csrf_validation_failed",
                method=request.method,
                path=request.url.path,
                has_cookie=bool(cookie_token),
                has_submitted=bool(submitted_token),
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF validation failed"},
            )

        # Generate new token if needed
        if not cookie_token:
            new_token = self._generate_csrf_token()
            request.state.csrf_token = new_token
            request.state.set_csrf_cookie = True
        else:
            request.state.csrf_token = cookie_token

        # Process request
        response = await call_next(request)

        # Set CSRF cookie if needed
        if hasattr(request.state, "set_csrf_cookie") and request.state.set_csrf_cookie:
            self._set_csrf_cookie(response, request.state.csrf_token)

        return response

    def _generate_csrf_token(self) -> str:
        """Generate a new CSRF token.

        Returns:
            CSRF token
        """
        # Generate random token
        token = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

        # Sign it with our secret
        signature = hmac.new(
            self.csrf_secret,
            token.encode(),
            "sha256",
        ).hexdigest()

        # Combine token and signature
        signed_token = f"{token}.{signature}"
        return signed_token

    def _validate_csrf_token(self, cookie_token: Optional[str], submitted_token: Optional[str]) -> bool:
        """Validate CSRF token using double-submit pattern.

        Args:
            cookie_token: Token from cookie
            submitted_token: Token from header/form

        Returns:
            True if valid, False otherwise
        """
        # Both must be present
        if not cookie_token or not submitted_token:
            return False

        # Must be identical (double-submit pattern)
        if cookie_token != submitted_token:
            return False

        # Validate signature
        try:
            # Check if token has the expected format
            if "." not in cookie_token:
                return False

            token_part, signature_part = cookie_token.rsplit(".", 1)
            expected_signature = hmac.new(
                self.csrf_secret,
                token_part.encode(),
                "sha256",
            ).hexdigest()

            # Constant-time comparison
            return hmac.compare_digest(signature_part, expected_signature)
        except Exception as e:
            logger.error("csrf_token_validation_error", error=str(e))
            return False

    def _set_csrf_cookie(self, response: Response, csrf_token: str) -> None:
        """Set CSRF cookie with security options.

        Args:
            response: Response to add cookie to
            csrf_token: CSRF token to set
        """
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=False,  # Must be readable by JS for inclusion in requests
            secure=settings.SECURE_COOKIES,
            samesite="strict",
            path="/",
        )
        logger.debug("csrf_cookie_set")


def get_csrf_token(request: Request) -> Optional[str]:
    """Get CSRF token for current request.

    Args:
        request: Current request

    Returns:
        CSRF token or None
    """
    return getattr(request.state, "csrf_token", None)


def exempt_from_csrf(func: Callable[..., Any]) -> Callable[..., Any]:
    """Exempt a route from CSRF protection.

    Args:
        func: Route function to exempt

    Returns:
        Decorated function
    """
    func._csrf_exempt = True  # type: ignore
    return func
