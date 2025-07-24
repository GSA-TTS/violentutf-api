"""Security headers middleware."""

from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from secure import Secure
from secure.headers import (
    ContentSecurityPolicy,
    PermissionsPolicy,
    ReferrerPolicy,
    StrictTransportSecurity,
    XFrameOptions,
)
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """Add comprehensive security headers to all responses."""

    def __init__(self: "SecurityHeadersMiddleware", app: FastAPI) -> None:
        """Initialize security headers middleware."""
        super().__init__(app)
        # Use default security headers for now
        self.secure = Secure()

    async def dispatch(
        self: "SecurityHeadersMiddleware", request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Add security headers to response."""
        response = await call_next(request)

        # Apply secure headers
        self.secure.framework.fastapi(response)

        # Additional security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Remove sensitive headers
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]

        # Add custom security headers
        response.headers["X-Request-ID"] = getattr(request.state, "request_id", "unknown")

        return response


def setup_security_middleware(app: FastAPI) -> None:
    """Set up all security middleware."""
    # Add trusted host middleware in production
    if settings.is_production and settings.ALLOWED_ORIGINS:
        allowed_hosts = [origin.replace("https://", "").replace("http://", "") for origin in settings.ALLOWED_ORIGINS]
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=allowed_hosts,
        )

    # Add security headers
    app.add_middleware(SecurityHeadersMiddleware)

    logger.info("Security middleware configured")
