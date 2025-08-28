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
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add comprehensive security headers to all responses."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize security headers middleware with explicit configuration."""
        super().__init__(app)

        # Configure HSTS (HTTP Strict Transport Security)
        hsts = StrictTransportSecurity()
        hsts = hsts.max_age(settings.HSTS_MAX_AGE)
        hsts = hsts.include_subdomains()
        if settings.is_production:
            hsts = hsts.preload()

        # Configure CSP (Content Security Policy)
        csp = ContentSecurityPolicy()
        if settings.CSP_POLICY:
            # Parse CSP policy string into directives
            # For now, use a secure default with explicit directives
            csp = csp.default_src("'self'")
            if settings.is_production:
                csp = csp.script_src("'self'", "'strict-dynamic'")
            else:
                csp = csp.script_src("'self'", "'unsafe-inline'")
            csp = csp.style_src("'self'", "'unsafe-inline'")  # Allow inline styles for error pages
            csp = csp.img_src("'self'", "data:", "https:")
            csp = csp.font_src("'self'")
            csp = csp.connect_src("'self'")
            csp = csp.frame_ancestors("'none'")
            csp = csp.base_uri("'self'")
            csp = csp.form_action("'self'")

        # Configure X-Frame-Options
        x_frame = XFrameOptions()
        x_frame = x_frame.deny()  # Most restrictive option

        # Configure Referrer Policy
        referrer = ReferrerPolicy()
        referrer = referrer.strict_origin_when_cross_origin()

        # Configure Permissions Policy (Feature Policy)
        permissions = PermissionsPolicy()
        permissions = permissions.geolocation("'none'")
        permissions = permissions.camera("'none'")
        permissions = permissions.microphone("'none'")

        # Initialize Secure with all explicit configurations
        self.secure = Secure(
            hsts=hsts,
            csp=csp,
            xfo=x_frame,
            referrer=referrer,
            permissions=permissions,
        )

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Add security headers to response."""
        response = await call_next(request)

        # Apply secure headers
        secure_headers = self.secure.headers

        # Handle case where headers might be a function instead of dict
        if callable(secure_headers):
            try:
                secure_headers = secure_headers()
            except Exception:
                secure_headers = {}

        # Ensure we have a dict-like object
        if hasattr(secure_headers, "items") and not callable(secure_headers):
            for header_name, header_value in secure_headers.items():
                response.headers[header_name] = header_value

        # Additional security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Remove sensitive headers
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]

        # Add custom security headers
        # Use request ID from state, header, or generate new one
        request_id = getattr(request.state, "request_id", None)
        if not request_id:
            # Check if client provided a request ID
            request_id = request.headers.get("X-Request-ID")
            if not request_id:
                import uuid

                request_id = str(uuid.uuid4())
            request.state.request_id = request_id
        response.headers["X-Request-ID"] = request_id

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
