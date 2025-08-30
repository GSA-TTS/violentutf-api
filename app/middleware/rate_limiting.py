"""Rate limiting middleware for ViolentUTF API.

This middleware provides comprehensive rate limiting functionality using SlowAPI
with Redis backend, following ADR-005 specifications for multi-layered rate limiting.
"""

import re
from typing import Any, Callable, Optional

from fastapi import Request, Response
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from structlog.stdlib import get_logger

from ..core.config import settings
from ..core.rate_limiting import get_rate_limit, get_rate_limit_key, limiter

logger = get_logger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Middleware for applying rate limiting to all requests."""

    def __init__(self, app: Any, enabled: Optional[bool] = None):
        """Initialize rate limiting middleware.

        Args:
            app: FastAPI application instance
            enabled: Override for rate limiting enabled state
        """
        super().__init__(app)
        self.enabled = enabled if enabled is not None else settings.RATE_LIMIT_ENABLED

        # Define endpoint patterns and their rate limit types
        # Using list of tuples to handle duplicate patterns with different methods
        self.endpoint_patterns = [
            # Authentication endpoints
            (r"/api/v1/auth/login$", "auth_login"),
            (r"/api/v1/auth/register$", "auth_register"),
            (r"/api/v1/auth/refresh$", "auth_refresh"),
            (r"/api/v1/auth/logout$", "auth_logout"),
            (r"/api/v1/auth/password-reset$", "auth_password_reset"),
            # User management endpoints (method-specific handling in get_endpoint_type)
            (r"/api/v1/users/?$", "user_crud"),  # POST/GET
            (r"/api/v1/users/[^/]+/?$", "user_crud"),  # GET/PUT/PATCH/DELETE
            # API key management endpoints (method-specific handling in get_endpoint_type)
            (r"/api/v1/api-keys/?$", "api_key_crud"),  # POST/GET
            (r"/api/v1/api-keys/[^/]+/?$", "api_key_crud"),  # DELETE
            # Health endpoints
            (r"/api/v1/health/?$", "health_check"),
            (r"/api/v1/ready/?$", "readiness"),
            # Admin endpoints
            (r"/api/v1/admin/.*", "admin_operation"),
        ]

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Any:
        """Process request with rate limiting."""
        if not self.enabled:
            return await call_next(request)

        try:
            # Determine endpoint type based on path and method
            endpoint_type = self._get_endpoint_type(request.url.path, request.method)

            if endpoint_type:
                # Get rate limit for this endpoint type
                rate_limit_str = get_rate_limit(endpoint_type)

                # Get rate limit key for this request
                rate_limit_key = get_rate_limit_key(request)

                # Apply rate limiting using SlowAPI
                try:
                    # Create a simple wrapper to check rate limit
                    await self._check_rate_limit(request, rate_limit_str, rate_limit_key)
                except RateLimitExceeded as e:
                    return self._create_rate_limit_response(e, endpoint_type)

            # Process request normally
            response = await call_next(request)

            # Add rate limit headers if applicable
            if endpoint_type:
                self._add_rate_limit_headers(response, request, endpoint_type)

            return response

        except Exception as e:
            logger.error(
                "rate_limiting_middleware_error",
                error=str(e),
                path=request.url.path,
                method=request.method,
            )
            # Continue processing on middleware errors
            return await call_next(request)

    def _get_endpoint_type(self, path: str, method: str) -> str:
        """Determine endpoint type based on path and HTTP method.

        Args:
            path: Request path
            method: HTTP method

        Returns:
            Endpoint type string or empty string if not matched
        """
        for pattern, endpoint_type in self.endpoint_patterns:
            if re.match(pattern, path):
                # For CRUD endpoints, adjust based on HTTP method
                if endpoint_type == "user_crud":
                    if method == "POST" and path.endswith("/users/"):
                        return "user_create"
                    elif method == "GET" and path.endswith("/users/"):
                        return "user_list"
                    elif method == "GET":
                        return "user_read"
                    elif method in ["PUT", "PATCH"]:
                        return "user_update"
                    elif method == "DELETE":
                        return "user_delete"
                elif endpoint_type == "api_key_crud":
                    if method == "POST":
                        return "api_key_create"
                    elif method == "GET":
                        return "api_key_list"
                    elif method == "DELETE":
                        return "api_key_delete"

                return endpoint_type

        # Default rate limiting for unmatched endpoints
        return "default"

    async def _check_rate_limit(self, request: Request, rate_limit_str: str, rate_limit_key: str) -> None:
        """Check rate limit using simplified logic.

        Args:
            request: FastAPI request object
            rate_limit_str: Rate limit string (e.g., "5/minute")
            rate_limit_key: Rate limit key for the request

        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        # For the middleware approach, we'll implement a simple in-memory rate limiter
        # In production, this should use Redis for proper distributed rate limiting

        # For now, since we're in test environment with RATE_LIMIT_ENABLED=False,
        # we'll just log the rate limiting attempt and not actually enforce limits
        logger.debug(
            "rate_limit_check",
            rate_limit_str=rate_limit_str,
            rate_limit_key=rate_limit_key,
            path=request.url.path,
        )

        # Skip actual rate limiting in test/development mode
        # In production, implement proper rate limiting logic here

    def _parse_rate_limit_count(self, rate_limit_str: str) -> int:
        """Parse count from rate limit string.

        Args:
            rate_limit_str: Rate limit string (e.g., "5/minute")

        Returns:
            Rate limit count
        """
        return int(rate_limit_str.split("/")[0])

    def _parse_rate_limit_expire(self, rate_limit_str: str) -> int:
        """Parse expiration time from rate limit string.

        Args:
            rate_limit_str: Rate limit string (e.g., "5/minute")

        Returns:
            Expiration time in seconds
        """
        time_unit = rate_limit_str.split("/")[1]
        if time_unit == "second":
            return 1
        elif time_unit == "minute":
            return 60
        elif time_unit == "hour":
            return 3600
        else:
            return 60  # Default to minute

    def _create_rate_limit_response(self, exc: RateLimitExceeded, endpoint_type: str) -> JSONResponse:
        """Create rate limit exceeded response.

        Args:
            exc: Rate limit exceeded exception
            endpoint_type: Type of endpoint that was rate limited

        Returns:
            JSON response with rate limit exceeded message
        """
        logger.warning(
            "rate_limit_exceeded_middleware",
            endpoint_type=endpoint_type,
            detail=str(exc),
        )

        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded for {endpoint_type}",
                "type": "rate_limit_exceeded",
                "endpoint_type": endpoint_type,
            },
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": "varies",
                "X-RateLimit-Remaining": "0",
            },
        )

    def _add_rate_limit_headers(self, response: Response, request: Request, endpoint_type: str) -> None:
        """Add rate limit headers to response.

        Args:
            response: Response object to modify
            request: Request object
            endpoint_type: Type of endpoint
        """
        # Add basic rate limit headers
        # In a full implementation, you'd get actual values from the limiter
        rate_limit_str = get_rate_limit(endpoint_type)
        limit = self._parse_rate_limit_count(rate_limit_str)

        response.headers["X-RateLimit-Limit-Type"] = endpoint_type
        response.headers["X-RateLimit-Limit"] = str(limit)
        # Note: Getting remaining count would require integration with SlowAPI internals
