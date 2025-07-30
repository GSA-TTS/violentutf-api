"""JWT authentication middleware for ViolentUTF API."""

from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..core.config import settings
from ..core.security import decode_token

logger = get_logger(__name__)

# Protected paths that require authentication
PROTECTED_PATHS: List[str] = [
    "/api/v1/users",
    "/api/v1/api-keys",
    "/api/v1/sessions",
    "/api/v1/audit-logs",
    "/api/v1/llm-configs",
    "/api/v1/prompt-injections",
    "/api/v1/jailbreaks",
    "/api/v1/test-state",  # Test endpoint for middleware testing
]

# Paths that don't require authentication
EXEMPT_PATHS: List[str] = [
    "/",  # Root endpoint
    "/api/v1/auth",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/live",
    "/api/v1/public",  # Test path for middleware testing
    "/docs",
    "/redoc",
    "/openapi.json",
    "/metrics",
]

# HTTP methods that require authentication for protected resources
PROTECTED_METHODS: Set[str] = {"POST", "PUT", "PATCH", "DELETE"}


class JWTAuthenticationMiddleware(BaseHTTPMiddleware):
    """JWT Authentication middleware that validates Bearer tokens."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize JWT authentication middleware."""
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Process request with JWT authentication.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response or 401 if authentication fails
        """
        # Skip authentication for exempt paths
        if self._is_path_exempt(request.url.path):
            return await call_next(request)

        # All non-exempt paths require authentication by default
        # This is more secure than requiring explicit protection

        # Extract and validate JWT token
        token = self._extract_bearer_token(request)
        if not token:
            logger.warning(
                "missing_auth_token",
                method=request.method,
                path=request.url.path,
            )
            return self._unauthorized_response("Missing authentication token")

        # Validate JWT token
        try:
            payload = decode_token(token)

            # Validate token type
            if payload.get("type") != "access":
                logger.warning(
                    "invalid_token_type",
                    token_type=payload.get("type"),
                    expected="access",
                )
                return self._unauthorized_response("Invalid token type")

            # Add user info to request state
            request.state.user_id = payload.get("sub")
            request.state.token_payload = payload

            # For testing or when user lookup is not needed, create a minimal user object
            # In production, this should fetch the actual user from database
            from types import SimpleNamespace

            user_roles = payload.get("roles", ["viewer"])
            # Handle cases where roles might not be a list
            if not isinstance(user_roles, list):
                user_roles = ["viewer"]  # Default fallback for invalid role types

            request.state.user = SimpleNamespace(
                id=payload.get("sub"), is_superuser="admin" in user_roles, roles=user_roles
            )

            logger.debug(
                "auth_success",
                user_id=payload.get("sub"),
                path=request.url.path,
            )

        except ValueError as e:
            logger.warning(
                "auth_token_invalid",
                error=str(e),
                path=request.url.path,
            )
            return self._unauthorized_response("Invalid authentication token")
        except Exception as e:
            logger.error(
                "auth_error",
                error=str(e),
                path=request.url.path,
            )
            return self._unauthorized_response("Authentication error")

        # Continue to next middleware/handler
        return await call_next(request)

    def _is_path_exempt(self, path: str) -> bool:
        """Check if path is exempt from authentication.

        Args:
            path: Request path

        Returns:
            True if exempt, False otherwise
        """
        for exempt_path in EXEMPT_PATHS:
            # Exact match or prefix followed by slash or query parameters
            if path == exempt_path or path.startswith(exempt_path + "/") or path.startswith(exempt_path + "?"):
                return True
        return False

    def _requires_authentication(self, path: str, method: str) -> bool:
        """Check if path and method combination requires authentication.

        Args:
            path: Request path
            method: HTTP method

        Returns:
            True if authentication required, False otherwise
        """
        # Check if path is protected
        for protected_path in PROTECTED_PATHS:
            if path.startswith(protected_path):
                # For protected paths, always require auth for write operations
                if method in PROTECTED_METHODS:
                    return True
                # For GET requests, require auth for most protected resources
                # (some endpoints might be public, but default to protected)
                return True

        return False

    def _extract_bearer_token(self, request: Request) -> Optional[str]:
        """Extract Bearer token from Authorization header.

        Args:
            request: Request object

        Returns:
            JWT token if found, None otherwise
        """
        authorization = request.headers.get("Authorization")
        if not authorization:
            return None

        try:
            scheme, token = authorization.split(" ", 1)
            if scheme != "Bearer":
                return None
            # Return None if token is empty or just whitespace
            if not token.strip():
                return None
            return token
        except ValueError:
            return None

    def _unauthorized_response(self, detail: str) -> JSONResponse:
        """Create standardized unauthorized response.

        Args:
            detail: Error detail message

        Returns:
            JSON response with 401 status
        """
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "detail": detail,
                "type": "authentication_error",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user_id(request: Request) -> Optional[str]:
    """Get current authenticated user ID from request state.

    Args:
        request: Current request

    Returns:
        User ID if authenticated, None otherwise
    """
    return getattr(request.state, "user_id", None)


def get_current_token_payload(request: Request) -> Optional[Dict[str, Any]]:
    """Get current JWT token payload from request state.

    Args:
        request: Current request

    Returns:
        Token payload if authenticated, None otherwise
    """
    return getattr(request.state, "token_payload", None)


def require_auth(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate a route to require authentication.

    Args:
        func: Route function to protect

    Returns:
        Decorated function
    """
    func._requires_auth = True  # type: ignore
    return func
