"""JWT authentication middleware for ViolentUTF API.

This middleware has been enhanced to support the new ABAC (Attribute-Based Access Control)
system that addresses critical security issues identified in the authentication audit report.
"""

from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..core.authority import AuthorityLevel, evaluate_user_authority
from ..core.config import get_settings
from ..core.security import decode_token
from ..db.session import get_db
from ..repositories.api_key import APIKeyRepository
from ..repositories.user import UserRepository
from ..services.api_key_service import APIKeyService

logger = get_logger(__name__)

# Protected paths that require authentication
PROTECTED_PATHS: List[str] = [
    "/api/v1/users",
    "/api/v1/api-keys",
    "/api/v1/sessions",
    "/api/v1/audit-logs",
    "/api/v1/oauth/applications",
    "/api/v1/oauth/authorizations",
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
    "/api/v1/oauth/authorize",  # OAuth authorization page (handled by endpoint)
    "/api/v1/oauth/token",  # OAuth token endpoint (public)
    "/api/v1/oauth/revoke",  # OAuth revoke endpoint (public with client auth)
    "/docs",
    "/redoc",
    "/openapi.json",
    "/metrics",
]

# HTTP methods that require authentication for protected resources
PROTECTED_METHODS: Set[str] = {"POST", "PUT", "PATCH", "DELETE"}


class JWTAuthenticationMiddleware(BaseHTTPMiddleware):
    """JWT Authentication middleware that validates Bearer tokens.

    This middleware has been enhanced with ABAC (Attribute-Based Access Control)
    context establishment to support the new authorization system that addresses
    critical security vulnerabilities identified in the authentication audit.
    """

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

        # Debug log
        logger.info(
            "jwt_auth_checking_path",
            path=request.url.path,
            method=request.method,
            has_auth_header="authorization" in request.headers,
        )

        # All non-exempt paths require authentication by default
        # This is more secure than requiring explicit protection

        # Try JWT authentication first
        token = self._extract_bearer_token(request)
        if token:
            return await self._authenticate_jwt(request, call_next, token)

        # Try API key authentication
        api_key = self._extract_api_key(request)
        if api_key:
            return await self._authenticate_api_key(request, call_next, api_key)

        # No authentication provided
        logger.warning(
            "missing_auth_token",
            method=request.method,
            path=request.url.path,
            headers=list(request.headers.keys()),
            auth_header=request.headers.get("authorization"),
            api_key_header=request.headers.get("x-api-key"),
        )
        return self._unauthorized_response("Missing authentication token or API key")

    async def _authenticate_jwt(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]], token: str
    ) -> Response:
        """Authenticate using JWT token."""
        try:
            logger.debug(
                "validating_token",
                token_prefix=token[:20] if token else None,
                path=request.url.path,
            )
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
            request.state.organization_id = payload.get(
                "organization_id"
            )  # CRITICAL: Extract organization_id for multi-tenant isolation
            request.state.token_payload = payload

            # Enhanced user context with authority-based system
            user_roles = payload.get("roles", ["viewer"])
            # Handle cases where roles might not be a list
            if not isinstance(user_roles, list):
                user_roles = ["viewer"]  # Default fallback for invalid role types

            # DEPRECATED: Still set is_superuser for backward compatibility but log warning
            has_deprecated_superuser = "admin" in user_roles
            if has_deprecated_superuser:
                logger.warning(
                    "DEPRECATED: Boolean superuser flag detected in JWT - migrate to authority levels",
                    user_id=payload.get("sub"),
                    roles=user_roles,
                    migration_needed=True,
                )

            from types import SimpleNamespace

            request.state.user = SimpleNamespace(
                id=payload.get("sub"),
                is_superuser=has_deprecated_superuser,  # DEPRECATED - for backward compatibility
                roles=user_roles,
                username=payload.get("username"),
                email=payload.get("email"),
            )

            # Set ABAC context for enhanced permission evaluation
            try:
                # Try to get database session for authority evaluation
                async for db_session in get_db():
                    request.state.db_session = db_session

                    # Load full user model for authority evaluation
                    user_repo = UserRepository(db_session)
                    full_user = await user_repo.get_by_id(payload.get("sub"), payload.get("organization_id"))

                    if full_user:
                        # Calculate authority level using new system
                        authority_level = await evaluate_user_authority(full_user, db_session)
                        request.state.authority_level = authority_level
                        request.state.full_user = full_user

                        logger.debug(
                            "ABAC context established",
                            user_id=payload.get("sub"),
                            authority_level=authority_level.level_name,
                            organization_id=payload.get("organization_id"),
                        )
                    break
            except Exception as e:
                logger.warning(
                    "Failed to establish ABAC context - using legacy authentication",
                    user_id=payload.get("sub"),
                    error=str(e),
                )
                # Continue with basic authentication context

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
                token_prefix=token[:20] if token else None,
            )
            return self._unauthorized_response("Invalid authentication token")
        except Exception as e:
            logger.error(
                "auth_error",
                error=str(e),
                error_type=type(e).__name__,
                path=request.url.path,
                token_prefix=token[:20] if token else None,
            )
            return self._unauthorized_response("Authentication error")

        # Continue to next middleware/handler
        return await call_next(request)

    async def _authenticate_api_key(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]], api_key: str
    ) -> Response:
        """Authenticate using API key."""
        try:
            logger.debug(
                "validating_api_key",
                key_prefix=api_key[:10] if api_key else None,
                path=request.url.path,
            )

            # Get database session - respect test overrides if present
            session = None

            try:
                # Check if get_db has been overridden during testing
                if hasattr(request, "app") and hasattr(request.app, "dependency_overrides"):
                    db_override = request.app.dependency_overrides.get(get_db)
                    if db_override:
                        # Use overridden database (test database) - async generator
                        async for session in db_override():
                            request.state.db_session = session
                            break
                    else:
                        # No override, use regular get_db
                        async for session in get_db():
                            request.state.db_session = session
                            break
                else:
                    # Fallback for when app is not accessible
                    async for session in get_db():
                        request.state.db_session = session
                        break

                # Validate API key
                api_key_repo = APIKeyRepository(session)
                api_key_service = APIKeyService(session)

                # Find API key by prefix (first part of the key)
                api_key_prefix = api_key[:10] if len(api_key) >= 10 else api_key
                api_key_models = await api_key_repo.get_by_prefix(api_key_prefix)

                authenticated_user = None
                for api_key_model in api_key_models:
                    # Verify the full API key hash
                    if await api_key_service._verify_key_hash(api_key, api_key_model.key_hash):
                        # Check if API key is active and not expired
                        if (
                            api_key_model.expires_at
                            and api_key_model.expires_at.replace(tzinfo=None) < datetime.utcnow()
                        ):
                            logger.warning(
                                "api_key_expired",
                                key_id=str(api_key_model.id),
                                expires_at=api_key_model.expires_at,
                            )
                            continue

                        # Load user
                        user_repo = UserRepository(session)
                        user = await user_repo.get_by_id(str(api_key_model.user_id))

                        if user and user.is_verified:
                            authenticated_user = user
                            # Record API key usage
                            api_key_model.record_usage()
                            if session:
                                await session.commit()  # Commit the usage update
                            break

                if not authenticated_user:
                    logger.warning(
                        "api_key_invalid",
                        key_prefix=api_key_prefix,
                        path=request.url.path,
                    )
                    return self._unauthorized_response("Invalid API key")

                # Set user context similar to JWT authentication
                request.state.user_id = str(authenticated_user.id)
                request.state.organization_id = None  # API keys don't have organization context by default

                from types import SimpleNamespace

                request.state.user = SimpleNamespace(
                    id=str(authenticated_user.id),
                    is_superuser=authenticated_user.is_superuser,
                    roles=["user"],  # API keys have basic user role
                    username=authenticated_user.username,
                    email=authenticated_user.email,
                )

                # Set ABAC context
                try:
                    authority_level = await evaluate_user_authority(authenticated_user, session)
                    request.state.authority_level = authority_level
                    request.state.full_user = authenticated_user

                    logger.debug(
                        "api_key_auth_success",
                        user_id=str(authenticated_user.id),
                        authority_level=authority_level.level_name,
                        path=request.url.path,
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to establish ABAC context for API key",
                        user_id=str(authenticated_user.id),
                        error=str(e),
                    )

            finally:
                # Database session cleanup is handled by the async generator
                pass

        except Exception as e:
            logger.error(
                "api_key_auth_error",
                error=str(e),
                error_type=type(e).__name__,
                path=request.url.path,
                key_prefix=api_key[:10] if api_key else None,
            )
            return self._unauthorized_response("API key authentication error")

        # Continue to next middleware/handler
        return await call_next(request)

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from X-API-Key header."""
        return request.headers.get("X-API-Key")

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


def get_current_organization_id(request: Request) -> Optional[str]:
    """Get current authenticated user's organization ID from request state.

    Args:
        request: Current request

    Returns:
        Organization ID if authenticated, None otherwise
    """
    return getattr(request.state, "organization_id", None)


def get_current_token_payload(request: Request) -> Optional[Dict[str, Any]]:
    """Get current JWT token payload from request state.

    Args:
        request: Current request

    Returns:
        Token payload if authenticated, None otherwise
    """
    return getattr(request.state, "token_payload", None)


def get_current_authority_level(request: Request) -> Optional[AuthorityLevel]:
    """Get current user's authority level from request state.

    This provides access to the new authority-based system that replaces
    the problematic boolean is_superuser flag.

    Args:
        request: Current request

    Returns:
        User's authority level if authenticated and ABAC context established
    """
    return getattr(request.state, "authority_level", None)


def get_current_full_user(request: Request) -> Any:
    """Get current full user model from request state.

    This provides access to the complete user model for ABAC evaluation.

    Args:
        request: Current request

    Returns:
        Full user model if authenticated and loaded
    """
    return getattr(request.state, "full_user", None)


def get_current_db_session(request: Request) -> Optional[AsyncSession]:
    """Get current database session from request state.

    This provides access to the database session established during authentication
    for ABAC policy evaluation.

    Args:
        request: Current request

    Returns:
        Database session if available
    """
    return getattr(request.state, "db_session", None)


def require_auth(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate a route to require authentication.

    DEPRECATED: Use ABAC permission decorators instead for enhanced security.
    This decorator only checks for basic authentication, not authorization.

    Args:
        func: Route function to protect

    Returns:
        Decorated function

    Migration Recommendation:
        Replace with specific ABAC permission decorators:
        @require_abac_permission(resource_type="resource", action="action")
    """
    func._requires_auth = True
    return func
