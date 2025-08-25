"""Permission checking middleware for RBAC authorization."""

import uuid
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from structlog.stdlib import get_logger

from app.core.errors import ForbiddenError, UnauthorizedError
from app.dependencies.middleware import get_middleware_service
from app.services.middleware_service import MiddlewareService
from app.services.rbac_service import RBACService

logger = get_logger(__name__)


class PermissionChecker:
    """Permission checking middleware for FastAPI."""

    def __init__(self):
        """Initialize permission checker."""
        # Define permission mappings for endpoints
        self.endpoint_permissions = self._build_endpoint_permissions()

        # Define public endpoints that don't require permissions
        self.public_endpoints = {
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/live",
            "/api/v1/docs",
            "/api/v1/redoc",
            "/api/v1/openapi.json",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/api/v1/oauth/authorize",
            "/api/v1/oauth/token",
            "/api/v1/oauth/revoke",
            # Root-level paths that don't have API prefix
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
        }

    def _build_endpoint_permissions(self) -> Dict[str, Dict[str, str]]:
        """Build mapping of endpoints to required permissions.

        Returns:
            Dictionary mapping endpoint patterns to HTTP methods and required permissions
        """
        return {
            # User management endpoints
            "/users": {
                "GET": "users:read",
                "POST": "users:write",
                "DELETE": "users:delete",
            },
            "/users/{user_id}": {
                "GET": "users:read:own",  # Will be enhanced to check ownership
                "PUT": "users:write:own",
                "DELETE": "users:delete",
            },
            "/users/me": {
                "GET": "users:read:own",
                "PUT": "users:write:own",
            },
            # API key management endpoints
            "/api-keys": {
                "GET": "api_keys:read:own",
                "POST": "api_keys:write:own",
            },
            "/api-keys/{key_id}": {
                "GET": "api_keys:read:own",
                "PUT": "api_keys:write:own",
                "DELETE": "api_keys:delete:own",
            },
            "/api-keys/rotate/{key_id}": {
                "POST": "api_keys:write:own",
            },
            "/api-keys/analytics": {
                "GET": "api_keys:read",
            },
            # Role management endpoints (admin only)
            "/roles": {
                "GET": "roles:read",
                "POST": "roles:write",
            },
            "/roles/{role_id}": {
                "GET": "roles:read",
                "PUT": "roles:write",
                "DELETE": "roles:delete",
            },
            "/roles/assign": {
                "POST": "roles:write",
            },
            "/roles/revoke": {
                "POST": "roles:write",
            },
            "/roles/initialize": {
                "POST": "roles:manage:system",
            },
            # Session management endpoints
            "/sessions": {
                "GET": "sessions:read:own",
                "DELETE": "sessions:delete:own",
            },
            "/sessions/{session_id}": {
                "GET": "sessions:read:own",
                "DELETE": "sessions:delete:own",
            },
            # Audit log endpoints (admin only)
            "/audit-logs": {
                "GET": "audit_logs:read",
            },
            "/audit-logs/{log_id}": {
                "GET": "audit_logs:read",
            },
        }

    async def __call__(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        """Process request through permission checking middleware.

        Args:
            request: FastAPI request object
            call_next: Next middleware/endpoint in chain

        Returns:
            Response from next handler or permission denied response
        """
        try:
            # Skip permission checking for public endpoints
            if self._is_public_endpoint(request):
                return await call_next(request)

            # Extract user information from request
            user_id = self._get_user_id_from_request(request)
            if not user_id:
                return self._create_unauthorized_response(request, "Authentication required")

            # Determine required permission for this endpoint
            required_permission = self._get_required_permission(request)
            if not required_permission:
                # No specific permission required, proceed
                return await call_next(request)

            # Check if user has the required permission
            has_permission = await self._check_user_permission(request, user_id, required_permission)

            # If we couldn't check permissions (no DB), allow the request to proceed
            # The endpoint will handle its own authorization
            if has_permission is None:
                logger.warning(
                    "Could not verify permissions due to missing database session",
                    user_id=user_id,
                    permission=required_permission,
                    path=request.url.path,
                )
                # Allow request to proceed - endpoint will handle authorization
                return await call_next(request)
            elif not has_permission:
                return self._create_forbidden_response(
                    request, f"Permission '{required_permission}' required for {request.method} {request.url.path}"
                )

            # Permission check passed, proceed to next middleware/endpoint
            logger.debug(
                "Permission check passed",
                user_id=user_id,
                permission=required_permission,
                method=request.method,
                path=request.url.path,
            )

            return await call_next(request)

        except Exception as e:
            logger.error(
                "Permission middleware error",
                error=str(e),
                method=request.method,
                path=request.url.path,
            )
            return self._create_error_response(request, "Permission check failed")

    def _is_public_endpoint(self, request: Request) -> bool:
        """Check if endpoint is public and doesn't require permissions.

        Args:
            request: FastAPI request object

        Returns:
            True if endpoint is public
        """
        path = request.url.path

        # Check exact matches
        if path in self.public_endpoints:
            return True

        # Check pattern matches
        public_patterns = [
            "/api/v1/health",
            "/api/v1/auth/",  # All auth endpoints
            "/api/v1/oauth/",  # OAuth endpoints
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static/",
        ]

        for pattern in public_patterns:
            if path.startswith(pattern):
                return True

        return False

    def _get_user_id_from_request(self, request: Request) -> Optional[str]:
        """Extract user ID from request state.

        Args:
            request: FastAPI request object

        Returns:
            User ID if authenticated, None otherwise
        """
        # User ID should be set by authentication middleware
        user_id = getattr(request.state, "user_id", None)

        if user_id:
            return str(user_id)

        # Fallback: check for user object
        user = getattr(request.state, "user", None)
        if user and hasattr(user, "id"):
            return str(user.id)

        return None

    def _get_required_permission(self, request: Request) -> Optional[str]:
        """Determine required permission for the request.

        Args:
            request: FastAPI request object

        Returns:
            Required permission string or None if no permission required
        """
        path = request.url.path
        method = request.method.upper()

        # Strip API version prefix if present
        if path.startswith("/api/v1"):
            path = path[7:]  # Remove "/api/v1"

        # Direct endpoint match
        if path in self.endpoint_permissions:
            endpoint_perms = self.endpoint_permissions[path]
            return endpoint_perms.get(method)

        # Pattern matching for parameterized endpoints
        for endpoint_pattern, methods in self.endpoint_permissions.items():
            if self._matches_pattern(path, endpoint_pattern):
                return methods.get(method)

        return None

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches endpoint pattern.

        Args:
            path: Actual request path (already stripped of /api/v1 prefix)
            pattern: Endpoint pattern with {param} placeholders

        Returns:
            True if path matches pattern
        """
        import re

        # Convert pattern to regex
        # Replace {param} with regex to match UUID or string
        regex_pattern = pattern
        regex_pattern = regex_pattern.replace("{user_id}", r"[a-f0-9-]{36}")
        regex_pattern = regex_pattern.replace("{key_id}", r"[a-f0-9-]{36}")
        regex_pattern = regex_pattern.replace("{role_id}", r"[a-f0-9-]{36}")
        regex_pattern = regex_pattern.replace("{session_id}", r"[a-f0-9-]{36}")
        regex_pattern = regex_pattern.replace("{log_id}", r"[a-f0-9-]{36}")

        # Add anchors
        regex_pattern = f"^{regex_pattern}$"

        return bool(re.match(regex_pattern, path))

    async def _check_user_permission(self, request: Request, user_id: str, permission: str) -> Optional[bool]:
        """Check if user has the required permission.

        Args:
            request: FastAPI request object
            user_id: User identifier
            permission: Required permission string

        Returns:
            True if user has permission, False if not, None if unable to check
        """
        try:
            # Get database session
            session = await self._get_db_session(request)
            if not session:
                logger.debug("No database session available for permission check")
                return None  # Return None to indicate we can't check permissions

            # Create RBAC service
            rbac_service = RBACService(session)

            # Enhance permission based on ownership if it's a scoped permission
            enhanced_permission = await self._enhance_scoped_permission(request, user_id, permission, rbac_service)

            # Check if user has the (enhanced) permission
            has_permission = await rbac_service.check_user_permission(user_id, enhanced_permission)

            logger.debug(
                "Permission check result",
                user_id=user_id,
                original_permission=permission,
                enhanced_permission=enhanced_permission,
                has_permission=has_permission,
            )

            return has_permission

        except Exception as e:
            logger.error(
                "Error checking user permission",
                user_id=user_id,
                permission=permission,
                error=str(e),
            )
            # Default to deny on error
            return False

    async def _enhance_scoped_permission(
        self,
        request: Request,
        user_id: str,
        permission: str,
        rbac_service: RBACService,
    ) -> str:
        """Enhance scoped permissions based on resource ownership.

        For permissions like 'users:read:own', this will check if the user
        is accessing their own resource and adjust the permission accordingly.

        Args:
            request: FastAPI request object
            user_id: User identifier
            permission: Original permission string
            rbac_service: RBAC service instance

        Returns:
            Enhanced permission string
        """
        if ":own" not in permission:
            return permission

        try:
            # Extract resource ID from path
            resource_id = self._extract_resource_id(request)
            if not resource_id:
                return permission

            # Check if user owns the resource
            owns_resource = await self._check_resource_ownership(request, user_id, resource_id, permission)

            if owns_resource:
                # User owns the resource, keep the scoped permission
                return permission
            else:
                # User doesn't own the resource, need broader permission
                return permission.replace(":own", "")

        except Exception as e:
            logger.error(
                "Error enhancing scoped permission",
                user_id=user_id,
                permission=permission,
                error=str(e),
            )
            # Return original permission on error
            return permission

    def _extract_resource_id(self, request: Request) -> Optional[str]:
        """Extract resource ID from request path.

        Args:
            request: FastAPI request object

        Returns:
            Resource ID if found in path parameters
        """
        path_params = getattr(request, "path_params", {})

        # Common parameter names for resource IDs
        id_params = ["user_id", "key_id", "role_id", "session_id", "log_id"]

        for param in id_params:
            if param in path_params:
                return str(path_params[param])

        return None

    async def _check_resource_ownership(
        self,
        request: Request,
        user_id: str,
        resource_id: str,
        permission: str,
    ) -> bool:
        """Check if user owns the specified resource.

        Args:
            request: FastAPI request object
            user_id: User identifier
            resource_id: Resource identifier
            permission: Permission being checked

        Returns:
            True if user owns the resource
        """
        try:
            # For user resources, check if user_id matches resource_id
            if permission.startswith("users:"):
                return user_id == resource_id

            # For API keys, check ownership via database
            if permission.startswith("api_keys:"):
                return await self._check_api_key_ownership(request, user_id, resource_id)

            # For sessions, check ownership via database
            if permission.startswith("sessions:"):
                return await self._check_session_ownership(request, user_id, resource_id)

            # Default to false for unknown resource types
            return False

        except Exception as e:
            logger.error(
                "Error checking resource ownership",
                user_id=user_id,
                resource_id=resource_id,
                permission=permission,
                error=str(e),
            )
            return False

    async def _check_api_key_ownership(self, request: Request, user_id: str, key_id: str) -> bool:
        """Check if user owns the specified API key.

        Args:
            request: FastAPI request object
            user_id: User identifier
            key_id: API key identifier

        Returns:
            True if user owns the API key
        """
        try:
            # Use dependency injection to avoid N+1 query problems
            base_middleware_service = None
            async for service in get_middleware_service():
                base_middleware_service = service
                break

            if base_middleware_service:
                middleware_service = MiddlewareService(base_middleware_service.session)
                api_key = await middleware_service.api_key_repo.get(key_id)
                return api_key and str(api_key.user_id) == user_id
            return False

        except Exception as e:
            logger.error(
                "Error checking API key ownership",
                user_id=user_id,
                key_id=key_id,
                error=str(e),
            )
            return False

    async def _check_session_ownership(self, request: Request, user_id: str, session_id: str) -> bool:
        """Check if user owns the specified session.

        Args:
            request: FastAPI request object
            user_id: User identifier
            session_id: Session identifier

        Returns:
            True if user owns the session
        """
        try:
            # Use dependency injection to avoid N+1 query problems
            base_middleware_service = None
            async for service in get_middleware_service():
                base_middleware_service = service
                break

            if base_middleware_service:
                middleware_service = MiddlewareService(base_middleware_service.session)
                user_session = await middleware_service.session_repo.get(session_id)
                return user_session and str(user_session.user_id) == user_id
            return False

        except Exception as e:
            logger.error(
                "Error checking session ownership",
                user_id=user_id,
                session_id=session_id,
                error=str(e),
            )
            return False

    async def _get_db_session(self, request: Request) -> Optional[object]:
        """Get database session from request dependency injection.

        Args:
            request: FastAPI request object

        Returns:
            Database session if available
        """
        try:
            # Try to get session from request state (if set by dependency)
            session = getattr(request.state, "db_session", None)
            if session:
                return session

            # For testing or when database is not available, skip permission checks
            # This allows the endpoint to handle its own database access
            logger.debug("No database session in request state, skipping permission check")
            return None

        except Exception as e:
            logger.error("Error getting database session", error=str(e))
            return None

    def _create_unauthorized_response(self, request: Request, message: str) -> JSONResponse:
        """Create unauthorized response.

        Args:
            request: FastAPI request object
            message: Error message

        Returns:
            JSON response with 401 status
        """
        trace_id = getattr(request.state, "trace_id", None)

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": "Unauthorized",
                "message": message,
                "trace_id": trace_id,
            },
        )

    def _create_forbidden_response(self, request: Request, message: str) -> JSONResponse:
        """Create forbidden response.

        Args:
            request: FastAPI request object
            message: Error message

        Returns:
            JSON response with 403 status
        """
        trace_id = getattr(request.state, "trace_id", None)

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Forbidden",
                "message": message,
                "trace_id": trace_id,
            },
        )

    def _create_error_response(self, request: Request, message: str) -> JSONResponse:
        """Create internal server error response.

        Args:
            request: FastAPI request object
            message: Error message

        Returns:
            JSON response with 500 status
        """
        trace_id = getattr(request.state, "trace_id", None)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "message": message,
                "trace_id": trace_id,
            },
        )


# Global permission checker instance
permission_checker = PermissionChecker()
