"""Audit logging middleware for tracking all API requests and responses."""

import time
import uuid
from typing import Any, Callable, Dict, Optional

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.db.session import get_db
from app.services.audit_service import AuditService

logger = get_logger(__name__)


class AuditLoggingMiddleware:
    """Middleware for comprehensive audit logging of API requests."""

    def __init__(self):
        """Initialize audit logging middleware."""
        # Endpoints that should not be logged (to avoid noise)
        self.excluded_paths = {
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
        }

        # Endpoints that require enhanced logging
        self.sensitive_paths = {
            "/auth/login",
            "/auth/logout",
            "/auth/register",
            "/users",
            "/api-keys",
            "/roles",
            "/permissions",
        }

    async def __call__(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        """Process request through audit logging middleware.

        Args:
            request: FastAPI request object
            call_next: Next middleware/endpoint in chain

        Returns:
            Response from next handler
        """
        # Skip excluded paths
        if self._should_skip_logging(request):
            return await call_next(request)

        # Record start time
        start_time = time.time()

        # Get request information
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        user_id = getattr(request.state, "user_id", None)
        user_email = None

        # Get user email if available
        user = getattr(request.state, "user", None)
        if user and hasattr(user, "email"):
            user_email = user.email

        # Store original request data (before processing)
        request_data = await self._extract_request_data(request)

        # Process the request
        response = None
        error_message = None
        status = "success"

        try:
            response = await call_next(request)

            # Check response status
            if response.status_code >= 400:
                status = "failure"
                if response.status_code >= 500:
                    status = "error"

        except Exception as e:
            status = "error"
            error_message = str(e)
            logger.error(
                "Request processing failed",
                request_id=request_id,
                path=request.url.path,
                error=error_message,
            )
            raise

        finally:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Log the audit event asynchronously (don't block response)
            try:
                await self._log_audit_event(
                    request=request,
                    response=response,
                    request_id=request_id,
                    user_id=user_id,
                    user_email=user_email,
                    request_data=request_data,
                    status=status,
                    error_message=error_message,
                    duration_ms=duration_ms,
                )
            except Exception as e:
                logger.error(
                    "Failed to log audit event",
                    request_id=request_id,
                    error=str(e),
                )

        return response

    def _should_skip_logging(self, request: Request) -> bool:
        """Check if request should be skipped from logging.

        Args:
            request: FastAPI request object

        Returns:
            True if should skip logging
        """
        path = request.url.path

        # Check exact matches
        if path in self.excluded_paths:
            return True

        # Check prefixes
        excluded_prefixes = ["/static/", "/_next/", "/api/health/"]
        for prefix in excluded_prefixes:
            if path.startswith(prefix):
                return True

        # Skip OPTIONS requests
        if request.method == "OPTIONS":
            return True

        return False

    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract request data for logging.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary with request data
        """
        try:
            data = {
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "path_params": getattr(request, "path_params", {}),
                "headers": self._sanitize_headers(dict(request.headers)),
            }

            # Try to get request body for POST/PUT/PATCH
            if request.method in ["POST", "PUT", "PATCH"]:
                # Note: Reading body here might interfere with the actual endpoint
                # In production, you might want to handle this differently
                pass

            return data

        except Exception as e:
            logger.error("Failed to extract request data", error=str(e))
            return {"method": request.method, "path": request.url.path}

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove sensitive information from headers.

        Args:
            headers: Request headers

        Returns:
            Sanitized headers
        """
        sensitive_headers = {
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
        }

        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized

    async def _log_audit_event(
        self,
        request: Request,
        response: Optional[Response],
        request_id: str,
        user_id: Optional[str],
        user_email: Optional[str],
        request_data: Dict[str, Any],
        status: str,
        error_message: Optional[str],
        duration_ms: int,
    ) -> None:
        """Log the audit event.

        Args:
            request: FastAPI request object
            response: Response object (if available)
            request_id: Request identifier
            user_id: User identifier
            user_email: User email
            request_data: Request data
            status: Request status
            error_message: Error message (if any)
            duration_ms: Request duration
        """
        try:
            # Use database session within context manager
            async with get_db() as session:
                audit_service = AuditService(session)

                # Determine action and resource from path
                action, resource_type, resource_id = self._parse_endpoint(request)

                # Build metadata
                metadata = {
                    "request_id": request_id,
                    "method": request.method,
                    "endpoint": request.url.path,
                    "status_code": response.status_code if response else None,
                    "request_data": request_data,
                }

                # Check if this is a sensitive endpoint
                if any(request.url.path.startswith(path) for path in self.sensitive_paths):
                    metadata["sensitive_endpoint"] = True

                # Log based on endpoint type
                if request.url.path.startswith("/auth/"):
                    # Authentication event
                    await self._log_auth_event(audit_service, request, user_id, user_email, status, metadata)
                elif request.url.path.startswith("/api-keys"):
                    # API key event
                    await self._log_api_key_event(audit_service, request, resource_id, user_id, metadata)
                elif action in ["create", "update", "delete"]:
                    # Resource modification event
                    await audit_service.log_resource_event(
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        user_id=user_id,  # Don't provide default, let audit service handle None
                        request=request,
                        metadata=metadata,
                    )
                else:
                    # General API access
                    await audit_service.log_event(
                        action=f"api.{request.method.lower()}",
                        resource_type=resource_type or "api",
                        resource_id=resource_id,
                        user_id=user_id,
                        user_email=user_email,
                        request=request,
                        metadata=metadata,
                        status=status,
                        error_message=error_message,
                        duration_ms=duration_ms,
                    )

                # Commit the audit log
                await session.commit()

        except Exception as e:
            logger.error(
                "Failed to log audit event",
                request_id=request_id,
                error=str(e),
            )
            # Don't propagate - audit logging should not break the application

    async def _log_auth_event(
        self,
        audit_service: AuditService,
        request: Request,
        user_id: Optional[str],
        user_email: Optional[str],
        status: str,
        metadata: Dict[str, Any],
    ) -> None:
        """Log authentication-specific events.

        Args:
            audit_service: Audit service instance
            request: Request object
            user_id: User identifier
            user_email: User email
            status: Request status
            metadata: Event metadata
        """
        path = request.url.path

        if "/login" in path:
            event_type = "login_success" if status == "success" else "login_failed"
        elif "/logout" in path:
            event_type = "logout"
        elif "/register" in path:
            event_type = "account_created"
        elif "/password" in path:
            if "reset" in path:
                event_type = "password_reset"
            else:
                event_type = "password_changed"
        else:
            event_type = "auth_event"

        await audit_service.log_auth_event(
            event_type=event_type,
            user_id=user_id,
            user_email=user_email,
            request=request,
            success=status == "success",
            metadata=metadata,
        )

    async def _log_api_key_event(
        self,
        audit_service: AuditService,
        request: Request,
        api_key_id: Optional[str],
        user_id: Optional[str],
        metadata: Dict[str, Any],
    ) -> None:
        """Log API key-specific events.

        Args:
            audit_service: Audit service instance
            request: Request object
            api_key_id: API key identifier
            user_id: User identifier
            metadata: Event metadata
        """
        method = request.method
        path = request.url.path

        if method == "POST" and path.endswith("/api-keys"):
            event_type = "api_key_created"
        elif method == "POST" and "rotate" in path:
            event_type = "api_key_rotated"
        elif method == "DELETE":
            event_type = "api_key_revoked"
        elif method == "GET":
            event_type = "api_key_accessed"
        else:
            event_type = "api_key_event"

        await audit_service.log_api_key_event(
            event_type=event_type,
            api_key_id=api_key_id or "unknown",
            user_id=user_id,
            request=request,
            metadata=metadata,
        )

    def _parse_endpoint(self, request: Request) -> tuple[str, Optional[str], Optional[str]]:
        """Parse endpoint to determine action and resource.

        Args:
            request: FastAPI request object

        Returns:
            Tuple of (action, resource_type, resource_id)
        """
        method = request.method
        path = request.url.path
        path_params = getattr(request, "path_params", {})

        # Determine action from HTTP method
        action_map = {
            "GET": "read",
            "POST": "create",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "delete",
        }
        action = action_map.get(method, method.lower())

        # Extract resource type from path
        path_parts = path.strip("/").split("/")
        resource_type = None
        resource_id = None

        if path_parts:
            # Skip API prefix
            if path_parts[0] == "api":
                path_parts = path_parts[1:]

            # Skip version prefix
            if path_parts and path_parts[0] in ["v1", "v2"]:
                path_parts = path_parts[1:]

            if path_parts:
                resource_type = path_parts[0]

                # Check for resource ID in path params
                for param_name, param_value in path_params.items():
                    if param_name.endswith("_id"):
                        resource_id = str(param_value)
                        break

        return action, resource_type, resource_id


# Global audit logging middleware instance
audit_middleware = AuditLoggingMiddleware()
