"""
ABAC-Enhanced Permission Decorators

This module provides permission decorators that leverage the ABAC policy engine
for advanced authorization with attribute-based evaluation.
"""

from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.abac import check_abac_permission, explain_abac_decision
from app.core.errors import ForbiddenError, UnauthorizedError
from app.db.session import get_db

logger = get_logger(__name__)


def require_abac_permission(
    resource_type: str,
    action: str,
    resource_id_param: Optional[str] = None,
    resource_owner_param: Optional[str] = None,
    explain_on_deny: bool = False,
    environment_context: Optional[Dict[str, Any]] = None,
) -> Callable:
    """Decorator to require ABAC-evaluated permissions.

    This decorator replaces the simple permission checks with comprehensive
    ABAC policy evaluation that considers:
    - User attributes (roles, organization, authority level)
    - Resource attributes (type, ownership, organization)
    - Action attributes (risk level, destructive nature)
    - Environmental attributes (time, context)

    Args:
        resource_type: Type of resource being accessed (e.g., 'users', 'api_keys')
        action: Action being performed (e.g., 'read', 'write', 'delete')
        resource_id_param: Parameter name containing resource ID (for resource-specific checks)
        resource_owner_param: Parameter name containing resource owner ID (for ownership checks)
        explain_on_deny: Whether to provide detailed explanation on denial (for debugging)
        environment_context: Additional environmental context

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Extract request and session from function arguments
            request = None
            session = None

            # Detect request and session from arguments
            for arg in args:
                if isinstance(arg, Request) or (hasattr(arg, "state") and hasattr(arg, "method")):
                    request = arg
                elif hasattr(arg, "execute") and hasattr(arg, "commit"):
                    session = arg
                elif hasattr(arg, "__class__") and ("Session" in str(type(arg)) or "Mock" in str(type(arg))):
                    # For testing - detect mock sessions
                    session = arg

            # Check kwargs for request and session (only if not already set)
            if request is None:
                request = kwargs.get("request")
            if session is None:
                session = kwargs.get("session")

            # Check kwargs for request and session by type
            if request is None:
                for key, value in kwargs.items():
                    if isinstance(value, Request) or (hasattr(value, "state") and hasattr(value, "method")):
                        request = value
                        break

            if session is None:
                for key, value in kwargs.items():
                    if (
                        (hasattr(value, "execute") and hasattr(value, "commit"))
                        or "Session" in str(type(value))
                        or "Mock" in str(type(value))
                    ):
                        session = value
                        break

            if request is None:
                raise ValueError("Request object not found in function arguments")
            if session is None:
                raise ValueError("Database session not found in function arguments")

            # Get user context from request state
            subject_id = getattr(request.state, "user_id", None)
            organization_id = getattr(request.state, "organization_id", None)

            if not subject_id:
                raise UnauthorizedError(message="Authentication required")

            # Extract resource identifiers if specified
            resource_id = None
            if resource_id_param:
                resource_id = kwargs.get(resource_id_param)
                if not resource_id:
                    # Try path parameters
                    path_params = getattr(request, "path_params", {})
                    resource_id = path_params.get(resource_id_param)

            resource_owner_id = None
            if resource_owner_param:
                resource_owner_id = kwargs.get(resource_owner_param)
                if not resource_owner_id:
                    # Try path parameters
                    path_params = getattr(request, "path_params", {})
                    resource_owner_id = path_params.get(resource_owner_param)

            # Build environmental context
            env_context = {
                "request_method": request.method,
                "request_path": request.url.path,
                "user_agent": request.headers.get("user-agent", ""),
                "ip_address": request.client.host if request.client else None,
            }
            if environment_context:
                env_context.update(environment_context)

            # Evaluate ABAC permission
            try:
                is_allowed, reason = await check_abac_permission(
                    subject_id=subject_id,
                    resource_type=resource_type,
                    action=action,
                    organization_id=organization_id,
                    resource_id=resource_id,
                    resource_owner_id=resource_owner_id,
                    environment=env_context,
                )

                if not is_allowed:
                    error_detail = f"Access denied: {reason}"

                    if explain_on_deny:
                        try:
                            explanation = await explain_abac_decision(
                                subject_id=subject_id,
                                resource_type=resource_type,
                                action=action,
                                organization_id=organization_id,
                                resource_id=resource_id,
                                resource_owner_id=resource_owner_id,
                                environment=env_context,
                            )
                            logger.info("ABAC decision explanation", subject_id=subject_id, explanation=explanation)
                        except Exception as e:
                            logger.error("Failed to generate explanation", error=str(e))

                    logger.warning(
                        "ABAC permission denied",
                        subject_id=subject_id,
                        resource_type=resource_type,
                        action=action,
                        organization_id=organization_id,
                        resource_id=resource_id,
                        reason=reason,
                    )

                    raise ForbiddenError(detail=error_detail)

                logger.debug(
                    "ABAC permission granted",
                    subject_id=subject_id,
                    resource_type=resource_type,
                    action=action,
                    organization_id=organization_id,
                    resource_id=resource_id,
                    reason=reason,
                )

                # Add ABAC context to kwargs for use in the endpoint (if function accepts it)
                import inspect

                sig = inspect.signature(func)
                if "abac_context" in sig.parameters or any(
                    param.kind == param.VAR_KEYWORD for param in sig.parameters.values()
                ):
                    kwargs["abac_context"] = {
                        "subject_id": subject_id,
                        "organization_id": organization_id,
                        "resource_id": resource_id,
                        "resource_owner_id": resource_owner_id,
                        "decision_reason": reason,
                    }

                return await func(*args, **kwargs)

            except (UnauthorizedError, ForbiddenError):
                raise
            except Exception as e:
                logger.error(
                    "ABAC evaluation error",
                    subject_id=subject_id,
                    resource_type=resource_type,
                    action=action,
                    error=str(e),
                )
                raise ForbiddenError(detail=f"Permission evaluation error: {str(e)}")

        return wrapper

    return decorator


def require_resource_access(
    resource_type: str,
    action: str,
    resource_id_param: str = "resource_id",
    check_ownership: bool = False,
) -> Callable:
    """Decorator for resource-specific access control.

    Args:
        resource_type: Type of resource
        action: Action being performed
        resource_id_param: Parameter containing the resource ID
        check_ownership: Whether to validate resource ownership

    Returns:
        Decorator function
    """
    owner_param = resource_id_param if check_ownership else None

    return require_abac_permission(
        resource_type=resource_type,
        action=action,
        resource_id_param=resource_id_param,
        resource_owner_param=owner_param,
    )


def require_user_access(action: str, check_ownership: bool = True) -> Callable:
    """Decorator for user resource access."""
    return require_resource_access(
        resource_type="users",
        action=action,
        resource_id_param="user_id",
        check_ownership=check_ownership,
    )


def require_api_key_access(action: str, check_ownership: bool = True) -> Callable:
    """Decorator for API key resource access."""
    return require_resource_access(
        resource_type="api_keys",
        action=action,
        resource_id_param="key_id",
        check_ownership=check_ownership,
    )


def require_session_access(action: str, check_ownership: bool = True) -> Callable:
    """Decorator for session resource access."""
    return require_resource_access(
        resource_type="sessions",
        action=action,
        resource_id_param="session_id",
        check_ownership=check_ownership,
    )


def require_admin_access(resource_type: Optional[str] = None) -> Callable:
    """Decorator for admin-level access (replaces is_superuser checks)."""
    return require_abac_permission(
        resource_type=resource_type or "*",
        action="manage",
        explain_on_deny=True,
    )


def require_organization_admin() -> Callable:
    """Decorator for organization admin access."""
    return require_abac_permission(
        resource_type="organization",
        action="manage",
        explain_on_deny=True,
    )


class ABACPermissionChecker:
    """Dependency class for ABAC permission checking."""

    def __init__(
        self,
        resource_type: str,
        action: str,
        resource_id_param: Optional[str] = None,
        resource_owner_param: Optional[str] = None,
    ):
        """Initialize ABAC permission checker.

        Args:
            resource_type: Type of resource
            action: Action being performed
            resource_id_param: Parameter containing resource ID
            resource_owner_param: Parameter containing resource owner ID
        """
        self.resource_type = resource_type
        self.action = action
        self.resource_id_param = resource_id_param
        self.resource_owner_param = resource_owner_param

    async def __call__(
        self,
        request: Request,
        session: AsyncSession = Depends(get_db),
    ) -> Dict[str, Any]:
        """Check permissions as FastAPI dependency.

        Args:
            request: FastAPI request object
            session: Database session

        Returns:
            ABAC context dictionary

        Raises:
            UnauthorizedError: If user is not authenticated
            ForbiddenError: If user lacks required permissions
        """
        # Get user context
        subject_id = getattr(request.state, "user_id", None)
        organization_id = getattr(request.state, "organization_id", None)

        if not subject_id:
            raise UnauthorizedError(message="Authentication required")

        # Extract resource parameters from path
        resource_id = None
        resource_owner_id = None

        if self.resource_id_param:
            path_params = getattr(request, "path_params", {})
            resource_id = path_params.get(self.resource_id_param)

        if self.resource_owner_param:
            path_params = getattr(request, "path_params", {})
            resource_owner_id = path_params.get(self.resource_owner_param)

        # Build environmental context
        env_context = {
            "request_method": request.method,
            "request_path": request.url.path,
            "user_agent": request.headers.get("user-agent", ""),
            "ip_address": request.client.host if request.client else None,
        }

        # Evaluate ABAC permission
        is_allowed, reason = await check_abac_permission(
            subject_id=subject_id,
            resource_type=self.resource_type,
            action=self.action,
            organization_id=organization_id,
            resource_id=resource_id,
            resource_owner_id=resource_owner_id,
            environment=env_context,
        )

        if not is_allowed:
            logger.warning(
                "ABAC dependency permission denied",
                subject_id=subject_id,
                resource_type=self.resource_type,
                action=self.action,
                reason=reason,
            )
            raise ForbiddenError(detail=f"Access denied: {reason}")

        return {
            "subject_id": subject_id,
            "organization_id": organization_id,
            "resource_id": resource_id,
            "resource_owner_id": resource_owner_id,
            "decision_reason": reason,
        }


# Pre-configured permission dependencies
ABACRequireUserRead = ABACPermissionChecker("users", "read")
ABACRequireUserWrite = ABACPermissionChecker("users", "write")
ABACRequireUserDelete = ABACPermissionChecker("users", "delete")
ABACRequireAPIKeyRead = ABACPermissionChecker("api_keys", "read")
ABACRequireAPIKeyWrite = ABACPermissionChecker("api_keys", "write")
ABACRequireAPIKeyDelete = ABACPermissionChecker("api_keys", "delete")
ABACRequireSessionRead = ABACPermissionChecker("sessions", "read")
ABACRequireSessionWrite = ABACPermissionChecker("sessions", "write")
ABACRequireAuditRead = ABACPermissionChecker("audit_logs", "read")
ABACRequireAdmin = ABACPermissionChecker("*", "manage")


def abac_permission_checker(
    resource_type: str,
    action: str,
    resource_id_param: Optional[str] = None,
    resource_owner_param: Optional[str] = None,
) -> ABACPermissionChecker:
    """Create an ABAC permission checker dependency.

    Args:
        resource_type: Type of resource
        action: Action being performed
        resource_id_param: Parameter containing resource ID
        resource_owner_param: Parameter containing resource owner ID

    Returns:
        ABACPermissionChecker instance
    """
    return ABACPermissionChecker(
        resource_type=resource_type,
        action=action,
        resource_id_param=resource_id_param,
        resource_owner_param=resource_owner_param,
    )
