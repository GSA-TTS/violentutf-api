"""Permission decorators and utilities for RBAC and ABAC authorization.

This module provides permission decorators that integrate with both the legacy
RBAC system and the new ABAC (Attribute-Based Access Control) system.
The ABAC system addresses the critical security issues identified in the
authentication audit report.
"""

from functools import wraps
from typing import Any, Callable, List, Optional, Union

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.abac import check_abac_permission
from app.core.authority import AuthorityLevel, evaluate_user_authority, is_deprecated_superuser
from app.core.errors import ForbiddenError, UnauthorizedError
from app.db.session import get_db
from app.repositories.user import UserRepository
from app.services.rbac_service import RBACService

logger = get_logger(__name__)


def require_permissions(
    permissions: Union[str, List[str]],
    require_all: bool = False,
    allow_superuser: bool = True,
    use_abac: bool = True,
) -> Callable:
    """Decorator to require specific permissions for an endpoint.

    DEPRECATED: This function still uses the problematic boolean superuser approach.
    Use require_abac_permission() or specific ABAC decorators instead for secure access control.

    Args:
        permissions: Single permission string or list of permissions
        require_all: If True, user must have ALL permissions. If False, ANY permission is sufficient
        allow_superuser: DEPRECATED - If True, superusers bypass permission checks
        use_abac: If True, use new ABAC evaluation (recommended)

    Returns:
        Decorator function

    Example:
        @require_permissions("users:read")
        @require_permissions(["users:read", "users:write"], require_all=True)

    Migration Recommendation:
        Replace with:
        @require_abac_permission(resource_type="users", action="read")
    """
    # Normalize permissions to list
    if isinstance(permissions, str):
        permission_list = [permissions]
    else:
        permission_list = permissions

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Extract request and session from function arguments
            request = None
            session = None

            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    session = arg

            # Check keyword arguments too
            if request is None:
                request = kwargs.get("request")
            if session is None:
                session = kwargs.get("session")

            if not request:
                raise ValueError("Request object not found in function arguments")
            if not session:
                raise ValueError("Database session not found in function arguments")

            # Get user ID from request
            user_id = _get_user_id_from_request(request)
            if not user_id:
                raise UnauthorizedError(message="Authentication required")

            # DEPRECATED: Check superuser flag with migration warning
            if allow_superuser:
                user_repo = UserRepository(session)
                organization_id = _get_organization_id_from_request(request)
                user = await user_repo.get_by_id(user_id, organization_id)

                if user and is_deprecated_superuser(user):
                    logger.warning(
                        "DEPRECATED: Boolean is_superuser flag used - migrate to authority levels",
                        user_id=user_id,
                        permissions=permission_list,
                        migration_needed=True,
                    )
                    # Still allow for backward compatibility but log warning
                    return await func(*args, **kwargs)

                # Use new authority-based evaluation
                if user:
                    authority_level = await evaluate_user_authority(user, session)
                    if authority_level.has_system_access():
                        logger.debug(
                            "System authority bypassing permission check",
                            user_id=user_id,
                            authority_level=authority_level.level_name,
                            permissions=permission_list,
                        )
                        return await func(*args, **kwargs)

            # Use ABAC evaluation if enabled (recommended)
            if use_abac:
                organization_id = _get_organization_id_from_request(request)

                # For multiple permissions, evaluate each with ABAC
                if require_all:
                    # All permissions must be granted
                    for perm in permission_list:
                        if ":" in perm:
                            resource_type, action = perm.split(":", 1)
                        else:
                            resource_type, action = perm, "*"

                        is_allowed, reason = await check_abac_permission(
                            subject_id=user_id,
                            resource_type=resource_type,
                            action=action,
                            session=session,
                            organization_id=organization_id,
                        )

                        if not is_allowed:
                            logger.info("ABAC permission denied", user_id=user_id, permission=perm, reason=reason)
                            permission_desc = " AND ".join(permission_list)
                            raise ForbiddenError(
                                message=f"Access denied: {reason}. Required permissions: {permission_desc}"
                            )

                    # All permissions passed
                    has_required_permissions = True
                else:
                    # Any permission is sufficient
                    has_required_permissions = False
                    for perm in permission_list:
                        if ":" in perm:
                            resource_type, action = perm.split(":", 1)
                        else:
                            resource_type, action = perm, "*"

                        is_allowed, reason = await check_abac_permission(
                            subject_id=user_id,
                            resource_type=resource_type,
                            action=action,
                            session=session,
                            organization_id=organization_id,
                        )

                        if is_allowed:
                            has_required_permissions = True
                            break
            else:
                # Fallback to legacy RBAC evaluation
                has_required_permissions = await _check_permissions(session, user_id, permission_list, require_all)

            if not has_required_permissions:
                permission_desc = " AND ".join(permission_list) if require_all else " OR ".join(permission_list)
                raise ForbiddenError(detail=f"Required permissions: {permission_desc}")

            logger.debug(
                "Permission check passed",
                user_id=user_id,
                permissions=permission_list,
                require_all=require_all,
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_admin(func: Callable) -> Callable:
    """DEPRECATED: Decorator to require admin privileges.

    This function is deprecated and uses the problematic superuser boolean approach.
    Use require_abac_permission(resource_type="*", action="manage") instead.

    Args:
        func: Function to decorate

    Returns:
        Decorated function

    Migration Recommendation:
        Replace with:
        @require_abac_permission(resource_type="*", action="manage")
    """
    # Use ABAC-based admin check by default
    from app.core.abac_permissions import require_admin_access

    return require_admin_access()(func)


def require_owner_or_admin(resource_param: str = "user_id") -> Callable:
    """Decorator to require resource ownership or admin privileges.

    WARNING: This decorator only validates user_id ownership without organization context.
    Use require_organization_owner_or_admin for multi-tenant secure ownership validation.

    Args:
        resource_param: Name of the parameter containing the resource ID

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Extract request from arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found in function arguments")

            # Get current user ID
            current_user_id = _get_user_id_from_request(request)
            if not current_user_id:
                raise UnauthorizedError(message="Authentication required")

            # DEPRECATED: Check superuser/admin with new authority system
            session = None
            for arg in args:
                if hasattr(arg, "execute"):  # AsyncSession
                    session = arg
                    break
            if not session:
                session = kwargs.get("session")

            if session:
                user_repo = UserRepository(session)
                organization_id = _get_organization_id_from_request(request)
                user = await user_repo.get_by_id(current_user_id, organization_id)

                if user:
                    # Check for deprecated superuser flag with warning
                    if is_deprecated_superuser(user):
                        logger.warning(
                            "DEPRECATED: Boolean is_superuser flag used in ownership check",
                            user_id=current_user_id,
                            migration_needed=True,
                        )
                        return await func(*args, **kwargs)

                    # Use new authority-based evaluation
                    authority_level = await evaluate_user_authority(user, session)
                    if authority_level.has_admin_access():
                        logger.debug(
                            "Admin authority bypassing ownership check",
                            user_id=current_user_id,
                            authority_level=authority_level.level_name,
                        )
                        return await func(*args, **kwargs)

            # Check if user owns the resource
            resource_id = kwargs.get(resource_param)
            if not resource_id:
                # Try to get from path parameters
                path_params = getattr(request, "path_params", {})
                resource_id = path_params.get(resource_param)

            if not resource_id:
                raise ValueError(f"Resource parameter '{resource_param}' not found")

            if str(current_user_id) != str(resource_id):
                raise ForbiddenError(detail="You can only access your own resources")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_organization_access(allow_superuser: bool = True) -> Callable:
    """Decorator to require organization context and ensure multi-tenant isolation.

    This decorator adds organization_id from JWT to request state and validates
    that the user has access to resources within their organization.

    Args:
        allow_superuser: If True, superusers bypass organization checks

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Extract request from arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found in function arguments")

            # Get current user and organization IDs
            current_user_id = _get_user_id_from_request(request)
            current_organization_id = _get_organization_id_from_request(request)

            if not current_user_id:
                raise UnauthorizedError(message="Authentication required")

            if not current_organization_id:
                logger.warning(
                    "Missing organization_id in JWT token",
                    user_id=current_user_id,
                    endpoint=request.url.path,
                )
                raise UnauthorizedError(message="Organization context required for this operation")

            # Check if user is superuser (if allowed)
            if allow_superuser and await _is_superuser(request):
                logger.debug(
                    "Superuser bypassing organization check",
                    user_id=current_user_id,
                    organization_id=current_organization_id,
                )
                return await func(*args, **kwargs)

            # Add organization_id to kwargs for use by repository methods
            kwargs["organization_id"] = current_organization_id

            logger.debug(
                "Organization access check passed",
                user_id=current_user_id,
                organization_id=current_organization_id,
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_organization_owner_or_admin(resource_param: str = "user_id", allow_superuser: bool = True) -> Callable:
    """Decorator to require organization-aware resource ownership or admin privileges.

    This decorator provides secure multi-tenant ownership validation by:
    1. Verifying the user belongs to an organization
    2. Checking if user is admin/superuser (if allowed)
    3. Validating that the resource owner belongs to the same organization
    4. Only then checking if the current user owns the resource

    Args:
        resource_param: Name of the parameter containing the resource ID
        allow_superuser: If True, superusers bypass ownership checks

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Extract request and session from arguments
            request = None
            session = None

            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif hasattr(arg, "execute"):  # Check for AsyncSession
                    session = arg

            if not request:
                request = kwargs.get("request")
            if not session:
                session = kwargs.get("session")

            if not request:
                raise ValueError("Request object not found in function arguments")
            if not session:
                raise ValueError("Database session not found in function arguments")

            # Get current user and organization IDs
            current_user_id = _get_user_id_from_request(request)
            current_organization_id = _get_organization_id_from_request(request)

            if not current_user_id:
                raise UnauthorizedError(message="Authentication required")

            if not current_organization_id:
                logger.warning(
                    "Missing organization_id in JWT token for ownership validation",
                    user_id=current_user_id,
                    endpoint=request.url.path,
                )
                raise UnauthorizedError(message="Organization context required for resource access")

            # DEPRECATED: Check admin privileges with new authority system
            if allow_superuser:
                user_repo = UserRepository(session)
                user = await user_repo.get_by_id(current_user_id, current_organization_id)

                if user:
                    # Check for deprecated superuser flag with warning
                    if is_deprecated_superuser(user):
                        logger.warning(
                            "DEPRECATED: Boolean is_superuser flag used in organization ownership check",
                            user_id=current_user_id,
                            organization_id=current_organization_id,
                            migration_needed=True,
                        )
                        kwargs["organization_id"] = current_organization_id
                        return await func(*args, **kwargs)

                    # Use new authority-based evaluation
                    authority_level = await evaluate_user_authority(user, session)
                    if authority_level.has_admin_access():
                        logger.debug(
                            "Admin authority bypassing organization ownership check",
                            user_id=current_user_id,
                            organization_id=current_organization_id,
                            authority_level=authority_level.level_name,
                        )
                        kwargs["organization_id"] = current_organization_id
                        return await func(*args, **kwargs)

            # Get resource ID from parameters
            resource_id = kwargs.get(resource_param)
            if not resource_id:
                # Try to get from path parameters
                path_params = getattr(request, "path_params", {})
                resource_id = path_params.get(resource_param)

            if not resource_id:
                raise ValueError(f"Resource parameter '{resource_param}' not found")

            # For ownership validation, we need to:
            # 1. Check if the user owns the resource (user_id match)
            # 2. Ensure both user and resource belong to the same organization
            if str(current_user_id) != str(resource_id):
                raise ForbiddenError(detail="You can only access your own resources")

            # Add organization_id to kwargs for repository method filtering
            kwargs["organization_id"] = current_organization_id

            logger.debug(
                "Organization-aware ownership check passed",
                user_id=current_user_id,
                organization_id=current_organization_id,
                resource_id=str(resource_id),
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def get_current_user_permissions(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> List[str]:
    """Dependency to get current user's permissions.

    Args:
        request: FastAPI request object
        session: Database session

    Returns:
        List of user's permissions

    Raises:
        UnauthorizedError: If user is not authenticated
    """
    user_id = _get_user_id_from_request(request)
    if not user_id:
        raise UnauthorizedError(message="Authentication required")

    try:
        rbac_service = RBACService(session)
        permissions = await rbac_service.get_user_permissions(user_id)
        return sorted(list(permissions))

    except Exception as e:
        logger.error(
            "Error getting user permissions",
            user_id=user_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user permissions",
        )


async def check_permission(
    permission: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    allow_superuser: bool = True,
) -> bool:
    """Check if current user has a specific permission.

    Args:
        permission: Permission to check
        request: FastAPI request object
        session: Database session
        allow_superuser: Whether superusers bypass permission checks

    Returns:
        True if user has permission
    """
    user_id = _get_user_id_from_request(request)
    if not user_id:
        return False

    try:
        # DEPRECATED: Check superuser flag with authority-based replacement
        if allow_superuser:
            # Try to get session for authority evaluation
            try:
                session = getattr(request.state, "db_session", None)
                if not session:
                    from app.db.session import get_db

                    async for session in get_db():
                        break

                if session:
                    user_repo = UserRepository(session)
                    organization_id = _get_organization_id_from_request(request)
                    user = await user_repo.get_by_id(user_id, organization_id)

                    if user:
                        # Check deprecated superuser flag with warning
                        if is_deprecated_superuser(user):
                            logger.warning(
                                "DEPRECATED: Boolean is_superuser flag used in permission check",
                                user_id=user_id,
                                migration_needed=True,
                            )
                            return True

                        # Use authority-based evaluation
                        authority_level = await evaluate_user_authority(user, session)
                        if authority_level.has_system_access():
                            return True
            except Exception as e:
                logger.error("Error in superuser authority check", error=str(e))
                # Fallback to legacy check
                if await _is_superuser(request):
                    return True

        # Check specific permission
        rbac_service = RBACService(session)
        return await rbac_service.check_user_permission(user_id, permission)

    except Exception as e:
        logger.error(
            "Error checking permission",
            user_id=user_id,
            permission=permission,
            error=str(e),
        )
        return False


def _get_user_id_from_request(request: Request) -> Optional[str]:
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


def _get_organization_id_from_request(request: Request) -> Optional[str]:
    """Extract organization ID from request state.

    Args:
        request: FastAPI request object

    Returns:
        Organization ID if authenticated, None otherwise
    """
    # Organization ID should be set by authentication middleware
    organization_id = getattr(request.state, "organization_id", None)

    if organization_id:
        return str(organization_id)

    return None


async def _is_superuser(request: Request) -> bool:
    """DEPRECATED: Check if current user is a superuser using boolean flag.

    This function is deprecated and should be replaced with authority-based checks.
    Use evaluate_user_authority() and AuthorityLevel comparisons instead.

    Args:
        request: FastAPI request object

    Returns:
        True if user has deprecated superuser flag set

    Migration Recommendation:
        Replace with authority level evaluation:
        authority_level = await evaluate_user_authority(user, session)
        return authority_level.has_system_access()
    """
    user = getattr(request.state, "user", None)
    if user and hasattr(user, "is_superuser"):
        if user.is_superuser:
            logger.warning(
                "DEPRECATED: Boolean is_superuser flag accessed - migrate to authority levels",
                user_id=getattr(user, "id", None),
                migration_needed=True,
            )
        return bool(user.is_superuser)

    return False


async def _has_admin_permissions(request: Request) -> bool:
    """Check if current user has admin permissions.

    Args:
        request: FastAPI request object

    Returns:
        True if user has admin permissions
    """
    try:
        session = None
        # Try to get session from request state
        session = getattr(request.state, "db_session", None)

        if not session:
            # Create new session
            from app.db.session import get_db

            async for session in get_db():
                break

        if not session:
            return False

        user_id = _get_user_id_from_request(request)
        if not user_id:
            return False

        rbac_service = RBACService(session)
        return await rbac_service.check_user_permission(user_id, "*")

    except Exception as e:
        logger.error("Error checking admin permissions", error=str(e))
        return False


async def _check_permissions(
    session: AsyncSession,
    user_id: str,
    permissions: List[str],
    require_all: bool,
) -> bool:
    """Check if user has required permissions.

    Args:
        session: Database session
        user_id: User identifier
        permissions: List of permissions to check
        require_all: Whether all permissions are required

    Returns:
        True if user has required permissions
    """
    try:
        rbac_service = RBACService(session)

        # Check user permissions directly without storing result

        if require_all:
            # User must have ALL permissions
            for perm in permissions:
                if not await rbac_service.check_user_permission(user_id, perm):
                    return False
            return True
        else:
            # User must have ANY permission
            for perm in permissions:
                if await rbac_service.check_user_permission(user_id, perm):
                    return True
            return False

    except Exception as e:
        logger.error(
            "Error checking permissions",
            user_id=user_id,
            permissions=permissions,
            error=str(e),
        )
        return False


class PermissionDependency:
    """Dependency class for permission checking."""

    def __init__(
        self,
        permissions: Union[str, List[str]],
        require_all: bool = False,
        allow_superuser: bool = True,
    ):
        """Initialize permission dependency.

        Args:
            permissions: Required permissions
            require_all: Whether all permissions are required
            allow_superuser: Whether superusers bypass checks
        """
        self.permissions = [permissions] if isinstance(permissions, str) else permissions
        self.require_all = require_all
        self.allow_superuser = allow_superuser

    async def __call__(
        self,
        request: Request,
        session: AsyncSession = Depends(get_db),
    ) -> None:
        """Check permissions as FastAPI dependency.

        Args:
            request: FastAPI request object
            session: Database session

        Raises:
            UnauthorizedError: If user is not authenticated
            ForbiddenError: If user lacks required permissions
        """
        user_id = _get_user_id_from_request(request)
        if not user_id:
            raise UnauthorizedError(message="Authentication required")

        # DEPRECATED: Check superuser with authority-based evaluation
        if self.allow_superuser:
            # Try authority-based evaluation first
            try:
                user_repo = UserRepository(session)
                organization_id = _get_organization_id_from_request(request)
                user = await user_repo.get_by_id(user_id, organization_id)

                if user:
                    # Check deprecated superuser flag with warning
                    if is_deprecated_superuser(user):
                        logger.warning(
                            "DEPRECATED: Boolean is_superuser flag used in permission dependency",
                            user_id=user_id,
                            migration_needed=True,
                        )
                        return

                    # Use authority-based evaluation
                    authority_level = await evaluate_user_authority(user, session)
                    if authority_level.has_system_access():
                        return
            except Exception as e:
                logger.error("Error in authority evaluation", error=str(e))
                # Fallback to legacy superuser check
                if await _is_superuser(request):
                    return

        # Check permissions
        has_required_permissions = await _check_permissions(session, user_id, self.permissions, self.require_all)

        if not has_required_permissions:
            permission_desc = " AND ".join(self.permissions) if self.require_all else " OR ".join(self.permissions)
            raise ForbiddenError(detail=f"Required permissions: {permission_desc}")


# Common permission dependencies
RequireAdmin = PermissionDependency("*")
RequireUserRead = PermissionDependency("users:read")
RequireUserWrite = PermissionDependency("users:write")
RequireAPIKeyRead = PermissionDependency("api_keys:read")
RequireAPIKeyWrite = PermissionDependency("api_keys:write")
RequireRoleRead = PermissionDependency("roles:read")
RequireRoleWrite = PermissionDependency("roles:write")
RequireAuditRead = PermissionDependency("audit_logs:read")


def permission_checker(permissions: Union[str, List[str]], require_all: bool = False) -> PermissionDependency:
    """Create a permission checker dependency.

    Args:
        permissions: Required permissions
        require_all: Whether all permissions are required

    Returns:
        PermissionDependency instance
    """
    return PermissionDependency(permissions, require_all)


def require_any_permission(permissions: List[str]) -> PermissionDependency:
    """Create a permission checker that requires ANY of the given permissions.

    Args:
        permissions: List of permissions (user needs at least one)

    Returns:
        PermissionDependency instance
    """
    return PermissionDependency(permissions, require_all=False)


def require_permission(permission: str) -> PermissionDependency:
    """Create a permission checker for a single permission.

    Args:
        permission: Required permission

    Returns:
        PermissionDependency instance
    """
    return PermissionDependency(permission)
