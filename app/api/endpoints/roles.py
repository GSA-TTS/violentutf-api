"""Role management API endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from structlog.stdlib import get_logger

from app.api.deps import get_rbac_service
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.core.permissions import RequireAdmin, RequireRoleRead, RequireRoleWrite
from app.schemas.base import BaseResponse, OperationResult, PaginatedResponse
from app.services.rbac_service import RBACService

logger = get_logger(__name__)

router = APIRouter(prefix="/roles", tags=["Roles"])


# TODO: Create role schemas
class RoleCreate:
    """Temporary schema for role creation - replace with proper Pydantic model."""

    def __init__(self, **data: Any) -> None:
        """Initialize role creation data."""
        self.name = data.get("name")
        self.display_name = data.get("display_name")
        self.description = data.get("description")
        self.permissions = data.get("permissions", [])
        self.parent_role_id = data.get("parent_role_id")


class RoleUpdate:
    """Temporary schema for role updates - replace with proper Pydantic model."""

    def __init__(self, **data: Any) -> None:
        """Initialize role update data."""
        self.display_name = data.get("display_name")
        self.description = data.get("description")
        self.permissions = data.get("permissions")
        self.is_active = data.get("is_active")


class RoleAssignment:
    """Temporary schema for role assignments - replace with proper Pydantic model."""

    def __init__(self, **data: Any) -> None:
        """Initialize role assignment data."""
        self.user_id = data.get("user_id")
        self.role_id = data.get("role_id")
        self.expires_at = data.get("expires_at")
        self.reason = data.get("reason")
        self.context = data.get("context")


def get_current_user_id(request: Request) -> str:
    """Get current user ID from request state."""
    current_user_id = getattr(request.state, "user_id", None)
    if not current_user_id:
        raise ValidationError(message="User authentication required")
    return str(current_user_id)


def check_admin_permission(request: Request) -> None:
    """Check if user has admin permissions."""
    current_user = getattr(request.state, "user", None)
    if not current_user or not getattr(current_user, "is_superuser", False):
        raise ForbiddenError(message="Administrator privileges required")


@router.post("/initialize", response_model=BaseResponse[List[Dict[str, Any]]])
async def initialize_system_roles(
    request: Request, rbac_service: RBACService = Depends(get_rbac_service), _: None = Depends(RequireAdmin)
) -> BaseResponse[List[Dict[str, Any]]]:
    """Initialize system roles and permissions."""

    try:
        # Use injected service
        created_roles = await rbac_service.initialize_system_roles()

        role_dicts = [role.to_dict() for role in created_roles]

        return BaseResponse(
            data=role_dicts,
            message=f"Initialized {len(created_roles)} system roles",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to initialize system roles", error=str(e))
        raise


@router.get("/", response_model=BaseResponse[List[Dict[str, Any]]])
async def list_roles(
    request: Request,
    include_system: bool = Query(True, description="Include system roles"),
    include_custom: bool = Query(True, description="Include custom roles"),
    rbac_service: RBACService = Depends(get_rbac_service),
    _: None = Depends(RequireRoleRead),
) -> BaseResponse[List[Dict[str, Any]]]:
    """Get all roles."""
    try:
        # Use injected RBAC service
        all_roles = []

        if include_system:
            system_roles = await rbac_service.get_system_roles()
            all_roles.extend(system_roles)

        if include_custom:
            custom_roles = await rbac_service.get_custom_roles()
            all_roles.extend(custom_roles)

        # Sort by level then by name
        all_roles.sort(key=lambda r: (r.role_metadata.get("level", 999), r.name))
        role_dicts = [role.to_dict() for role in all_roles]

        return BaseResponse(
            data=role_dicts,
            message=f"Retrieved {len(role_dicts)} roles",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to list roles", error=str(e))
        raise


@router.get("/{role_id}", response_model=BaseResponse[Dict[str, Any]])
async def get_role(
    role_id: str, request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[Dict[str, Any]]:
    """Get a specific role by ID."""
    try:
        # Use injected RBAC service
        role_repository = rbac_service.role_repository

        role = await role_repository.get(role_id)
        if not role:
            raise NotFoundError(message=f"Role {role_id} not found")

        return BaseResponse(
            data=role.to_dict(),
            message="Role retrieved successfully",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to get role", role_id=role_id, error=str(e))
        raise


@router.post("/", response_model=BaseResponse[Dict[str, Any]], status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: Dict[str, Any],
    request: Request,
    rbac_service: RBACService = Depends(get_rbac_service),
    _: None = Depends(RequireRoleWrite),
) -> BaseResponse[Dict[str, Any]]:
    """Create a new role."""

    try:
        current_user_id = get_current_user_id(request)
        # Use injected RBAC service

        # Create role using service (handles validation and transactions)
        role = await rbac_service.create_role(
            name=role_data.get("name"),
            display_name=role_data.get("display_name"),
            description=role_data.get("description"),
            permissions=role_data.get("permissions", []),
            parent_role_id=role_data.get("parent_role_id"),
            created_by=current_user_id,
        )

        return BaseResponse(
            data=role.to_dict(), message="Role created successfully", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to create role", error=str(e))
        raise


@router.put("/{role_id}", response_model=BaseResponse[Dict[str, Any]])
async def update_role(
    role_id: str, role_data: Dict[str, Any], request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[Dict[str, Any]]:
    """Update an existing role."""
    check_admin_permission(request)

    try:
        current_user_id = get_current_user_id(request)
        # Use injected RBAC service

        # Update role using service (handles validation and transactions)
        role = await rbac_service.update_role(
            role_id=role_id,
            display_name=role_data.get("display_name"),
            description=role_data.get("description"),
            permissions=role_data.get("permissions"),
            is_active=role_data.get("is_active"),
            updated_by=current_user_id,
        )

        return BaseResponse(
            data=role.to_dict(), message="Role updated successfully", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to update role", role_id=role_id, error=str(e))
        raise


@router.delete("/{role_id}", response_model=BaseResponse[OperationResult])
async def delete_role(
    role_id: str, request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[OperationResult]:
    """Delete a role."""
    check_admin_permission(request)

    try:
        current_user_id = get_current_user_id(request)
        # Use injected RBAC service

        # Delete role using service (handles validation and transactions)
        success = await rbac_service.delete_role(role_id, deleted_by=current_user_id)

        result = OperationResult(
            success=success,
            message="Role deleted successfully" if success else "Role not found",
            affected_rows=1 if success else 0,
            operation_id=str(uuid.uuid4()),
        )

        return BaseResponse(
            data=result, message="Operation completed", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to delete role", role_id=role_id, error=str(e))
        raise


@router.post("/assign", response_model=BaseResponse[Dict[str, Any]])
async def assign_role_to_user(
    assignment_data: Dict[str, Any], request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[Dict[str, Any]]:
    """Assign a role to a user."""
    check_admin_permission(request)

    try:
        current_user_id = get_current_user_id(request)
        # Use injected RBAC service

        # Parse expiration date if provided
        expires_at = None
        if assignment_data.get("expires_at"):
            expires_at = datetime.fromisoformat(assignment_data["expires_at"])

        # Assign role using service (handles validation and transactions)
        assignment = await rbac_service.assign_role_to_user(
            user_id=assignment_data["user_id"],
            role_id=assignment_data["role_id"],
            assigned_by=current_user_id,
            expires_at=expires_at,
            reason=assignment_data.get("reason"),
            context=assignment_data.get("context"),
        )

        return BaseResponse(
            data=assignment.to_dict(),
            message="Role assigned successfully",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to assign role", error=str(e))
        raise


@router.post("/revoke", response_model=BaseResponse[OperationResult])
async def revoke_role_from_user(
    revocation_data: Dict[str, Any], request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[OperationResult]:
    """Revoke a role from a user."""
    check_admin_permission(request)

    try:
        current_user_id = get_current_user_id(request)
        # Use injected RBAC service

        # Revoke role using service
        success = await rbac_service.revoke_role_from_user(
            user_id=revocation_data["user_id"],
            role_id=revocation_data["role_id"],
            revoked_by=current_user_id,
            reason=revocation_data.get("reason"),
        )

        result = OperationResult(
            success=success,
            message="Role revoked successfully" if success else "Role assignment not found",
            affected_rows=1 if success else 0,
            operation_id=str(uuid.uuid4()),
        )

        return BaseResponse(
            data=result, message="Operation completed", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to revoke role", error=str(e))
        raise


@router.get("/user/{user_id}/roles", response_model=BaseResponse[List[Dict[str, Any]]])
async def get_user_roles(
    user_id: str,
    request: Request,
    include_expired: bool = Query(False, description="Include expired assignments"),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> BaseResponse[List[Dict[str, Any]]]:
    """Get all roles assigned to a user."""
    current_user_id = get_current_user_id(request)

    # Users can view their own roles, admins can view any user's roles
    current_user = getattr(request.state, "user", None)
    is_admin = current_user and getattr(current_user, "is_superuser", False)

    if not is_admin and current_user_id != user_id:
        raise ForbiddenError(message="You can only view your own roles")

    try:
        # Use injected RBAC service

        # Get user roles
        roles = await rbac_service.get_user_roles(user_id, include_expired)
        role_dicts = [role.to_dict() for role in roles]

        return BaseResponse(
            data=role_dicts,
            message=f"Retrieved {len(role_dicts)} roles for user",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to get user roles", user_id=user_id, error=str(e))
        raise


@router.get("/user/{user_id}/permissions", response_model=BaseResponse[List[str]])
async def get_user_permissions(
    user_id: str, request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[List[str]]:
    """Get all effective permissions for a user."""
    current_user_id = get_current_user_id(request)

    # Users can view their own permissions, admins can view any user's permissions
    current_user = getattr(request.state, "user", None)
    is_admin = current_user and getattr(current_user, "is_superuser", False)

    if not is_admin and current_user_id != user_id:
        raise ForbiddenError(message="You can only view your own permissions")

    try:
        # Use injected RBAC service

        # Get user permissions
        permissions = await rbac_service.get_user_permissions(user_id)
        permission_list = sorted(list(permissions))

        return BaseResponse(
            data=permission_list,
            message=f"Retrieved {len(permission_list)} permissions for user",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to get user permissions", user_id=user_id, error=str(e))
        raise


@router.post("/user/{user_id}/check-permission", response_model=BaseResponse[Dict[str, Any]])
async def check_user_permission(
    user_id: str,
    permission_data: Dict[str, str],
    request: Request,
    rbac_service: RBACService = Depends(get_rbac_service),
) -> BaseResponse[Dict[str, Any]]:
    """Check if a user has a specific permission."""
    current_user_id = get_current_user_id(request)

    # Users can check their own permissions, admins can check any user's permissions
    current_user = getattr(request.state, "user", None)
    is_admin = current_user and getattr(current_user, "is_superuser", False)

    if not is_admin and current_user_id != user_id:
        raise ForbiddenError(message="You can only check your own permissions")

    try:
        permission = permission_data.get("permission")
        if not permission:
            raise ValidationError(message="Permission is required")

        # Use injected RBAC service

        # Check permission
        has_permission = await rbac_service.check_user_permission(user_id, permission)

        result = {
            "user_id": user_id,
            "permission": permission,
            "has_permission": has_permission,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        return BaseResponse(
            data=result, message=f"Permission check completed", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        logger.error("Failed to check user permission", user_id=user_id, error=str(e))
        raise


@router.get("/{role_id}/assignments", response_model=BaseResponse[List[Dict[str, Any]]])
async def get_role_assignments(
    role_id: str,
    request: Request,
    include_inactive: bool = Query(False, description="Include inactive assignments"),
    include_expired: bool = Query(False, description="Include expired assignments"),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> BaseResponse[List[Dict[str, Any]]]:
    """Get all assignments for a specific role."""
    check_admin_permission(request)

    try:
        # Use injected RBAC service

        # Get role assignments
        assignments = await rbac_service.get_users_with_role(role_id)
        assignment_dicts = [assignment.to_dict() for assignment in assignments]

        return BaseResponse(
            data=assignment_dicts,
            message=f"Retrieved {len(assignment_dicts)} assignments for role",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to get role assignments", role_id=role_id, error=str(e))
        raise


@router.get("/statistics", response_model=BaseResponse[Dict[str, Any]])
async def get_rbac_statistics(
    request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[Dict[str, Any]]:
    """Get RBAC system statistics."""
    check_admin_permission(request)

    try:
        # Use injected RBAC service

        # Get statistics
        stats = await rbac_service.get_rbac_statistics()

        return BaseResponse(
            data=stats,
            message="RBAC statistics retrieved successfully",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error("Failed to get RBAC statistics", error=str(e))
        raise


@router.post("/cleanup-expired", response_model=BaseResponse[OperationResult])
async def cleanup_expired_assignments(
    request: Request, rbac_service: RBACService = Depends(get_rbac_service)
) -> BaseResponse[OperationResult]:
    """Clean up expired role assignments."""
    check_admin_permission(request)

    try:
        # Use injected RBAC service

        # Clean up expired assignments
        cleaned_count = await rbac_service.cleanup_expired_assignments()

        result = OperationResult(
            success=True,
            message=f"Cleaned up {cleaned_count} expired assignments",
            affected_rows=cleaned_count,
            operation_id=str(uuid.uuid4()),
        )

        return BaseResponse(
            data=result, message="Cleanup completed successfully", trace_id=getattr(request.state, "trace_id", None)
        )

    except Exception as e:
        # Service layer handles rollback automatically
        logger.error("Failed to cleanup expired assignments", error=str(e))
        raise
