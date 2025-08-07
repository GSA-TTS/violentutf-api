"""RBAC service for role and permission management."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.permission import Permission
from app.models.role import Role
from app.models.user_role import UserRole
from app.repositories.role import RoleRepository
from app.repositories.user import UserRepository

logger = get_logger(__name__)


class RBACService:
    """Service for Role-Based Access Control operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize RBAC service."""
        self.session = session
        self.role_repository = RoleRepository(session)
        self.user_repository = UserRepository(session)

    async def initialize_system_roles(self) -> List[Role]:
        """Initialize default system roles and permissions.

        Returns:
            List of created system roles
        """
        try:
            # Create system roles
            created_roles = await self.role_repository.create_system_roles()

            # TODO: Create system permissions when Permission repository is implemented

            if created_roles:
                await self.session.commit()
                logger.info("System roles initialized", count=len(created_roles))

            return created_roles

        except Exception as e:
            await self.session.rollback()
            logger.error("Failed to initialize system roles", error=str(e))
            raise

    async def create_role(
        self,
        name: str,
        display_name: str,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        parent_role_id: Optional[str] = None,
        created_by: str = "system",
    ) -> Role:
        """Create a new role.

        Args:
            name: Unique role name
            display_name: Human-readable role name
            description: Optional role description
            permissions: List of permission strings
            parent_role_id: Optional parent role for hierarchy
            created_by: Who is creating the role

        Returns:
            Created Role instance
        """
        try:
            # Check if role name already exists
            existing_role = await self.role_repository.get_by_name(name)
            if existing_role:
                raise ConflictError(message=f"Role with name '{name}' already exists")

            # Validate parent role if specified
            parent_role = None
            if parent_role_id:
                parent_role = await self.role_repository.get(parent_role_id)
                if not parent_role:
                    raise ValidationError(message=f"Parent role {parent_role_id} not found")

            # Create role data
            role_data = {
                "name": name,
                "display_name": display_name,
                "description": description,
                "parent_role_id": uuid.UUID(parent_role_id) if parent_role_id else None,
                "is_system_role": False,
                "is_active": True,
                "role_metadata": {
                    "permissions": permissions or [],
                    "level": (parent_role.role_metadata.get("level", 0) + 1) if parent_role else 5,
                    "immutable": False,
                },
                "created_by": created_by,
                "updated_by": created_by,
            }

            role = Role(**role_data)
            role.validate_role_data()

            # Save role
            created_role = await self.role_repository.create(role_data)

            logger.info(
                "Role created",
                role_id=str(created_role.id),
                name=name,
                display_name=display_name,
                created_by=created_by,
                permission_count=len(permissions or []),
            )

            return created_role

        except Exception as e:
            logger.error("Failed to create role", name=name, error=str(e))
            raise

    async def update_role(
        self,
        role_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        updated_by: str = "system",
    ) -> Role:
        """Update an existing role.

        Args:
            role_id: Role identifier
            display_name: New display name
            description: New description
            permissions: New permission list
            is_active: New active status
            updated_by: Who is updating the role

        Returns:
            Updated Role instance
        """
        try:
            role = await self.role_repository.get(role_id)
            if not role:
                raise NotFoundError(message=f"Role {role_id} not found")

            if role.is_immutable:
                raise ForbiddenError(message="Cannot modify immutable role")

            # Build update data
            update_data = {"updated_by": updated_by}

            if display_name is not None:
                update_data["display_name"] = display_name

            if description is not None:
                update_data["description"] = description

            if is_active is not None:
                update_data["is_active"] = is_active

            if permissions is not None:
                # Validate permissions first
                temp_metadata = {**role.role_metadata, "permissions": permissions}
                temp_role = Role(name="temp", display_name="temp", role_metadata=temp_metadata)
                temp_role.validate_role_data()

                update_data["role_metadata"] = {**role.role_metadata, "permissions": permissions}

            # Update role
            updated_role = await self.role_repository.update(role_id, update_data)

            logger.info("Role updated", role_id=role_id, updated_by=updated_by, changes=list(update_data.keys()))

            return updated_role

        except Exception as e:
            logger.error("Failed to update role", role_id=role_id, error=str(e))
            raise

    async def delete_role(self, role_id: str, deleted_by: str = "system") -> bool:
        """Delete a role (soft delete).

        Args:
            role_id: Role identifier
            deleted_by: Who is deleting the role

        Returns:
            True if role was deleted
        """
        try:
            role = await self.role_repository.get(role_id)
            if not role:
                raise NotFoundError(message=f"Role {role_id} not found")

            if role.is_immutable:
                raise ForbiddenError(message="Cannot delete immutable role")

            # Check if role is assigned to any users
            assignments = await self.role_repository.get_role_assignments(
                role_id, include_inactive=False, include_expired=False
            )

            if assignments:
                raise ValidationError(message=f"Cannot delete role with {len(assignments)} active assignments")

            # Soft delete the role
            success = await self.role_repository.delete(role_id, deleted_by)

            if success:
                logger.info("Role deleted", role_id=role_id, name=role.name, deleted_by=deleted_by)

            return success

        except Exception as e:
            logger.error("Failed to delete role", role_id=role_id, error=str(e))
            raise

    async def assign_role_to_user(
        self,
        user_id: str,
        role_id: str,
        assigned_by: str,
        expires_at: Optional[datetime] = None,
        reason: Optional[str] = None,
        context: Optional[str] = None,
    ) -> UserRole:
        """Assign a role to a user.

        Args:
            user_id: User identifier
            role_id: Role identifier
            assigned_by: Who is making the assignment
            expires_at: Optional expiration date
            reason: Optional reason for assignment
            context: Optional context

        Returns:
            UserRole assignment record
        """
        try:
            # Validate role exists and is active
            role = await self.role_repository.get(role_id)
            if not role:
                raise NotFoundError(message=f"Role {role_id} not found")

            if not role.is_active:
                raise ValidationError(message="Cannot assign inactive role")

            # TODO: Validate user exists when User repository is available

            # Create assignment
            assignment = await self.role_repository.assign_role_to_user(
                user_id=user_id,
                role_id=role_id,
                assigned_by=assigned_by,
                expires_at=expires_at,
                reason=reason,
                context=context,
            )

            return assignment

        except Exception as e:
            logger.error("Failed to assign role to user", user_id=user_id, role_id=role_id, error=str(e))
            raise

    async def revoke_role_from_user(
        self, user_id: str, role_id: str, revoked_by: str, reason: Optional[str] = None
    ) -> bool:
        """Revoke a role from a user.

        Args:
            user_id: User identifier
            role_id: Role identifier
            revoked_by: Who is revoking the assignment
            reason: Optional reason for revocation

        Returns:
            True if role was revoked
        """
        try:
            success = await self.role_repository.revoke_role_from_user(
                user_id=user_id, role_id=role_id, revoked_by=revoked_by, reason=reason
            )

            return success

        except Exception as e:
            logger.error("Failed to revoke role from user", user_id=user_id, role_id=role_id, error=str(e))
            raise

    async def get_user_roles(self, user_id: str, include_expired: bool = False) -> List[Role]:
        """Get all roles assigned to a user.

        Args:
            user_id: User identifier
            include_expired: Whether to include expired assignments

        Returns:
            List of roles assigned to the user
        """
        try:
            roles = await self.role_repository.get_user_roles(user_id, include_expired)
            return roles

        except Exception as e:
            logger.error("Failed to get user roles", user_id=user_id, error=str(e))
            raise

    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all effective permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            Set of permission strings
        """
        try:
            # Get user's roles
            user_roles = await self.get_user_roles(user_id, include_expired=False)

            # Collect all permissions from roles
            all_permissions = set()
            for role in user_roles:
                role_permissions = role.get_effective_permissions()
                all_permissions.update(role_permissions)

            logger.debug(
                "User permissions collected",
                user_id=user_id,
                role_count=len(user_roles),
                permission_count=len(all_permissions),
            )

            return all_permissions

        except Exception as e:
            logger.error("Failed to get user permissions", user_id=user_id, error=str(e))
            raise

    async def check_user_permission(self, user_id: str, permission: str) -> bool:
        """Check if a user has a specific permission.

        Args:
            user_id: User identifier
            permission: Permission string to check

        Returns:
            True if user has the permission
        """
        try:
            user_permissions = await self.get_user_permissions(user_id)

            # Check for exact match
            if permission in user_permissions:
                return True

            # Check for wildcard permissions
            if "*" in user_permissions:
                return True

            # Check for resource-level wildcards
            if ":" in permission:
                resource, action = permission.split(":", 1)
                if f"{resource}:*" in user_permissions:
                    return True

                # Check for scoped permissions (e.g., "users:read:own" vs "users:read")
                if ":" in action:
                    base_permission = f"{resource}:{action.split(':', 1)[0]}"
                    if base_permission in user_permissions:
                        return True

            logger.debug("User permission checked", user_id=user_id, permission=permission, has_permission=False)
            return False

        except Exception as e:
            logger.error("Failed to check user permission", user_id=user_id, permission=permission, error=str(e))
            # Default to deny on error
            return False

    async def get_role_assignments_for_user(self, user_id: str) -> List[UserRole]:
        """Get detailed role assignment information for a user.

        Args:
            user_id: User identifier

        Returns:
            List of UserRole assignment records
        """
        try:
            user_uuid = uuid.UUID(user_id)

            # Get all assignments for the user
            from sqlalchemy import and_, select

            query = (
                select(UserRole)
                .where(and_(UserRole.user_id == user_uuid, UserRole.is_active == True))  # noqa: E712
                .order_by(UserRole.assigned_at.desc())
            )

            result = await self.session.execute(query)
            assignments = list(result.scalars().all())

            logger.debug("User role assignments retrieved", user_id=user_id, assignment_count=len(assignments))

            return assignments

        except Exception as e:
            logger.error("Failed to get user role assignments", user_id=user_id, error=str(e))
            raise

    async def get_users_with_role(self, role_id: str) -> List[UserRole]:
        """Get all users assigned to a specific role.

        Args:
            role_id: Role identifier

        Returns:
            List of UserRole assignment records
        """
        try:
            assignments = await self.role_repository.get_role_assignments(
                role_id, include_inactive=False, include_expired=False
            )

            return assignments

        except Exception as e:
            logger.error("Failed to get users with role", role_id=role_id, error=str(e))
            raise

    async def bulk_assign_roles(
        self,
        user_id: str,
        role_ids: List[str],
        assigned_by: str,
        expires_at: Optional[datetime] = None,
        reason: Optional[str] = None,
    ) -> List[UserRole]:
        """Assign multiple roles to a user in a single operation.

        Args:
            user_id: User identifier
            role_ids: List of role identifiers
            assigned_by: Who is making the assignments
            expires_at: Optional expiration date for all assignments
            reason: Optional reason for assignments

        Returns:
            List of UserRole assignment records
        """
        try:
            assignments = []

            for role_id in role_ids:
                try:
                    assignment = await self.assign_role_to_user(
                        user_id=user_id,
                        role_id=role_id,
                        assigned_by=assigned_by,
                        expires_at=expires_at,
                        reason=reason,
                        context="bulk_assignment",
                    )
                    assignments.append(assignment)
                except Exception as e:
                    logger.warning(
                        "Failed to assign role in bulk operation", user_id=user_id, role_id=role_id, error=str(e)
                    )
                    # Continue with other assignments

            logger.info(
                "Bulk role assignment completed",
                user_id=user_id,
                requested_roles=len(role_ids),
                successful_assignments=len(assignments),
                assigned_by=assigned_by,
            )

            return assignments

        except Exception as e:
            logger.error("Failed to bulk assign roles", user_id=user_id, error=str(e))
            raise

    async def get_role_hierarchy(self, role_id: str) -> Dict[str, Any]:
        """Get role hierarchy information.

        Args:
            role_id: Role identifier

        Returns:
            Dictionary with hierarchy information
        """
        try:
            hierarchy = await self.role_repository.get_role_hierarchy(role_id)
            return hierarchy

        except Exception as e:
            logger.error("Failed to get role hierarchy", role_id=role_id, error=str(e))
            raise

    async def get_system_roles(self) -> List[Role]:
        """Get all system roles.

        Returns:
            List of system roles
        """
        try:
            roles = await self.role_repository.get_system_roles(include_inactive=False)
            return roles

        except Exception as e:
            logger.error("Failed to get system roles", error=str(e))
            raise

    async def get_custom_roles(self) -> List[Role]:
        """Get all custom roles.

        Returns:
            List of custom roles
        """
        try:
            roles = await self.role_repository.get_custom_roles(include_inactive=False)
            return roles

        except Exception as e:
            logger.error("Failed to get custom roles", error=str(e))
            raise

    async def get_rbac_statistics(self) -> Dict[str, Any]:
        """Get RBAC system statistics.

        Returns:
            Dictionary with RBAC statistics
        """
        try:
            stats = await self.role_repository.get_statistics()

            # Add permission-related stats when Permission repository is available
            stats["permission_checks_24h"] = 0  # TODO: Implement with audit logging
            stats["most_assigned_role"] = None  # TODO: Calculate from assignments

            return stats

        except Exception as e:
            logger.error("Failed to get RBAC statistics", error=str(e))
            raise

    async def validate_role_assignment(self, user_id: str, role_id: str, assigned_by: str) -> Tuple[bool, str]:
        """Validate if a role assignment is allowed.

        Args:
            user_id: User identifier
            role_id: Role identifier
            assigned_by: Who wants to make the assignment

        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # Check if role exists and is active
            role = await self.role_repository.get(role_id)
            if not role:
                return False, f"Role {role_id} does not exist"

            if not role.is_active:
                return False, "Role is not active"

            # TODO: Check if assigned_by has permission to assign this role
            # This would require checking if assigned_by has "roles:assign" permission
            # or can manage the specific role based on hierarchy

            # Check if user already has this role
            user_roles = await self.get_user_roles(user_id, include_expired=False)
            if any(r.id == role.id for r in user_roles):
                return False, "User already has this role"

            return True, "Assignment is valid"

        except Exception as e:
            logger.error("Failed to validate role assignment", user_id=user_id, role_id=role_id, error=str(e))
            return False, f"Validation error: {str(e)}"

    async def cleanup_expired_assignments(self) -> int:
        """Clean up expired role assignments.

        Returns:
            Number of assignments cleaned up
        """
        try:
            from sqlalchemy import and_, update

            # Mark expired assignments as inactive
            update_query = (
                update(UserRole)
                .where(
                    and_(UserRole.expires_at <= datetime.now(timezone.utc), UserRole.is_active == True)
                )  # noqa: E712
                .values(is_active=False, updated_at=datetime.now(timezone.utc), updated_by="system_cleanup")
            )

            result = await self.session.execute(update_query)
            cleaned_count = result.rowcount

            if cleaned_count > 0:
                await self.session.commit()
                logger.info("Expired role assignments cleaned up", count=cleaned_count)

            return cleaned_count

        except Exception as e:
            await self.session.rollback()
            logger.error("Failed to cleanup expired assignments", error=str(e))
            raise

    async def can_manage_user_roles(self, manager_id: str, target_user_id: str) -> bool:
        """Check if a manager can manage another user's roles based on hierarchy.

        Args:
            manager_id: ID of the manager user
            target_user_id: ID of the target user

        Returns:
            True if manager can manage target user's roles
        """
        try:
            # Get manager's roles
            manager_roles = await self.get_user_roles(manager_id)
            if not manager_roles:
                return False

            # Get target user's roles
            target_roles = await self.get_user_roles(target_user_id)
            if not target_roles:
                return True  # Can manage users with no roles

            # Find highest level role for manager
            manager_max_level = max(role.role_metadata.get("level", 0) for role in manager_roles)

            # Find highest level role for target
            target_max_level = max(role.role_metadata.get("level", 0) for role in target_roles)

            # Manager can only manage users with lower hierarchy level
            return manager_max_level > target_max_level

        except Exception as e:
            logger.error(
                "Failed to check role management permission",
                manager_id=manager_id,
                target_user_id=target_user_id,
                error=str(e),
            )
            return False

    async def check_organization_permission(
        self,
        user_id: str,
        permission: str,
        organization_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
    ) -> bool:
        """Check if user has permission with organization and ownership context.

        This method provides secure multi-tenant permission validation by:
        1. Checking basic permission (resource:action or resource:action:scope)
        2. Validating organization context for :own scoped permissions
        3. Ensuring ownership validation for :own scoped permissions

        Args:
            user_id: User requesting access
            permission: Permission string (e.g., "users:read:own", "users:write")
            organization_id: Organization context from JWT
            resource_owner_id: Owner of the resource being accessed (for :own scoped permissions)

        Returns:
            True if user has permission with proper organization/ownership validation
        """
        try:
            # First check basic permission without scope
            base_permissions = await self.get_user_permissions(user_id)

            # Check for global admin permission
            if "*" in base_permissions:
                return True

            # Parse permission format: resource:action or resource:action:scope
            parts = permission.split(":")
            if len(parts) < 2:
                logger.warning("Invalid permission format", permission=permission)
                return False

            resource = parts[0]
            action = parts[1]
            scope = parts[2] if len(parts) >= 3 else None

            # Check for exact permission match
            if permission in base_permissions:
                # If it's an :own scoped permission, validate ownership
                if scope == "own":
                    return await self._validate_ownership_context(user_id, resource_owner_id, organization_id)
                return True

            # Check for resource wildcard (e.g., users:*)
            resource_wildcard = f"{resource}:*"
            if resource_wildcard in base_permissions:
                # If requesting :own scope, validate ownership
                if scope == "own":
                    return await self._validate_ownership_context(user_id, resource_owner_id, organization_id)
                return True

            # Check for scoped wildcard (e.g., api_keys:*:own matching api_keys:write:own)
            if scope:
                scoped_wildcard = f"{resource}:*:{scope}"
                if scoped_wildcard in base_permissions:
                    # If requesting :own scope, validate ownership
                    if scope == "own":
                        return await self._validate_ownership_context(user_id, resource_owner_id, organization_id)
                    return True

            # Check for broader permissions (e.g., users:read covers users:read:own)
            if scope:
                broader_permission = f"{resource}:{action}"
                if broader_permission in base_permissions:
                    return True

            return False

        except Exception as e:
            logger.error(
                "Failed to check organization permission",
                user_id=user_id,
                permission=permission,
                organization_id=organization_id,
                error=str(e),
            )
            return False

    async def _validate_ownership_context(
        self,
        user_id: str,
        resource_owner_id: Optional[str],
        organization_id: Optional[str],
    ) -> bool:
        """Validate ownership context for :own scoped permissions.

        Args:
            user_id: User requesting access
            resource_owner_id: Owner of the resource being accessed
            organization_id: Organization context from JWT

        Returns:
            True if ownership validation passes
        """
        try:
            # Must have organization context for multi-tenant validation
            if not organization_id:
                logger.warning(
                    "Missing organization context for ownership validation",
                    user_id=user_id,
                    resource_owner_id=resource_owner_id,
                )
                return False

            # Must have resource owner for ownership validation
            if not resource_owner_id:
                logger.warning(
                    "Missing resource owner for ownership validation",
                    user_id=user_id,
                    organization_id=organization_id,
                )
                return False

            # User must own the resource
            if str(user_id) != str(resource_owner_id):
                logger.debug(
                    "Ownership validation failed - user does not own resource",
                    user_id=user_id,
                    resource_owner_id=resource_owner_id,
                    organization_id=organization_id,
                )
                return False

            # Verify both user and resource belong to the same organization
            user = await self.user_repository.get_by_id(user_id, organization_id)
            if not user:
                logger.warning(
                    "User not found in specified organization",
                    user_id=user_id,
                    organization_id=organization_id,
                )
                return False

            # If resource owner is different from user, verify they're in same organization
            if str(user_id) != str(resource_owner_id):
                resource_owner = await self.user_repository.get_by_id(resource_owner_id, organization_id)
                if not resource_owner:
                    logger.warning(
                        "Resource owner not found in specified organization",
                        resource_owner_id=resource_owner_id,
                        organization_id=organization_id,
                    )
                    return False

            return True

        except Exception as e:
            logger.error(
                "Failed to validate ownership context",
                user_id=user_id,
                resource_owner_id=resource_owner_id,
                organization_id=organization_id,
                error=str(e),
            )
            return False
