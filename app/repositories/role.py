"""Role repository for RBAC system."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.models.role import Role
from app.models.user_role import UserRole
from app.repositories.base import BaseRepository

logger = get_logger(__name__)


class RoleRepository(BaseRepository[Role]):
    """Repository for role management operations."""

    def __init__(self, session: AsyncSession):
        """Initialize role repository."""
        super().__init__(session, Role)

    async def get_by_name(self, name: str) -> Optional[Role]:
        """Get role by name.

        Args:
            name: Role name

        Returns:
            Role if found, None otherwise
        """
        try:
            query = select(self.model).where(
                and_(self.model.name == name, self.model.is_deleted == False)  # noqa: E712
            )
            result = await self.session.execute(query)
            role = result.scalar_one_or_none()

            if role:
                logger.debug("Role found by name", name=name, role_id=str(role.id))
            else:
                logger.debug("Role not found by name", name=name)

            return role

        except Exception as e:
            logger.error("Failed to get role by name", name=name, error=str(e))
            raise

    async def get_system_roles(self, include_inactive: bool = False) -> List[Role]:
        """Get all system roles.

        Args:
            include_inactive: Whether to include inactive roles

        Returns:
            List of system roles
        """
        try:
            conditions = [self.model.is_system_role == True, self.model.is_deleted == False]  # noqa: E712  # noqa: E712

            if not include_inactive:
                conditions.append(self.model.is_active == True)  # noqa: E712

            query = (
                select(self.model)
                .where(and_(*conditions))
                .order_by(self.model.metadata["level"].astext.cast(self.session.bind.dialect.INTEGER))
            )

            result = await self.session.execute(query)
            roles = list(result.scalars().all())

            logger.debug("System roles retrieved", count=len(roles), include_inactive=include_inactive)
            return roles

        except Exception as e:
            logger.error("Failed to get system roles", error=str(e))
            raise

    async def get_custom_roles(self, include_inactive: bool = False) -> List[Role]:
        """Get all custom (non-system) roles.

        Args:
            include_inactive: Whether to include inactive roles

        Returns:
            List of custom roles
        """
        try:
            conditions = [
                self.model.is_system_role == False,  # noqa: E712
                self.model.is_deleted == False,  # noqa: E712
            ]

            if not include_inactive:
                conditions.append(self.model.is_active == True)  # noqa: E712

            query = select(self.model).where(and_(*conditions)).order_by(self.model.display_name)

            result = await self.session.execute(query)
            roles = list(result.scalars().all())

            logger.debug("Custom roles retrieved", count=len(roles), include_inactive=include_inactive)
            return roles

        except Exception as e:
            logger.error("Failed to get custom roles", error=str(e))
            raise

    async def get_user_roles(self, user_id: str, include_expired: bool = False) -> List[Role]:
        """Get all roles assigned to a user.

        Args:
            user_id: User identifier
            include_expired: Whether to include expired role assignments

        Returns:
            List of roles assigned to the user
        """
        try:
            user_uuid = uuid.UUID(user_id)

            # Build query conditions
            conditions = [
                UserRole.user_id == user_uuid,
                UserRole.is_active == True,  # noqa: E712
                Role.is_deleted == False,  # noqa: E712
                Role.is_active == True,  # noqa: E712
            ]

            if not include_expired:
                conditions.append(or_(UserRole.expires_at.is_(None), UserRole.expires_at > datetime.now(timezone.utc)))

            query = (
                select(Role)
                .join(UserRole, Role.id == UserRole.role_id)
                .where(and_(*conditions))
                .order_by(Role.metadata["level"].astext.cast(self.session.bind.dialect.INTEGER))
            )

            result = await self.session.execute(query)
            roles = list(result.scalars().all())

            logger.debug("User roles retrieved", user_id=str(user_uuid), count=len(roles))
            return roles

        except Exception as e:
            logger.error("Failed to get user roles", user_id=user_id, error=str(e))
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
            context: Optional context (e.g., "promotion", "project")

        Returns:
            UserRole assignment record

        Raises:
            ValueError: If role assignment is invalid
        """
        try:
            user_uuid = uuid.UUID(user_id)
            role_uuid = uuid.UUID(role_id)

            # Check if assignment already exists
            existing_query = select(UserRole).where(
                and_(
                    UserRole.user_id == user_uuid,
                    UserRole.role_id == role_uuid,
                    UserRole.is_active == True,  # noqa: E712
                )
            )
            result = await self.session.execute(existing_query)
            existing_assignment = result.scalar_one_or_none()

            if existing_assignment:
                if not existing_assignment.is_expired():
                    raise ValueError(f"User already has active assignment for role {role_id}")
                else:
                    # Reactivate expired assignment
                    existing_assignment.is_active = True
                    existing_assignment.expires_at = expires_at
                    existing_assignment.assigned_by = assigned_by
                    existing_assignment.assigned_at = datetime.now(timezone.utc)
                    existing_assignment.assignment_reason = reason
                    existing_assignment.assignment_context = context
                    existing_assignment.updated_by = assigned_by
                    existing_assignment.updated_at = datetime.now(timezone.utc)

                    logger.info(
                        "Role assignment reactivated",
                        user_id=str(user_uuid),
                        role_id=str(role_uuid),
                        assigned_by=assigned_by,
                    )
                    return existing_assignment

            # Create new assignment
            assignment_data = {
                "user_id": user_uuid,
                "role_id": role_uuid,
                "assigned_by": assigned_by,
                "assigned_at": datetime.now(timezone.utc),
                "expires_at": expires_at,
                "assignment_reason": reason,
                "assignment_context": context,
                "created_by": assigned_by,
                "updated_by": assigned_by,
            }

            assignment = UserRole(**assignment_data)
            assignment.validate_assignment()

            self.session.add(assignment)
            await self.session.flush()  # Get the ID

            logger.info(
                "Role assigned to user",
                user_id=str(user_uuid),
                role_id=str(role_uuid),
                assignment_id=str(assignment.id),
                assigned_by=assigned_by,
                expires_at=expires_at.isoformat() if expires_at else None,
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
            True if role was revoked, False if not found
        """
        try:
            user_uuid = uuid.UUID(user_id)
            role_uuid = uuid.UUID(role_id)

            # Find active assignment
            query = select(UserRole).where(
                and_(
                    UserRole.user_id == user_uuid,
                    UserRole.role_id == role_uuid,
                    UserRole.is_active == True,  # noqa: E712
                )
            )
            result = await self.session.execute(query)
            assignment = result.scalar_one_or_none()

            if not assignment:
                logger.warning(
                    "No active role assignment found to revoke", user_id=str(user_uuid), role_id=str(role_uuid)
                )
                return False

            # Revoke the assignment
            assignment.revoke(revoked_by, reason)

            logger.info(
                "Role revoked from user",
                user_id=str(user_uuid),
                role_id=str(role_uuid),
                assignment_id=str(assignment.id),
                revoked_by=revoked_by,
                reason=reason,
            )

            return True

        except Exception as e:
            logger.error("Failed to revoke role from user", user_id=user_id, role_id=role_id, error=str(e))
            raise

    async def get_role_assignments(
        self, role_id: str, include_inactive: bool = False, include_expired: bool = False
    ) -> List[UserRole]:
        """Get all assignments for a specific role.

        Args:
            role_id: Role identifier
            include_inactive: Whether to include inactive assignments
            include_expired: Whether to include expired assignments

        Returns:
            List of role assignments
        """
        try:
            role_uuid = uuid.UUID(role_id)

            conditions = [UserRole.role_id == role_uuid]

            if not include_inactive:
                conditions.append(UserRole.is_active == True)  # noqa: E712

            if not include_expired:
                conditions.append(or_(UserRole.expires_at.is_(None), UserRole.expires_at > datetime.now(timezone.utc)))

            query = select(UserRole).where(and_(*conditions)).order_by(UserRole.assigned_at.desc())

            result = await self.session.execute(query)
            assignments = list(result.scalars().all())

            logger.debug(
                "Role assignments retrieved",
                role_id=str(role_uuid),
                count=len(assignments),
                include_inactive=include_inactive,
                include_expired=include_expired,
            )
            return assignments

        except Exception as e:
            logger.error("Failed to get role assignments", role_id=role_id, error=str(e))
            raise

    async def create_system_roles(self) -> List[Role]:
        """Create default system roles if they don't exist.

        Returns:
            List of created system roles
        """
        try:
            system_roles = Role.create_system_roles()
            created_roles = []

            for role in system_roles:
                # Check if role already exists
                existing = await self.get_by_name(role.name)
                if not existing:
                    role.validate_role_data()
                    self.session.add(role)
                    created_roles.append(role)
                    logger.info("System role created", name=role.name, display_name=role.display_name)
                else:
                    logger.debug("System role already exists", name=role.name)

            if created_roles:
                await self.session.flush()

            logger.info("System roles initialization completed", created_count=len(created_roles))
            return created_roles

        except Exception as e:
            logger.error("Failed to create system roles", error=str(e))
            raise

    async def get_role_hierarchy(self, role_id: str) -> Dict[str, Any]:
        """Get role hierarchy information.

        Args:
            role_id: Role identifier

        Returns:
            Dictionary with hierarchy information
        """
        try:
            role_uuid = uuid.UUID(role_id)
            role = await self.get(role_uuid)

            if not role:
                raise ValueError(f"Role {role_id} not found")

            # TODO: Implement full hierarchy traversal when parent_role_id is used
            hierarchy = {
                "role": role.to_dict(),
                "level": role.metadata.get("level", 999),
                "parent": None,
                "children": [],
                "ancestors": [],
                "descendants": [],
            }

            return hierarchy

        except Exception as e:
            logger.error("Failed to get role hierarchy", role_id=role_id, error=str(e))
            raise

    async def get_roles_with_permission(self, permission: str) -> List[Role]:
        """Get all roles that have a specific permission.

        Args:
            permission: Permission string to search for

        Returns:
            List of roles with the permission
        """
        try:
            # Get all active roles
            query = select(self.model).where(
                and_(self.model.is_active == True, self.model.is_deleted == False)  # noqa: E712  # noqa: E712
            )

            result = await self.session.execute(query)
            all_roles = list(result.scalars().all())

            # Filter roles that have the permission
            matching_roles = []
            for role in all_roles:
                if role.has_permission(permission):
                    matching_roles.append(role)

            logger.debug("Roles with permission found", permission=permission, count=len(matching_roles))
            return matching_roles

        except Exception as e:
            logger.error("Failed to get roles with permission", permission=permission, error=str(e))
            raise

    async def get_statistics(self) -> Dict[str, Any]:
        """Get role-related statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            # Total roles
            total_query = select(func.count(self.model.id)).where(self.model.is_deleted == False)  # noqa: E712
            total_result = await self.session.execute(total_query)
            total_roles = total_result.scalar() or 0

            # Active roles
            active_query = select(func.count(self.model.id)).where(
                and_(self.model.is_active == True, self.model.is_deleted == False)  # noqa: E712  # noqa: E712
            )
            active_result = await self.session.execute(active_query)
            active_roles = active_result.scalar() or 0

            # System roles
            system_query = select(func.count(self.model.id)).where(
                and_(self.model.is_system_role == True, self.model.is_deleted == False)  # noqa: E712  # noqa: E712
            )
            system_result = await self.session.execute(system_query)
            system_roles = system_result.scalar() or 0

            # Role assignments
            assignments_query = select(func.count(UserRole.id)).where(UserRole.is_active == True)  # noqa: E712
            assignments_result = await self.session.execute(assignments_query)
            total_assignments = assignments_result.scalar() or 0

            # Active assignments (not expired)
            active_assignments_query = select(func.count(UserRole.id)).where(
                and_(
                    UserRole.is_active == True,  # noqa: E712
                    or_(UserRole.expires_at.is_(None), UserRole.expires_at > datetime.now(timezone.utc)),
                )
            )
            active_assignments_result = await self.session.execute(active_assignments_query)
            active_assignments = active_assignments_result.scalar() or 0

            statistics = {
                "total_roles": total_roles,
                "active_roles": active_roles,
                "system_roles": system_roles,
                "custom_roles": total_roles - system_roles,
                "total_assignments": total_assignments,
                "active_assignments": active_assignments,
                "expired_assignments": total_assignments - active_assignments,
            }

            return statistics

        except Exception as e:
            logger.error("Failed to get role statistics", error=str(e))
            raise

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

    async def cleanup_expired_assignments(self) -> int:
        """Clean up expired role assignments.

        Returns:
            Number of assignments cleaned up
        """
        try:
            from sqlalchemy import update

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
                logger.info("Expired role assignments cleaned up", count=cleaned_count)

            return cleaned_count

        except Exception as e:
            logger.error("Failed to cleanup expired assignments", error=str(e))
            raise
