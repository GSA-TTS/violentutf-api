"""
Authority Level System - Replaces boolean is_superuser flag

This module provides a hierarchical authority system that replaces the simple
boolean is_superuser flag with a proper role-based hierarchy and authority
level determination.

Design Principles:
- Authority levels are derived from roles, not boolean flags
- Clear hierarchy with well-defined privilege levels
- Extensible authority calculation
- Secure fallback to lowest privilege
- Comprehensive authority evaluation
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.models.user import User

logger = get_logger(__name__)


class AuthorityLevel(Enum):
    """Hierarchical authority levels (replacing is_superuser boolean)."""

    # System-level authorities (highest privilege)
    GLOBAL_ADMIN = ("global_admin", 0, "Global system administrator with all permissions")
    SUPER_ADMIN = ("super_admin", 0, "Super administrator (deprecated, use global_admin)")

    # Administrative authorities
    ADMIN = ("admin", 10, "Organization administrator")
    USER_MANAGER = ("user_manager", 20, "User management authority")
    API_MANAGER = ("api_manager", 20, "API and integration management authority")

    # Standard authorities
    TESTER = ("tester", 30, "Testing and quality assurance authority")
    VIEWER = ("viewer", 40, "Read-only access authority")

    # Basic authorities (lowest privilege)
    USER = ("user", 50, "Standard user authority")
    GUEST = ("guest", 60, "Limited guest access")
    NONE = ("none", 100, "No authority (default)")

    def __init__(self, level_name: str, priority: int, description: str):
        """Initialize authority level.

        Args:
            level_name: Human-readable level name
            priority: Priority number (lower = higher authority)
            description: Description of authority level
        """
        self.level_name = level_name
        self.priority = priority
        self.description = description

    def __lt__(self, other: "AuthorityLevel") -> bool:
        """Compare authority levels by priority."""
        return self.priority < other.priority

    def __le__(self, other: "AuthorityLevel") -> bool:
        """Compare authority levels by priority (less than or equal)."""
        return self.priority <= other.priority

    def __gt__(self, other: "AuthorityLevel") -> bool:
        """Compare authority levels by priority."""
        return self.priority > other.priority

    def __ge__(self, other: "AuthorityLevel") -> bool:
        """Compare authority levels by priority (greater than or equal)."""
        return self.priority >= other.priority

    def can_manage(self, other: "AuthorityLevel") -> bool:
        """Check if this authority level can manage another authority level."""
        return self.priority < other.priority

    def has_system_access(self) -> bool:
        """Check if this authority level has system-level access."""
        return self.priority <= 0

    def has_admin_access(self) -> bool:
        """Check if this authority level has administrative access."""
        return self.priority <= 10

    def has_management_access(self) -> bool:
        """Check if this authority level has management access."""
        return self.priority <= 20

    @classmethod
    def from_string(cls, level_str: str) -> "AuthorityLevel":
        """Parse authority level from string."""
        for level in cls:
            if level.level_name == level_str:
                return level
        return cls.NONE


class AuthorityEvaluator:
    """Evaluates user authority levels based on roles and permissions."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize authority evaluator.

        Args:
            session: Database session for dynamic evaluation
        """
        self.session = session

    async def evaluate_user_authority(
        self,
        user: User,
        permissions: Optional[Set[str]] = None,
    ) -> AuthorityLevel:
        """Evaluate user's authority level based on roles and permissions.

        This replaces the simple is_superuser boolean with comprehensive
        authority level calculation.

        Args:
            user: User model instance
            permissions: Pre-loaded user permissions (optional)

        Returns:
            User's authority level
        """
        try:
            # Load permissions if not provided
            if permissions is None and self.session:
                from app.services.rbac_service import RBACService

                rbac_service = RBACService(self.session)
                permissions = await rbac_service.get_user_permissions(str(user.id))
            elif permissions is None:
                permissions = set()

            # Check for global administrative permissions
            if "*" in permissions:
                logger.debug(
                    "User has global admin authority", user_id=str(user.id), reason="global_wildcard_permission"
                )
                return AuthorityLevel.GLOBAL_ADMIN

            # Check for system-level role assignments
            user_roles = set(user.roles) if user.roles else set()

            # Map roles to authority levels (in priority order)
            role_authority_map = {
                "super_admin": AuthorityLevel.SUPER_ADMIN,
                "global_admin": AuthorityLevel.GLOBAL_ADMIN,
                "admin": AuthorityLevel.ADMIN,
                "user_manager": AuthorityLevel.USER_MANAGER,
                "api_manager": AuthorityLevel.API_MANAGER,
                "tester": AuthorityLevel.TESTER,
                "viewer": AuthorityLevel.VIEWER,
                "user": AuthorityLevel.USER,
                "guest": AuthorityLevel.GUEST,
            }

            # Find highest authority level from roles
            highest_authority = AuthorityLevel.NONE
            for role in user_roles:
                if role in role_authority_map:
                    role_authority = role_authority_map[role]
                    if role_authority < highest_authority:
                        highest_authority = role_authority

            # Check for permission-based authority elevation
            authority_from_permissions = self._evaluate_permission_authority(permissions)
            if authority_from_permissions < highest_authority:
                highest_authority = authority_from_permissions

            # Special handling for deprecated is_superuser flag
            # This provides backward compatibility while we transition
            if hasattr(user, "is_superuser") and user.is_superuser:
                logger.warning(
                    "Deprecated is_superuser flag detected - upgrading to admin authority",
                    user_id=str(user.id),
                    current_authority=highest_authority.level_name,
                )
                if highest_authority > AuthorityLevel.ADMIN:
                    highest_authority = AuthorityLevel.ADMIN

            logger.debug(
                "User authority evaluated",
                user_id=str(user.id),
                authority_level=highest_authority.level_name,
                roles=list(user_roles),
                permission_count=len(permissions),
            )

            return highest_authority

        except Exception as e:
            logger.error("Failed to evaluate user authority", user_id=str(user.id), error=str(e))
            # Fail-secure: return lowest authority on error
            return AuthorityLevel.NONE

    def _evaluate_permission_authority(self, permissions: Set[str]) -> AuthorityLevel:
        """Evaluate authority level based on permissions.

        Args:
            permissions: Set of user permissions

        Returns:
            Authority level inferred from permissions
        """
        # Global wildcard = global admin
        if "*" in permissions:
            return AuthorityLevel.GLOBAL_ADMIN

        # Count permission scopes to determine authority
        admin_permissions = {"users:*", "api_keys:*", "sessions:*", "roles:*", "permissions:*"}
        management_permissions = {"users:write", "users:delete", "api_keys:write", "api_keys:delete"}

        # Check for administrative permission patterns
        if any(perm in permissions for perm in admin_permissions):
            return AuthorityLevel.ADMIN

        if any(perm in permissions for perm in management_permissions):
            return AuthorityLevel.USER_MANAGER

        # Check for read permissions (viewer level)
        read_permissions = {"users:read", "api_keys:read", "sessions:read", "audit_logs:read"}
        if any(perm in permissions for perm in read_permissions):
            return AuthorityLevel.VIEWER

        # Check for own-scoped permissions (user level)
        own_permissions = {perm for perm in permissions if perm.endswith(":own")}
        if own_permissions:
            return AuthorityLevel.USER

        return AuthorityLevel.NONE

    async def can_user_manage_user(
        self,
        manager_user: User,
        target_user: User,
        manager_permissions: Optional[Set[str]] = None,
        target_permissions: Optional[Set[str]] = None,
    ) -> Tuple[bool, str]:
        """Check if manager user can manage target user.

        Args:
            manager_user: User attempting to manage
            target_user: User being managed
            manager_permissions: Manager's permissions (optional)
            target_permissions: Target's permissions (optional)

        Returns:
            Tuple of (can_manage, reason)
        """
        try:
            # Evaluate authority levels
            manager_authority = await self.evaluate_user_authority(manager_user, manager_permissions)
            target_authority = await self.evaluate_user_authority(target_user, target_permissions)

            # Global admins can manage anyone except other global admins
            if manager_authority == AuthorityLevel.GLOBAL_ADMIN:
                if target_authority == AuthorityLevel.GLOBAL_ADMIN:
                    return False, "Cannot manage other global administrators"
                return True, f"{manager_authority.level_name} can manage {target_authority.level_name}"

            # Authority hierarchy check
            if manager_authority.can_manage(target_authority):
                return True, f"{manager_authority.level_name} can manage {target_authority.level_name}"
            else:
                return False, f"{manager_authority.level_name} cannot manage {target_authority.level_name}"

        except Exception as e:
            logger.error(
                "Failed to check user management authority",
                manager_id=str(manager_user.id),
                target_id=str(target_user.id),
                error=str(e),
            )
            return False, "Authority evaluation failed"

    def get_authority_capabilities(self, authority_level: AuthorityLevel) -> Dict[str, Any]:
        """Get capabilities associated with an authority level.

        Args:
            authority_level: Authority level to check

        Returns:
            Dictionary of capabilities
        """
        capabilities = {
            "authority_level": authority_level.level_name,
            "priority": authority_level.priority,
            "description": authority_level.description,
            "can_access_system": authority_level.has_system_access(),
            "can_administer": authority_level.has_admin_access(),
            "can_manage_users": authority_level.has_management_access(),
            "can_manage_apis": authority_level.priority <= 20,
            "can_view_audit_logs": authority_level.priority <= 40,
            "can_manage_own_resources": authority_level.priority <= 50,
        }

        # Add specific capabilities per level
        if authority_level == AuthorityLevel.GLOBAL_ADMIN:
            capabilities.update(
                {
                    "can_manage_system_roles": True,
                    "can_access_all_organizations": True,
                    "can_override_restrictions": True,
                    "can_manage_global_settings": True,
                }
            )
        elif authority_level == AuthorityLevel.ADMIN:
            capabilities.update(
                {
                    "can_manage_organization_users": True,
                    "can_manage_organization_settings": True,
                    "can_assign_roles": True,
                    "can_view_all_resources": True,
                }
            )
        elif authority_level == AuthorityLevel.USER_MANAGER:
            capabilities.update(
                {
                    "can_create_users": True,
                    "can_modify_user_roles": True,
                    "can_reset_passwords": True,
                    "can_manage_user_sessions": True,
                }
            )
        elif authority_level == AuthorityLevel.API_MANAGER:
            capabilities.update(
                {
                    "can_create_api_keys": True,
                    "can_manage_integrations": True,
                    "can_view_api_usage": True,
                    "can_manage_webhooks": True,
                }
            )

        return capabilities


class AuthorityContext:
    """Context for authority-based decisions."""

    def __init__(
        self,
        user: User,
        authority_level: AuthorityLevel,
        permissions: Set[str],
        organization_id: Optional[str] = None,
    ):
        """Initialize authority context.

        Args:
            user: User instance
            authority_level: Evaluated authority level
            permissions: User permissions
            organization_id: Organization context
        """
        self.user = user
        self.authority_level = authority_level
        self.permissions = permissions
        self.organization_id = organization_id

    def has_authority_level(self, required_level: AuthorityLevel) -> bool:
        """Check if user has required authority level or higher.

        Args:
            required_level: Minimum required authority level

        Returns:
            True if user has sufficient authority
        """
        return self.authority_level <= required_level

    def can_perform_action(self, action: str, resource_type: str) -> bool:
        """Check if user can perform action based on authority and permissions.

        Args:
            action: Action to perform
            resource_type: Type of resource

        Returns:
            True if user can perform action
        """
        # Check explicit permission first
        permission = f"{resource_type}:{action}"
        if permission in self.permissions:
            return True

        # Check wildcard permissions
        if "*" in self.permissions or f"{resource_type}:*" in self.permissions:
            return True

        # If there are explicit permissions for this resource type, respect them
        # (don't allow authority-based override)
        has_explicit_resource_permissions = any(p.startswith(f"{resource_type}:") for p in self.permissions)
        if has_explicit_resource_permissions:
            return False

        # Check authority-based implicit permissions only if no explicit resource permissions exist
        if action == "read" and self.authority_level.priority <= 40:  # Viewer and above
            return True
        elif action in ["write", "create"] and self.authority_level.priority <= 20:  # Management and above
            return True
        elif action in ["delete", "manage"] and self.authority_level.priority <= 10:  # Admin and above
            return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert authority context to dictionary."""
        return {
            "user_id": str(self.user.id),
            "username": self.user.username,
            "authority_level": self.authority_level.level_name,
            "authority_priority": self.authority_level.priority,
            "organization_id": self.organization_id,
            "permission_count": len(self.permissions),
            "roles": self.user.roles,
            "capabilities": get_authority_evaluator().get_authority_capabilities(self.authority_level),
        }


# Global authority evaluator instance
_authority_evaluator: Optional[AuthorityEvaluator] = None


def get_authority_evaluator(session: Optional[AsyncSession] = None) -> AuthorityEvaluator:
    """Get the global authority evaluator instance."""
    global _authority_evaluator
    if _authority_evaluator is None or session is not None:
        _authority_evaluator = AuthorityEvaluator(session)
    return _authority_evaluator


async def evaluate_user_authority(
    user: User,
    session: Optional[AsyncSession] = None,
    permissions: Optional[Set[str]] = None,
) -> AuthorityLevel:
    """Convenience function to evaluate user authority.

    Args:
        user: User to evaluate
        session: Database session
        permissions: Pre-loaded permissions (optional)

    Returns:
        User's authority level
    """
    evaluator = get_authority_evaluator(session)
    return await evaluator.evaluate_user_authority(user, permissions)


async def create_authority_context(
    user: User,
    session: AsyncSession,
    organization_id: Optional[str] = None,
) -> AuthorityContext:
    """Create authority context for a user.

    Args:
        user: User instance
        session: Database session
        organization_id: Organization context

    Returns:
        Authority context
    """
    evaluator = get_authority_evaluator(session)

    # Load user permissions
    from app.services.rbac_service import RBACService

    rbac_service = RBACService(session)
    permissions = await rbac_service.get_user_permissions(str(user.id))

    # Evaluate authority level
    authority_level = await evaluator.evaluate_user_authority(user, permissions)

    return AuthorityContext(
        user=user,
        authority_level=authority_level,
        permissions=permissions,
        organization_id=organization_id,
    )


def is_deprecated_superuser(user: User) -> bool:
    """Check if user is using deprecated is_superuser flag.

    This function helps identify users still using the old boolean
    superuser flag so they can be migrated to the new authority system.

    Args:
        user: User to check

    Returns:
        True if user has deprecated superuser flag set
    """
    return hasattr(user, "is_superuser") and user.is_superuser


def get_migration_recommendation(user: User) -> Optional[str]:
    """Get role migration recommendation for deprecated superuser users.

    Args:
        user: User to check

    Returns:
        Recommended role for migration, or None if no migration needed
    """
    if not is_deprecated_superuser(user):
        return None

    # Analyze current user roles to recommend appropriate authority level
    user_roles = set(user.roles) if user.roles else set()

    # If already has proper admin role, recommend keeping it
    if "admin" in user_roles:
        return "admin"
    elif "user_manager" in user_roles:
        return "user_manager"
    else:
        # Default recommendation for superusers without specific roles
        return "admin"
