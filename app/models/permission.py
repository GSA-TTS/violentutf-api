"""Permission model for RBAC system."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import JSON, Boolean, Column, DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class Permission(Base, BaseModelMixin):
    """Permission model for fine-grained access control.

    Permissions define specific actions that can be performed on resources.
    They follow the format: resource:action:scope (e.g., "users:read:own")
    """

    __tablename__ = "permissions"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Permission structure
    resource = Column(String(50), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    scope = Column(String(50), nullable=True, index=True)

    # Permission properties
    is_system_permission = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # JSON field for additional permission metadata
    permission_metadata = Column(JSON, default=dict, nullable=False)

    # Composite index for efficient permission lookups
    __table_args__ = (
        Index("ix_permissions_resource_action_scope", "resource", "action", "scope"),
        Index("ix_permissions_active_system", "is_active", "is_system_permission"),
    )

    def __repr__(self) -> str:
        """Return string representation of the permission."""
        return f"<Permission(id={self.id}, name='{self.name}', resource='{self.resource}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert permission to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "resource": self.resource,
            "action": self.action,
            "scope": self.scope,
            "is_system_permission": self.is_system_permission,
            "is_active": self.is_active,
            "metadata": self.permission_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "version": self.version,
        }

    @classmethod
    def parse_permission_string(cls: type["Permission"], permission_str: str) -> Dict[str, Optional[str]]:
        """Parse a permission string into components.

        Args:
            permission_str: Permission string (e.g., "users:read:own")

        Returns:
            Dictionary with resource, action, and scope

        Raises:
            ValueError: If permission string format is invalid
        """
        if not permission_str or not isinstance(permission_str, str):
            raise ValueError("Permission string cannot be empty")

        parts = permission_str.split(":")
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f"Invalid permission format: {permission_str}")

        return {
            "resource": parts[0],
            "action": parts[1],
            "scope": parts[2] if len(parts) == 3 else None,
        }

    @classmethod
    def create_system_permissions(cls: type["Permission"]) -> List["Permission"]:
        """Create default system permissions.

        Returns:
            List of system Permission instances
        """
        permissions_data = [
            # Global permissions
            {
                "name": "*",
                "display_name": "All Permissions",
                "description": "Global wildcard permission for all actions",
                "resource": "*",
                "action": "*",
                "scope": None,
            },
            # User management permissions
            {
                "name": "users:read",
                "display_name": "Read Users",
                "description": "View user information and profiles",
                "resource": "users",
                "action": "read",
                "scope": None,
            },
            {
                "name": "users:read:own",
                "display_name": "Read Own Profile",
                "description": "View own user profile",
                "resource": "users",
                "action": "read",
                "scope": "own",
            },
            {
                "name": "users:write",
                "display_name": "Modify Users",
                "description": "Create and modify user accounts",
                "resource": "users",
                "action": "write",
                "scope": None,
            },
            {
                "name": "users:delete",
                "display_name": "Delete Users",
                "description": "Delete user accounts",
                "resource": "users",
                "action": "delete",
                "scope": None,
            },
            {
                "name": "users:*",
                "display_name": "All User Operations",
                "description": "All operations on user accounts",
                "resource": "users",
                "action": "*",
                "scope": None,
            },
            # API key management permissions
            {
                "name": "api_keys:read",
                "display_name": "Read API Keys",
                "description": "View API key information",
                "resource": "api_keys",
                "action": "read",
                "scope": None,
            },
            {
                "name": "api_keys:read:own",
                "display_name": "Read Own API Keys",
                "description": "View own API keys",
                "resource": "api_keys",
                "action": "read",
                "scope": "own",
            },
            {
                "name": "api_keys:write",
                "display_name": "Manage API Keys",
                "description": "Create and modify API keys",
                "resource": "api_keys",
                "action": "write",
                "scope": None,
            },
            {
                "name": "api_keys:write:own",
                "display_name": "Manage Own API Keys",
                "description": "Create and modify own API keys",
                "resource": "api_keys",
                "action": "write",
                "scope": "own",
            },
            {
                "name": "api_keys:delete",
                "display_name": "Delete API Keys",
                "description": "Delete API keys",
                "resource": "api_keys",
                "action": "delete",
                "scope": None,
            },
            {
                "name": "api_keys:*",
                "display_name": "All API Key Operations",
                "description": "All operations on API keys",
                "resource": "api_keys",
                "action": "*",
                "scope": None,
            },
            {
                "name": "api_keys:*:own",
                "display_name": "All Own API Key Operations",
                "description": "All operations on own API keys",
                "resource": "api_keys",
                "action": "*",
                "scope": "own",
            },
            # Session management permissions
            {
                "name": "sessions:read",
                "display_name": "Read Sessions",
                "description": "View session information",
                "resource": "sessions",
                "action": "read",
                "scope": None,
            },
            {
                "name": "sessions:read:own",
                "display_name": "Read Own Sessions",
                "description": "View own session information",
                "resource": "sessions",
                "action": "read",
                "scope": "own",
            },
            {
                "name": "sessions:write",
                "display_name": "Manage Sessions",
                "description": "Create and modify sessions",
                "resource": "sessions",
                "action": "write",
                "scope": None,
            },
            {
                "name": "sessions:delete",
                "display_name": "Delete Sessions",
                "description": "Terminate sessions",
                "resource": "sessions",
                "action": "delete",
                "scope": None,
            },
            {
                "name": "sessions:*",
                "display_name": "All Session Operations",
                "description": "All operations on sessions",
                "resource": "sessions",
                "action": "*",
                "scope": None,
            },
            # Audit log permissions
            {
                "name": "audit_logs:read",
                "display_name": "Read Audit Logs",
                "description": "View audit log entries",
                "resource": "audit_logs",
                "action": "read",
                "scope": None,
            },
            {
                "name": "audit_logs:*",
                "display_name": "All Audit Log Operations",
                "description": "All operations on audit logs",
                "resource": "audit_logs",
                "action": "*",
                "scope": None,
            },
            # Role management permissions
            {
                "name": "roles:read",
                "display_name": "Read Roles",
                "description": "View role information",
                "resource": "roles",
                "action": "read",
                "scope": None,
            },
            {
                "name": "roles:write",
                "display_name": "Manage Roles",
                "description": "Create and modify roles",
                "resource": "roles",
                "action": "write",
                "scope": None,
            },
            {
                "name": "roles:delete",
                "display_name": "Delete Roles",
                "description": "Delete roles",
                "resource": "roles",
                "action": "delete",
                "scope": None,
            },
            {
                "name": "roles:manage:system",
                "display_name": "Manage System Roles",
                "description": "Manage system-defined roles",
                "resource": "roles",
                "action": "manage",
                "scope": "system",
            },
            {
                "name": "roles:*",
                "display_name": "All Role Operations",
                "description": "All operations on roles",
                "resource": "roles",
                "action": "*",
                "scope": None,
            },
            # Permission management permissions
            {
                "name": "permissions:read",
                "display_name": "Read Permissions",
                "description": "View permission information",
                "resource": "permissions",
                "action": "read",
                "scope": None,
            },
            {
                "name": "permissions:write",
                "display_name": "Manage Permissions",
                "description": "Create and modify permissions",
                "resource": "permissions",
                "action": "write",
                "scope": None,
            },
            {
                "name": "permissions:*",
                "display_name": "All Permission Operations",
                "description": "All operations on permissions",
                "resource": "permissions",
                "action": "*",
                "scope": None,
            },
            # Project management permissions (for future use)
            {
                "name": "projects:read",
                "display_name": "Read Projects",
                "description": "View project information",
                "resource": "projects",
                "action": "read",
                "scope": None,
            },
            {
                "name": "projects:write",
                "display_name": "Manage Projects",
                "description": "Create and modify projects",
                "resource": "projects",
                "action": "write",
                "scope": None,
            },
            {
                "name": "projects:delete",
                "display_name": "Delete Projects",
                "description": "Delete projects",
                "resource": "projects",
                "action": "delete",
                "scope": None,
            },
            {
                "name": "projects:*",
                "display_name": "All Project Operations",
                "description": "All operations on projects",
                "resource": "projects",
                "action": "*",
                "scope": None,
            },
        ]

        permissions = []
        for perm_data in permissions_data:
            permission = cls(
                name=perm_data["name"],
                display_name=perm_data["display_name"],
                description=perm_data["description"],
                resource=perm_data["resource"],
                action=perm_data["action"],
                scope=perm_data["scope"],
                is_system_permission=True,
                permission_metadata={"category": cls._get_permission_category(perm_data["resource"])},
            )
            permissions.append(permission)

        return permissions

    @classmethod
    def _get_permission_category(cls: type["Permission"], resource: str) -> str:
        """Get category for a resource type."""
        categories = {
            "*": "system",
            "users": "user_management",
            "api_keys": "api_management",  # pragma: allowlist secret
            "sessions": "session_management",
            "audit_logs": "auditing",
            "roles": "access_control",
            "permissions": "access_control",
            "projects": "project_management",
        }
        return categories.get(resource, "other")

    def matches_permission(self, required_permission: str) -> bool:
        """Check if this permission matches a required permission string.

        Args:
            required_permission: Permission string to match against

        Returns:
            True if this permission satisfies the required permission
        """
        if not self.is_active:
            return False

        # Parse the required permission
        try:
            req_parts = self.parse_permission_string(required_permission)
        except ValueError:
            return False

        # Check for exact match
        if (
            self.resource == req_parts["resource"]
            and self.action == req_parts["action"]
            and self.scope == req_parts["scope"]
        ):
            return True

        # Check for wildcard matches
        if self.resource == "*" or self.action == "*":
            return True

        # Check for resource-level wildcard
        if self.resource == req_parts["resource"] and self.action == "*":
            return True

        return False

    def implies_permission(self, other_permission: "Permission") -> bool:
        """Check if this permission implies another permission.

        Args:
            other_permission: Permission to check if implied

        Returns:
            True if this permission implies the other
        """
        if not self.is_active or not other_permission.is_active:
            return False

        # Global wildcard implies everything
        if self.resource == "*" and self.action == "*":
            return True

        # Resource wildcard implies all actions on that resource
        if self.resource == other_permission.resource and self.action == "*":
            return True

        # Exact match
        if (
            self.resource == other_permission.resource
            and self.action == other_permission.action
            and self.scope == other_permission.scope
        ):
            return True

        return False

    def validate_permission_data(self) -> None:
        """Validate permission data before saving.

        Raises:
            ValueError: If permission data is invalid
        """
        if not self.name or len(self.name.strip()) == 0:
            raise ValueError("Permission name cannot be empty")

        if not self.display_name or len(self.display_name.strip()) == 0:
            raise ValueError("Permission display name cannot be empty")

        if not self.resource or len(self.resource.strip()) == 0:
            raise ValueError("Permission resource cannot be empty")

        if not self.action or len(self.action.strip()) == 0:
            raise ValueError("Permission action cannot be empty")

        # Validate resource format
        valid_resources = {
            "users",
            "api_keys",
            "sessions",
            "audit_logs",
            "roles",
            "permissions",
            "projects",
            "reports",
            "system",
            "*",
        }
        if self.resource not in valid_resources:
            raise ValueError(f"Invalid resource: {self.resource}")

        # Validate action format
        valid_actions = {"read", "write", "delete", "manage", "*"}
        if self.action not in valid_actions:
            raise ValueError(f"Invalid action: {self.action}")

        # Validate scope format (if provided)
        if self.scope:
            valid_scopes = {"own", "team", "all", "system", "*"}
            if self.scope not in valid_scopes:
                raise ValueError(f"Invalid scope: {self.scope}")

        # Validate permission name format matches components
        expected_name = self._build_permission_name()
        if self.name != expected_name:
            raise ValueError(f"Permission name '{self.name}' does not match components '{expected_name}'")

    def _build_permission_name(self) -> str:
        """Build permission name from components."""
        if self.scope:
            return f"{self.resource}:{self.action}:{self.scope}"
        else:
            return f"{self.resource}:{self.action}"

    @property
    def full_name(self) -> str:
        """Get the full permission name including scope."""
        return self._build_permission_name()

    @property
    def category(self) -> str:
        """Get the permission category."""
        return self.permission_metadata.get("category", "other")

    def is_scoped_permission(self) -> bool:
        """Check if this is a scoped permission (has scope component)."""
        return self.scope is not None

    def is_wildcard_permission(self) -> bool:
        """Check if this is a wildcard permission."""
        return self.resource == "*" or self.action == "*"

    def get_permission_level(self) -> int:
        """Get the permission level for hierarchy comparison.

        Returns:
            Integer representing permission level (lower = more privileged)
        """
        # Global wildcard is most privileged
        if self.resource == "*" and self.action == "*":
            return 0

        # Resource wildcard is second most privileged
        if self.action == "*":
            return 1

        # Specific permissions have higher numbers
        action_levels = {
            "delete": 2,
            "write": 3,
            "manage": 3,
            "read": 4,
        }

        base_level = action_levels.get(self.action, 5)

        # Scoped permissions are less privileged
        if self.scope:
            base_level += 1

        return base_level
