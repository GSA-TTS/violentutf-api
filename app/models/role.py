"""Role model for RBAC system."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class Role(Base, BaseModelMixin):
    """Role model for role-based access control.

    A role represents a collection of permissions that can be assigned to users.
    Roles can be hierarchical (parent-child relationships) and can inherit
    permissions from parent roles.
    """

    __tablename__ = "roles"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Role properties
    is_system_role = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Hierarchical role support
    parent_role_id = Column(UUID(as_uuid=True), nullable=True)

    # JSON field for additional role metadata
    role_metadata = Column(JSON, default=dict, nullable=False)

    # Timestamps and audit fields (inherited from BaseModel)
    # created_at, updated_at, created_by, updated_by, version, is_deleted

    @property
    def permissions(self) -> List[str]:
        """Get permissions from role metadata."""
        return self.role_metadata.get("permissions", [])

    @permissions.setter
    def permissions(self, value: List[str]) -> None:
        """Set permissions in role metadata."""
        self.role_metadata["permissions"] = value

    def __repr__(self) -> str:
        """Return string representation of the role."""
        return f"<Role(id={self.id}, name='{self.name}', display_name='{self.display_name}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert role to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "is_system_role": self.is_system_role,
            "is_active": self.is_active,
            "parent_role_id": str(self.parent_role_id) if self.parent_role_id else None,
            "metadata": self.role_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "version": self.version,
        }

    @classmethod
    def create_system_roles(cls: type["Role"]) -> List["Role"]:
        """Create default system roles.

        Returns:
            List of system Role instances
        """
        system_roles = [
            cls(
                name="super_admin",
                display_name="Super Administrator",
                description="Full system access with all permissions",
                is_system_role=True,
                role_metadata={
                    "permissions": ["*"],
                    "level": 0,
                    "immutable": True,
                },
            ),
            cls(
                name="admin",
                display_name="Administrator",
                description="Administrative access to most system functions",
                is_system_role=True,
                role_metadata={
                    "permissions": [
                        "users:*",
                        "api_keys:*",
                        "sessions:*",
                        "audit_logs:read",
                        "roles:read",
                        "permissions:read",
                    ],
                    "level": 1,
                    "immutable": False,
                },
            ),
            cls(
                name="user_manager",
                display_name="User Manager",
                description="Manage users and their basic permissions",
                is_system_role=True,
                role_metadata={
                    "permissions": ["users:read", "users:write", "users:delete", "sessions:read", "audit_logs:read"],
                    "level": 2,
                    "immutable": False,
                },
            ),
            cls(
                name="api_manager",
                display_name="API Manager",
                description="Manage API keys and integrations",
                is_system_role=True,
                role_metadata={
                    "permissions": ["api_keys:*", "sessions:read", "audit_logs:read"],
                    "level": 2,
                    "immutable": False,
                },
            ),
            cls(
                name="viewer",
                display_name="Viewer",
                description="Read-only access to most resources",
                is_system_role=True,
                role_metadata={
                    "permissions": [
                        "users:read",
                        "api_keys:read",
                        "sessions:read",
                        "audit_logs:read",
                        "roles:read",
                        "permissions:read",
                    ],
                    "level": 3,
                    "immutable": False,
                },
            ),
            cls(
                name="user",
                display_name="Standard User",
                description="Basic user access to own resources",
                is_system_role=True,
                role_metadata={
                    "permissions": ["users:read:own", "api_keys:*:own", "sessions:read:own"],
                    "level": 4,
                    "immutable": False,
                },
            ),
        ]

        return system_roles

    def get_effective_permissions(self) -> List[str]:
        """Get effective permissions for this role (including inherited).

        Returns:
            List of permission strings
        """
        permissions = self.role_metadata.get("permissions", [])

        # TODO: Implement hierarchical permission inheritance
        # This would recursively collect permissions from parent roles

        return permissions

    def has_permission(self, permission: str) -> bool:
        """Check if this role has a specific permission.

        Args:
            permission: Permission string to check

        Returns:
            True if role has the permission
        """
        if not self.is_active:
            return False

        effective_permissions = self.get_effective_permissions()

        # Check for wildcard permissions
        if "*" in effective_permissions:
            return True

        # Check for exact match
        if permission in effective_permissions:
            return True

        # Check for resource-level wildcard (e.g., "users:*" includes "users:read")
        if ":" in permission:
            resource, action = permission.split(":", 1)
            if f"{resource}:*" in effective_permissions:
                return True

        return False

    def can_manage_role(self, other_role: "Role") -> bool:
        """Check if this role can manage another role.

        Args:
            other_role: Role to check management rights for

        Returns:
            True if this role can manage the other role
        """
        # Super admin can manage everything
        if self.has_permission("*"):
            return True

        # Cannot manage system roles unless explicitly allowed
        if other_role.is_system_role and not self.has_permission("roles:manage:system"):
            return False

        # Check role hierarchy (higher level roles can manage lower level ones)
        self_level = self.role_metadata.get("level", 999)
        other_level = other_role.role_metadata.get("level", 999)

        return self_level < other_level

    def is_descendant_of(self, ancestor_role: "Role") -> bool:
        """Check if this role is a descendant of another role.

        Args:
            ancestor_role: Potential ancestor role

        Returns:
            True if this role inherits from the ancestor role
        """
        # TODO: Implement role hierarchy traversal
        # This would check parent_role_id relationships
        return False

    def validate_role_data(self) -> None:
        """Validate role data before saving.

        Raises:
            ValueError: If role data is invalid
        """
        if not self.name or len(self.name.strip()) == 0:
            raise ValueError("Role name cannot be empty")

        if not self.display_name or len(self.display_name.strip()) == 0:
            raise ValueError("Role display name cannot be empty")

        # Validate role name format (alphanumeric, underscore, hyphen)
        import re

        if not re.match(r"^[a-zA-Z0-9_-]+$", self.name):
            raise ValueError("Role name can only contain letters, numbers, underscores, and hyphens")

        # Validate permissions format
        permissions = self.role_metadata.get("permissions", [])
        if not isinstance(permissions, list):
            raise ValueError("Permissions must be a list")

        # Validate each permission string
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
        valid_actions = {"read", "write", "delete", "manage", "*"}
        valid_scopes = {"own", "team", "all", "*"}

        for perm in permissions:
            if not isinstance(perm, str):
                raise ValueError(f"Permission must be a string: {perm}")

            if perm == "*":
                continue  # Global wildcard is always valid

            parts = perm.split(":")
            if len(parts) < 2 or len(parts) > 3:
                raise ValueError(f"Invalid permission format: {perm}")

            resource, action = parts[0], parts[1]
            scope = parts[2] if len(parts) == 3 else None

            if resource not in valid_resources:
                raise ValueError(f"Invalid resource in permission: {resource}")

            if action not in valid_actions:
                raise ValueError(f"Invalid action in permission: {action}")

            if scope and scope not in valid_scopes:
                raise ValueError(f"Invalid scope in permission: {scope}")

    @property
    def permission_count(self) -> int:
        """Get the number of permissions assigned to this role."""
        return len(self.role_metadata.get("permissions", []))

    @property
    def is_immutable(self) -> bool:
        """Check if this role is immutable (cannot be modified)."""
        return self.role_metadata.get("immutable", False)

    def add_permission(self, permission: str) -> None:
        """Add a permission to this role.

        Args:
            permission: Permission string to add
        """
        if self.is_immutable:
            raise ValueError("Cannot modify immutable role")

        permissions = self.role_metadata.get("permissions", [])
        if permission not in permissions:
            permissions.append(permission)
            self.role_metadata = {**self.role_metadata, "permissions": permissions}

    def remove_permission(self, permission: str) -> None:
        """Remove a permission from this role.

        Args:
            permission: Permission string to remove
        """
        if self.is_immutable:
            raise ValueError("Cannot modify immutable role")

        permissions = self.role_metadata.get("permissions", [])
        if permission in permissions:
            permissions.remove(permission)
            self.role_metadata = {**self.role_metadata, "permissions": permissions}

    def set_permissions(self, permissions: List[str]) -> None:
        """Set the complete list of permissions for this role.

        Args:
            permissions: List of permission strings
        """
        if self.is_immutable:
            raise ValueError("Cannot modify immutable role")

        # Validate permissions first
        temp_metadata = {**self.role_metadata, "permissions": permissions}
        temp_role = Role(name="temp", display_name="temp", metadata=temp_metadata)
        temp_role.validate_role_data()

        # If validation passes, update the permissions
        self.role_metadata = {**self.role_metadata, "permissions": permissions}
