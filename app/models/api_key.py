"""API Key model for authentication and authorization - SQLAlchemy 2.0 Compatible."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base_class import Base
from app.db.types import GUID, JSONType
from app.models.mixins import BaseModelMixin

if TYPE_CHECKING:
    from app.models.user import User


class APIKey(Base, BaseModelMixin):
    """
    API Key model for token-based authentication.

    Stores hashed API keys with permissions and usage tracking.
    Inherits comprehensive audit and security features from BaseModelMixin.
    """

    # API Key specific fields
    key_hash: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True, comment="SHA256 hash of the API key"
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, comment="Descriptive name for the API key")

    description: Mapped[Optional[str]] = mapped_column(
        String(1000), nullable=True, comment="Detailed description of key purpose"
    )

    key_prefix: Mapped[str] = mapped_column(
        String(10), nullable=False, index=True, comment="First few characters of key for identification"
    )

    # Permissions stored as JSON with cross-database compatibility
    permissions: Mapped[Dict[str, Any]] = mapped_column(
        JSONType,
        nullable=False,
        default=dict,
        server_default=text("'{}'"),
        comment="JSON containing permission scopes",
    )

    # Usage tracking
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True, comment="Last time this key was used"
    )

    last_used_ip: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, comment="IP address from last use (supports IPv6)"
    )

    usage_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0", comment="Number of times key has been used"
    )

    # Expiration
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True, comment="Optional expiration timestamp"
    )

    # User relationship
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID of the user who owns this API key",
    )

    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, comment="Timestamp when API key was revoked"
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="api_keys",
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize APIKey with proper defaults for in-memory instances."""
        # Set defaults for fields that should have default values
        if "permissions" not in kwargs:
            kwargs["permissions"] = {}
        if "usage_count" not in kwargs:
            kwargs["usage_count"] = 0

        # Call parent constructor
        super().__init__(**kwargs)

    # Model-specific constraints (will be combined by AuditMixin)
    _model_constraints = (
        UniqueConstraint("name", "user_id", "is_deleted", name="uq_apikey_name_user"),
        Index("idx_apikey_user_active", "user_id", "is_deleted"),
        Index("idx_apikey_expires", "expires_at", postgresql_where=text("expires_at IS NOT NULL")),
    )
    _model_config = {"comment": "API keys for authentication with granular permissions"}

    @validates("key_hash")
    def validate_key_hash(self: "APIKey", key: str, value: str) -> str:
        """Validate API key hash format."""
        if not value:
            raise ValueError("Key hash is required")

        # Should be a SHA256 hash (64 hex characters)
        if len(value) != 64 or not all(c in "0123456789abcdef" for c in value.lower()):
            raise ValueError("Key hash must be a valid SHA256 hash")

        return value.lower()

    @validates("name")
    def validate_name(self: "APIKey", key: str, value: str) -> str:
        """Validate API key name."""
        if not value:
            raise ValueError("API key name is required")

        if len(value) > 255:
            raise ValueError("API key name cannot exceed 255 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value

    @validates("description")
    def validate_description(self: "APIKey", key: str, value: Optional[str]) -> Optional[str]:
        """Validate description if provided."""
        if value is None:
            return value

        if len(value) > 1000:
            raise ValueError("Description cannot exceed 1000 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value

    @validates("key_prefix")
    def validate_key_prefix(self: "APIKey", key: str, value: str) -> str:
        """Validate key prefix format."""
        if not value:
            raise ValueError("Key prefix is required")

        # Add minimum length check for security
        if len(value) < 6:
            raise ValueError("Key prefix must be at least 6 characters")

        if len(value) > 10:
            raise ValueError("Key prefix cannot exceed 10 characters")

        # Should only contain alphanumeric characters and underscores
        if not all(c.isalnum() or c == "_" for c in value):
            raise ValueError("Key prefix must contain only alphanumeric characters and underscores")

        return value

    @validates("last_used_ip")
    def validate_last_used_ip(self: "APIKey", key: str, value: Optional[str]) -> Optional[str]:
        """Validate IP address if provided."""
        if value is None:
            return value

        # Use mixin IP validation
        return self.validate_ip_address(key, value)

    @validates("permissions")
    def validate_permissions(self: "APIKey", key: str, value: Dict[str, Any]) -> Dict[str, Any]:
        """Validate permissions structure and values."""
        if not isinstance(value, dict):
            raise ValueError("Permissions must be a dictionary")

        # Define valid permission scopes
        VALID_SCOPES = {
            # Global permissions
            "read",
            "write",
            "delete",
            "admin",
            "*",
            # Resource-specific permissions
            "targets:read",
            "targets:write",
            "targets:delete",
            "sessions:read",
            "sessions:write",
            "sessions:delete",
            "sessions:*",
            "users:read",
            "users:write",
            "users:delete",
            "api_keys:read",
            "api_keys:write",
            "api_keys:delete",
        }

        for scope, enabled in value.items():
            # Check if scope is valid
            if scope not in VALID_SCOPES and not scope.endswith(":*"):
                raise ValueError(f"Invalid permission scope: {scope}")

            # Permissions must be boolean
            if not isinstance(enabled, bool):
                raise ValueError(f"Permission value for '{scope}' must be boolean")

        return value

    def is_expired(self: "APIKey") -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False

        # Handle both timezone-aware and naive datetimes
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at

        # If expires_at is naive, assume it's UTC
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return now > expires_at

    def is_active(self: "APIKey") -> bool:
        """Check if the API key is active and valid."""
        # Handle case where is_deleted might be None before database save
        is_not_deleted = self.is_deleted is False or self.is_deleted is None
        return is_not_deleted and not self.is_expired()

    @property
    def is_valid(self: "APIKey") -> bool:
        """Alias for is_active() for backward compatibility."""
        return self.is_active()

    def record_usage(self: "APIKey", ip_address: Optional[str] = None) -> None:
        """Record usage of the API key."""
        self.last_used_at = datetime.now(timezone.utc)
        # Increment usage count (defensive programming for None values)
        if self.usage_count is None:
            self.usage_count = 1  # type: ignore[unreachable]
        else:
            self.usage_count += 1
        if ip_address:
            self.last_used_ip = ip_address

    def has_permission(self: "APIKey", permission: str) -> bool:
        """Check if the API key has a specific permission."""
        # Invalid keys have no permissions
        if not self.is_active():
            return False

        if not self.permissions:
            return False

        # Check for admin or wildcard permission
        if self.permissions.get("admin") is True or self.permissions.get("*") is True:
            return True

        # Check specific permission
        if self.permissions.get(permission) is True:
            return True

        # Check wildcard permissions (e.g., sessions:* covers sessions:read)
        if ":" in permission:
            resource, _ = permission.split(":", 1)
            if self.permissions.get(f"{resource}:*") is True:
                return True

        return False

    def __str__(self: "APIKey") -> str:
        """Return human-readable string representation of API key."""
        status = "active" if self.is_active() else "inactive"
        return f"APIKey '{self.name}' ({self.key_prefix}***) - {status}"

    def __repr__(self: "APIKey") -> str:
        """Return string representation of API key."""
        return f"<APIKey(id={str(self.id)[:8]}, name='{self.name}', prefix='{self.key_prefix}', active={self.is_active()}, usage={self.usage_count})>"

    def mask_key(self: "APIKey", key: Optional[str] = None) -> str:
        """
        Return masked version of API key for display purposes.

        Args:
            key: The full key to mask. If None, uses key_prefix.

        Returns:
            Masked key string for safe display.
        """
        if key is None:
            # Use prefix for masking when full key not available
            if not self.key_prefix:
                return "***"
            return f"{self.key_prefix}{'*' * max(16 - len(self.key_prefix), 3)}"

        if not key:
            return "***"

        # For full keys, show first 6 chars and mask the rest
        if len(key) <= 6:
            return f"{key[:2]}{'*' * (len(key) - 2)}"

        return f"{key[:6]}{'*' * (len(key) - 6)}"

    def to_dict(self: "APIKey", include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert API key to dictionary for serialization.

        Args:
            include_sensitive: Whether to include sensitive data like full key and IP.

        Returns:
            Dictionary representation of the API key.
        """
        result = {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "key_prefix": self.key_prefix,
            "permissions": self.permissions,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "usage_count": self.usage_count,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }

        # Only include sensitive fields when explicitly requested
        if include_sensitive:
            result["last_used_ip"] = self.last_used_ip
        else:
            # Include masked key for non-sensitive view
            result["masked_key"] = self.mask_key()

        return result

    def get_display_name(self: "APIKey") -> str:
        """Get display-friendly name for the API key."""
        if self.description:
            return f"{self.name} - {self.description[:50]}{'...' if len(self.description) > 50 else ''}"
        return self.name

    def get_status_display(self: "APIKey") -> str:
        """Get human-readable status of the API key."""
        if not self.is_active():
            if self.revoked_at:
                return "Revoked"
            elif self.is_expired():
                return "Expired"
            else:
                return "Inactive"

        if self.expires_at:
            from datetime import datetime, timezone

            days_until_expiry = (self.expires_at.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            if days_until_expiry <= 7:
                return f"Active (expires in {days_until_expiry} days)"

        return "Active"
