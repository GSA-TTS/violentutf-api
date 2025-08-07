"""User model with comprehensive audit and security features - SQLAlchemy 2.0 Compatible."""

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin

if TYPE_CHECKING:
    from app.models.api_key import APIKey
    from app.models.audit_log import AuditLog
    from app.models.mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent
    from app.models.oauth import OAuthAccessToken, OAuthApplication, OAuthAuthorizationCode, OAuthRefreshToken
    from app.models.session import Session
    from app.models.user_role import UserRole


class User(Base, BaseModelMixin):
    """
    User model with full audit trail and security features.

    Inherits from BaseModelMixin which provides:
    - UUID primary key (id)
    - Audit fields (created_at, created_by, updated_at, updated_by)
    - Soft delete (is_deleted, deleted_at, deleted_by)
    - Optimistic locking (version)
    - Row-level security (owner_id, organization_id, access_level)
    - Security validations for all string fields
    """

    # User-specific fields
    username: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True, comment="Unique username for login"
    )

    email: Mapped[str] = mapped_column(
        String(254),  # RFC 5321 maximum email length
        unique=True,
        nullable=False,
        index=True,
        comment="User email address",
    )

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False, comment="Argon2 password hash")

    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, comment="User's full display name")

    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true", comment="Whether the user account is active"
    )

    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
        comment="Whether the user has administrative privileges",
    )

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
        comment="Whether the user email has been verified",
    )

    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when the user was verified",
    )

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the user's last successful login",
    )

    last_login_ip: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length is 39, plus some margin
        nullable=True,
        comment="IP address of the user's last successful login",
    )

    # Use JSON type that works with both PostgreSQL and SQLite
    # SQLAlchemy will handle the JSON serialization/deserialization
    roles: Mapped[List[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,  # Empty list by default
        server_default="[]",
        comment="User roles for RBAC authorization (viewer, tester, admin)",
    )

    # Relationships
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog", back_populates="user", foreign_keys="AuditLog.user_id", lazy="dynamic", cascade="all, delete-orphan"
    )

    sessions: Mapped[List["Session"]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    user_roles: Mapped[List["UserRole"]] = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # OAuth relationships
    oauth_applications: Mapped[List["OAuthApplication"]] = relationship(
        "OAuthApplication",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    oauth_access_tokens: Mapped[List["OAuthAccessToken"]] = relationship(
        "OAuthAccessToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    oauth_refresh_tokens: Mapped[List["OAuthRefreshToken"]] = relationship(
        "OAuthRefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    oauth_authorization_codes: Mapped[List["OAuthAuthorizationCode"]] = relationship(
        "OAuthAuthorizationCode",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # MFA relationships
    mfa_devices: Mapped[List["MFADevice"]] = relationship(
        "MFADevice",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    mfa_backup_codes: Mapped[List["MFABackupCode"]] = relationship(
        "MFABackupCode",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    mfa_challenges: Mapped[List["MFAChallenge"]] = relationship(
        "MFAChallenge",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    mfa_events: Mapped[List["MFAEvent"]] = relationship(
        "MFAEvent",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize User with proper defaults for in-memory instances."""
        # Set defaults for fields that should have default values
        if "is_active" not in kwargs:
            kwargs["is_active"] = True
        if "is_superuser" not in kwargs:
            kwargs["is_superuser"] = False
        if "is_verified" not in kwargs:
            kwargs["is_verified"] = False
        if "roles" not in kwargs:
            kwargs["roles"] = ["viewer"]

        # Call parent constructor (BaseModelMixin will handle its own defaults)
        super().__init__(**kwargs)

    # Model-specific constraints (will be combined by AuditMixin)
    _model_constraints = (
        UniqueConstraint("username", "is_deleted", name="uq_user_username_active"),
        UniqueConstraint("email", "is_deleted", name="uq_user_email_active"),
    )
    _model_config = {"comment": "User accounts with authentication and authorization"}

    @validates("username")
    def validate_username(self: "User", key: str, value: str) -> str:
        """Validate username format and security."""
        if not value:
            raise ValueError("Username is required")

        # Length validation
        if len(value) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(value) > 100:
            raise ValueError("Username cannot exceed 100 characters")

        # Format validation
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")

        # Security validation
        self.validate_string_security(key, value)

        # Normalize to lowercase for case-insensitive matching
        return value.lower()

    @validates("email")
    def validate_email_field(self: "User", key: str, value: str) -> str:
        """Validate email format and security."""
        if not value:
            raise ValueError("Email is required")

        # Use mixin email validation
        validated_value = self.validate_email_format(key, value)
        assert validated_value is not None, f"Email validation failed for {key}"
        value = validated_value

        # Security validation
        self.validate_string_security(key, value)

        return value

    @validates("password_hash")
    def validate_password_hash(self: "User", key: str, value: str) -> str:
        """Ensure password is properly hashed."""
        if not value:
            raise ValueError("Password hash is required")

        # Verify it's an Argon2 hash (starts with $argon2)
        if not value.startswith("$argon2"):
            raise ValueError("Password must be hashed with Argon2")

        return value

    @validates("full_name")
    def validate_full_name(self: "User", key: str, value: Optional[str]) -> Optional[str]:
        """Validate full name if provided."""
        if value is None:
            return value

        # Length validation
        if len(value) > 255:
            raise ValueError("Full name cannot exceed 255 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value

    @validates("roles")
    def validate_roles(self: "User", key: str, value: List[str]) -> List[str]:
        """Validate user roles according to ADR-003 specifications."""
        if not value:
            raise ValueError("User must have at least one role")

        # Valid roles according to ADR-003
        valid_roles = {"viewer", "tester", "admin"}

        # Ensure all roles are valid
        for role in value:
            if role not in valid_roles:
                raise ValueError(f"Invalid role '{role}'. Valid roles are: {', '.join(valid_roles)}")

        # Remove duplicates and maintain order
        unique_roles = []
        for role in value:
            if role not in unique_roles:
                unique_roles.append(role)

        return unique_roles

    def __str__(self: "User") -> str:
        """Return human-readable string representation of user."""
        status = "active" if self.is_active else "inactive"
        verified = "verified" if self.is_verified else "unverified"
        return f"User '{self.username}' ({self.email}) - {status}, {verified}"

    def __repr__(self: "User") -> str:
        """Return string representation of user."""
        return (
            f"<User(id={str(self.id)[:8]}, username='{self.username}', email='{self.email}', active={self.is_active})>"
        )

    def to_dict(self: "User") -> Dict[str, Any]:
        """Convert user to dictionary for serialization."""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "roles": self.roles,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def get_display_name(self: "User") -> str:
        """Get display-friendly name for the user."""
        if self.full_name:
            return self.full_name
        return self.username

    def get_status_display(self: "User") -> str:
        """Get human-readable status of the user."""
        if not self.is_active:
            return "Inactive"
        if not self.is_verified:
            return "Pending Verification"
        return "Active"

    def can_login(self: "User") -> bool:
        """Check if user can login."""
        return self.is_active and self.is_verified

    def update_login_info(self: "User", ip_address: Optional[str] = None) -> None:
        """Update login information."""
        from datetime import datetime, timezone

        self.last_login_at = datetime.now(timezone.utc)
        if ip_address:
            self.last_login_ip = ip_address

        # Update timestamp (login count tracking could be added later)
