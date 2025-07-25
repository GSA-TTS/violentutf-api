"""User model with comprehensive audit and security features - SQLAlchemy 2.0 Compatible."""

import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import Boolean, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin

if TYPE_CHECKING:
    from app.models.api_key import APIKey


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

    # Relationships
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

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

        return value.lower()

    @validates("email")
    def validate_email_field(self: "User", key: str, value: str) -> str:
        """Validate email format and security."""
        if not value:
            raise ValueError("Email is required")

        # Use mixin email validation
        validated_value = self.validate_email_format(key, value)
        assert validated_value is not None  # We already checked value is not None
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

    def __repr__(self: "User") -> str:
        """Return string representation of user."""
        return f"<User(username={self.username}, email={self.email}, active={self.is_active})>"

    def to_dict(self: "User") -> Dict[str, Any]:
        """Convert user to dictionary for serialization."""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
