"""User Session model for tracking authenticated sessions - SQLAlchemy 2.0 Compatible."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base_class import Base
from app.db.types import GUID, JSONType
from app.models.mixins import BaseModelMixin, SecurityValidationMixin

if TYPE_CHECKING:
    from app.models.user import User


class Session(Base, BaseModelMixin, SecurityValidationMixin):
    """
    User session model for tracking authenticated sessions.

    Inherits from BaseModelMixin which provides:
    - UUID primary key (id)
    - Audit fields (created_at, created_by, updated_at, updated_by)
    - Soft delete (is_deleted, deleted_at, deleted_by)
    - Optimistic locking (version)
    - Row-level security (owner_id, organization_id, access_level)
    - Security validations for all string fields
    """

    # Session identification
    session_token: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True, comment="Unique session token (hashed)"
    )

    refresh_token: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True, comment="Refresh token for session renewal (hashed)"
    )

    # User relationship
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User who owns this session",
    )

    # Session metadata
    device_info: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True, comment="Device information (user agent, etc.)"
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, index=True, comment="IP address where session was created"
    )

    location: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True, comment="Geographic location (city, country)"
    )

    # Session status and timing
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true", comment="Whether the session is currently active"
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, comment="When the session expires"
    )

    last_activity_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Last time the session was used"
    )

    last_activity_ip: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, comment="IP address of last activity"
    )

    # Session termination
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="When the session was revoked"
    )

    revoked_by: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, comment="Who revoked the session (user ID or system)"
    )

    revocation_reason: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True, comment="Reason for session revocation"
    )

    # Security features
    security_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=True, default=None, comment="Additional security metadata (MFA, risk scores, etc.)"
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions", foreign_keys=[user_id], lazy="select")

    def __init__(self, **kwargs: Any) -> None:
        """Initialize Session with proper defaults for in-memory instances."""
        # Set defaults for fields that should have default values
        if "is_active" not in kwargs:
            kwargs["is_active"] = True

        # Call parent constructor (BaseModelMixin will handle its own defaults)
        super().__init__(**kwargs)

    # Table configuration
    __tablename__ = "session"

    # Model-specific constraints (will be combined by BaseModelMixin)
    _model_constraints = (
        Index("idx_session_user_active", "user_id", "is_active"),
        Index("idx_session_expires", "expires_at"),
        Index("idx_session_last_activity", "last_activity_at"),
        Index("idx_session_ip", "ip_address", "last_activity_ip"),
    )
    _model_config = {"comment": "User authentication sessions with comprehensive tracking"}

    @validates("session_token")
    def validate_session_token(self, key: str, value: str) -> str:
        """Validate session token format."""
        if not value:
            raise ValueError("Session token is required")

        if len(value) < 32:
            raise ValueError("Session token must be at least 32 characters")

        if len(value) > 255:
            raise ValueError("Session token cannot exceed 255 characters")

        # Skip general security validation for tokens since they are securely generated
        # and don't contain user input that could have SQL injection/XSS

        return value

    @validates("refresh_token")
    def validate_refresh_token(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate refresh token if provided."""
        if value is None:
            return value

        if len(value) < 32:
            raise ValueError("Refresh token must be at least 32 characters")

        if len(value) > 255:
            raise ValueError("Refresh token cannot exceed 255 characters")

        # Skip general security validation for tokens since they are securely generated
        # and don't contain user input that could have SQL injection/XSS

        return value

    @validates("device_info")
    def validate_device_info(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate device info if provided."""
        if value is None:
            return value

        if len(value) > 500:
            raise ValueError("Device info cannot exceed 500 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value.strip() if value.strip() else None

    @validates("ip_address", "last_activity_ip")
    def validate_ip_address_field(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate IP address fields if provided."""
        if value is None:
            return value

        # Use mixin IP validation
        return self.validate_ip_address(key, value)

    @validates("location")
    def validate_location(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate location if provided."""
        if value is None:
            return value

        if len(value) > 200:
            raise ValueError("Location cannot exceed 200 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value.strip() if value.strip() else None

    @validates("revocation_reason")
    def validate_revocation_reason(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate revocation reason if provided."""
        if value is None:
            return value

        if len(value) > 200:
            raise ValueError("Revocation reason cannot exceed 200 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value.strip() if value.strip() else None

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) >= self.expires_at

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        return self.is_active and not self.is_expired() and self.revoked_at is None and not self.is_deleted

    def revoke(self, revoked_by: str, reason: str = "Manual revocation") -> None:
        """Revoke the session."""
        self.is_active = False
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_by = revoked_by
        self.revocation_reason = reason
        self.updated_by = revoked_by

    def update_activity(self, ip_address: Optional[str] = None) -> None:
        """Update last activity timestamp and IP."""
        self.last_activity_at = datetime.now(timezone.utc)
        if ip_address:
            self.last_activity_ip = ip_address

    def extend_session(self, new_expires_at: datetime) -> None:
        """Extend session expiration time."""
        if new_expires_at <= datetime.now(timezone.utc):
            raise ValueError("New expiration time must be in the future")

        self.expires_at = new_expires_at

    def mask_token(self) -> str:
        """Return masked version of session token for display."""
        if not self.session_token:
            return ""

        if len(self.session_token) <= 8:
            return "***"

        return f"{self.session_token[:4]}...{self.session_token[-4:]}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization."""
        return {
            "id": str(self.id),
            "session_token": self.mask_token(),  # Masked for security
            "user_id": str(self.user_id),
            "device_info": self.device_info,
            "ip_address": self.ip_address,
            "location": self.location,
            "is_active": self.is_active,
            "is_valid": self.is_valid(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_activity_at": self.last_activity_at.isoformat() if self.last_activity_at else None,
            "last_activity_ip": self.last_activity_ip,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
            "security_metadata": self.security_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "version": self.version,
        }

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return f"Session {self.mask_token()} for user {self.user_id}"

    def __repr__(self) -> str:
        """Return string representation of session."""
        return (
            f"<Session(id={self.id}, user_id={self.user_id}, " f"active={self.is_active}, expires={self.expires_at})>"
        )
