"""Audit Log model for tracking all system actions - SQLAlchemy 2.0 Compatible."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Type, Union

from sqlalchemy import DateTime, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db.base_class import Base
from app.models.mixins import AuditMixin, SecurityValidationMixin


class AuditLog(Base, AuditMixin, SecurityValidationMixin):
    """
    Immutable audit log for tracking all system actions.

    Does not inherit from BaseModelMixin to avoid soft delete functionality.
    Audit logs should never be deleted or modified.
    """

    # Action details
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True, comment="Action performed (e.g., 'user.create', 'api_key.delete')"
    )

    resource_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True, comment="Type of resource affected (e.g., 'user', 'api_key')"
    )

    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True, comment="ID of the affected resource"
    )

    # Actor information
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="User who performed the action (null for system actions)",
    )

    user_email: Mapped[Optional[str]] = mapped_column(
        String(254), nullable=True, comment="Email of user at time of action (denormalized for history)"
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, index=True, comment="IP address of the request"
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True, comment="User agent string from the request"
    )

    # Change tracking
    changes: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=None,
        comment="JSON object with before/after values for updates",
    )

    # Additional context
    action_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=None,
        comment="Additional context or metadata about the action",
    )

    # Result tracking
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="success",
        server_default="success",
        comment="Result status: success, failure, error",
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        String(1000), nullable=True, comment="Error message if action failed"
    )

    # Performance tracking
    duration_ms: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, comment="Duration of the action in milliseconds"
    )

    # Table configuration
    __tablename__ = "audit_log"

    # Model-specific constraints (will be combined by AuditMixin)
    _model_constraints = (
        Index("idx_auditlog_timestamp", "created_at"),
        Index("idx_auditlog_user_action", "user_id", "action"),
        Index("idx_auditlog_resource", "resource_type", "resource_id"),
        Index("idx_auditlog_status", "status", "created_at"),
    )
    _model_config = {"comment": "Immutable audit trail of all system actions"}

    @validates("action")
    def validate_action(self: "AuditLog", key: str, value: str) -> str:
        """Validate action format."""
        if not value:
            raise ValueError("Action is required")

        if len(value) > 100:
            raise ValueError("Action cannot exceed 100 characters")

        # Action should follow dot notation: resource.action
        if "." not in value:
            raise ValueError("Action must follow 'resource.action' format")

        # Skip SQL injection check for action field since it contains valid SQL keywords
        # like "create", "update", "delete" in structured format (resource.action)
        # Just validate for XSS
        for char in ["<", ">", '"', "'", "&"]:
            if char in value:
                raise ValueError(f"Action contains invalid character: {char}")

        return value.lower()

    @validates("resource_type")
    def validate_resource_type(self: "AuditLog", key: str, value: str) -> str:
        """Validate resource type."""
        if not value:
            raise ValueError("Resource type is required")

        if len(value) > 100:
            raise ValueError("Resource type cannot exceed 100 characters")

        # Security validation
        self.validate_string_security(key, value)

        return value.lower()

    @validates("status")
    def validate_status(self: "AuditLog", key: str, value: str) -> str:
        """Validate status value."""
        valid_statuses = ["success", "failure", "error"]
        if value not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")

        return value

    @validates("ip_address")
    def validate_ip_address_field(self: "AuditLog", key: str, value: Optional[str]) -> Optional[str]:
        """Validate IP address if provided."""
        if value is None:
            return value

        # Use mixin IP validation
        return self.validate_ip_address(key, value)

    @validates("user_email")
    def validate_user_email(self: "AuditLog", key: str, value: Optional[str]) -> Optional[str]:
        """Validate email if provided."""
        if value is None:
            return value

        # Use mixin email validation
        return self.validate_email_format(key, value)

    @classmethod
    def create_log(
        cls: Type["AuditLog"],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[Union[str, uuid.UUID]] = None,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        changes: Optional[Dict[str, Any]] = None,
        action_metadata: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
        created_by: str = "system",
    ) -> "AuditLog":
        """Create an audit log entry."""
        # Convert user_id string to UUID if provided
        uuid_user_id = None
        if user_id:
            if isinstance(user_id, str):
                uuid_user_id = uuid.UUID(user_id)
            else:
                uuid_user_id = user_id

        return cls(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=uuid_user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            changes=changes,
            action_metadata=action_metadata,
            status=status,
            error_message=error_message,
            duration_ms=duration_ms,
            created_by=created_by,
            updated_by=created_by,
        )

    @classmethod
    def log_action(
        cls: Type["AuditLog"],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> "AuditLog":
        """Log an action with proper formatting. Alias for create_log with additional parameters."""
        # Combine request_id and metadata into action_metadata
        action_metadata = metadata or {}
        if request_id:
            action_metadata["request_id"] = request_id

        return cls.create_log(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            action_metadata=action_metadata if action_metadata else None,
            status=status,
            error_message=error_message,
            duration_ms=duration_ms,
        )

    def __repr__(self: "AuditLog") -> str:
        """Return string representation of audit log."""
        return (
            f"<AuditLog(action={self.action}, resource={self.resource_type}:{self.resource_id}, status={self.status})>"
        )

    def to_dict(self: "AuditLog") -> Dict[str, Any]:
        """Convert audit log to dictionary for serialization."""
        return {
            "id": str(self.id),
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "user_id": str(self.user_id) if self.user_id else None,
            "user_email": self.user_email,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "changes": self.changes,
            "action_metadata": self.action_metadata,
            "status": self.status,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }
