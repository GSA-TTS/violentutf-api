"""Database model mixins for audit, soft delete, and security features - SQLAlchemy 2.0 Compatible."""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Type, Union

from sqlalchemy import Boolean, DateTime, Index, Integer, String, UniqueConstraint, event, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, Session, declared_attr, mapped_column, validates
from sqlalchemy.orm.attributes import get_history
from structlog.stdlib import get_logger

logger = get_logger(__name__)

# Security patterns for validation
SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b)",
    r"(\bunion\b.*\bselect\b)",
    r"(\b(OR|AND)\b.*=)",
    r'([\'";].*(--))',
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
]


class AuditMixin:
    """Comprehensive audit mixin for tracking all database changes."""

    # Mixins should not define __tablename__ - that's handled by the base class

    # Use mapped_column for SQLAlchemy 2.0 compatibility
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )

    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
        server_default="system",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )

    updated_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
        server_default="system",
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )

    @declared_attr  # type: ignore[arg-type]
    @classmethod
    def __table_args__(cls: Type[Any]) -> Union[
        Tuple[Union[Index, UniqueConstraint], ...],
        Tuple[Union[Index, UniqueConstraint, Dict[str, str]], ...],
    ]:
        """Create indexes for audit fields and combine with model-specific constraints."""
        # Get model-specific constraints if they exist
        model_constraints = getattr(cls, "_model_constraints", ())
        model_config = getattr(cls, "_model_config", {})

        # Base audit indexes
        indexes = [
            Index(f"idx_{cls.__tablename__}_created", "created_at", "created_by"),
            Index(f"idx_{cls.__tablename__}_updated", "updated_at", "updated_by"),
            Index(f"idx_{cls.__tablename__}_version", "version"),
        ]

        # Add soft delete index if SoftDeleteMixin is present
        if hasattr(cls, "is_deleted"):
            indexes.append(
                Index(
                    f"idx_{cls.__tablename__}_active",
                    "created_at",
                    postgresql_where=text("is_deleted = false"),
                )
            )

        # Add RLS indexes if RowLevelSecurityMixin is present
        if hasattr(cls, "owner_id"):
            indexes.extend(
                [
                    Index(f"idx_{cls.__tablename__}_owner", "owner_id", "organization_id"),
                    Index(f"idx_{cls.__tablename__}_access", "access_level", "owner_id"),
                ]
            )

        # Combine all constraints
        all_constraints = tuple(indexes) + model_constraints

        # Return tuple with config dict if present
        if model_config:
            return all_constraints + (model_config,)
        else:
            return all_constraints


class SoftDeleteMixin:
    """Mixin for soft delete functionality."""

    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    deleted_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )

    def soft_delete(self: "SoftDeleteMixin", deleted_by: str = "system") -> None:
        """Mark record as deleted without removing from database."""
        self.is_deleted = True
        self.deleted_at = datetime.now(timezone.utc)
        self.deleted_by = deleted_by

    def restore(self: "SoftDeleteMixin") -> None:
        """Restore a soft-deleted record."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None

    # Soft delete index will be handled by the main __table_args__ in AuditMixin


class SecurityValidationMixin:
    """Mixin for security validation on string fields."""

    def validate_string_security(self: "SecurityValidationMixin", key: str, value: Optional[str]) -> Optional[str]:
        """Validate string fields against security threats."""
        if value is None:
            return value

        # Check string length
        if len(value) > 10000:
            raise ValueError(f"{key} exceeds maximum allowed length")

        # Check for SQL injection patterns
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(
                    "Potential SQL injection attempt detected",
                    field=key,
                    pattern=pattern,
                    value_preview=value[:50],
                )
                raise ValueError(f"Invalid characters or patterns in {key}")

        # Check for XSS patterns
        for pattern in XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(
                    "Potential XSS attempt detected",
                    field=key,
                    pattern=pattern,
                    value_preview=value[:50],
                )
                raise ValueError(f"Invalid HTML/Script content in {key}")

        return value

    def validate_email_format(self: "SecurityValidationMixin", key: str, value: Optional[str]) -> Optional[str]:
        """Validate email format."""
        if value is None:
            return value

        # Basic email regex
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, value):
            raise ValueError(f"Invalid email format for {key}")

        # Additional checks
        if value.count("@") != 1:
            raise ValueError(f"Invalid email format for {key}")

        if ".." in value:
            raise ValueError(f"Invalid email format for {key}")

        return value.lower()

    def validate_url_format(self: "SecurityValidationMixin", key: str, value: Optional[str]) -> Optional[str]:
        """Validate URL format."""
        if value is None:
            return value

        # Basic URL regex
        url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        if not re.match(url_pattern, value, re.IGNORECASE):
            raise ValueError(f"Invalid URL format for {key}")

        return value

    def validate_ip_address(self: "SecurityValidationMixin", key: str, value: Optional[str]) -> Optional[str]:
        """Validate IP address format."""
        if value is None:
            return value

        # IPv4 pattern
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

        # IPv6 pattern (simplified)
        ipv6_pattern = r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

        if not re.match(ipv4_pattern, value) and not re.match(ipv6_pattern, value):
            raise ValueError(f"Invalid IP address format for {key}")

        return value


class OptimisticLockMixin:
    """Mixin for optimistic locking support."""

    # Version field is already in AuditMixin
    pass


class RowLevelSecurityMixin:
    """Mixin for row-level security support."""

    owner_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    access_level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="private",
        server_default="private",
    )

    # RLS indexes will be handled by the main __table_args__ in AuditMixin


class BaseModelMixin(
    AuditMixin,
    SoftDeleteMixin,
    SecurityValidationMixin,
    OptimisticLockMixin,
    RowLevelSecurityMixin,
):
    """Base mixin combining all common model functionality."""

    pass


# Event listener for optimistic locking
@event.listens_for(Session, "before_flush")
def receive_before_flush(session: Session, flush_context: Any, instances: Any) -> None:  # noqa: ANN401
    """Automatically increment version on updates."""
    for instance in session.dirty:
        if hasattr(instance, "version") and session.is_modified(instance):
            # Check if version was manually changed
            history = get_history(instance, "version")
            if not history.has_changes():
                # Increment version only if not manually changed
                if instance.version is None:
                    instance.version = 1
                else:
                    instance.version = instance.version + 1

            # Update the updated_at timestamp
            if hasattr(instance, "updated_at"):
                instance.updated_at = datetime.now(timezone.utc)
