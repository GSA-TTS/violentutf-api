"""Evidence document model for secure storage of security evidence."""

import enum
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base
from app.models.mixins import AuditMixin, SoftDeleteMixin


class EvidenceType(enum.Enum):
    """Types of security evidence that can be stored."""

    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    SESSION = "SESSION"
    ACCESS_LOG = "ACCESS_LOG"
    SECURITY_EVENT = "SECURITY_EVENT"
    AUDIT_TRAIL = "AUDIT_TRAIL"


class SecurityClassification(enum.Enum):
    """Security classification levels for evidence documents."""

    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    TOP_SECRET = 5


class EvidenceDocument(Base, AuditMixin, SoftDeleteMixin):
    """
    Evidence document for secure storage of security-related evidence.

    This model stores various types of security evidence including authentication,
    authorization, session data, and audit trails with proper security classifications
    and retention policies.
    """

    __tablename__ = "evidence_documents"

    # Basic fields
    evidence_type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Security and data
    security_classification: Mapped[SecurityClassification] = mapped_column(
        Enum(SecurityClassification), nullable=False, index=True
    )
    evidence_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    retention_period_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    def __repr__(self) -> str:
        """String representation of evidence document."""
        return (
            f"<EvidenceDocument(type={self.evidence_type.value}, "
            f"classification={self.security_classification.name}, "
            f"session={self.session_id[:8]}...)>"
        )

    @property
    def is_expired(self) -> bool:
        """Check if the evidence document has expired based on retention policy."""
        if not self.created_at:
            return False

        from datetime import timedelta

        expiry_date = self.created_at + timedelta(days=self.retention_period_days)
        return datetime.now(timezone.utc) > expiry_date

    def can_access(self, user_clearance_level: int) -> bool:
        """Check if user can access this evidence based on security classification."""
        return user_clearance_level >= self.security_classification.value
