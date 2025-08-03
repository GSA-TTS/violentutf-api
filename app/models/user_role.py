"""User-Role association model for RBAC system."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Table, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class UserRole(Base, BaseModelMixin):
    """User-Role association model for many-to-many relationships.

    This model represents the assignment of roles to users, including
    metadata about when and by whom the assignment was made.
    """

    __tablename__ = "user_roles"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)

    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False, index=True)

    # Assignment metadata
    assigned_by = Column(String(255), nullable=False)  # User ID or system identifier
    assigned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration
    is_active = Column(Boolean, default=True, nullable=False)

    # Optional context for the assignment
    assignment_reason = Column(Text, nullable=True)
    assignment_context = Column(String(100), nullable=True)  # e.g., "promotion", "project", "temporary"

    # Relationships
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role")

    def __repr__(self) -> str:
        """Return string representation of the user-role assignment."""
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id}, active={self.is_active})>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert user-role assignment to dictionary representation."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "role_id": str(self.role_id),
            "assigned_by": self.assigned_by,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "assignment_reason": self.assignment_reason,
            "assignment_context": self.assignment_context,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def is_expired(self) -> bool:
        """Check if this role assignment has expired.

        Returns:
            True if the assignment has expired
        """
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Check if this role assignment is valid (active and not expired).

        Returns:
            True if the assignment is valid
        """
        return self.is_active and not self.is_expired()

    def revoke(self, revoked_by: str, reason: Optional[str] = None) -> None:
        """Revoke this role assignment.

        Args:
            revoked_by: Identifier of who revoked the assignment
            reason: Optional reason for revocation
        """
        self.is_active = False
        self.updated_by = revoked_by
        self.updated_at = datetime.now(timezone.utc)
        if reason:
            self.assignment_reason = f"{self.assignment_reason or ''} | Revoked: {reason}".strip(" |")

    def extend_expiration(self, new_expiration: Optional[datetime], extended_by: str) -> None:
        """Extend or modify the expiration date.

        Args:
            new_expiration: New expiration date (None for no expiration)
            extended_by: Identifier of who extended the assignment
        """
        self.expires_at = new_expiration
        self.updated_by = extended_by
        self.updated_at = datetime.now(timezone.utc)

    def validate_assignment(self) -> None:
        """Validate the user-role assignment.

        Raises:
            ValueError: If assignment data is invalid
        """
        if not self.user_id:
            raise ValueError("User ID is required")

        if not self.role_id:
            raise ValueError("Role ID is required")

        if not self.assigned_by:
            raise ValueError("Assigned by is required")

        if self.expires_at and self.expires_at <= self.assigned_at:
            raise ValueError("Expiration date must be after assignment date")

    @property
    def days_until_expiration(self) -> Optional[int]:
        """Get the number of days until expiration.

        Returns:
            Number of days until expiration, or None if no expiration
        """
        if not self.expires_at:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)

    @property
    def is_temporary(self) -> bool:
        """Check if this is a temporary assignment (has expiration)."""
        return self.expires_at is not None

    @property
    def assignment_age_days(self) -> int:
        """Get the age of this assignment in days."""
        if not self.assigned_at:
            return 0
        delta = datetime.now(timezone.utc) - self.assigned_at
        return delta.days
