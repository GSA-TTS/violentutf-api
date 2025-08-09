"""Multi-Factor Authentication (MFA) models."""

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.models.mixins import AuditMixin, SoftDeleteMixin


class MFAMethod(str, Enum):
    """Supported MFA methods."""

    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, etc.)
    SMS = "sms"  # SMS text message
    EMAIL = "email"  # Email verification
    BACKUP_CODE = "backup_code"  # One-time backup codes
    WEBAUTHN = "webauthn"  # WebAuthn/FIDO2 (hardware keys)


class MFADevice(Base, AuditMixin, SoftDeleteMixin):
    """Model for MFA devices/methods configured by users."""

    __tablename__ = "mfa_devices"

    # Device identification
    name = Column(String(255), nullable=False)  # User-friendly name
    method: Column[MFAMethod] = Column(SQLEnum(MFAMethod), nullable=False)
    is_primary = Column(Boolean, default=False)  # Primary MFA method
    is_active = Column(Boolean, default=True)

    # Method-specific data
    secret = Column(String(255), nullable=True)  # Encrypted TOTP secret
    phone_number = Column(String(50), nullable=True)  # For SMS
    email = Column(String(255), nullable=True)  # For email verification
    public_key = Column(Text, nullable=True)  # For WebAuthn

    # Verification tracking
    verified_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)

    # Trust settings
    trusted_until = Column(DateTime, nullable=True)  # Remember this device until

    # User relationship
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="mfa_devices")

    # Unique constraint per user and method
    __table_args__ = (
        UniqueConstraint("user_id", "method", "phone_number", name="uq_mfa_device_phone"),
        UniqueConstraint("user_id", "method", "email", name="uq_mfa_device_email"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"<MFADevice(name={self.name}, method={self.method})>"


class MFABackupCode(Base, AuditMixin):
    """Model for one-time backup codes."""

    __tablename__ = "mfa_backup_codes"

    # Code details
    code_hash = Column(String(255), unique=True, nullable=False, index=True)
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)

    # User relationship
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="mfa_backup_codes")

    # Code metadata
    expires_at = Column(DateTime, nullable=True)
    description = Column(String(255), nullable=True)  # Optional description

    @classmethod
    def generate_code(cls) -> str:
        """Generate a secure backup code."""
        # Generate 8-digit numeric code
        code = "".join(str(secrets.randbelow(10)) for _ in range(8))
        # Format as XXXX-XXXX
        return f"{code[:4]}-{code[4:]}"

    def __repr__(self) -> str:
        """String representation."""
        return f"<MFABackupCode(user_id={self.user_id}, used={self.is_used})>"


class MFAChallenge(Base, AuditMixin):
    """Model for tracking MFA challenges/attempts."""

    __tablename__ = "mfa_challenges"

    # Challenge details
    challenge_id = Column(String(255), unique=True, nullable=False, index=True)
    method: Column[MFAMethod] = Column(SQLEnum(MFAMethod), nullable=False)
    challenge_data = Column(Text, nullable=True)  # JSON data for challenge

    # Status tracking
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    attempt_count = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)

    # User and device relationship
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="mfa_challenges")

    device_id = Column(UUID(as_uuid=True), ForeignKey("mfa_devices.id"), nullable=True)
    device = relationship("MFADevice")

    # Request metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    @property
    def is_expired(self) -> bool:
        """Check if challenge is expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if challenge is still valid."""
        return not self.is_verified and not self.is_expired and self.attempt_count < self.max_attempts

    def __repr__(self) -> str:
        """String representation."""
        return f"<MFAChallenge(id={self.challenge_id}, method={self.method})>"


class MFAPolicy(Base, AuditMixin):
    """Model for MFA enforcement policies."""

    __tablename__ = "mfa_policies"

    # Policy identification
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=0)  # Higher priority policies apply first

    # Policy conditions (JSON)
    conditions = Column(Text, nullable=False)  # JSON: roles, permissions, IP ranges, etc.

    # Policy requirements
    required_methods = Column(Text, nullable=False)  # JSON: list of required methods
    min_methods = Column(Integer, default=1)  # Minimum number of methods required

    # Grace period for new users
    grace_period_days = Column(Integer, default=0)

    # Enforcement settings
    enforcement_level = Column(String(50), default="required")  # required, recommended, optional
    bypass_permissions = Column(Text, nullable=True)  # JSON: permissions that bypass MFA

    def __repr__(self) -> str:
        """String representation."""
        return f"<MFAPolicy(name={self.name}, active={self.is_active})>"


class MFAEvent(Base, AuditMixin):
    """Model for MFA-related security events."""

    __tablename__ = "mfa_events"

    # Event details
    event_type = Column(String(100), nullable=False)  # setup, verify, challenge, remove, etc.
    event_status = Column(String(50), nullable=False)  # success, failure, timeout
    method: Column[Optional[MFAMethod]] = Column(SQLEnum(MFAMethod), nullable=True)

    # User and device
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="mfa_events")

    device_id = Column(UUID(as_uuid=True), ForeignKey("mfa_devices.id"), nullable=True)
    device = relationship("MFADevice")

    # Event metadata
    details = Column(Text, nullable=True)  # JSON: additional event details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)  # 0-100 risk assessment

    def __repr__(self) -> str:
        """String representation."""
        return f"<MFAEvent(type={self.event_type}, status={self.event_status})>"
