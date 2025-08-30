"""Session schemas for requests and responses."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Type

from pydantic import Field, field_validator

from app.schemas.base import (
    AdvancedFilter,
    BaseCreateSchema,
    BaseModelSchema,
    BaseUpdateSchema,
)


class SessionBase(BaseCreateSchema):
    """Base session schema with common fields."""

    device_info: Optional[str] = Field(None, max_length=500, description="Device information (user agent, etc.)")
    location: Optional[str] = Field(None, max_length=200, description="Geographic location")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    security_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Security metadata")

    @field_validator("device_info")
    @classmethod
    def validate_device_info(cls: Type["SessionBase"], v: Optional[str]) -> Optional[str]:
        """Validate device info if provided."""
        if v is None:
            return v

        # Remove potentially dangerous characters
        dangerous_chars = ["<script", "javascript:", "onerror", "<iframe", "<object"]
        for char in dangerous_chars:
            if char in v.lower():
                raise ValueError("Device info contains invalid content")

        return v.strip() if v.strip() else None

    @field_validator("location")
    @classmethod
    def validate_location(cls: Type["SessionBase"], v: Optional[str]) -> Optional[str]:
        """Validate location if provided."""
        if v is None:
            return v

        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"Location cannot contain '{char}'")

        return v.strip() if v.strip() else None

    @field_validator("security_metadata")
    @classmethod
    def validate_security_metadata(cls: Type["SessionBase"], v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate security metadata if provided."""
        if not v:
            return {}

        if not isinstance(v, dict):
            raise ValueError("Security metadata must be a dictionary")

        # Limit size to prevent abuse
        if len(v) > 20:
            raise ValueError("Security metadata cannot have more than 20 keys")

        # Validate each key and value
        for key, value in v.items():
            if not isinstance(key, str):
                raise ValueError("Security metadata keys must be strings")

            if len(key) > 100:
                raise ValueError("Security metadata keys cannot exceed 100 characters")

            # Allow basic types only
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("Security metadata values must be simple types (str, int, float, bool, None)")

        return v


class SessionCreate(SessionBase):
    """Schema for creating a session."""

    user_id: uuid.UUID = Field(..., description="User ID who owns this session")
    session_token: str = Field(..., min_length=32, max_length=255, description="Session token (will be hashed)")
    refresh_token: Optional[str] = Field(
        None,
        min_length=32,
        max_length=255,
        description="Refresh token (will be hashed)",
    )
    ip_address: Optional[str] = Field(None, description="IP address where session was created")

    @field_validator("session_token", "refresh_token")
    @classmethod
    def validate_tokens(cls: Type["SessionCreate"], v: Optional[str]) -> Optional[str]:
        """Validate session and refresh tokens."""
        if v is None:
            return v

        if len(v) < 32:
            raise ValueError("Token must be at least 32 characters")

        # Basic security check
        if any(char in v for char in ["<", ">", "&", '"', "'", ";", "--"]):
            raise ValueError("Token contains invalid characters")

        return v


class SessionUpdate(BaseUpdateSchema):
    """Schema for updating a session."""

    device_info: Optional[str] = Field(None, max_length=500, description="Device information")
    location: Optional[str] = Field(None, max_length=200, description="Geographic location")
    expires_at: Optional[datetime] = Field(None, description="Session expiration timestamp")
    security_metadata: Optional[Dict[str, Any]] = Field(None, description="Security metadata")

    @field_validator("device_info")
    @classmethod
    def validate_device_info(cls: Type["SessionUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate device info if provided."""
        if v is None:
            return v

        return v

    @field_validator("location")
    @classmethod
    def validate_location(cls: Type["SessionUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate location if provided."""
        if v is None:
            return v

        return v

    @field_validator("security_metadata")
    @classmethod
    def validate_security_metadata(cls: Type["SessionUpdate"], v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate security metadata if provided."""
        if v is None:
            return v

        return v


class SessionResponse(BaseModelSchema):
    """Schema for session responses (excludes sensitive data)."""

    user_id: uuid.UUID = Field(..., description="User ID who owns this session")
    masked_token: str = Field(..., description="Masked session token for display")
    device_info: Optional[str] = Field(None, description="Device information")
    ip_address: Optional[str] = Field(None, description="IP address where session was created")
    location: Optional[str] = Field(None, description="Geographic location")
    is_active: bool = Field(..., description="Whether the session is active")
    is_valid: bool = Field(..., description="Whether the session is valid (active and not expired)")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    last_activity_at: Optional[datetime] = Field(None, description="Last activity timestamp")
    last_activity_ip: Optional[str] = Field(None, description="IP address of last activity")
    revoked_at: Optional[datetime] = Field(None, description="When the session was revoked")
    revoked_by: Optional[str] = Field(None, description="Who revoked the session")
    revocation_reason: Optional[str] = Field(None, description="Reason for session revocation")
    security_metadata: Optional[Dict[str, Any]] = Field(None, description="Security metadata")


class SessionRevokeRequest(BaseCreateSchema):
    """Schema for revoking a session."""

    reason: str = Field(default="Manual revocation", max_length=200, description="Reason for revocation")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls: Type["SessionRevokeRequest"], v: str) -> str:
        """Validate revocation reason."""
        if not v or not v.strip():
            return "Manual revocation"

        # Security validation
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"Reason cannot contain '{char}'")

        return v.strip()


class SessionExtendRequest(BaseCreateSchema):
    """Schema for extending a session."""

    extension_minutes: int = Field(60, ge=1, le=10080, description="Minutes to extend (max 1 week)")

    @field_validator("extension_minutes")
    @classmethod
    def validate_extension_minutes(cls: Type["SessionExtendRequest"], v: int) -> int:
        """Validate extension minutes."""
        if v < 1:
            raise ValueError("Extension must be at least 1 minute")

        if v > 10080:  # 1 week
            raise ValueError("Extension cannot exceed 1 week (10080 minutes)")

        return v


class SessionFilter(AdvancedFilter):
    """Filtering parameters for session list endpoint."""

    user_id: Optional[uuid.UUID] = Field(None, description="Filter by user ID")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_expired: Optional[bool] = Field(None, description="Filter by expiration status")
    ip_address: Optional[str] = Field(None, description="Filter by IP address")
    device_contains: Optional[str] = Field(None, description="Filter by device info containing text")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date")
    last_activity_after: Optional[datetime] = Field(None, description="Filter by last activity date")
    last_activity_before: Optional[datetime] = Field(None, description="Filter by last activity date")


class SessionStatistics(BaseCreateSchema):
    """Session statistics schema."""

    total_sessions: int = Field(..., description="Total number of sessions")
    active_sessions: int = Field(..., description="Number of active sessions")
    expired_sessions: int = Field(..., description="Number of expired sessions")
    revoked_sessions: int = Field(..., description="Number of revoked sessions")
    sessions_created_today: int = Field(..., description="Sessions created today")


class SessionActivityUpdate(BaseCreateSchema):
    """Schema for updating session activity."""

    ip_address: Optional[str] = Field(None, description="IP address of the activity")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls: Type["SessionActivityUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate IP address if provided."""
        if v is None:
            return v

        # Basic IP address validation
        import ipaddress

        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Invalid IP address format")
