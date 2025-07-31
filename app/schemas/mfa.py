"""MFA request/response schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.mfa import MFAMethod


class MFASetupStart(BaseModel):
    """Schema for starting MFA setup."""

    device_name: str = Field(..., min_length=1, max_length=255, description="Name for the MFA device")


class MFASetupResponse(BaseModel):
    """Response for MFA setup initiation."""

    secret: str = Field(..., description="TOTP secret (for manual entry)")
    provisioning_uri: str = Field(..., description="otpauth:// URI for QR code")
    qr_code: str = Field(..., description="QR code as base64 data URI")


class MFASetupComplete(BaseModel):
    """Schema for completing MFA setup."""

    token: str = Field(..., pattern=r"^\d{6}$", description="6-digit TOTP token")

    @field_validator("token")
    def validate_token(cls, v: str) -> str:
        """Ensure token is 6 digits."""
        if not v.isdigit() or len(v) != 6:
            raise ValueError("Token must be exactly 6 digits")
        return v


class MFABackupCodesResponse(BaseModel):
    """Response containing backup codes."""

    backup_codes: List[str] = Field(..., description="List of backup codes")


class MFAChallengeCreate(BaseModel):
    """Schema for creating an MFA challenge."""

    user_id: str = Field(..., description="User ID (temporary - would come from partial auth)")
    method: Optional[MFAMethod] = Field(None, description="Specific MFA method to use")


class MFAChallengeResponse(BaseModel):
    """Response for MFA challenge creation."""

    challenge_id: str = Field(..., description="Challenge identifier")
    expires_in: int = Field(..., description="Seconds until challenge expires")


class MFAChallengeVerify(BaseModel):
    """Schema for verifying an MFA challenge."""

    challenge_id: str = Field(..., description="Challenge identifier")
    token: str = Field(..., min_length=6, max_length=20, description="MFA token")


class MFADeviceResponse(BaseModel):
    """Response for a single MFA device."""

    id: str = Field(..., description="Device ID")
    name: str = Field(..., description="Device name")
    method: str = Field(..., description="MFA method")
    is_active: bool = Field(..., description="Whether device is active")
    is_primary: bool = Field(..., description="Whether device is primary")
    verified_at: Optional[str] = Field(None, description="When device was verified")
    last_used_at: Optional[str] = Field(None, description="When device was last used")
    created_at: str = Field(..., description="When device was created")


class MFADeviceList(BaseModel):
    """Response containing list of MFA devices."""

    devices: List[MFADeviceResponse] = Field(..., description="List of MFA devices")


class MFAPolicyResponse(BaseModel):
    """Response for MFA policy information."""

    is_required: bool = Field(..., description="Whether MFA is required")
    grace_period_remaining: Optional[int] = Field(None, description="Days remaining in grace period")
    required_methods: List[str] = Field(default_factory=list, description="Required MFA methods")
    enforcement_level: str = Field("optional", description="Policy enforcement level")
