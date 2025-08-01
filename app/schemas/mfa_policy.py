"""MFA Policy schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class PolicyConditions(BaseModel):
    """Conditions for MFA policy applicability."""

    roles: Optional[List[str]] = Field(None, description="Required roles")
    permissions: Optional[List[str]] = Field(None, description="Required permissions")
    organization_ids: Optional[List[str]] = Field(None, description="Organization IDs")
    is_superuser: Optional[bool] = Field(None, description="Superuser requirement")
    min_account_age_days: Optional[int] = Field(None, description="Minimum account age in days")


class MFAPolicyCreate(BaseModel):
    """Schema for creating an MFA policy."""

    name: str = Field(..., min_length=1, max_length=255, description="Policy name")
    description: str = Field(..., description="Policy description")
    conditions: PolicyConditions = Field(..., description="Policy conditions")
    required_methods: List[str] = Field(..., description="Required MFA methods")
    min_methods: int = Field(1, ge=1, le=5, description="Minimum number of methods")
    grace_period_days: int = Field(0, ge=0, description="Grace period for new users")
    enforcement_level: str = Field("required", description="Enforcement level: required, recommended, optional")
    bypass_permissions: Optional[List[str]] = Field(None, description="Permissions that bypass MFA")
    priority: int = Field(0, description="Policy priority (higher = higher priority)")

    @field_validator("enforcement_level")
    def validate_enforcement_level(cls, v: str) -> str:
        """Validate enforcement level."""
        valid_levels = ["required", "recommended", "optional"]
        if v not in valid_levels:
            raise ValueError(f"Must be one of: {valid_levels}")
        return v

    @field_validator("required_methods")
    def validate_methods(cls, v: List[str]) -> List[str]:
        """Validate MFA methods."""
        valid_methods = ["totp", "sms", "email", "backup_code", "webauthn"]
        for method in v:
            if method not in valid_methods:
                raise ValueError(f"Invalid method: {method}. Must be one of: {valid_methods}")
        return v


class MFAPolicyUpdate(BaseModel):
    """Schema for updating an MFA policy."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = None
    conditions: Optional[PolicyConditions] = None
    required_methods: Optional[List[str]] = None
    min_methods: Optional[int] = Field(None, ge=1, le=5)
    grace_period_days: Optional[int] = Field(None, ge=0)
    enforcement_level: Optional[str] = None
    bypass_permissions: Optional[List[str]] = None

    @field_validator("enforcement_level")
    def validate_enforcement_level(cls, v: Optional[str]) -> Optional[str]:
        """Validate enforcement level."""
        if v is not None:
            valid_levels = ["required", "recommended", "optional"]
            if v not in valid_levels:
                raise ValueError(f"Must be one of: {valid_levels}")
        return v


class MFAPolicyResponse(BaseModel):
    """Response for a single MFA policy."""

    id: str = Field(..., description="Policy ID")
    name: str = Field(..., description="Policy name")
    description: str = Field(..., description="Policy description")
    is_active: bool = Field(..., description="Whether policy is active")
    priority: int = Field(..., description="Policy priority")
    enforcement_level: str = Field(..., description="Enforcement level")
    grace_period_days: int = Field(..., description="Grace period days")
    min_methods: int = Field(..., description="Minimum methods required")
    conditions: Dict[str, Any] = Field(..., description="Policy conditions")
    required_methods: List[str] = Field(..., description="Required MFA methods")
    bypass_permissions: List[str] = Field(..., description="Bypass permissions")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: Optional[str] = Field(None, description="Update timestamp")


class MFAPolicyList(BaseModel):
    """Response containing list of MFA policies."""

    policies: List[MFAPolicyResponse] = Field(..., description="List of policies")


class UserMFARequirement(BaseModel):
    """Response for user MFA requirement check."""

    user_id: str = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    is_required: bool = Field(..., description="Whether MFA is required")
    enforcement_level: str = Field(..., description="Enforcement level")
    policy_name: Optional[str] = Field(None, description="Applicable policy name")
    reason: Optional[str] = Field(None, description="Reason for requirement")
    grace_period_remaining: Optional[int] = Field(None, description="Days remaining in grace period")
    required_methods: List[str] = Field(default_factory=list, description="Required methods")
    min_methods: int = Field(1, description="Minimum methods required")
