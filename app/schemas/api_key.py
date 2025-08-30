"""API Key schemas for requests and responses."""

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


class APIKeyBase(BaseCreateSchema):
    """Base API key schema with common fields."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Descriptive name for the API key",
    )
    description: Optional[str] = Field(None, max_length=1000, description="Detailed description of key purpose")
    permissions: Dict[str, Any] = Field(default_factory=dict, description="Permission scopes as JSON")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration timestamp")

    @field_validator("name")
    @classmethod
    def validate_name(cls: Type["APIKeyBase"], v: str) -> str:
        """Validate API key name."""
        if not v.strip():
            raise ValueError("API key name cannot be empty")

        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"API key name cannot contain '{char}'")

        return v.strip()

    @field_validator("description")
    @classmethod
    def validate_description(cls: Type["APIKeyBase"], v: Optional[str]) -> Optional[str]:
        """Validate description if provided."""
        if v is None:
            return v

        # Remove potentially dangerous characters
        dangerous_chars = ["<script", "javascript:", "onerror"]
        for char in dangerous_chars:
            if char in v.lower():
                raise ValueError("Description contains invalid content")

        return v.strip() if v.strip() else None

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls: Type["APIKeyBase"], v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate permissions structure."""
        if not isinstance(v, dict):
            raise ValueError("Permissions must be a dictionary")

        # Define valid permission scopes
        VALID_SCOPES = {
            # Global permissions
            "read",
            "write",
            "delete",
            "admin",
            "*",
            # Resource-specific permissions
            "users:read",
            "users:write",
            "users:delete",
            "users:*",
            "api_keys:read",
            "api_keys:write",
            "api_keys:delete",
            "api_keys:*",
            "sessions:read",
            "sessions:write",
            "sessions:delete",
            "sessions:*",
            "audit_logs:read",
            "audit_logs:*",
        }

        for scope, enabled in v.items():
            # Check if scope is valid
            if scope not in VALID_SCOPES and not scope.endswith(":*"):
                raise ValueError(f"Invalid permission scope: {scope}")

            # Permissions must be boolean
            if not isinstance(enabled, bool):
                raise ValueError(f"Permission value for '{scope}' must be boolean")

        return v


class APIKeyCreate(APIKeyBase):
    """Schema for creating an API key."""

    # All fields inherited from base
    pass


class APIKeyUpdate(BaseUpdateSchema):
    """Schema for updating an API key."""

    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Descriptive name")
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    permissions: Optional[Dict[str, Any]] = Field(None, description="Permission scopes")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")

    @field_validator("name")
    @classmethod
    def validate_name(cls: Type["APIKeyUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate name if provided."""
        if v is None:
            return v

        if not v.strip():
            raise ValueError("API key name cannot be empty")

        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"API key name cannot contain '{char}'")

        return v.strip()

    @field_validator("description")
    @classmethod
    def validate_description(cls: Type["APIKeyUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate description if provided."""
        if v is None:
            return v

        # Remove potentially dangerous characters
        dangerous_chars = ["<script", "javascript:", "onerror"]
        for char in dangerous_chars:
            if char in v.lower():
                raise ValueError("Description contains invalid content")

        return v.strip() if v.strip() else None

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls: Type["APIKeyUpdate"], v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate permissions if provided."""
        if v is None:
            return v

        return v


class APIKeyResponse(BaseModelSchema):
    """Schema for API key responses (excludes sensitive data)."""

    name: str = Field(..., description="Descriptive name for the API key")
    description: Optional[str] = Field(None, description="Detailed description")
    key_prefix: str = Field(..., description="First few characters of key for identification")
    masked_key: str = Field(..., description="Masked version of the key for display")
    permissions: Dict[str, Any] = Field(..., description="Permission scopes")
    last_used_at: Optional[datetime] = Field(None, description="Last time key was used")
    last_used_ip: Optional[str] = Field(None, description="IP address from last use")
    usage_count: int = Field(..., description="Number of times key has been used")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    is_active: bool = Field(..., description="Whether the key is active and valid")
    revoked_at: Optional[datetime] = Field(None, description="When the key was revoked")
    user_id: uuid.UUID = Field(..., description="ID of the user who owns this key")


class APIKeyCreateResponse(BaseModelSchema):
    """Response after creating an API key (includes full key once)."""

    id: uuid.UUID = Field(..., description="Unique API key identifier")
    name: str = Field(..., description="Descriptive name")
    description: Optional[str] = Field(None, description="Description")
    key: str = Field(..., description="Full API key (only shown once)")
    key_prefix: str = Field(..., description="Key prefix for identification")
    permissions: Dict[str, Any] = Field(..., description="Permission scopes")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    user_id: uuid.UUID = Field(..., description="Owner user ID")
    created_at: datetime = Field(..., description="Creation timestamp")

    # Security warning in response
    warning: str = Field(
        default="Store this API key securely. It will not be shown again.",
        description="Security warning about key storage",
    )


class APIKeyFilter(AdvancedFilter):
    """Filtering parameters for API key list endpoint."""

    name: Optional[str] = Field(None, description="Filter by name")
    user_id: Optional[uuid.UUID] = Field(None, description="Filter by user ID")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    has_expired: Optional[bool] = Field(None, description="Filter by expiration status")
    last_used_after: Optional[datetime] = Field(None, description="Filter by last used date")
    last_used_before: Optional[datetime] = Field(None, description="Filter by last used date")


class APIKeyUsageStats(BaseCreateSchema):
    """API key usage statistics."""

    total_keys: int = Field(..., description="Total number of API keys")
    active_keys: int = Field(..., description="Number of active keys")
    expired_keys: int = Field(..., description="Number of expired keys")
    revoked_keys: int = Field(..., description="Number of revoked keys")
    keys_used_today: int = Field(..., description="Keys used in last 24 hours")
    total_requests: int = Field(..., description="Total requests across all keys")


class APIKeyPermissionTemplate(BaseCreateSchema):
    """Predefined permission templates for common use cases."""

    name: str = Field(..., description="Template name")
    description: str = Field(..., description="Template description")
    permissions: Dict[str, Any] = Field(..., description="Permission set")

    @classmethod
    def get_templates(
        cls: Type["APIKeyPermissionTemplate"],
    ) -> Dict[str, "APIKeyPermissionTemplate"]:
        """Get predefined permission templates."""
        return {
            "read_only": APIKeyPermissionTemplate(
                name="Read Only",
                description="Read access to all resources",
                permissions={
                    "users:read": True,
                    "api_keys:read": True,
                    "sessions:read": True,
                    "audit_logs:read": True,
                },
            ),
            "user_management": APIKeyPermissionTemplate(
                name="User Management",
                description="Full access to user resources",
                permissions={
                    "users:*": True,
                },
            ),
            "api_key_management": APIKeyPermissionTemplate(
                name="API Key Management",
                description="Full access to API key resources",
                permissions={
                    "api_keys:*": True,
                },
            ),
            "session_management": APIKeyPermissionTemplate(
                name="Session Management",
                description="Full access to session resources",
                permissions={
                    "sessions:*": True,
                },
            ),
            "admin": APIKeyPermissionTemplate(
                name="Administrator",
                description="Full access to all resources",
                permissions={
                    "admin": True,
                },
            ),
        }
