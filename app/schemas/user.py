"""User-related schemas for API requests and responses."""

import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from .common import PaginatedResponse


class UserBase(BaseModel):
    """Base user schema with common fields."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Unique username for login",
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    email: EmailStr = Field(..., description="User email address")
    full_name: Optional[str] = Field(None, max_length=255, description="User's full display name")
    is_active: bool = Field(True, description="Whether the user account is active")
    is_superuser: bool = Field(False, description="Whether the user has superuser privileges")
    email_verified: bool = Field(False, description="Whether the email is verified")
    totp_enabled: bool = Field(False, description="Whether TOTP 2FA is enabled")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls: type["UserBase"], v: Optional[str]) -> Optional[str]:
        """Validate full name doesn't contain malicious content."""
        if v is None:
            return v
        # Remove any potential HTML/JS
        cleaned = re.sub(r"<[^>]*>", "", v)
        # Remove any potential SQL injection attempts
        if any(pattern in cleaned.lower() for pattern in ["<script", "javascript:", "onerror"]):
            raise ValueError("Full name contains invalid content")
        return cleaned.strip() if cleaned else None


class UserCreate(BaseModel):
    """Schema for creating a new user."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Unique username for login",
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password (will be hashed)",
    )
    full_name: Optional[str] = Field(None, max_length=255, description="User's full display name")
    is_active: bool = Field(True, description="Whether the user account is active")
    is_superuser: bool = Field(False, description="Whether the user has superuser privileges")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls: type["UserCreate"], v: str) -> str:
        """Validate password meets security requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls: type["UserCreate"], v: Optional[str]) -> Optional[str]:
        """Validate full name doesn't contain malicious content."""
        if v is None:
            return v
        # Remove any potential HTML/JS
        cleaned = re.sub(r"<[^>]*>", "", v)
        # Remove any potential SQL injection attempts
        if any(pattern in cleaned.lower() for pattern in ["<script", "javascript:", "onerror"]):
            raise ValueError("Full name contains invalid content")
        return cleaned.strip() if cleaned else None


class UserUpdate(BaseModel):
    """Schema for updating user information."""

    email: Optional[EmailStr] = Field(None, description="User email address")
    full_name: Optional[str] = Field(None, max_length=255, description="User's full display name")
    is_active: Optional[bool] = Field(None, description="Whether the user account is active")
    is_superuser: Optional[bool] = Field(None, description="Whether the user has superuser privileges")
    email_verified: Optional[bool] = Field(None, description="Whether the email is verified")
    totp_enabled: Optional[bool] = Field(None, description="Whether TOTP 2FA is enabled")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls: type["UserUpdate"], v: Optional[str]) -> Optional[str]:
        """Validate full name doesn't contain malicious content."""
        if v is None:
            return v
        # Remove any potential HTML/JS
        cleaned = re.sub(r"<[^>]*>", "", v)
        # Remove any potential SQL injection attempts
        if any(pattern in cleaned.lower() for pattern in ["<script", "javascript:", "onerror"]):
            raise ValueError("Full name contains invalid content")
        return cleaned.strip() if cleaned else None


class UserUpdatePassword(BaseModel):
    """Schema for updating user password."""

    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password (will be hashed)",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls: type["UserUpdatePassword"], v: str) -> str:
        """Validate password meets security requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserResponse(UserBase):
    """Schema for user response (excludes sensitive data)."""

    id: str = Field(..., description="User UUID")
    created_at: datetime = Field(..., description="User creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    last_login_ip: Optional[str] = Field(None, description="Last login IP address")
    login_count: int = Field(0, description="Total login count")
    failed_login_count: int = Field(0, description="Failed login attempts")

    class Config:
        """Pydantic config."""

        from_attributes = True


class UserCreateResponse(UserResponse):
    """Response after creating a user."""

    message: str = Field(default="User created successfully", description="Success message")


class UserListResponse(PaginatedResponse[UserResponse]):
    """Paginated list of users."""

    pass
