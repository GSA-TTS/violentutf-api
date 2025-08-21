"""Authentication response DTOs for Clean Architecture compliance."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AuthTokenResponse(BaseModel):
    """Authentication token response."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token for token renewal")


class AuthUserResponse(BaseModel):
    """Authenticated user information."""

    id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    is_active: bool = Field(..., description="Account status")
    is_verified: bool = Field(..., description="Email verification status")
    roles: List[str] = Field(default_factory=list, description="User roles")
    organization_id: Optional[str] = Field(None, description="Organization identifier")
    last_login_at: Optional[datetime] = Field(None, description="Previous login timestamp")


class AuthResponse(BaseModel):
    """Complete authentication response."""

    user: AuthUserResponse = Field(..., description="User information")
    token: AuthTokenResponse = Field(..., description="Authentication token")
    message: str = Field(default="Login successful", description="Response message")


class LogoutResponse(BaseModel):
    """Logout response."""

    message: str = Field(default="Logout successful", description="Response message")
    logged_out_at: datetime = Field(..., description="Logout timestamp")
