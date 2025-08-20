"""User response DTOs for Clean Architecture compliance."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from ..common import PaginatedResponse


class UserProfileResponse(BaseModel):
    """Minimal user profile for general use."""

    id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    is_active: bool = Field(..., description="Account status")
    roles: List[str] = Field(default_factory=list, description="User roles")


class UserDetailResponse(BaseModel):
    """Detailed user response for admin operations."""

    id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    is_active: bool = Field(..., description="Account status")
    is_verified: bool = Field(..., description="Email verification status")
    is_superuser: bool = Field(..., description="Superuser status")
    roles: List[str] = Field(default_factory=list, description="User roles")
    organization_id: Optional[str] = Field(None, description="Organization identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    last_login_ip: Optional[str] = Field(None, description="Last login IP address")
    login_count: int = Field(0, description="Total login count")
    failed_login_count: int = Field(0, description="Failed login attempts")


class UserListResponse(PaginatedResponse[UserDetailResponse]):
    """Paginated user list response."""

    pass
