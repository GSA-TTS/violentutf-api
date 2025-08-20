"""API Key response DTOs for Clean Architecture compliance."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from ..common import PaginatedResponse


class APIKeyResponse(BaseModel):
    """API Key response for safe exposure."""

    id: str = Field(..., description="API Key identifier")
    name: str = Field(..., description="API Key name")
    key_preview: str = Field(..., description="Masked API key preview")
    permissions: List[str] = Field(default_factory=list, description="API Key permissions")
    is_active: bool = Field(..., description="API Key status")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(0, description="Total usage count")
    organization_id: Optional[str] = Field(None, description="Organization identifier")
    created_by: str = Field(..., description="Creator user identifier")


class APIKeyCreateResponse(BaseModel):
    """API Key creation response with full key."""

    id: str = Field(..., description="API Key identifier")
    name: str = Field(..., description="API Key name")
    key: str = Field(..., description="Full API key (shown only once)")
    permissions: List[str] = Field(default_factory=list, description="API Key permissions")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")
    message: str = Field(
        default="API key created successfully. Save this key - it will not be shown again.",
        description="Important message",
    )


class APIKeyListResponse(PaginatedResponse[APIKeyResponse]):
    """Paginated API key list response."""

    pass
