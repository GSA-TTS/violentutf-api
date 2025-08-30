"""Common schemas used across the API."""

from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error description")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Error timestamp",
    )


class ValidationErrorResponse(BaseModel):
    """Validation error response."""

    error: str = Field(default="Validation Error", description="Error type")
    detail: List[Dict[str, Any]] = Field(..., description="Validation error details")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Error timestamp",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Current timestamp")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")


class PaginationParams(BaseModel):
    """Pagination parameters."""

    page: int = Field(1, ge=1, description="Page number (1-based)")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")

    @property
    def skip(self) -> int:
        """Calculate skip value for database queries."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Get limit value for database queries."""
        return self.page_size


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response."""

    items: List[T] = Field(..., description="List of items")
    total: int = Field(..., ge=0, description="Total number of items")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")

    @field_validator("total_pages", mode="before")
    @classmethod
    def calculate_total_pages(cls, v: Optional[int], info) -> int:  # type: ignore[no-untyped-def]
        """Calculate total pages based on total items and page size."""
        if v is not None:
            return int(v)
        # Access other fields using info.data
        data = info.data if hasattr(info, "data") else {}
        total = data.get("total", 0)
        page_size = data.get("page_size", 20)
        return (total + page_size - 1) // page_size if page_size > 0 else 0


class IdempotencyHeader(BaseModel):
    """Idempotency key header."""

    idempotency_key: Optional[str] = Field(
        None,
        description="Unique key for idempotent requests",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9-_]+$",
    )
