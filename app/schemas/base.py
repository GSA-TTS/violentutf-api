"""Base schemas for consistent API responses and requests."""

import uuid
from datetime import datetime
from typing import Dict, Generic, List, Optional, Type, TypeVar, Union

from pydantic import BaseModel, Field, ValidationInfo, field_validator

# Type variables for generic schemas
DataT = TypeVar("DataT")
ModelT = TypeVar("ModelT")


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = {
        "from_attributes": True,
        "str_strip_whitespace": True,
        "validate_assignment": True,
        "use_enum_values": True,
    }


class BaseResponse(BaseSchema, Generic[DataT]):
    """Standard response wrapper for all API endpoints."""

    data: DataT = Field(..., description="Response data")
    message: Optional[str] = Field(None, description="Optional response message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    trace_id: Optional[str] = Field(None, description="Request trace ID for debugging")


class PaginatedResponse(BaseSchema, Generic[DataT]):
    """Paginated response for list endpoints."""

    data: List[DataT] = Field(..., description="List of items")
    pagination: "PaginationInfo" = Field(..., description="Pagination information")
    filters: Optional[Dict[str, object]] = Field(None, description="Applied filters")
    total_count: int = Field(..., description="Total number of items (across all pages)")
    message: Optional[str] = Field(None, description="Optional response message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    trace_id: Optional[str] = Field(None, description="Request trace ID for debugging")


class PaginationInfo(BaseSchema):
    """Pagination metadata."""

    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, le=100, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_prev: bool = Field(..., description="Whether there is a previous page")
    next_cursor: Optional[str] = Field(None, description="Cursor for next page (if using cursor pagination)")
    prev_cursor: Optional[str] = Field(None, description="Cursor for previous page (if using cursor pagination)")


class BaseRequest(BaseSchema):
    """Base schema for request bodies."""

    pass


class BaseFilter(BaseSchema):
    """Base filtering parameters for list endpoints."""

    # Pagination
    page: int = Field(1, ge=1, le=1000, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")

    # Cursor-based pagination (alternative to offset-based)
    cursor: Optional[str] = Field(None, description="Cursor for pagination")

    # Sorting
    sort_by: Optional[str] = Field(None, description="Field to sort by")
    sort_order: str = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")

    # Search
    search: Optional[str] = Field(None, min_length=1, max_length=255, description="Search query")

    # Date filtering
    created_after: Optional[datetime] = Field(None, description="Filter items created after this date")
    created_before: Optional[datetime] = Field(None, description="Filter items created before this date")
    updated_after: Optional[datetime] = Field(None, description="Filter items updated after this date")
    updated_before: Optional[datetime] = Field(None, description="Filter items updated before this date")

    # Status filtering
    include_deleted: bool = Field(False, description="Include soft-deleted items")

    @field_validator("search")
    @classmethod
    def validate_search(cls: Type["BaseFilter"], v: Optional[str]) -> Optional[str]:
        """Validate and sanitize search query."""
        if v is None:
            return v

        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--", "/*", "*/"]
        for char in dangerous_chars:
            v = v.replace(char, "")

        return v.strip() if v.strip() else None


class BaseModelSchema(BaseSchema):
    """Base schema for database models with audit fields."""

    id: uuid.UUID = Field(..., description="Unique identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="Creator identifier")
    updated_by: Optional[str] = Field(None, description="Last updater identifier")
    version: int = Field(..., description="Version for optimistic locking")


class BaseCreateSchema(BaseSchema):
    """Base schema for create operations."""

    pass


class BaseUpdateSchema(BaseSchema):
    """Base schema for update operations."""

    version: Optional[int] = Field(None, description="Version for optimistic locking")


class HealthCheckResponse(BaseSchema):
    """Health check response schema."""

    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Check timestamp")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")


class DetailedHealthResponse(BaseSchema):
    """Detailed health check response schema."""

    status: str = Field(..., description="Overall service status")
    timestamp: datetime = Field(..., description="Check timestamp")
    checks: Dict[str, bool] = Field(..., description="Individual health checks")
    details: Optional[Dict[str, object]] = Field(None, description="Additional health check details")


class OperationResult(BaseSchema):
    """Result of a database operation."""

    success: bool = Field(..., description="Whether the operation succeeded")
    message: str = Field(..., description="Operation result message")
    affected_rows: Optional[int] = Field(None, description="Number of affected rows")
    operation_id: Optional[str] = Field(None, description="Unique operation identifier")


class BulkOperationRequest(BaseSchema, Generic[DataT]):
    """Request for bulk operations."""

    items: List[DataT] = Field(..., min_length=1, max_length=100, description="Items to process")
    operation: str = Field(..., description="Operation to perform")
    options: Optional[Dict[str, object]] = Field(None, description="Additional operation options")


class BulkOperationResponse(BaseSchema):
    """Response for bulk operations."""

    total_items: int = Field(..., description="Total items processed")
    successful_items: int = Field(..., description="Successfully processed items")
    failed_items: int = Field(..., description="Failed items")
    errors: List[Dict[str, object]] = Field(default_factory=list, description="Errors that occurred")
    operation_id: str = Field(..., description="Unique operation identifier")


class ValidationErrorDetail(BaseSchema):
    """Detailed validation error information."""

    field: str = Field(..., description="Field that failed validation")
    value: object = Field(..., description="Invalid value provided")
    message: str = Field(..., description="Validation error message")
    error_type: str = Field(..., description="Type of validation error")


class APIErrorResponse(BaseSchema):
    """Standard API error response following RFC 7807."""

    type: str = Field(..., description="URI reference that identifies the problem type")
    title: str = Field(..., description="Short, human-readable summary of the problem")
    status: int = Field(..., description="HTTP status code")
    detail: str = Field(..., description="Human-readable explanation of the problem")
    instance: str = Field(..., description="URI reference that identifies the specific occurrence")
    timestamp: str = Field(..., description="ISO 8601 timestamp when the error occurred")
    trace_id: Optional[str] = Field(None, description="Request trace ID for debugging")
    validation_errors: Optional[List[ValidationErrorDetail]] = Field(
        None, description="Detailed validation errors for validation failures"
    )
    help_url: Optional[str] = Field(None, description="URL to documentation about this error")


# Operator-based filtering support
class FilterOperator(BaseSchema):
    """Filter operator for advanced queries."""

    field: str = Field(..., description="Field to filter on")
    operator: str = Field(
        ...,
        pattern="^(eq|ne|gt|lt|gte|lte|in|nin|contains|icontains|startswith|endswith|isnull)$",
        description="Filter operator",
    )
    value: Union[str, int, float, bool, List[object], None] = Field(..., description="Filter value")

    @field_validator("value")
    @classmethod
    def validate_value_for_operator(
        cls: Type["FilterOperator"], v: Union[str, int, float, bool, List[object], None], info: ValidationInfo
    ) -> Union[str, int, float, bool, List[object], None]:
        """Validate value based on operator."""
        if not hasattr(info, "data") or "operator" not in info.data:
            return v

        operator = info.data["operator"]

        # Operators that require list values
        if operator in ["in", "nin"] and not isinstance(v, list):
            raise ValueError(f"Operator '{operator}' requires a list value")

        # Operators that don't allow null values (except isnull)
        if operator != "isnull" and v is None:
            raise ValueError(f"Operator '{operator}' does not allow null values")

        return v


class AdvancedFilter(BaseFilter):
    """Advanced filtering with operator support."""

    filters: Optional[List[FilterOperator]] = Field(None, description="Advanced filter operations")

    # Logical operators for combining filters
    filter_logic: str = Field(default="and", pattern="^(and|or)$", description="Logic for combining filters (and/or)")
