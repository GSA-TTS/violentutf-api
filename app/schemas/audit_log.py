"""Audit Log schemas for requests and responses."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Type

from pydantic import Field, field_validator

from app.schemas.base import AdvancedFilter, BaseCreateSchema, BaseModelSchema


class AuditLogResponse(BaseModelSchema):
    """Schema for audit log responses (read-only)."""

    action: str = Field(..., description="Action performed")
    resource_type: str = Field(..., description="Type of resource affected")
    resource_id: Optional[str] = Field(None, description="ID of the affected resource")
    user_id: Optional[uuid.UUID] = Field(None, description="User who performed the action")
    user_email: Optional[str] = Field(None, description="Email of user at time of action")
    ip_address: Optional[str] = Field(None, description="IP address of the request")
    user_agent: Optional[str] = Field(None, description="User agent string from the request")
    changes: Optional[Dict[str, Any]] = Field(None, description="Before/after values for updates")
    action_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional context about the action")
    status: str = Field(..., description="Result status: success, failure, error")
    error_message: Optional[str] = Field(None, description="Error message if action failed")
    duration_ms: Optional[int] = Field(None, description="Duration of the action in milliseconds")


class AuditLogFilter(AdvancedFilter):
    """Filtering parameters for audit log list endpoint."""

    action: Optional[str] = Field(None, description="Filter by action")
    resource_type: Optional[str] = Field(None, description="Filter by resource type")
    resource_id: Optional[str] = Field(None, description="Filter by resource ID")
    user_id: Optional[uuid.UUID] = Field(None, description="Filter by user ID")
    user_email: Optional[str] = Field(None, description="Filter by user email")
    ip_address: Optional[str] = Field(None, description="Filter by IP address")
    status: Optional[str] = Field(None, description="Filter by status")
    action_contains: Optional[str] = Field(None, description="Filter by actions containing text")
    resource_contains: Optional[str] = Field(None, description="Filter by resource types containing text")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date")
    duration_min_ms: Optional[int] = Field(None, description="Filter by minimum duration")
    duration_max_ms: Optional[int] = Field(None, description="Filter by maximum duration")

    @field_validator("status")
    @classmethod
    def validate_status(cls: Type["AuditLogFilter"], v: Optional[str]) -> Optional[str]:
        """Validate status filter."""
        if v is None:
            return v

        valid_statuses = ["success", "failure", "error"]
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")

        return v


class AuditLogStatistics(BaseCreateSchema):
    """Audit log statistics schema."""

    total_logs: int = Field(..., description="Total number of audit logs")
    logs_today: int = Field(..., description="Logs created today")
    success_rate: float = Field(..., description="Success rate percentage")
    failure_rate: float = Field(..., description="Failure rate percentage")
    error_rate: float = Field(..., description="Error rate percentage")
    avg_duration_ms: Optional[float] = Field(None, description="Average action duration")
    top_actions: Dict[str, int] = Field(..., description="Most common actions")
    top_users: Dict[str, int] = Field(..., description="Most active users")
    top_resource_types: Dict[str, int] = Field(..., description="Most accessed resource types")


class AuditLogSummary(BaseCreateSchema):
    """Audit log summary for a specific resource."""

    resource_type: str = Field(..., description="Resource type")
    resource_id: str = Field(..., description="Resource ID")
    total_actions: int = Field(..., description="Total number of actions")
    first_action_at: Optional[datetime] = Field(None, description="Timestamp of first action")
    last_action_at: Optional[datetime] = Field(None, description="Timestamp of last action")
    unique_users: int = Field(..., description="Number of unique users who acted on this resource")
    action_breakdown: Dict[str, int] = Field(..., description="Count of each action type")
    status_breakdown: Dict[str, int] = Field(..., description="Count of each status type")


class AuditLogExportRequest(BaseCreateSchema):
    """Schema for audit log export requests."""

    format: str = Field("csv", description="Export format (csv, json)")
    date_from: Optional[datetime] = Field(None, description="Start date for export")
    date_to: Optional[datetime] = Field(None, description="End date for export")
    user_id: Optional[uuid.UUID] = Field(None, description="Filter by specific user")
    resource_type: Optional[str] = Field(None, description="Filter by resource type")
    actions: Optional[list[str]] = Field(None, description="Filter by specific actions")
    include_metadata: bool = Field(False, description="Include metadata and changes in export")

    @field_validator("format")
    @classmethod
    def validate_format(cls: Type["AuditLogExportRequest"], v: str) -> str:
        """Validate export format."""
        valid_formats = ["csv", "json"]
        if v not in valid_formats:
            raise ValueError(f"Format must be one of: {', '.join(valid_formats)}")

        return v

    @field_validator("actions")
    @classmethod
    def validate_actions(cls: Type["AuditLogExportRequest"], v: Optional[list[str]]) -> Optional[list[str]]:
        """Validate actions list."""
        if v is None:
            return v

        if len(v) > 50:
            raise ValueError("Cannot filter by more than 50 actions")

        # Validate each action format
        for action in v:
            if not action or len(action) > 100:
                raise ValueError("Each action must be 1-100 characters")

            if "." not in action:
                raise ValueError("Actions must follow 'resource.action' format")

        return v
