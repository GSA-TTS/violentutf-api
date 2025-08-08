"""Pydantic schemas for task management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.task import TaskPriority, TaskStatus


class TaskBase(BaseModel):
    """Base schema for task."""

    name: str = Field(..., description="Task name", max_length=255)
    task_type: str = Field(..., description="Type of task", max_length=100)
    description: Optional[str] = Field(None, description="Task description")
    priority: TaskPriority = Field(TaskPriority.NORMAL, description="Task priority")
    input_data: Dict[str, Any] = Field(default_factory=dict, description="Task input data")
    config: Dict[str, Any] = Field(default_factory=dict, description="Task configuration")
    max_retries: int = Field(3, description="Maximum retry attempts", ge=0, le=10)
    webhook_url: Optional[str] = Field(None, description="Webhook URL for notifications", max_length=2048)
    webhook_secret: Optional[str] = Field(None, description="Webhook secret", max_length=255)


class TaskCreate(TaskBase):
    """Schema for creating a task."""

    pass


class TaskUpdate(BaseModel):
    """Schema for updating a task."""

    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None)
    priority: Optional[TaskPriority] = Field(None)
    config: Optional[Dict[str, Any]] = Field(None)
    webhook_url: Optional[str] = Field(None, max_length=2048)
    webhook_secret: Optional[str] = Field(None, max_length=255)


class TaskResponse(TaskBase):
    """Schema for task response."""

    id: str = Field(..., description="Task ID")
    status: TaskStatus = Field(..., description="Task status")
    progress: int = Field(..., description="Task progress (0-100)", ge=0, le=100)
    progress_message: Optional[str] = Field(None, description="Current progress message")
    started_at: Optional[datetime] = Field(None, description="Task start time")
    completed_at: Optional[datetime] = Field(None, description="Task completion time")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    retry_count: int = Field(..., description="Number of retries attempted")
    celery_task_id: Optional[str] = Field(None, description="Celery task ID")
    webhook_called: bool = Field(..., description="Whether webhook was called")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="Task creator")

    class Config:  # noqa: D106
        from_attributes = True


class TaskListResponse(BaseModel):
    """Schema for task list response."""

    tasks: List[TaskResponse] = Field(..., description="List of tasks")
    total: int = Field(..., description="Total number of tasks")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")


class TaskStatusUpdate(BaseModel):
    """Schema for task status updates."""

    status: TaskStatus = Field(..., description="New task status")
    progress: Optional[int] = Field(None, description="Progress percentage", ge=0, le=100)
    progress_message: Optional[str] = Field(None, description="Progress message")
    output_data: Optional[Dict[str, Any]] = Field(None, description="Task output data")
    error_message: Optional[str] = Field(None, description="Error message")
    error_details: Optional[Dict[str, Any]] = Field(None, description="Error details")


class TaskResultBase(BaseModel):
    """Base schema for task result."""

    result_type: str = Field(..., description="Type of result", max_length=100)
    name: str = Field(..., description="Result name", max_length=255)
    description: Optional[str] = Field(None, description="Result description")
    data: Dict[str, Any] = Field(default_factory=dict, description="Result data")
    result_metadata: Dict[str, Any] = Field(default_factory=dict, description="Result metadata")
    confidence_score: Optional[float] = Field(None, description="Confidence score", ge=0.0, le=1.0)


class TaskResultCreate(TaskResultBase):
    """Schema for creating a task result."""

    pass


class TaskResultResponse(TaskResultBase):
    """Schema for task result response."""

    id: str = Field(..., description="Result ID")
    task_id: str = Field(..., description="Associated task ID")
    file_path: Optional[str] = Field(None, description="File path if stored")
    file_size: Optional[int] = Field(None, description="File size in bytes")
    mime_type: Optional[str] = Field(None, description="MIME type")
    quality_metrics: Optional[Dict[str, Any]] = Field(None, description="Quality metrics")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:  # noqa: D106
        from_attributes = True


class TaskResultListResponse(BaseModel):
    """Schema for task result list response."""

    results: List[TaskResultResponse] = Field(..., description="List of task results")
    total: int = Field(..., description="Total number of results")


class TaskExecutionRequest(BaseModel):
    """Schema for task execution request."""

    task_id: str = Field(..., description="Task ID to execute")
    config_override: Optional[Dict[str, Any]] = Field(None, description="Configuration overrides")


class TaskExecutionResponse(BaseModel):
    """Schema for task execution response."""

    task_id: str = Field(..., description="Task ID")
    execution_id: str = Field(..., description="Execution ID")
    status: TaskStatus = Field(..., description="Execution status")
    started_at: datetime = Field(..., description="Execution start time")
    celery_task_id: Optional[str] = Field(None, description="Celery task ID")
    status_url: str = Field(..., description="URL to check task status")
    webhook_configured: bool = Field(..., description="Whether webhook is configured")


class TaskStatsResponse(BaseModel):
    """Schema for task statistics response."""

    total_tasks: int = Field(..., description="Total number of tasks")
    pending_tasks: int = Field(..., description="Number of pending tasks")
    running_tasks: int = Field(..., description="Number of running tasks")
    completed_tasks: int = Field(..., description="Number of completed tasks")
    failed_tasks: int = Field(..., description="Number of failed tasks")
    cancelled_tasks: int = Field(..., description="Number of cancelled tasks")
    avg_execution_time: Optional[float] = Field(None, description="Average execution time in seconds")
    success_rate: Optional[float] = Field(None, description="Success rate (0-1)")


class TaskRetryRequest(BaseModel):
    """Schema for task retry request."""

    reset_retry_count: bool = Field(False, description="Whether to reset retry count")
    config_override: Optional[Dict[str, Any]] = Field(None, description="Configuration overrides")


class TaskBulkActionRequest(BaseModel):
    """Schema for bulk task actions."""

    task_ids: List[str] = Field(..., description="List of task IDs", min_length=1, max_length=100)
    action: str = Field(..., description="Action to perform")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Action parameters")


class TaskBulkActionResponse(BaseModel):
    """Schema for bulk task action response."""

    total_requested: int = Field(..., description="Total tasks requested")
    successful: int = Field(..., description="Successfully processed tasks")
    failed: int = Field(..., description="Failed to process tasks")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Error details")
    results: List[Dict[str, Any]] = Field(default_factory=list, description="Action results")
