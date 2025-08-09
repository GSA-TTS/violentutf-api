"""Task management models for async processing."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class TaskStatus(str, Enum):
    """Task execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(str, Enum):
    """Task priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class Task(BaseModelMixin, Base):
    """Model for async task management."""

    # Basic task information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[TaskStatus] = mapped_column(
        SQLEnum(TaskStatus), nullable=False, default=TaskStatus.PENDING, index=True
    )
    priority: Mapped[TaskPriority] = mapped_column(
        SQLEnum(TaskPriority), nullable=False, default=TaskPriority.NORMAL, index=True
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize Task with proper defaults for unit testing."""
        # Set defaults for fields that should have them
        if "status" not in kwargs:
            kwargs["status"] = TaskStatus.PENDING
        if "priority" not in kwargs:
            kwargs["priority"] = TaskPriority.NORMAL
        if "progress" not in kwargs:
            kwargs["progress"] = 0
        if "retry_count" not in kwargs:
            kwargs["retry_count"] = 0
        if "max_retries" not in kwargs:
            kwargs["max_retries"] = 3
        if "webhook_called" not in kwargs:
            kwargs["webhook_called"] = False
        if "input_data" not in kwargs:
            kwargs["input_data"] = {}
        if "config" not in kwargs:
            kwargs["config"] = {}

        super().__init__(**kwargs)

    # Task configuration and data
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    input_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    output_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Execution tracking
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    progress: Mapped[int] = mapped_column(nullable=False, default=0)  # 0-100
    progress_message: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    retry_count: Mapped[int] = mapped_column(nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(nullable=False, default=3)

    # Celery integration
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, unique=True)

    # Webhooks
    webhook_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    webhook_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    webhook_called: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Relationships
    results: Mapped[list["TaskResult"]] = relationship(
        "TaskResult", back_populates="task", cascade="all, delete-orphan"
    )

    # Model-specific constraints and indexes
    _model_constraints = (
        Index("idx_task_status_priority", "status", "priority"),
        Index("idx_task_type_status", "task_type", "status"),
        Index("idx_task_created_status", "created_at", "status"),
        Index("idx_task_celery_id", "celery_task_id"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<Task(id='{self.id}', name='{self.name}', type='{self.task_type}', status='{self.status.name}')>"


class TaskResult(BaseModelMixin, Base):
    """Model for storing task execution results and artifacts."""

    # Relationship to task
    task_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("task.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task: Mapped[Task] = relationship("Task", back_populates="results")

    # Result information
    result_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Result data
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    result_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # File storage
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mime_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Quality metrics
    confidence_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    quality_metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Priority flag
    is_primary: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_task_result_type", "task_id", "result_type"),
        Index("idx_task_result_task_created", "task_id", "created_at"),
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize TaskResult with proper defaults for unit testing."""
        # Set defaults for fields that should have them
        if "data" not in kwargs:
            kwargs["data"] = {}
        if "result_metadata" not in kwargs:
            kwargs["result_metadata"] = {}
        if "is_primary" not in kwargs:
            kwargs["is_primary"] = False

        super().__init__(**kwargs)

    def __repr__(self) -> str:  # noqa: D105
        return f"<TaskResult(id='{self.id}', task_id='{self.task_id}', type='{self.result_type}')>"
