"""Orchestrator models for PyRIT integration."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from app.models.task import Task

from sqlalchemy import JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class OrchestratorStatus(str, Enum):
    """Orchestrator configuration status."""

    CONFIGURED = "configured"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    DEPRECATED = "deprecated"


class ExecutionType(str, Enum):
    """Types of orchestrator executions."""

    PROMPT_LIST = "prompt_list"
    DATASET = "dataset"
    SINGLE_PROMPT = "single_prompt"
    CONVERSATION = "conversation"
    BENCHMARK = "benchmark"


class ExecutionStatus(str, Enum):
    """Execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class OrchestratorConfiguration(BaseModelMixin, Base):
    """Model for orchestrator configurations."""

    # Basic configuration
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    orchestrator_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Configuration data
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Status tracking
    status: Mapped[OrchestratorStatus] = mapped_column(
        SQLEnum(OrchestratorStatus), nullable=False, default=OrchestratorStatus.CONFIGURED, index=True
    )

    # PyRIT-specific fields
    pyrit_identifier: Mapped[Optional[Dict[str, str]]] = mapped_column(JSON, nullable=True)
    instance_active: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Relationships
    executions: Mapped[list["OrchestratorExecution"]] = relationship(
        "OrchestratorExecution", back_populates="orchestrator", cascade="all, delete-orphan"
    )

    # Model-specific constraints
    _model_constraints = (
        Index("idx_orchestrator_type_status", "orchestrator_type", "status"),
        Index("idx_orchestrator_name", "name"),
        Index("idx_orchestrator_active", "instance_active", "status"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<OrchestratorConfiguration(id='{self.id}', name='{self.name}', type='{self.orchestrator_type}')>"


class OrchestratorExecution(BaseModelMixin, Base):
    """Model for orchestrator executions."""

    # Relationship to orchestrator
    orchestrator_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("orchestrator_configuration.id", ondelete="CASCADE"), nullable=False, index=True
    )
    orchestrator: Mapped[OrchestratorConfiguration] = relationship(
        "OrchestratorConfiguration", back_populates="executions"
    )

    # Execution information
    execution_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    execution_type: Mapped[ExecutionType] = mapped_column(SQLEnum(ExecutionType), nullable=False, index=True)
    status: Mapped[ExecutionStatus] = mapped_column(
        SQLEnum(ExecutionStatus), nullable=False, default=ExecutionStatus.PENDING, index=True
    )

    # Input and configuration
    input_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    execution_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Execution tracking
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(nullable=True)

    # Progress tracking
    progress: Mapped[int] = mapped_column(nullable=False, default=0)  # 0-100
    current_operation: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    expected_operations: Mapped[int] = mapped_column(nullable=False, default=1)
    completed_operations: Mapped[int] = mapped_column(nullable=False, default=0)

    # Results and outputs
    results: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    execution_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # PyRIT-specific fields
    pyrit_memory_session: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    conversation_ids: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Task integration
    task_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("task.id", ondelete="SET NULL"), nullable=True, index=True
    )
    task: Mapped[Optional[Task]] = relationship("Task", foreign_keys=[task_id])

    # Model-specific constraints
    _model_constraints = (
        Index("idx_execution_orchestrator_status", "orchestrator_id", "status"),
        Index("idx_execution_type_status", "execution_type", "status"),
        Index("idx_execution_started", "started_at", "status"),
        Index("idx_execution_task", "task_id"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"<OrchestratorExecution(id='{self.id}', orchestrator_id='{self.orchestrator_id}', status='{self.status}')>"
        )


class OrchestratorTemplate(BaseModelMixin, Base):
    """Model for orchestrator configuration templates."""

    # Basic template info
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Template configuration
    orchestrator_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    template_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    default_parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    required_parameters: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Categorization
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    use_cases: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Version and compatibility
    template_version_str: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    min_pyrit_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    compatibility: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    is_featured: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Usage tracking
    usage_count: Mapped[int] = mapped_column(nullable=False, default=0)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_template_type_category", "orchestrator_type", "category"),
        Index("idx_template_active", "is_active", "category"),
        Index("idx_orchestrator_template_featured", "is_featured", "is_active"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<OrchestratorTemplate(id='{self.id}', name='{self.name}', type='{self.orchestrator_type}')>"


class OrchestratorScore(BaseModelMixin, Base):
    """Model for orchestrator execution scores."""

    # Relationship to execution
    execution_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("orchestrator_execution.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution: Mapped[OrchestratorExecution] = relationship("OrchestratorExecution")

    # Score information
    scorer_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    score_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    score_value: Mapped[float] = mapped_column(nullable=False, index=True)
    score_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)

    # Context and metadata
    prompt_request_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    conversation_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    score_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Scoring details
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    threshold: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Timestamp
    scored_at: Mapped[datetime] = mapped_column(nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_score_execution_scorer", "execution_id", "scorer_name"),
        Index("idx_score_type_value", "score_type", "score_value"),
        Index("idx_score_category_value", "score_category", "score_value"),
        Index("idx_score_conversation", "conversation_id", "scored_at"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"<OrchestratorScore(id='{self.id}', execution_id='{self.execution_id}', "
            f"scorer='{self.scorer_name}', value={self.score_value})>"
        )
