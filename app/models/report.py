"""Report generation and template models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from app.models.orchestrator import OrchestratorExecution
    from app.models.scan import Scan
    from app.models.task import Task

from sqlalchemy import JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class ReportStatus(str, Enum):
    """Report generation status."""

    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class ReportFormat(str, Enum):
    """Supported report formats."""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"
    XLSX = "xlsx"
    XML = "xml"


class TemplateType(str, Enum):
    """Template types."""

    SCAN_REPORT = "scan_report"
    EXECUTION_REPORT = "execution_report"
    SUMMARY_REPORT = "summary_report"
    COMPLIANCE_REPORT = "compliance_report"
    CUSTOM_REPORT = "custom_report"


class Report(BaseModelMixin, Base):
    """Model for generated reports."""

    # Basic report information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Report type and format
    report_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    format: Mapped[ReportFormat] = mapped_column(SQLEnum(ReportFormat), nullable=False, index=True)
    status: Mapped[ReportStatus] = mapped_column(
        SQLEnum(ReportStatus), nullable=False, default=ReportStatus.PENDING, index=True
    )

    # Template information
    template_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("report_template.id", ondelete="SET NULL"), nullable=True, index=True
    )
    template: Mapped[Optional["ReportTemplate"]] = relationship("ReportTemplate")
    template_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Source data references
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("scan.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan: Mapped[Optional[Scan]] = relationship("Scan")

    execution_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("orchestrator_execution.id", ondelete="CASCADE"), nullable=True, index=True
    )
    execution: Mapped[Optional[OrchestratorExecution]] = relationship("OrchestratorExecution")

    task_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("task.id", ondelete="SET NULL"), nullable=True, index=True
    )
    task: Mapped[Optional[Task]] = relationship("Task")

    # Report configuration
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    filters: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Generation tracking
    generated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    generation_time_seconds: Mapped[Optional[int]] = mapped_column(nullable=True)

    # Content and storage
    content: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    summary: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # File storage
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA256
    mime_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Access control
    is_public: Mapped[bool] = mapped_column(nullable=False, default=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    download_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_report_type_status", "report_type", "status"),
        Index("idx_report_table_format", "format", "generated_at"),
        Index("idx_report_scan", "scan_id", "report_type"),
        Index("idx_report_execution", "execution_id", "report_type"),
        Index("idx_report_expires", "expires_at", "status"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<Report(id='{self.id}', name='{self.name}', type='{self.report_type}', status='{self.status}')>"


class ReportTemplate(BaseModelMixin, Base):
    """Model for report templates."""

    # Basic template information
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Template configuration
    template_type: Mapped[TemplateType] = mapped_column(SQLEnum(TemplateType), nullable=False, index=True)
    supported_formats: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Template content
    template_content: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    default_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Template structure
    sections: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    fields: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    # Styling and layout
    styles: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    layout: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Version and compatibility
    template_version_str: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    schema_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")

    # Categorization
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Status and usage
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    is_featured: Mapped[bool] = mapped_column(nullable=False, default=False)
    usage_count: Mapped[int] = mapped_column(nullable=False, default=0)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Relationships
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="template")

    # Model-specific constraints
    _model_constraints = (
        Index("idx_template_type_active", "template_type", "is_active"),
        Index("idx_template_category", "category", "is_active"),
        Index("idx_template_featured", "is_featured", "is_active"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<ReportTemplate(id='{self.id}', name='{self.name}', type='{self.template_type}')>"


class ReportSchedule(BaseModelMixin, Base):
    """Model for scheduled report generation."""

    # Basic schedule information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Schedule configuration
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    tz: Mapped[str] = mapped_column(String(50), nullable=False, default="UTC")

    # Report configuration
    report_template_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("report_template.id", ondelete="CASCADE"), nullable=False, index=True
    )
    report_template: Mapped[ReportTemplate] = relationship("ReportTemplate")

    report_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    output_formats: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Schedule status
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)

    # Execution tracking
    total_runs: Mapped[int] = mapped_column(nullable=False, default=0)
    successful_runs: Mapped[int] = mapped_column(nullable=False, default=0)
    failed_runs: Mapped[int] = mapped_column(nullable=False, default=0)

    # Notification settings
    notify_on_success: Mapped[bool] = mapped_column(nullable=False, default=False)
    notify_on_failure: Mapped[bool] = mapped_column(nullable=False, default=True)
    notification_emails: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_schedule_active_next", "is_active", "next_run_at"),
        Index("idx_schedule_template", "report_template_id", "is_active"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<ReportSchedule(id='{self.id}', name='{self.name}', active={self.is_active})>"
