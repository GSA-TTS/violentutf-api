"""Scan models for AI red-teaming security scans."""

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


class ScanType(str, Enum):
    """Types of security scans."""

    PYRIT_ORCHESTRATOR = "pyrit_orchestrator"
    GARAK_PROBE = "garak_probe"
    CUSTOM_SCAN = "custom_scan"
    BENCHMARK_TEST = "benchmark_test"
    ADVERSARIAL_TEST = "adversarial_test"


class ScanStatus(str, Enum):
    """Scan execution status."""

    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ScanSeverity(str, Enum):
    """Scan result severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scan(BaseModelMixin, Base):
    """Model for AI security scans."""

    # Basic scan information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scan_type: Mapped[ScanType] = mapped_column(SQLEnum(ScanType), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING, index=True
    )

    # Configuration
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    scan_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Execution tracking
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(nullable=True)

    # Progress tracking
    progress: Mapped[int] = mapped_column(nullable=False, default=0)  # 0-100
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    total_tests: Mapped[int] = mapped_column(nullable=False, default=0)
    completed_tests: Mapped[int] = mapped_column(nullable=False, default=0)
    failed_tests: Mapped[int] = mapped_column(nullable=False, default=0)

    # Results summary
    findings_count: Mapped[int] = mapped_column(nullable=False, default=0)
    critical_findings: Mapped[int] = mapped_column(nullable=False, default=0)
    high_findings: Mapped[int] = mapped_column(nullable=False, default=0)
    medium_findings: Mapped[int] = mapped_column(nullable=False, default=0)
    low_findings: Mapped[int] = mapped_column(nullable=False, default=0)

    # Quality metrics
    overall_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_score: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Integration details
    orchestrator_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        ForeignKey("task.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Tags for organization
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Relationships
    task: Mapped[Optional["Task"]] = relationship("Task", foreign_keys=[task_id])
    findings: Mapped[list["ScanFinding"]] = relationship(
        "ScanFinding", back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["ScanReport"]] = relationship(
        "ScanReport", back_populates="scan", cascade="all, delete-orphan"
    )

    # Model-specific constraints
    _model_constraints = (
        Index("idx_scan_type_status", "scan_type", "status"),
        Index("idx_scan_started", "started_at", "scan_type"),
        Index("idx_scan_findings", "findings_count", "status"),
        Index("idx_scan_severity", "critical_findings", "high_findings"),
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize Scan with proper defaults for unit testing."""
        # Set defaults for fields that should have them
        if "status" not in kwargs:
            kwargs["status"] = ScanStatus.PENDING
        if "target_config" not in kwargs:
            kwargs["target_config"] = {}
        if "scan_config" not in kwargs:
            kwargs["scan_config"] = {}
        if "parameters" not in kwargs:
            kwargs["parameters"] = {}
        if "tags" not in kwargs:
            kwargs["tags"] = []
        if "progress" not in kwargs:
            kwargs["progress"] = 0
        if "total_tests" not in kwargs:
            kwargs["total_tests"] = 0
        if "completed_tests" not in kwargs:
            kwargs["completed_tests"] = 0
        if "failed_tests" not in kwargs:
            kwargs["failed_tests"] = 0
        if "findings_count" not in kwargs:
            kwargs["findings_count"] = 0
        if "critical_findings" not in kwargs:
            kwargs["critical_findings"] = 0
        if "high_findings" not in kwargs:
            kwargs["high_findings"] = 0
        if "medium_findings" not in kwargs:
            kwargs["medium_findings"] = 0
        if "low_findings" not in kwargs:
            kwargs["low_findings"] = 0

        super().__init__(**kwargs)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"<Scan(id='{self.id}', name='{self.name}', type='{self.scan_type.value}', status='{self.status.value}')>"
        )


class ScanFinding(BaseModelMixin, Base):
    """Model for individual scan findings/vulnerabilities."""

    # Relationship to scan
    scan_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("scan.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    # Finding information
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[ScanSeverity] = mapped_column(SQLEnum(ScanSeverity), nullable=False, index=True)

    # Classification
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    subcategory: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vulnerability_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Technical details
    affected_component: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    attack_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scoring
    cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    impact_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    exploitability_score: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Status tracking
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")
    false_positive: Mapped[bool] = mapped_column(nullable=False, default=False)
    verified: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Metadata
    source_test: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_rule: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    finding_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_finding_severity_category", "severity", "category"),
        Index("idx_finding_scan_severity", "scan_id", "severity"),
        Index("idx_finding_type_confidence", "vulnerability_type", "confidence_score"),
    )

    def __init__(self, **kwargs: Any) -> None:
        """Initialize ScanFinding with proper defaults for unit testing."""
        # Set defaults for fields that should have them
        if "evidence" not in kwargs:
            kwargs["evidence"] = {}
        if "references" not in kwargs:
            kwargs["references"] = []
        if "confidence_score" not in kwargs:
            kwargs["confidence_score"] = 0.0
        if "status" not in kwargs:
            kwargs["status"] = "open"
        if "false_positive" not in kwargs:
            kwargs["false_positive"] = False
        if "verified" not in kwargs:
            kwargs["verified"] = False
        if "finding_metadata" not in kwargs:
            kwargs["finding_metadata"] = {}

        super().__init__(**kwargs)

    def __repr__(self) -> str:  # noqa: D105
        return f"<ScanFinding(id='{self.id}', scan_id='{self.scan_id}', severity='{self.severity.value}')>"


class ScanReport(BaseModelMixin, Base):
    """Model for scan reports and exports."""

    # Relationship to scan
    scan_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("scan.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan: Mapped[Scan] = relationship("Scan", back_populates="reports")

    # Report information
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(50), nullable=False)  # json, csv, pdf, html

    # Content
    content: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    summary: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # File storage
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA256

    # Generation info
    template_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(nullable=False, default=lambda: datetime.now(timezone.utc))

    # Access control
    is_public: Mapped[bool] = mapped_column(nullable=False, default=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_report_scan_type", "scan_id", "report_type"),
        Index("idx_scan_report_format", "format", "generated_at"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<ScanReport(id='{self.id}', scan_id='{self.scan_id}', type='{self.report_type}')>"
