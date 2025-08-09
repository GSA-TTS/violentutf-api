"""Security scan model for tracking vulnerability assessment activities."""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, Session, declared_attr, mapped_column, relationship

from app.core.enums import ScanStatus, ScanType
from app.db.base_class import Base
from app.models.mixins import AuditMixin, SoftDeleteMixin

if TYPE_CHECKING:
    from app.models.vulnerability_finding import VulnerabilityFinding


class SecurityScan(Base, AuditMixin, SoftDeleteMixin):
    """
    Security scan orchestration and tracking model.

    This model tracks security assessment activities including automated scans
    (PyRIT, Garak, static analysis) and manual assessments (penetration tests,
    code reviews) with comprehensive metadata and results tracking.
    """

    __tablename__ = "security_scans"

    # Basic Scan Information
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    scan_type: Mapped[ScanType] = mapped_column(nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scan Configuration
    target: Mapped[str] = mapped_column(String(500), nullable=False)  # URL, IP, component, etc.
    configuration: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    scan_parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # CLI args, config files

    # Execution Context
    initiated_by: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tool_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scanner_host: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Timeline and Status
    status: Mapped[ScanStatus] = mapped_column(nullable=False, default=ScanStatus.PENDING, index=True)
    scheduled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Performance Metrics
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timeout_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=3600)  # 1 hour default

    # Results Summary
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    critical_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Quality Metrics
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0-1.0
    coverage_percentage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0-100.0
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0-1.0

    # Error Handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    warning_messages: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Output and Artifacts
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    artifacts: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)  # Log files, screenshots

    # AI/ML Specific Fields
    ai_models_tested: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    prompt_categories: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # OWASP LLM categories tested
    attack_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # MITRE ATLAS techniques

    # Integration and Automation
    pipeline_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)  # CI/CD pipeline
    trigger_event: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # manual, scheduled, webhook
    parent_scan_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)  # For scan chains

    # Compliance and Reporting
    compliance_frameworks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    report_recipients: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of emails

    # Metadata
    tags: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_baseline: Mapped[bool] = mapped_column(Boolean, default=False, index=True)  # Baseline scan for comparison

    # Relationships
    vulnerability_findings: Mapped[List["VulnerabilityFinding"]] = relationship(
        "VulnerabilityFinding", back_populates="scan", lazy="dynamic"
    )

    # Database Indexes for Performance
    @declared_attr
    @classmethod
    def __table_args__(cls) -> Any:
        """Define table-specific indexes in addition to mixin indexes."""
        return (
            Index("idx_security_scan_type_status", "scan_type", "status"),
            Index("idx_scan_timeline", "started_at", "completed_at"),
            Index("idx_scan_findings_summary", "total_findings", "critical_findings"),
            Index("idx_scan_initiator_type", "initiated_by", "scan_type"),
            Index("idx_scan_target_type", "target", "scan_type"),
            Index("idx_scan_pipeline", "pipeline_id", "trigger_event"),
            Index("idx_scan_baseline_comparison", "is_baseline", "scan_type", "target"),
        )

    def __repr__(self) -> str:
        return f"<SecurityScan(name='{self.name}', type='{self.scan_type}', status='{self.status}')>"

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == ScanStatus.RUNNING

    @property
    def is_completed(self) -> bool:
        """Check if scan completed successfully."""
        return self.status == ScanStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if scan failed or timed out."""
        return self.status in [ScanStatus.FAILED, ScanStatus.TIMEOUT]

    @property
    def duration_minutes(self) -> Optional[float]:
        """Get scan duration in minutes."""
        if self.duration_seconds is None:
            return None
        return self.duration_seconds / 60.0

    @property
    def progress_percentage(self) -> Optional[float]:
        """Calculate progress percentage for running scans."""
        if not self.is_running or not self.started_at:
            return None

        elapsed = (datetime.now(timezone.utc) - self.started_at).total_seconds()
        if self.timeout_seconds and self.timeout_seconds > 0:
            return min(100.0, (elapsed / self.timeout_seconds) * 100.0)

        return None

    @property
    def risk_score(self) -> float:
        """Calculate composite risk score based on findings."""
        if self.total_findings == 0:
            return 0.0

        weighted_score = (
            self.critical_findings * 10.0
            + self.high_findings * 7.5
            + self.medium_findings * 5.0
            + self.low_findings * 2.5
            + self.info_findings * 0.5
        )

        # Normalize to 0-10 scale
        max_possible = self.total_findings * 10.0
        return (weighted_score / max_possible) * 10.0 if max_possible > 0 else 0.0

    def start_scan(self) -> None:
        """Mark scan as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def complete_scan(self, findings_summary: Optional[Dict[str, int]] = None) -> None:
        """Mark scan as completed and update findings summary."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)

        if self.started_at:
            self.duration_seconds = int((self.completed_at - self.started_at).total_seconds())

        if findings_summary:
            self.update_findings_summary(findings_summary)

    def fail_scan(self, error_message: str) -> None:
        """Mark scan as failed with error message."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = error_message

        if self.started_at:
            self.duration_seconds = int((self.completed_at - self.started_at).total_seconds())

    def timeout_scan(self) -> None:
        """Mark scan as timed out."""
        self.status = ScanStatus.TIMEOUT
        self.completed_at = datetime.now(timezone.utc)

        if self.started_at:
            self.duration_seconds = int((self.completed_at - self.started_at).total_seconds())

    def cancel_scan(self) -> None:
        """Cancel a running scan."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)

        if self.started_at:
            self.duration_seconds = int((self.completed_at - self.started_at).total_seconds())

    def update_findings_summary(self, findings_by_severity: Dict[str, int]) -> None:
        """Update findings count by severity."""
        self.critical_findings = findings_by_severity.get("critical", 0)
        self.high_findings = findings_by_severity.get("high", 0)
        self.medium_findings = findings_by_severity.get("medium", 0)
        self.low_findings = findings_by_severity.get("low", 0)
        self.info_findings = findings_by_severity.get("info", 0)
        self.total_findings = sum(findings_by_severity.values())

    def get_configuration_dict(self) -> Dict[str, Any]:
        """Get scan configuration as dictionary."""
        return self.configuration or {}

    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set scan configuration."""
        self.configuration = config

    def get_ai_models_tested_list(self) -> List[str]:
        """Get list of AI models tested."""
        if not self.ai_models_tested:
            return []

        try:
            import json

            result = json.loads(self.ai_models_tested)
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return [model.strip() for model in self.ai_models_tested.split(",") if model.strip()]

    def set_ai_models_tested(self, models: List[str]) -> None:
        """Set AI models tested."""
        import json

        self.ai_models_tested = json.dumps(models)

    def get_prompt_categories_list(self) -> List[str]:
        """Get list of prompt categories tested."""
        if not self.prompt_categories:
            return []

        try:
            import json

            result = json.loads(self.prompt_categories)
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return [cat.strip() for cat in self.prompt_categories.split(",") if cat.strip()]

    def set_prompt_categories(self, categories: List[str]) -> None:
        """Set prompt categories tested."""
        import json

        self.prompt_categories = json.dumps(categories)

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        new_warning = f"{timestamp}: {warning}"

        if self.warning_messages:
            self.warning_messages = f"{self.warning_messages}\n{new_warning}"
        else:
            self.warning_messages = new_warning

    def estimate_remaining_time(self) -> Optional[timedelta]:
        """Estimate remaining time for running scan."""
        if not self.is_running or not self.started_at or not self.timeout_seconds:
            return None

        elapsed = datetime.now(timezone.utc) - self.started_at
        timeout = timedelta(seconds=self.timeout_seconds)

        return max(timedelta(0), timeout - elapsed)

    @classmethod
    def get_recent_scans(cls, session: Session, limit: int = 10) -> List["SecurityScan"]:
        """Get most recent scans."""
        return session.query(cls).order_by(cls.created_at.desc()).limit(limit).all()

    @classmethod
    def get_running_scans(cls, session: Session) -> List["SecurityScan"]:
        """Get currently running scans."""
        return session.query(cls).filter(cls.status == ScanStatus.RUNNING).order_by(cls.started_at.asc()).all()

    @classmethod
    def get_failed_scans(cls, session: Session, hours: int = 24) -> List["SecurityScan"]:
        """Get scans that failed in the last N hours."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        return (
            session.query(cls)
            .filter(cls.status.in_([ScanStatus.FAILED, ScanStatus.TIMEOUT]), cls.completed_at >= since)
            .order_by(cls.completed_at.desc())
            .all()
        )

    @classmethod
    def get_baseline_scans(cls, session: Session, scan_type: Optional[ScanType] = None) -> List["SecurityScan"]:
        """Get baseline scans for comparison."""
        query = session.query(cls).filter(cls.is_baseline == True)  # noqa: E712

        if scan_type:
            query = query.filter(cls.scan_type == scan_type)

        return query.order_by(cls.completed_at.desc()).all()
