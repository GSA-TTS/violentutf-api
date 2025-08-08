"""Pydantic schemas for security scan management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ScanStatus, ScanType
from app.schemas.base import BaseEntityResponse, TimestampMixin


class SecurityScanBase(BaseModel):
    """Base security scan schema."""

    name: str = Field(..., min_length=1, max_length=200, description="Scan name")
    scan_type: ScanType = Field(..., description="Type of security scan")
    description: Optional[str] = Field(None, description="Scan description")

    # Scan configuration
    target: str = Field(..., max_length=500, description="Scan target (URL, IP, service, etc.)")
    configuration: Optional[Dict[str, Any]] = Field(None, description="Scan configuration JSON")
    scan_parameters: Optional[str] = Field(None, description="Additional scan parameters")

    # Execution context
    initiated_by: str = Field(..., max_length=100, description="User who initiated the scan")
    tool_version: Optional[str] = Field(None, max_length=50, description="Scanning tool version")
    scanner_host: Optional[str] = Field(None, max_length=100, description="Scanner host/server")

    # Timeline and status
    scheduled_at: Optional[datetime] = Field(None, description="When scan is scheduled")
    timeout_seconds: int = Field(default=3600, ge=60, le=86400, description="Scan timeout in seconds")

    # AI/ML specific fields
    ai_models_tested: Optional[str] = Field(None, description="AI models tested")
    prompt_categories: Optional[str] = Field(None, description="Prompt categories tested")
    attack_techniques: Optional[str] = Field(None, description="Attack techniques used")

    # Integration and automation
    pipeline_id: Optional[str] = Field(None, max_length=100, description="CI/CD pipeline ID")
    trigger_event: Optional[str] = Field(None, max_length=100, description="Event that triggered scan")
    parent_scan_id: Optional[str] = Field(None, description="Parent scan ID if part of suite")

    # Compliance and reporting
    compliance_frameworks: Optional[str] = Field(None, description="Compliance frameworks addressed")
    report_recipients: Optional[str] = Field(None, description="Report recipients")

    # Metadata
    tags: Optional[str] = Field(None, max_length=500, description="Scan tags")
    notes: Optional[str] = Field(None, description="Additional notes")
    is_baseline: bool = Field(default=False, description="Whether this is a baseline scan")


class SecurityScanCreate(SecurityScanBase):
    """Create security scan schema."""

    # Set default status
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Initial scan status")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Weekly Security Scan",
                "scan_type": "pyrit",
                "description": "Regular security scan for API endpoints",
                "target": "https://api.example.com",
                "initiated_by": "security_team",
                "configuration": {"depth": "full", "include_authenticated": True},
                "timeout_seconds": 7200,
                "tags": "weekly,api,production",
            }
        }
    )


class SecurityScanUpdate(BaseModel):
    """Update security scan schema."""

    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None
    scan_parameters: Optional[str] = None
    tool_version: Optional[str] = Field(None, max_length=50)
    scanner_host: Optional[str] = Field(None, max_length=100)
    status: Optional[ScanStatus] = None
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: Optional[int] = Field(None, ge=60, le=86400)

    # Results summary
    total_findings: Optional[int] = Field(None, ge=0)
    critical_findings: Optional[int] = Field(None, ge=0)
    high_findings: Optional[int] = Field(None, ge=0)
    medium_findings: Optional[int] = Field(None, ge=0)
    low_findings: Optional[int] = Field(None, ge=0)
    info_findings: Optional[int] = Field(None, ge=0)

    # Quality metrics
    false_positive_rate: Optional[float] = Field(None, ge=0.0, le=1.0)
    coverage_percentage: Optional[float] = Field(None, ge=0.0, le=100.0)
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)

    # Error handling
    error_message: Optional[str] = None
    warning_messages: Optional[str] = None

    # Output and artifacts
    raw_output: Optional[str] = None
    report_path: Optional[str] = Field(None, max_length=1000)
    artifacts: Optional[Dict[str, Any]] = None

    # AI/ML specific fields
    ai_models_tested: Optional[str] = None
    prompt_categories: Optional[str] = None
    attack_techniques: Optional[str] = None

    # Integration and automation
    pipeline_id: Optional[str] = Field(None, max_length=100)
    trigger_event: Optional[str] = Field(None, max_length=100)

    # Compliance and reporting
    compliance_frameworks: Optional[str] = None
    report_recipients: Optional[str] = None

    # Metadata
    tags: Optional[str] = Field(None, max_length=500)
    notes: Optional[str] = None
    is_baseline: Optional[bool] = None


class SecurityScanResponse(SecurityScanBase, BaseEntityResponse, TimestampMixin):
    """Security scan response schema."""

    status: ScanStatus = Field(..., description="Current scan status")
    started_at: Optional[datetime] = Field(None, description="When scan started")
    completed_at: Optional[datetime] = Field(None, description="When scan completed")

    # Performance metrics
    duration_seconds: Optional[int] = Field(None, description="Scan duration in seconds")

    # Results summary
    total_findings: int = Field(default=0, description="Total number of findings")
    critical_findings: int = Field(default=0, description="Critical findings count")
    high_findings: int = Field(default=0, description="High severity findings count")
    medium_findings: int = Field(default=0, description="Medium severity findings count")
    low_findings: int = Field(default=0, description="Low severity findings count")
    info_findings: int = Field(default=0, description="Info level findings count")

    # Quality metrics
    false_positive_rate: Optional[float] = Field(None, description="False positive rate")
    coverage_percentage: Optional[float] = Field(None, description="Coverage percentage")
    confidence_score: Optional[float] = Field(None, description="Confidence score")

    # Error handling
    error_message: Optional[str] = Field(None, description="Error message if failed")
    warning_messages: Optional[str] = Field(None, description="Warning messages")

    # Output and artifacts
    report_path: Optional[str] = Field(None, description="Path to generated report")
    artifacts: Optional[Dict[str, Any]] = Field(None, description="Scan artifacts")

    # Computed fields
    success_rate: Optional[float] = Field(None, description="Scan success rate")
    findings_per_minute: Optional[float] = Field(None, description="Findings per minute")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Weekly Security Scan",
                "scan_type": "pyrit",
                "status": "completed",
                "target": "https://api.example.com",
                "initiated_by": "security_team",
                "started_at": "2024-01-01T00:00:00Z",
                "completed_at": "2024-01-01T02:00:00Z",
                "duration_seconds": 7200,
                "total_findings": 15,
                "critical_findings": 2,
                "high_findings": 5,
                "success_rate": 95.0,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        },
    )


class SecurityScanListResponse(BaseModel):
    """List response for security scans."""

    scans: List[SecurityScanResponse]
    total: int = Field(..., description="Total number of scans")
    page: int = Field(..., description="Current page number")
    size: int = Field(..., description="Page size")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class SecurityScanStatistics(BaseModel):
    """Statistics for security scans."""

    total_scans: int = Field(..., description="Total number of scans")
    by_status: Dict[str, int] = Field(..., description="Count by status")
    by_type: Dict[str, int] = Field(..., description="Count by scan type")
    success_rate_percent: float = Field(..., description="Success rate percentage")
    avg_duration_minutes: float = Field(..., description="Average duration in minutes")
    findings_summary: Dict[str, int] = Field(..., description="Summary of all findings")
    top_initiators: List[Dict[str, Any]] = Field(..., description="Top scan initiators")
    top_targets: List[Dict[str, Any]] = Field(..., description="Most scanned targets")
    pipeline_stats: List[Dict[str, Any]] = Field(..., description="Pipeline statistics")


class SecurityScanFilter(BaseModel):
    """Filter parameters for scan queries."""

    scan_type: Optional[ScanType] = None
    status: Optional[ScanStatus] = None
    initiated_by: Optional[str] = None
    target: Optional[str] = None
    pipeline_id: Optional[str] = None
    is_baseline: Optional[bool] = None
    has_findings: Optional[bool] = None
    search: Optional[str] = Field(None, min_length=1, max_length=100, description="Search term")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"scan_type": "pyrit", "status": "completed", "initiated_by": "security_team", "search": "api"}
        }
    )


class ScanProgressUpdate(BaseModel):
    """Update scan progress."""

    status: ScanStatus = Field(..., description="New scan status")
    findings_counts: Optional[Dict[str, int]] = Field(None, description="Findings count by severity")
    error_message: Optional[str] = Field(None, description="Error message if applicable")
    progress_percentage: Optional[float] = Field(None, ge=0.0, le=100.0, description="Progress percentage")
    current_phase: Optional[str] = Field(None, max_length=100, description="Current scan phase")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "running",
                "progress_percentage": 45.5,
                "current_phase": "vulnerability_detection",
                "findings_counts": {"critical": 2, "high": 5, "medium": 8},
            }
        }
    )


class ScanComparisonRequest(BaseModel):
    """Request for scan comparison."""

    baseline_scan_id: str = Field(..., description="Baseline scan ID to compare against")
    organization_id: Optional[str] = Field(None, description="Organization ID")

    model_config = ConfigDict(
        json_schema_extra={"example": {"baseline_scan_id": "baseline-scan-123", "organization_id": "org-123"}}
    )


class ScanComparisonResponse(BaseModel):
    """Response for scan comparison."""

    current_scan: Dict[str, Any] = Field(..., description="Current scan data")
    baseline_scan: Dict[str, Any] = Field(..., description="Baseline scan data")
    differences: Dict[str, Any] = Field(..., description="Differences between scans")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_scan": {
                    "id": "current-scan-456",
                    "total_findings": 20,
                    "findings_by_severity": {"critical": 3, "high": 7},
                },
                "baseline_scan": {
                    "id": "baseline-scan-123",
                    "total_findings": 15,
                    "findings_by_severity": {"critical": 1, "high": 5},
                },
                "differences": {"total_change": 5, "trend": "worsened", "by_severity": {"critical": 2, "high": 2}},
            }
        }
    )


class ScanCleanupRequest(BaseModel):
    """Request for scan cleanup."""

    days_to_keep: int = Field(default=90, ge=7, le=365, description="Days of scans to keep")
    organization_id: Optional[str] = Field(None, description="Organization ID")
    dry_run: bool = Field(default=True, description="Whether to perform dry run")

    model_config = ConfigDict(json_schema_extra={"example": {"days_to_keep": 90, "dry_run": True}})


class ScanCleanupResponse(BaseModel):
    """Response for scan cleanup."""

    scans_to_delete: int = Field(..., description="Number of scans that would be deleted")
    scans_deleted: int = Field(..., description="Number of scans actually deleted")
    dry_run: bool = Field(..., description="Whether this was a dry run")

    model_config = ConfigDict(
        json_schema_extra={"example": {"scans_to_delete": 25, "scans_deleted": 0, "dry_run": True}}
    )
