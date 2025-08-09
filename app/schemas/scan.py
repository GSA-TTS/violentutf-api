"""Pydantic schemas for scan management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.scan import ScanSeverity, ScanStatus, ScanType


class ScanBase(BaseModel):
    """Base schema for scan."""

    name: str = Field(..., description="Scan name", max_length=255)
    scan_type: ScanType = Field(..., description="Type of scan")
    description: Optional[str] = Field(None, description="Scan description")
    target_config: Dict[str, Any] = Field(default_factory=dict, description="Target configuration")
    scan_config: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Scan parameters")
    tags: List[str] = Field(default_factory=list, description="Scan tags")


class ScanCreate(ScanBase):
    """Schema for creating a scan."""

    webhook_url: Optional[str] = Field(None, description="Webhook URL for notifications", max_length=2048)
    webhook_secret: Optional[str] = Field(None, description="Webhook secret", max_length=255)


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None)
    target_config: Optional[Dict[str, Any]] = Field(None)
    scan_config: Optional[Dict[str, Any]] = Field(None)
    parameters: Optional[Dict[str, Any]] = Field(None)
    tags: Optional[List[str]] = Field(None)


class ScanResponse(ScanBase):
    """Schema for scan response."""

    id: str = Field(..., description="Scan ID")
    status: ScanStatus = Field(..., description="Scan status")
    started_at: Optional[datetime] = Field(None, description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    duration_seconds: Optional[int] = Field(None, description="Scan duration in seconds")
    progress: int = Field(..., description="Scan progress (0-100)", ge=0, le=100)
    current_phase: Optional[str] = Field(None, description="Current scan phase")
    total_tests: int = Field(..., description="Total number of tests")
    completed_tests: int = Field(..., description="Completed tests")
    failed_tests: int = Field(..., description="Failed tests")
    findings_count: int = Field(..., description="Total findings count")
    critical_findings: int = Field(..., description="Critical findings count")
    high_findings: int = Field(..., description="High findings count")
    medium_findings: int = Field(..., description="Medium findings count")
    low_findings: int = Field(..., description="Low findings count")
    overall_score: Optional[float] = Field(None, description="Overall score")
    risk_score: Optional[float] = Field(None, description="Risk score")
    confidence_score: Optional[float] = Field(None, description="Confidence score")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    orchestrator_id: Optional[str] = Field(None, description="Associated orchestrator ID")
    task_id: Optional[str] = Field(None, description="Associated task ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="Scan creator")

    class Config:  # noqa: D106
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for scan list response."""

    scans: List[ScanResponse] = Field(..., description="List of scans")
    total: int = Field(..., description="Total number of scans")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")


class ScanFindingBase(BaseModel):
    """Base schema for scan finding."""

    title: str = Field(..., description="Finding title", max_length=500)
    description: str = Field(..., description="Finding description")
    severity: ScanSeverity = Field(..., description="Finding severity")
    category: str = Field(..., description="Finding category", max_length=100)
    subcategory: Optional[str] = Field(None, description="Finding subcategory", max_length=100)
    vulnerability_type: str = Field(..., description="Vulnerability type", max_length=100)
    affected_component: Optional[str] = Field(None, description="Affected component", max_length=255)
    attack_vector: Optional[str] = Field(None, description="Attack vector", max_length=100)
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence data")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept")
    cvss_score: Optional[float] = Field(None, description="CVSS score", ge=0.0, le=10.0)
    confidence_score: float = Field(..., description="Confidence score", ge=0.0, le=1.0)
    impact_score: Optional[float] = Field(None, description="Impact score", ge=0.0, le=1.0)
    exploitability_score: Optional[float] = Field(None, description="Exploitability score", ge=0.0, le=1.0)
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    references: List[str] = Field(default_factory=list, description="Reference links")
    finding_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScanFindingCreate(ScanFindingBase):
    """Schema for creating a scan finding."""

    pass


class ScanFindingResponse(ScanFindingBase):
    """Schema for scan finding response."""

    id: str = Field(..., description="Finding ID")
    scan_id: str = Field(..., description="Associated scan ID")
    status: str = Field(..., description="Finding status")
    false_positive: bool = Field(..., description="Whether marked as false positive")
    verified: bool = Field(..., description="Whether verified")
    source_test: Optional[str] = Field(None, description="Source test name")
    source_rule: Optional[str] = Field(None, description="Source rule name")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:  # noqa: D106
        from_attributes = True


class ScanFindingListResponse(BaseModel):
    """Schema for scan finding list response."""

    findings: List[ScanFindingResponse] = Field(..., description="List of findings")
    total: int = Field(..., description="Total number of findings")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")


class ScanFindingUpdate(BaseModel):
    """Schema for updating a scan finding."""

    status: Optional[str] = Field(None, description="Finding status")
    false_positive: Optional[bool] = Field(None, description="Mark as false positive")
    verified: Optional[bool] = Field(None, description="Mark as verified")
    remediation: Optional[str] = Field(None, description="Remediation guidance")


class ScanReportBase(BaseModel):
    """Base schema for scan report."""

    name: str = Field(..., description="Report name", max_length=255)
    report_type: str = Field(..., description="Report type", max_length=100)
    format: str = Field(..., description="Report format", max_length=50)
    template_name: Optional[str] = Field(None, description="Template name", max_length=255)
    is_public: bool = Field(False, description="Whether report is public")
    expires_at: Optional[datetime] = Field(None, description="Report expiration time")


class ScanReportCreate(ScanReportBase):
    """Schema for creating a scan report."""

    pass


class ScanReportResponse(ScanReportBase):
    """Schema for scan report response."""

    id: str = Field(..., description="Report ID")
    scan_id: str = Field(..., description="Associated scan ID")
    content: Optional[Dict[str, Any]] = Field(None, description="Report content")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Report summary")
    file_path: Optional[str] = Field(None, description="File path if stored")
    file_size: Optional[int] = Field(None, description="File size in bytes")
    file_hash: Optional[str] = Field(None, description="File hash")
    generated_at: datetime = Field(..., description="Generation timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:  # noqa: D106
        from_attributes = True


class ScanExecutionRequest(BaseModel):
    """Schema for scan execution request."""

    scan_id: str = Field(..., description="Scan ID to execute")
    config_override: Optional[Dict[str, Any]] = Field(None, description="Configuration overrides")
    async_execution: bool = Field(True, description="Whether to execute asynchronously")


class ScanExecutionResponse(BaseModel):
    """Schema for scan execution response."""

    scan_id: str = Field(..., description="Scan ID")
    execution_id: str = Field(..., description="Execution ID")
    task_id: Optional[str] = Field(None, description="Associated task ID")
    status: ScanStatus = Field(..., description="Execution status")
    started_at: datetime = Field(..., description="Execution start time")
    status_url: str = Field(..., description="URL to check scan status")
    webhook_configured: bool = Field(..., description="Whether webhook is configured")


class ScanStatsResponse(BaseModel):
    """Schema for scan statistics response."""

    total_scans: int = Field(..., description="Total number of scans")
    pending_scans: int = Field(..., description="Number of pending scans")
    running_scans: int = Field(..., description="Number of running scans")
    completed_scans: int = Field(..., description="Number of completed scans")
    failed_scans: int = Field(..., description="Number of failed scans")
    total_findings: int = Field(..., description="Total findings across all scans")
    critical_findings: int = Field(..., description="Total critical findings")
    high_findings: int = Field(..., description="Total high findings")
    medium_findings: int = Field(..., description="Total medium findings")
    low_findings: int = Field(..., description="Total low findings")
    avg_scan_time: Optional[float] = Field(None, description="Average scan time in seconds")
    success_rate: Optional[float] = Field(None, description="Success rate (0-1)")


class ScanFilterRequest(BaseModel):
    """Schema for scan filtering request."""

    scan_types: Optional[List[ScanType]] = Field(None, description="Filter by scan types")
    statuses: Optional[List[ScanStatus]] = Field(None, description="Filter by statuses")
    severity_threshold: Optional[ScanSeverity] = Field(None, description="Minimum severity level")
    date_from: Optional[datetime] = Field(None, description="Filter from date")
    date_to: Optional[datetime] = Field(None, description="Filter to date")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    has_critical: Optional[bool] = Field(None, description="Filter scans with critical findings")
    min_findings: Optional[int] = Field(None, description="Minimum number of findings")
    created_by: Optional[str] = Field(None, description="Filter by creator")
