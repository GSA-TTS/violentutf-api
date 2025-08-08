"""Report generation and template schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.report import ReportFormat, ReportStatus, TemplateType


class ReportBase(BaseModel):
    """Base report schema."""

    name: str = Field(..., min_length=1, max_length=255, description="Report name")
    title: str = Field(..., min_length=1, max_length=500, description="Report title")
    description: Optional[str] = Field(None, description="Report description")
    report_type: str = Field(..., min_length=1, max_length=100, description="Report type")
    format: ReportFormat = Field(..., description="Report format")


class ReportCreate(ReportBase):
    """Schema for creating a report."""

    template_id: Optional[str] = Field(None, description="Template ID to use")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    execution_id: Optional[str] = Field(None, description="Associated execution ID")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Report configuration")
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Data filters")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Report parameters")
    is_public: Optional[bool] = Field(False, description="Whether report is publicly accessible")
    expires_at: Optional[datetime] = Field(None, description="Report expiration time")


class ReportUpdate(BaseModel):
    """Schema for updating a report."""

    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Report name")
    title: Optional[str] = Field(None, min_length=1, max_length=500, description="Report title")
    description: Optional[str] = Field(None, description="Report description")
    config: Optional[Dict[str, Any]] = Field(None, description="Report configuration")
    filters: Optional[Dict[str, Any]] = Field(None, description="Data filters")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Report parameters")
    is_public: Optional[bool] = Field(None, description="Whether report is publicly accessible")
    expires_at: Optional[datetime] = Field(None, description="Report expiration time")


class ReportResponse(ReportBase):
    """Schema for report response."""

    id: str = Field(..., description="Report ID")
    status: ReportStatus = Field(..., description="Report status")
    template_id: Optional[str] = Field(None, description="Template ID used")
    template_version: Optional[str] = Field(None, description="Template version")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    execution_id: Optional[str] = Field(None, description="Associated execution ID")
    task_id: Optional[str] = Field(None, description="Associated task ID")
    config: Dict[str, Any] = Field(default_factory=dict, description="Report configuration")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Data filters")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Report parameters")
    generated_at: Optional[datetime] = Field(None, description="Generation completion time")
    generation_time_seconds: Optional[int] = Field(None, description="Generation time in seconds")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Report summary")
    file_size: Optional[int] = Field(None, description="File size in bytes")
    file_hash: Optional[str] = Field(None, description="File SHA256 hash")
    mime_type: Optional[str] = Field(None, description="File MIME type")
    is_public: bool = Field(False, description="Whether report is publicly accessible")
    expires_at: Optional[datetime] = Field(None, description="Report expiration time")
    download_count: int = Field(0, description="Number of downloads")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    created_at: datetime = Field(..., description="Creation time")
    updated_at: datetime = Field(..., description="Last update time")
    created_by: Optional[str] = Field(None, description="Creator username")

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class ReportListResponse(BaseModel):
    """Schema for report list response."""

    reports: List[ReportResponse] = Field(..., description="List of reports")
    total: int = Field(..., ge=0, description="Total number of reports")
    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, description="Reports per page")
    has_next: bool = Field(..., description="Whether there are more pages")


class ReportGenerationRequest(BaseModel):
    """Schema for report generation request."""

    config_override: Optional[Dict[str, Any]] = Field(None, description="Configuration overrides")
    priority: Optional[str] = Field("normal", description="Generation priority")


class ReportGenerationResponse(BaseModel):
    """Schema for report generation response."""

    report_id: str = Field(..., description="Report ID")
    task_id: Optional[str] = Field(None, description="Associated task ID")
    status: ReportStatus = Field(..., description="Report status")
    started_at: datetime = Field(..., description="Generation start time")
    status_url: str = Field(..., description="URL to check status")
    download_url: Optional[str] = Field(None, description="URL to download report when ready")


class ReportStatsResponse(BaseModel):
    """Schema for report statistics response."""

    total_reports: int = Field(..., ge=0, description="Total number of reports")
    pending_reports: int = Field(..., ge=0, description="Number of pending reports")
    generating_reports: int = Field(..., ge=0, description="Number of generating reports")
    completed_reports: int = Field(..., ge=0, description="Number of completed reports")
    failed_reports: int = Field(..., ge=0, description="Number of failed reports")
    success_rate: Optional[float] = Field(None, ge=0, le=1, description="Success rate (0-1)")
    total_downloads: int = Field(..., ge=0, description="Total number of downloads")
    format_distribution: Dict[str, int] = Field(..., description="Distribution by format")


# Template schemas
class ReportTemplateBase(BaseModel):
    """Base template schema."""

    name: str = Field(..., min_length=1, max_length=255, description="Template name")
    display_name: str = Field(..., min_length=1, max_length=255, description="Display name")
    description: str = Field(..., min_length=1, description="Template description")
    template_type: TemplateType = Field(..., description="Template type")
    supported_formats: List[str] = Field(default_factory=list, description="Supported output formats")


class ReportTemplateCreate(ReportTemplateBase):
    """Schema for creating a report template."""

    template_content: Dict[str, Any] = Field(default_factory=dict, description="Template content")
    default_config: Dict[str, Any] = Field(default_factory=dict, description="Default configuration")
    sections: List[Dict[str, Any]] = Field(default_factory=list, description="Template sections")
    fields: List[Dict[str, Any]] = Field(default_factory=list, description="Template fields")
    styles: Dict[str, Any] = Field(default_factory=dict, description="Styling configuration")
    layout: Dict[str, Any] = Field(default_factory=dict, description="Layout configuration")
    template_version_str: str = Field("1.0.0", description="Template version")
    schema_version: str = Field("1.0.0", description="Schema version")
    category: str = Field(..., min_length=1, max_length=100, description="Template category")
    tags: List[str] = Field(default_factory=list, description="Template tags")
    is_active: bool = Field(True, description="Whether template is active")
    is_featured: bool = Field(False, description="Whether template is featured")


class ReportTemplateUpdate(BaseModel):
    """Schema for updating a report template."""

    display_name: Optional[str] = Field(None, min_length=1, max_length=255, description="Display name")
    description: Optional[str] = Field(None, min_length=1, description="Template description")
    supported_formats: Optional[List[str]] = Field(None, description="Supported output formats")
    template_content: Optional[Dict[str, Any]] = Field(None, description="Template content")
    default_config: Optional[Dict[str, Any]] = Field(None, description="Default configuration")
    sections: Optional[List[Dict[str, Any]]] = Field(None, description="Template sections")
    fields: Optional[List[Dict[str, Any]]] = Field(None, description="Template fields")
    styles: Optional[Dict[str, Any]] = Field(None, description="Styling configuration")
    layout: Optional[Dict[str, Any]] = Field(None, description="Layout configuration")
    category: Optional[str] = Field(None, min_length=1, max_length=100, description="Template category")
    tags: Optional[List[str]] = Field(None, description="Template tags")
    is_active: Optional[bool] = Field(None, description="Whether template is active")
    is_featured: Optional[bool] = Field(None, description="Whether template is featured")

    @field_validator("supported_formats")
    @classmethod
    def validate_supported_formats(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate supported formats."""
        if v is not None:
            valid_formats = [fmt.value for fmt in ReportFormat]
            for fmt in v:
                if fmt not in valid_formats:
                    raise ValueError(f"Invalid format: {fmt}. Valid formats: {valid_formats}")
        return v


class ReportTemplateResponse(ReportTemplateBase):
    """Schema for template response."""

    id: str = Field(..., description="Template ID")
    template_content: Dict[str, Any] = Field(default_factory=dict, description="Template content")
    default_config: Dict[str, Any] = Field(default_factory=dict, description="Default configuration")
    sections: List[Dict[str, Any]] = Field(default_factory=list, description="Template sections")
    fields: List[Dict[str, Any]] = Field(default_factory=list, description="Template fields")
    styles: Dict[str, Any] = Field(default_factory=dict, description="Styling configuration")
    layout: Dict[str, Any] = Field(default_factory=dict, description="Layout configuration")
    template_version_str: str = Field("1.0.0", description="Template version")
    schema_version: str = Field("1.0.0", description="Schema version")
    category: str = Field(..., description="Template category")
    tags: List[str] = Field(default_factory=list, description="Template tags")
    is_active: bool = Field(True, description="Whether template is active")
    is_featured: bool = Field(False, description="Whether template is featured")
    usage_count: int = Field(0, description="Number of times used")
    last_used_at: Optional[datetime] = Field(None, description="Last usage time")
    created_at: datetime = Field(..., description="Creation time")
    updated_at: datetime = Field(..., description="Last update time")
    created_by: Optional[str] = Field(None, description="Creator username")

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class ReportTemplateListResponse(BaseModel):
    """Schema for template list response."""

    templates: List[ReportTemplateResponse] = Field(..., description="List of templates")
    total: int = Field(..., ge=0, description="Total number of templates")
    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, description="Templates per page")
    has_next: bool = Field(..., description="Whether there are more pages")
