"""Unified data models for audit automation scripts."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    from pydantic import BaseModel, Field, field_validator, model_validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    # Fallback when Pydantic is not available
    BaseModel = object  # type: ignore[misc,assignment]

    def _field_fallback(**kwargs: Any) -> None:
        """Fallback for Pydantic Field when not available."""
        return None

    def _field_validator_fallback(*args: Any, **kwargs: Any) -> Any:
        """Fallback for Pydantic field_validator when not available."""

        def decorator(func: Any) -> Any:
            return func

        return decorator

    def _model_validator_fallback(**kwargs: Any) -> Any:
        """Fallback for Pydantic model_validator when not available."""

        def decorator(func: Any) -> Any:
            return func

        return decorator

    Field = _field_fallback  # type: ignore[assignment]
    field_validator = _field_validator_fallback
    model_validator = _model_validator_fallback
    PYDANTIC_AVAILABLE = False


class AuditStatus(Enum):
    """Standard audit status enumeration."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class CriticalityLevel(Enum):
    """Standard criticality enumeration."""

    CRITICAL = "critical"
    IMPORTANT = "important"
    STANDARD = "standard"


if PYDANTIC_AVAILABLE:

    class AuditMetadata(BaseModel):
        """Standard audit metadata structure."""

        generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
        version: str = Field(default="1.0")
        audit_type: str
        scope: str
        status: AuditStatus = AuditStatus.PENDING

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("audit_type")
        @classmethod
        def validate_audit_type(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("audit_type must be a non-empty string")
            return v.strip()

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("scope must be a non-empty string")
            return v.strip()

    class AuditResult(BaseModel):
        """Standard audit result structure."""

        metadata: AuditMetadata
        findings: List[Dict[str, Any]]
        recommendations: List[str]
        summary: Dict[str, Any]

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("findings")
        @classmethod
        def validate_findings(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            if not isinstance(v, list):
                raise ValueError("findings must be a list")
            return v

        @field_validator("recommendations")
        @classmethod
        def validate_recommendations(cls, v: List[str]) -> List[str]:
            if not isinstance(v, list):
                raise ValueError("recommendations must be a list")
            # Ensure all recommendations are strings
            return [str(rec) for rec in v]

        @model_validator(mode="after")
        def validate_consistency(self) -> "AuditResult":
            if self.metadata and self.metadata.status == AuditStatus.COMPLETED and not self.findings:
                # It's ok to have completed audits with no findings
                pass
            return self

    class RepositoryInfo(BaseModel):
        """Standard repository information structure."""

        name: str
        criticality: CriticalityLevel
        data_size_mb: float = 0.0
        last_backup: Optional[datetime] = None
        table_name: Optional[str] = None
        backup_frequency: str = "daily"
        retention_required_days: int = 30

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat() if v else None}}

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("name must be a non-empty string")
            return v.strip()

        @field_validator("data_size_mb")
        @classmethod
        def validate_data_size(cls, v: float) -> float:
            if v < 0:
                raise ValueError("data_size_mb must be non-negative")
            return v

        @field_validator("retention_required_days")
        @classmethod
        def validate_retention(cls, v: int) -> int:
            if v < 1:
                raise ValueError("retention_required_days must be at least 1")
            return v

        def is_backup_overdue(self) -> bool:
            """Check if backup is overdue based on criticality."""
            if not self.last_backup:
                return True

            now = datetime.now()
            hours_since_backup = (now - self.last_backup).total_seconds() / 3600

            # Define maximum allowed hours based on criticality (using string values)
            max_hours = {
                "critical": 2,  # 2 hours
                "important": 8,  # 8 hours
                "standard": 26,  # 26 hours (daily + buffer)
            }

            # Handle both enum and string criticality values
            criticality_str = (
                str(self.criticality.value) if hasattr(self.criticality, "value") else str(self.criticality)
            )
            return hours_since_backup > max_hours.get(criticality_str, 26)

    class DependencyInfo(BaseModel):
        """Standard dependency information structure."""

        name: str
        version: Optional[str] = None
        criticality: CriticalityLevel
        dependents: List[str] = Field(default_factory=list)
        service_type: str
        health_status: str = "unknown"
        last_check: Optional[datetime] = None

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat() if v else None}}

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("name must be a non-empty string")
            return v.strip()

        @field_validator("service_type")
        @classmethod
        def validate_service_type(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("service_type must be a non-empty string")
            return v.strip()

        @field_validator("health_status")
        @classmethod
        def validate_health_status(cls, v: str) -> str:
            valid_statuses = ["healthy", "unhealthy", "degraded", "unknown"]
            if v not in valid_statuses:
                raise ValueError(f"health_status must be one of {valid_statuses}")
            return v

    class BackupGap(BaseModel):
        """Standard backup gap information."""

        repository: str
        criticality: CriticalityLevel
        gap_hours: float
        last_backup: Optional[datetime] = None
        severity: str = "medium"

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat() if v else None}}

        @field_validator("repository")
        @classmethod
        def validate_repository(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("repository must be a non-empty string")
            return v.strip()

        @field_validator("gap_hours")
        @classmethod
        def validate_gap_hours(cls, v: float) -> float:
            if v < 0:
                raise ValueError("gap_hours must be non-negative")
            return v

        @field_validator("severity")
        @classmethod
        def validate_severity(cls, v: str) -> str:
            valid_severities = ["low", "medium", "high", "critical"]
            if v not in valid_severities:
                raise ValueError(f"severity must be one of {valid_severities}")
            return v

    class ConfigurationBaseline(BaseModel):
        """Standard configuration baseline structure."""

        environment: str
        timestamp: datetime
        version: str
        configurations: Dict[str, Any]
        metadata: Dict[str, Any] = Field(default_factory=dict)
        checksum: str = ""

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("environment")
        @classmethod
        def validate_environment(cls, v: str) -> str:
            valid_environments = {"development", "staging", "production"}
            if v not in valid_environments:
                raise ValueError(f"environment must be one of {valid_environments}")
            return v

        @field_validator("version")
        @classmethod
        def validate_version(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("version must be a non-empty string")
            return v.strip()

        @field_validator("configurations")
        @classmethod
        def validate_configurations(cls, v: Dict[str, Any]) -> Dict[str, Any]:
            if not isinstance(v, dict):
                raise ValueError("configurations must be a dictionary")
            return v

    class ComprehensiveAnalysisResult(BaseModel):
        """Standard comprehensive analysis result structure."""

        metadata: AuditMetadata
        static_analysis: Dict[str, Any]
        repository_analysis: Dict[str, Any]
        runtime_analysis: Optional[Dict[str, Any]] = None
        dependency_graphs: Dict[str, str] = Field(default_factory=dict)
        summary_report: Dict[str, Any] = Field(default_factory=dict)
        recommendations: List[str] = Field(default_factory=list)

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

    class SecurityClassification(BaseModel):
        """Standard security classification structure."""

        asset_id: str
        classification_level: str
        data_types: List[str] = Field(default_factory=list)
        access_restrictions: List[str] = Field(default_factory=list)
        compliance_requirements: List[str] = Field(default_factory=list)
        classification_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("asset_id")
        @classmethod
        def validate_asset_id(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("asset_id must be a non-empty string")
            return v.strip()

        @field_validator("classification_level")
        @classmethod
        def validate_classification_level(cls, v: str) -> str:
            valid_levels = ["public", "internal", "confidential", "restricted", "top_secret"]
            if v not in valid_levels:
                raise ValueError(f"classification_level must be one of {valid_levels}")
            return v

    class ComplianceStatus(Enum):
        """Standard compliance status enumeration."""

        COMPLIANT = "compliant"
        WARNING = "warning"
        NON_COMPLIANT = "non_compliant"

    class BackupCoverageReport(BaseModel):
        """Standard backup coverage report structure."""

        total_repositories: int
        compliant_repositories: int = 0
        compliance_score: float = 0.0
        backup_gaps: List[BackupGap] = Field(default_factory=list)
        timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
        status: ComplianceStatus = ComplianceStatus.COMPLIANT
        storage_usage_gb: float = 0.0
        recommendations: List[Dict[str, str]] = Field(default_factory=list)

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("total_repositories")
        @classmethod
        def validate_total_repositories(cls, v: int) -> int:
            if v < 0:
                raise ValueError("total_repositories must be non-negative")
            return v

        @field_validator("compliant_repositories")
        @classmethod
        def validate_compliant_repositories(cls, v: int) -> int:
            if v < 0:
                raise ValueError("compliant_repositories must be non-negative")
            return v

        @field_validator("compliance_score")
        @classmethod
        def validate_compliance_score(cls, v: float) -> float:
            if not 0 <= v <= 100:
                raise ValueError("compliance_score must be between 0 and 100")
            return v

        @field_validator("storage_usage_gb")
        @classmethod
        def validate_storage_usage(cls, v: float) -> float:
            if v < 0:
                raise ValueError("storage_usage_gb must be non-negative")
            return v

        def determine_status(self) -> ComplianceStatus:
            """Determine compliance status based on compliance score."""
            if self.compliance_score >= 95:
                return ComplianceStatus.COMPLIANT
            elif self.compliance_score >= 80:
                return ComplianceStatus.WARNING
            else:
                return ComplianceStatus.NON_COMPLIANT

        @model_validator(mode="after")
        def validate_consistency(self) -> "BackupCoverageReport":
            # Validate compliant_repositories doesn't exceed total
            if self.compliant_repositories > self.total_repositories:
                raise ValueError("compliant_repositories cannot exceed total_repositories")

            # Auto-calculate compliance score if not set
            if self.total_repositories > 0:
                calculated_score = (self.compliant_repositories / self.total_repositories) * 100
                if abs(self.compliance_score - calculated_score) > 1.0:  # Allow small rounding differences
                    self.compliance_score = calculated_score

            return self

    class PerformanceMetrics(BaseModel):
        """Standard performance metrics structure."""

        operation_name: str
        execution_time_seconds: float
        memory_usage_mb: float = 0.0
        cpu_usage_percent: float = 0.0
        database_queries: int = 0
        cache_hits: int = 0
        cache_misses: int = 0
        errors_count: int = 0
        timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

        model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

        @field_validator("operation_name")
        @classmethod
        def validate_operation_name(cls, v: str) -> str:
            if not v or not isinstance(v, str):
                raise ValueError("operation_name must be a non-empty string")
            return v.strip()

        @field_validator("execution_time_seconds")
        @classmethod
        def validate_execution_time(cls, v: float) -> float:
            if v < 0:
                raise ValueError("execution_time_seconds must be non-negative")
            return v

else:
    # Fallback implementations when Pydantic is not available

    class AuditMetadata:  # type: ignore[no-redef]
        """Fallback audit metadata structure when Pydantic is not available."""

        def __init__(self, audit_type: str, scope: str, **kwargs: Any) -> None:
            self.generated_at = datetime.now(timezone.utc)
            self.version = kwargs.get("version", "1.0")
            self.audit_type = audit_type
            self.scope = scope
            self.status = kwargs.get("status", AuditStatus.PENDING)

    class AuditResult:  # type: ignore[no-redef]
        """Fallback audit result structure when Pydantic is not available."""

        def __init__(
            self,
            metadata: AuditMetadata,
            findings: List[Dict[str, Any]],
            recommendations: List[str],
            summary: Dict[str, Any],
        ) -> None:
            self.metadata = metadata
            self.findings = findings
            self.recommendations = recommendations
            self.summary = summary

    class RepositoryInfo:  # type: ignore[no-redef]
        """Fallback repository information structure when Pydantic is not available."""

        def __init__(self, name: str, criticality: CriticalityLevel, **kwargs: Any) -> None:
            self.name = name
            self.criticality = criticality
            self.data_size_mb = kwargs.get("data_size_mb", 0.0)
            self.last_backup = kwargs.get("last_backup")
            self.table_name = kwargs.get("table_name")
            self.backup_frequency = kwargs.get("backup_frequency", "daily")
            self.retention_required_days = kwargs.get("retention_required_days", 30)

        def is_backup_overdue(self) -> bool:
            """Check if backup is overdue based on criticality."""
            if not self.last_backup:
                return True

            now = datetime.now()
            hours_since_backup: float = (now - self.last_backup).total_seconds() / 3600

            # Define maximum allowed hours based on criticality (using string values)
            max_hours: Dict[str, int] = {
                "critical": 2,  # 2 hours
                "important": 8,  # 8 hours
                "standard": 26,  # 26 hours (daily + buffer)
            }

            # Handle both enum and string criticality values
            criticality_str = (
                str(self.criticality.value) if hasattr(self.criticality, "value") else str(self.criticality)
            )
            max_allowed_hours: int = max_hours.get(criticality_str, 26)
            return hours_since_backup > max_allowed_hours

    class DependencyInfo:  # type: ignore[no-redef]
        """Fallback dependency information structure when Pydantic is not available."""

        def __init__(self, name: str, criticality: CriticalityLevel, service_type: str, **kwargs: Any) -> None:
            self.name = name
            self.criticality = criticality
            self.service_type = service_type
            self.version = kwargs.get("version")
            self.dependents = kwargs.get("dependents", [])
            self.health_status = kwargs.get("health_status", "unknown")


# Utility functions for model interoperability


def convert_to_dict(model_instance: Any) -> Dict[str, Any]:
    """
    Convert model instance to dictionary.

    Works with both Pydantic models and fallback implementations.

    Args:
        model_instance: Model instance to convert

    Returns:
        Dictionary representation of the model
    """
    if PYDANTIC_AVAILABLE and hasattr(model_instance, "model_dump"):
        return model_instance.model_dump()  # type: ignore[no-any-return]
    elif PYDANTIC_AVAILABLE and hasattr(model_instance, "dict"):  # Pydantic V1 fallback
        return model_instance.dict()  # type: ignore[no-any-return]
    elif hasattr(model_instance, "__dict__"):
        result = {}
        for key, value in model_instance.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result
    else:
        raise ValueError(f"Cannot convert {type(model_instance)} to dictionary")


def create_audit_result(
    audit_type: str,
    scope: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    recommendations: Optional[List[str]] = None,
    summary: Optional[Dict[str, Any]] = None,
    status: AuditStatus = AuditStatus.COMPLETED,
) -> AuditResult:
    """
    Factory function to create standardized audit results.

    Args:
        audit_type: Type of audit performed
        scope: Scope of the audit
        findings: List of audit findings
        recommendations: List of recommendations
        summary: Audit summary information
        status: Audit completion status

    Returns:
        Standardized AuditResult instance
    """
    metadata = AuditMetadata(audit_type=audit_type, scope=scope, status=status)

    return AuditResult(
        metadata=metadata, findings=findings or [], recommendations=recommendations or [], summary=summary or {}
    )
