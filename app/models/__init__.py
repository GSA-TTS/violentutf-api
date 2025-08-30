"""Models package."""

# Import base classes first
from .api_key import APIKey
from .audit_log import AuditLog

# Import MFA models
from .mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent
from .mixins import AuditMixin, BaseModelMixin, SecurityValidationMixin, SoftDeleteMixin

# Import OAuth models
from .oauth import (
    OAuthAccessToken,
    OAuthApplication,
    OAuthAuthorizationCode,
    OAuthRefreshToken,
)

# Import orchestrator models (they reference Task)
from .orchestrator import (
    OrchestratorConfiguration,
    OrchestratorExecution,
    OrchestratorScore,
    OrchestratorTemplate,
)

# Import models in dependency order
from .permission import Permission

# Import plugin models (they reference Task)
from .plugin import Plugin, PluginConfiguration, PluginExecution, PluginRegistry

# Import report models (they reference Task and Scan)
from .report import Report, ReportSchedule, ReportTemplate
from .role import Role

# Import scan models (they reference Task)
from .scan import Scan, ScanFinding, ScanReport
from .security_scan import SecurityScan
from .session import Session

# Import task models first (they are referenced by others)
from .task import Task, TaskResult
from .user import User
from .user_role import UserRole
from .vulnerability_finding import VulnerabilityFinding

# Import vulnerability management models
from .vulnerability_taxonomy import VulnerabilityTaxonomy

__all__ = [
    "BaseModelMixin",
    "AuditMixin",
    "SoftDeleteMixin",
    "SecurityValidationMixin",
    "Permission",
    "Role",
    "User",
    "UserRole",
    "APIKey",
    "Session",
    "AuditLog",
    "OAuthApplication",
    "OAuthAccessToken",
    "OAuthRefreshToken",
    "OAuthAuthorizationCode",
    "MFADevice",
    "MFABackupCode",
    "MFAChallenge",
    "MFAEvent",
    "VulnerabilityTaxonomy",
    "VulnerabilityFinding",
    "SecurityScan",
    # New async task models
    "Task",
    "TaskResult",
    # Scan models
    "Scan",
    "ScanFinding",
    "ScanReport",
    # Orchestrator models
    "OrchestratorConfiguration",
    "OrchestratorExecution",
    "OrchestratorScore",
    "OrchestratorTemplate",
    # Report models
    "Report",
    "ReportTemplate",
    "ReportSchedule",
    # Plugin models
    "Plugin",
    "PluginConfiguration",
    "PluginExecution",
    "PluginRegistry",
]
