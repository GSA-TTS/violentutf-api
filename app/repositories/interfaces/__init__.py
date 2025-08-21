"""Repository interfaces for data access layer abstraction."""

from .api_key import IApiKeyRepository
from .audit_log import IAuditLogRepository
from .base import IBaseRepository
from .mfa_policy import IMfaPolicyRepository
from .oauth import IOAuthRepository
from .role import IRoleRepository
from .security_scan import ISecurityScanRepository
from .session import ISessionRepository
from .task import ITaskRepository
from .user import IUserRepository
from .vulnerability import IVulnerabilityRepository

__all__ = [
    "IBaseRepository",
    "IUserRepository",
    "ISessionRepository",
    "IApiKeyRepository",
    "IAuditLogRepository",
    "IMfaPolicyRepository",
    "ISecurityScanRepository",
    "ITaskRepository",
    "IVulnerabilityRepository",
    "IRoleRepository",
    "IOAuthRepository",
]
