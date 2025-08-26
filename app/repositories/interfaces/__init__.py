"""Repository interface contracts."""

from .api_key import IApiKeyRepository
from .audit import IAuditRepository
from .health import IHealthRepository
from .role import IRoleRepository
from .security_scan import ISecurityScanRepository
from .session import ISessionRepository
from .user import IUserRepository
from .vulnerability import IVulnerabilityRepository

__all__ = [
    "IApiKeyRepository",
    "IAuditRepository",
    "IHealthRepository",
    "IRoleRepository",
    "ISecurityScanRepository",
    "ISessionRepository",
    "IUserRepository",
    "IVulnerabilityRepository",
]
