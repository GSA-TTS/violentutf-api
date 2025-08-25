"""Repository pattern implementation for data access abstraction."""

from .api_key import APIKeyRepository
from .audit_log import AuditLogRepository
from .base import BaseRepository, Page
from .mfa_backup_code import MFABackupCodeRepository
from .mfa_challenge import MFAChallengeRepository
from .mfa_device import MFADeviceRepository
from .mfa_event import MFAEventRepository
from .mfa_policy import MFAPolicyRepository
from .oauth_access_token import OAuthAccessTokenRepository
from .oauth_application import OAuthApplicationRepository
from .oauth_authorization_code import OAuthAuthorizationCodeRepository
from .oauth_refresh_token import OAuthRefreshTokenRepository
from .oauth_scope import OAuthScopeRepository
from .role import RoleRepository
from .security_scan import SecurityScanRepository
from .session import SessionRepository
from .user import UserRepository
from .vulnerability_finding import VulnerabilityFindingRepository
from .vulnerability_taxonomy import VulnerabilityTaxonomyRepository

__all__ = [
    "BaseRepository",
    "Page",
    "UserRepository",
    "APIKeyRepository",
    "SessionRepository",
    "AuditLogRepository",
    "VulnerabilityTaxonomyRepository",
    "VulnerabilityFindingRepository",
    "SecurityScanRepository",
    "MFAPolicyRepository",
    "MFADeviceRepository",
    "MFAChallengeRepository",
    "MFABackupCodeRepository",
    "MFAEventRepository",
    "RoleRepository",
    "OAuthApplicationRepository",
    "OAuthAccessTokenRepository",
    "OAuthRefreshTokenRepository",
    "OAuthAuthorizationCodeRepository",
    "OAuthScopeRepository",
]
