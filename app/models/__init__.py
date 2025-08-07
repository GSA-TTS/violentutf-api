"""Models package."""

# Import base classes first
from .api_key import APIKey
from .audit_log import AuditLog

# Import MFA models
from .mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent
from .mixins import AuditMixin, BaseModelMixin, SecurityValidationMixin, SoftDeleteMixin

# Import OAuth models
from .oauth import OAuthAccessToken, OAuthApplication, OAuthAuthorizationCode, OAuthRefreshToken

# Import models in dependency order
from .permission import Permission
from .role import Role
from .session import Session
from .user import User
from .user_role import UserRole

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
]
