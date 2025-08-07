"""Database base configuration - imports all models for Alembic."""

# Import base class
from app.db.base_class import Base  # noqa

# Import all models here so Alembic can discover them
# This ensures all models are registered with SQLAlchemy
from app.models.api_key import APIKey  # noqa
from app.models.audit_log import AuditLog  # noqa
from app.models.mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent  # noqa
from app.models.oauth import (  # noqa
    OAuthAccessToken,
    OAuthApplication,
    OAuthAuthorizationCode,
    OAuthRefreshToken,
)
from app.models.permission import Permission  # noqa
from app.models.role import Role  # noqa
from app.models.session import Session  # noqa
from app.models.user import User  # noqa
from app.models.user_role import UserRole  # noqa
