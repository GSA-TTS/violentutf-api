"""Database base configuration - imports all models for Alembic."""

# Import base class
from app.db.base_class import Base  # noqa
from app.models.api_key import APIKey  # noqa
from app.models.audit_log import AuditLog  # noqa
from app.models.session import Session  # noqa

# Import all models here so Alembic can discover them
# This ensures all models are registered with SQLAlchemy
from app.models.user import User  # noqa
