"""Comprehensive tests for model methods to achieve 100% coverage."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import String, create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import mapped_column, sessionmaker

from app.db.base import Base
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.mixins import (
    AuditMixin,
    BaseModelMixin,
    OptimisticLockMixin,
    RowLevelSecurityMixin,
    SecurityValidationMixin,
    SoftDeleteMixin,
)
from app.models.user import User


class TestAPIKeyModel:
    """Test APIKey model methods for complete coverage."""

    def test_api_key_str_representation(self):
        """Test APIKey string representation."""
        api_key = APIKey(id=str(uuid.uuid4()), name="Test Key", user_id=str(uuid.uuid4()), key_prefix="test123")

        result = str(api_key)

        assert "APIKey" in result
        assert api_key.id in result
        assert "Test Key" in result
        assert "test123..." in result

    def test_api_key_repr(self):
        """Test APIKey repr."""
        api_key = APIKey(id=str(uuid.uuid4()), name="Test Key", user_id=str(uuid.uuid4()))

        result = repr(api_key)

        assert "APIKey" in result
        assert f"id={api_key.id}" in result

    def test_api_key_is_expired_not_set(self):
        """Test is_expired when expires_at is not set."""
        api_key = APIKey(expires_at=None)

        assert api_key.is_expired() is False

    def test_api_key_is_expired_future(self):
        """Test is_expired when expires_at is in future."""
        api_key = APIKey(expires_at=datetime.now(timezone.utc) + timedelta(days=1))

        assert api_key.is_expired() is False

    def test_api_key_is_expired_past(self):
        """Test is_expired when expires_at is in past."""
        api_key = APIKey(expires_at=datetime.now(timezone.utc) - timedelta(days=1))

        assert api_key.is_expired() is True

    def test_api_key_has_permission_exists(self):
        """Test has_permission when permission exists and is True."""
        api_key = APIKey(permissions={"read": True, "write": False, "admin": True})

        assert api_key.has_permission("read") is True
        assert api_key.has_permission("admin") is True

    def test_api_key_has_permission_false(self):
        """Test has_permission when permission is False."""
        api_key = APIKey(permissions={"read": True, "write": False})

        assert api_key.has_permission("write") is False

    def test_api_key_has_permission_not_exists(self):
        """Test has_permission when permission doesn't exist."""
        api_key = APIKey(permissions={"read": True})

        assert api_key.has_permission("admin") is False

    def test_api_key_has_permission_empty_permissions(self):
        """Test has_permission with empty permissions."""
        api_key = APIKey(permissions={})

        assert api_key.has_permission("read") is False

    def test_api_key_mask_key_various_lengths(self):
        """Test mask_key with various key lengths."""
        # Short key
        assert APIKey.mask_key("abc") == "abc"

        # Exact 8 characters
        assert APIKey.mask_key("12345678") == "12345678"

        # Longer key
        assert APIKey.mask_key("1234567890abcdef") == "12345678********"

        # Very long key
        assert APIKey.mask_key("a" * 50) == "aaaaaaaa" + "*" * 42

    def test_api_key_mask_key_none(self):
        """Test mask_key with None."""
        assert APIKey.mask_key(None) == ""

    def test_api_key_mask_key_empty(self):
        """Test mask_key with empty string."""
        assert APIKey.mask_key("") == ""

    def test_api_key_relationships(self):
        """Test APIKey relationships are properly defined."""
        api_key = APIKey()

        # Check relationship exists
        assert hasattr(api_key, "user")

        # Check back_populates
        rel = APIKey.user.property
        assert rel.back_populates == "api_keys"


class TestAuditLogModel:
    """Test AuditLog model methods for complete coverage."""

    def test_audit_log_str_representation(self):
        """Test AuditLog string representation."""
        audit_log = AuditLog(
            id=str(uuid.uuid4()), action="user.create", resource_type="user", resource_id="12345", status="success"
        )

        result = str(audit_log)

        assert "AuditLog" in result
        assert audit_log.id in result
        assert "user.create" in result
        assert "user" in result
        assert "12345" in result

    def test_audit_log_repr(self):
        """Test AuditLog repr."""
        audit_log = AuditLog(id=str(uuid.uuid4()), action="test.action")

        result = repr(audit_log)

        assert "AuditLog" in result
        assert f"id={audit_log.id}" in result

    def test_audit_log_get_changes_dict(self):
        """Test get_changes returns dict when changes is JSON string."""
        changes_dict = {"before": "old", "after": "new"}
        audit_log = AuditLog(changes=json.dumps(changes_dict))

        result = audit_log.get_changes()

        assert result == changes_dict

    def test_audit_log_get_changes_none(self):
        """Test get_changes returns empty dict when changes is None."""
        audit_log = AuditLog(changes=None)

        result = audit_log.get_changes()

        assert result == {}

    def test_audit_log_get_changes_empty_string(self):
        """Test get_changes returns empty dict when changes is empty string."""
        audit_log = AuditLog(changes="")

        result = audit_log.get_changes()

        assert result == {}

    def test_audit_log_get_changes_invalid_json(self):
        """Test get_changes returns empty dict when changes is invalid JSON."""
        audit_log = AuditLog(changes="invalid json")

        result = audit_log.get_changes()

        assert result == {}

    def test_audit_log_get_metadata_dict(self):
        """Test get_metadata returns dict when action_metadata is JSON string."""
        metadata_dict = {"request_id": "123", "source": "api"}
        audit_log = AuditLog(action_metadata=json.dumps(metadata_dict))

        result = audit_log.get_metadata()

        assert result == metadata_dict

    def test_audit_log_get_metadata_none(self):
        """Test get_metadata returns empty dict when action_metadata is None."""
        audit_log = AuditLog(action_metadata=None)

        result = audit_log.get_metadata()

        assert result == {}

    def test_audit_log_get_metadata_empty_string(self):
        """Test get_metadata returns empty dict when action_metadata is empty string."""
        audit_log = AuditLog(action_metadata="")

        result = audit_log.get_metadata()

        assert result == {}

    def test_audit_log_get_metadata_invalid_json(self):
        """Test get_metadata returns empty dict when action_metadata is invalid JSON."""
        audit_log = AuditLog(action_metadata="not json")

        result = audit_log.get_metadata()

        assert result == {}

    def test_audit_log_relationships(self):
        """Test AuditLog relationships are properly defined."""
        audit_log = AuditLog()

        # Check user relationship exists
        assert hasattr(audit_log, "user")

        # Check relationship configuration
        rel = AuditLog.user.property
        assert rel.back_populates == "audit_logs"


class TestUserModel:
    """Test User model methods for complete coverage."""

    def test_user_str_representation(self):
        """Test User string representation."""
        user = User(id=str(uuid.uuid4()), username="testuser", email="test@example.com")

        result = str(user)

        assert "User" in result
        assert user.id in result
        assert "testuser" in result

    def test_user_repr(self):
        """Test User repr."""
        user = User(id=str(uuid.uuid4()), username="testuser")

        result = repr(user)

        assert "User" in result
        assert f"id={user.id}" in result

    def test_user_relationships(self):
        """Test User relationships are properly defined."""
        user = User()

        # Check relationships exist
        assert hasattr(user, "api_keys")
        assert hasattr(user, "audit_logs")

        # Check back_populates
        api_key_rel = User.api_keys.property
        assert api_key_rel.back_populates == "user"

        audit_log_rel = User.audit_logs.property
        assert audit_log_rel.back_populates == "user"

    def test_user_cascade_delete(self):
        """Test User cascade delete configuration."""
        # Check API keys cascade
        api_key_rel = User.api_keys.property
        assert "delete" in api_key_rel.cascade
        assert api_key_rel.passive_deletes is True


class TestMixins:
    """Test mixin functionality for complete coverage."""

    def test_base_model_mixin_dict_conversion(self):
        """Test BaseModelMixin dict conversion."""

        class TestEntity(Base, BaseModelMixin):
            __tablename__ = "test_entity"

        entity = TestEntity(id="123", created_at=datetime.now(timezone.utc), created_by="test")

        # Test dict()
        result_dict = entity.dict()
        assert "id" in result_dict
        assert "created_at" in result_dict
        assert "created_by" in result_dict

        # Test to_dict() alias
        result_to_dict = entity.to_dict()
        assert result_to_dict == result_dict

    def test_soft_delete_mixin_properties(self):
        """Test SoftDeleteMixin properties."""

        class TestSoftDelete(Base, SoftDeleteMixin):
            __tablename__ = "test_soft_delete"

        entity = TestSoftDelete()

        # Check default values
        assert entity.is_deleted is False
        assert entity.deleted_at is None
        assert entity.deleted_by is None

        # Test soft delete
        entity.is_deleted = True
        entity.deleted_at = datetime.now(timezone.utc)
        entity.deleted_by = "admin"

        assert entity.is_deleted is True
        assert entity.deleted_at is not None
        assert entity.deleted_by == "admin"

    def test_audit_mixin_update_tracking(self):
        """Test AuditMixin tracks updates."""

        class TestAudit(Base, AuditMixin):
            __tablename__ = "test_audit"

        entity = TestAudit(created_by="creator", updated_by="creator")

        # Initial state
        assert entity.created_by == "creator"
        assert entity.updated_by == "creator"
        assert entity.version == 1

        # Update
        entity.updated_by = "updater"
        entity.version = 2

        assert entity.updated_by == "updater"
        assert entity.version == 2

    def test_security_validation_mixin(self):
        """Test SecurityValidationMixin functionality."""

        class TestSecurityValidation(Base, SecurityValidationMixin):
            __tablename__ = "test_security_validation"
            sensitive_field = mapped_column(String(100))

        entity = TestSecurityValidation()

        # Test normal input
        entity.sensitive_field = "normal input"
        assert entity.sensitive_field == "normal input"

        # SQL injection patterns should be caught by validator
        # Note: The validator would need to be called explicitly or via session events

    def test_optimistic_lock_mixin(self):
        """Test OptimisticLockMixin functionality."""

        class TestOptimisticLock(Base, OptimisticLockMixin):
            __tablename__ = "test_optimistic_lock"

        entity = TestOptimisticLock()

        # Check version field exists and defaults to 1
        assert hasattr(entity, "version")
        assert entity.version == 1

    def test_row_level_security_mixin(self):
        """Test RowLevelSecurityMixin functionality."""

        class TestRowLevelSecurity(Base, RowLevelSecurityMixin):
            __tablename__ = "test_row_level_security"

        entity = TestRowLevelSecurity()

        # Check RLS fields exist with defaults
        assert hasattr(entity, "owner_id")
        assert hasattr(entity, "tenant_id")
        assert hasattr(entity, "is_public")
        assert hasattr(entity, "access_level")

        assert entity.is_public is False
        assert entity.access_level == "private"
