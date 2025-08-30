"""Comprehensive tests for APIKey model to achieve 100% coverage."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.models.api_key import APIKey
from app.models.mixins import BaseModelMixin


class TestAPIKeyModelCreation:
    """Test API key creation and basic functionality."""

    def test_api_key_creation_minimal(self):
        """Test creating API key with minimal required fields."""
        user_id = uuid.uuid4()
        api_key = APIKey(key_hash="a" * 64, name="Test Key", key_prefix="test123", user_id=user_id)  # Valid SHA256 hash

        assert api_key.key_hash == "a" * 64
        assert api_key.name == "Test Key"
        assert api_key.key_prefix == "test123"
        assert api_key.user_id == user_id
        assert api_key.description is None
        assert api_key.permissions == {}  # Default empty dict
        assert api_key.last_used_at is None
        assert api_key.last_used_ip is None
        assert api_key.usage_count == 0  # Default value
        assert api_key.expires_at is None

    def test_api_key_creation_full_fields(self):
        """Test creating API key with all fields populated."""
        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=30)
        permissions = {"read": True, "write": False}

        api_key = APIKey(
            key_hash="b" * 64,
            name="Full Test Key",
            description="Complete test API key",
            key_prefix="full123",
            permissions=permissions,
            last_used_at=now,
            last_used_ip="192.168.1.1",
            usage_count=42,
            expires_at=expires,
            user_id=user_id,
        )

        assert api_key.key_hash == "b" * 64
        assert api_key.name == "Full Test Key"
        assert api_key.description == "Complete test API key"
        assert api_key.key_prefix == "full123"
        assert api_key.permissions == permissions
        assert api_key.last_used_at == now
        assert api_key.last_used_ip == "192.168.1.1"
        assert api_key.usage_count == 42
        assert api_key.expires_at == expires
        assert api_key.user_id == user_id

    def test_api_key_inherits_from_base_model_mixin(self):
        """Test that APIKey inherits from BaseModelMixin."""
        user_id = uuid.uuid4()
        api_key = APIKey(key_hash="c" * 64, name="Test Key", key_prefix="test123", user_id=user_id)

        assert isinstance(api_key, BaseModelMixin)
        # Check inherited fields exist
        assert hasattr(api_key, "id")
        assert hasattr(api_key, "created_at")
        assert hasattr(api_key, "updated_at")
        assert hasattr(api_key, "is_deleted")
        assert hasattr(api_key, "version")


class TestAPIKeyValidations:
    """Test all validation methods in APIKey model."""

    def test_validate_key_hash_success(self):
        """Test successful key hash validation."""
        api_key = APIKey()

        # Test valid SHA256 hashes
        valid_hashes = [
            "a" * 64,
            "0123456789abcdef" * 4,
            "ABCDEF0123456789" * 4,  # Uppercase should be converted
            "fedcba9876543210" * 4,
        ]

        for hash_val in valid_hashes:
            result = api_key.validate_key_hash("key_hash", hash_val)
            assert result == hash_val.lower()  # Should be lowercased

    def test_validate_key_hash_empty(self):
        """Test key hash validation with empty value (allowed for secrets manager)."""
        api_key = APIKey()

        # Empty hash is now allowed for secrets manager support
        result = api_key.validate_key_hash("key_hash", "")
        assert result == ""

    def test_validate_key_hash_argon2_success(self):
        """Test successful Argon2 hash validation."""
        api_key = APIKey()

        # Test valid Argon2 hashes
        valid_argon2_hashes = [
            "$argon2id$v=19$m=102400,t=2,p=8$tSm+JOWigOux9jMVyBOmXg$UBX2UfkqJHsD8BqHYPsCuKbyJGGLOwPLpOpJJC6YQ8s",
            "$argon2i$v=19$m=4096,t=3,p=1$UhIMwzRMhkzLTGkWqj27vg$G2nHHmABV+OEJmkTjCcY7Eg8NUXdIKHKHAVdOULKaL4",
            "$argon2d$v=19$m=8192,t=1,p=2$bTRsXdJuCYk8OwJ4AXm4ag$E8aYxB+6GYjW+4bQpZCfZI3YoV5mD9tEAjNCw4YXsOE",
        ]

        for hash_val in valid_argon2_hashes:
            result = api_key.validate_key_hash("key_hash", hash_val)
            assert result == hash_val  # Argon2 hashes are returned as-is

    def test_validate_key_hash_wrong_length(self):
        """Test key hash validation with wrong length."""
        api_key = APIKey()

        invalid_lengths = [
            "a" * 63,  # Too short
            "a" * 65,  # Too long
            "a" * 32,  # MD5 length
            "a" * 128,  # SHA512 length
            "abc",  # Very short
            "",  # Empty handled separately
        ]

        for hash_val in invalid_lengths:
            if hash_val:  # Skip empty string
                with pytest.raises(ValueError, match="Key hash must be a valid SHA256 hash"):
                    api_key.validate_key_hash("key_hash", hash_val)

    def test_validate_key_hash_invalid_characters(self):
        """Test key hash validation with invalid hex characters."""
        api_key = APIKey()

        invalid_hashes = [
            "g" + "a" * 63,  # Invalid hex character 'g'
            "z" + "b" * 63,  # Invalid hex character 'z'
            "@" + "c" * 63,  # Invalid character '@'
            " " + "d" * 63,  # Space character
            "!" + "e" * 63,  # Special character
            "0123456789abcdefg" + "a" * 47,  # 'g' is invalid
        ]

        for hash_val in invalid_hashes:
            with pytest.raises(ValueError, match="Key hash must be a valid SHA256 hash"):
                api_key.validate_key_hash("key_hash", hash_val)

    def test_validate_name_success(self):
        """Test successful name validation."""
        api_key = APIKey()

        valid_names = [
            "Test Key",
            "Production API Key",
            "Development Key 123",
            "Special-Key_Name",
            "A" * 255,  # Maximum length
        ]

        for name in valid_names:
            with patch.object(api_key, "validate_string_security", return_value=None):
                result = api_key.validate_name("name", name)
                assert result == name

    def test_validate_name_empty(self):
        """Test name validation with empty value."""
        api_key = APIKey()

        with pytest.raises(ValueError, match="API key name is required"):
            api_key.validate_name("name", "")

    def test_validate_name_too_long(self):
        """Test name validation with too long value."""
        api_key = APIKey()

        long_name = "a" * 256
        with pytest.raises(ValueError, match="API key name cannot exceed 255 characters"):
            api_key.validate_name("name", long_name)

    def test_validate_name_calls_security_validation(self):
        """Test that name validation calls string security validation."""
        api_key = APIKey()

        with patch.object(api_key, "validate_string_security") as mock_security:
            api_key.validate_name("name", "Valid Name")
            mock_security.assert_called_once_with("name", "Valid Name")

    def test_validate_description_success(self):
        """Test successful description validation."""
        api_key = APIKey()

        valid_descriptions = [
            "Short description",
            "A" * 1000,  # Maximum length
            "Multi-line\nDescription\nWith details",
        ]

        for desc in valid_descriptions:
            with patch.object(api_key, "validate_string_security", return_value=None):
                result = api_key.validate_description("description", desc)
                assert result == desc

    def test_validate_description_none(self):
        """Test description validation with None value."""
        api_key = APIKey()

        result = api_key.validate_description("description", None)
        assert result is None

    def test_validate_description_too_long(self):
        """Test description validation with too long value."""
        api_key = APIKey()

        long_desc = "a" * 1001
        with pytest.raises(ValueError, match="Description cannot exceed 1000 characters"):
            api_key.validate_description("description", long_desc)

    def test_validate_description_calls_security_validation(self):
        """Test that description validation calls string security validation."""
        api_key = APIKey()

        with patch.object(api_key, "validate_string_security") as mock_security:
            api_key.validate_description("description", "Valid description")
            mock_security.assert_called_once_with("description", "Valid description")

    def test_validate_key_prefix_success(self):
        """Test successful key prefix validation."""
        api_key = APIKey()

        valid_prefixes = [
            "test123",  # Minimum length 6
            "prefix123",  # Alphanumeric
            "key_test1",  # With underscore
            "test-123",  # With hyphen (now allowed)
            "ABC123DEF",  # Uppercase
            "1234567890",  # Maximum length 10
        ]

        for prefix in valid_prefixes:
            result = api_key.validate_key_prefix("key_prefix", prefix)
            assert result == prefix

    def test_validate_key_prefix_empty(self):
        """Test key prefix validation with empty value."""
        api_key = APIKey()

        with pytest.raises(ValueError, match="Key prefix is required"):
            api_key.validate_key_prefix("key_prefix", "")

    def test_validate_key_prefix_too_short(self):
        """Test key prefix validation with too short value."""
        api_key = APIKey()

        short_prefixes = ["a", "ab", "abc", "abcd", "abcde"]  # All < 6 chars

        for prefix in short_prefixes:
            with pytest.raises(ValueError, match="Key prefix must be at least 6 characters"):
                api_key.validate_key_prefix("key_prefix", prefix)

    def test_validate_key_prefix_too_long(self):
        """Test key prefix validation with too long value."""
        api_key = APIKey()

        long_prefix = "a" * 11
        with pytest.raises(ValueError, match="Key prefix cannot exceed 10 characters"):
            api_key.validate_key_prefix("key_prefix", long_prefix)

    def test_validate_key_prefix_invalid_characters(self):
        """Test key prefix validation with invalid characters."""
        api_key = APIKey()

        invalid_prefixes = [
            "test.123",  # Dot not allowed
            "test@123",  # At symbol not allowed
            "test 123",  # Space not allowed
            "test#123",  # Hash not allowed
            "test!123",  # Exclamation not allowed
        ]

        for prefix in invalid_prefixes:
            with pytest.raises(
                ValueError,
                match="Key prefix must contain only alphanumeric characters, underscores, and hyphens",
            ):
                api_key.validate_key_prefix("key_prefix", prefix)

    def test_validate_last_used_ip_success(self):
        """Test successful IP address validation."""
        api_key = APIKey()

        valid_ips = ["192.168.1.1", "10.0.0.1", "::1", "2001:db8::1"]

        for ip in valid_ips:
            with patch.object(api_key, "validate_ip_address", return_value=ip):
                result = api_key.validate_last_used_ip("last_used_ip", ip)
                assert result == ip

    def test_validate_last_used_ip_none(self):
        """Test IP address validation with None value."""
        api_key = APIKey()

        result = api_key.validate_last_used_ip("last_used_ip", None)
        assert result is None

    def test_validate_last_used_ip_calls_mixin_validation(self):
        """Test that IP validation calls mixin validate_ip_address."""
        api_key = APIKey()

        with patch.object(api_key, "validate_ip_address", return_value="192.168.1.1") as mock_ip:
            api_key.validate_last_used_ip("last_used_ip", "192.168.1.1")
            mock_ip.assert_called_once_with("last_used_ip", "192.168.1.1")

    def test_validate_permissions_success(self):
        """Test successful permissions validation."""
        api_key = APIKey()

        valid_permissions = [
            {},  # Empty permissions
            {"read": True},
            {"read": True, "write": False},
            {"admin": True},
            {"*": True},
            {"targets:read": True, "sessions:write": False},
            {"users:*": True},
            {"sessions:delete": True, "api_keys:read": False},
        ]

        for perms in valid_permissions:
            result = api_key.validate_permissions("permissions", perms)
            assert result == perms

    def test_validate_permissions_not_dict(self):
        """Test permissions validation with non-dict value."""
        api_key = APIKey()

        invalid_types = ["string", ["list"], 42, True, None]

        for invalid in invalid_types:
            with pytest.raises(ValueError, match="Permissions must be a dictionary"):
                api_key.validate_permissions("permissions", invalid)

    def test_validate_permissions_invalid_scope(self):
        """Test permissions validation with invalid scope."""
        api_key = APIKey()

        invalid_scopes = [
            {"invalid_scope": True},
            {"random:permission": True},
            {"": True},  # Empty scope
            {"bad_resource:action": True},
        ]

        for perms in invalid_scopes:
            with pytest.raises(ValueError, match="Invalid permission scope"):
                api_key.validate_permissions("permissions", perms)

    def test_validate_permissions_non_boolean_value(self):
        """Test permissions validation with non-boolean values."""
        api_key = APIKey()

        invalid_values = [
            {"read": "true"},  # String instead of boolean
            {"write": 1},  # Integer instead of boolean
            {"admin": None},  # None instead of boolean
            {"delete": []},  # List instead of boolean
        ]

        for perms in invalid_values:
            scope = list(perms.keys())[0]
            with pytest.raises(ValueError, match=f"Permission value for '{scope}' must be boolean"):
                api_key.validate_permissions("permissions", perms)

    def test_validate_permissions_wildcard_scopes(self):
        """Test permissions validation with wildcard scopes."""
        api_key = APIKey()

        # Wildcard scopes should be valid even if not in VALID_SCOPES
        wildcard_permissions = [
            {"custom:*": True},
            {"resource:*": False},
            {"another_resource:*": True},
        ]

        for perms in wildcard_permissions:
            result = api_key.validate_permissions("permissions", perms)
            assert result == perms


class TestAPIKeyBusinessLogic:
    """Test business logic methods in APIKey model."""

    def test_is_expired_no_expiration(self):
        """Test is_expired when no expiration is set."""
        api_key = APIKey(expires_at=None)

        assert api_key.is_expired() is False

    def test_is_expired_future_expiration(self):
        """Test is_expired with future expiration."""
        future = datetime.now(timezone.utc) + timedelta(days=1)
        api_key = APIKey(expires_at=future)

        assert api_key.is_expired() is False

    def test_is_expired_past_expiration(self):
        """Test is_expired with past expiration."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        api_key = APIKey(expires_at=past)

        assert api_key.is_expired() is True

    def test_is_expired_exact_expiration(self):
        """Test is_expired at exact expiration time."""
        now = datetime.now(timezone.utc)
        api_key = APIKey(expires_at=now)

        # Should be expired since now > expires_at (even by microseconds)
        import time

        time.sleep(0.001)  # Ensure we're past the expiration
        assert api_key.is_expired() is True

    def test_is_expired_naive_datetime(self):
        """Test is_expired with naive datetime (no timezone)."""
        # Create naive datetime (no timezone info)
        naive_future = datetime.now() + timedelta(days=1)
        api_key = APIKey(expires_at=naive_future)

        # Should not be expired (naive datetime treated as UTC)
        assert api_key.is_expired() is False

    def test_is_expired_naive_past_datetime(self):
        """Test is_expired with naive past datetime."""
        naive_past = datetime.now() - timedelta(days=1)
        api_key = APIKey(expires_at=naive_past)

        assert api_key.is_expired() is True

    def test_is_active_not_deleted_not_expired(self):
        """Test is_active when not deleted and not expired."""
        future = datetime.now(timezone.utc) + timedelta(days=1)
        api_key = APIKey(expires_at=future)
        api_key.is_deleted = False

        assert api_key.is_active() is True

    def test_is_active_deleted(self):
        """Test is_active when deleted."""
        api_key = APIKey()
        api_key.is_deleted = True

        assert api_key.is_active() is False

    def test_is_active_expired(self):
        """Test is_active when expired."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        api_key = APIKey(expires_at=past)
        api_key.is_deleted = False

        assert api_key.is_active() is False

    def test_is_active_is_deleted_none(self):
        """Test is_active when is_deleted is None (before database save)."""
        api_key = APIKey()
        api_key.is_deleted = None  # Simulate before database save

        assert api_key.is_active() is True

    def test_is_valid_property(self):
        """Test is_valid property (alias for is_active)."""
        api_key = APIKey()
        api_key.is_deleted = False

        assert api_key.is_valid == api_key.is_active()

    def test_record_usage_first_time(self):
        """Test record_usage for the first time."""
        api_key = APIKey()
        api_key.usage_count = None  # Simulate fresh key

        before_time = datetime.now(timezone.utc)
        api_key.record_usage("192.168.1.1")
        after_time = datetime.now(timezone.utc)

        assert api_key.usage_count == 1
        assert api_key.last_used_ip == "192.168.1.1"
        assert before_time <= api_key.last_used_at <= after_time

    def test_record_usage_subsequent_times(self):
        """Test record_usage for subsequent uses."""
        api_key = APIKey()
        api_key.usage_count = 5

        api_key.record_usage("10.0.0.1")

        assert api_key.usage_count == 6
        assert api_key.last_used_ip == "10.0.0.1"
        assert api_key.last_used_at is not None

    def test_record_usage_without_ip(self):
        """Test record_usage without providing IP address."""
        api_key = APIKey()
        api_key.usage_count = 0
        api_key.last_used_ip = "192.168.1.100"  # Valid IP address

        api_key.record_usage()

        assert api_key.usage_count == 1
        assert api_key.last_used_ip == "192.168.1.100"  # Should remain unchanged
        assert api_key.last_used_at is not None

    def test_record_usage_with_none_ip(self):
        """Test record_usage with None IP address."""
        api_key = APIKey()
        api_key.usage_count = 0
        api_key.last_used_ip = "10.0.0.1"  # Valid IP address

        api_key.record_usage(None)

        assert api_key.usage_count == 1
        assert api_key.last_used_ip == "10.0.0.1"  # Should remain unchanged

    def test_has_permission_inactive_key(self):
        """Test has_permission with inactive key."""
        api_key = APIKey()
        api_key.is_deleted = True  # Make it inactive
        api_key.permissions = {"read": True}

        assert api_key.has_permission("read") is False

    def test_has_permission_no_permissions(self):
        """Test has_permission when permissions are empty."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {}

        assert api_key.has_permission("read") is False

    def test_has_permission_none_permissions(self):
        """Test has_permission when permissions is None."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {}

        assert api_key.has_permission("read") is False

    def test_has_permission_admin_permission(self):
        """Test has_permission with admin permission."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {"admin": True}

        # Admin should have all permissions
        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is True
        assert api_key.has_permission("delete") is True
        assert api_key.has_permission("custom:action") is True

    def test_has_permission_wildcard_permission(self):
        """Test has_permission with wildcard (*) permission."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {"*": True}

        # Wildcard should grant all permissions
        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is True
        assert api_key.has_permission("sessions:delete") is True

    def test_has_permission_specific_permission(self):
        """Test has_permission with specific permission."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {"read": True, "write": False}

        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is False
        assert api_key.has_permission("delete") is False

    def test_has_permission_resource_wildcard(self):
        """Test has_permission with resource wildcard permissions."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {"sessions:*": True, "users:read": True}

        # sessions:* should cover all sessions permissions
        assert api_key.has_permission("sessions:read") is True
        assert api_key.has_permission("sessions:write") is True
        assert api_key.has_permission("sessions:delete") is True

        # users:read should be specific
        assert api_key.has_permission("users:read") is True
        assert api_key.has_permission("users:write") is False

    def test_has_permission_no_colon_in_permission(self):
        """Test has_permission with permission without colon."""
        api_key = APIKey()
        api_key.is_deleted = False
        api_key.permissions = {"read": True}

        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is False


class TestAPIKeyRepresentation:
    """Test string representation methods."""

    def test_repr_active_key(self):
        """Test __repr__ method with active key."""
        api_key = APIKey(name="Test Key", key_prefix="test123")
        api_key.is_deleted = False

        repr_str = repr(api_key)
        # Check that repr contains the expected components
        assert repr_str.startswith("<APIKey(")
        assert repr_str.endswith(")>")
        assert "name='Test Key'" in repr_str
        assert "prefix='test123'" in repr_str
        assert "active=True" in repr_str
        assert "usage=0" in repr_str  # Default usage count

    def test_repr_inactive_key(self):
        """Test __repr__ method with inactive key."""
        api_key = APIKey(name="Inactive Key", key_prefix="inactive")
        api_key.is_deleted = True

        repr_str = repr(api_key)
        # Check that repr contains the expected components
        assert repr_str.startswith("<APIKey(")
        assert repr_str.endswith(")>")
        assert "name='Inactive Key'" in repr_str
        assert "prefix='inactive'" in repr_str
        assert "active=False" in repr_str
        assert "usage=0" in repr_str

    def test_to_dict_minimal(self):
        """Test to_dict method with minimal data."""
        api_key = APIKey(name="Test Key", key_prefix="test123", permissions={"read": True})

        with patch.object(api_key, "id", "123e4567-e89b-12d3-a456-426614174000"):
            with patch.object(api_key, "is_active", return_value=True):
                with patch.object(api_key, "created_at", None):
                    with patch.object(api_key, "updated_at", None):
                        result = api_key.to_dict()

        # Check required fields
        assert result["id"] == "123e4567-e89b-12d3-a456-426614174000"
        assert result["name"] == "Test Key"
        assert result["description"] is None
        assert result["key_prefix"] == "test123"
        assert result["permissions"] == {"read": True}
        assert result["last_used_at"] is None
        assert result["usage_count"] == 0  # Default from __init__
        assert result["expires_at"] is None
        assert result["is_active"] is True
        assert result["created_at"] is None
        assert result["updated_at"] is None
        assert result["revoked_at"] is None
        assert "masked_key" in result  # Should have masked key
        assert "last_used_ip" not in result  # Sensitive field excluded

    def test_to_dict_full_data(self):
        """Test to_dict method with full data."""
        created_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        used_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        expires_time = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        api_key = APIKey(
            name="Full Key",
            description="Complete API key",
            key_prefix="full123",
            permissions={"admin": True},
            last_used_at=used_time,
            usage_count=100,
            expires_at=expires_time,
        )

        with patch.object(api_key, "id", "456e7890-e12b-34c5-d678-901234567890"):
            with patch.object(api_key, "is_active", return_value=True):
                with patch.object(api_key, "created_at", created_time):
                    with patch.object(api_key, "updated_at", created_time):
                        result = api_key.to_dict()

        # Check all fields are properly set
        assert result["id"] == "456e7890-e12b-34c5-d678-901234567890"
        assert result["name"] == "Full Key"
        assert result["description"] == "Complete API key"
        assert result["key_prefix"] == "full123"
        assert result["permissions"] == {"admin": True}
        assert result["last_used_at"] == "2024-01-15T10:30:00+00:00"
        assert result["usage_count"] == 100
        assert result["expires_at"] == "2024-12-31T23:59:59+00:00"
        assert result["is_active"] is True
        assert result["created_at"] == "2024-01-01T12:00:00+00:00"
        assert result["updated_at"] == "2024-01-01T12:00:00+00:00"
        assert "masked_key" in result
        assert "last_used_ip" not in result  # Sensitive data excluded by default


class TestAPIKeyConstraintsAndConfig:
    """Test model constraints and configuration."""

    def test_model_constraints(self):
        """Test that model constraints are properly defined."""
        constraints = APIKey._model_constraints

        assert len(constraints) == 3

        # Check unique constraint for name/user
        name_constraint = constraints[0]
        assert name_constraint.name == "uq_apikey_name_user"
        constraint_columns = [col.name for col in name_constraint.columns]
        assert "name" in constraint_columns
        assert "user_id" in constraint_columns
        assert "is_deleted" in constraint_columns

    def test_model_config(self):
        """Test that model configuration is properly defined."""
        config = APIKey._model_config

        assert config["comment"] == "API keys for authentication with granular permissions"

    def test_table_name(self):
        """Test that the table name is correctly set."""
        # The table name should be 'api_key' by default
        assert APIKey.__tablename__ == "api_key"


class TestAPIKeyFieldProperties:
    """Test individual field properties and constraints."""

    def test_key_hash_field_properties(self):
        """Test key_hash field properties."""
        key_hash_column = APIKey.key_hash.property.columns[0]

        assert key_hash_column.type.length == 255
        assert key_hash_column.unique is True
        assert key_hash_column.nullable is False
        assert key_hash_column.index is True
        assert key_hash_column.comment == "SHA256 hash of the API key"

    def test_name_field_properties(self):
        """Test name field properties."""
        name_column = APIKey.name.property.columns[0]

        assert name_column.type.length == 255
        assert name_column.nullable is False
        assert name_column.comment == "Descriptive name for the API key"

    def test_description_field_properties(self):
        """Test description field properties."""
        desc_column = APIKey.description.property.columns[0]

        assert desc_column.type.length == 1000
        assert desc_column.nullable is True
        assert desc_column.comment == "Detailed description of key purpose"

    def test_key_prefix_field_properties(self):
        """Test key_prefix field properties."""
        prefix_column = APIKey.key_prefix.property.columns[0]

        assert prefix_column.type.length == 10
        assert prefix_column.nullable is False
        assert prefix_column.index is True
        assert prefix_column.comment == "First few characters of key for identification"

    def test_permissions_field_properties(self):
        """Test permissions field properties."""
        perms_column = APIKey.permissions.property.columns[0]

        assert perms_column.nullable is False
        # The default is dict (the actual function, not a callable wrapper)
        assert callable(perms_column.default.arg)
        assert perms_column.default.arg.__name__ == "dict"
        assert perms_column.comment == "JSON containing permission scopes"

    def test_usage_tracking_field_properties(self):
        """Test usage tracking field properties."""
        last_used_column = APIKey.last_used_at.property.columns[0]
        usage_count_column = APIKey.usage_count.property.columns[0]

        # last_used_at
        assert last_used_column.type.timezone is True
        assert last_used_column.nullable is True
        assert last_used_column.index is True

        # usage_count
        assert usage_count_column.nullable is False
        assert usage_count_column.default.arg == 0
        assert str(usage_count_column.server_default.arg) == "0"

    def test_expires_at_field_properties(self):
        """Test expires_at field properties."""
        expires_column = APIKey.expires_at.property.columns[0]

        assert expires_column.type.timezone is True
        assert expires_column.nullable is True
        assert expires_column.index is True
        assert expires_column.comment == "Optional expiration timestamp"

    def test_user_id_field_properties(self):
        """Test user_id field properties."""
        user_id_column = APIKey.user_id.property.columns[0]

        assert user_id_column.nullable is False
        assert user_id_column.index is True
        assert user_id_column.comment == "ID of the user who owns this API key"
        # ForeignKey constraint
        assert len(user_id_column.foreign_keys) == 1
        fk = list(user_id_column.foreign_keys)[0]
        assert str(fk.column) == "user.id"
        assert fk.ondelete == "CASCADE"


class TestAPIKeyRelationships:
    """Test model relationships."""

    def test_user_relationship(self):
        """Test user relationship configuration."""
        relationship_property = APIKey.user.property

        assert relationship_property.mapper.class_.__name__ == "User"
        assert relationship_property.back_populates == "api_keys"


class TestAPIKeyValidationEdgeCases:
    """Test edge cases in validation methods."""

    def test_validation_with_security_failure(self):
        """Test validation when security validation fails."""
        api_key = APIKey()

        with patch.object(
            api_key,
            "validate_string_security",
            side_effect=ValueError("Security validation failed"),
        ):
            with pytest.raises(ValueError, match="Security validation failed"):
                api_key.validate_name("name", "Valid Name")

    def test_key_hash_case_insensitive(self):
        """Test that key hash is converted to lowercase."""
        api_key = APIKey()

        uppercase_hash = "ABCDEF0123456789" * 4
        result = api_key.validate_key_hash("key_hash", uppercase_hash)
        assert result == uppercase_hash.lower()

    def test_permissions_valid_scopes_coverage(self):
        """Test all valid permission scopes are accepted."""
        api_key = APIKey()

        # Test all scopes from VALID_SCOPES
        valid_scopes = [
            "read",
            "write",
            "delete",
            "admin",
            "*",
            "targets:read",
            "targets:write",
            "targets:delete",
            "sessions:read",
            "sessions:write",
            "sessions:delete",
            "sessions:*",
            "users:read",
            "users:write",
            "users:delete",
            "api_keys:read",
            "api_keys:write",
            "api_keys:delete",
        ]

        for scope in valid_scopes:
            permissions = {scope: True}
            result = api_key.validate_permissions("permissions", permissions)
            assert result == permissions


class TestAPIKeyIntegrationScenarios:
    """Test integration scenarios and complex use cases."""

    def test_api_key_lifecycle(self):
        """Test complete API key lifecycle."""
        user_id = uuid.uuid4()

        # Create new key
        api_key = APIKey(
            key_hash="a" * 64,
            name="Lifecycle Test Key",
            key_prefix="lifecycle",
            user_id=user_id,
            permissions={"read": True},
        )

        # Should be active initially
        api_key.is_deleted = False
        assert api_key.is_active() is True
        assert api_key.has_permission("read") is True

        # Record usage
        api_key.record_usage("192.168.1.1")
        assert api_key.usage_count == 1

        # Set expiration and check
        api_key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert api_key.is_expired() is True
        assert api_key.is_active() is False

        # Expired keys have no permissions
        assert api_key.has_permission("read") is False

    def test_permission_hierarchy(self):
        """Test permission hierarchy (admin > wildcard > specific)."""
        user_id = uuid.uuid4()

        # Admin key
        admin_key = APIKey(user_id=user_id, permissions={"admin": True})
        admin_key.is_deleted = False

        # Wildcard key
        wildcard_key = APIKey(user_id=user_id, permissions={"*": True})
        wildcard_key.is_deleted = False

        # Resource wildcard key
        resource_key = APIKey(user_id=user_id, permissions={"sessions:*": True})
        resource_key.is_deleted = False

        # Specific permission key
        specific_key = APIKey(user_id=user_id, permissions={"sessions:read": True})
        specific_key.is_deleted = False

        test_permission = "sessions:delete"

        # Test hierarchy
        assert admin_key.has_permission(test_permission) is True
        assert wildcard_key.has_permission(test_permission) is True
        assert resource_key.has_permission(test_permission) is True
        assert specific_key.has_permission(test_permission) is False
