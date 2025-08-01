"""Comprehensive tests for User model to achieve 100% coverage."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.mixins import BaseModelMixin
from app.models.user import User


class TestUserModelCreation:
    """Test user creation and basic functionality."""

    def test_user_creation_minimal(self):
        """Test creating user with minimal required fields."""
        user = User(username="testuser", email="test@example.com", password_hash="$argon2id$v=19$m=102400,t=2,p=8$test")

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash.startswith("$argon2")
        assert user.is_active is True  # Default value
        assert user.is_superuser is False  # Default value
        assert user.is_verified is False  # Default value
        assert user.full_name is None
        assert user.verified_at is None
        assert user.last_login_at is None
        assert user.last_login_ip is None

    def test_user_creation_full_fields(self):
        """Test creating user with all fields populated."""
        now = datetime.now(timezone.utc)
        user = User(
            username="fulluser",
            email="full@example.com",
            password_hash="$argon2id$v=19$m=102400,t=2,p=8$test",
            full_name="Full Name",
            is_active=True,
            is_superuser=True,
            is_verified=True,
            verified_at=now,
            last_login_at=now,
            last_login_ip="192.168.1.1",
        )

        assert user.username == "fulluser"
        assert user.email == "full@example.com"
        assert user.full_name == "Full Name"
        assert user.is_active is True
        assert user.is_superuser is True
        assert user.is_verified is True
        assert user.verified_at == now
        assert user.last_login_at == now
        assert user.last_login_ip == "192.168.1.1"

    def test_user_inherits_from_base_model_mixin(self):
        """Test that User inherits from BaseModelMixin."""
        user = User(username="testuser", email="test@example.com", password_hash="$argon2id$v=19$m=102400,t=2,p=8$test")

        assert isinstance(user, BaseModelMixin)
        # Check inherited fields exist
        assert hasattr(user, "id")
        assert hasattr(user, "created_at")
        assert hasattr(user, "updated_at")
        assert hasattr(user, "is_deleted")
        assert hasattr(user, "version")


class TestUserValidations:
    """Test all validation methods in User model."""

    def test_validate_username_success(self):
        """Test successful username validation."""
        user = User()

        # Test valid usernames
        valid_usernames = ["user123", "test_user", "user-name", "ABC123", "a1b2c3", "user_123-test"]

        for username in valid_usernames:
            with patch.object(user, "validate_string_security", return_value=None):
                result = user.validate_username("username", username)
                # Username validation converts to lowercase
                assert result == username.lower()

    def test_validate_username_empty(self):
        """Test username validation with empty value."""
        user = User()

        with pytest.raises(ValueError, match="Username is required"):
            user.validate_username("username", "")

    def test_validate_username_too_short(self):
        """Test username validation with too short value."""
        user = User()

        with pytest.raises(ValueError, match="Username must be at least 3 characters"):
            user.validate_username("username", "ab")

    def test_validate_username_too_long(self):
        """Test username validation with too long value."""
        user = User()

        long_username = "a" * 101
        with pytest.raises(ValueError, match="Username cannot exceed 100 characters"):
            user.validate_username("username", long_username)

    def test_validate_username_invalid_characters(self):
        """Test username validation with invalid characters."""
        user = User()

        invalid_usernames = [
            "user@name",
            "user.name",
            "user name",
            "user#name",
            "user$name",
            "user%name",
            "user&name",
            "user*name",
            "user+name",
            "user=name",
            "user!name",
        ]

        for username in invalid_usernames:
            with pytest.raises(
                ValueError, match="Username can only contain letters, numbers, underscores, and hyphens"
            ):
                user.validate_username("username", username)

    def test_validate_username_calls_security_validation(self):
        """Test that username validation calls string security validation."""
        user = User()

        with patch.object(user, "validate_string_security") as mock_security:
            user.validate_username("username", "validuser")
            mock_security.assert_called_once_with("username", "validuser")

    def test_validate_email_field_success(self):
        """Test successful email validation."""
        user = User()

        valid_emails = ["test@example.com", "user.name@domain.org", "user+tag@example.co.uk", "123@numbers.com"]

        for email in valid_emails:
            with patch.object(user, "validate_email_format", return_value=email):
                with patch.object(user, "validate_string_security", return_value=None):
                    result = user.validate_email_field("email", email)
                    assert result == email

    def test_validate_email_field_empty(self):
        """Test email validation with empty value."""
        user = User()

        with pytest.raises(ValueError, match="Email is required"):
            user.validate_email_field("email", "")

    def test_validate_email_field_calls_mixin_validation(self):
        """Test that email validation calls mixin email validation."""
        user = User()

        with patch.object(user, "validate_email_format", return_value="test@example.com") as mock_email:
            with patch.object(user, "validate_string_security", return_value=None):
                user.validate_email_field("email", "test@example.com")
                mock_email.assert_called_once_with("email", "test@example.com")

    def test_validate_email_field_calls_security_validation(self):
        """Test that email validation calls string security validation."""
        user = User()

        with patch.object(user, "validate_email_format", return_value="test@example.com"):
            with patch.object(user, "validate_string_security") as mock_security:
                user.validate_email_field("email", "test@example.com")
                mock_security.assert_called_once_with("email", "test@example.com")

    def test_validate_email_field_handles_none_from_mixin(self):
        """Test email validation when mixin returns None."""
        user = User()

        with patch.object(user, "validate_email_format", return_value=None):
            # This should trigger the assertion error in the code
            with pytest.raises(AssertionError):
                user.validate_email_field("email", "test@example.com")

    def test_validate_password_hash_success(self):
        """Test successful password hash validation."""
        user = User()

        valid_hashes = [
            "$argon2id$v=19$m=102400,t=2,p=8$test",
            "$argon2i$v=19$m=65536,t=3,p=4$salt$hash",
            "$argon2d$v=19$m=32768,t=1,p=2$another",
        ]

        for hash_val in valid_hashes:
            result = user.validate_password_hash("password_hash", hash_val)
            assert result == hash_val

    def test_validate_password_hash_empty(self):
        """Test password hash validation with empty value."""
        user = User()

        with pytest.raises(ValueError, match="Password hash is required"):
            user.validate_password_hash("password_hash", "")

    def test_validate_password_hash_not_argon2(self):
        """Test password hash validation with non-Argon2 hash."""
        user = User()

        invalid_hashes = [
            "plaintext_password",
            "$2b$12$hash",  # bcrypt
            "$1$salt$hash",  # MD5
            "$5$salt$hash",  # SHA-256
            "$6$salt$hash",  # SHA-512
            "pbkdf2_sha256$hash",
        ]

        for hash_val in invalid_hashes:
            with pytest.raises(ValueError, match="Password must be hashed with Argon2"):
                user.validate_password_hash("password_hash", hash_val)

    def test_validate_full_name_success(self):
        """Test successful full name validation."""
        user = User()

        valid_names = [
            "John Doe",
            "Jane Smith-Johnson",
            "José María García",
            "李小明",  # Chinese characters
            "Müller",  # German umlaut
            "O'Connor",  # Apostrophe
            "Van Der Berg",
        ]

        for name in valid_names:
            with patch.object(user, "validate_string_security", return_value=None):
                result = user.validate_full_name("full_name", name)
                assert result == name

    def test_validate_full_name_none(self):
        """Test full name validation with None value."""
        user = User()

        result = user.validate_full_name("full_name", None)
        assert result is None

    def test_validate_full_name_too_long(self):
        """Test full name validation with too long value."""
        user = User()

        long_name = "a" * 256
        with pytest.raises(ValueError, match="Full name cannot exceed 255 characters"):
            user.validate_full_name("full_name", long_name)

    def test_validate_full_name_calls_security_validation(self):
        """Test that full name validation calls string security validation."""
        user = User()

        with patch.object(user, "validate_string_security") as mock_security:
            user.validate_full_name("full_name", "John Doe")
            mock_security.assert_called_once_with("full_name", "John Doe")


class TestUserRepresentation:
    """Test string representation methods."""

    def test_repr(self):
        """Test __repr__ method."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=102400,t=2,p=8$test",
            is_active=True,
        )

        # Mock the id since it's None before saving to DB
        with patch.object(user, "id", "12345678-1234-5678-1234-567812345678"):
            repr_str = repr(user)
            expected = "<User(id=12345678, username='testuser', email='test@example.com', active=True)>"
            assert repr_str == expected

    def test_repr_inactive_user(self):
        """Test __repr__ method with inactive user."""
        user = User(
            username="inactive",
            email="inactive@example.com",
            password_hash="$argon2id$v=19$m=102400,t=2,p=8$test",
            is_active=False,
        )

        # Mock the id since it's None before saving to DB
        with patch.object(user, "id", "87654321-4321-8765-4321-876543218765"):
            repr_str = repr(user)
            expected = "<User(id=87654321, username='inactive', email='inactive@example.com', active=False)>"
            assert repr_str == expected

    def test_to_dict_minimal(self):
        """Test to_dict method with minimal user data."""
        user = User(username="testuser", email="test@example.com", password_hash="$argon2id$v=19$m=102400,t=2,p=8$test")

        # Mock the id property since it's from the mixin
        with patch.object(user, "id", "123e4567-e89b-12d3-a456-426614174000"):
            with patch.object(user, "created_at", None):
                with patch.object(user, "updated_at", None):
                    with patch.object(user, "organization_id", None):
                        result = user.to_dict()

        expected = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "testuser",
            "email": "test@example.com",
            "full_name": None,
            "is_active": True,
            "is_superuser": False,
            "roles": ["viewer"],  # Default role
            "organization_id": None,
            "created_at": None,
            "updated_at": None,
        }

        assert result == expected

    def test_to_dict_full_data(self):
        """Test to_dict method with full user data."""
        created_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        updated_time = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
        org_id = "456e4567-e89b-12d3-a456-426614174001"

        user = User(
            username="fulluser",
            email="full@example.com",
            password_hash="$argon2id$v=19$m=102400,t=2,p=8$test",
            full_name="Full Name",
            is_active=True,
            is_superuser=True,
        )

        with patch.object(user, "id", "123e4567-e89b-12d3-a456-426614174000"):
            with patch.object(user, "created_at", created_time):
                with patch.object(user, "updated_at", updated_time):
                    with patch.object(user, "roles", ["admin", "tester"]):
                        with patch.object(user, "organization_id", org_id):
                            result = user.to_dict()

        expected = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "fulluser",
            "email": "full@example.com",
            "full_name": "Full Name",
            "is_active": True,
            "is_superuser": True,
            "roles": ["admin", "tester"],
            "organization_id": org_id,
            "created_at": "2024-01-01T12:00:00+00:00",
            "updated_at": "2024-01-02T12:00:00+00:00",
        }

        assert result == expected


class TestUserConstraintsAndConfig:
    """Test model constraints and configuration."""

    def test_model_constraints(self):
        """Test that model constraints are properly defined."""
        constraints = User._model_constraints

        assert len(constraints) == 2

        # Check username constraint
        username_constraint = constraints[0]
        assert username_constraint.name == "uq_user_username_active"
        assert "username" in [col.name for col in username_constraint.columns]
        assert "is_deleted" in [col.name for col in username_constraint.columns]

        # Check email constraint
        email_constraint = constraints[1]
        assert email_constraint.name == "uq_user_email_active"
        assert "email" in [col.name for col in email_constraint.columns]
        assert "is_deleted" in [col.name for col in email_constraint.columns]

    def test_model_config(self):
        """Test that model configuration is properly defined."""
        config = User._model_config

        assert config["comment"] == "User accounts with authentication and authorization"

    def test_table_name(self):
        """Test that the table name is correctly set."""
        # The table name should be 'user' by default (lowercase class name)
        assert User.__tablename__ == "user"


class TestUserFieldProperties:
    """Test individual field properties and constraints."""

    def test_username_field_properties(self):
        """Test username field properties."""
        username_column = User.username.property.columns[0]

        assert username_column.type.length == 100
        assert username_column.unique is True
        assert username_column.nullable is False
        assert username_column.index is True
        assert username_column.comment == "Unique username for login"

    def test_email_field_properties(self):
        """Test email field properties."""
        email_column = User.email.property.columns[0]

        assert email_column.type.length == 254  # RFC 5321 maximum
        assert email_column.unique is True
        assert email_column.nullable is False
        assert email_column.index is True
        assert email_column.comment == "User email address"

    def test_password_hash_field_properties(self):
        """Test password_hash field properties."""
        password_column = User.password_hash.property.columns[0]

        assert password_column.type.length == 255
        assert password_column.nullable is False
        assert password_column.comment == "Argon2 password hash"

    def test_full_name_field_properties(self):
        """Test full_name field properties."""
        full_name_column = User.full_name.property.columns[0]

        assert full_name_column.type.length == 255
        assert full_name_column.nullable is True
        assert full_name_column.comment == "User's full display name"

    def test_boolean_field_properties(self):
        """Test boolean field properties."""
        is_active_column = User.is_active.property.columns[0]
        is_superuser_column = User.is_superuser.property.columns[0]
        is_verified_column = User.is_verified.property.columns[0]

        # Test is_active
        assert is_active_column.default.arg is True
        assert is_active_column.nullable is False
        assert str(is_active_column.server_default.arg) == "true"

        # Test is_superuser
        assert is_superuser_column.default.arg is False
        assert is_superuser_column.nullable is False
        assert str(is_superuser_column.server_default.arg) == "false"

        # Test is_verified
        assert is_verified_column.default.arg is False
        assert is_verified_column.nullable is False
        assert str(is_verified_column.server_default.arg) == "false"

    def test_datetime_field_properties(self):
        """Test datetime field properties."""
        verified_at_column = User.verified_at.property.columns[0]
        last_login_at_column = User.last_login_at.property.columns[0]

        # Both should allow timezone and be nullable
        assert verified_at_column.type.timezone is True
        assert verified_at_column.nullable is True

        assert last_login_at_column.type.timezone is True
        assert last_login_at_column.nullable is True

    def test_last_login_ip_field_properties(self):
        """Test last_login_ip field properties."""
        ip_column = User.last_login_ip.property.columns[0]

        assert ip_column.type.length == 45  # IPv6 support
        assert ip_column.nullable is True
        assert ip_column.comment == "IP address of the user's last successful login"


class TestUserRelationships:
    """Test model relationships."""

    def test_api_keys_relationship(self):
        """Test api_keys relationship configuration."""
        relationship_property = User.api_keys.property

        assert relationship_property.mapper.class_.__name__ == "APIKey"
        assert relationship_property.back_populates == "user"
        # In SQLAlchemy 2.0+, "all" is expanded to individual cascade options
        # Check for "delete" which is part of the "all" cascade
        assert "delete" in relationship_property.cascade
        assert "delete-orphan" in relationship_property.cascade
        assert relationship_property.lazy == "dynamic"


class TestUserValidationEdgeCases:
    """Test edge cases in validation methods."""

    def test_validation_with_security_failure(self):
        """Test validation when security validation fails."""
        user = User()

        with patch.object(user, "validate_string_security", side_effect=ValueError("Security validation failed")):
            with pytest.raises(ValueError, match="Security validation failed"):
                user.validate_username("username", "validuser")

    def test_validation_preserves_original_exceptions(self):
        """Test that original validation exceptions are preserved."""
        user = User()

        # Test that username validation error is raised before security validation
        try:
            user.validate_username("username", "ab")  # Too short
        except ValueError as e:
            assert "Username must be at least 3 characters" in str(e)

    def test_email_validation_assertion_coverage(self):
        """Test the assertion in email validation."""
        user = User()

        # Create a case where validation returns a string but we want to test the assertion
        with patch.object(user, "validate_email_format", return_value="validated@example.com"):
            with patch.object(user, "validate_string_security", return_value=None):
                result = user.validate_email_field("email", "test@example.com")
                assert result == "validated@example.com"


class TestUserIntegrationScenarios:
    """Test integration scenarios and complex use cases."""

    def test_user_creation_with_all_validations(self):
        """Test creating a user that triggers all validation methods."""
        # This should trigger all validation methods during object creation
        with patch.object(User, "validate_string_security", return_value=None):
            with patch.object(User, "validate_email_format", return_value="test@example.com"):
                user = User(
                    username="testuser123",
                    email="test@example.com",
                    password_hash="$argon2id$v=19$m=102400,t=2,p=8$test",
                    full_name="Test User",
                )

                assert user.username == "testuser123"
                assert user.email == "test@example.com"
                assert user.full_name == "Test User"

    def test_user_modification_triggers_validation(self):
        """Test that modifying user fields triggers validation."""
        user = User(
            username="original", email="original@example.com", password_hash="$argon2id$v=19$m=102400,t=2,p=8$test"
        )

        with patch.object(user, "validate_string_security", return_value=None):
            # Changing username should trigger validation
            user.username = "newusername"
            assert user.username == "newusername"
