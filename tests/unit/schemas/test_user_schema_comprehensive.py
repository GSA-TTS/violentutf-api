"""Comprehensive tests for user schemas to achieve 90%+ coverage."""

from datetime import datetime, timezone
from typing import Optional
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.schemas.user import (
    UserBase,
    UserCreate,
    UserCreateResponse,
    UserListResponse,
    UserResponse,
    UserUpdate,
    UserUpdatePassword,
)


class TestUserBase:
    """Test UserBase schema."""

    def test_user_base_valid(self):
        """Test creating valid UserBase."""
        user = UserBase(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_superuser=False,
            email_verified=True,
            totp_enabled=False,
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.is_active is True
        assert user.is_superuser is False
        assert user.email_verified is True
        assert user.totp_enabled is False

    def test_user_base_minimal(self):
        """Test UserBase with minimal required fields."""
        user = UserBase(username="minuser", email="min@example.com")

        assert user.username == "minuser"
        assert user.email == "min@example.com"
        assert user.full_name is None
        assert user.is_active is True  # Default
        assert user.is_superuser is False  # Default
        assert user.email_verified is False  # Default
        assert user.totp_enabled is False  # Default

    def test_username_validation(self):
        """Test username validation rules."""
        # Valid usernames
        valid_usernames = [
            "abc",  # Minimum length
            "user123",
            "test_user",
            "user-name",
            "UPPERCASE",
            "mixedCase123",
            "a" * 100,  # Maximum length
        ]

        for username in valid_usernames:
            user = UserBase(username=username, email="test@example.com")
            assert user.username == username

        # Invalid usernames
        invalid_usernames = [
            "ab",  # Too short
            "a" * 101,  # Too long
            "user name",  # Space
            "user@name",  # Invalid character
            "user.name",  # Dot
            "user/name",  # Slash
            "user\\name",  # Backslash
            "user#name",  # Hash
            "user$name",  # Dollar
            "user%name",  # Percent
            "user&name",  # Ampersand
            "user*name",  # Asterisk
            "user+name",  # Plus
            "user=name",  # Equals
            "user[name]",  # Brackets
            "user{name}",  # Braces
            "user|name",  # Pipe
            "user:name",  # Colon
            "user;name",  # Semicolon
            "user'name",  # Quote
            'user"name',  # Double quote
            "user<name>",  # Angle brackets
            "user?name",  # Question mark
            "",  # Empty
        ]

        for username in invalid_usernames:
            with pytest.raises(ValidationError):
                UserBase(username=username, email="test@example.com")

    def test_email_validation(self):
        """Test email validation."""
        # Valid emails
        valid_emails = [
            "test@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "test123@sub.example.com",
            "TEST@EXAMPLE.COM",
        ]

        for email in valid_emails:
            user = UserBase(username="testuser", email=email)
            # Pydantic v2 EmailStr only normalizes domain part to lowercase
            local, domain = email.split("@")
            expected_email = f"{local}@{domain.lower()}"
            assert user.email == expected_email

        # Invalid emails
        invalid_emails = [
            "notanemail",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@example",
            "user space@example.com",
            "user@exam ple.com",
            "",
        ]

        for email in invalid_emails:
            with pytest.raises(ValidationError):
                UserBase(username="testuser", email=email)

    def test_full_name_validation(self):
        """Test full name validation and sanitization."""
        # Valid names
        user = UserBase(username="testuser", email="test@example.com", full_name="John Doe")
        assert user.full_name == "John Doe"

        # Names with HTML tags should be cleaned
        user = UserBase(username="testuser", email="test@example.com", full_name="<b>John</b> <i>Doe</i>")
        assert user.full_name == "John Doe"

        # Names with script tags should fail
        with pytest.raises(ValidationError) as exc_info:
            UserBase(username="testuser", email="test@example.com", full_name="<script>alert('xss')</script>John")
        assert "Full name contains invalid content" in str(exc_info.value)

        # Names with javascript: should fail
        with pytest.raises(ValidationError) as exc_info:
            UserBase(username="testuser", email="test@example.com", full_name="javascript:alert('xss')")
        assert "Full name contains invalid content" in str(exc_info.value)

        # Names with onerror should fail
        with pytest.raises(ValidationError) as exc_info:
            UserBase(username="testuser", email="test@example.com", full_name='<img onerror="alert(1)" src=x>')
        assert "Full name contains invalid content" in str(exc_info.value)

        # Empty string after cleaning
        user = UserBase(username="testuser", email="test@example.com", full_name="<><><>")
        assert user.full_name is None

        # Whitespace handling
        user = UserBase(username="testuser", email="test@example.com", full_name="  John Doe  ")
        assert user.full_name == "John Doe"

        # None is valid
        user = UserBase(username="testuser", email="test@example.com", full_name=None)
        assert user.full_name is None

        # Max length
        long_name = "A" * 255
        user = UserBase(username="testuser", email="test@example.com", full_name=long_name)
        assert user.full_name == long_name

        # Too long
        with pytest.raises(ValidationError):
            UserBase(username="testuser", email="test@example.com", full_name="A" * 256)

    def test_boolean_fields(self):
        """Test boolean field handling."""
        # All True
        user = UserBase(
            username="testuser",
            email="test@example.com",
            is_active=True,
            is_superuser=True,
            email_verified=True,
            totp_enabled=True,
        )
        assert all([user.is_active, user.is_superuser, user.email_verified, user.totp_enabled])

        # All False
        user = UserBase(
            username="testuser",
            email="test@example.com",
            is_active=False,
            is_superuser=False,
            email_verified=False,
            totp_enabled=False,
        )
        assert not any([user.is_active, user.is_superuser, user.email_verified, user.totp_enabled])

    def test_user_base_dict_export(self):
        """Test exporting UserBase to dict."""
        user = UserBase(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_superuser=False,
            email_verified=True,
            totp_enabled=False,
        )

        data = user.model_dump()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"
        assert data["is_active"] is True
        assert data["is_superuser"] is False
        assert data["email_verified"] is True
        assert data["totp_enabled"] is False


class TestUserCreate:
    """Test UserCreate schema."""

    def test_user_create_valid(self):
        """Test creating valid UserCreate."""
        user = UserCreate(
            username="newuser",
            email="new@example.com",
            password="SecureP@ssw0rd!",
            full_name="New User",
            is_active=True,
            is_superuser=False,
        )

        assert user.username == "newuser"
        assert user.email == "new@example.com"
        assert user.password == "SecureP@ssw0rd!"
        assert user.full_name == "New User"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_user_create_minimal(self):
        """Test UserCreate with minimal fields."""
        user = UserCreate(username="minuser", email="min@example.com", password="MinP@ssw0rd!")

        assert user.username == "minuser"
        assert user.email == "min@example.com"
        assert user.password == "MinP@ssw0rd!"
        assert user.full_name is None
        assert user.is_active is True  # Default
        assert user.is_superuser is False  # Default

    def test_password_validation_strength(self):
        """Test password strength validation."""
        base_data = {"username": "testuser", "email": "test@example.com"}

        # Valid passwords
        valid_passwords = [
            "ValidP@ss1",  # Minimum requirements
            "Complex!P@ssw0rd123",  # Complex password
            "A" * 100 + "a1!",  # Long password
            "Aa1!Aa1!",  # Minimum length
            "MySecure123!Pass",  # Mixed position
            "P@ssw0rd" * 15,  # Maximum length (120 chars)
        ]

        for password in valid_passwords:
            user = UserCreate(**base_data, password=password)
            assert user.password == password

        # Invalid passwords
        invalid_passwords = [
            ("Short1!", "Password must be at least 8 characters long"),
            ("lowercase1!", "Password must contain at least one uppercase letter"),
            ("UPPERCASE1!", "Password must contain at least one lowercase letter"),
            ("NoNumbers!", "Password must contain at least one digit"),
            ("NoSpecial1", "Password must contain at least one special character"),
            ("", "Password must be at least 8 characters long"),
            ("A" * 129, "ensure this value has at most 128 characters"),
        ]

        for password, expected_error in invalid_passwords:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(**base_data, password=password)
            assert expected_error in str(exc_info.value)

    def test_password_special_characters(self):
        """Test various special characters in password."""
        base_data = {"username": "testuser", "email": "test@example.com"}

        special_chars = '!@#$%^&*(),.?":{}|<>'

        for char in special_chars:
            password = f"TestPass1{char}"
            user = UserCreate(**base_data, password=password)
            assert char in user.password

    def test_user_create_inherits_validation(self):
        """Test that UserCreate inherits UserBase validations."""
        # Username validation
        with pytest.raises(ValidationError):
            UserCreate(username="a", email="test@example.com", password="ValidP@ss1")  # Too short

        # Email validation
        with pytest.raises(ValidationError):
            UserCreate(username="validuser", email="invalid-email", password="ValidP@ss1")

        # Full name XSS validation
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(
                username="validuser",
                email="test@example.com",
                password="ValidP@ss1",
                full_name="<script>alert('xss')</script>",
            )
        assert "Full name contains invalid content" in str(exc_info.value)

    def test_user_create_full_name_sanitization(self):
        """Test full name sanitization in UserCreate."""
        user = UserCreate(
            username="testuser", email="test@example.com", password="ValidP@ss1", full_name="<p>Clean Name</p>"
        )
        assert user.full_name == "Clean Name"


class TestUserUpdate:
    """Test UserUpdate schema."""

    def test_user_update_all_fields(self):
        """Test updating all fields."""
        user = UserUpdate(
            email="updated@example.com",
            full_name="Updated Name",
            is_active=False,
            is_superuser=True,
            email_verified=True,
            totp_enabled=True,
        )

        assert user.email == "updated@example.com"
        assert user.full_name == "Updated Name"
        assert user.is_active is False
        assert user.is_superuser is True
        assert user.email_verified is True
        assert user.totp_enabled is True

    def test_user_update_partial(self):
        """Test partial updates with None values."""
        # Update only email
        user = UserUpdate(email="new@example.com")
        assert user.email == "new@example.com"
        assert user.full_name is None
        assert user.is_active is None
        assert user.is_superuser is None
        assert user.email_verified is None
        assert user.totp_enabled is None

        # Update only full_name
        user = UserUpdate(full_name="New Name")
        assert user.email is None
        assert user.full_name == "New Name"

        # Update only boolean fields
        user = UserUpdate(is_active=False, email_verified=True)
        assert user.is_active is False
        assert user.email_verified is True
        assert user.email is None
        assert user.full_name is None

    def test_user_update_empty(self):
        """Test empty update (all None)."""
        user = UserUpdate()
        assert user.email is None
        assert user.full_name is None
        assert user.is_active is None
        assert user.is_superuser is None
        assert user.email_verified is None
        assert user.totp_enabled is None

    def test_user_update_email_validation(self):
        """Test email validation in update."""
        # Valid email
        user = UserUpdate(email="valid@example.com")
        assert user.email == "valid@example.com"

        # Invalid email
        with pytest.raises(ValidationError):
            UserUpdate(email="invalid-email")

    def test_user_update_full_name_validation(self):
        """Test full name validation in update."""
        # Valid name
        user = UserUpdate(full_name="Valid Name")
        assert user.full_name == "Valid Name"

        # HTML cleaning
        user = UserUpdate(full_name="<em>Emphasized</em> Name")
        assert user.full_name == "Emphasized Name"

        # XSS prevention
        with pytest.raises(ValidationError) as exc_info:
            UserUpdate(full_name="javascript:void(0)")
        assert "Full name contains invalid content" in str(exc_info.value)

        # None is valid
        user = UserUpdate(full_name=None)
        assert user.full_name is None

        # Max length
        user = UserUpdate(full_name="A" * 255)
        assert len(user.full_name) == 255

        # Too long
        with pytest.raises(ValidationError):
            UserUpdate(full_name="A" * 256)

    def test_user_update_dict_exclude_none(self):
        """Test excluding None values when converting to dict."""
        user = UserUpdate(email="test@example.com", is_active=True)

        # Default behavior includes None values
        data = user.model_dump()
        assert "email" in data
        assert "is_active" in data
        assert "full_name" in data
        assert data["full_name"] is None

        # Exclude None values
        data = user.model_dump(exclude_none=True)
        assert data == {"email": "test@example.com", "is_active": True}
        assert "full_name" not in data


class TestUserUpdatePassword:
    """Test UserUpdatePassword schema."""

    def test_password_update_valid(self):
        """Test valid password update."""
        update = UserUpdatePassword(current_password="OldP@ssw0rd!", new_password="NewP@ssw0rd!")

        assert update.current_password == "OldP@ssw0rd!"
        assert update.new_password == "NewP@ssw0rd!"

    def test_password_update_same_passwords(self):
        """Test that same passwords are allowed (business logic should handle)."""
        # Schema allows same passwords, business logic should validate
        update = UserUpdatePassword(current_password="SameP@ssw0rd!", new_password="SameP@ssw0rd!")

        assert update.current_password == update.new_password

    def test_new_password_validation(self):
        """Test new password strength validation."""
        base_data = {"current_password": "OldP@ssw0rd!"}

        # Valid new passwords
        valid_passwords = [
            "NewP@ssw0rd!",
            "Str0ng!Password",
            "C0mplex!Pass123",
        ]

        for password in valid_passwords:
            update = UserUpdatePassword(**base_data, new_password=password)
            assert update.new_password == password

        # Invalid new passwords
        invalid_passwords = [
            ("weak", "Password must be at least 8 characters long"),
            ("weakpass", "Password must contain at least one uppercase letter"),
            ("WEAKPASS", "Password must contain at least one lowercase letter"),
            ("Weakpass", "Password must contain at least one digit"),
            ("Weakpass1", "Password must contain at least one special character"),
        ]

        for password, expected_error in invalid_passwords:
            with pytest.raises(ValidationError) as exc_info:
                UserUpdatePassword(**base_data, new_password=password)
            assert expected_error in str(exc_info.value)

    def test_current_password_no_validation(self):
        """Test that current password has no strength validation."""
        # Current password can be anything (already in system)
        update = UserUpdatePassword(current_password="weak", new_password="NewStr0ng!Pass")  # No validation on current

        assert update.current_password == "weak"
        assert update.new_password == "NewStr0ng!Pass"

    def test_password_update_required_fields(self):
        """Test that both fields are required."""
        # Missing current_password
        with pytest.raises(ValidationError):
            UserUpdatePassword(new_password="NewP@ssw0rd!")

        # Missing new_password
        with pytest.raises(ValidationError):
            UserUpdatePassword(current_password="OldP@ssw0rd!")

        # Both missing
        with pytest.raises(ValidationError):
            UserUpdatePassword()


class TestUserResponse:
    """Test UserResponse schema."""

    def test_user_response_complete(self):
        """Test complete user response."""
        now = datetime.now(timezone.utc)
        user = UserResponse(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_superuser=False,
            email_verified=True,
            totp_enabled=False,
            created_at=now,
            updated_at=now,
            last_login_at=now,
            last_login_ip="192.168.1.1",
            login_count=42,
            failed_login_count=3,
        )

        assert user.id == "550e8400-e29b-41d4-a716-446655440000"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.is_active is True
        assert user.is_superuser is False
        assert user.email_verified is True
        assert user.totp_enabled is False
        assert user.created_at == now
        assert user.updated_at == now
        assert user.last_login_at == now
        assert user.last_login_ip == "192.168.1.1"
        assert user.login_count == 42
        assert user.failed_login_count == 3

    def test_user_response_minimal(self):
        """Test user response with minimal fields."""
        now = datetime.now(timezone.utc)
        user = UserResponse(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="minuser",
            email="min@example.com",
            created_at=now,
            updated_at=now,
        )

        assert user.id == "550e8400-e29b-41d4-a716-446655440000"
        assert user.username == "minuser"
        assert user.email == "min@example.com"
        assert user.full_name is None
        assert user.is_active is True  # Default from UserBase
        assert user.is_superuser is False  # Default from UserBase
        assert user.email_verified is False  # Default from UserBase
        assert user.totp_enabled is False  # Default from UserBase
        assert user.created_at == now
        assert user.updated_at == now
        assert user.last_login_at is None
        assert user.last_login_ip is None
        assert user.login_count == 0  # Default
        assert user.failed_login_count == 0  # Default

    def test_user_response_from_orm(self):
        """Test UserResponse with from_attributes config."""

        # Simulate ORM object
        class MockUser:
            id = "123e4567-e89b-12d3-a456-426614174000"
            username = "ormuser"
            email = "orm@example.com"
            full_name = "ORM User"
            is_active = True
            is_superuser = False
            email_verified = True
            totp_enabled = True
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)
            last_login_at = None
            last_login_ip = None
            login_count = 0
            failed_login_count = 0

        # Should work with from_attributes=True
        user = UserResponse.model_validate(MockUser())
        assert user.id == "123e4567-e89b-12d3-a456-426614174000"
        assert user.username == "ormuser"
        assert user.email == "orm@example.com"

    def test_user_response_datetime_handling(self):
        """Test datetime field handling."""
        # ISO format strings
        user = UserResponse(
            id="test-id",
            username="testuser",
            email="test@example.com",
            created_at="2024-01-01T12:00:00Z",
            updated_at="2024-01-02T12:00:00Z",
            last_login_at="2024-01-03T12:00:00Z",
        )

        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
        assert isinstance(user.last_login_at, datetime)

        # Timezone aware datetimes
        tz_aware = datetime.now(timezone.utc)
        user = UserResponse(
            id="test-id", username="testuser", email="test@example.com", created_at=tz_aware, updated_at=tz_aware
        )

        assert user.created_at == tz_aware
        assert user.updated_at == tz_aware

    def test_user_response_validation_inherited(self):
        """Test that UserResponse inherits UserBase validations."""
        now = datetime.now(timezone.utc)

        # Invalid username
        with pytest.raises(ValidationError):
            UserResponse(
                id="test-id", username="a", email="test@example.com", created_at=now, updated_at=now  # Too short
            )

        # Invalid email
        with pytest.raises(ValidationError):
            UserResponse(id="test-id", username="testuser", email="invalid", created_at=now, updated_at=now)

    def test_user_response_counter_fields(self):
        """Test counter field validation."""
        now = datetime.now(timezone.utc)

        # Negative values should work (edge case)
        user = UserResponse(
            id="test-id",
            username="testuser",
            email="test@example.com",
            created_at=now,
            updated_at=now,
            login_count=-1,  # Edge case
            failed_login_count=-1,  # Edge case
        )

        assert user.login_count == -1
        assert user.failed_login_count == -1

        # Large values
        user = UserResponse(
            id="test-id",
            username="testuser",
            email="test@example.com",
            created_at=now,
            updated_at=now,
            login_count=999999,
            failed_login_count=999999,
        )

        assert user.login_count == 999999
        assert user.failed_login_count == 999999


class TestUserCreateResponse:
    """Test UserCreateResponse schema."""

    def test_user_create_response_default_message(self):
        """Test user create response with default message."""
        now = datetime.now(timezone.utc)
        response = UserCreateResponse(
            id="new-user-id", username="newuser", email="new@example.com", created_at=now, updated_at=now
        )

        assert response.message == "User created successfully"
        assert response.id == "new-user-id"
        assert response.username == "newuser"

    def test_user_create_response_custom_message(self):
        """Test user create response with custom message."""
        now = datetime.now(timezone.utc)
        response = UserCreateResponse(
            id="new-user-id",
            username="newuser",
            email="new@example.com",
            created_at=now,
            updated_at=now,
            message="Welcome! Please verify your email.",
        )

        assert response.message == "Welcome! Please verify your email."

    def test_user_create_response_inherits_user_response(self):
        """Test that UserCreateResponse inherits all UserResponse fields."""
        now = datetime.now(timezone.utc)
        response = UserCreateResponse(
            id="test-id",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_superuser=False,
            email_verified=False,
            totp_enabled=False,
            created_at=now,
            updated_at=now,
            last_login_at=None,
            last_login_ip=None,
            login_count=0,
            failed_login_count=0,
            message="Custom success message",
        )

        # Check inherited fields
        assert response.id == "test-id"
        assert response.username == "testuser"
        assert response.email == "test@example.com"
        assert response.full_name == "Test User"
        assert response.created_at == now

        # Check own field
        assert response.message == "Custom success message"


class TestUserListResponse:
    """Test UserListResponse schema."""

    def test_user_list_response_empty(self):
        """Test empty user list response."""
        response = UserListResponse(items=[], total=0, page=1, page_size=20, total_pages=0)

        assert response.items == []
        assert response.total == 0
        assert response.total_pages == 0

    def test_user_list_response_with_users(self):
        """Test user list response with users."""
        now = datetime.now(timezone.utc)
        users = [
            UserResponse(
                id=f"user-{i}", username=f"user{i}", email=f"user{i}@example.com", created_at=now, updated_at=now
            )
            for i in range(3)
        ]

        response = UserListResponse(items=users, total=10, page=1, page_size=3, total_pages=4)

        assert len(response.items) == 3
        assert response.items[0].username == "user0"
        assert response.items[2].username == "user2"
        assert response.total == 10
        assert response.page == 1
        assert response.page_size == 3
        assert response.total_pages == 4

    def test_user_list_response_pagination_inheritance(self):
        """Test that UserListResponse properly inherits PaginatedResponse."""
        now = datetime.now(timezone.utc)
        user = UserResponse(id="test-id", username="testuser", email="test@example.com", created_at=now, updated_at=now)

        # Test automatic total_pages calculation
        response = UserListResponse(
            items=[user], total=100, page=3, page_size=10, total_pages=None  # Should calculate to 10
        )

        assert response.total_pages == 10

    def test_user_list_response_type_validation(self):
        """Test that items must be UserResponse objects."""
        # Valid with UserResponse objects
        now = datetime.now(timezone.utc)
        user = UserResponse(id="test-id", username="testuser", email="test@example.com", created_at=now, updated_at=now)

        response = UserListResponse(items=[user], total=1, page=1, page_size=10, total_pages=1)

        assert response.items[0] == user

        # Invalid with plain dicts (should fail or convert)
        with pytest.raises(ValidationError):
            UserListResponse(items=[{"not": "a user"}], total=1, page=1, page_size=10, total_pages=1)


class TestUserSchemaEdgeCases:
    """Test edge cases and special scenarios."""

    def test_unicode_handling(self):
        """Test Unicode character handling in fields."""
        user = UserBase(username="testuser", email="test@example.com", full_name="José García 北京 🚀")
        assert user.full_name == "José García 北京 🚀"

    def test_email_normalization(self):
        """Test email normalization."""
        user = UserBase(username="testuser", email="TEST@EXAMPLE.COM")
        # Pydantic normalizes emails to lowercase
        assert user.email == "test@example.com"

    def test_field_aliasing(self):
        """Test that fields don't have aliases."""
        data = {"username": "testuser", "email": "test@example.com"}

        user = UserBase(**data)
        exported = user.model_dump()

        # Field names should match
        assert "username" in exported
        assert "email" in exported

    def test_extra_fields_forbidden(self):
        """Test that extra fields are not allowed."""
        with pytest.raises(ValidationError):
            UserBase(username="testuser", email="test@example.com", extra_field="not allowed")

    def test_json_serialization(self):
        """Test JSON serialization of schemas."""
        now = datetime.now(timezone.utc)
        user = UserResponse(id="test-id", username="testuser", email="test@example.com", created_at=now, updated_at=now)

        json_str = user.model_dump_json()
        assert "test-id" in json_str
        assert "testuser" in json_str
        assert "test@example.com" in json_str

    def test_schema_validation_error_details(self):
        """Test detailed validation error information."""
        try:
            UserCreate(
                username="a", email="invalid", password="weak"  # Too short  # Invalid format  # Multiple violations
            )
        except ValidationError as e:
            errors = e.errors()

            # Should have multiple errors
            assert len(errors) >= 3

            # Check error structure
            for error in errors:
                assert "loc" in error  # Field location
                assert "msg" in error  # Error message
                assert "type" in error  # Error type
