"""Test security utilities."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    hash_password,
    validate_password_strength,
    verify_password,
)


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password(self) -> None:
        """Test password hashing."""
        password = "SecurePassword123!"  # pragma: allowlist secret
        hashed = hash_password(password)

        assert hashed != password
        assert hashed.startswith("$argon2")  # Argon2 hash prefix

    def test_verify_password_correct(self) -> None:
        """Test verifying correct password."""
        password = "SecurePassword123!"  # pragma: allowlist secret
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self) -> None:
        """Test verifying incorrect password."""
        password = "SecurePassword123!"  # pragma: allowlist secret
        hashed = hash_password(password)

        assert verify_password("WrongPassword", hashed) is False

    def test_hash_uniqueness(self) -> None:
        """Test that same password produces different hashes."""
        password = "SecurePassword123!"  # pragma: allowlist secret
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2  # Salt ensures uniqueness
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestJWTTokens:
    """Test JWT token creation and validation."""

    def test_create_access_token(self) -> None:
        """Test access token creation."""
        data = {"sub": "user123", "roles": ["user"]}
        token = create_access_token(data)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_refresh_token(self) -> None:
        """Test refresh token creation."""
        data = {"sub": "user123"}
        token = create_refresh_token(data)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_valid_token(self) -> None:
        """Test decoding valid token."""
        data = {"sub": "user123", "custom": "value"}
        token = create_access_token(data)

        decoded = decode_token(token)
        assert decoded["sub"] == "user123"
        assert decoded["custom"] == "value"
        assert decoded["type"] == "access"
        assert "exp" in decoded

    def test_decode_expired_token(self) -> None:
        """Test decoding expired token."""
        data = {"sub": "user123"}
        # Create token that expires immediately
        token = create_access_token(data, expires_delta=timedelta(seconds=-1))

        with pytest.raises(ValueError, match="Token has expired"):
            decode_token(token)

    def test_decode_invalid_token(self) -> None:
        """Test decoding invalid token."""
        with pytest.raises(ValueError, match="Could not validate credentials"):
            decode_token("invalid.token.here")

    def test_token_expiration(self) -> None:
        """Test token expiration times."""
        data = {"sub": "user123"}

        # Access token with custom expiration
        access_token = create_access_token(data, expires_delta=timedelta(minutes=15))
        decoded_access = decode_token(access_token)

        # Refresh token
        refresh_token = create_refresh_token(data)
        decoded_refresh = decode_token(refresh_token)

        # Check token types
        assert decoded_access["type"] == "access"
        assert decoded_refresh["type"] == "refresh"

        # Check expiration times are different
        assert decoded_access["exp"] < decoded_refresh["exp"]


class TestPasswordValidation:
    """Test password strength validation."""

    def test_strong_password(self) -> None:
        """Test validation of strong password."""
        valid, message = validate_password_strength("SecurePass123!")
        assert valid is True
        assert message == "Password is strong"

    def test_password_too_short(self) -> None:
        """Test password length validation."""
        valid, message = validate_password_strength("Short1!")
        assert valid is False
        assert "at least 8 characters" in message

    def test_password_no_uppercase(self) -> None:
        """Test uppercase requirement."""
        valid, message = validate_password_strength("securepass123!")
        assert valid is False
        assert "uppercase letter" in message

    def test_password_no_lowercase(self) -> None:
        """Test lowercase requirement."""
        valid, message = validate_password_strength("SECUREPASS123!")
        assert valid is False
        assert "lowercase letter" in message

    def test_password_no_digit(self) -> None:
        """Test digit requirement."""
        valid, message = validate_password_strength("SecurePass!")
        assert valid is False
        assert "digit" in message

    def test_password_no_special(self) -> None:
        """Test special character requirement."""
        valid, message = validate_password_strength("SecurePass123")
        assert valid is False
        assert "special character" in message


class TestAPIKey:
    """Test API key generation."""

    def test_generate_api_key_default_length(self) -> None:
        """Test API key generation with default length."""
        key = generate_api_key()
        assert len(key) == 32
        assert key.isalnum()  # Only letters and numbers

    def test_generate_api_key_custom_length(self) -> None:
        """Test API key generation with custom length."""
        key = generate_api_key(length=64)
        assert len(key) == 64
        assert key.isalnum()

    def test_api_key_uniqueness(self) -> None:
        """Test that generated keys are unique."""
        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) == 100  # All unique
