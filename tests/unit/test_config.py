"""Test configuration module."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


class TestConfiguration:
    """Test configuration validation and loading."""

    def test_valid_configuration(self) -> None:
        """Test loading valid configuration."""
        settings = Settings(
            SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
            DATABASE_URL="postgresql://user:pass@localhost/db",  # pragma: allowlist secret
            REDIS_URL="redis://localhost:6379/0",
        )

        assert settings.SECRET_KEY.get_secret_value() == "test-secret-key-minimum-32-characters"
        assert settings.DATABASE_URL == "postgresql://user:pass@localhost/db"  # pragma: allowlist secret
        assert settings.REDIS_URL == "redis://localhost:6379/0"

    def test_invalid_database_url(self) -> None:
        """Test that invalid database URLs are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret  # pragma: allowlist secret
                DATABASE_URL="mysql://user:pass@localhost/db",  # MySQL not supported  # pragma: allowlist secret
            )

        assert "Invalid database URL" in str(exc_info.value)

    def test_invalid_redis_url(self) -> None:
        """Test that invalid Redis URLs are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
                REDIS_URL="memcached://localhost:11211",  # Not a Redis URL
            )

        assert "Invalid Redis URL" in str(exc_info.value)

    def test_missing_required_settings(self) -> None:
        """Test that missing required settings raise errors."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(_env_file=None)  # SECRET_KEY is required

        assert "SECRET_KEY" in str(exc_info.value)

    def test_secret_key_minimum_length(self) -> None:
        """Test that secret key has minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(SECRET_KEY="too-short", _env_file=None)  # pragma: allowlist secret

        assert "at least 32 items" in str(exc_info.value)

    def test_environment_validation(self) -> None:
        """Test environment field validation."""
        # Valid environments
        for env in ["development", "staging", "production"]:
            settings = Settings(
                SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
                ENVIRONMENT=env,
            )
            assert settings.ENVIRONMENT == env

        # Invalid environment
        with pytest.raises(ValidationError):
            Settings(
                SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
                ENVIRONMENT="invalid",
            )

    def test_default_values(self) -> None:
        """Test default configuration values."""
        settings = Settings(
            SECRET_KEY="test-secret-key-minimum-32-characters", _env_file=None  # pragma: allowlist secret
        )

        assert settings.PROJECT_NAME == "ViolentUTF API"
        assert settings.VERSION == "1.0.0"
        assert settings.API_V1_STR == "/api/v1"
        assert settings.ENVIRONMENT == "development"
        assert settings.DEBUG is False
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30
        assert settings.RATE_LIMIT_PER_MINUTE == 60

    def test_is_production_property(self) -> None:
        """Test is_production property."""
        dev_settings = Settings(
            SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
            ENVIRONMENT="development",
        )
        assert dev_settings.is_production is False
        assert dev_settings.is_development is True

        prod_settings = Settings(
            SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
            ENVIRONMENT="production",
        )
        assert prod_settings.is_production is True
        assert prod_settings.is_development is False

    def test_database_url_safe(self) -> None:
        """Test database URL masking."""
        settings = Settings(
            SECRET_KEY="test-secret-key-minimum-32-characters",  # pragma: allowlist secret
            DATABASE_URL="postgresql://user:password@localhost:5432/db",  # pragma: allowlist secret
        )

        safe_url = settings.database_url_safe
        assert "***:***" in safe_url
        assert "password" not in safe_url
        assert "localhost:5432/db" in safe_url
