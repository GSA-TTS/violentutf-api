"""Test enhanced configuration system."""

import json
import os
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.core.config import ConfigurationError, Settings, get_settings, reload_settings, validate_environment_file


class SettingsForTesting(Settings):
    """Settings class that ignores .env file for testing."""

    model_config = Settings.model_config.copy()
    model_config.update({"env_file": None})


class TestSettingsValidation:
    """Test settings validation and creation."""

    def test_minimal_valid_settings(self) -> None:
        """Test creating settings with minimal valid configuration."""
        # Clear all environment variables and set only what we need
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.SECRET_KEY.get_secret_value() == strong_key
            assert settings.ENVIRONMENT == "development"
            assert settings.DEBUG is False

    def test_production_settings_validation(self) -> None:
        """Test production-specific validation."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key, "ENVIRONMENT": "production", "DEBUG": "false"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.is_production
            assert not settings.DEBUG

    def test_production_debug_error(self) -> None:
        """Test that DEBUG=True in production raises error."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key, "ENVIRONMENT": "production", "DEBUG": "true"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="DEBUG must be False in production"):
                SettingsForTesting()

    def test_weak_secret_key_error(self) -> None:
        """Test that weak secret keys are rejected in production."""
        weak_keys = [
            "test" + "a" * 28,  # Starts with 'test' (32 chars)
            "development" + "a" * 21,  # Starts with 'development' (32 chars)
            "secret" + "a" * 26,  # Starts with 'secret' (32 chars)
            "password" + "a" * 24,  # Starts with 'password' (32 chars)
            "12345678901234567890123456789012",  # Only numbers (32 chars)
            "abcdefghijklmnopqrstuvwxyzabcdef",  # Only lowercase (32 chars)
        ]

        for weak_key in weak_keys:
            clean_env = {"SECRET_KEY": weak_key, "ENVIRONMENT": "production"}
            with patch.dict(os.environ, clean_env, clear=True):
                with pytest.raises(ValidationError, match="SECRET_KEY appears to be weak"):
                    SettingsForTesting()

    def test_short_secret_key_error(self) -> None:
        """Test that short secret keys are rejected in production."""
        clean_env = {
            "SECRET_KEY": "short",  # pragma: allowlist secret
            "ENVIRONMENT": "production",
        }
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="at least 32 items"):
                SettingsForTesting()

    def test_invalid_environment(self) -> None:
        """Test invalid environment value."""
        clean_env = {"SECRET_KEY": "a" * 32, "ENVIRONMENT": "invalid"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError):
                SettingsForTesting()

    def test_invalid_database_url(self) -> None:
        """Test invalid database URL format."""
        clean_env = {"SECRET_KEY": "a" * 32, "DATABASE_URL": "invalid://url"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="Invalid database URL"):
                SettingsForTesting()

    def test_invalid_redis_url(self) -> None:
        """Test invalid Redis URL format."""
        clean_env = {"SECRET_KEY": "a" * 32, "REDIS_URL": "invalid://url"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="Invalid Redis URL"):
                SettingsForTesting()

    def test_invalid_server_host(self) -> None:
        """Test invalid server host format."""
        clean_env = {"SECRET_KEY": "a" * 32, "SERVER_HOST": "invalid host!"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="Invalid server host format"):
                SettingsForTesting()

    def test_valid_server_hosts(self) -> None:
        """Test valid server host formats."""
        valid_hosts = ["127.0.0.1", "0.0.0.0", "localhost", "example.com", "sub.domain.com"]  # nosec B104

        for host in valid_hosts:
            clean_env = {"SECRET_KEY": "a" * 32, "SERVER_HOST": host}
            with patch.dict(os.environ, clean_env, clear=True):
                settings = SettingsForTesting()
                assert settings.SERVER_HOST == host

    def test_rate_limiting_validation(self) -> None:
        """Test rate limiting validation."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key, "RATE_LIMIT_ENABLED": "true", "RATE_LIMIT_PER_MINUTE": "5"}
        with patch.dict(os.environ, clean_env, clear=True):
            with pytest.raises(ValidationError, match="greater than or equal to 10"):
                SettingsForTesting()


class TestSettingsProperties:
    """Test settings properties and methods."""

    def setup_method(self) -> None:
        """Set up test environment."""
        self.strong_key = secrets.token_urlsafe(32)
        self.env_vars = {
            "SECRET_KEY": self.strong_key,
            "DATABASE_URL": "postgresql://user:pass@localhost/db",  # pragma: allowlist secret
            "REDIS_URL": "redis://user:pass@localhost:6379/0",  # pragma: allowlist secret
        }

    def test_is_production_property(self) -> None:
        """Test is_production property."""
        clean_env = {**self.env_vars, "ENVIRONMENT": "production"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.is_production is True

        clean_env = {**self.env_vars, "ENVIRONMENT": "development"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.is_production is False

    def test_is_development_property(self) -> None:
        """Test is_development property."""
        clean_env = {**self.env_vars, "ENVIRONMENT": "development"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.is_development is True

        clean_env = {**self.env_vars, "ENVIRONMENT": "production"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.is_development is False

    def test_database_url_safe(self) -> None:
        """Test database URL password masking."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            safe_url = settings.database_url_safe
            assert "pass" not in safe_url
            assert "***" in safe_url
            assert "postgresql://" in safe_url
            assert "localhost/db" in safe_url

    def test_database_url_safe_no_password(self) -> None:
        """Test database URL without password."""
        clean_env = {**self.env_vars, "DATABASE_URL": "postgresql://localhost/db"}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert settings.database_url_safe == "postgresql://localhost/db"

    def test_database_url_safe_none(self) -> None:
        """Test database URL when None."""
        env_vars = {k: v for k, v in self.env_vars.items() if k != "DATABASE_URL"}
        with patch.dict(os.environ, env_vars, clear=True):
            settings = SettingsForTesting()
            assert settings.database_url_safe is None

    def test_redis_url_safe(self) -> None:
        """Test Redis URL password masking."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            safe_url = settings.redis_url_safe
            assert "pass" not in safe_url
            assert "***" in safe_url
            assert "redis://" in safe_url

    def test_get_database_config(self) -> None:
        """Test database configuration dictionary."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            config = settings.get_database_config()

            assert "url" in config
            assert "pool_size" in config
            assert "max_overflow" in config
            assert "enabled" in config
            assert config["enabled"] is True
            assert config["pool_size"] == settings.DATABASE_POOL_SIZE

    def test_get_redis_config(self) -> None:
        """Test Redis configuration dictionary."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            config = settings.get_redis_config()

            assert "url" in config
            assert "ttl" in config
            assert "enabled" in config
            assert config["enabled"] is True
            assert config["ttl"] == settings.CACHE_TTL

    def test_get_security_config(self) -> None:
        """Test security configuration dictionary."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            config = settings.get_security_config()

            required_keys = [
                "environment",
                "debug",
                "secure_cookies",
                "csrf_protection",
                "rate_limit_enabled",
                "access_token_expire_minutes",
            ]

            for key in required_keys:
                assert key in config

    def test_validate_configuration(self) -> None:
        """Test configuration validation method."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            result = settings.validate_configuration()

            assert "valid" in result
            assert "issues" in result
            assert "warnings" in result
            assert "environment" in result
            assert "database_configured" in result
            assert "cache_configured" in result

            assert result["valid"] is True
            assert result["database_configured"] is True
            assert result["cache_configured"] is True

    def test_validate_configuration_missing_secret(self) -> None:
        """Test validation with missing secret key."""
        clean_env = {"SECRET_KEY": ""}
        with patch.dict(os.environ, clean_env, clear=True):
            # This should fail during Settings creation, not validation
            with pytest.raises(ValidationError):
                SettingsForTesting()

    def test_generate_secret_key(self) -> None:
        """Test secret key generation."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()
            key = settings.generate_secret_key()

            assert isinstance(key, str)
            assert len(key) >= 32

            # Generate multiple keys to ensure they're different
            key2 = settings.generate_secret_key()
            assert key != key2

    def test_to_dict(self) -> None:
        """Test settings to dictionary conversion."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            settings = SettingsForTesting()

            # Test with masked secrets
            masked_dict = settings.to_dict(mask_secrets=True)
            assert masked_dict["SECRET_KEY"] == "***"
            assert "pass" not in masked_dict["DATABASE_URL"]

            # Test without masking
            unmasked_dict = settings.to_dict(mask_secrets=False)
            assert unmasked_dict["SECRET_KEY"] == self.strong_key
            assert "pass" in unmasked_dict["DATABASE_URL"]


class TestAllowedOrigins:
    """Test ALLOWED_ORIGINS validation."""

    def test_default_origins(self) -> None:
        """Test default origins are set."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            assert "http://localhost:3000" in settings.ALLOWED_ORIGINS
            assert "http://localhost:8000" in settings.ALLOWED_ORIGINS

    def test_valid_origins(self) -> None:
        """Test valid origin URLs."""
        valid_origins = ["http://example.com", "https://secure.example.com", "http://localhost:3000"]

        origins_json = json.dumps(valid_origins)
        clean_env = {"SECRET_KEY": "a" * 32, "ALLOWED_ORIGINS": origins_json}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()
            for origin in valid_origins:
                assert origin in settings.ALLOWED_ORIGINS

    def test_invalid_origins_filtered(self) -> None:
        """Test that invalid origins are filtered out."""
        mixed_origins = ["http://valid.com", "invalid-url", "ftp://not-allowed.com", "https://also-valid.com"]

        origins_json = json.dumps(mixed_origins)
        clean_env = {"SECRET_KEY": "a" * 32, "ALLOWED_ORIGINS": origins_json}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = SettingsForTesting()

            # Use exact URL matching to prevent URL substring vulnerabilities
            expected_valid_origins = {"http://valid.com", "https://also-valid.com"}
            expected_invalid_origins = {"invalid-url", "ftp://not-allowed.com"}

            # Convert to sets for exact matching
            actual_origins = set(settings.ALLOWED_ORIGINS)

            # Check that valid origins are present
            assert expected_valid_origins.issubset(actual_origins)
            # Check that invalid origins are not present
            assert not expected_invalid_origins.intersection(actual_origins)


class TestGetSettings:
    """Test get_settings function and caching."""

    def test_get_settings_returns_instance(self) -> None:
        """Test that get_settings returns a Settings instance."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key}
        with patch.dict(os.environ, clean_env, clear=True):
            settings = get_settings()
            assert isinstance(settings, Settings)

    def test_get_settings_caching(self) -> None:
        """Test that get_settings caches the instance."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key}
        with patch.dict(os.environ, clean_env, clear=True):
            settings1 = get_settings()
            settings2 = get_settings()
            assert settings1 is settings2  # Same instance

    def test_reload_settings(self) -> None:
        """Test reload_settings clears cache."""
        strong_key = secrets.token_urlsafe(32)
        clean_env = {"SECRET_KEY": strong_key}
        with patch.dict(os.environ, clean_env, clear=True):
            settings1 = get_settings()
            settings2 = reload_settings()
            # After reload, should be different instances
            assert settings1 is not settings2

    def test_get_settings_with_invalid_config(self) -> None:
        """Test get_settings with invalid configuration."""
        clean_env = {"SECRET_KEY": "short", "ENVIRONMENT": "production"}  # pragma: allowlist secret
        with patch.dict(os.environ, clean_env, clear=True):
            # Clear cache first to ensure fresh settings
            get_settings.cache_clear()
            with pytest.raises(ConfigurationError):
                get_settings()


class TestEnvironmentFileValidation:
    """Test environment file validation."""

    def test_missing_env_file(self) -> None:
        """Test validation when env file doesn't exist."""
        result = validate_environment_file("nonexistent.env")
        assert result["exists"] is False
        assert "not found" in result["error"]
        assert result["required_variables"] == ["SECRET_KEY"]

    def test_valid_env_file(self) -> None:
        """Test validation with valid env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("SECRET_KEY=test_secret_key\n")
            f.write("DATABASE_URL=postgresql://localhost/test\n")
            f.write("# This is a comment\n")
            f.write("REDIS_URL=redis://localhost\n")
            env_file = f.name

        try:
            result = validate_environment_file(env_file)
            assert result["exists"] is True
            assert result["error"] is None
            assert "SECRET_KEY" in result["found_variables"]
            assert "DATABASE_URL" in result["found_variables"]
            assert "REDIS_URL" in result["found_variables"]
            assert result["valid"] is True
            assert len(result["missing_variables"]) == 0
        finally:
            Path(env_file).unlink()

    def test_env_file_missing_required_vars(self) -> None:
        """Test validation when required variables are missing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("DATABASE_URL=postgresql://localhost/test\n")
            f.write("SOME_OTHER_VAR=value\n")
            env_file = f.name

        try:
            result = validate_environment_file(env_file)
            assert result["exists"] is True
            assert result["error"] is None
            assert "SECRET_KEY" not in result["found_variables"]
            assert "SECRET_KEY" in result["missing_variables"]
            assert result["valid"] is False
        finally:
            Path(env_file).unlink()

    def test_unreadable_env_file(self) -> None:
        """Test validation when env file can't be read."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            env_file = f.name

        try:
            # Make file unreadable
            os.chmod(env_file, 0o000)
            result = validate_environment_file(env_file)
            assert result["exists"] is True
            assert "Failed to read" in result["error"]
        finally:
            # Restore permissions and cleanup
            os.chmod(env_file, 0o644)
            Path(env_file).unlink()


class TestConfigurationIntegration:
    """Test configuration system integration."""

    def test_production_configuration(self) -> None:
        """Test complete production configuration."""
        production_env = {
            "SECRET_KEY": "super-secure-secret-key-32-chars-long-12345",  # pragma: allowlist secret
            "ENVIRONMENT": "production",
            "DEBUG": "false",
            "DATABASE_URL": "postgresql://user:pass@prod-db:5432/app",  # pragma: allowlist secret
            "REDIS_URL": "redis://user:pass@prod-redis:6379/0",  # pragma: allowlist secret
            "ALLOWED_ORIGINS": '["https://app.example.com","https://admin.example.com"]',
            "SECURE_COOKIES": "true",
            "RATE_LIMIT_ENABLED": "true",
            "LOG_LEVEL": "INFO",
        }

        with patch.dict(os.environ, production_env, clear=True):
            settings = SettingsForTesting()

            assert settings.is_production
            assert not settings.DEBUG
            assert settings.SECURE_COOKIES
            assert settings.RATE_LIMIT_ENABLED
            assert settings.LOG_LEVEL == "INFO"

            # Validate configuration
            validation = settings.validate_configuration()
            assert validation["valid"]

    def test_development_configuration(self) -> None:
        """Test development configuration."""
        dev_env = {
            "SECRET_KEY": "development-secret-key-32-chars-long",  # pragma: allowlist secret
            "ENVIRONMENT": "development",
            "DEBUG": "true",
            "LOG_LEVEL": "DEBUG",
        }

        with patch.dict(os.environ, dev_env, clear=True):
            settings = SettingsForTesting()

            assert settings.is_development
            assert settings.DEBUG
            assert settings.LOG_LEVEL == "DEBUG"

            # Should still be valid even with DEBUG in development
            validation = settings.validate_configuration()
            assert validation["valid"]

    def test_configuration_warnings(self) -> None:
        """Test configuration validation warnings."""
        # Production config with potential issues
        production_env = {
            "SECRET_KEY": "super-secure-secret-key-32-chars-long-12345",  # pragma: allowlist secret
            "ENVIRONMENT": "production",
            "DEBUG": "false",
            "LOG_LEVEL": "DEBUG",  # This should generate a warning
            "DATABASE_POOL_SIZE": "15",
            "MAX_WORKERS": "10",  # Pool size > workers should warn
        }

        with patch.dict(os.environ, production_env, clear=True):
            settings = SettingsForTesting()
            validation = settings.validate_configuration()

            # Should be valid but have warnings
            assert validation["valid"]
            assert len(validation["warnings"]) > 0

            # Check specific warnings
            warning_text = " ".join(validation["warnings"])
            assert "DEBUG logging" in warning_text or "DATABASE_POOL_SIZE" in warning_text
