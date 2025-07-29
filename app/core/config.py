"""Enhanced configuration with validation and security."""

import os
import re
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class Settings(BaseSettings):  # type: ignore[misc]
    """Application settings with validation and secure defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Project Info
    PROJECT_NAME: str = "ViolentUTF API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DESCRIPTION: str = "Standalone AI red-teaming API service"

    # Environment
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = Field(default=False)

    # Security settings
    SECRET_KEY: SecretStr = Field(..., min_length=32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=5, le=1440)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=30)
    ALGORITHM: str = Field(default="HS256")
    BCRYPT_ROUNDS: int = Field(default=12, ge=10, le=15)

    # CORS settings
    ALLOWED_ORIGINS: List[str] = Field(default=[])
    ALLOWED_METHODS: List[str] = Field(default=["GET", "POST", "PUT", "DELETE"])
    ALLOWED_HEADERS: List[str] = Field(default=["*"])
    ALLOW_CREDENTIALS: bool = Field(default=True)

    # Security headers
    SECURE_COOKIES: bool = Field(default=True)
    CSRF_PROTECTION: bool = Field(default=True)
    REQUEST_SIGNING_ENABLED: bool = Field(default=True)
    HSTS_MAX_AGE: int = Field(default=31536000)  # 1 year
    CSP_POLICY: Optional[str] = Field(default="default-src 'self'")

    # Database settings
    DATABASE_URL: Optional[str] = Field(default=None)
    DATABASE_POOL_SIZE: int = Field(default=5, ge=1, le=20)
    DATABASE_MAX_OVERFLOW: int = Field(default=10, ge=0, le=20)

    # Redis settings
    REDIS_URL: Optional[str] = Field(default=None)
    CACHE_TTL: int = Field(default=300, ge=60, le=3600)

    # Performance settings
    WORKERS_PER_CORE: int = Field(default=1, ge=1, le=4)
    MAX_WORKERS: int = Field(default=10, ge=1, le=100)
    KEEPALIVE: int = Field(default=5, ge=0, le=300)

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=10, le=1000)

    # Request size limits
    MAX_REQUEST_SIZE: int = Field(default=10 * 1024 * 1024, description="Maximum request size in bytes (10MB)")
    MAX_UPLOAD_SIZE: int = Field(default=50 * 1024 * 1024, description="Maximum upload size in bytes (50MB)")
    MAX_REQUEST_LINE_SIZE: int = Field(default=8190, description="Maximum request line size")
    MAX_REQUEST_FIELD_SIZE: int = Field(default=8190, description="Maximum request header field size")

    # Logging
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    LOG_FORMAT: str = Field(default="json")
    ENABLE_ACCESS_LOGS: bool = Field(default=True)

    # Monitoring
    ENABLE_METRICS: bool = Field(default=True)
    METRICS_PORT: int = Field(default=9090, ge=1024, le=65535)

    # Request settings
    REQUEST_TIMEOUT: int = Field(default=60, ge=10, le=300)

    # Server settings
    SERVER_HOST: str = Field(default="127.0.0.1")  # Secure default: localhost only
    SERVER_PORT: int = Field(default=8000, ge=1024, le=65535)

    @field_validator("DATABASE_URL")  # type: ignore[misc]
    @classmethod
    def validate_database_url(cls: type["Settings"], v: Optional[str]) -> Optional[str]:
        """Validate database URL format."""
        if v and not v.startswith(("postgresql://", "postgresql+asyncpg://", "sqlite://", "sqlite+aiosqlite://")):
            raise ValueError("Invalid database URL. Must be PostgreSQL or SQLite.")
        return v

    @field_validator("REDIS_URL")  # type: ignore[misc]
    @classmethod
    def validate_redis_url(cls: type["Settings"], v: Optional[str]) -> Optional[str]:
        """Validate Redis URL format."""
        if v and not v.startswith(("redis://", "rediss://")):
            raise ValueError("Invalid Redis URL")
        return v

    @field_validator("ALLOWED_ORIGINS")  # type: ignore[misc]
    @classmethod
    def validate_origins(cls: type["Settings"], v: List[str]) -> List[str]:
        """Validate and set default origins based on environment."""
        if not v:
            return ["http://localhost:3000", "http://localhost:8000"]

        # Validate each origin URL
        validated_origins = []
        for origin in v:
            try:
                parsed = urlparse(origin)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"Invalid origin URL format: {origin}")
                    continue
                if parsed.scheme not in ["http", "https"]:
                    logger.warning(f"Invalid origin scheme: {origin}")
                    continue
                validated_origins.append(origin)
            except Exception as e:
                logger.warning(f"Failed to parse origin URL {origin}: {e}")
                continue

        return validated_origins

    @field_validator("SERVER_HOST")  # type: ignore[misc]
    @classmethod
    def validate_server_host(cls: type["Settings"], v: str) -> str:
        """Validate server host format."""
        # Allow IPv4, IPv6, localhost, and domain names
        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )

        if v == "localhost":
            return v

        # Allow 0.0.0.0 with explicit warning (controlled binding)
        if v == "0.0.0.0":  # nosec B104 - Intentional for configuration validation
            return v

        # Check various patterns
        if re.match(ipv4_pattern, v):
            return v
        if re.match(ipv6_pattern, v):  # type: ignore[unreachable]
            return v
        if re.match(domain_pattern, v):
            return v

        raise ValueError(f"Invalid server host format: {v}")

    def _validate_production_security(self: "Settings") -> None:
        """Validate production security settings."""
        if self.DEBUG:
            raise ValueError("DEBUG must be False in production")

        if not self.SECURE_COOKIES:
            logger.warning("SECURE_COOKIES should be True in production")

        if self.SERVER_HOST == "0.0.0.0":  # nosec B104
            logger.warning("Binding to 0.0.0.0 in production - ensure proper firewall")

    def _validate_secret_key_strength(self: "Settings") -> None:
        """Validate SECRET_KEY strength in production."""
        secret_key = self.SECRET_KEY.get_secret_value()
        if len(secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production")

        weak_patterns = [
            r"^(test|dev|development|local)",
            r"^(secret|password|key)",
            r"^[0-9]+$",
            r"^[a-z]+$",
            r"^[A-Z]+$",
        ]

        for pattern in weak_patterns:
            if re.match(pattern, secret_key, re.IGNORECASE):
                raise ValueError("SECRET_KEY appears to be weak - use a strong random key")

    def _validate_database_url(self: "Settings") -> None:
        """Validate database URL format."""
        if not self.DATABASE_URL:
            return

        try:
            parsed = urlparse(self.DATABASE_URL)
            if not parsed.scheme:
                raise ValueError("DATABASE_URL must be a valid URL")
            # SQLite URLs don't have netloc, so only check for other schemes
            if parsed.scheme.startswith("postgresql") and not parsed.netloc:
                raise ValueError("DATABASE_URL must be a valid URL")
        except Exception as e:
            raise ValueError(f"Invalid DATABASE_URL format: {e}")

    def _validate_redis_url(self: "Settings") -> None:
        """Validate Redis URL format."""
        if not self.REDIS_URL:
            return

        try:
            parsed = urlparse(self.REDIS_URL)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("REDIS_URL must be a valid URL")
        except Exception as e:
            raise ValueError(f"Invalid REDIS_URL format: {e}")

    @model_validator(mode="after")  # type: ignore[misc]
    def validate_production_settings(self: "Settings") -> "Settings":
        """Validate production-specific security requirements."""
        if self.is_production:
            self._validate_production_security()
            self._validate_secret_key_strength()

        self._validate_database_url()
        self._validate_redis_url()

        # Validate rate limiting
        if self.RATE_LIMIT_ENABLED and self.RATE_LIMIT_PER_MINUTE <= 0:
            raise ValueError("RATE_LIMIT_PER_MINUTE must be positive when rate limiting is enabled")

        return self

    @property
    def is_production(self: "Settings") -> bool:
        """Check if running in production."""
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self: "Settings") -> bool:
        """Check if running in development."""
        return self.ENVIRONMENT == "development"

    @property
    def database_url_safe(self: "Settings") -> Optional[str]:
        """Get database URL with password masked."""
        if not self.DATABASE_URL:
            return None

        try:
            parsed = urlparse(self.DATABASE_URL)
            if parsed.password:
                # Replace password with asterisks
                safe_url = self.DATABASE_URL.replace(f":{parsed.password}@", ":***@")
                return safe_url
            return self.DATABASE_URL
        except Exception:
            # Fallback to simple masking
            if "@" in self.DATABASE_URL:
                parts = self.DATABASE_URL.split("@")
                prefix = parts[0].split("//")[0] + "//***:***@"
                return prefix + parts[1]
            return self.DATABASE_URL

    @property
    def redis_url_safe(self: "Settings") -> Optional[str]:
        """Get Redis URL with password masked."""
        if not self.REDIS_URL:
            return None

        try:
            parsed = urlparse(self.REDIS_URL)
            if parsed.password:
                safe_url = self.REDIS_URL.replace(f":{parsed.password}@", ":***@")
                return safe_url
            return self.REDIS_URL
        except Exception:
            return self.REDIS_URL

    def get_database_config(self: "Settings") -> Dict[str, Any]:
        """Get database configuration dictionary."""
        return {
            "url": self.database_url_safe,
            "pool_size": self.DATABASE_POOL_SIZE,
            "max_overflow": self.DATABASE_MAX_OVERFLOW,
            "enabled": bool(self.DATABASE_URL),
        }

    def get_redis_config(self: "Settings") -> Dict[str, Any]:
        """Get Redis configuration dictionary."""
        return {"url": self.redis_url_safe, "ttl": self.CACHE_TTL, "enabled": bool(self.REDIS_URL)}

    def get_security_config(self: "Settings") -> Dict[str, Any]:
        """Get security configuration dictionary."""
        return {
            "environment": self.ENVIRONMENT,
            "debug": self.DEBUG,
            "secure_cookies": self.SECURE_COOKIES,
            "csrf_protection": self.CSRF_PROTECTION,
            "request_signing_enabled": self.REQUEST_SIGNING_ENABLED,
            "hsts_max_age": self.HSTS_MAX_AGE,
            "csp_policy": self.CSP_POLICY,
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
            "rate_limit_per_minute": self.RATE_LIMIT_PER_MINUTE,
            "access_token_expire_minutes": self.ACCESS_TOKEN_EXPIRE_MINUTES,
            "bcrypt_rounds": self.BCRYPT_ROUNDS,
        }

    def validate_configuration(self: "Settings") -> Dict[str, Any]:
        """
        Validate current configuration and return validation results.

        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []

        # Check for missing required settings
        if not self.SECRET_KEY.get_secret_value():
            issues.append("SECRET_KEY is required")

        # Security validations
        if self.is_production:
            if self.DEBUG:
                issues.append("DEBUG should be False in production")

            if not self.DATABASE_URL and not self.REDIS_URL:
                warnings.append("No database or cache configured - limited functionality")

            if self.LOG_LEVEL == "DEBUG":
                warnings.append("DEBUG logging in production may expose sensitive data")

        # Performance validations
        if self.DATABASE_POOL_SIZE > self.MAX_WORKERS:
            warnings.append("DATABASE_POOL_SIZE larger than MAX_WORKERS may be inefficient")

        # Check environment file
        env_file_exists = Path(".env").exists()
        if not env_file_exists and self.ENVIRONMENT == "production":
            warnings.append(".env file not found - ensure environment variables are set")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "environment": self.ENVIRONMENT,
            "debug": self.DEBUG,
            "database_configured": bool(self.DATABASE_URL),
            "cache_configured": bool(self.REDIS_URL),
            "env_file_exists": env_file_exists,
        }

    def generate_secret_key(self: "Settings") -> str:
        """Generate a secure random secret key."""
        return secrets.token_urlsafe(32)

    def to_dict(self: "Settings", mask_secrets: bool = True) -> Dict[str, Any]:
        """
        Convert settings to dictionary.

        Args:
            mask_secrets: Whether to mask secret values

        Returns:
            Dictionary representation of settings
        """
        result = {}

        for field_name, _field_info in self.model_fields.items():
            value = getattr(self, field_name)

            if isinstance(value, SecretStr):
                if mask_secrets:
                    result[field_name] = "***"
                else:
                    result[field_name] = value.get_secret_value()
            elif field_name in ["DATABASE_URL", "REDIS_URL"] and mask_secrets:
                if field_name == "DATABASE_URL":
                    result[field_name] = self.database_url_safe or ""
                elif field_name == "REDIS_URL":
                    result[field_name] = self.redis_url_safe or ""
            else:
                result[field_name] = value

        return result


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""

    pass


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance with error handling.

    Returns:
        Settings instance

    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        # Ensure SECRET_KEY exists before creating Settings
        if not os.getenv("SECRET_KEY"):
            os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(32))
        settings_instance = Settings()  # type: ignore[call-arg]

        # Validate configuration
        validation_result = settings_instance.validate_configuration()

        # Log configuration status
        logger.info(
            "Configuration loaded",
            environment=settings_instance.ENVIRONMENT,
            debug=settings_instance.DEBUG,
            database_configured=validation_result["database_configured"],
            cache_configured=validation_result["cache_configured"],
        )

        # Log warnings
        for warning in validation_result["warnings"]:
            logger.warning("Configuration warning", warning=warning)

        # Raise error for critical issues
        if validation_result["issues"]:
            error_msg = "Configuration validation failed: " + "; ".join(validation_result["issues"])
            logger.error("Configuration validation failed", issues=validation_result["issues"])
            raise ConfigurationError(error_msg)

        return settings_instance

    except Exception as e:
        if isinstance(e, ConfigurationError):
            raise
        logger.error("Failed to load configuration", error=str(e))
        raise ConfigurationError(f"Failed to load configuration: {e}")


def reload_settings() -> Settings:
    """
    Reload settings (clears cache).

    Returns:
        New settings instance
    """
    get_settings.cache_clear()
    return get_settings()


def validate_environment_file(env_file: str = ".env") -> Dict[str, Any]:
    """
    Validate environment file exists and has required variables.

    Args:
        env_file: Path to environment file

    Returns:
        Validation results
    """
    env_path = Path(env_file)

    if not env_path.exists():
        return {
            "exists": False,
            "error": f"Environment file {env_file} not found",
            "required_variables": ["SECRET_KEY"],
            "found_variables": [],
        }

    # Read environment file
    found_variables = []
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    var_name = line.split("=")[0]
                    found_variables.append(var_name)
    except Exception as e:
        return {
            "exists": True,
            "error": f"Failed to read environment file: {e}",
            "required_variables": ["SECRET_KEY"],
            "found_variables": [],
        }

    required_variables = ["SECRET_KEY"]
    missing_variables = [var for var in required_variables if var not in found_variables]

    return {
        "exists": True,
        "error": None,
        "required_variables": required_variables,
        "found_variables": found_variables,
        "missing_variables": missing_variables,
        "valid": len(missing_variables) == 0,
    }


# Global settings instance with error handling
try:
    settings = get_settings()
except ConfigurationError as e:
    logger.critical("Critical configuration error", error=str(e))
    # In production, you might want to exit here
    # For development, we'll create a minimal settings instance
    if os.getenv("ENVIRONMENT") == "production":
        raise
    else:
        logger.warning("Using fallback configuration for development")
        # Create minimal settings with generated secret key
        if not os.getenv("SECRET_KEY"):
            os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(32))
        settings = Settings()  # type: ignore[call-arg]
