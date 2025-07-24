"""Enhanced configuration with validation and security."""

from functools import lru_cache
from typing import List, Optional, Union

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Logging
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    LOG_FORMAT: str = Field(default="json")
    ENABLE_ACCESS_LOGS: bool = Field(default=True)

    # Monitoring
    ENABLE_METRICS: bool = Field(default=True)
    METRICS_PORT: int = Field(default=9090, ge=1024, le=65535)

    # Request settings
    MAX_REQUEST_SIZE: int = Field(default=10 * 1024 * 1024, ge=1024)  # 10MB
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
        """Set default origins based on environment."""
        if not v:
            return ["http://localhost:3000", "http://localhost:8000"]
        return v

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
        # Simple masking - in production use proper URL parsing
        if "@" in self.DATABASE_URL:
            parts = self.DATABASE_URL.split("@")
            prefix = parts[0].split("//")[0] + "//***:***@"
            return prefix + parts[1]
        return self.DATABASE_URL


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()  # type: ignore[call-arg]
