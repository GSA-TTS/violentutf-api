"""Shared configuration management utilities for audit automation scripts."""

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import structlog

from app.core.config import get_settings
from audit_utils.file_operations import safe_read_json

logger = structlog.get_logger(__name__)


class DatabaseConfig:
    """Database configuration container."""

    def __init__(self, database_url: str, pool_size: int = 10, timeout: int = 30, **kwargs: Any):
        if not database_url or not database_url.strip():
            raise ValueError("Invalid database URL: URL cannot be empty")

        # Parse database URL
        try:
            parsed = urlparse(database_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid database URL format")
        except Exception as e:
            raise ValueError(f"Invalid database URL: {str(e)}") from e

        self.database_url = database_url
        self.pool_size = pool_size
        self.timeout = timeout

        # Extract components from URL
        self._parsed_url = parsed

    @property
    def host(self) -> str:
        """Get database host."""
        return self._parsed_url.hostname or "localhost"

    @property
    def port(self) -> int:
        """Get database port."""
        return self._parsed_url.port or 5432

    @property
    def database(self) -> str:
        """Get database name."""
        return self._parsed_url.path.lstrip("/") if self._parsed_url.path else ""

    @property
    def username(self) -> str:
        """Get database username."""
        return self._parsed_url.username or ""


class LoggingConfig:
    """Logging configuration container."""

    VALID_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    VALID_FORMATS = ["json", "text"]

    def __init__(
        self,
        level: str = "INFO",
        format: str = "json",
        file_path: Optional[str] = None,
        max_file_size_mb: int = 50,
        **kwargs: Any,
    ):
        level = level.upper()
        if level not in self.VALID_LEVELS:
            raise ValueError(f"Invalid log level: {level}. Must be one of {self.VALID_LEVELS}")

        if format not in self.VALID_FORMATS:
            raise ValueError(f"Invalid log format: {format}. Must be one of {self.VALID_FORMATS}")

        self.level = level
        self.format = format
        self.file_path = Path(file_path) if file_path else None
        self.max_file_size_mb = max_file_size_mb


class AuditConfig:
    """Centralized configuration management for audit utilities."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.settings = get_settings()
        self.custom_config: Dict[str, Any] = {}
        self._cache: Dict[str, Any] = {}
        self._cache_lock = threading.Lock()

        # Load custom configuration if path provided
        if config_path:
            self.load_configuration(config_path)

    def load_configuration(self, config_path: Path) -> None:
        """Load configuration from file.

        Args:
            config_path: Path to configuration file

        Raises:
            FileNotFoundError: If config file doesn't exist
        """
        self.custom_config = safe_read_json(config_path)
        self.config_path = config_path

        # Clear cache when configuration is reloaded
        with self._cache_lock:
            self._cache.clear()

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration with environment and custom overrides.

        Returns:
            DatabaseConfig instance
        """
        # Double-checked locking pattern for thread safety
        with self._cache_lock:
            if "database_config" in self._cache:
                return self._cache["database_config"]  # type: ignore

            # Create config under lock to prevent race conditions
            # Start with default settings
            config_dict = {
                "database_url": self.settings.DATABASE_URL,
                "pool_size": getattr(self.settings, "DATABASE_POOL_SIZE", 10),
                "timeout": 30,
            }

            # Apply custom config overrides
            if "database" in self.custom_config:
                db_config = self.custom_config["database"]

                # Handle individual components or full URL
                if "host" in db_config:
                    # Construct URL from components
                    host = db_config.get("host", "localhost")
                    port = db_config.get("port", 5432)
                    database = db_config.get("database", "")
                    username = db_config.get("username", "user")
                    password = db_config.get("password", "password")

                    config_dict["database_url"] = f"postgresql://{username}:{password}@{host}:{port}/{database}"

                config_dict.update(db_config)

            # Apply environment variable overrides
            if "AUDIT_DATABASE_HOST" in os.environ:
                # Parse existing URL and replace host
                parsed = urlparse(str(config_dict["database_url"]))
                new_netloc = f"{parsed.username}:{parsed.password}@{os.environ['AUDIT_DATABASE_HOST']}:{parsed.port}"
                config_dict["database_url"] = parsed._replace(netloc=new_netloc).geturl()

            db_config = DatabaseConfig(
                database_url=str(config_dict["database_url"]),
                pool_size=int(config_dict.get("pool_size", 10) or 10),
                timeout=int(config_dict.get("timeout", 30) or 30),
            )

            # Cache the result (still under lock)
            self._cache["database_config"] = db_config
            return db_config

    def get_logging_config(self) -> LoggingConfig:
        """Get logging configuration with environment and custom overrides.

        Returns:
            LoggingConfig instance
        """
        # Double-checked locking pattern for thread safety
        with self._cache_lock:
            if "logging_config" in self._cache:
                return self._cache["logging_config"]  # type: ignore

            # Create config under lock to prevent race conditions
            # Start with default settings
            config_dict = {"level": getattr(self.settings, "LOG_LEVEL", "INFO"), "format": "json"}

            # Apply custom config overrides
            if "logging" in self.custom_config:
                config_dict.update(self.custom_config["logging"])

            # Apply environment variable overrides
            if "AUDIT_LOG_LEVEL" in os.environ:
                config_dict["level"] = os.environ["AUDIT_LOG_LEVEL"]

            log_config = LoggingConfig(
                level=str(config_dict.get("level", "INFO")),
                format=str(config_dict.get("format", "json")),
                file_path=config_dict.get("file_path"),
                max_file_size_mb=int(config_dict.get("max_file_size_mb", 50)),
            )

            # Cache the result (still under lock)
            self._cache["logging_config"] = log_config
            return log_config

    def validate_configuration(self) -> bool:
        """Validate the current configuration.

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Validate database config
            db_config = self.get_database_config()
            if not db_config.database_url.strip():
                return False

            # Validate logging config
            log_config = self.get_logging_config()
            if log_config.level not in LoggingConfig.VALID_LEVELS:
                return False

            return True

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False

    def reload_configuration(self) -> None:
        """Reload configuration from file and clear cache."""
        if self.config_path:
            self.load_configuration(self.config_path)

        # Clear cache
        with self._cache_lock:
            self._cache.clear()
