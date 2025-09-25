"""Tests for audit_utils.config module."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from audit_utils.config import AuditConfig, DatabaseConfig, LoggingConfig


class TestAuditConfig:
    """Test cases for audit configuration utilities."""

    def test_audit_config_default_initialization(self):
        """Test AuditConfig initialization with default settings."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()

            assert config is not None
            assert config.settings == mock_settings

    def test_audit_config_with_custom_path(self):
        """Test AuditConfig initialization with custom config path."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            test_config = {
                "database": {"host": "localhost", "port": 5432, "database": "test_db"},
                "logging": {"level": "DEBUG", "format": "json"},
            }
            import json

            json.dump(test_config, f)
            config_path = Path(f.name)

        try:
            config = AuditConfig(config_path=config_path)
            assert config.config_path == config_path
            assert config.custom_config == test_config
        finally:
            config_path.unlink(missing_ok=True)

    def test_audit_config_invalid_path(self):
        """Test AuditConfig with invalid config path raises FileNotFoundError."""
        invalid_path = Path("/non/existent/config.json")

        with pytest.raises(FileNotFoundError):
            AuditConfig(config_path=invalid_path)

    def test_get_database_config_default(self):
        """Test getting default database configuration."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = "postgresql://user:pass@localhost/db"
            mock_settings.DATABASE_POOL_SIZE = 10
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            db_config = config.get_database_config()

            assert isinstance(db_config, DatabaseConfig)
            assert db_config.database_url == "postgresql://user:pass@localhost/db"
            assert db_config.pool_size == 10

    def test_get_database_config_custom_override(self):
        """Test database config with custom overrides."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            test_config = {"database": {"host": "custom-host", "port": 5433, "database": "custom_db", "pool_size": 20}}
            import json

            json.dump(test_config, f)
            config_path = Path(f.name)

        try:
            config = AuditConfig(config_path=config_path)
            db_config = config.get_database_config()

            assert db_config.host == "custom-host"
            assert db_config.port == 5433
            assert db_config.database == "custom_db"
            assert db_config.pool_size == 20
        finally:
            config_path.unlink(missing_ok=True)

    def test_get_logging_config_default(self):
        """Test getting default logging configuration."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.LOG_LEVEL = "INFO"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            log_config = config.get_logging_config()

            assert isinstance(log_config, LoggingConfig)
            assert log_config.level == "INFO"
            assert log_config.format in ["json", "text"]

    def test_get_logging_config_custom_override(self):
        """Test logging config with custom overrides."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            test_config = {
                "logging": {
                    "level": "DEBUG",
                    "format": "json",
                    "file_path": "/var/log/audit.log",
                    "max_file_size_mb": 100,
                }
            }
            import json

            json.dump(test_config, f)
            config_path = Path(f.name)

        try:
            config = AuditConfig(config_path=config_path)
            log_config = config.get_logging_config()

            assert log_config.level == "DEBUG"
            assert log_config.format == "json"
            assert log_config.file_path == Path("/var/log/audit.log")
            assert log_config.max_file_size_mb == 100
        finally:
            config_path.unlink(missing_ok=True)

    def test_validate_configuration_valid(self):
        """Test configuration validation with valid config."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = "postgresql://user:pass@localhost/db"
            mock_settings.LOG_LEVEL = "INFO"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            assert config.validate_configuration() is True

    def test_validate_configuration_invalid_database(self):
        """Test configuration validation with invalid database settings."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = ""  # Empty database URL
            mock_settings.LOG_LEVEL = "INFO"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            assert config.validate_configuration() is False

    def test_validate_configuration_invalid_log_level(self):
        """Test configuration validation with invalid log level."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = "postgresql://user:pass@localhost/db"
            mock_settings.LOG_LEVEL = "INVALID_LEVEL"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            assert config.validate_configuration() is False

    def test_configuration_caching(self):
        """Test that configuration is cached for performance."""
        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = "postgresql://test:test@localhost:5432/test"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()

            # First call
            db_config1 = config.get_database_config()

            # Second call should return cached result
            db_config2 = config.get_database_config()

            assert db_config1 is db_config2  # Same object instance

    def test_environment_variable_override(self):
        """Test that environment variables override configuration."""
        with patch.dict("os.environ", {"AUDIT_DATABASE_HOST": "env-host", "AUDIT_LOG_LEVEL": "DEBUG"}):
            config = AuditConfig()

            db_config = config.get_database_config()
            log_config = config.get_logging_config()

            assert db_config.host == "env-host"
            assert log_config.level == "DEBUG"

    def test_config_merge_priority(self):
        """Test configuration merge priority: env vars > custom config > defaults."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            test_config = {"database": {"host": "config-host", "port": 5433}, "logging": {"level": "WARNING"}}
            import json

            json.dump(test_config, f)
            config_path = Path(f.name)

        try:
            with patch.dict("os.environ", {"AUDIT_DATABASE_HOST": "env-host"}):
                with patch("audit_utils.config.get_settings") as mock_get_settings:
                    mock_settings = Mock()
                    mock_settings.database_url = "postgresql://default:pass@default/db"
                    mock_get_settings.return_value = mock_settings

                    config = AuditConfig(config_path=config_path)
                    db_config = config.get_database_config()
                    log_config = config.get_logging_config()

                    # Environment variable should take precedence
                    assert db_config.host == "env-host"
                    # Custom config should override default
                    assert db_config.port == 5433
                    assert log_config.level == "WARNING"
        finally:
            config_path.unlink(missing_ok=True)

    def test_database_config_properties(self):
        """Test DatabaseConfig properties and validation."""
        db_config = DatabaseConfig(
            database_url="postgresql://user:pass@localhost:5432/testdb", pool_size=15, timeout=30
        )

        assert db_config.host == "localhost"
        assert db_config.port == 5432
        assert db_config.database == "testdb"
        assert db_config.username == "user"
        assert db_config.pool_size == 15
        assert db_config.timeout == 30

    def test_database_config_invalid_url(self):
        """Test DatabaseConfig with invalid database URL."""
        with pytest.raises(ValueError, match="Invalid database URL"):
            DatabaseConfig(database_url="invalid-url")

    def test_logging_config_properties(self):
        """Test LoggingConfig properties and validation."""
        log_config = LoggingConfig(level="DEBUG", format="json", file_path="/var/log/audit.log", max_file_size_mb=50)

        assert log_config.level == "DEBUG"
        assert log_config.format == "json"
        assert log_config.file_path == Path("/var/log/audit.log")
        assert log_config.max_file_size_mb == 50

    def test_logging_config_invalid_level(self):
        """Test LoggingConfig with invalid log level."""
        with pytest.raises(ValueError, match="Invalid log level"):
            LoggingConfig(level="INVALID")

    def test_logging_config_invalid_format(self):
        """Test LoggingConfig with invalid format."""
        with pytest.raises(ValueError, match="Invalid log format"):
            LoggingConfig(format="invalid_format")

    def test_config_reload(self):
        """Test configuration reload functionality."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            initial_config = {"logging": {"level": "INFO"}}
            import json

            json.dump(initial_config, f)
            config_path = Path(f.name)

        try:
            config = AuditConfig(config_path=config_path)
            initial_log_config = config.get_logging_config()
            assert initial_log_config.level == "INFO"

            # Modify config file
            updated_config = {"logging": {"level": "DEBUG"}}
            with open(config_path, "w") as f:
                json.dump(updated_config, f)

            # Reload configuration
            config.reload_configuration()
            updated_log_config = config.get_logging_config()
            assert updated_log_config.level == "DEBUG"
        finally:
            config_path.unlink(missing_ok=True)

    def test_config_thread_safety(self):
        """Test that configuration access is thread-safe."""
        import threading
        import time

        with patch("audit_utils.config.get_settings") as mock_get_settings:
            mock_settings = Mock()
            mock_settings.DATABASE_URL = "postgresql://test:test@localhost:5432/test"
            mock_get_settings.return_value = mock_settings

            config = AuditConfig()
            results = []

            def get_config_multiple_times():
                for _ in range(10):
                    db_config = config.get_database_config()
                    results.append(db_config)
                    time.sleep(0.001)  # Small delay to encourage race conditions

            threads = [threading.Thread(target=get_config_multiple_times) for _ in range(5)]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            # All results should be the same instance (cached)
            assert len(set(id(result) for result in results)) == 1
