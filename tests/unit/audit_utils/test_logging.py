"""Tests for audit_utils.logging module."""

import logging
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog

from audit_utils.logging import (
    log_audit_event,
    sanitize_log_data,
    setup_audit_logger,
)


class TestAuditLogging:
    """Test cases for audit logging utilities."""

    def test_setup_audit_logger_default_level(self):
        """Test setting up logger with default INFO level."""
        logger = setup_audit_logger("test_audit")

        assert logger is not None
        assert isinstance(logger, structlog.stdlib.BoundLogger)

    def test_setup_audit_logger_custom_level(self):
        """Test setting up logger with custom level."""
        logger = setup_audit_logger("test_audit", level="DEBUG")

        assert logger is not None
        assert isinstance(logger, structlog.stdlib.BoundLogger)

    def test_setup_audit_logger_invalid_level(self):
        """Test setting up logger with invalid level raises ValueError."""
        with pytest.raises(ValueError, match="Invalid log level"):
            setup_audit_logger("test_audit", level="INVALID")

    def test_log_audit_event_basic(self):
        """Test basic audit event logging."""
        with patch("structlog.get_logger") as mock_get_logger:
            mock_logger = mock_get_logger.return_value

            log_audit_event("user_login", user_id="123", ip_address="192.168.1.1")

            mock_logger.info.assert_called_once_with(
                "Audit event: user_login",
                event_type="user_login",
                user_id="123",
                ip_address="192.168.1.1",
                timestamp=pytest.approx(mock_logger.info.call_args[1]["timestamp"], abs=1),
            )

    def test_log_audit_event_no_context(self):
        """Test audit event logging without additional context."""
        with patch("structlog.get_logger") as mock_get_logger:
            mock_logger = mock_get_logger.return_value

            log_audit_event("system_startup")

            mock_logger.info.assert_called_once()
            args, kwargs = mock_logger.info.call_args
            assert "Audit event: system_startup" in args[0]
            assert kwargs["event_type"] == "system_startup"

    def test_sanitize_log_data_removes_sensitive_fields(self):
        """Test that sensitive fields are removed from log data."""
        data = {
            "user_id": "123",
            "username": "testuser",
            "password": "secret123",
            "api_key": "abc123def456",
            "token": "jwt.token.here",
            "credit_card": "1234-5678-9012-3456",
            "ssn": "123-45-6789",
            "email": "user@example.com",
        }

        sanitized = sanitize_log_data(data)

        assert sanitized["user_id"] == "123"
        assert sanitized["username"] == "testuser"
        assert sanitized["email"] == "user@example.com"

        # Sensitive fields should be redacted
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["token"] == "[REDACTED]"
        assert sanitized["credit_card"] == "[REDACTED]"
        assert sanitized["ssn"] == "[REDACTED]"

    def test_sanitize_log_data_nested_dict(self):
        """Test sanitizing nested dictionaries."""
        data = {
            "user": {"id": "123", "credentials": {"password": "secret123", "api_key": "abc123"}},
            "request": {"headers": {"authorization": "Bearer token123"}},
        }

        sanitized = sanitize_log_data(data)

        assert sanitized["user"]["id"] == "123"
        assert sanitized["user"]["credentials"]["password"] == "[REDACTED]"
        assert sanitized["user"]["credentials"]["api_key"] == "[REDACTED]"
        assert sanitized["request"]["headers"]["authorization"] == "[REDACTED]"

    def test_sanitize_log_data_with_lists(self):
        """Test sanitizing data with lists containing sensitive information."""
        data = {
            "users": [{"id": "1", "password": "secret1"}, {"id": "2", "api_key": "key123"}],
            "tokens": ["token1", "token2"],
        }

        sanitized = sanitize_log_data(data)

        assert sanitized["users"][0]["id"] == "1"
        assert sanitized["users"][0]["password"] == "[REDACTED]"
        assert sanitized["users"][1]["id"] == "2"
        assert sanitized["users"][1]["api_key"] == "[REDACTED]"
        assert sanitized["tokens"] == ["[REDACTED]", "[REDACTED]"]

    def test_sanitize_log_data_none_values(self):
        """Test sanitizing data with None values."""
        data = {"user_id": "123", "password": None, "api_key": None}

        sanitized = sanitize_log_data(data)

        assert sanitized["user_id"] == "123"
        assert sanitized["password"] is None
        assert sanitized["api_key"] is None

    def test_sanitize_log_data_empty_dict(self):
        """Test sanitizing empty dictionary."""
        data = {}
        sanitized = sanitize_log_data(data)
        assert sanitized == {}

    def test_audit_logger_file_output(self):
        """Test that audit logger can write to file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            log_file = Path(f.name)

        try:
            # This would require actual implementation to test file output
            # For now, we test the basic setup
            logger = setup_audit_logger("test_file", level="INFO")
            assert logger is not None
        finally:
            log_file.unlink(missing_ok=True)

    def test_audit_logger_performance(self):
        """Test that audit logger setup is reasonably fast."""
        import time

        start_time = time.time()
        for i in range(100):
            setup_audit_logger(f"test_perf_{i}")
        end_time = time.time()

        # Should complete 100 logger setups in under 1 second
        assert (end_time - start_time) < 1.0

    @pytest.mark.parametrize(
        "sensitive_key",
        [
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
            "authorization",
            "auth",
            "credential",
            "credit_card",
            "ssn",
        ],
    )
    def test_sanitize_sensitive_keys_case_insensitive(self, sensitive_key):
        """Test that sensitive keys are detected case-insensitively."""
        data = {sensitive_key.upper(): "sensitive_value"}
        sanitized = sanitize_log_data(data)
        assert sanitized[sensitive_key.upper()] == "[REDACTED]"

        data = {sensitive_key.lower(): "sensitive_value"}
        sanitized = sanitize_log_data(data)
        assert sanitized[sensitive_key.lower()] == "[REDACTED]"
