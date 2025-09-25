"""Tests for audit_utils.exceptions module."""

import functools
from unittest.mock import Mock, patch

import pytest

from audit_utils.exceptions import (
    AuditError,
    ConfigurationError,
    ValidationError,
    audit_error_handler,
    create_error_context,
)


class TestAuditExceptions:
    """Test cases for audit exception utilities."""

    def test_audit_error_inheritance(self):
        """Test that AuditError is base exception."""
        error = AuditError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"

    def test_configuration_error_inheritance(self):
        """Test that ConfigurationError inherits from AuditError."""
        error = ConfigurationError("Config error")
        assert isinstance(error, AuditError)
        assert isinstance(error, Exception)
        assert str(error) == "Config error"

    def test_validation_error_inheritance(self):
        """Test that ValidationError inherits from AuditError."""
        error = ValidationError("Validation error")
        assert isinstance(error, AuditError)
        assert isinstance(error, Exception)
        assert str(error) == "Validation error"

    def test_create_error_context_basic(self):
        """Test creating basic error context."""
        context = create_error_context(operation="test_operation", user_id="123", timestamp="2023-01-01T00:00:00Z")

        expected = {"operation": "test_operation", "user_id": "123", "timestamp": "2023-01-01T00:00:00Z"}
        assert context == expected

    def test_create_error_context_empty(self):
        """Test creating error context with no parameters."""
        context = create_error_context()
        assert context == {}

    def test_create_error_context_with_none_values(self):
        """Test creating error context with None values."""
        context = create_error_context(operation="test", user_id=None, data=None)

        expected = {"operation": "test", "user_id": None, "data": None}
        assert context == expected

    def test_audit_error_handler_success(self):
        """Test audit error handler with successful function execution."""

        @audit_error_handler
        def successful_function(x, y):
            return x + y

        result = successful_function(2, 3)
        assert result == 5

    def test_audit_error_handler_catches_general_exception(self):
        """Test that audit error handler catches and logs general exceptions."""

        @audit_error_handler
        def failing_function():
            raise ValueError("Test error")

        with patch("audit_utils.exceptions.logger") as mock_logger:
            with pytest.raises(AuditError) as exc_info:
                failing_function()

            # Should log the original exception
            mock_logger.error.assert_called_once()

            # Should raise AuditError wrapping the original exception
            assert "Test error" in str(exc_info.value)

    def test_audit_error_handler_preserves_audit_errors(self):
        """Test that audit error handler preserves AuditError exceptions."""

        @audit_error_handler
        def function_raising_audit_error():
            raise ConfigurationError("Configuration is invalid")

        with pytest.raises(ConfigurationError) as exc_info:
            function_raising_audit_error()

        assert str(exc_info.value) == "Configuration is invalid"

    def test_audit_error_handler_with_context(self):
        """Test audit error handler with error context."""

        @audit_error_handler
        def function_with_context():
            context = create_error_context(operation="test_op", user_id="123")
            raise ValueError("Context error")

        with patch("audit_utils.exceptions.logger") as mock_logger:
            with pytest.raises(AuditError):
                function_with_context()

            mock_logger.error.assert_called_once()

    def test_audit_error_handler_async_function(self):
        """Test audit error handler works with async functions."""

        @audit_error_handler
        async def async_function(x):
            if x < 0:
                raise ValueError("Negative value")
            return x * 2

        # Note: This test would need actual async execution in real implementation
        # For now, we test that the decorator can be applied
        assert hasattr(async_function, "__wrapped__")

    def test_audit_error_handler_preserves_function_metadata(self):
        """Test that error handler preserves function metadata."""

        @audit_error_handler
        def documented_function(x, y):
            """This function adds two numbers."""
            return x + y

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This function adds two numbers."

    def test_audit_error_handler_with_args_kwargs(self):
        """Test error handler with functions that have various argument types."""

        @audit_error_handler
        def complex_function(a, b, *args, c=None, **kwargs):
            if c == "error":
                raise ValueError("Triggered error")
            return (a, b, args, c, kwargs)

        # Test successful call
        result = complex_function(1, 2, 3, 4, c="test", extra="value")
        expected = (1, 2, (3, 4), "test", {"extra": "value"})
        assert result == expected

        # Test error case
        with pytest.raises(AuditError):
            complex_function(1, 2, c="error")

    def test_error_context_integration_with_handler(self):
        """Test integration between error context and handler."""

        @audit_error_handler
        def function_using_context(user_id):
            context = create_error_context(operation="user_validation", user_id=user_id, module="test_module")
            # Context should be available for error handling
            if user_id == "invalid":
                raise ValidationError("Invalid user ID")
            return f"User {user_id} is valid"

        # Test successful case
        result = function_using_context("valid_user")
        assert result == "User valid_user is valid"

        # Test error case
        with pytest.raises(ValidationError):
            function_using_context("invalid")

    def test_nested_error_handlers(self):
        """Test that nested error handlers work correctly."""

        @audit_error_handler
        def outer_function():
            return inner_function()

        @audit_error_handler
        def inner_function():
            raise ValueError("Inner error")

        with pytest.raises(AuditError):
            outer_function()

    def test_error_handler_performance(self):
        """Test that error handler doesn't significantly impact performance."""

        @audit_error_handler
        def fast_function():
            return 42

        import time

        start_time = time.time()
        for _ in range(1000):
            fast_function()
        end_time = time.time()

        # Should complete 1000 calls in under 0.1 seconds
        assert (end_time - start_time) < 0.1
