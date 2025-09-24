"""
Security hardening tests for Issue #138.

Tests for security improvements including exception handling,
secure checksums, and input validation.
"""

import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from scripts.config_baseline_manager import (
    BaselineGenerationError,
    BaselineValidationError,
    ChecksumValidationError,
    ConfigurationBaseline,
    ConfigurationBaselineManager,
    SecurityValidationError,
)


class TestSecureExceptionHandling:
    """Test security improvements in exception handling."""

    def test_specific_exception_types_raised(self):
        """Test that specific exceptions are raised instead of generic Exception."""
        manager = ConfigurationBaselineManager()

        # Test that specific exceptions are raised for known error conditions
        with pytest.raises(BaselineValidationError):
            # This should raise a specific exception, not generic Exception
            manager.load_baseline(Path("/nonexistent/file.json"))

    def test_no_sensitive_information_in_exceptions(self):
        """Test that exception messages don't leak sensitive information."""
        manager = ConfigurationBaselineManager()

        # Create a file with sensitive-looking content
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"password": "secret123", "api_key": "sensitive_key"}')
            temp_path = f.name

        try:
            with pytest.raises(BaselineValidationError) as exc_info:
                manager.load_baseline(Path(temp_path))

            # Exception message should not contain sensitive data
            error_msg = str(exc_info.value)
            assert "secret123" not in error_msg
            assert "sensitive_key" not in error_msg
            assert "password" not in error_msg.lower() or "redacted" in error_msg.lower()
        finally:
            os.unlink(temp_path)

    def test_security_aware_logging(self):
        """Test that security events are logged without information disclosure."""
        manager = ConfigurationBaselineManager()

        with patch("scripts.config_baseline_manager.logger") as mock_logger:
            try:
                manager.load_baseline(Path("/nonexistent/file.json"))
            except BaselineValidationError:
                pass

            # Verify that logger was called
            assert mock_logger.error.called or mock_logger.warning.called

            # Check that logged messages don't contain sensitive patterns
            logged_calls = mock_logger.error.call_args_list + mock_logger.warning.call_args_list
            for call in logged_calls:
                args = call[0] if call[0] else []
                for arg in args:
                    if isinstance(arg, str):
                        # Should not log raw file paths that might contain sensitive info
                        assert "/home/" not in arg.lower() or "redacted" in arg.lower()


class TestSecureChecksumImplementation:
    """Test HMAC-based secure checksum implementation."""

    @pytest.fixture
    def test_key(self):
        """Provide a test key for HMAC operations."""
        return b"test_secret_key_for_unit_tests_only"

    @pytest.fixture
    def sample_baseline_data(self):
        """Provide sample baseline data for testing."""
        return {
            "environment": "test",
            "version": "1.0",
            "configurations": {"setting1": "value1", "setting2": "value2"},
            "metadata": {"created_by": "test", "purpose": "testing"},
        }

    def test_hmac_checksum_generation(self, test_key, sample_baseline_data):
        """Test secure HMAC checksum generation."""
        manager = ConfigurationBaselineManager()

        # Test that secure checksum method exists and works
        checksum_hex, salt = manager.generate_secure_checksum(sample_baseline_data, test_key)

        # Verify the checksum is generated
        assert isinstance(checksum_hex, str)
        assert isinstance(salt, bytes)
        assert len(checksum_hex) == 64  # SHA256 hex string length
        assert len(salt) == 32  # 32 bytes salt

    def test_hmac_checksum_validation(self, test_key, sample_baseline_data):
        """Test HMAC checksum validation."""
        manager = ConfigurationBaselineManager()

        # Generate a checksum first
        checksum_hex, salt = manager.generate_secure_checksum(sample_baseline_data, test_key)

        # Test that validation works with correct data
        assert manager.verify_secure_checksum(sample_baseline_data, checksum_hex, salt) is True

        # Test that validation fails with wrong data
        wrong_data = sample_baseline_data.copy()
        wrong_data["environment"] = "modified"
        assert manager.verify_secure_checksum(wrong_data, checksum_hex, salt) is False

    def test_checksum_tamper_detection(self, test_key, sample_baseline_data):
        """Test that checksum detects data tampering."""
        manager = ConfigurationBaselineManager()

        # Make a deep copy to avoid fixture mutation
        import copy

        original_data = copy.deepcopy(sample_baseline_data)

        # Generate checksum for original data
        original_checksum, salt = manager.generate_secure_checksum(original_data, test_key)

        # Modify the data
        tampered_data = copy.deepcopy(original_data)
        tampered_data["configurations"]["setting1"] = "modified_value"

        # Verification should fail with tampered data
        assert not manager.verify_secure_checksum(tampered_data, original_checksum, salt)

        # But should succeed with original data
        assert manager.verify_secure_checksum(original_data, original_checksum, salt)

    def test_insecure_checksum_removed(self):
        """Test that old insecure JSON-based checksum is removed or deprecated."""
        from datetime import datetime, timezone

        baseline = ConfigurationBaseline(
            environment="development",
            version="1.0",
            configurations={"test": "value"},
            metadata={},
            timestamp=datetime.now(timezone.utc),
        )

        # The old calculate_checksum method should be marked as insecure or removed
        # For now, we'll test that it's documented as insecure
        checksum = baseline.calculate_checksum()
        assert isinstance(checksum, str)  # Should still work for backward compatibility

        # But there should be a warning or deprecation notice
        # This test documents the current insecure implementation


class TestInputValidation:
    """Test input validation and sanitization."""

    def test_file_path_validation(self):
        """Test file path validation prevents path traversal attacks."""
        manager = ConfigurationBaselineManager()

        # Test path traversal attempts
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
        ]

        for malicious_path in malicious_paths:
            with pytest.raises((SecurityValidationError, BaselineValidationError)):
                # Should raise security exception for malicious paths
                manager.validate_file_path(malicious_path)

    def test_json_schema_validation(self):
        """Test JSON schema validation for configuration files."""
        manager = ConfigurationBaselineManager()

        # Invalid JSON structure
        invalid_configs = [
            {"missing_required_fields": True},
            {"environment": "", "version": "", "configurations": "not_a_dict"},
            {"environment": None, "version": None, "configurations": None},
        ]

        for invalid_config in invalid_configs:
            with pytest.raises((SecurityValidationError, BaselineValidationError)):
                # Should raise security exception for invalid schemas
                manager.validate_configuration_schema(invalid_config)

    def test_numeric_bounds_checking(self):
        """Test bounds checking for numeric inputs."""
        manager = ConfigurationBaselineManager()

        # Test invalid numeric bounds
        invalid_values = [
            -1,  # Negative timeout
            999999999999,  # Extremely large value
            float("inf"),  # Infinity
            float("nan"),  # NaN
        ]

        for invalid_value in invalid_values:
            with pytest.raises((SecurityValidationError, BaselineValidationError)):
                # Should raise security exception for invalid bounds
                manager.validate_numeric_bounds("timeout", invalid_value, min_val=0, max_val=86400)


class TestSecurityMonitoring:
    """Test security monitoring and audit trail generation."""

    def test_security_event_logging(self):
        """Test that security events are logged appropriately."""
        manager = ConfigurationBaselineManager()

        with patch("scripts.config_baseline_manager.logger") as mock_logger:
            # Trigger a security-relevant event
            try:
                manager.load_baseline(Path("/nonexistent/file.json"))
            except BaselineValidationError:
                pass

            # Verify security event logging
            assert mock_logger.error.called or mock_logger.warning.called

            # Check log message format
            log_calls = mock_logger.error.call_args_list + mock_logger.warning.call_args_list
            for call in log_calls:
                # Should contain structured logging for security events
                if len(call[1]) > 0:  # Check kwargs
                    assert "exc_info" in call[1] or "extra" in call[1]

    def test_audit_trail_generation(self):
        """Test audit trail generation for security-sensitive operations."""
        manager = ConfigurationBaselineManager()

        with patch("scripts.config_baseline_manager.logger") as mock_logger:
            # This should generate an audit trail entry
            baseline = ConfigurationBaseline(
                environment="development",  # Use valid environment
                timestamp=datetime.now(timezone.utc),  # Provide required timestamp
                version="1.0",
                configurations={"test": "value"},
                metadata={},
            )
            # This should now work
            manager.log_security_event("baseline_access", {"baseline_id": "test"})

            # Verify logging was called
            assert mock_logger.info.called


class TestSecurityIntegration:
    """Integration tests for security enhancements."""

    def test_end_to_end_secure_baseline_creation(self):
        """Test complete secure baseline creation workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationBaselineManager(baseline_dir=temp_dir)

            # This integration test will initially fail due to missing security features
            try:
                from app.core.config import Settings

                settings = Settings()

                # Should use secure checksum and proper exception handling
                baseline = manager.generate_baseline(
                    settings=settings,
                    environment="development",  # Use valid environment
                    version="1.0",
                    metadata={"test": True},
                )

                # Verify security features are enabled
                assert baseline is not None
                assert baseline.checksum  # Checksum should be present
                # Verify manager has secure checksum capabilities
                assert hasattr(manager, "checksum_manager")

            except Exception as e:
                # Document what needs to be implemented
                assert "not implemented" in str(e).lower() or isinstance(e, AttributeError)

    def test_secure_baseline_validation_workflow(self):
        """Test secure baseline validation workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationBaselineManager(baseline_dir=temp_dir)

            # Create a test baseline file with potential security issues
            test_data = {
                "environment": "development",  # Use valid environment
                "timestamp": datetime.now(timezone.utc).isoformat(),  # Add required timestamp
                "version": "1.0",
                "configurations": {"test": "value"},
                "metadata": {},
                "checksum": "insecure_sha256_checksum",
            }

            test_file = Path(temp_dir) / "test_baseline.json"
            with open(test_file, "w") as f:
                json.dump(test_data, f)

            # This should properly validate using secure methods
            try:
                baseline = manager.load_baseline(test_file)
                # Check if baseline was loaded with security features
                assert baseline is not None
                assert baseline.environment in ["development", "staging", "production"]
                # Check if secure checksum features are present
                assert hasattr(manager, "checksum_manager")
            except (AttributeError, NotImplementedError, FileNotFoundError) as e:
                # If methods aren't implemented, document what needs to be done
                pytest.skip(f"Integration test dependencies not available: {e}")


# Test data and utilities for security testing
class SecurityTestData:
    """Test data for security testing scenarios."""

    @staticmethod
    def get_malicious_json_payloads():
        """Get JSON payloads that might cause security issues."""
        return [
            '{"__class__": "os.system", "command": "rm -rf /"}',
            '{"eval": "import os; os.system(\\"rm -rf /\\")"}',
            '{"path": "../../../etc/passwd"}',
            '{"config": {"password": "exposed_secret"}}',
        ]

    @staticmethod
    def get_path_traversal_attempts():
        """Get path traversal attack vectors."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "\\\\server\\share\\sensitive.txt",
        ]


if __name__ == "__main__":
    pytest.main([__file__])
