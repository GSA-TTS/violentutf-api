"""
Unit tests for input validation security module.

Tests comprehensive input validation to prevent XSS, SQL injection,
path traversal, and other security vulnerabilities.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.pre_audit.reporting.security import InputValidator, ValidationError


class TestInputValidator:
    """Test suite for InputValidator class."""

    @pytest.fixture
    def validator(self):
        """Create InputValidator instance."""
        return InputValidator(strict_mode=True)

    @pytest.fixture
    def lenient_validator(self):
        """Create InputValidator with lenient mode."""
        return InputValidator(strict_mode=False)

    @pytest.fixture
    def sample_audit_data(self):
        """Create sample audit data for testing."""
        return {
            "all_violations": [
                {
                    "file_path": "src/main.py",
                    "line_number": 42,
                    "adr_id": "ADR-001",
                    "risk_level": "high",
                    "message": "Missing authentication",
                }
            ],
            "architectural_hotspots": [
                {
                    "file_path": "src/api/auth.py",
                    "risk_score": 0.85,
                    "violation_history": ["ADR-001", "ADR-002"],
                }
            ],
            "audit_metadata": {
                "total_files_analyzed": 100,
                "repository_path": "/path/to/repo",
                "analysis_timestamp": "2024-01-01T00:00:00Z",
            },
        }

    # Test XSS Prevention
    def test_validate_string_blocks_xss_patterns(self, validator):
        """Test that XSS patterns are blocked."""
        xss_patterns = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='evil.com'></iframe>",
            "<object data='evil.swf'></object>",
            "<embed src='evil.swf'>",
            "<link rel='stylesheet' href='evil.css'>",
            "@import url('evil.css')",
            "expression(alert('XSS'))",
            "vbscript:msgbox('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
        ]

        for pattern in xss_patterns:
            with pytest.raises(ValidationError) as exc_info:
                validator.validate_string(pattern, "test_field")
            assert "dangerous pattern" in str(exc_info.value).lower()

    def test_validate_string_allows_safe_content(self, validator):
        """Test that safe content passes validation."""
        safe_strings = [
            "This is a safe string",
            "Code: function test() { return true; }",
            "HTML entities: &lt;div&gt;",
            "Math: 2 < 3 && 4 > 1",
            "URL: https://example.com/path?param=value",
        ]

        for safe_string in safe_strings:
            result = validator.validate_string(safe_string, "test_field")
            assert result == safe_string

    # Test SQL Injection Prevention
    def test_validate_string_blocks_sql_injection(self, validator):
        """Test that SQL injection patterns are blocked in strict mode."""
        sql_patterns = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "1 UNION SELECT * FROM passwords",
            "'; DELETE FROM users WHERE '1'='1",
        ]

        for pattern in sql_patterns:
            with pytest.raises(ValidationError) as exc_info:
                validator.validate_string(pattern, "test_field")
            assert "sql pattern" in str(exc_info.value).lower()

    def test_lenient_mode_allows_sql_keywords(self, lenient_validator):
        """Test that lenient mode allows SQL keywords."""
        sql_like_strings = [
            "Select the best option",
            "Update your profile",
            "Delete unnecessary files",
        ]

        for string in sql_like_strings:
            result = lenient_validator.validate_string(string, "test_field")
            assert result == string

    # Test Path Traversal Prevention
    def test_validate_file_path_blocks_traversal(self, validator):
        """Test that path traversal attempts are blocked."""
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "path/with\x00null/byte",
            "../../../../../../../../etc/passwd",
        ]

        for path in dangerous_paths:
            with pytest.raises(ValidationError):
                validator.validate_file_path(path)

    def test_validate_file_path_allows_safe_paths(self, validator):
        """Test that safe relative paths are allowed."""
        with patch("pathlib.Path.cwd", return_value=Path("/project")):
            safe_paths = [
                "src/main.py",
                "tests/test_app.py",
                "docs/README.md",
                "path/to/file.txt",
            ]

            for path in safe_paths:
                with patch("pathlib.Path.resolve") as mock_resolve:
                    mock_resolve.return_value = Path(f"/project/{path}")
                    result = validator.validate_file_path(path)
                    assert isinstance(result, Path)

    # Test Control Character Prevention
    def test_validate_string_blocks_control_characters(self, validator):
        """Test that control characters are blocked."""
        strings_with_control = [
            "text\x00with\x01null",
            "bell\x07character",
            "escape\x1bsequence",
            "form\x0cfeed",
        ]

        for string in strings_with_control:
            with pytest.raises(ValidationError) as exc_info:
                validator.validate_string(string, "test_field")
            assert "control characters" in str(exc_info.value).lower()

    def test_validate_string_allows_normal_whitespace(self, validator):
        """Test that normal whitespace is allowed."""
        strings_with_whitespace = [
            "Line 1\nLine 2",
            "Tab\tseparated",
            "Carriage\rreturn",
            "Multiple  spaces",
        ]

        for string in strings_with_whitespace:
            result = validator.validate_string(string, "test_field")
            assert result == string

    # Test Length Limits
    def test_validate_string_enforces_length_limit(self, validator):
        """Test that string length limits are enforced."""
        long_string = "a" * (validator.MAX_STRING_LENGTH + 1)

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_string(long_string, "test_field")
        assert "too long" in str(exc_info.value).lower()

    def test_validate_file_path_enforces_length_limit(self, validator):
        """Test that path length limits are enforced."""
        long_path = "a" * (validator.MAX_PATH_LENGTH + 1)

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_file_path(long_path)
        assert "too long" in str(exc_info.value).lower()

    # Test Audit Data Validation
    def test_validate_audit_data_success(self, validator, sample_audit_data):
        """Test successful validation of audit data."""
        result = validator.validate_audit_data(sample_audit_data)

        assert "all_violations" in result
        assert "architectural_hotspots" in result
        assert "audit_metadata" in result
        assert len(result["all_violations"]) == 1
        assert result["all_violations"][0]["file_path"] == "src/main.py"

    def test_validate_audit_data_sanitizes_dangerous_content(self, validator):
        """Test that dangerous content in audit data is sanitized."""
        dangerous_data = {
            "all_violations": [
                {
                    "file_path": "../../../etc/passwd",
                    "message": "<script>alert('XSS')</script>",
                    "adr_id": "ADR-001",
                }
            ],
            "audit_metadata": {"repository_path": "/etc/passwd"},
        }

        result = validator.validate_audit_data(dangerous_data)

        # File path should be sanitized to "unknown"
        assert result["all_violations"][0]["file_path"] == "unknown"
        # Message should be sanitized
        assert result["all_violations"][0]["message"] == "[Content sanitized]"

    # Test JSON Validation
    def test_validate_json_data_with_string(self, validator):
        """Test JSON validation with string input."""
        json_string = '{"key": "value", "number": 42}'
        result = validator.validate_json_data(json_string)

        assert result == {"key": "value", "number": 42}

    def test_validate_json_data_with_dict(self, validator):
        """Test JSON validation with dictionary input."""
        json_dict = {"key": "value", "nested": {"inner": "data"}}
        result = validator.validate_json_data(json_dict)

        assert result == json_dict

    def test_validate_json_data_blocks_deep_nesting(self, validator):
        """Test that deeply nested JSON is blocked."""
        # Create deeply nested structure
        deep_json = {}
        current = deep_json
        for i in range(validator.MAX_DICT_DEPTH + 2):
            current["level"] = {}
            current = current["level"]

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_json_data(deep_json)
        assert "too deep" in str(exc_info.value).lower()

    def test_validate_json_data_blocks_large_arrays(self, validator):
        """Test that very large arrays are blocked."""
        large_array = list(range(validator.MAX_ARRAY_SIZE + 1))

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_json_data(large_array)
        assert "too large" in str(exc_info.value).lower()

    # Test Violation Validation
    def test_validate_violations_with_safe_data(self, validator):
        """Test violation validation with safe data."""
        violations = [
            {
                "file_path": "src/app.py",
                "line_number": 10,
                "adr_id": "ADR-001",
                "risk_level": "high",
                "message": "Missing authentication check",
            }
        ]

        result = validator._validate_violations(violations)

        assert len(result) == 1
        assert result[0]["file_path"] == "src/app.py"
        assert result[0]["message"] == "Missing authentication check"

    def test_validate_violations_handles_missing_fields(self, validator):
        """Test that missing fields are handled gracefully."""
        violations = [{"adr_id": "ADR-001"}]  # Missing most fields

        result = validator._validate_violations(violations)

        assert len(result) == 1
        assert "adr_id" in result[0]

    # Test Hotspot Validation
    def test_validate_hotspots_with_dict(self, validator):
        """Test hotspot validation with dictionary input."""
        hotspots = [
            {
                "file_path": "src/hotspot.py",
                "risk_score": 0.85,
                "violation_history": ["ADR-001", "ADR-002"],
            }
        ]

        result = validator._validate_hotspots(hotspots)

        assert len(result) == 1
        assert result[0]["file_path"] == "src/hotspot.py"
        assert result[0]["risk_score"] == 0.85
        assert len(result[0]["violation_history"]) == 2

    def test_validate_hotspots_limits_history_size(self, validator):
        """Test that violation history is limited in size."""
        hotspots = [{"file_path": "src/hotspot.py", "violation_history": list(range(100))}]  # Large history

        result = validator._validate_hotspots(hotspots)

        # Should limit to 10 items
        assert len(result[0]["violation_history"]) == 10

    # Test Data Size Validation
    def test_validate_data_size_blocks_large_data(self, validator):
        """Test that overly large data is blocked."""
        # Create data that exceeds 50MB when serialized
        large_data = {
            "all_violations": [
                {
                    "file_path": f"file_{i}.py",
                    "message": "x" * 10000,
                    "adr_id": "ADR-001",
                }  # 10KB per message
                for i in range(6000)  # 60MB total
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            validator._validate_data_size(large_data, max_size_mb=50)
        assert "exceeds maximum allowed size" in str(exc_info.value)

    def test_validate_data_size_allows_normal_data(self, validator, sample_audit_data):
        """Test that normal-sized data passes validation."""
        # This should not raise any exception
        validator._validate_data_size(sample_audit_data, max_size_mb=50)

    def test_validate_audit_data_enforces_size_limit(self, validator):
        """Test that validate_audit_data checks size internally."""
        # Create data that's just over 50MB
        large_data = {
            "all_violations": [
                {
                    "file_path": f"file_{i}.py",
                    "message": "x" * 1000000,
                    "adr_id": "ADR-001",
                }  # 1MB per message
                for i in range(55)  # 55MB total
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_audit_data(large_data)
        assert "data size" in str(exc_info.value).lower()

    # Test Statistics Tracking
    def test_get_validation_stats(self, validator, sample_audit_data):
        """Test validation statistics tracking."""
        # Perform some validations
        validator.validate_audit_data(sample_audit_data)

        # Try to validate dangerous data
        try:
            validator.validate_string("<script>alert('XSS')</script>", "test")
        except ValidationError:
            pass

        stats = validator.get_validation_stats()

        assert stats["total_validations"] == 1
        assert stats["passed"] == 1
        assert stats["failed"] == 0
        assert len(stats["blocked_patterns"]) > 0
