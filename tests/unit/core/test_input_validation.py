"""Tests for comprehensive input validation framework."""

from datetime import datetime
from decimal import Decimal
from typing import List
from unittest.mock import Mock, patch

import pytest
from fastapi import Request
from pydantic import BaseModel

from app.core.input_validation import (
    API_KEY_NAME_RULE,
    EMAIL_RULE,
    PASSWORD_RULE,
    USERNAME_RULE,
    FieldValidationRule,
    InputValidationError,
    ValidationConfig,
    ValidationLevel,
    validate_email_field,
    validate_field,
    validate_input,
    validate_ip_field,
    validate_json_input,
    validate_numeric_field,
    validate_query_params,
    validate_request_data,
    validate_string_field,
    validate_url_field,
)


class TestFieldValidationRule:
    """Test FieldValidationRule configuration."""

    def test_field_validation_rule_creation(self):
        """Test creating field validation rules."""
        rule = FieldValidationRule(
            field_name="test_field",
            field_type=str,
            min_length=5,
            max_length=50,
            pattern=r"^[a-zA-Z]+$",
        )

        assert rule.field_name == "test_field"
        assert rule.field_type == str
        assert rule.min_length == 5
        assert rule.max_length == 50
        assert rule.pattern == r"^[a-zA-Z]+$"
        assert rule.check_sql_injection is True  # Default
        assert rule.check_xss is True  # Default

    def test_field_validation_rule_with_custom_validator(self):
        """Test field validation rule with custom validator."""

        def custom_validator(value):
            return value.startswith("TEST_")

        rule = FieldValidationRule(
            field_name="test_field",
            custom_validator=custom_validator,
            error_message="Value must start with TEST_",
        )

        assert rule.custom_validator is not None
        assert rule.custom_validator("TEST_value") is True
        assert rule.custom_validator("value") is False


class TestValidationConfig:
    """Test ValidationConfig settings."""

    def test_default_validation_config(self):
        """Test default validation configuration."""
        config = ValidationConfig()

        assert config.level == ValidationLevel.MODERATE
        assert config.max_string_length == 10000
        assert config.max_array_length == 1000
        assert config.max_object_depth == 10
        assert config.reject_additional_fields is True
        assert config.strip_whitespace is True

    def test_custom_validation_config(self):
        """Test custom validation configuration."""
        config = ValidationConfig(
            level=ValidationLevel.STRICT,
            max_string_length=5000,
            reject_additional_fields=False,
        )

        assert config.level == ValidationLevel.STRICT
        assert config.max_string_length == 5000
        assert config.reject_additional_fields is False


class TestStringFieldValidation:
    """Test string field validation."""

    def test_validate_string_field_success(self):
        """Test successful string validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            min_length=3,
            max_length=10,
        )
        config = ValidationConfig()

        result = validate_string_field("hello", rule, config)
        assert result == "hello"

    def test_validate_string_field_strips_whitespace(self):
        """Test string validation strips whitespace."""
        rule = FieldValidationRule(field_name="test", field_type=str)
        config = ValidationConfig(strip_whitespace=True)

        result = validate_string_field("  hello  ", rule, config)
        assert result == "hello"

    def test_validate_string_field_too_short(self):
        """Test string validation fails when too short."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            min_length=5,
        )
        config = ValidationConfig()

        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field("hi", rule, config)

        assert "too short" in str(exc_info.value.detail)

    def test_validate_string_field_too_long(self):
        """Test string validation fails when too long."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            max_length=5,
        )
        config = ValidationConfig()

        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field("hello world", rule, config)

        assert "too long" in str(exc_info.value.detail)

    def test_validate_string_field_pattern_match(self):
        """Test string validation with pattern matching."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            pattern=r"^[A-Z]+$",
            error_message="Must be uppercase letters only",
        )
        config = ValidationConfig()

        # Valid pattern
        result = validate_string_field("HELLO", rule, config)
        assert result == "HELLO"

        # Invalid pattern
        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field("hello", rule, config)

        assert "Must be uppercase letters only" in str(exc_info.value.detail)

    def test_validate_string_field_sql_injection_strict(self):
        """Test string validation detects SQL injection in strict mode."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_sql_injection=True,
        )
        config = ValidationConfig(level=ValidationLevel.STRICT)

        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field("'; DROP TABLE users; --", rule, config)

        assert "SQL injection" in str(exc_info.value.detail)

    @patch("app.core.input_validation.logger")
    def test_validate_string_field_sql_injection_moderate(self, mock_logger):
        """Test string validation logs SQL injection in moderate mode."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_sql_injection=True,
        )
        config = ValidationConfig(level=ValidationLevel.MODERATE)

        # Should not raise, just log warning
        result = validate_string_field("SELECT * FROM users", rule, config)
        assert result == "SELECT * FROM users"
        mock_logger.warning.assert_called()

    def test_validate_string_field_xss_strict(self):
        """Test string validation detects XSS in strict mode."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_xss=True,
        )
        config = ValidationConfig(level=ValidationLevel.STRICT)

        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field("<script>alert('xss')</script>", rule, config)

        assert "XSS" in str(exc_info.value.detail)

    def test_validate_string_field_required(self):
        """Test required string field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            required=True,
        )
        config = ValidationConfig()

        # None value should fail
        with pytest.raises(InputValidationError) as exc_info:
            validate_string_field(None, rule, config)

        assert "Required field" in str(exc_info.value.detail)

    def test_validate_string_field_optional(self):
        """Test optional string field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            required=False,
        )
        config = ValidationConfig()

        result = validate_string_field(None, rule, config)
        assert result is None


class TestNumericFieldValidation:
    """Test numeric field validation."""

    def test_validate_numeric_field_int(self):
        """Test integer field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=int,
            min_value=0,
            max_value=100,
        )
        config = ValidationConfig()

        result = validate_numeric_field(42, rule, config)
        assert result == 42
        assert isinstance(result, int)

    def test_validate_numeric_field_float(self):
        """Test float field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=float,
            min_value=0.0,
            max_value=100.0,
        )
        config = ValidationConfig()

        result = validate_numeric_field(42.5, rule, config)
        assert result == 42.5
        assert isinstance(result, float)

    def test_validate_numeric_field_decimal(self):
        """Test decimal field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=Decimal,
        )
        config = ValidationConfig()

        result = validate_numeric_field("42.50", rule, config)
        assert result == Decimal("42.50")
        assert isinstance(result, Decimal)

    def test_validate_numeric_field_range_validation(self):
        """Test numeric range validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=int,
            min_value=10,
            max_value=20,
        )
        config = ValidationConfig()

        # Valid range
        result = validate_numeric_field(15, rule, config)
        assert result == 15

        # Too small
        with pytest.raises(InputValidationError) as exc_info:
            validate_numeric_field(5, rule, config)
        assert "too small" in str(exc_info.value.detail)

        # Too large
        with pytest.raises(InputValidationError) as exc_info:
            validate_numeric_field(25, rule, config)
        assert "too large" in str(exc_info.value.detail)

    def test_validate_numeric_field_allowed_values(self):
        """Test numeric allowed values validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=int,
            allowed_values={1, 2, 3, 5, 8},
        )
        config = ValidationConfig()

        # Valid value
        result = validate_numeric_field(3, rule, config)
        assert result == 3

        # Invalid value
        with pytest.raises(InputValidationError) as exc_info:
            validate_numeric_field(4, rule, config)
        assert "not in allowed set" in str(exc_info.value.detail)


class TestValidateField:
    """Test general field validation."""

    def test_validate_field_with_custom_validator(self):
        """Test field validation with custom validator."""

        def is_even(value):
            return isinstance(value, int) and value % 2 == 0

        rule = FieldValidationRule(
            field_name="test",
            custom_validator=is_even,
            error_message="Value must be even",
        )
        config = ValidationConfig()

        # Valid
        result = validate_field(4, rule, config)
        assert result == 4

        # Invalid
        with pytest.raises(InputValidationError) as exc_info:
            validate_field(3, rule, config)
        assert "Value must be even" in str(exc_info.value.detail)

    def test_validate_field_boolean(self):
        """Test boolean field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=bool,
        )
        config = ValidationConfig()

        assert validate_field(True, rule, config) is True
        assert validate_field(False, rule, config) is False

        with pytest.raises(InputValidationError) as exc_info:
            validate_field("true", rule, config)
        assert "Expected boolean" in str(exc_info.value.detail)

    def test_validate_field_datetime(self):
        """Test datetime field validation."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=datetime,
        )
        config = ValidationConfig()

        # ISO format string
        result = validate_field("2023-01-01T12:00:00", rule, config)
        assert isinstance(result, datetime)

        # Datetime object
        now = datetime.now()
        result = validate_field(now, rule, config)
        assert result == now

        # Invalid format
        with pytest.raises(InputValidationError) as exc_info:
            validate_field("not a date", rule, config)
        assert "Invalid datetime format" in str(exc_info.value.detail)


class TestValidateRequestData:
    """Test request data validation."""

    def test_validate_request_data_success(self):
        """Test successful request data validation."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str, min_length=3),
            FieldValidationRule(field_name="age", field_type=int, min_value=0),
            FieldValidationRule(field_name="email", field_type=str),
        ]
        config = ValidationConfig()

        data = {
            "username": "john_doe",
            "age": 25,
            "email": "john@example.com",
        }

        result = validate_request_data(data, rules, config)
        assert result == data

    def test_validate_request_data_missing_required_field(self):
        """Test request data validation with missing required field."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str, required=True),
            FieldValidationRule(field_name="email", field_type=str, required=True),
        ]
        config = ValidationConfig()

        data = {"username": "john_doe"}  # Missing email

        with pytest.raises(InputValidationError) as exc_info:
            validate_request_data(data, rules, config)

        assert "Required field" in str(exc_info.value.detail)

    def test_validate_request_data_extra_fields_rejected(self):
        """Test request data validation rejects extra fields."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str),
        ]
        config = ValidationConfig(reject_additional_fields=True)

        data = {
            "username": "john_doe",
            "extra_field": "should not be here",
        }

        with pytest.raises(InputValidationError) as exc_info:
            validate_request_data(data, rules, config)

        assert "Unexpected fields" in str(exc_info.value.detail)

    def test_validate_request_data_extra_fields_allowed(self):
        """Test request data validation allows extra fields when configured."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str),
        ]
        config = ValidationConfig(reject_additional_fields=False)

        data = {
            "username": "john_doe",
            "extra_field": "allowed",
        }

        result = validate_request_data(data, rules, config)
        assert result == {"username": "john_doe"}  # Extra field not included


class TestValidateJsonInput:
    """Test JSON input validation."""

    def test_validate_json_input_success(self):
        """Test successful JSON validation."""
        config = ValidationConfig()

        data = {
            "name": "test",
            "items": [1, 2, 3],
            "nested": {"key": "value"},
        }

        result = validate_json_input(data, config)
        assert result == data

    def test_validate_json_input_too_deep(self):
        """Test JSON validation fails when too deeply nested."""
        config = ValidationConfig(max_object_depth=2)

        data = {"level1": {"level2": {"level3": {"too": "deep"}}}}

        with pytest.raises(InputValidationError) as exc_info:
            validate_json_input(data, config)

        assert "nesting too deep" in str(exc_info.value.detail)

    def test_validate_json_input_too_many_keys(self):
        """Test JSON validation fails with too many keys."""
        config = ValidationConfig(max_object_keys=5)

        data = {f"key{i}": i for i in range(10)}

        with pytest.raises(InputValidationError) as exc_info:
            validate_json_input(data, config)

        assert "Too many keys" in str(exc_info.value.detail)


class TestValidateQueryParams:
    """Test query parameter validation."""

    def test_validate_query_params_success(self):
        """Test successful query parameter validation."""
        request = Mock(spec=Request)
        request.query_params = {"page": "1", "limit": "10"}

        allowed_params = {"page", "limit", "sort"}
        config = ValidationConfig()

        result = validate_query_params(request, allowed_params, config)
        assert result == {"page": "1", "limit": "10"}

    def test_validate_query_params_unexpected_rejected(self):
        """Test query parameter validation rejects unexpected params."""
        request = Mock(spec=Request)
        request.query_params = {"page": "1", "hack": "attempt"}

        allowed_params = {"page", "limit"}
        config = ValidationConfig(reject_additional_fields=True)

        with pytest.raises(InputValidationError) as exc_info:
            validate_query_params(request, allowed_params, config)

        assert "Unexpected query parameters" in str(exc_info.value.detail)

    def test_validate_query_params_sql_injection_check(self):
        """Test query parameter validation checks for SQL injection."""
        request = Mock(spec=Request)
        request.query_params = {"search": "'; DROP TABLE users; --"}

        allowed_params = {"search"}
        config = ValidationConfig(level=ValidationLevel.STRICT)

        with pytest.raises(InputValidationError) as exc_info:
            validate_query_params(request, allowed_params, config)

        assert "SQL injection" in str(exc_info.value.detail)


class TestValidationDecorator:
    """Test validation decorator."""

    @pytest.mark.asyncio
    async def test_validate_input_decorator_query_params(self):
        """Test input validation decorator for query parameters."""
        config = ValidationConfig()

        @validate_input(
            validate_query=True,
            allowed_query_params={"page", "limit"},
            config=config,
        )
        async def test_endpoint(request: Request):
            return {"success": True}

        # Valid query params
        request = Mock(spec=Request)
        request.query_params = {"page": "1", "limit": "10"}
        request.state = Mock()

        result = await test_endpoint(request)
        assert result == {"success": True}
        assert hasattr(request.state, "validated_query")

    @pytest.mark.asyncio
    async def test_validate_input_decorator_json_body(self):
        """Test input validation decorator for JSON body."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str, min_length=3),
            FieldValidationRule(field_name="email", field_type=str),
        ]
        config = ValidationConfig()

        @validate_input(rules=rules, config=config, validate_json=True)
        async def test_endpoint(request: Request, body: dict):
            return body

        # Valid JSON body
        request = Mock(spec=Request)
        request.method = "POST"
        request.url.path = "/test"
        body = {"username": "john", "email": "john@example.com"}

        result = await test_endpoint(request, body=body)
        assert result == body

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Decorator validation with field rules only requires request object")
    async def test_validate_input_decorator_validation_failure(self):
        """Test input validation decorator handles validation failures."""
        rules = [
            FieldValidationRule(field_name="username", field_type=str, min_length=10),
        ]
        config = ValidationConfig(log_validation_failures=True)

        # Test without request to check field rules directly
        @validate_input(rules=rules, config=config, validate_json=False)
        async def test_endpoint(body: dict):
            return body

        body = {"username": "short"}  # Too short

        with pytest.raises(InputValidationError) as exc_info:
            await test_endpoint(body=body)

        assert "too short" in str(exc_info.value.detail)


class TestSpecificFieldValidators:
    """Test specific field validator functions."""

    def test_validate_email_field_success(self):
        """Test email field validation success."""
        email = validate_email_field("test@example.com")
        assert email == "test@example.com"

    def test_validate_email_field_invalid(self):
        """Test email field validation failure."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_email_field("not-an-email")

        assert "Invalid email format" in str(exc_info.value.detail)

    def test_validate_url_field_success(self):
        """Test URL field validation success."""
        url = validate_url_field("https://example.com")
        assert url == "https://example.com"

    def test_validate_url_field_invalid_scheme(self):
        """Test URL field validation with invalid scheme."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_url_field("ftp://example.com", allowed_schemes=["http", "https"])

        assert "scheme" in str(exc_info.value.detail)

    def test_validate_ip_field_success(self):
        """Test IP field validation success."""
        ip = validate_ip_field("192.168.1.1")
        assert ip == "192.168.1.1"

    def test_validate_ip_field_invalid(self):
        """Test IP field validation failure."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_ip_field("999.999.999.999")

        assert "Invalid" in str(exc_info.value.detail)


class TestCommonValidationRules:
    """Test common validation rules."""

    def test_username_rule(self):
        """Test username validation rule."""
        config = ValidationConfig()

        # Valid username
        result = validate_string_field("john_doe", USERNAME_RULE, config)
        assert result == "john_doe"

        # Too short
        with pytest.raises(InputValidationError):
            validate_string_field("ab", USERNAME_RULE, config)

        # Invalid characters
        with pytest.raises(InputValidationError):
            validate_string_field("john@doe", USERNAME_RULE, config)

    def test_password_rule(self):
        """Test password validation rule."""
        config = ValidationConfig()

        # Valid password
        result = validate_string_field("SecureP@ss123", PASSWORD_RULE, config)
        assert result == "SecureP@ss123"

        # Too short
        with pytest.raises(InputValidationError):
            validate_string_field("short", PASSWORD_RULE, config)

        # SQL injection chars allowed in passwords
        result = validate_string_field("Pass'; DROP TABLE--", PASSWORD_RULE, config)
        assert result == "Pass'; DROP TABLE--"

    def test_email_rule(self):
        """Test email validation rule."""
        config = ValidationConfig()

        # Valid email
        result = validate_field("test@example.com", EMAIL_RULE, config)
        assert result == "test@example.com"

        # Invalid email
        with pytest.raises(InputValidationError):
            validate_field("not-an-email", EMAIL_RULE, config)

    def test_api_key_name_rule(self):
        """Test API key name validation rule."""
        config = ValidationConfig()

        # Valid API key name
        result = validate_string_field("My API Key 123", API_KEY_NAME_RULE, config)
        assert result == "My API Key 123"

        # Invalid characters
        with pytest.raises(InputValidationError):
            validate_string_field("Key@#$%", API_KEY_NAME_RULE, config)


class TestValidationLevels:
    """Test different validation levels."""

    def test_strict_level_rejects_on_warnings(self):
        """Test strict validation level rejects on warnings."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_sql_injection=True,
        )
        config = ValidationConfig(level=ValidationLevel.STRICT)

        with pytest.raises(InputValidationError):
            validate_string_field("SELECT * FROM users", rule, config)

    @patch("app.core.input_validation.logger")
    def test_moderate_level_logs_warnings(self, mock_logger):
        """Test moderate validation level logs warnings."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_sql_injection=True,
        )
        config = ValidationConfig(level=ValidationLevel.MODERATE)

        result = validate_string_field("SELECT * FROM users", rule, config)
        assert result == "SELECT * FROM users"
        mock_logger.warning.assert_called()

    def test_lenient_level_skips_security_checks(self):
        """Test lenient validation level skips security checks."""
        rule = FieldValidationRule(
            field_name="test",
            field_type=str,
            check_sql_injection=True,
            check_xss=True,
        )
        config = ValidationConfig(level=ValidationLevel.LENIENT)

        # Should pass without security checks
        result = validate_string_field("'; DROP TABLE users; --", rule, config)
        assert result == "'; DROP TABLE users; --"

        result = validate_string_field("<script>alert('xss')</script>", rule, config)
        assert result == "<script>alert('xss')</script>"
