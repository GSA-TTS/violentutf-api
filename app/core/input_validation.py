"""Comprehensive input validation framework for ViolentUTF API.

This module provides a comprehensive validation framework with decorators and utilities
for validating API inputs, including field-level validation, type checking, and
security validation for SQL injection, XSS, and other attack vectors.
"""

import re
from datetime import datetime
from decimal import Decimal
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError, validator
from structlog.stdlib import get_logger

from ..utils.validation import (
    check_prompt_injection,
    check_sql_injection,
    check_xss_injection,
    validate_email,
    validate_ip_address,
    validate_json_payload,
    validate_url,
)

logger = get_logger(__name__)


class ValidationLevel(str, Enum):
    """Validation strictness levels."""

    STRICT = "strict"  # Reject on any security warning
    MODERATE = "moderate"  # Log warnings but allow
    LENIENT = "lenient"  # Minimal validation


class FieldValidationRule(BaseModel):
    """Configuration for field validation rules."""

    field_name: str
    field_type: Optional[Type[Any]] = None
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    min_value: Optional[Union[int, float, Decimal]] = None
    max_value: Optional[Union[int, float, Decimal]] = None
    allowed_values: Optional[Set[Any]] = None
    custom_validator: Optional[Callable[[Any], bool]] = None
    check_sql_injection: bool = True
    check_xss: bool = True
    check_prompt_injection: bool = False
    sanitize: bool = True
    error_message: Optional[str] = None


class ValidationConfig(BaseModel):
    """Configuration for validation behavior."""

    level: ValidationLevel = ValidationLevel.MODERATE
    max_string_length: int = 10000
    max_array_length: int = 1000
    max_object_depth: int = 10
    max_object_keys: int = 1000
    reject_additional_fields: bool = True
    strip_whitespace: bool = True
    convert_empty_to_none: bool = True
    log_validation_failures: bool = True
    custom_validators: Dict[str, Callable[[Any], bool]] = Field(default_factory=dict)


class InputValidationError(HTTPException):
    """Custom exception for input validation failures."""

    def __init__(
        self,
        detail: Union[str, List[str]],
        field: Optional[str] = None,
        security_issue: bool = False,
    ):
        if isinstance(detail, list):
            detail_str = "; ".join(detail)
        else:
            detail_str = detail

        if field:
            detail_str = f"{field}: {detail_str}"

        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail_str,
            headers={"X-Validation-Error": "true"},
        )

        if security_issue:
            logger.warning(
                "security_validation_failure",
                detail=detail,
                field=field,
            )


def validate_string_field(
    value: Any,
    rule: FieldValidationRule,
    config: ValidationConfig,
) -> str:
    """Validate a string field according to rules.

    Args:
        value: Value to validate
        rule: Validation rule configuration
        config: Validation configuration

    Returns:
        Validated and cleaned string value

    Raises:
        InputValidationError: If validation fails
    """
    if value is None or value == "":
        if config.convert_empty_to_none:
            value = None
        if rule.required and value is None:
            raise InputValidationError(f"Required field", field=rule.field_name)
        if value is None:
            return None  # type: ignore[return-value]

    if not isinstance(value, str):
        raise InputValidationError(
            f"Expected string, got {type(value).__name__}",
            field=rule.field_name,
        )

    # Strip whitespace if configured
    if config.strip_whitespace:
        value = value.strip()

    # Length validation
    if rule.min_length is not None and len(value) < rule.min_length:
        raise InputValidationError(
            f"String too short (min {rule.min_length} chars)",
            field=rule.field_name,
        )

    if rule.max_length is not None and len(value) > rule.max_length:
        raise InputValidationError(
            f"String too long (max {rule.max_length} chars)",
            field=rule.field_name,
        )

    # Pattern validation
    if rule.pattern:
        if not re.match(rule.pattern, value):
            raise InputValidationError(
                rule.error_message or f"Invalid format",
                field=rule.field_name,
            )

    # Security checks
    if rule.check_sql_injection and config.level != ValidationLevel.LENIENT:
        sql_result = check_sql_injection(value)
        if not sql_result.is_valid:
            if config.level == ValidationLevel.STRICT:
                raise InputValidationError(
                    "Potential SQL injection detected",
                    field=rule.field_name,
                    security_issue=True,
                )
            else:
                logger.warning(
                    "sql_injection_warning",
                    field=rule.field_name,
                    warnings=sql_result.warnings,
                )

    if rule.check_xss and config.level != ValidationLevel.LENIENT:
        xss_result = check_xss_injection(value)
        if not xss_result.is_valid:
            if config.level == ValidationLevel.STRICT:
                raise InputValidationError(
                    "Potential XSS detected",
                    field=rule.field_name,
                    security_issue=True,
                )
            else:
                logger.warning(
                    "xss_warning",
                    field=rule.field_name,
                    warnings=xss_result.warnings,
                )

    if rule.check_prompt_injection:
        prompt_result = check_prompt_injection(value)
        if not prompt_result.is_valid:
            if config.level == ValidationLevel.STRICT:
                raise InputValidationError(
                    "Potential prompt injection detected",
                    field=rule.field_name,
                    security_issue=True,
                )
            else:
                logger.warning(
                    "prompt_injection_warning",
                    field=rule.field_name,
                    warnings=prompt_result.warnings,
                )

    return value  # type: ignore[no-any-return]


def validate_numeric_field(
    value: Any,
    rule: FieldValidationRule,
    config: ValidationConfig,
) -> Optional[Union[int, float, Decimal]]:
    """Validate a numeric field according to rules.

    Args:
        value: Value to validate
        rule: Validation rule configuration
        config: Validation configuration

    Returns:
        Validated numeric value

    Raises:
        InputValidationError: If validation fails
    """
    if value is None:
        if rule.required:
            raise InputValidationError(f"Required field", field=rule.field_name)
        return None

    # Type conversion
    target_type = rule.field_type or float
    try:
        if target_type == int:
            value = int(value)
        elif target_type == float:
            value = float(value)
        elif target_type == Decimal:
            value = Decimal(str(value))
        else:
            value = float(value)
    except (ValueError, TypeError):
        raise InputValidationError(
            f"Invalid numeric value",
            field=rule.field_name,
        )

    # Range validation
    if rule.min_value is not None and value < rule.min_value:
        raise InputValidationError(
            f"Value too small (min {rule.min_value})",
            field=rule.field_name,
        )

    if rule.max_value is not None and value > rule.max_value:
        raise InputValidationError(
            f"Value too large (max {rule.max_value})",
            field=rule.field_name,
        )

    # Allowed values
    if rule.allowed_values and value not in rule.allowed_values:
        raise InputValidationError(
            f"Value not in allowed set",
            field=rule.field_name,
        )

    return value  # type: ignore[no-any-return]


def validate_array_field(
    value: Any,
    rule: FieldValidationRule,
    config: ValidationConfig,
) -> Optional[List[Any]]:
    """Validate an array field according to rules.

    Args:
        value: Value to validate
        rule: Validation rule configuration
        config: Validation configuration

    Returns:
        Validated array value

    Raises:
        InputValidationError: If validation fails
    """
    if value is None:
        if rule.required:
            raise InputValidationError(f"Required field", field=rule.field_name)
        return None

    if not isinstance(value, list):
        raise InputValidationError(
            f"Expected array, got {type(value).__name__}",
            field=rule.field_name,
        )

    # Length validation
    if len(value) > config.max_array_length:
        raise InputValidationError(
            f"Array too long (max {config.max_array_length} items)",
            field=rule.field_name,
        )

    # Validate each item if type specified
    if rule.field_type and hasattr(rule.field_type, "__origin__"):
        # Handle List[Type] annotations
        item_type = rule.field_type.__args__[0] if rule.field_type.__args__ else None
        if item_type:
            validated_items = []
            for i, item in enumerate(value):
                try:
                    if item_type == str:
                        item_rule = FieldValidationRule(
                            field_name=f"{rule.field_name}[{i}]",
                            field_type=str,
                            required=True,
                            check_sql_injection=rule.check_sql_injection,
                            check_xss=rule.check_xss,
                        )
                        validated_items.append(validate_string_field(item, item_rule, config))
                    else:
                        validated_items.append(item)
                except InputValidationError as e:
                    raise InputValidationError(
                        f"Array item {i}: {e.detail}",
                        field=rule.field_name,
                    )
            return validated_items

    return value


def validate_field(
    value: Any,
    rule: FieldValidationRule,
    config: ValidationConfig,
) -> Any:
    """Validate a field according to its type and rules.

    Args:
        value: Value to validate
        rule: Validation rule configuration
        config: Validation configuration

    Returns:
        Validated value

    Raises:
        InputValidationError: If validation fails
    """
    # Custom validator takes precedence
    if rule.custom_validator:
        if not rule.custom_validator(value):
            raise InputValidationError(
                rule.error_message or "Custom validation failed",
                field=rule.field_name,
            )

    # Handle None/empty values
    if value is None or value == "":
        if config.convert_empty_to_none:
            value = None
        if rule.required and value is None:
            raise InputValidationError("Required field", field=rule.field_name)
        if value is None:
            return None

    # Type-based validation
    if rule.field_type:
        if rule.field_type == str:
            return validate_string_field(value, rule, config)
        elif rule.field_type in [int, float, Decimal]:
            return validate_numeric_field(value, rule, config)
        elif hasattr(rule.field_type, "__origin__") and rule.field_type.__origin__ == list:
            return validate_array_field(value, rule, config)
        elif rule.field_type == bool:
            if not isinstance(value, bool):
                raise InputValidationError(
                    f"Expected boolean, got {type(value).__name__}",
                    field=rule.field_name,
                )
            return value
        elif rule.field_type == datetime:
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    raise InputValidationError(
                        "Invalid datetime format",
                        field=rule.field_name,
                    )
            elif isinstance(value, datetime):
                return value
            else:
                raise InputValidationError(
                    f"Expected datetime, got {type(value).__name__}",
                    field=rule.field_name,
                )

    # Default string validation for untyped fields
    if isinstance(value, str):
        return validate_string_field(value, rule, config)

    return value


def validate_request_data(
    data: Dict[str, Any],
    rules: List[FieldValidationRule],
    config: Optional[ValidationConfig] = None,
) -> Dict[str, Any]:
    """Validate request data against a set of rules.

    Args:
        data: Request data dictionary
        rules: List of field validation rules
        config: Validation configuration

    Returns:
        Validated and cleaned data dictionary

    Raises:
        InputValidationError: If validation fails
    """
    if config is None:
        config = ValidationConfig()

    validated_data = {}
    errors = []
    field_names = {rule.field_name for rule in rules}

    # Check for unexpected fields
    if config.reject_additional_fields:
        extra_fields = set(data.keys()) - field_names
        if extra_fields:
            errors.append(f"Unexpected fields: {', '.join(extra_fields)}")

    # Validate each field
    for rule in rules:
        try:
            value = data.get(rule.field_name)
            validated_value = validate_field(value, rule, config)
            if validated_value is not None or not rule.required:
                validated_data[rule.field_name] = validated_value
        except InputValidationError as e:
            errors.append(str(e.detail))
        except Exception as e:
            logger.error(
                "validation_error",
                field=rule.field_name,
                error=str(e),
            )
            errors.append(f"{rule.field_name}: Validation error")

    if errors:
        raise InputValidationError(errors)

    return validated_data


def validate_json_input(
    data: Any,
    config: Optional[ValidationConfig] = None,
) -> Any:
    """Validate JSON input for security and structure.

    Args:
        data: JSON data to validate
        config: Validation configuration

    Returns:
        Validated JSON data

    Raises:
        InputValidationError: If validation fails
    """
    if config is None:
        config = ValidationConfig()

    # Validate JSON structure
    result = validate_json_payload(
        data,
        max_depth=config.max_object_depth,
        max_keys=config.max_object_keys,
    )

    if not result.is_valid:
        raise InputValidationError(
            result.errors,
            security_issue=True,
        )

    if result.warnings and config.level == ValidationLevel.STRICT:
        raise InputValidationError(
            result.warnings,
            security_issue=True,
        )

    return data


def validate_query_params(
    request: Request,
    allowed_params: Set[str],
    config: Optional[ValidationConfig] = None,
) -> Dict[str, str]:
    """Validate query parameters.

    Args:
        request: FastAPI request object
        allowed_params: Set of allowed parameter names
        config: Validation configuration

    Returns:
        Validated query parameters

    Raises:
        InputValidationError: If validation fails
    """
    if config is None:
        config = ValidationConfig()

    params = dict(request.query_params)

    # Check for unexpected parameters
    if config.reject_additional_fields:
        extra_params = set(params.keys()) - allowed_params
        if extra_params:
            raise InputValidationError(f"Unexpected query parameters: {', '.join(extra_params)}")

    # Validate each parameter value
    validated_params = {}
    for key, value in params.items():
        if key in allowed_params:
            # Basic string validation for query params
            rule = FieldValidationRule(
                field_name=key,
                field_type=str,
                max_length=1000,  # Reasonable limit for query params
                check_sql_injection=True,
                check_xss=True,
            )
            validated_params[key] = validate_string_field(value, rule, config)

    return validated_params


# Validation Decorators


def validate_input(
    rules: Optional[List[FieldValidationRule]] = None,
    config: Optional[ValidationConfig] = None,
    validate_json: bool = True,
    validate_query: bool = True,
    allowed_query_params: Optional[Set[str]] = None,
) -> Callable[..., Any]:
    """Decorator to validate input data for FastAPI endpoints.

    Args:
        rules: List of field validation rules
        config: Validation configuration
        validate_json: Whether to validate JSON structure
        validate_query: Whether to validate query parameters
        allowed_query_params: Set of allowed query parameter names

    Returns:
        Decorator function
    """
    if config is None:
        config = ValidationConfig()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find request object in arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            for arg in kwargs.values():
                if isinstance(arg, Request):
                    request = arg
                    break

            if request:
                # Validate query parameters
                if validate_query and allowed_query_params:
                    try:
                        validated_query = validate_query_params(
                            request,
                            allowed_query_params,
                            config,
                        )
                        # Add validated query params to request state
                        request.state.validated_query = validated_query
                    except InputValidationError as e:
                        if config.log_validation_failures:
                            logger.warning(
                                "query_validation_failed",
                                detail=str(e.detail),
                                path=request.url.path,
                            )
                        raise

                # Validate JSON body
                if validate_json and request.method in ["POST", "PUT", "PATCH"]:
                    try:
                        # Get request body
                        if hasattr(request.state, "json_body"):
                            body = request.state.json_body
                        else:
                            body = kwargs.get("body") or kwargs.get("data")

                        if body:
                            validate_json_input(body, config)

                            # Apply field rules if provided
                            if rules and isinstance(body, dict):
                                validated_data = validate_request_data(
                                    body,
                                    rules,
                                    config,
                                )
                                # Update kwargs with validated data
                                if "body" in kwargs:
                                    kwargs["body"] = validated_data
                                elif "data" in kwargs:
                                    kwargs["data"] = validated_data

                    except InputValidationError as e:
                        if config.log_validation_failures:
                            logger.warning(
                                "json_validation_failed",
                                detail=str(e.detail),
                                path=request.url.path,
                            )
                        raise

                # Also validate field rules if provided but not JSON
                elif rules and not validate_json:
                    # Check for body in kwargs
                    body = kwargs.get("body") or kwargs.get("data")
                    if body and isinstance(body, dict):
                        try:
                            validated_data = validate_request_data(
                                body,
                                rules,
                                config,
                            )
                            # Update kwargs with validated data
                            if "body" in kwargs:
                                kwargs["body"] = validated_data
                            elif "data" in kwargs:
                                kwargs["data"] = validated_data
                        except InputValidationError as e:
                            if config.log_validation_failures:
                                logger.warning(
                                    "field_validation_failed",
                                    detail=str(e.detail),
                                    path=request.url.path if request else "unknown",
                                )
                            raise

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_email_field(email: str) -> str:
    """Validate and normalize email address.

    Args:
        email: Email address to validate

    Returns:
        Normalized email address

    Raises:
        InputValidationError: If email is invalid
    """
    result = validate_email(email)
    if not result.is_valid:
        raise InputValidationError(result.errors, field="email")
    return result.cleaned_value or email  # Fallback to original if cleaned_value is None


def validate_url_field(url: str, allowed_schemes: Optional[List[str]] = None) -> str:
    """Validate URL field.

    Args:
        url: URL to validate
        allowed_schemes: Allowed URL schemes

    Returns:
        Validated URL

    Raises:
        InputValidationError: If URL is invalid
    """
    result = validate_url(url, allowed_schemes)
    if not result.is_valid:
        raise InputValidationError(result.errors, field="url")
    return result.cleaned_value or url  # Fallback to original if cleaned_value is None


def validate_ip_field(ip: str) -> str:
    """Validate IP address field.

    Args:
        ip: IP address to validate

    Returns:
        Validated IP address

    Raises:
        InputValidationError: If IP is invalid
    """
    result = validate_ip_address(ip)
    if not result.is_valid:
        raise InputValidationError(result.errors, field="ip_address")
    return result.cleaned_value or ip  # Fallback to original if cleaned_value is None


# Common validation rules
USERNAME_RULE = FieldValidationRule(
    field_name="username",
    field_type=str,
    min_length=3,
    max_length=50,
    pattern=r"^[a-zA-Z0-9_-]+$",
    error_message="Username must be 3-50 characters, alphanumeric with - and _",
)

PASSWORD_RULE = FieldValidationRule(
    field_name="password",
    field_type=str,
    min_length=8,
    max_length=128,
    check_sql_injection=False,  # Passwords may contain special chars
    check_xss=False,
)

EMAIL_RULE = FieldValidationRule(
    field_name="email",
    field_type=str,
    custom_validator=lambda x: validate_email(x).is_valid,
    error_message="Invalid email format",
)

API_KEY_NAME_RULE = FieldValidationRule(
    field_name="name",
    field_type=str,
    min_length=1,
    max_length=100,
    pattern=r"^[a-zA-Z0-9\s_-]+$",
    error_message="API key name must be 1-100 characters",
)
