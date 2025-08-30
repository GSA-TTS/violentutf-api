"""Enhanced field sanitization framework for ViolentUTF API.

This module provides comprehensive field-level sanitization with configurable
rules and integration with the input validation framework.
"""

import re
from collections.abc import MutableMapping
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field
from structlog.stdlib import get_logger

from ..utils.sanitization import (
    remove_sensitive_data,
    sanitize_ai_prompt,
    sanitize_filename,
    sanitize_html,
    sanitize_json_keys,
    sanitize_log_output,
    sanitize_sql_input,
    sanitize_string,
    sanitize_url,
)

logger = get_logger(__name__)


class SanitizationType(str, Enum):
    """Types of sanitization to apply."""

    HTML = "html"
    SQL = "sql"
    FILENAME = "filename"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    LOG = "log"
    JSON_KEYS = "json_keys"
    AI_PROMPT = "ai_prompt"
    GENERAL = "general"
    CUSTOM = "custom"


class SanitizationLevel(str, Enum):
    """Sanitization strictness levels."""

    STRICT = "strict"  # Maximum sanitization
    MODERATE = "moderate"  # Balanced sanitization
    LENIENT = "lenient"  # Minimal sanitization
    NONE = "none"  # No sanitization


class FieldSanitizationRule(BaseModel):
    """Configuration for field sanitization rules."""

    field_name: str
    sanitization_types: List[SanitizationType] = Field(default_factory=list)
    level: SanitizationLevel = SanitizationLevel.MODERATE
    max_length: Optional[int] = None
    strip_html: bool = True
    strip_sql: bool = True
    strip_js: bool = True
    allow_html_tags: Optional[Set[str]] = None
    allow_url_schemes: Optional[List[str]] = None
    custom_sanitizer: Optional[Callable[[Any], Any]] = None
    remove_patterns: Optional[List[str]] = None
    preserve_case: bool = False
    trim_whitespace: bool = True


class SanitizationConfig(BaseModel):
    """Configuration for sanitization behavior."""

    default_level: SanitizationLevel = SanitizationLevel.MODERATE
    max_string_length: int = 10000
    max_filename_length: int = 255
    max_url_length: int = 2048
    strip_null_bytes: bool = True
    normalize_unicode: bool = True
    log_sanitization: bool = True
    fail_on_error: bool = False


class SanitizationResult(BaseModel):
    """Result of sanitization operation."""

    original_value: Any
    sanitized_value: Any
    applied_rules: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


def sanitize_email_field(email: str, level: SanitizationLevel = SanitizationLevel.MODERATE) -> str:
    """Sanitize email address field.

    Args:
        email: Email address to sanitize
        level: Sanitization level

    Returns:
        Sanitized email address
    """
    if not email or not isinstance(email, str):
        return ""

    # Remove whitespace
    email = email.strip().lower()

    # Remove dangerous characters but keep valid email chars
    if level == SanitizationLevel.STRICT:
        # Only allow alphanumeric, @, ., -, _
        email = re.sub(r"[^a-zA-Z0-9@.\-_+]", "", email)
    else:
        # Remove obvious dangerous patterns
        email = re.sub(r"[<>\"';\\]", "", email)

    # Validate basic email structure
    if "@" not in email or len(email) < 3:
        return ""

    # Limit length
    if len(email) > 254:  # RFC 5321
        email = email[:254]

    return email


def sanitize_phone_field(phone: str, level: SanitizationLevel = SanitizationLevel.MODERATE) -> str:
    """Sanitize phone number field.

    Args:
        phone: Phone number to sanitize
        level: Sanitization level

    Returns:
        Sanitized phone number
    """
    if not phone or not isinstance(phone, str):
        return ""

    # Remove all non-numeric except common separators
    if level == SanitizationLevel.STRICT:
        # Only keep numbers
        phone = re.sub(r"[^0-9]", "", phone)
    else:
        # Keep numbers and common separators
        phone = re.sub(r"[^0-9+\-().\s]", "", phone)

    # Remove excessive separators
    phone = re.sub(r"[\-().\s]+", " ", phone).strip()

    # Limit length (international numbers can be up to 15 digits)
    if len(phone) > 20:
        phone = phone[:20]

    return phone


def sanitize_field(
    value: Any,
    rule: FieldSanitizationRule,
    config: Optional[SanitizationConfig] = None,
) -> SanitizationResult:
    """Sanitize a field according to its rules.

    Args:
        value: Value to sanitize
        rule: Sanitization rule configuration
        config: Sanitization configuration

    Returns:
        SanitizationResult with sanitized value and metadata
    """
    if config is None:
        config = SanitizationConfig()

    result = SanitizationResult(
        original_value=value,
        sanitized_value=value,
    )

    # Skip if level is NONE
    if rule.level == SanitizationLevel.NONE:
        return result

    try:
        # Apply custom sanitizer first if provided
        if rule.custom_sanitizer:
            value = rule.custom_sanitizer(value)
            result.applied_rules.append("custom_sanitizer")

        # Convert to string for text sanitization
        if not isinstance(value, str):
            if value is None:
                result.sanitized_value = None
                return result
            value = str(value)

        # Strip null bytes if configured
        if config.strip_null_bytes:
            value = value.replace("\x00", "")

        # Apply sanitization types in order
        for sanitization_type in rule.sanitization_types:
            if sanitization_type == SanitizationType.HTML:
                value = sanitize_html(
                    value,
                    allowed_tags=rule.allow_html_tags,
                    strip_dangerous=rule.strip_html,
                )
                result.applied_rules.append("html_sanitization")

            elif sanitization_type == SanitizationType.SQL:
                if rule.strip_sql:
                    value = sanitize_sql_input(value)
                    result.applied_rules.append("sql_sanitization")

            elif sanitization_type == SanitizationType.FILENAME:
                value = sanitize_filename(
                    value,
                    max_length=rule.max_length or config.max_filename_length,
                )
                result.applied_rules.append("filename_sanitization")

            elif sanitization_type == SanitizationType.URL:
                sanitized_url = sanitize_url(value, allowed_schemes=rule.allow_url_schemes)
                if sanitized_url is None:
                    result.warnings.append(f"Invalid URL detected: {value[:50]}...")
                    value = ""
                else:
                    value = sanitized_url
                result.applied_rules.append("url_sanitization")

            elif sanitization_type == SanitizationType.EMAIL:
                value = sanitize_email_field(value, level=rule.level)
                result.applied_rules.append("email_sanitization")

            elif sanitization_type == SanitizationType.PHONE:
                value = sanitize_phone_field(value, level=rule.level)
                result.applied_rules.append("phone_sanitization")

            elif sanitization_type == SanitizationType.LOG:
                value = sanitize_log_output(
                    value,
                    max_length=rule.max_length or config.max_string_length,
                )
                result.applied_rules.append("log_sanitization")

            elif sanitization_type == SanitizationType.AI_PROMPT:
                value = sanitize_ai_prompt(
                    value,
                    max_length=rule.max_length or 50000,
                )
                result.applied_rules.append("ai_prompt_sanitization")

            elif sanitization_type == SanitizationType.GENERAL:
                value = sanitize_string(
                    value,
                    max_length=rule.max_length or config.max_string_length,
                    allow_html=not rule.strip_html,
                    strip_sql=rule.strip_sql,
                    strip_js=rule.strip_js,
                )
                result.applied_rules.append("general_sanitization")

        # Apply additional pattern removal
        if rule.remove_patterns:
            for pattern in rule.remove_patterns:
                value = re.sub(pattern, "", value, flags=re.IGNORECASE)
            result.applied_rules.append("pattern_removal")

        # Apply length limit
        if rule.max_length and len(value) > rule.max_length:
            value = value[: rule.max_length]
            result.warnings.append(f"Value truncated to {rule.max_length} characters")

        # Handle whitespace
        if rule.trim_whitespace:
            value = value.strip()

        # Handle case preservation
        if not rule.preserve_case and rule.level == SanitizationLevel.STRICT:
            value = value.lower()

        result.sanitized_value = value

        if config.log_sanitization and value != result.original_value:
            logger.debug(
                "field_sanitized",
                field=rule.field_name,
                original_length=(len(str(result.original_value)) if result.original_value else 0),
                sanitized_length=len(value),
                rules_applied=result.applied_rules,
            )

    except Exception as e:
        error_msg = f"Sanitization failed for field {rule.field_name}: {str(e)}"
        result.errors.append(error_msg)
        logger.error("sanitization_error", field=rule.field_name, error=str(e))

        if config.fail_on_error:
            raise ValueError(error_msg) from e
        else:
            # Return original value on error
            result.sanitized_value = result.original_value

    return result


def sanitize_request_data(
    data: Dict[str, Any],
    rules: List[FieldSanitizationRule],
    config: Optional[SanitizationConfig] = None,
) -> Dict[str, Any]:
    """Sanitize request data according to rules.

    Args:
        data: Request data dictionary
        rules: List of field sanitization rules
        config: Sanitization configuration

    Returns:
        Dictionary with sanitized values
    """
    if config is None:
        config = SanitizationConfig()

    sanitized_data = {}
    field_rules = {rule.field_name: rule for rule in rules}

    for key, value in data.items():
        if key in field_rules:
            # Apply specific rule
            result = sanitize_field(value, field_rules[key], config)
            sanitized_data[key] = result.sanitized_value
        else:
            # Apply default sanitization for unknown fields
            if config.default_level != SanitizationLevel.NONE:
                default_rule = FieldSanitizationRule(
                    field_name=key,
                    sanitization_types=[SanitizationType.GENERAL],
                    level=config.default_level,
                )
                result = sanitize_field(value, default_rule, config)
                sanitized_data[key] = result.sanitized_value
            else:
                # No sanitization for unknown fields
                sanitized_data[key] = value

    return sanitized_data


# Common sanitization rules
USERNAME_SANITIZATION = FieldSanitizationRule(
    field_name="username",
    sanitization_types=[SanitizationType.GENERAL],
    level=SanitizationLevel.MODERATE,
    max_length=50,
    strip_html=True,
    strip_sql=True,
    remove_patterns=[r"[^a-zA-Z0-9_\-]"],  # Only alphanumeric, underscore, hyphen
)

EMAIL_SANITIZATION = FieldSanitizationRule(
    field_name="email",
    sanitization_types=[SanitizationType.EMAIL],
    level=SanitizationLevel.MODERATE,
    max_length=254,
)

PHONE_SANITIZATION = FieldSanitizationRule(
    field_name="phone",
    sanitization_types=[SanitizationType.PHONE],
    level=SanitizationLevel.MODERATE,
    max_length=20,
)

URL_SANITIZATION = FieldSanitizationRule(
    field_name="url",
    sanitization_types=[SanitizationType.URL],
    level=SanitizationLevel.STRICT,
    allow_url_schemes=["http", "https"],
    max_length=2048,
)

FILENAME_SANITIZATION = FieldSanitizationRule(
    field_name="filename",
    sanitization_types=[SanitizationType.FILENAME],
    level=SanitizationLevel.STRICT,
    max_length=255,
)

COMMENT_SANITIZATION = FieldSanitizationRule(
    field_name="comment",
    sanitization_types=[SanitizationType.HTML, SanitizationType.SQL],
    level=SanitizationLevel.MODERATE,
    max_length=1000,
    allow_html_tags={"p", "br", "strong", "em"},
)

AI_PROMPT_SANITIZATION = FieldSanitizationRule(
    field_name="prompt",
    sanitization_types=[SanitizationType.AI_PROMPT],
    level=SanitizationLevel.STRICT,
    max_length=50000,
)


def create_sanitization_middleware(
    rules: List[FieldSanitizationRule],
    config: Optional[SanitizationConfig] = None,
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Create a sanitization middleware function.

    Args:
        rules: List of field sanitization rules
        config: Sanitization configuration

    Returns:
        Middleware function that sanitizes data
    """

    def middleware(data: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_request_data(data, rules, config)

    return middleware
