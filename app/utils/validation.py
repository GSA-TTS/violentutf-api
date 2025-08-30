"""Input validation utilities for security and AI applications."""

import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from pydantic import BaseModel, ValidationError, validator
from structlog.stdlib import get_logger

logger = get_logger(__name__)

# Common validation patterns
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_%+-]+(?:\.[a-zA-Z0-9_%+-]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")
URL_PATTERN = re.compile(r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$")
IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

# Security validation patterns
SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b)",
    r"(\bunion\b.*\bselect\b)",
    r"(\b(OR|AND)\b.*=)",  # Changed to detect OR/AND with equals
    r'([\'";].*(--))',
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
]

# Prompt injection patterns for AI safety
PROMPT_INJECTION_PATTERNS = [
    r"ignore.*(previous|above|system)",
    r"forget.*(instructions|prompt)",
    r"act\s+as\s+(admin|root|developer)",
    r"system:\s*",
    r"jailbreak",
    r"developer\s+mode",
]


class ValidationResult(BaseModel):
    """Result of validation operation."""

    is_valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    cleaned_value: Optional[str] = None


def validate_email(email: str) -> ValidationResult:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        ValidationResult with validation outcome
    """
    if not email or not isinstance(email, str):
        return ValidationResult(is_valid=False, errors=["Email must be a non-empty string"])

    email = email.strip().lower()

    if len(email) > 254:  # RFC 5321 limit
        return ValidationResult(is_valid=False, errors=["Email address too long (max 254 characters)"])

    if EMAIL_PATTERN.match(email):
        return ValidationResult(is_valid=True, cleaned_value=email)

    return ValidationResult(is_valid=False, errors=["Invalid email format"])


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> ValidationResult:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        allowed_schemes: List of allowed schemes (default: ['http', 'https'])

    Returns:
        ValidationResult with validation outcome
    """
    if not url or not isinstance(url, str):
        return ValidationResult(is_valid=False, errors=["URL must be a non-empty string"])

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    try:
        parsed = urlparse(url.strip())

        if not parsed.scheme:
            return ValidationResult(is_valid=False, errors=["URL missing scheme"])

        if parsed.scheme.lower() not in allowed_schemes:
            return ValidationResult(
                is_valid=False,
                errors=[f"URL scheme '{parsed.scheme}' not allowed. Allowed: {allowed_schemes}"],
            )

        if not parsed.netloc:
            return ValidationResult(is_valid=False, errors=["URL missing domain"])

        return ValidationResult(is_valid=True, cleaned_value=url.strip())

    except Exception:
        return ValidationResult(is_valid=False, errors=["Invalid URL format"])


def validate_ip_address(ip: str) -> ValidationResult:
    """
    Validate IPv4 address format.

    Args:
        ip: IP address to validate

    Returns:
        ValidationResult with validation outcome
    """
    if not ip or not isinstance(ip, str):
        return ValidationResult(is_valid=False, errors=["IP address must be a non-empty string"])

    ip = ip.strip()

    if not IPV4_PATTERN.match(ip):
        return ValidationResult(is_valid=False, errors=["Invalid IPv4 address format"])

    # Check each octet
    octets = ip.split(".")
    for octet in octets:
        # Check for leading zeros (except "0" itself)
        if len(octet) > 1 and octet[0] == "0":
            return ValidationResult(
                is_valid=False,
                errors=[f"Invalid octet format: {octet} (leading zeros not allowed)"],
            )
        try:
            num = int(octet)
            if num < 0 or num > 255:
                return ValidationResult(
                    is_valid=False,
                    errors=[f"Invalid octet value: {num} (must be 0-255)"],
                )
        except ValueError:
            return ValidationResult(is_valid=False, errors=[f"Invalid octet format: {octet}"])

    return ValidationResult(is_valid=True, cleaned_value=ip)


def check_sql_injection(input_text: str) -> ValidationResult:
    """
    Check input for potential SQL injection patterns.

    Args:
        input_text: Text to check for SQL injection

    Returns:
        ValidationResult with security assessment
    """
    if not input_text or not isinstance(input_text, str):
        return ValidationResult(is_valid=True)

    text_lower = input_text.lower()
    warnings = []

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            warnings.append(f"Potential SQL injection pattern detected")
            logger.warning(
                "SQL injection pattern detected",
                pattern=pattern,
                input_sample=input_text[:100],
            )

    return ValidationResult(is_valid=len(warnings) == 0, warnings=warnings)


def check_xss_injection(input_text: str) -> ValidationResult:
    """
    Check input for potential XSS injection patterns.

    Args:
        input_text: Text to check for XSS injection

    Returns:
        ValidationResult with security assessment
    """
    if not input_text or not isinstance(input_text, str):
        return ValidationResult(is_valid=True)

    warnings = []

    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_text, re.IGNORECASE):
            warnings.append(f"Potential XSS pattern detected")
            logger.warning("XSS pattern detected", pattern=pattern, input_sample=input_text[:100])

    return ValidationResult(is_valid=len(warnings) == 0, warnings=warnings)


def check_prompt_injection(prompt_text: str) -> ValidationResult:
    """
    Check AI prompt for potential injection attacks.

    Args:
        prompt_text: AI prompt text to validate

    Returns:
        ValidationResult with security assessment
    """
    if not prompt_text or not isinstance(prompt_text, str):
        return ValidationResult(is_valid=True)

    text_lower = prompt_text.lower()
    warnings = []

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            warnings.append(f"Potential prompt injection pattern detected")
            logger.warning(
                "Prompt injection pattern detected",
                pattern=pattern,
                input_sample=prompt_text[:100],
            )

    return ValidationResult(is_valid=len(warnings) == 0, warnings=warnings)


def _count_dict_keys_and_depth(obj: Dict[str, Any], current_depth: int, max_depth: int) -> tuple[int, int]:
    """Count keys and depth in a dictionary."""
    if current_depth > max_depth:
        return 0, current_depth

    key_count = len(obj)
    max_depth_found = current_depth

    for value in obj.values():
        sub_keys, sub_depth = _count_keys_and_depth(value, current_depth + 1, max_depth)
        key_count += sub_keys
        max_depth_found = max(max_depth_found, sub_depth)

    return key_count, max_depth_found


def _count_list_keys_and_depth(items: List[Any], current_depth: int, max_depth: int) -> tuple[int, int]:
    """Count keys and depth in a list."""
    if current_depth > max_depth:
        return 0, current_depth

    key_count = 0
    max_depth_found = current_depth

    for item in items:
        sub_keys, sub_depth = _count_keys_and_depth(item, current_depth + 1, max_depth)
        key_count += sub_keys
        max_depth_found = max(max_depth_found, sub_depth)

    return key_count, max_depth_found


def _count_keys_and_depth(obj: object, current_depth: int, max_depth: int) -> tuple[int, int]:
    """Count total keys and maximum depth in nested structure."""
    if current_depth > max_depth:
        return 0, current_depth

    if isinstance(obj, dict):
        return _count_dict_keys_and_depth(obj, current_depth, max_depth)
    elif isinstance(obj, list):
        return _count_list_keys_and_depth(obj, current_depth, max_depth)

    return 0, current_depth


def validate_json_payload(payload: object, max_depth: int = 10, max_keys: int = 1000) -> ValidationResult:
    """
    Validate JSON payload for security and size constraints.

    Args:
        payload: JSON payload to validate
        max_depth: Maximum nesting depth allowed
        max_keys: Maximum number of keys allowed

    Returns:
        ValidationResult with validation outcome
    """
    errors = []
    warnings = []

    try:
        total_keys, depth = _count_keys_and_depth(payload, 0, max_depth)

        if depth > max_depth:
            errors.append(f"JSON nesting too deep: {depth} (max {max_depth})")

        if total_keys > max_keys:
            errors.append(f"Too many keys in JSON: {total_keys} (max {max_keys})")

        if total_keys > max_keys * 0.8:  # Warning at 80% of limit
            warnings.append(f"High number of keys in JSON: {total_keys}")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    except Exception:
        return ValidationResult(is_valid=False, errors=["Invalid JSON format"])


def validate_input_length(
    input_text: Optional[str],
    min_length: int = 0,
    max_length: int = 10000,
    field_name: str = "input",
) -> ValidationResult:
    """
    Validate input text length constraints.

    Args:
        input_text: Text to validate
        min_length: Minimum required length
        max_length: Maximum allowed length
        field_name: Name of field for error messages

    Returns:
        ValidationResult with validation outcome
    """
    if input_text is None:
        input_text = ""

    if not isinstance(input_text, str):
        return ValidationResult(is_valid=False, errors=[f"{field_name} must be a string"])  # type: ignore[unreachable]

    length = len(input_text)
    errors = []
    warnings = []

    if length < min_length:
        errors.append(f"{field_name} too short: {length} chars (min {min_length})")

    if length > max_length:
        errors.append(f"{field_name} too long: {length} chars (max {max_length})")

    # Warning at 90% of max length
    if length > max_length * 0.9:
        warnings.append(f"{field_name} approaching length limit: {length} chars")

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        cleaned_value=input_text.strip() if input_text else "",
    )


def comprehensive_input_validation(
    input_text: str,
    check_sql: bool = True,
    check_xss: bool = True,
    check_prompt_injection_flag: bool = False,
    max_length: int = 10000,
    field_name: str = "input",
) -> ValidationResult:
    """
    Perform comprehensive validation on input text.

    Args:
        input_text: Text to validate
        check_sql: Whether to check for SQL injection
        check_xss: Whether to check for XSS injection
        check_prompt_injection_flag: Whether to check for prompt injection
        max_length: Maximum allowed length
        field_name: Name of field for error messages

    Returns:
        ValidationResult with comprehensive assessment
    """
    all_errors = []
    all_warnings = []

    # Length validation
    length_result = validate_input_length(input_text, max_length=max_length, field_name=field_name)
    all_errors.extend(length_result.errors)
    all_warnings.extend(length_result.warnings)

    if not length_result.is_valid:
        return ValidationResult(is_valid=False, errors=all_errors, warnings=all_warnings)

    # Security checks
    if check_sql:
        sql_result = check_sql_injection(input_text)
        all_warnings.extend(sql_result.warnings)
        if not sql_result.is_valid:
            all_errors.extend(sql_result.errors)

    if check_xss:
        xss_result = check_xss_injection(input_text)
        all_warnings.extend(xss_result.warnings)
        if not xss_result.is_valid:
            all_errors.extend(xss_result.errors)

    if check_prompt_injection_flag:
        prompt_result = check_prompt_injection(input_text)
        all_warnings.extend(prompt_result.warnings)
        if not prompt_result.is_valid:
            all_errors.extend(prompt_result.errors)

    return ValidationResult(
        is_valid=len(all_errors) == 0,
        errors=all_errors,
        warnings=all_warnings,
        cleaned_value=input_text.strip() if input_text else "",
    )
