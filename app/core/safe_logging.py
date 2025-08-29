"""Safe logging utilities to prevent log injection vulnerabilities."""

import re
from typing import Any


def sanitize_log_value(value: Any) -> str:
    """Sanitize a value for safe logging.

    Removes potential log injection characters including:
    - Newlines and carriage returns
    - Control characters
    - ANSI escape sequences
    - Excessive whitespace

    Args:
        value: Value to sanitize

    Returns:
        Sanitized string safe for logging
    """
    if value is None:
        return "None"

    # Convert to string and limit length to prevent log flooding
    str_value = str(value)[:500]

    # Remove newlines and carriage returns that could split log entries
    str_value = re.sub(r"[\r\n]", " ", str_value)

    # Remove ANSI escape sequences
    str_value = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str_value)

    # Remove other control characters except space and tab
    str_value = re.sub(r"[\x00-\x08\x0B-\x1F\x7F]", "", str_value)

    # Normalize whitespace
    str_value = re.sub(r"\s+", " ", str_value).strip()

    return str_value


def safe_log_dict(data: dict[str, Any]) -> dict[str, str]:
    """Sanitize all values in a dictionary for safe logging.

    Args:
        data: Dictionary with potentially unsafe values

    Returns:
        Dictionary with all values sanitized
    """
    return {key: sanitize_log_value(value) for key, value in data.items()}


def safe_user_id(user_id: Any) -> str:
    """Safely format a user ID for logging.

    Args:
        user_id: User ID value

    Returns:
        Safely formatted user ID
    """
    sanitized = sanitize_log_value(user_id)

    # Additional validation for user IDs - should be UUID-like or alphanumeric
    if re.match(r"^[a-fA-F0-9-]+$", sanitized):
        return sanitized
    elif re.match(r"^[a-zA-Z0-9_-]+$", sanitized):
        return sanitized
    else:
        return "invalid_format"


def safe_error_message(error: Exception) -> str:
    """Safely format an error message for logging.

    Args:
        error: Exception object

    Returns:
        Safe error message without sensitive details
    """
    error_type = type(error).__name__
    error_msg = sanitize_log_value(str(error))

    # Truncate very long error messages
    if len(error_msg) > 200:
        error_msg = error_msg[:200] + "..."

    return f"{error_type}: {error_msg}"
