"""Shared logging utilities for audit automation scripts."""

import logging
import re
import time
from typing import Any, Dict, List, Optional, Union

import structlog

# Sensitive field patterns for log sanitization
SENSITIVE_PATTERNS = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "authorization",
    "auth",
    "credential",
    "credit_card",
    "ssn",
    "social_security",
    "api_key",
    "apikey",
]

# Compiled regex for case-insensitive matching - match whole words or specific patterns
SENSITIVE_REGEX = re.compile(r"(" + "|".join(SENSITIVE_PATTERNS) + r")", re.IGNORECASE)


def setup_audit_logger(name: str, level: str = "INFO") -> structlog.stdlib.BoundLogger:
    """Setup standardized audit logger with consistent format.

    Args:
        name: Logger name (typically __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured structlog logger

    Raises:
        ValueError: If log level is invalid
    """
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if level.upper() not in valid_levels:
        raise ValueError(f"Invalid log level: {level}. Must be one of {valid_levels}")

    # Configure structlog if not already configured
    if not hasattr(structlog, "_configured"):
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(colors=False),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            context_class=dict,
            cache_logger_on_first_use=True,
        )
        structlog._configured = "configured"

    # Set logging level
    logging.getLogger(name).setLevel(getattr(logging, level.upper()))

    # Get logger and ensure it's bound
    logger = structlog.get_logger(name)
    # Force binding to ensure we get the correct type
    if hasattr(logger, "bind"):
        return logger.bind()
    return logger


def log_audit_event(event_type: str, **context: Any) -> None:
    """Log a standardized audit event.

    Args:
        event_type: Type of audit event (e.g., 'user_login', 'data_access')
        **context: Additional context information
    """
    logger = structlog.get_logger("audit_events")

    # Add timestamp if not provided
    context.setdefault("timestamp", time.time())
    context["event_type"] = event_type

    # Sanitize any sensitive data
    sanitized_context = sanitize_log_data(context)

    logger.info(f"Audit event: {event_type}", **sanitized_context)


def sanitize_log_data(data: Any) -> Any:
    """Sanitize log data by removing or masking sensitive information.

    Args:
        data: Data to sanitize (dict, list, or primitive)

    Returns:
        Sanitized data with sensitive fields redacted
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if _is_sensitive_field(key) and not isinstance(value, dict):
                # Only sanitize leaf values, not nested objects
                sanitized[key] = "[REDACTED]" if value is not None else None
            else:
                sanitized[key] = sanitize_log_data(value)
        return sanitized

    elif isinstance(data, list):
        # Handle lists - sanitize individual items
        return [sanitize_log_data(item) for item in data]

    elif isinstance(data, (str, int, float, bool)) or data is None:
        # For strings, check if they look like sensitive values
        if isinstance(data, str) and _contains_sensitive_pattern(data):
            return "[REDACTED]"
        return data

    else:
        # For other types, convert to string and check if it looks sensitive
        str_data = str(data)
        if _contains_sensitive_pattern(str_data):
            return "[REDACTED]"
        return str_data


def _is_sensitive_field(field_name: str) -> bool:
    """Check if a field name indicates sensitive data.

    Args:
        field_name: Name of the field to check

    Returns:
        True if field appears to contain sensitive data
    """
    if not isinstance(field_name, str):
        return False  # type: ignore[unreachable]

    # Check exact matches and specific patterns
    field_lower = field_name.lower()

    # Exact matches for sensitive fields
    sensitive_exact = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "authorization",
        "auth",
        "credential",
        "credit_card",
        "ssn",
        "social_security",
        "api_key",
        "apikey",
    }

    if field_lower in sensitive_exact:
        return True

    # Check for patterns containing these words (but be more specific)
    sensitive_patterns = [
        "password",
        "passwd",
        "secret",
        "authorization",
        "credential",
        "credit_card",
        "ssn",
        "api_key",
    ]

    for pattern in sensitive_patterns:
        if pattern in field_lower:
            return True

    # Special case: "key" only when it's clearly about API keys or similar
    if "key" in field_lower and ("api" in field_lower or "access" in field_lower or field_lower == "key"):
        return True

    return False


def _contains_sensitive_pattern(text: str) -> bool:
    """Check if text contains sensitive patterns.

    Args:
        text: Text to check

    Returns:
        True if text contains sensitive patterns
    """
    if not isinstance(text, str):
        return False  # type: ignore[unreachable]

    text_lower = text.lower()

    # Check for token-like values (starts with "token")
    if text_lower.startswith("token"):
        return True

    # Check for common sensitive data patterns
    # Note: These are DETECTION PATTERNS for security filtering, not actual secrets  # nosec B105
    patterns = [
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card pattern detection
        r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",  # SSN pattern detection
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",  # Bearer token pattern detection
        r'api[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9]+',  # API key pattern detection
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def configure_standard_logging(
    service_name: str, environment: str = "development", json_logs: bool = True
) -> structlog.BoundLogger:
    """
    Standard logging configuration for all audit automation scripts.

    Provides consistent structured logging with security-safe formatting.

    Args:
        service_name: Name of the service/script for logging context
        environment: Environment (development, staging, production)
        json_logs: Whether to use JSON output format

    Returns:
        Configured structlog logger instance
    """
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    # Configure structlog with enhanced settings
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Set logging level based on environment
    level = "DEBUG" if environment == "development" else "INFO"
    logging.getLogger(service_name).setLevel(getattr(logging, level))

    # Get bound logger with service context
    logger = structlog.get_logger(service_name)
    return logger.bind(service=service_name, environment=environment)
