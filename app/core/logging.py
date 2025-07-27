"""Structured logging setup with security features."""

import logging
import sys
from typing import Any, Dict, MutableMapping, Optional, Union, cast

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars

from .config import settings


def add_app_context(logger: object, method_name: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Add application context to all logs."""
    event_dict["service"] = settings.PROJECT_NAME
    event_dict["environment"] = settings.ENVIRONMENT
    event_dict["version"] = settings.VERSION
    return event_dict


def sanitize_sensitive_data(
    logger: object, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Remove or mask sensitive data from logs."""
    sensitive_keys = {
        "password",
        "token",
        "api_key",
        "secret",
        "authorization",
        "cookie",
        "session",
        "credit_card",
        "ssn",
    }

    def _sanitize_dict(d: MutableMapping[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary."""
        sanitized = {}
        for key, value in d.items():
            lower_key = key.lower()
            # Check if key contains sensitive words
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = _sanitize_dict(value)  # type: ignore[assignment]
            elif isinstance(value, list):
                sanitized[key] = [_sanitize_dict(item) if isinstance(item, dict) else item for item in value]  # type: ignore[assignment]
            else:
                sanitized[key] = value
        return sanitized

    return _sanitize_dict(event_dict)


def setup_logging() -> None:
    """Configure structured logging for the application."""
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.contextvars.merge_contextvars,
            add_app_context,
            sanitize_sensitive_data,
            (
                structlog.processors.JSONRenderer()
                if settings.LOG_FORMAT == "json"
                else structlog.dev.ConsoleRenderer(colors=True)
            ),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.LOG_LEVEL),
    )

    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.INFO if settings.ENABLE_ACCESS_LOGS else logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))


def log_request_context(
    request_id: str,
    method: str,
    path: str,
    client_ip: Optional[str] = None,
    user_id: Optional[str] = None,
) -> None:
    """Bind request context for all logs in this request."""
    bind_contextvars(
        request_id=request_id,
        method=method,
        path=path,
        client_ip=client_ip,
        user_id=user_id,
    )


def clear_request_context() -> None:
    """Clear request context after request completion."""
    clear_contextvars()


def get_request_context() -> Dict[str, Any]:
    """Get current request context from context vars."""
    from structlog.contextvars import get_contextvars

    return dict(get_contextvars())


# Initialize logger for this module
logger = get_logger(__name__)
