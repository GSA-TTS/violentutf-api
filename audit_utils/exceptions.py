"""Shared exception handling utilities for audit automation scripts."""

import functools
import inspect
from typing import Any, Callable, Dict, Optional, TypeVar

import structlog

logger = structlog.get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class AuditError(Exception):
    """Base exception class for audit operations."""

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}


class ConfigurationError(AuditError):
    """Exception raised for configuration-related errors."""

    pass


class ValidationError(AuditError):
    """Exception raised for validation errors."""

    pass


def create_error_context(**context: Any) -> Dict[str, Any]:
    """Create error context dictionary with provided information.

    Args:
        **context: Context information for error handling

    Returns:
        Dictionary containing error context
    """
    return dict(context)


def audit_error_handler(func: F) -> F:
    """Decorator to provide standardized error handling for audit functions.

    This decorator:
    - Catches general exceptions and wraps them in AuditError
    - Preserves AuditError exceptions as-is
    - Logs exceptions with context information
    - Maintains function metadata

    Args:
        func: Function to wrap with error handling

    Returns:
        Wrapped function with error handling
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except AuditError:
            # Re-raise audit errors as-is
            raise
        except Exception as e:
            # Log the original exception
            logger.error(
                f"Error in {func.__name__}",
                error=str(e),
                error_type=type(e).__name__,
                function=func.__name__,
                module=func.__module__,
            )

            # Wrap in AuditError
            raise AuditError(
                f"Error in {func.__name__}: {str(e)}",
                context=create_error_context(
                    original_error=str(e),
                    original_error_type=type(e).__name__,
                    function=func.__name__,
                    module=func.__module__,
                ),
            ) from e

    # Handle async functions
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except AuditError:
                # Re-raise audit errors as-is
                raise
            except Exception as e:
                # Log the original exception
                logger.error(
                    f"Error in async {func.__name__}",
                    error=str(e),
                    error_type=type(e).__name__,
                    function=func.__name__,
                    module=func.__module__,
                )

                # Wrap in AuditError
                raise AuditError(
                    f"Error in {func.__name__}: {str(e)}",
                    context=create_error_context(
                        original_error=str(e),
                        original_error_type=type(e).__name__,
                        function=func.__name__,
                        module=func.__module__,
                    ),
                ) from e

        return async_wrapper  # type: ignore

    return wrapper  # type: ignore
