"""Retry logic utilities for resilient external API calls."""

import asyncio
import functools
import secrets
import time
from typing import Any, Callable, Coroutine, List, Optional, Type, TypeVar, Union, cast

from structlog.stdlib import get_logger

T = TypeVar("T")

logger = get_logger(__name__)


class RetryConfig:
    """Configuration for retry behavior."""

    def __init__(
        self: "RetryConfig",
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        exceptions: Optional[Union[Type[Exception], tuple[Type[Exception], ...]]] = None,
    ) -> None:
        """
        Initialize retry configuration.

        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Base delay between retries in seconds
            max_delay: Maximum delay between retries in seconds
            exponential_base: Base for exponential backoff
            jitter: Whether to add random jitter to delays
            exceptions: Exception types to retry on (default: all exceptions)
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.exceptions = exceptions or Exception


class RetryState:
    """State tracking for retry attempts."""

    def __init__(self: "RetryState", config: RetryConfig) -> None:
        """Initialize retry state."""
        self.config = config
        self.attempt = 0
        self.total_delay = 0.0
        self.start_time = time.time()
        self.last_exception: Optional[Exception] = None


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """
    Calculate delay for a retry attempt.

    Args:
        attempt: Current attempt number (0-based)
        config: Retry configuration

    Returns:
        Delay in seconds
    """
    if attempt == 0:
        return 0.0

    # Exponential backoff
    delay = config.base_delay * (config.exponential_base ** (attempt - 1))

    # Cap at max delay
    delay = min(delay, config.max_delay)

    # Add jitter if enabled
    if config.jitter:
        jitter_range = delay * 0.1  # 10% jitter
        # Use cryptographically secure random for jitter
        jitter = secrets.randbelow(int(jitter_range * 2 * 1000)) / 1000 - jitter_range
        delay += jitter

    return max(0.0, delay)


async def _execute_with_timing(
    func: Union[Callable[..., Coroutine[Any, Any, T]], Callable[..., T]], *args: object, **kwargs: object
) -> T:
    """Execute function and return result."""
    if asyncio.iscoroutinefunction(func):
        result = await func(*args, **kwargs)
        return cast(T, result)
    else:
        result = func(*args, **kwargs)
        return cast(T, result)


async def _handle_retry_delay(attempt: int, config: RetryConfig, state: RetryState, func_name: str) -> None:
    """Handle delay between retry attempts."""
    delay = calculate_delay(attempt, config)
    if delay > 0:
        logger.debug(
            "Retrying after delay",
            attempt=attempt + 1,
            max_attempts=config.max_attempts,
            delay=delay,
            function=func_name,
        )
        await asyncio.sleep(delay)
        state.total_delay += delay


def _log_retry_outcome(attempt: int, state: RetryState, config: RetryConfig, func_name: str, duration: float) -> None:
    """Log successful retry outcome."""
    if attempt > 0:
        logger.info(
            "Retry successful",
            attempt=attempt + 1,
            total_attempts=attempt + 1,
            total_delay=state.total_delay,
            duration=duration,
            function=func_name,
        )


def _handle_retry_exception(e: Exception, attempt: int, state: RetryState, config: RetryConfig, func_name: str) -> None:
    """Handle exception during retry attempt."""
    state.last_exception = e

    if not isinstance(e, config.exceptions):
        logger.warning("Exception not configured for retry", exception_type=type(e).__name__, function=func_name)
        raise

    if attempt < config.max_attempts - 1:
        logger.warning(
            "Retry attempt failed",
            attempt=attempt + 1,
            max_attempts=config.max_attempts,
            exception=str(e),
            function=func_name,
        )
    else:
        logger.error(
            "All retry attempts failed",
            total_attempts=config.max_attempts,
            total_delay=state.total_delay,
            total_duration=time.time() - state.start_time,
            final_exception=str(e),
            function=func_name,
        )


async def retry_async(
    func: Union[Callable[..., Coroutine[Any, Any, T]], Callable[..., T]],
    config: Optional[RetryConfig] = None,
    *args: object,
    **kwargs: object,
) -> T:
    """
    Retry an async function with exponential backoff.

    Args:
        func: Async function to retry
        config: Retry configuration
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function

    Returns:
        Result of the function call

    Raises:
        Last exception if all retries fail
    """
    if config is None:
        config = RetryConfig()

    state = RetryState(config)

    for attempt in range(config.max_attempts):
        state.attempt = attempt

        await _handle_retry_delay(attempt, config, state, func.__name__)

        try:
            start_time = time.time()
            result = await _execute_with_timing(func, *args, **kwargs)
            duration = time.time() - start_time

            _log_retry_outcome(attempt, state, config, func.__name__, duration)
            return result

        except Exception as e:
            _handle_retry_exception(e, attempt, state, config, func.__name__)

    # All retries exhausted
    if state.last_exception is not None:
        raise state.last_exception
    else:
        raise RuntimeError("All retry attempts failed")


def retry_sync(func: Callable[..., T], config: Optional[RetryConfig] = None, *args: object, **kwargs: object) -> T:
    """
    Retry a synchronous function with exponential backoff.

    Args:
        func: Function to retry
        config: Retry configuration
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function

    Returns:
        Result of the function call

    Raises:
        Last exception if all retries fail
    """
    if config is None:
        config = RetryConfig()

    state = RetryState(config)

    for attempt in range(config.max_attempts):
        state.attempt = attempt
        delay = calculate_delay(attempt, config)

        if delay > 0:
            logger.debug(
                "Retrying after delay",
                attempt=attempt + 1,
                max_attempts=config.max_attempts,
                delay=delay,
                function=func.__name__,
            )
            time.sleep(delay)
            state.total_delay += delay

        try:
            start_time = time.time()
            result = func(*args, **kwargs)

            duration = time.time() - start_time
            if attempt > 0:
                logger.info(
                    "Retry successful",
                    attempt=attempt + 1,
                    total_attempts=attempt + 1,
                    total_delay=state.total_delay,
                    duration=duration,
                    function=func.__name__,
                )

            return result

        except Exception as e:
            state.last_exception = e

            # Check if this exception type should be retried
            if not isinstance(e, config.exceptions):
                logger.warning(
                    "Exception not configured for retry", exception_type=type(e).__name__, function=func.__name__
                )
                raise

            # Log the attempt
            if attempt < config.max_attempts - 1:
                logger.warning(
                    "Retry attempt failed",
                    attempt=attempt + 1,
                    max_attempts=config.max_attempts,
                    exception=str(e),
                    function=func.__name__,
                )
            else:
                logger.error(
                    "All retry attempts failed",
                    total_attempts=config.max_attempts,
                    total_delay=state.total_delay,
                    total_duration=time.time() - state.start_time,
                    final_exception=str(e),
                    function=func.__name__,
                )

    # All retries exhausted
    if state.last_exception is not None:
        raise state.last_exception
    else:
        raise RuntimeError("All retry attempts failed")


def with_retry(
    config: Optional[RetryConfig] = None,
) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
    """
    Decorate async functions for automatic retry.

    Args:
        config: Retry configuration

    Usage:
        @with_retry(RetryConfig(max_attempts=5))
        async def api_call():
            # Function that might fail
            pass
    """

    def decorator(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        @functools.wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> T:
            return await retry_async(func, config, *args, **kwargs)

        return cast(Callable[..., Coroutine[Any, Any, T]], wrapper)

    return decorator


def with_retry_sync(config: Optional[RetryConfig] = None) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorate synchronous functions for automatic retry.

    Args:
        config: Retry configuration

    Usage:
        @with_retry_sync(RetryConfig(max_attempts=3))
        def database_operation():
            # Function that might fail
            pass
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> T:
            return retry_sync(func, config, *args, **kwargs)

        return wrapper

    return decorator


# Predefined retry configurations for common scenarios
HTTP_RETRY_CONFIG = RetryConfig(max_attempts=3, base_delay=1.0, max_delay=30.0, exponential_base=2.0, jitter=True)

DATABASE_RETRY_CONFIG = RetryConfig(max_attempts=5, base_delay=0.5, max_delay=10.0, exponential_base=1.5, jitter=True)

EXTERNAL_API_RETRY_CONFIG = RetryConfig(
    max_attempts=4, base_delay=2.0, max_delay=60.0, exponential_base=2.0, jitter=True
)

QUICK_RETRY_CONFIG = RetryConfig(max_attempts=2, base_delay=0.1, max_delay=1.0, exponential_base=2.0, jitter=False)
