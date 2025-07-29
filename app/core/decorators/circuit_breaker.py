"""Decorators for circuit breaker protection."""

import functools
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, Union, cast

if TYPE_CHECKING:
    from typing import ParamSpec

    P = ParamSpec("P")
else:
    # Fallback for older Python versions
    P = TypeVar("P")

from structlog.stdlib import get_logger

from ...utils.circuit_breaker import CircuitBreakerConfig, CircuitBreakerException, get_circuit_breaker

logger = get_logger(__name__)

T = TypeVar("T")


def protect_with_circuit_breaker(
    circuit_name: str,
    config: Optional[CircuitBreakerConfig] = None,
    fallback: Optional[Callable[..., Any]] = None,
    log_errors: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator to protect functions with circuit breaker.

    Args:
        circuit_name: Name of the circuit breaker
        config: Circuit breaker configuration
        fallback: Optional fallback function to call when circuit is open
        log_errors: Whether to log errors

    Returns:
        Decorator function

    Example:
        ```python
        @protect_with_circuit_breaker(
            "payment_service",
            config=CircuitBreakerConfig(failure_threshold=3),
            fallback=lambda: {"status": "service_unavailable"}
        )
        async def process_payment(amount: float) -> dict:
            # Call external payment service
            return await payment_api.charge(amount)
        ```
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        circuit_breaker = get_circuit_breaker(circuit_name, config)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return await circuit_breaker.call(func, *args, **kwargs)
            except CircuitBreakerException as e:
                if log_errors:
                    logger.warning(
                        "circuit_breaker_open",
                        circuit_name=circuit_name,
                        function=func.__name__,
                        error=str(e),
                    )

                if fallback:
                    logger.info(
                        "using_fallback",
                        circuit_name=circuit_name,
                        function=func.__name__,
                    )
                    result = fallback(*args, **kwargs)
                    return cast(T, result)
                raise
            except Exception as e:
                if log_errors:
                    logger.error(
                        "circuit_breaker_error",
                        circuit_name=circuit_name,
                        function=func.__name__,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            # For sync functions, convert to async and run
            import asyncio

            async def _async_func(*args: Any, **kwargs: Any) -> T:
                return func(*args, **kwargs)

            loop = asyncio.new_event_loop()
            try:
                # Cast to Any to avoid type issues
                result: Any = loop.run_until_complete(
                    circuit_breaker.call(_async_func, *args, **kwargs)  # type: ignore[arg-type]
                )
                return cast(T, result)
            except CircuitBreakerException as e:
                if log_errors:
                    logger.warning(
                        "circuit_breaker_open",
                        circuit_name=circuit_name,
                        function=func.__name__,
                        error=str(e),
                    )

                if fallback:
                    logger.info(
                        "using_fallback",
                        circuit_name=circuit_name,
                        function=func.__name__,
                    )
                    result = fallback(*args, **kwargs)
                    return cast(T, result)
                raise
            except Exception as e:
                if log_errors:
                    logger.error(
                        "circuit_breaker_error",
                        circuit_name=circuit_name,
                        function=func.__name__,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                raise
            finally:
                loop.close()

        # Return appropriate wrapper based on function type
        import inspect

        if inspect.iscoroutinefunction(func):
            return cast(Callable[..., T], async_wrapper)
        else:
            return cast(Callable[..., T], sync_wrapper)

    return decorator


def external_service(
    service_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    timeout: float = 30.0,
    fallback: Optional[Callable[..., Any]] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator specifically for external service calls.

    Args:
        service_name: Name of the external service
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time before trying half-open state
        timeout: Timeout for individual calls
        fallback: Fallback function when service is unavailable

    Returns:
        Decorator function

    Example:
        ```python
        @external_service(
            "weather_api",
            failure_threshold=3,
            recovery_timeout=30.0,
            fallback=lambda city: {"temp": "unknown", "conditions": "unavailable"}
        )
        async def get_weather(city: str) -> dict:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://api.weather.com/{city}")
                return response.json()
        ```
    """
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        timeout=timeout,
        expected_exception=(Exception,),  # Catch all exceptions for external services
    )

    return protect_with_circuit_breaker(
        circuit_name=f"external_{service_name}",
        config=config,
        fallback=fallback,
        log_errors=True,
    )


def database_operation(
    operation_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 30.0,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for database operations with circuit breaker.

    Args:
        operation_name: Name of the database operation
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time before trying half-open state

    Returns:
        Decorator function

    Example:
        ```python
        @database_operation("user_lookup")
        async def get_user_by_id(db: AsyncSession, user_id: int) -> User:
            return await db.get(User, user_id)
        ```
    """
    from sqlalchemy.exc import DBAPIError, DisconnectionError, OperationalError, TimeoutError

    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        expected_exception=(
            DBAPIError,
            DisconnectionError,
            OperationalError,
            TimeoutError,
            asyncio.TimeoutError,
        ),
    )

    return protect_with_circuit_breaker(
        circuit_name=f"database_{operation_name}",
        config=config,
        log_errors=True,
    )


def cache_operation(
    cache_name: str = "default",
    failure_threshold: int = 3,
    recovery_timeout: float = 10.0,
    fallback_to_none: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for cache operations with circuit breaker.

    Args:
        cache_name: Name of the cache
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time before trying half-open state
        fallback_to_none: Return None when circuit is open

    Returns:
        Decorator function

    Example:
        ```python
        @cache_operation("redis", fallback_to_none=True)
        async def get_cached_data(key: str) -> Optional[dict]:
            return await redis_client.get(key)
        ```
    """
    fallback = (lambda *args, **kwargs: None) if fallback_to_none else None

    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        expected_exception=(Exception,),  # Cache errors can vary
    )

    return protect_with_circuit_breaker(
        circuit_name=f"cache_{cache_name}",
        config=config,
        fallback=fallback,
        log_errors=True,
    )


def message_queue(
    queue_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for message queue operations with circuit breaker.

    Args:
        queue_name: Name of the message queue
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time before trying half-open state

    Returns:
        Decorator function

    Example:
        ```python
        @message_queue("rabbitmq")
        async def publish_message(message: dict) -> bool:
            return await rabbitmq.publish("events", message)
        ```
    """
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        expected_exception=(Exception,),
    )

    return protect_with_circuit_breaker(
        circuit_name=f"queue_{queue_name}",
        config=config,
        log_errors=True,
    )


# Import asyncio for type checking
import asyncio
