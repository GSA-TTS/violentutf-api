"""Circuit breaker pattern implementation for resilient service calls."""

import asyncio
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, Optional, TypeVar, Union, cast

from structlog.stdlib import get_logger

T = TypeVar("T")

logger = get_logger(__name__)


class CircuitState(enum.Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit is open, calls fail fast
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""

    failure_threshold: int = 5  # Number of failures to open circuit
    recovery_timeout: float = 60.0  # Time to wait before trying half-open
    success_threshold: int = 3  # Successes needed in half-open to close
    timeout: float = 30.0  # Timeout for individual calls
    expected_exception: type = Exception  # Exception type that counts as failure


@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics."""

    failure_count: int = 0
    success_count: int = 0
    total_requests: int = 0
    last_failure_time: Optional[float] = None
    state_changed_time: float = field(default_factory=time.time)
    consecutive_successes: int = 0


class CircuitBreakerException(Exception):
    """Exception raised when circuit breaker is open."""

    def __init__(self: "CircuitBreakerException", message: str, circuit_name: str) -> None:
        """Initialize circuit breaker exception."""
        super().__init__(message)
        self.circuit_name = circuit_name


# Alias for backward compatibility
CircuitBreakerOpenError = CircuitBreakerException


class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance.

    Implements the circuit breaker pattern to prevent cascading failures
    by monitoring service calls and opening the circuit when failures exceed
    a threshold.
    """

    def __init__(self: "CircuitBreaker", name: str, config: Optional[CircuitBreakerConfig] = None) -> None:
        """
        Initialize circuit breaker.

        Args:
            name: Name of the circuit breaker for logging
            config: Circuit breaker configuration
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()

        logger.info(
            "Circuit breaker initialized",
            name=self.name,
            failure_threshold=self.config.failure_threshold,
            recovery_timeout=self.config.recovery_timeout,
        )

    async def _check_state_transitions(self: "CircuitBreaker") -> None:
        """Check and perform state transitions."""
        if self.state == CircuitState.CLOSED:
            if (
                self.stats.failure_count >= self.config.failure_threshold
                and self.stats.last_failure_time
                and time.time() - self.stats.last_failure_time < self.config.recovery_timeout
            ):
                await self._open_circuit()
        elif self.state == CircuitState.OPEN:
            if (
                self.stats.last_failure_time
                and time.time() - self.stats.last_failure_time >= self.config.recovery_timeout
            ):
                await self._half_open_circuit()

    async def call(
        self: "CircuitBreaker",
        func: Union[Callable[..., Coroutine[Any, Any, T]], Callable[..., T]],
        *args: object,
        **kwargs: object,
    ) -> T:
        """
        Execute a function through the circuit breaker.

        Args:
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            Result of the function call

        Raises:
            CircuitBreakerException: If circuit is open
            Original exception: If function fails and circuit should track it
        """
        async with self._lock:
            self.stats.total_requests += 1
            await self._check_state_transitions()

            # Fail fast if circuit is open
            if self.state == CircuitState.OPEN:
                raise CircuitBreakerException(f"Circuit breaker '{self.name}' is open", self.name)

        # Execute the function
        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
            else:
                result = func(*args, **kwargs)

            await self._on_success()
            return cast(T, result)

        except asyncio.TimeoutError as e:
            await self._on_failure(e)
            raise
        except Exception as e:
            if isinstance(e, self.config.expected_exception):
                await self._on_failure(e)
                raise
            else:
                # Don't count unexpected exceptions as circuit breaker failures
                logger.warning(
                    "Unexpected exception in circuit breaker",
                    name=self.name,
                    exception=str(e),
                    exception_type=type(e).__name__,
                )
                raise

    async def _on_success(self: "CircuitBreaker") -> None:
        """Handle successful function execution."""
        async with self._lock:
            self.stats.success_count += 1
            self.stats.consecutive_successes += 1

            if self.state == CircuitState.HALF_OPEN:
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    await self._close_circuit()

            logger.debug(
                "Circuit breaker success",
                name=self.name,
                state=self.state.value,
                consecutive_successes=self.stats.consecutive_successes,
            )

    async def _on_failure(self: "CircuitBreaker", exception: Exception) -> None:
        """Handle failed function execution."""
        async with self._lock:
            self.stats.failure_count += 1
            self.stats.consecutive_successes = 0
            self.stats.last_failure_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                await self._open_circuit()
            elif self.state == CircuitState.CLOSED and self.stats.failure_count >= self.config.failure_threshold:
                await self._open_circuit()

            logger.warning(
                "Circuit breaker failure",
                name=self.name,
                state=self.state.value,
                failure_count=self.stats.failure_count,
                exception=str(exception),
            )

    async def _open_circuit(self: "CircuitBreaker") -> None:
        """Open the circuit breaker."""
        if self.state != CircuitState.OPEN:
            self.state = CircuitState.OPEN
            self.stats.state_changed_time = time.time()

            logger.warning(
                "Circuit breaker opened",
                name=self.name,
                failure_count=self.stats.failure_count,
                threshold=self.config.failure_threshold,
            )

    async def _close_circuit(self: "CircuitBreaker") -> None:
        """Close the circuit breaker."""
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED
            self.stats.state_changed_time = time.time()
            self.stats.failure_count = 0  # Reset failure count

            logger.info(
                "Circuit breaker closed", name=self.name, consecutive_successes=self.stats.consecutive_successes
            )

    async def _half_open_circuit(self: "CircuitBreaker") -> None:
        """Set circuit breaker to half-open state."""
        if self.state != CircuitState.HALF_OPEN:
            self.state = CircuitState.HALF_OPEN
            self.stats.state_changed_time = time.time()
            self.stats.consecutive_successes = 0

            time_since_open = time.time() - self.stats.last_failure_time if self.stats.last_failure_time else 0
            logger.info(
                "Circuit breaker half-opened",
                name=self.name,
                time_since_open=time_since_open,
            )

    def get_stats(self: "CircuitBreaker") -> Dict[str, Any]:
        """
        Get current circuit breaker statistics.

        Returns:
            Dictionary with circuit breaker stats
        """
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "total_requests": self.stats.total_requests,
            "consecutive_successes": self.stats.consecutive_successes,
            "last_failure_time": self.stats.last_failure_time,
            "state_changed_time": self.stats.state_changed_time,
            "uptime_seconds": time.time() - self.stats.state_changed_time,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
            },
        }

    async def reset(self: "CircuitBreaker") -> None:
        """Reset circuit breaker to closed state."""
        async with self._lock:
            self.state = CircuitState.CLOSED
            self.stats = CircuitBreakerStats()

            logger.info("Circuit breaker reset", name=self.name)

    def is_closed(self: "CircuitBreaker") -> bool:
        """Check if circuit breaker is closed (normal operation)."""
        return self.state == CircuitState.CLOSED

    def is_open(self: "CircuitBreaker") -> bool:
        """Check if circuit breaker is open (failing fast)."""
        return self.state == CircuitState.OPEN

    def is_half_open(self: "CircuitBreaker") -> bool:
        """Check if circuit breaker is half-open (testing recovery)."""
        return self.state == CircuitState.HALF_OPEN


# Global circuit breaker registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """
    Get or create a circuit breaker by name.

    Args:
        name: Circuit breaker name
        config: Configuration (only used for new circuit breakers)

    Returns:
        Circuit breaker instance
    """
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, config)

    return _circuit_breakers[name]


def with_circuit_breaker(
    name: str, config: Optional[CircuitBreakerConfig] = None
) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
    """
    Wrap functions with circuit breaker protection.

    Args:
        name: Circuit breaker name
        config: Circuit breaker configuration

    Usage:
        @with_circuit_breaker("external_api")
        async def call_external_api():
            # Function that might fail
            pass
    """

    def decorator(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        circuit_breaker = get_circuit_breaker(name, config)

        async def wrapper(*args: object, **kwargs: object) -> T:
            return await circuit_breaker.call(func, *args, **kwargs)

        return cast(Callable[..., Coroutine[Any, Any, T]], wrapper)

    return decorator


async def get_all_circuit_breaker_stats() -> Dict[str, Dict[str, Any]]:
    """
    Get statistics for all registered circuit breakers.

    Returns:
        Dictionary mapping circuit breaker names to their stats
    """
    return {name: cb.get_stats() for name, cb in _circuit_breakers.items()}


async def reset_all_circuit_breakers() -> None:
    """Reset all registered circuit breakers."""
    for circuit_breaker in _circuit_breakers.values():
        await circuit_breaker.reset()

    logger.info("All circuit breakers reset", count=len(_circuit_breakers))
