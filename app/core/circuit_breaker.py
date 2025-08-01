"""Circuit breaker pattern implementation for fault tolerance."""

import asyncio
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union

from structlog.stdlib import get_logger

logger = get_logger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreakerError(Exception):
    """Exception raised when circuit is open."""

    def __init__(self, message: str, service_name: str, state: CircuitState):
        """Initialize circuit breaker error."""
        super().__init__(message)
        self.service_name = service_name
        self.state = state


class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance.

    The circuit breaker has three states:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service is failing, requests are rejected immediately
    - HALF_OPEN: Testing if service has recovered
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type[Exception] = Exception,
        success_threshold: int = 2,
        exclude_exceptions: Optional[list[type[Exception]]] = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Name of the service/operation
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying half-open
            expected_exception: Exception type to count as failure
            success_threshold: Successes needed in half-open to close
            exclude_exceptions: Exceptions that don't count as failures
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.success_threshold = success_threshold
        self.exclude_exceptions = exclude_exceptions or []

        # State tracking
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._last_state_change: datetime = datetime.utcnow()

        # Metrics
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._consecutive_failures = 0
        self._consecutive_successes = 0

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (rejecting calls)."""
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self._state == CircuitState.HALF_OPEN

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Execute function through circuit breaker.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerError: If circuit is open
            Exception: If function fails
        """
        if self.is_open:
            if self._should_attempt_reset():
                self._transition_to_half_open()
            else:
                raise CircuitBreakerError(f"Circuit breaker is open for {self.name}", self.name, self._state)

        self._total_calls += 1

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    async def call_async(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Execute async function through circuit breaker.

        Args:
            func: Async function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerError: If circuit is open
            Exception: If function fails
        """
        if self.is_open:
            if self._should_attempt_reset():
                self._transition_to_half_open()
            else:
                raise CircuitBreakerError(f"Circuit breaker is open for {self.name}", self.name, self._state)

        self._total_calls += 1

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if we should try to reset from open state."""
        if self._last_failure_time:
            time_since_failure = datetime.utcnow() - self._last_failure_time
            return time_since_failure.total_seconds() >= self.recovery_timeout
        return False

    def _on_success(self) -> None:
        """Handle successful call."""
        self._total_successes += 1
        self._consecutive_successes += 1
        self._consecutive_failures = 0

        if self.is_half_open:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._transition_to_closed()
        elif self.is_closed:
            self._failure_count = 0

    def _on_failure(self, exception: Exception) -> None:
        """Handle failed call."""
        # Check if exception should be excluded
        if any(isinstance(exception, exc_type) for exc_type in self.exclude_exceptions):
            return

        # Only count expected exceptions as failures
        if not isinstance(exception, self.expected_exception):
            return

        self._total_failures += 1
        self._consecutive_failures += 1
        self._consecutive_successes = 0
        self._last_failure_time = datetime.utcnow()

        if self.is_half_open:
            self._transition_to_open()
        elif self.is_closed:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._transition_to_open()

    def _transition_to_closed(self) -> None:
        """Transition to closed state."""
        logger.info(
            "Circuit breaker closing",
            service=self.name,
            previous_state=self._state.value,
        )
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_state_change = datetime.utcnow()

    def _transition_to_open(self) -> None:
        """Transition to open state."""
        logger.warning(
            "Circuit breaker opening",
            service=self.name,
            previous_state=self._state.value,
            consecutive_failures=self._consecutive_failures,
        )
        self._state = CircuitState.OPEN
        self._last_state_change = datetime.utcnow()

    def _transition_to_half_open(self) -> None:
        """Transition to half-open state."""
        logger.info(
            "Circuit breaker half-opening",
            service=self.name,
            previous_state=self._state.value,
        )
        self._state = CircuitState.HALF_OPEN
        self._success_count = 0
        self._last_state_change = datetime.utcnow()

    def reset(self) -> None:
        """Manually reset circuit to closed state."""
        self._transition_to_closed()
        self._failure_count = 0
        self._success_count = 0
        self._consecutive_failures = 0
        self._consecutive_successes = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        uptime = (datetime.utcnow() - self._last_state_change).total_seconds()

        return {
            "name": self.name,
            "state": self._state.value,
            "state_duration_seconds": uptime,
            "total_calls": self._total_calls,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "consecutive_failures": self._consecutive_failures,
            "consecutive_successes": self._consecutive_successes,
            "failure_rate": (self._total_failures / self._total_calls if self._total_calls > 0 else 0),
            "last_failure_time": (self._last_failure_time.isoformat() if self._last_failure_time else None),
        }


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""

    def __init__(self) -> None:
        """Initialize registry."""
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type[Exception] = Exception,
        success_threshold: int = 2,
    ) -> CircuitBreaker:
        """
        Get existing circuit breaker or create new one.

        Args:
            name: Service name
            failure_threshold: Failures before opening
            recovery_timeout: Recovery timeout in seconds
            expected_exception: Exception type to track
            success_threshold: Successes to close circuit

        Returns:
            Circuit breaker instance
        """
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
                expected_exception=expected_exception,
                success_threshold=success_threshold,
            )
        return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self._breakers.get(name)

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all circuit breakers."""
        return {name: breaker.get_stats() for name, breaker in self._breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()


# Global registry
_registry = CircuitBreakerRegistry()


def circuit_breaker(
    name: Optional[str] = None,
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exception: type[Exception] = Exception,
    success_threshold: int = 2,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for applying circuit breaker pattern.

    Args:
        name: Circuit breaker name (defaults to function name)
        failure_threshold: Failures before opening
        recovery_timeout: Recovery timeout in seconds
        expected_exception: Exception type to track
        success_threshold: Successes to close circuit

    Returns:
        Decorated function
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        breaker_name = name or f"{func.__module__}.{func.__name__}"

        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                breaker = _registry.get_or_create(
                    breaker_name,
                    failure_threshold,
                    recovery_timeout,
                    expected_exception,
                    success_threshold,
                )
                return await breaker.call_async(func, *args, **kwargs)

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                breaker = _registry.get_or_create(
                    breaker_name,
                    failure_threshold,
                    recovery_timeout,
                    expected_exception,
                    success_threshold,
                )
                return breaker.call(func, *args, **kwargs)

            return sync_wrapper

    return decorator


def get_circuit_breaker(name: str) -> Optional[CircuitBreaker]:
    """Get circuit breaker by name."""
    return _registry.get(name)


def get_all_circuit_stats() -> Dict[str, Dict[str, Any]]:
    """Get statistics for all circuit breakers."""
    return _registry.get_all_stats()


def reset_all_circuits() -> None:
    """Reset all circuit breakers."""
    _registry.reset_all()
