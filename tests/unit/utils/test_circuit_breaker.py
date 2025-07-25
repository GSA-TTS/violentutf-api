"""Tests for circuit breaker pattern implementation."""

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from app.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerException,
    CircuitState,
    _circuit_breakers,
    get_all_circuit_breaker_stats,
    get_circuit_breaker,
    reset_all_circuit_breakers,
    with_circuit_breaker,
)


class TestCircuitBreakerConfig:
    """Test circuit breaker configuration."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = CircuitBreakerConfig()

        assert config.failure_threshold == 5
        assert config.recovery_timeout == 60.0
        assert config.success_threshold == 3
        assert config.timeout == 30.0
        assert config.expected_exception == Exception

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=30.0,
            success_threshold=2,
            timeout=10.0,
            expected_exception=ValueError,
        )

        assert config.failure_threshold == 3
        assert config.recovery_timeout == 30.0
        assert config.success_threshold == 2
        assert config.timeout == 10.0
        assert config.expected_exception == ValueError


class TestCircuitBreakerException:
    """Test circuit breaker exception."""

    def test_exception_creation(self) -> None:
        """Test exception creation with message and circuit name."""
        message = "Circuit breaker is open"
        circuit_name = "test_circuit"

        exception = CircuitBreakerException(message, circuit_name)

        assert str(exception) == message
        assert exception.circuit_name == circuit_name


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    @pytest.fixture
    def config(self) -> CircuitBreakerConfig:
        """Create test circuit breaker configuration."""
        return CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1.0,
            success_threshold=2,
            timeout=1.0,
        )

    @pytest.fixture
    def circuit_breaker(self, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Create test circuit breaker."""
        return CircuitBreaker("test_circuit", config)

    def test_circuit_breaker_initialization(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit breaker initialization."""
        assert circuit_breaker.name == "test_circuit"
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.stats.failure_count == 0
        assert circuit_breaker.stats.success_count == 0
        assert circuit_breaker.stats.total_requests == 0

    @pytest.mark.asyncio
    async def test_successful_call(self, circuit_breaker: CircuitBreaker) -> None:
        """Test successful function call through circuit breaker."""

        async def success_func() -> str:
            return "success"

        result = await circuit_breaker.call(success_func)

        assert result == "success"
        assert circuit_breaker.stats.success_count == 1
        assert circuit_breaker.stats.failure_count == 0
        assert circuit_breaker.stats.total_requests == 1

    @pytest.mark.asyncio
    async def test_failed_call(self, circuit_breaker: CircuitBreaker) -> None:
        """Test failed function call through circuit breaker."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            await circuit_breaker.call(failing_func)

        assert circuit_breaker.stats.failure_count == 1
        assert circuit_breaker.stats.success_count == 0
        assert circuit_breaker.stats.total_requests == 1

    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit opens after failure threshold is reached."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        # First failure
        with pytest.raises(ValueError):
            await circuit_breaker.call(failing_func)
        assert circuit_breaker.state == CircuitState.CLOSED

        # Second failure should open circuit
        with pytest.raises(ValueError):
            await circuit_breaker.call(failing_func)
        assert circuit_breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_circuit_fails_fast_when_open(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit fails fast when open."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        # Force circuit to open
        for _ in range(2):
            with pytest.raises(ValueError):
                await circuit_breaker.call(failing_func)

        assert circuit_breaker.state == CircuitState.OPEN

        # Next call should fail fast with CircuitBreakerException
        with pytest.raises(CircuitBreakerException, match="Circuit breaker 'test_circuit' is open"):
            await circuit_breaker.call(failing_func)

    @pytest.mark.asyncio
    async def test_circuit_half_open_after_timeout(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit transitions to half-open after recovery timeout."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        async def success_func() -> str:
            return "success"

        # Force circuit to open
        for _ in range(2):
            with pytest.raises(ValueError):
                await circuit_breaker.call(failing_func)

        assert circuit_breaker.state == CircuitState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Next call should transition to half-open
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        assert circuit_breaker.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_circuit_closes_after_success_threshold(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit closes after success threshold in half-open state."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        async def success_func() -> str:
            return "success"

        # Force circuit to open
        for _ in range(2):
            with pytest.raises(ValueError):
                await circuit_breaker.call(failing_func)

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Transition to half-open with first success
        await circuit_breaker.call(success_func)
        assert circuit_breaker.state == CircuitState.HALF_OPEN

        # Second success should close circuit
        await circuit_breaker.call(success_func)
        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.stats.failure_count == 0  # Reset on close

    @pytest.mark.asyncio
    async def test_circuit_reopens_on_failure_in_half_open(self, circuit_breaker: CircuitBreaker) -> None:
        """Test circuit reopens on failure in half-open state."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        async def success_func() -> str:
            return "success"

        # Force circuit to open
        for _ in range(2):
            with pytest.raises(ValueError):
                await circuit_breaker.call(failing_func)

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Transition to half-open
        await circuit_breaker.call(success_func)
        assert circuit_breaker.state == CircuitState.HALF_OPEN

        # Failure should reopen circuit
        with pytest.raises(ValueError):
            await circuit_breaker.call(failing_func)
        assert circuit_breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_timeout_handling(self, circuit_breaker: CircuitBreaker) -> None:
        """Test timeout handling for async functions."""

        async def slow_func() -> str:
            await asyncio.sleep(2.0)  # Longer than timeout
            return "too_slow"

        with pytest.raises(asyncio.TimeoutError):
            await circuit_breaker.call(slow_func)

        assert circuit_breaker.stats.failure_count == 1

    def test_sync_function_call(self, circuit_breaker: CircuitBreaker) -> None:
        """Test calling synchronous functions through circuit breaker."""

        def sync_func() -> str:
            return "sync_result"

        async def test_sync() -> None:
            result = await circuit_breaker.call(sync_func)
            return result

        result = asyncio.run(test_sync())
        assert result == "sync_result"

    @pytest.mark.asyncio
    async def test_unexpected_exception_not_counted(self, circuit_breaker: CircuitBreaker) -> None:
        """Test unexpected exceptions are not counted as circuit breaker failures."""
        # Configure circuit breaker to only count ValueError
        circuit_breaker.config.expected_exception = ValueError

        async def unexpected_error_func() -> None:
            raise TypeError("Unexpected error")

        with pytest.raises(TypeError):
            await circuit_breaker.call(unexpected_error_func)

        # Should not count as failure
        assert circuit_breaker.stats.failure_count == 0

    def test_get_stats(self, circuit_breaker: CircuitBreaker) -> None:
        """Test getting circuit breaker statistics."""
        stats = circuit_breaker.get_stats()

        assert stats["name"] == "test_circuit"
        assert stats["state"] == CircuitState.CLOSED.value
        assert stats["failure_count"] == 0
        assert stats["success_count"] == 0
        assert stats["total_requests"] == 0
        assert "uptime_seconds" in stats
        assert "config" in stats

    @pytest.mark.asyncio
    async def test_reset(self, circuit_breaker: CircuitBreaker) -> None:
        """Test resetting circuit breaker."""

        async def failing_func() -> None:
            raise ValueError("Test error")

        # Generate some failures
        with pytest.raises(ValueError):
            await circuit_breaker.call(failing_func)

        assert circuit_breaker.stats.failure_count == 1

        # Reset circuit breaker
        await circuit_breaker.reset()

        assert circuit_breaker.state == CircuitState.CLOSED
        assert circuit_breaker.stats.failure_count == 0
        assert circuit_breaker.stats.success_count == 0
        assert circuit_breaker.stats.total_requests == 0

    def test_state_check_methods(self, circuit_breaker: CircuitBreaker) -> None:
        """Test state checking methods."""
        assert circuit_breaker.is_closed()
        assert not circuit_breaker.is_open()
        assert not circuit_breaker.is_half_open()

        # Manually set state for testing
        circuit_breaker.state = CircuitState.OPEN
        assert not circuit_breaker.is_closed()
        assert circuit_breaker.is_open()
        assert not circuit_breaker.is_half_open()

        circuit_breaker.state = CircuitState.HALF_OPEN
        assert not circuit_breaker.is_closed()
        assert not circuit_breaker.is_open()
        assert circuit_breaker.is_half_open()


class TestCircuitBreakerRegistry:
    """Test circuit breaker registry functions."""

    def teardown_method(self) -> None:
        """Clean up registry after each test."""
        _circuit_breakers.clear()

    def test_get_circuit_breaker_new(self) -> None:
        """Test getting a new circuit breaker."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = get_circuit_breaker("new_circuit", config)

        assert cb.name == "new_circuit"
        assert cb.config.failure_threshold == 3
        assert "new_circuit" in _circuit_breakers

    def test_get_circuit_breaker_existing(self) -> None:
        """Test getting an existing circuit breaker."""
        # Create first circuit breaker
        cb1 = get_circuit_breaker("existing_circuit")

        # Get same circuit breaker (should return same instance)
        cb2 = get_circuit_breaker("existing_circuit")

        assert cb1 is cb2
        assert cb1.name == "existing_circuit"

    @pytest.mark.asyncio
    async def test_get_all_circuit_breaker_stats(self) -> None:
        """Test getting all circuit breaker statistics."""
        # Create multiple circuit breakers
        get_circuit_breaker("circuit1")
        get_circuit_breaker("circuit2")

        stats = await get_all_circuit_breaker_stats()

        assert len(stats) == 2
        assert "circuit1" in stats
        assert "circuit2" in stats
        assert stats["circuit1"]["name"] == "circuit1"
        assert stats["circuit2"]["name"] == "circuit2"

    @pytest.mark.asyncio
    async def test_reset_all_circuit_breakers(self) -> None:
        """Test resetting all circuit breakers."""
        # Create circuit breakers and generate some stats
        cb1 = get_circuit_breaker("circuit1")
        cb2 = get_circuit_breaker("circuit2")

        # Manually set some stats
        cb1.stats.failure_count = 5
        cb2.stats.success_count = 3

        # Reset all
        await reset_all_circuit_breakers()

        assert cb1.stats.failure_count == 0
        assert cb1.stats.success_count == 0
        assert cb2.stats.failure_count == 0
        assert cb2.stats.success_count == 0


class TestCircuitBreakerDecorator:
    """Test circuit breaker decorator."""

    def teardown_method(self) -> None:
        """Clean up registry after each test."""
        _circuit_breakers.clear()

    @pytest.mark.asyncio
    async def test_decorator_success(self) -> None:
        """Test successful decorated function call."""
        config = CircuitBreakerConfig(failure_threshold=2)

        @with_circuit_breaker("decorated_circuit", config)
        async def decorated_func() -> str:
            return "decorated_success"

        result = await decorated_func()

        assert result == "decorated_success"

        # Check circuit breaker was created and used
        cb = get_circuit_breaker("decorated_circuit")
        assert cb.stats.success_count == 1

    @pytest.mark.asyncio
    async def test_decorator_failure(self) -> None:
        """Test failed decorated function call."""
        config = CircuitBreakerConfig(failure_threshold=2)

        @with_circuit_breaker("decorated_circuit", config)
        async def decorated_func() -> None:
            raise ValueError("Decorated error")

        with pytest.raises(ValueError, match="Decorated error"):
            await decorated_func()

        # Check circuit breaker tracked the failure
        cb = get_circuit_breaker("decorated_circuit")
        assert cb.stats.failure_count == 1

    @pytest.mark.asyncio
    async def test_decorator_circuit_opening(self) -> None:
        """Test circuit opening through decorated function."""
        config = CircuitBreakerConfig(failure_threshold=1)

        @with_circuit_breaker("decorated_circuit", config)
        async def decorated_func() -> None:
            raise ValueError("Decorated error")

        # First call should fail and open circuit
        with pytest.raises(ValueError):
            await decorated_func()

        # Second call should fail fast
        with pytest.raises(CircuitBreakerException):
            await decorated_func()


class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker."""

    def teardown_method(self) -> None:
        """Clean up registry after each test."""
        _circuit_breakers.clear()

    @pytest.mark.asyncio
    async def test_multiple_circuit_breakers(self) -> None:
        """Test multiple independent circuit breakers."""
        config1 = CircuitBreakerConfig(failure_threshold=1)
        config2 = CircuitBreakerConfig(failure_threshold=2)

        cb1 = CircuitBreaker("service1", config1)
        cb2 = CircuitBreaker("service2", config2)

        async def failing_func() -> None:
            raise ValueError("Service error")

        # Fail service1 (should open after 1 failure)
        with pytest.raises(ValueError):
            await cb1.call(failing_func)
        assert cb1.state == CircuitState.OPEN

        # Fail service2 once (should stay closed)
        with pytest.raises(ValueError):
            await cb2.call(failing_func)
        assert cb2.state == CircuitState.CLOSED

        # Fail service2 again (should open after 2 failures)
        with pytest.raises(ValueError):
            await cb2.call(failing_func)
        assert cb2.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_real_world_scenario(self) -> None:
        """Test realistic usage scenario."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=0.1,  # Fast recovery for testing
            success_threshold=2,
        )
        cb = CircuitBreaker("external_api", config)

        call_count = 0

        async def external_api_call() -> str:
            nonlocal call_count
            call_count += 1

            # First 3 calls fail
            if call_count <= 3:
                raise ConnectionError("API unavailable")
            # Subsequent calls succeed
            return f"API response {call_count}"

        # Generate failures to open circuit
        for _ in range(3):
            with pytest.raises(ConnectionError):
                await cb.call(external_api_call)

        assert cb.state == CircuitState.OPEN

        # Circuit should fail fast
        with pytest.raises(CircuitBreakerException):
            await cb.call(external_api_call)

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Should transition to half-open and start working
        result1 = await cb.call(external_api_call)
        assert result1 == "API response 4"
        assert cb.state == CircuitState.HALF_OPEN

        # Second success should close circuit
        result2 = await cb.call(external_api_call)
        assert result2 == "API response 5"
        assert cb.state == CircuitState.CLOSED
