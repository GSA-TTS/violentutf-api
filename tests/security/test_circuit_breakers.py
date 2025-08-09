"""Comprehensive tests for circuit breaker functionality."""

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerException,
    CircuitState,
    get_all_circuit_breaker_stats,
    get_circuit_breaker,
    reset_all_circuit_breakers,
    with_circuit_breaker,
)


class TestCircuitBreakerBasics:
    """Test basic circuit breaker functionality."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_initialization(self):
        """Test circuit breaker initialization."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=30.0,
            success_threshold=2,
            timeout=10.0,
        )

        cb = CircuitBreaker("test_service", config)

        assert cb.name == "test_service"
        assert cb.state == CircuitState.CLOSED
        assert cb.config.failure_threshold == 3
        assert cb.config.recovery_timeout == 30.0
        assert cb.stats.failure_count == 0
        assert cb.stats.success_count == 0

    @pytest.mark.asyncio
    async def test_successful_calls(self):
        """Test circuit breaker with successful calls."""
        cb = CircuitBreaker("test_service")

        async def successful_operation():
            return "success"

        # Multiple successful calls
        for _ in range(5):
            result = await cb.call(successful_operation)
            assert result == "success"

        # Circuit should remain closed
        assert cb.state == CircuitState.CLOSED
        assert cb.stats.success_count == 5
        assert cb.stats.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_opens_on_failures(self):
        """Test circuit opens after threshold failures."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test_service", config)

        async def failing_operation():
            raise Exception("Service unavailable")

        # Make failures up to threshold
        for i in range(config.failure_threshold):
            with pytest.raises(Exception):
                await cb.call(failing_operation)

            if i < config.failure_threshold - 1:
                assert cb.state == CircuitState.CLOSED
            else:
                assert cb.state == CircuitState.OPEN

        # Circuit should now be open
        assert cb.stats.failure_count == config.failure_threshold

        # Further calls should fail fast
        with pytest.raises(CircuitBreakerException) as exc_info:
            await cb.call(failing_operation)

        assert "Circuit breaker 'test_service' is open" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_half_open_state(self):
        """Test circuit transitions to half-open after recovery timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,  # 100ms for testing
            success_threshold=2,
        )
        cb = CircuitBreaker("test_service", config)

        async def failing_operation():
            raise Exception("Failed")

        # Open the circuit
        for _ in range(config.failure_threshold):
            with pytest.raises(Exception):
                await cb.call(failing_operation)

        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(config.recovery_timeout + 0.05)

        # Next call should transition to half-open
        async def successful_operation():
            return "success"

        # First successful call in half-open
        result = await cb.call(successful_operation)
        assert result == "success"
        assert cb.state == CircuitState.HALF_OPEN

        # Need success_threshold successes to close
        result = await cb.call(successful_operation)
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_circuit_reopens_from_half_open(self):
        """Test circuit reopens if failure occurs in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
            success_threshold=3,
        )
        cb = CircuitBreaker("test_service", config)

        async def failing_operation():
            raise Exception("Failed")

        # Open the circuit
        for _ in range(config.failure_threshold):
            with pytest.raises(Exception):
                await cb.call(failing_operation)

        # Wait for recovery timeout
        await asyncio.sleep(config.recovery_timeout + 0.05)

        # Succeed once to enter half-open
        async def successful_operation():
            return "success"

        await cb.call(successful_operation)
        assert cb.state == CircuitState.HALF_OPEN

        # Fail in half-open state
        with pytest.raises(Exception):
            await cb.call(failing_operation)

        # Should immediately reopen
        assert cb.state == CircuitState.OPEN


class TestCircuitBreakerTimeout:
    """Test circuit breaker timeout functionality."""

    @pytest.mark.asyncio
    async def test_call_timeout(self):
        """Test that calls timeout properly."""
        config = CircuitBreakerConfig(timeout=0.1)  # 100ms timeout
        cb = CircuitBreaker("test_service", config)

        async def slow_operation():
            await asyncio.sleep(0.5)  # 500ms
            return "should_timeout"

        with pytest.raises(asyncio.TimeoutError):
            await cb.call(slow_operation)

        # Timeout should count as failure
        assert cb.stats.failure_count == 1

    @pytest.mark.asyncio
    async def test_sync_function_call(self):
        """Test circuit breaker with synchronous functions."""
        cb = CircuitBreaker("test_service")

        def sync_operation(x: int, y: int) -> int:
            return x + y

        result = await cb.call(sync_operation, 2, 3)
        assert result == 5
        assert cb.stats.success_count == 1


class TestCircuitBreakerDecorator:
    """Test circuit breaker decorator functionality."""

    @pytest.mark.asyncio
    async def test_with_circuit_breaker_decorator(self):
        """Test @with_circuit_breaker decorator."""

        @with_circuit_breaker("decorated_service")
        async def protected_operation(value: str) -> str:
            if value == "fail":
                raise Exception("Operation failed")
            return f"processed_{value}"

        # Successful calls
        result = await protected_operation("test")
        assert result == "processed_test"

        # Get the circuit breaker
        cb = get_circuit_breaker("decorated_service")
        assert cb.stats.success_count == 1

        # Failing calls
        with pytest.raises(Exception):
            await protected_operation("fail")

        assert cb.stats.failure_count == 1

    @pytest.mark.asyncio
    async def test_decorator_with_config(self):
        """Test decorator with custom configuration."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
        )

        @with_circuit_breaker("custom_service", config)
        async def protected_operation():
            raise Exception("Always fails")

        # Open the circuit
        for _ in range(2):
            with pytest.raises(Exception):
                await protected_operation()

        # Should fail fast now
        with pytest.raises(CircuitBreakerException):
            await protected_operation()


class TestCircuitBreakerRegistry:
    """Test circuit breaker registry functionality."""

    @pytest.mark.asyncio
    async def test_get_circuit_breaker(self):
        """Test getting circuit breakers from registry."""
        # First call creates new circuit breaker
        cb1 = get_circuit_breaker("service1")
        assert cb1.name == "service1"

        # Second call returns same instance
        cb2 = get_circuit_breaker("service1")
        assert cb1 is cb2

        # Different name creates different instance
        cb3 = get_circuit_breaker("service2")
        assert cb3 is not cb1
        assert cb3.name == "service2"

    @pytest.mark.asyncio
    async def test_get_all_circuit_breaker_stats(self):
        """Test getting stats for all circuit breakers."""
        # Create multiple circuit breakers
        cb1 = get_circuit_breaker("stats_service1")
        cb2 = get_circuit_breaker("stats_service2")

        # Make some calls
        async def success():
            return "ok"

        async def failure():
            raise Exception("fail")

        await cb1.call(success)
        await cb1.call(success)

        with pytest.raises(Exception):
            await cb2.call(failure)

        # Get all stats
        all_stats = await get_all_circuit_breaker_stats()

        assert "stats_service1" in all_stats
        assert "stats_service2" in all_stats

        assert all_stats["stats_service1"]["success_count"] == 2
        assert all_stats["stats_service2"]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_reset_all_circuit_breakers(self):
        """Test resetting all circuit breakers."""
        # Create and use circuit breakers
        cb1 = get_circuit_breaker("reset_service1")
        cb2 = get_circuit_breaker("reset_service2")

        # Open one circuit
        async def failure():
            raise Exception("fail")

        for _ in range(5):
            with pytest.raises(Exception):
                await cb1.call(failure)

        assert cb1.state == CircuitState.OPEN
        assert cb1.stats.failure_count == 5

        # Reset all
        await reset_all_circuit_breakers()

        # All should be reset
        assert cb1.state == CircuitState.CLOSED
        assert cb1.stats.failure_count == 0
        assert cb2.state == CircuitState.CLOSED


class TestCircuitBreakerStats:
    """Test circuit breaker statistics."""

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting circuit breaker statistics."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=60.0,
        )
        cb = CircuitBreaker("stats_test", config)

        # Make some calls
        async def success():
            return "ok"

        async def failure():
            raise Exception("fail")

        await cb.call(success)
        await cb.call(success)

        with pytest.raises(Exception):
            await cb.call(failure)

        stats = cb.get_stats()

        assert stats["name"] == "stats_test"
        assert stats["state"] == "closed"
        assert stats["success_count"] == 2
        assert stats["failure_count"] == 1
        assert stats["total_requests"] == 3
        assert stats["config"]["failure_threshold"] == 3
        assert "uptime_seconds" in stats
        assert stats["uptime_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_consecutive_successes_tracking(self):
        """Test tracking of consecutive successes."""
        cb = CircuitBreaker("consecutive_test")

        async def success():
            return "ok"

        async def failure():
            raise Exception("fail")

        # Build up consecutive successes
        for _ in range(3):
            await cb.call(success)

        assert cb.stats.consecutive_successes == 3

        # Failure resets consecutive count
        with pytest.raises(Exception):
            await cb.call(failure)

        assert cb.stats.consecutive_successes == 0


class TestCircuitBreakerExceptions:
    """Test circuit breaker exception handling."""

    @pytest.mark.asyncio
    async def test_expected_vs_unexpected_exceptions(self):
        """Test handling of expected vs unexpected exceptions."""
        config = CircuitBreakerConfig(
            expected_exception=ValueError,
            failure_threshold=3,
        )
        cb = CircuitBreaker("exception_test", config)

        async def raises_value_error():
            raise ValueError("Expected error")

        async def raises_type_error():
            raise TypeError("Unexpected error")

        # Expected exceptions count as failures
        with pytest.raises(ValueError):
            await cb.call(raises_value_error)

        assert cb.stats.failure_count == 1

        # Unexpected exceptions don't count
        with pytest.raises(TypeError):
            await cb.call(raises_type_error)

        assert cb.stats.failure_count == 1  # Still 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_exception_details(self):
        """Test CircuitBreakerException contains proper details."""
        cb = CircuitBreaker("detail_test")

        # Open the circuit
        async def failure():
            raise Exception("fail")

        for _ in range(5):
            with pytest.raises(Exception):
                await cb.call(failure)

        # Get the exception
        with pytest.raises(CircuitBreakerException) as exc_info:
            await cb.call(failure)

        exception = exc_info.value
        assert exception.circuit_name == "detail_test"
        assert "detail_test" in str(exception)
        assert "open" in str(exception)


class TestCircuitBreakerIntegration:
    """Test circuit breaker integration scenarios."""

    @pytest.mark.asyncio
    async def test_external_api_circuit_breaker(self):
        """Test circuit breaker for external API calls."""
        # Simulate external API with circuit breaker
        api_cb = get_circuit_breaker(
            "external_api",
            CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=30.0,
                timeout=5.0,
            ),
        )

        async def call_external_api(endpoint: str) -> dict:
            if endpoint == "/failing":
                raise Exception("API Error")
            return {"status": "ok", "data": endpoint}

        # Successful calls
        result = await api_cb.call(call_external_api, "/users")
        assert result["status"] == "ok"

        # Failing calls
        for _ in range(3):
            with pytest.raises(Exception):
                await api_cb.call(call_external_api, "/failing")

        # Circuit should be open
        with pytest.raises(CircuitBreakerException):
            await api_cb.call(call_external_api, "/users")

    @pytest.mark.asyncio
    async def test_database_circuit_breaker(self):
        """Test circuit breaker for database operations."""
        db_cb = get_circuit_breaker(
            "database",
            CircuitBreakerConfig(
                failure_threshold=2,
                recovery_timeout=10.0,
                timeout=2.0,
            ),
        )

        async def db_query(query: str) -> list:
            if "bad_table" in query:
                raise Exception("Table not found")
            return [{"id": 1, "name": "Test"}]

        # Normal queries work
        result = await db_cb.call(db_query, "SELECT * FROM users")
        assert len(result) == 1

        # Bad queries fail and open circuit
        for _ in range(2):
            with pytest.raises(Exception):
                await db_cb.call(db_query, "SELECT * FROM bad_table")

        # All queries fail fast now
        with pytest.raises(CircuitBreakerException):
            await db_cb.call(db_query, "SELECT * FROM users")


class TestCircuitBreakerStates:
    """Test circuit breaker state methods."""

    def test_state_check_methods(self):
        """Test is_closed, is_open, is_half_open methods."""
        cb = CircuitBreaker("state_test")

        # Initial state
        assert cb.is_closed()
        assert not cb.is_open()
        assert not cb.is_half_open()

        # Change state
        cb.state = CircuitState.OPEN
        assert not cb.is_closed()
        assert cb.is_open()
        assert not cb.is_half_open()

        # Half-open state
        cb.state = CircuitState.HALF_OPEN
        assert not cb.is_closed()
        assert not cb.is_open()
        assert cb.is_half_open()
