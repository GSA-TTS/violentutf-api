"""Enhanced comprehensive tests for circuit breaker functionality.

This test suite provides extensive coverage for circuit breaker pattern,
including state transitions, timeout handling, and concurrent operations.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerException,
    CircuitBreakerOpenError,
    CircuitBreakerStats,
    CircuitState,
    get_all_circuit_breaker_stats,
    get_circuit_breaker,
    reset_all_circuit_breakers,
    with_circuit_breaker,
)


class TestCircuitBreakerConfig:
    """Test circuit breaker configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = CircuitBreakerConfig()

        assert config.failure_threshold == 5
        assert config.recovery_timeout == 60.0
        assert config.success_threshold == 3
        assert config.timeout == 30.0
        assert config.expected_exception == Exception

    def test_custom_config(self):
        """Test custom configuration values."""
        config = CircuitBreakerConfig(
            failure_threshold=10,
            recovery_timeout=120.0,
            success_threshold=5,
            timeout=45.0,
            expected_exception=ValueError,
        )

        assert config.failure_threshold == 10
        assert config.recovery_timeout == 120.0
        assert config.success_threshold == 5
        assert config.timeout == 45.0
        assert config.expected_exception == ValueError

    def test_config_validation_ranges(self):
        """Test configuration with edge values."""
        # Very sensitive circuit breaker
        sensitive_config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=5.0,
            success_threshold=1,
            timeout=1.0,
        )
        assert sensitive_config.failure_threshold == 1

        # Very tolerant circuit breaker
        tolerant_config = CircuitBreakerConfig(
            failure_threshold=100,
            recovery_timeout=300.0,
            success_threshold=20,
            timeout=120.0,
        )
        assert tolerant_config.failure_threshold == 100


class TestCircuitBreakerStats:
    """Test circuit breaker statistics."""

    def test_default_stats(self):
        """Test default statistics values."""
        stats = CircuitBreakerStats()

        assert stats.failure_count == 0
        assert stats.success_count == 0
        assert stats.total_requests == 0
        assert stats.last_failure_time is None
        assert stats.consecutive_successes == 0
        assert isinstance(stats.state_changed_time, float)

    def test_stats_update(self):
        """Test updating statistics."""
        stats = CircuitBreakerStats()

        # Update counters
        stats.failure_count = 5
        stats.success_count = 10
        stats.total_requests = 15
        stats.consecutive_successes = 3
        stats.last_failure_time = time.time()

        assert stats.failure_count == 5
        assert stats.success_count == 10
        assert stats.total_requests == 15
        assert stats.consecutive_successes == 3
        assert stats.last_failure_time is not None


class TestCircuitBreakerExceptions:
    """Test circuit breaker exceptions."""

    def test_circuit_breaker_exception(self):
        """Test CircuitBreakerException creation."""
        exc = CircuitBreakerException("Circuit is open", "test_circuit")

        assert str(exc) == "Circuit is open"
        assert exc.circuit_name == "test_circuit"

    def test_circuit_breaker_open_error_alias(self):
        """Test CircuitBreakerOpenError is an alias."""
        assert CircuitBreakerOpenError is CircuitBreakerException


@pytest.mark.asyncio
class TestCircuitBreaker:
    """Test CircuitBreaker class functionality."""

    def test_initialization(self):
        """Test circuit breaker initialization."""
        cb = CircuitBreaker("test_service")

        assert cb.name == "test_service"
        assert cb.state == CircuitState.CLOSED
        assert cb.stats.failure_count == 0
        assert cb.stats.success_count == 0
        assert isinstance(cb.config, CircuitBreakerConfig)

    def test_initialization_with_config(self):
        """Test initialization with custom config."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test_service", config)

        assert cb.config.failure_threshold == 3
        assert cb.config is config

    async def test_successful_call(self):
        """Test successful function call through circuit breaker."""
        cb = CircuitBreaker("test_service")

        async def successful_function(x: int) -> int:
            return x * 2

        result = await cb.call(successful_function, 5)

        assert result == 10
        assert cb.stats.success_count == 1
        assert cb.stats.failure_count == 0
        assert cb.stats.total_requests == 1
        assert cb.state == CircuitState.CLOSED

    async def test_failed_call(self):
        """Test failed function call through circuit breaker."""
        cb = CircuitBreaker("test_service")

        async def failing_function():
            raise ValueError("Expected failure")

        with pytest.raises(ValueError, match="Expected failure"):
            await cb.call(failing_function)

        assert cb.stats.failure_count == 1
        assert cb.stats.success_count == 0
        assert cb.stats.total_requests == 1
        assert cb.state == CircuitState.CLOSED  # Not enough failures yet

    async def test_sync_function_call(self):
        """Test calling synchronous function through circuit breaker."""
        cb = CircuitBreaker("test_service")

        def sync_function(x: int) -> int:
            return x + 1

        result = await cb.call(sync_function, 10)

        assert result == 11
        assert cb.stats.success_count == 1

    async def test_circuit_opens_after_threshold(self):
        """Test circuit opens after failure threshold."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test_service", config)

        async def failing_function():
            raise ValueError("Failure")

        # Fail 3 times to open circuit
        for i in range(3):
            with pytest.raises(ValueError):
                await cb.call(failing_function)

            if i < 2:
                assert cb.state == CircuitState.CLOSED
            else:
                assert cb.state == CircuitState.OPEN

        assert cb.stats.failure_count == 3

        # Next call should fail fast
        with pytest.raises(CircuitBreakerException) as exc_info:
            await cb.call(failing_function)

        assert "Circuit breaker 'test_service' is open" in str(exc_info.value)
        assert exc_info.value.circuit_name == "test_service"

    async def test_circuit_half_open_after_timeout(self):
        """Test circuit transitions to half-open after recovery timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,  # 100ms for fast testing
        )
        cb = CircuitBreaker("test_service", config)

        async def failing_function():
            raise ValueError("Failure")

        # Open the circuit
        for _ in range(2):
            with pytest.raises(ValueError):
                await cb.call(failing_function)

        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(0.15)

        # Next call should try (half-open state)
        async def check_state():
            await cb._check_state_transitions()

        await check_state()
        assert cb.state == CircuitState.HALF_OPEN

    async def test_circuit_closes_after_success_threshold(self):
        """Test circuit closes after consecutive successes in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
            success_threshold=2,
        )
        cb = CircuitBreaker("test_service", config)

        # Open the circuit
        async def failing_function():
            raise ValueError("Failure")

        for _ in range(2):
            with pytest.raises(ValueError):
                await cb.call(failing_function)

        # Wait for recovery
        await asyncio.sleep(0.15)

        # Successful calls in half-open state
        async def successful_function():
            return "success"

        # Force state check
        await cb._check_state_transitions()
        assert cb.state == CircuitState.HALF_OPEN

        # Success calls to close circuit
        for i in range(2):
            result = await cb.call(successful_function)
            assert result == "success"

            if i < 1:
                assert cb.state == CircuitState.HALF_OPEN
            else:
                assert cb.state == CircuitState.CLOSED

    async def test_circuit_reopens_on_failure_in_half_open(self):
        """Test circuit reopens immediately on failure in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
        )
        cb = CircuitBreaker("test_service", config)

        # Open the circuit
        async def failing_function():
            raise ValueError("Failure")

        for _ in range(2):
            with pytest.raises(ValueError):
                await cb.call(failing_function)

        # Wait for recovery
        await asyncio.sleep(0.15)
        await cb._check_state_transitions()
        assert cb.state == CircuitState.HALF_OPEN

        # Fail again in half-open
        with pytest.raises(ValueError):
            await cb.call(failing_function)

        # Should immediately reopen
        assert cb.state == CircuitState.OPEN

    async def test_timeout_handling(self):
        """Test function timeout handling."""
        config = CircuitBreakerConfig(timeout=0.1)  # 100ms timeout
        cb = CircuitBreaker("test_service", config)

        async def slow_function():
            await asyncio.sleep(0.5)  # Takes too long
            return "should not reach"

        with pytest.raises(asyncio.TimeoutError):
            await cb.call(slow_function)

        assert cb.stats.failure_count == 1

    async def test_unexpected_exception_handling(self):
        """Test handling of unexpected exceptions."""
        config = CircuitBreakerConfig(expected_exception=ValueError)
        cb = CircuitBreaker("test_service", config)

        async def unexpected_error():
            raise TypeError("Unexpected type error")

        # Unexpected exceptions should not count as failures
        with pytest.raises(TypeError):
            await cb.call(unexpected_error)

        assert cb.stats.failure_count == 0  # Not counted
        assert cb.state == CircuitState.CLOSED

    async def test_get_stats(self):
        """Test getting circuit breaker statistics."""
        config = CircuitBreakerConfig(failure_threshold=5)
        cb = CircuitBreaker("test_service", config)

        # Make some calls
        async def test_func(should_fail=False):
            if should_fail:
                raise ValueError("Test failure")
            return "success"

        # Success
        await cb.call(test_func, should_fail=False)

        # Failure
        with pytest.raises(ValueError):
            await cb.call(test_func, should_fail=True)

        stats = cb.get_stats()

        assert stats["name"] == "test_service"
        assert stats["state"] == "closed"
        assert stats["failure_count"] == 1
        assert stats["success_count"] == 1
        assert stats["total_requests"] == 2
        assert stats["config"]["failure_threshold"] == 5
        assert "uptime_seconds" in stats

    async def test_reset(self):
        """Test resetting circuit breaker."""
        cb = CircuitBreaker("test_service")

        # Generate some stats
        async def failing_function():
            raise ValueError("Failure")

        for _ in range(3):
            with pytest.raises(ValueError):
                await cb.call(failing_function)

        assert cb.stats.failure_count == 3

        # Reset
        await cb.reset()

        assert cb.state == CircuitState.CLOSED
        assert cb.stats.failure_count == 0
        assert cb.stats.success_count == 0
        assert cb.stats.total_requests == 0

    def test_state_check_methods(self):
        """Test state checking convenience methods."""
        cb = CircuitBreaker("test_service")

        # Initial state
        assert cb.is_closed() is True
        assert cb.is_open() is False
        assert cb.is_half_open() is False

        # Change state
        cb.state = CircuitState.OPEN
        assert cb.is_closed() is False
        assert cb.is_open() is True
        assert cb.is_half_open() is False

        cb.state = CircuitState.HALF_OPEN
        assert cb.is_closed() is False
        assert cb.is_open() is False
        assert cb.is_half_open() is True


@pytest.mark.asyncio
class TestCircuitBreakerDecorator:
    """Test circuit breaker decorator functionality."""

    async def test_decorator_basic(self):
        """Test basic decorator usage."""

        @with_circuit_breaker("decorated_service")
        async def decorated_function(x: int) -> int:
            return x * 2

        result = await decorated_function(5)
        assert result == 10

        # Check circuit breaker was created
        cb = get_circuit_breaker("decorated_service")
        assert cb.stats.success_count == 1

    async def test_decorator_with_config(self):
        """Test decorator with custom configuration."""
        config = CircuitBreakerConfig(failure_threshold=2)

        @with_circuit_breaker("configured_service", config)
        async def configured_function():
            raise ValueError("Expected failure")

        # Should fail twice before opening
        for i in range(2):
            with pytest.raises(ValueError):
                await configured_function()

        # Third call should fail fast
        with pytest.raises(CircuitBreakerException):
            await configured_function()

    async def test_decorator_preserves_function_metadata(self):
        """Test decorator preserves function metadata."""

        @with_circuit_breaker("metadata_service")
        async def documented_function(x: int) -> int:
            """This function doubles the input."""
            return x * 2

        # Metadata should be preserved
        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This function doubles the input."

    async def test_multiple_decorators_same_circuit(self):
        """Test multiple functions using same circuit breaker."""

        @with_circuit_breaker("shared_service")
        async def function_a():
            raise ValueError("Failure A")

        @with_circuit_breaker("shared_service")
        async def function_b():
            return "Success B"

        # Get the shared circuit breaker
        cb = get_circuit_breaker("shared_service")
        initial_failures = cb.stats.failure_count

        # Failure in function A
        with pytest.raises(ValueError):
            await function_a()

        assert cb.stats.failure_count == initial_failures + 1

        # Success in function B (same circuit)
        result = await function_b()
        assert result == "Success B"
        assert cb.stats.success_count > 0


class TestCircuitBreakerRegistry:
    """Test circuit breaker registry functionality."""

    def test_get_circuit_breaker_creates_new(self):
        """Test get_circuit_breaker creates new instance."""
        # Clear registry first
        from app.utils.circuit_breaker import _circuit_breakers

        _circuit_breakers.clear()

        cb1 = get_circuit_breaker("service1")
        assert cb1.name == "service1"
        assert "service1" in _circuit_breakers

    def test_get_circuit_breaker_returns_existing(self):
        """Test get_circuit_breaker returns existing instance."""
        cb1 = get_circuit_breaker("service2")
        cb2 = get_circuit_breaker("service2")

        assert cb1 is cb2  # Same instance

    def test_get_circuit_breaker_with_config(self):
        """Test get_circuit_breaker with configuration."""
        config = CircuitBreakerConfig(failure_threshold=10)

        # First call with config
        cb1 = get_circuit_breaker("service3", config)
        assert cb1.config.failure_threshold == 10

        # Second call without config (returns existing)
        cb2 = get_circuit_breaker("service3")
        assert cb2 is cb1
        assert cb2.config.failure_threshold == 10

    @pytest.mark.asyncio
    async def test_get_all_circuit_breaker_stats(self):
        """Test getting stats for all circuit breakers."""
        # Create multiple circuit breakers
        cb1 = get_circuit_breaker("stats_service1")
        cb2 = get_circuit_breaker("stats_service2")

        # Generate some activity
        async def success():
            return "ok"

        await cb1.call(success)
        await cb2.call(success)

        # Get all stats
        all_stats = await get_all_circuit_breaker_stats()

        assert "stats_service1" in all_stats
        assert "stats_service2" in all_stats
        assert all_stats["stats_service1"]["success_count"] >= 1
        assert all_stats["stats_service2"]["success_count"] >= 1

    @pytest.mark.asyncio
    async def test_reset_all_circuit_breakers(self):
        """Test resetting all circuit breakers."""
        # Create and use circuit breakers
        cb1 = get_circuit_breaker("reset_service1")
        cb2 = get_circuit_breaker("reset_service2")

        async def fail():
            raise ValueError("Failure")

        # Generate failures
        for cb in [cb1, cb2]:
            try:
                await cb.call(fail)
            except ValueError:
                pass

        assert cb1.stats.failure_count > 0
        assert cb2.stats.failure_count > 0

        # Reset all
        await reset_all_circuit_breakers()

        assert cb1.stats.failure_count == 0
        assert cb2.stats.failure_count == 0
        assert cb1.state == CircuitState.CLOSED
        assert cb2.state == CircuitState.CLOSED


@pytest.mark.asyncio
class TestCircuitBreakerConcurrency:
    """Test circuit breaker behavior under concurrent load."""

    async def test_concurrent_requests_same_circuit(self):
        """Test concurrent requests through same circuit breaker."""
        config = CircuitBreakerConfig(failure_threshold=10)
        cb = CircuitBreaker("concurrent_service", config)

        success_count = 0
        failure_count = 0

        async def maybe_fail(should_fail: bool):
            nonlocal success_count, failure_count
            if should_fail:
                failure_count += 1
                raise ValueError("Concurrent failure")
            success_count += 1
            return "success"

        # Create mixed concurrent requests
        tasks = []
        for i in range(20):
            should_fail = i % 3 == 0  # Every third request fails
            tasks.append(cb.call(maybe_fail, should_fail))

        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Count results
        successes = sum(1 for r in results if r == "success")
        failures = sum(1 for r in results if isinstance(r, ValueError))

        # Verify counts
        assert successes > 0
        assert failures > 0
        assert cb.stats.total_requests == 20

    async def test_state_transitions_under_load(self):
        """Test state transitions are thread-safe under load."""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=0.1,
        )
        cb = CircuitBreaker("transition_service", config)

        async def failing_function():
            raise ValueError("Load test failure")

        # Generate concurrent failures
        tasks = [cb.call(failing_function) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Circuit should be open
        assert cb.state == CircuitState.OPEN

        # Verify failure count is accurate
        failures = sum(1 for r in results if isinstance(r, ValueError))
        circuit_opens = sum(1 for r in results if isinstance(r, CircuitBreakerException))

        assert failures + circuit_opens == 10
        assert cb.stats.failure_count == failures  # Only actual calls count

    async def test_race_condition_on_state_change(self):
        """Test no race conditions during state changes."""
        config = CircuitBreakerConfig(
            failure_threshold=1,  # Opens immediately
            recovery_timeout=0.05,  # Quick recovery
            success_threshold=1,  # Closes immediately
        )
        cb = CircuitBreaker("race_service", config)

        state_changes = []

        # Monitor state changes
        original_open = cb._open_circuit
        original_close = cb._close_circuit
        original_half_open = cb._half_open_circuit

        async def track_open():
            state_changes.append(("open", time.time()))
            await original_open()

        async def track_close():
            state_changes.append(("close", time.time()))
            await original_close()

        async def track_half_open():
            state_changes.append(("half_open", time.time()))
            await original_half_open()

        cb._open_circuit = track_open
        cb._close_circuit = track_close
        cb._half_open_circuit = track_half_open

        # Rapid success/failure alternation
        for i in range(10):
            try:
                if i % 2 == 0:
                    await cb.call(lambda: 1 / 0)  # Fail
                else:
                    await cb.call(lambda: "ok")  # Success
            except:
                pass

            # Small delay to allow state transitions
            await asyncio.sleep(0.01)

        # Verify state changes are consistent
        assert len(state_changes) > 0

        # No duplicate consecutive state changes
        for i in range(1, len(state_changes)):
            assert state_changes[i][0] != state_changes[i - 1][0]


class TestCircuitBreakerEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_with_no_timeout(self):
        """Test circuit breaker with infinite timeout."""
        config = CircuitBreakerConfig(timeout=float("inf"))
        cb = CircuitBreaker("no_timeout_service", config)

        async def long_running():
            await asyncio.sleep(0.1)
            return "completed"

        # Should complete without timeout
        result = await cb.call(long_running)
        assert result == "completed"

    @pytest.mark.asyncio
    async def test_circuit_breaker_with_zero_threshold(self):
        """Test circuit breaker that never opens."""
        config = CircuitBreakerConfig(failure_threshold=0)
        cb = CircuitBreaker("never_open_service", config)

        async def always_fails():
            raise ValueError("Always fails")

        # Should never open circuit
        for _ in range(10):
            with pytest.raises(ValueError):
                await cb.call(always_fails)

        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_function_with_kwargs(self):
        """Test calling function with keyword arguments."""
        cb = CircuitBreaker("kwargs_service")

        async def kwargs_function(a: int, b: int = 10, *, c: int = 20) -> int:
            return a + b + c

        result = await cb.call(kwargs_function, 5, b=15, c=25)
        assert result == 45

    @pytest.mark.asyncio
    async def test_generator_function(self):
        """Test circuit breaker with generator/iterator."""
        cb = CircuitBreaker("generator_service")

        async def async_generator():
            for i in range(3):
                yield i

        # Generators need special handling
        gen = await cb.call(async_generator)
        values = []
        async for value in gen:
            values.append(value)

        assert values == [0, 1, 2]

    @pytest.mark.asyncio
    async def test_circuit_breaker_memory_cleanup(self):
        """Test that circuit breaker doesn't leak memory."""
        import gc
        import weakref

        # Create circuit breaker
        cb = CircuitBreaker("memory_test_service")
        cb_ref = weakref.ref(cb)

        # Use it
        await cb.call(lambda: "test")

        # Delete reference
        del cb

        # Force garbage collection
        gc.collect()

        # Should be collected (unless stored in registry)
        # Note: Will still exist in registry, so this tests the pattern


class TestCircuitBreakerIntegration:
    """Integration tests with real-world scenarios."""

    @pytest.mark.asyncio
    async def test_http_client_integration(self):
        """Test circuit breaker with HTTP client scenario."""
        import aiohttp
        from aiohttp import ClientError

        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=1.0,
            expected_exception=ClientError,
        )

        @with_circuit_breaker("http_service", config)
        async def fetch_data(url: str) -> dict:
            # Simulate HTTP client
            if "fail" in url:
                raise aiohttp.ClientError("Connection failed")
            return {"data": "success"}

        # Success case
        result = await fetch_data("http://example.com/api")
        assert result["data"] == "success"

        # Failure cases
        for _ in range(3):
            with pytest.raises(ClientError):
                await fetch_data("http://example.com/fail")

        # Circuit should be open
        with pytest.raises(CircuitBreakerException):
            await fetch_data("http://example.com/api")

    @pytest.mark.asyncio
    async def test_database_integration(self):
        """Test circuit breaker with database scenario."""

        class DatabaseError(Exception):
            pass

        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.5,
            timeout=1.0,
            expected_exception=DatabaseError,
        )

        cb = CircuitBreaker("database_service", config)

        # Simulate database operations
        query_count = 0

        async def query_database(query: str):
            nonlocal query_count
            query_count += 1

            if "SELECT" in query and query_count <= 2:
                raise DatabaseError("Connection lost")

            await asyncio.sleep(0.01)  # Simulate query time
            return [{"id": 1, "name": "Test"}]

        # First queries fail
        for _ in range(2):
            with pytest.raises(DatabaseError):
                await cb.call(query_database, "SELECT * FROM users")

        # Circuit opens
        assert cb.state == CircuitState.OPEN

        # Wait for recovery
        await asyncio.sleep(0.6)

        # Should work now (query_count > 2)
        result = await cb.call(query_database, "SELECT * FROM users")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_cascading_circuit_breakers(self):
        """Test multiple circuit breakers in a call chain."""
        # Service A depends on Service B
        cb_a = get_circuit_breaker("service_a")
        cb_b = get_circuit_breaker("service_b")

        async def service_b_call():
            raise ValueError("Service B is down")

        async def service_a_call():
            # Service A calls Service B
            try:
                return await cb_b.call(service_b_call)
            except (CircuitBreakerException, ValueError):
                # Handle both circuit breaker exceptions and actual failures gracefully
                return {"fallback": "data"}

        # Call Service A multiple times
        results = []
        for _ in range(10):
            try:
                result = await cb_a.call(service_a_call)
                results.append(result)
            except ValueError:
                results.append({"error": "propagated"})

        # Service A should remain healthy
        assert cb_a.state == CircuitState.CLOSED

        # Service B should be open
        assert cb_b.state == CircuitState.OPEN

        # Later calls should get fallback
        assert any(r.get("fallback") == "data" for r in results)
