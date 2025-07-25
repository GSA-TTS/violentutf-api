"""Tests for retry logic utilities."""

import asyncio
import time
from typing import Any
from unittest.mock import Mock, patch

import pytest

from app.utils.retry import (
    DATABASE_RETRY_CONFIG,
    EXTERNAL_API_RETRY_CONFIG,
    HTTP_RETRY_CONFIG,
    QUICK_RETRY_CONFIG,
    RetryConfig,
    RetryState,
    calculate_delay,
    retry_async,
    retry_sync,
    with_retry,
    with_retry_sync,
)


class TestRetryConfig:
    """Test retry configuration."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = RetryConfig()

        assert config.max_attempts == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0
        assert config.jitter is True
        assert config.exceptions == Exception

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = RetryConfig(
            max_attempts=5,
            base_delay=0.5,
            max_delay=30.0,
            exponential_base=1.5,
            jitter=False,
            exceptions=ValueError,
        )

        assert config.max_attempts == 5
        assert config.base_delay == 0.5
        assert config.max_delay == 30.0
        assert config.exponential_base == 1.5
        assert config.jitter is False
        assert config.exceptions == ValueError

    def test_tuple_exceptions(self) -> None:
        """Test configuration with tuple of exceptions."""
        config = RetryConfig(exceptions=(ValueError, TypeError))

        assert config.exceptions == (ValueError, TypeError)


class TestRetryState:
    """Test retry state tracking."""

    def test_retry_state_initialization(self) -> None:
        """Test retry state initialization."""
        config = RetryConfig(max_attempts=3)
        state = RetryState(config)

        assert state.config == config
        assert state.attempt == 0
        assert state.total_delay == 0.0
        assert isinstance(state.start_time, float)
        assert state.last_exception is None

    def test_retry_state_tracking(self) -> None:
        """Test retry state tracks values correctly."""
        config = RetryConfig()
        state = RetryState(config)

        # Simulate tracking
        state.attempt = 2
        state.total_delay = 5.5
        state.last_exception = ValueError("test")

        assert state.attempt == 2
        assert state.total_delay == 5.5
        assert isinstance(state.last_exception, ValueError)


class TestCalculateDelay:
    """Test delay calculation function."""

    def test_first_attempt_no_delay(self) -> None:
        """Test first attempt has no delay."""
        config = RetryConfig()
        delay = calculate_delay(0, config)

        assert delay == 0.0

    def test_exponential_backoff(self) -> None:
        """Test exponential backoff calculation."""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter=False)

        assert calculate_delay(1, config) == 1.0  # 1.0 * 2^0
        assert calculate_delay(2, config) == 2.0  # 1.0 * 2^1
        assert calculate_delay(3, config) == 4.0  # 1.0 * 2^2

    def test_max_delay_cap(self) -> None:
        """Test delay is capped at max_delay."""
        config = RetryConfig(base_delay=1.0, max_delay=5.0, exponential_base=2.0, jitter=False)

        # Should be capped at 5.0 instead of 8.0
        delay = calculate_delay(4, config)  # Would be 1.0 * 2^3 = 8.0
        assert delay == 5.0

    def test_jitter_adds_randomness(self) -> None:
        """Test jitter adds randomness to delay."""
        config = RetryConfig(base_delay=10.0, exponential_base=2.0, jitter=True)

        delays = [calculate_delay(1, config) for _ in range(10)]

        # With jitter, delays should vary slightly
        assert len(set(delays)) > 1  # Should have different values

        # All delays should be close to base delay (within jitter range)
        base_delay = 10.0
        jitter_range = base_delay * 0.1  # 10% jitter
        for delay in delays:
            assert (base_delay - jitter_range) <= delay <= (base_delay + jitter_range)

    def test_negative_delay_clamped(self) -> None:
        """Test negative delays are clamped to 0."""
        config = RetryConfig(base_delay=0.1, jitter=True)

        # With very small base delay and jitter, delay could go negative
        # but should be clamped to 0
        delay = calculate_delay(1, config)
        assert delay >= 0.0


class TestRetryAsync:
    """Test async retry function."""

    @pytest.mark.asyncio
    async def test_successful_first_attempt(self) -> None:
        """Test successful function on first attempt."""
        call_count = 0

        async def success_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        config = RetryConfig(max_attempts=3)
        result = await retry_async(success_func, config)

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_until_success(self) -> None:
        """Test retry until function succeeds."""
        call_count = 0

        async def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "finally"

        config = RetryConfig(max_attempts=5, base_delay=0.01)
        result = await retry_async(eventual_success, config)

        assert result == "finally"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_all_attempts_fail(self) -> None:
        """Test all retry attempts fail."""
        call_count = 0

        async def always_fails() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError(f"Failure {call_count}")

        config = RetryConfig(max_attempts=3, base_delay=0.01)

        with pytest.raises(ValueError, match="Failure 3"):
            await retry_async(always_fails, config)

        assert call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_exception(self) -> None:
        """Test exception not configured for retry."""
        call_count = 0

        async def wrong_exception() -> None:
            nonlocal call_count
            call_count += 1
            raise TypeError("Wrong type")

        config = RetryConfig(max_attempts=3, exceptions=ValueError)

        with pytest.raises(TypeError, match="Wrong type"):
            await retry_async(wrong_exception, config)

        assert call_count == 1  # Should not retry

    @pytest.mark.asyncio
    async def test_default_config(self) -> None:
        """Test retry with default configuration."""
        call_count = 0

        async def counting_func() -> int:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Try again")
            return call_count

        result = await retry_async(counting_func)  # No config = default

        assert result == 2
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_delay_timing(self) -> None:
        """Test actual delay timing between retries."""
        call_times = []

        async def timing_func() -> None:
            call_times.append(time.time())
            if len(call_times) < 3:
                raise ValueError("Keep trying")

        config = RetryConfig(max_attempts=3, base_delay=0.1, jitter=False)

        start_time = time.time()
        await retry_async(timing_func, config)

        # Check timing between calls
        assert len(call_times) == 3

        # First call immediate
        assert call_times[0] - start_time < 0.05

        # Second call after ~0.1s delay
        delay1 = call_times[1] - call_times[0]
        assert 0.08 <= delay1 <= 0.15

        # Third call after ~0.2s delay (exponential backoff)
        delay2 = call_times[2] - call_times[1]
        assert 0.18 <= delay2 <= 0.25

    @pytest.mark.asyncio
    async def test_function_with_args_kwargs(self) -> None:
        """Test retry with function arguments."""

        async def func_with_args(x: int, y: str, z: bool = False) -> str:
            if not z:
                raise ValueError("z must be True")
            return f"{x}-{y}-{z}"

        config = RetryConfig(max_attempts=1)

        # This should fail (z=False)
        with pytest.raises(ValueError):
            await retry_async(func_with_args, config, 42, "test", z=False)

        # This should succeed
        result = await retry_async(func_with_args, config, 42, "test", z=True)
        assert result == "42-test-True"


class TestRetrySync:
    """Test synchronous retry function."""

    def test_successful_first_attempt(self) -> None:
        """Test successful function on first attempt."""
        call_count = 0

        def success_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        config = RetryConfig(max_attempts=3)
        result = retry_sync(success_func, config)

        assert result == "success"
        assert call_count == 1

    def test_retry_until_success(self) -> None:
        """Test retry until function succeeds."""
        call_count = 0

        def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "finally"

        config = RetryConfig(max_attempts=5, base_delay=0.01)
        result = retry_sync(eventual_success, config)

        assert result == "finally"
        assert call_count == 3

    def test_all_attempts_fail(self) -> None:
        """Test all retry attempts fail."""
        call_count = 0

        def always_fails() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError(f"Failure {call_count}")

        config = RetryConfig(max_attempts=3, base_delay=0.01)

        with pytest.raises(ValueError, match="Failure 3"):
            retry_sync(always_fails, config)

        assert call_count == 3

    def test_non_retryable_exception(self) -> None:
        """Test exception not configured for retry."""
        call_count = 0

        def wrong_exception() -> None:
            nonlocal call_count
            call_count += 1
            raise TypeError("Wrong type")

        config = RetryConfig(max_attempts=3, exceptions=ValueError)

        with pytest.raises(TypeError, match="Wrong type"):
            retry_sync(wrong_exception, config)

        assert call_count == 1  # Should not retry


class TestRetryDecorators:
    """Test retry decorators."""

    @pytest.mark.asyncio
    async def test_async_decorator(self) -> None:
        """Test async retry decorator."""
        call_count = 0

        @with_retry(RetryConfig(max_attempts=3, base_delay=0.01))
        async def decorated_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Try again")
            return "decorated_success"

        result = await decorated_func()

        assert result == "decorated_success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_async_decorator_default_config(self) -> None:
        """Test async retry decorator with default config."""
        call_count = 0

        @with_retry()
        async def decorated_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Try again")
            return "default_config"

        result = await decorated_func()

        assert result == "default_config"
        assert call_count == 2

    def test_sync_decorator(self) -> None:
        """Test sync retry decorator."""
        call_count = 0

        @with_retry_sync(RetryConfig(max_attempts=3, base_delay=0.01))
        def decorated_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Try again")
            return "sync_decorated_success"

        result = decorated_func()

        assert result == "sync_decorated_success"
        assert call_count == 3

    def test_sync_decorator_default_config(self) -> None:
        """Test sync retry decorator with default config."""
        call_count = 0

        @with_retry_sync()
        def decorated_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Try again")
            return "sync_default_config"

        result = decorated_func()

        assert result == "sync_default_config"
        assert call_count == 2


class TestPredefinedConfigs:
    """Test predefined retry configurations."""

    def test_http_retry_config(self) -> None:
        """Test HTTP retry configuration."""
        config = HTTP_RETRY_CONFIG

        assert config.max_attempts == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 30.0
        assert config.exponential_base == 2.0
        assert config.jitter is True

    def test_database_retry_config(self) -> None:
        """Test database retry configuration."""
        config = DATABASE_RETRY_CONFIG

        assert config.max_attempts == 5
        assert config.base_delay == 0.5
        assert config.max_delay == 10.0
        assert config.exponential_base == 1.5
        assert config.jitter is True

    def test_external_api_retry_config(self) -> None:
        """Test external API retry configuration."""
        config = EXTERNAL_API_RETRY_CONFIG

        assert config.max_attempts == 4
        assert config.base_delay == 2.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0
        assert config.jitter is True

    def test_quick_retry_config(self) -> None:
        """Test quick retry configuration."""
        config = QUICK_RETRY_CONFIG

        assert config.max_attempts == 2
        assert config.base_delay == 0.1
        assert config.max_delay == 1.0
        assert config.exponential_base == 2.0
        assert config.jitter is False


class TestRetryIntegration:
    """Integration tests for retry functionality."""

    @pytest.mark.asyncio
    async def test_realistic_api_scenario(self) -> None:
        """Test realistic API retry scenario."""
        call_count = 0

        async def flaky_api_call() -> dict[str, Any]:
            nonlocal call_count
            call_count += 1

            # Fail first 2 calls with different errors
            if call_count == 1:
                raise ConnectionError("Connection refused")
            elif call_count == 2:
                raise TimeoutError("Request timeout")

            # Succeed on third call
            return {"status": "success", "data": f"attempt_{call_count}"}

        config = RetryConfig(
            max_attempts=5,
            base_delay=0.01,
            exceptions=(ConnectionError, TimeoutError),
        )

        result = await retry_async(flaky_api_call, config)

        assert result["status"] == "success"
        assert result["data"] == "attempt_3"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_mixed_retryable_exceptions(self) -> None:
        """Test retry with multiple exception types."""
        call_count = 0
        errors = [ConnectionError("No connection"), TimeoutError("Timeout"), ValueError("Bad value")]

        async def mixed_errors() -> str:
            nonlocal call_count
            if call_count < len(errors):
                error = errors[call_count]
                call_count += 1
                raise error
            return "success"

        config = RetryConfig(
            max_attempts=5,
            base_delay=0.01,
            exceptions=(ConnectionError, TimeoutError),  # ValueError not retryable
        )

        # Should fail on ValueError (third attempt)
        with pytest.raises(ValueError, match="Bad value"):
            await retry_async(mixed_errors, config)

        assert call_count == 3  # Two retries + one non-retryable failure

    @pytest.mark.asyncio
    async def test_retry_with_circuit_breaker_simulation(self) -> None:
        """Test retry behavior simulating circuit breaker pattern."""
        call_count = 0
        failure_threshold = 3

        async def failing_service() -> str:
            nonlocal call_count
            call_count += 1

            # Simulate service degradation
            if call_count <= failure_threshold:
                raise ConnectionError(f"Service degraded, attempt {call_count}")

            # Service recovers
            return f"Service recovered on attempt {call_count}"

        config = RetryConfig(
            max_attempts=5,
            base_delay=0.01,
            exceptions=ConnectionError,
        )

        result = await retry_async(failing_service, config)

        assert "Service recovered" in result
        assert call_count == 4  # 3 failures + 1 success

    def test_performance_with_many_retries(self) -> None:
        """Test performance with many quick retries."""
        call_count = 0

        def quick_failure() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 50:  # Fail 49 times
                raise ValueError("Quick failure")
            return "finally_succeeded"

        config = RetryConfig(
            max_attempts=100,
            base_delay=0.001,  # Very quick retries
            max_delay=0.001,  # Cap at 1ms
            jitter=False,
        )

        start_time = time.time()
        result = retry_sync(quick_failure, config)
        duration = time.time() - start_time

        assert result == "finally_succeeded"
        assert call_count == 50
        assert duration < 1.0  # Should complete quickly


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_zero_max_attempts(self) -> None:
        """Test behavior with zero max attempts."""

        async def never_called() -> str:
            pytest.fail("Should not be called")

        config = RetryConfig(max_attempts=0)

        # Should raise RuntimeError when max_attempts is 0
        with pytest.raises(RuntimeError, match="All retry attempts failed"):
            await retry_async(never_called, config)

    @pytest.mark.asyncio
    async def test_negative_delays(self) -> None:
        """Test behavior with negative delay configurations."""
        call_count = 0

        async def counting_func() -> int:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Keep trying")
            return call_count

        config = RetryConfig(
            max_attempts=5,
            base_delay=-1.0,  # Negative base delay
            jitter=False,
        )

        # Should still work (delays clamped to 0)
        result = await retry_async(counting_func, config)
        assert result == 3

    @pytest.mark.asyncio
    async def test_very_large_delays(self) -> None:
        """Test behavior with very large delay configurations."""
        call_count = 0

        async def quick_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("One failure")
            return "success"

        config = RetryConfig(
            max_attempts=3,
            base_delay=1000.0,  # Very large delay
            max_delay=0.01,  # But capped low
            jitter=False,
        )

        start_time = time.time()
        result = await retry_async(quick_success, config)
        duration = time.time() - start_time

        assert result == "success"
        assert duration < 0.1  # Should be fast due to max_delay cap
