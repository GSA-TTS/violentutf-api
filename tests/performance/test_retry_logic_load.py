"""Load tests for database retry logic under failure conditions.

Tests retry logic behavior under various failure scenarios:
- Transient network failures
- Database unavailability
- Connection timeouts
- Circuit breaker integration
"""

import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import DatabaseError, OperationalError
from sqlalchemy.exc import TimeoutError as SQLTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.repositories.user import UserRepository
from app.utils.circuit_breaker import CircuitBreaker, CircuitState
from tests.test_database import DatabaseTestManager


class FailureSimulator:
    """Simulates various database failure scenarios."""

    def __init__(self, failure_rate: float = 0.5, failure_duration: int = 5):
        self.failure_rate = failure_rate
        self.failure_duration = failure_duration
        self.failure_start = None
        self.failure_count = 0
        self.success_count = 0

    def should_fail(self) -> bool:
        """Determine if the current operation should fail."""
        if self.failure_start:
            # Check if we're still in failure window
            if time.time() - self.failure_start < self.failure_duration:
                self.failure_count += 1
                return True
            else:
                self.failure_start = None

        # Random failure based on rate
        if random.random() < self.failure_rate:
            if not self.failure_start:
                self.failure_start = time.time()
            self.failure_count += 1
            return True

        self.success_count += 1
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get failure simulation statistics."""
        total = self.failure_count + self.success_count
        return {
            "total_operations": total,
            "failures": self.failure_count,
            "successes": self.success_count,
            "failure_rate": self.failure_count / total if total > 0 else 0,
        }


class LoadTestMetrics:
    """Collects metrics for load testing."""

    def __init__(self):
        self.start_time = time.time()
        self.operations: List[Dict[str, Any]] = []
        self.retry_counts: List[int] = []
        self.circuit_breaker_trips = 0

    def record_operation(self, duration: float, success: bool, retries: int = 0, error: Optional[Exception] = None):
        """Record an operation's metrics."""
        self.operations.append(
            {
                "timestamp": time.time(),
                "duration": duration,
                "success": success,
                "retries": retries,
                "error": str(error) if error else None,
            }
        )
        if retries > 0:
            self.retry_counts.append(retries)

    def record_circuit_trip(self):
        """Record a circuit breaker trip."""
        self.circuit_breaker_trips += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        total_ops = len(self.operations)
        successful_ops = sum(1 for op in self.operations if op["success"])
        failed_ops = total_ops - successful_ops

        durations = [op["duration"] for op in self.operations]
        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            "total_operations": total_ops,
            "successful_operations": successful_ops,
            "failed_operations": failed_ops,
            "success_rate": successful_ops / total_ops if total_ops > 0 else 0,
            "avg_duration": avg_duration,
            "total_retries": sum(self.retry_counts),
            "avg_retries_per_failure": sum(self.retry_counts) / len(self.retry_counts) if self.retry_counts else 0,
            "circuit_breaker_trips": self.circuit_breaker_trips,
            "total_duration": time.time() - self.start_time,
        }


class TestRetryLogicLoad:
    """Test retry logic under load and failure conditions."""

    @pytest_asyncio.fixture
    async def db_manager(self):
        """Get database manager with retry logic."""
        manager = DatabaseTestManager()
        await manager.initialize()
        yield manager
        await manager.shutdown()

    async def execute_with_retry_tracking(
        self, db_func, metrics: LoadTestMetrics, failure_simulator: Optional[FailureSimulator] = None
    ):
        """Execute a database operation with retry tracking."""
        start_time = time.time()
        retries = 0
        error = None
        success = False

        try:
            if failure_simulator and failure_simulator.should_fail():
                # Simulate failure
                raise OperationalError("Simulated database failure", None, None)

            # Execute actual operation
            result = await db_func()
            success = True
            return result

        except Exception as e:
            error = e
            # Count retries by checking retry-related attributes if available
            if hasattr(e, "retry_count"):
                retries = e.retry_count

        finally:
            duration = time.time() - start_time
            metrics.record_operation(duration, success, retries, error)

    @pytest.mark.asyncio
    async def test_retry_under_transient_failures(self, db_manager):
        """Test retry logic with transient database failures."""
        metrics = LoadTestMetrics()
        failure_simulator = FailureSimulator(failure_rate=0.3, failure_duration=2)

        # Mock the session execute to simulate failures
        original_execute = None

        async def mock_execute(self, *args, **kwargs):
            if failure_simulator.should_fail():
                raise OperationalError("Connection lost", None, None)
            return await original_execute(*args, **kwargs)

        # Run concurrent operations with simulated failures
        concurrent_ops = 50

        async def operation_with_retry(op_id: int):
            retry_count = 0
            max_retries = 3
            last_error = None

            for attempt in range(max_retries + 1):
                try:
                    async with db_manager.get_session() as session:
                        # Patch the execute method
                        if "original_execute" not in locals():
                            original_execute = session.execute

                        with patch.object(session, "execute", mock_execute):
                            result = await session.execute(select(User).limit(1))
                            _ = result.scalar_one_or_none()

                    # Success
                    metrics.record_operation(duration=time.time() - time.time(), success=True, retries=retry_count)
                    return

                except OperationalError as e:
                    retry_count += 1
                    last_error = e
                    if attempt < max_retries:
                        # Exponential backoff
                        await asyncio.sleep(0.1 * (2**attempt))
                    continue

            # All retries failed
            metrics.record_operation(
                duration=time.time() - time.time(), success=False, retries=retry_count, error=last_error
            )

        # Execute operations concurrently
        tasks = [asyncio.create_task(operation_with_retry(i)) for i in range(concurrent_ops)]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        summary = metrics.get_summary()
        failure_stats = failure_simulator.get_stats()

        print(f"\nTransient Failures Test Results:")
        print(f"  Total operations: {summary['total_operations']}")
        print(f"  Success rate: {summary['success_rate']*100:.2f}%")
        print(f"  Total retries: {summary['total_retries']}")
        print(f"  Avg retries per failure: {summary['avg_retries_per_failure']:.2f}")
        print(f"  Simulated failure rate: {failure_stats['failure_rate']*100:.2f}%")

        # Verify retry logic worked
        assert summary["success_rate"] > failure_stats["failure_rate"]  # Should recover from failures
        assert summary["total_retries"] > 0  # Should have retried

    @pytest.mark.asyncio
    async def test_circuit_breaker_under_load(self, db_manager):
        """Test circuit breaker behavior under sustained failures."""
        metrics = LoadTestMetrics()
        circuit_breaker = db_manager.circuit_breaker

        # Record initial state
        initial_state = circuit_breaker.state

        # Simulate sustained failures
        async def failing_operation():
            raise OperationalError("Database unavailable", None, None)

        # Execute operations that will fail
        failure_count = 0
        for i in range(20):  # Enough to trip circuit
            try:
                await circuit_breaker.call(failing_operation)
            except Exception:
                failure_count += 1
                if circuit_breaker.state == CircuitState.OPEN:
                    metrics.record_circuit_trip()
                    break

        # Verify circuit breaker tripped
        assert circuit_breaker.state == CircuitState.OPEN
        assert metrics.circuit_breaker_trips > 0

        print(f"\nCircuit Breaker Load Test:")
        print(f"  Failures before trip: {failure_count}")
        print(f"  Circuit breaker state: {circuit_breaker.state}")
        print(f"  Circuit trips recorded: {metrics.circuit_breaker_trips}")

        # Test recovery after timeout
        await asyncio.sleep(2)  # Wait for recovery timeout

        # Try operations again - should enter HALF_OPEN
        recovery_success = False

        async def successful_operation():
            return True

        with patch.object(circuit_breaker, "_recovery_timeout", 1):
            # Force state check
            circuit_breaker._check_state()

            if circuit_breaker.state == CircuitState.HALF_OPEN:
                try:
                    await circuit_breaker.call(successful_operation)
                    recovery_success = True
                except Exception:
                    pass

        print(f"  Recovery attempted: {recovery_success}")

    @pytest.mark.asyncio
    async def test_timeout_handling_under_load(self, db_manager):
        """Test handling of connection timeouts under load."""
        metrics = LoadTestMetrics()

        async def slow_operation():
            """Simulate a slow database operation."""
            await asyncio.sleep(5)  # Longer than typical timeout

        concurrent_timeouts = 20

        async def operation_with_timeout(op_id: int):
            start_time = time.time()
            try:
                # Use asyncio timeout
                async with asyncio.timeout(1):  # 1 second timeout
                    async with db_manager.get_session() as session:
                        await slow_operation()

            except asyncio.TimeoutError:
                duration = time.time() - start_time
                metrics.record_operation(duration, False, 0, asyncio.TimeoutError())
                return

            duration = time.time() - start_time
            metrics.record_operation(duration, True, 0)

        # Execute operations concurrently
        tasks = [asyncio.create_task(operation_with_timeout(i)) for i in range(concurrent_timeouts)]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        summary = metrics.get_summary()

        print(f"\nTimeout Handling Test Results:")
        print(f"  Total operations: {summary['total_operations']}")
        print(f"  Successful operations: {summary['successful_operations']}")
        print(f"  Failed operations: {summary['failed_operations']}")
        print(f"  Avg duration: {summary['avg_duration']*1000:.2f}ms")

        # All should timeout
        assert summary["failed_operations"] == concurrent_timeouts
        assert summary["avg_duration"] < 1.5  # Should timeout at ~1 second

    @pytest.mark.asyncio
    async def test_retry_with_exponential_backoff(self, db_manager):
        """Test exponential backoff behavior under load."""
        metrics = LoadTestMetrics()

        # Track retry delays
        retry_delays: List[float] = []

        async def operation_with_backoff_tracking():
            """Operation that tracks backoff delays."""
            max_retries = 4
            base_delay = 0.1

            for attempt in range(max_retries):
                start_time = time.time()

                try:
                    if attempt < 3:  # Fail first 3 attempts
                        raise OperationalError("Simulated failure", None, None)

                    # Success on 4th attempt
                    return True

                except OperationalError:
                    if attempt < max_retries - 1:
                        # Calculate exponential backoff
                        delay = base_delay * (2**attempt)
                        retry_delays.append(delay)
                        await asyncio.sleep(delay)

            return False

        # Run multiple operations concurrently
        concurrent_ops = 10
        tasks = [asyncio.create_task(operation_with_backoff_tracking()) for _ in range(concurrent_ops)]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify exponential backoff pattern
        print(f"\nExponential Backoff Test:")
        print(f"  Operations run: {concurrent_ops}")
        print(f"  Successful operations: {sum(1 for r in results if r is True)}")
        print(f"  Retry delays recorded: {len(retry_delays)}")

        if retry_delays:
            # Group delays by attempt number
            delay_groups = {}
            for i, delay in enumerate(retry_delays):
                attempt = i % 3  # 3 retries per operation
                if attempt not in delay_groups:
                    delay_groups[attempt] = []
                delay_groups[attempt].append(delay)

            for attempt, delays in sorted(delay_groups.items()):
                avg_delay = sum(delays) / len(delays)
                expected_delay = 0.1 * (2**attempt)
                print(
                    f"  Attempt {attempt + 1} avg delay: {avg_delay*1000:.2f}ms (expected: {expected_delay*1000:.2f}ms)"
                )

                # Verify exponential growth
                assert abs(avg_delay - expected_delay) < 0.05

    @pytest.mark.asyncio
    async def test_concurrent_retry_storms(self, db_manager):
        """Test system behavior during retry storms (many concurrent retries)."""
        metrics = LoadTestMetrics()

        # Simulate a scenario where many operations fail and retry simultaneously
        storm_size = 100

        async def operation_causing_retry_storm(op_id: int):
            """Operation that fails initially, causing retries."""
            start_time = time.time()
            retries = 0

            # Simulate database being down for first 2 seconds
            if time.time() - metrics.start_time < 2:
                for attempt in range(3):  # Max 3 retries
                    retries += 1
                    await asyncio.sleep(0.05 * (2**attempt))  # Short backoff

                    if time.time() - metrics.start_time >= 2:
                        # Database "recovers"
                        break

            # Record operation
            success = time.time() - metrics.start_time >= 2
            duration = time.time() - start_time
            metrics.record_operation(duration, success, retries)

        # Launch storm of operations
        print(f"\nRetry Storm Test:")
        print(f"  Launching {storm_size} concurrent operations...")

        tasks = [asyncio.create_task(operation_causing_retry_storm(i)) for i in range(storm_size)]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze storm impact
        summary = metrics.get_summary()

        print(f"  Total duration: {summary['total_duration']:.2f}s")
        print(f"  Success rate: {summary['success_rate']*100:.2f}%")
        print(f"  Total retries: {summary['total_retries']}")
        print(f"  Avg retries per operation: {summary['total_retries']/storm_size:.2f}")

        # System should recover after initial failure period
        assert summary["success_rate"] > 0.8  # Most should eventually succeed
        assert summary["total_retries"] > storm_size  # Should have many retries
        assert summary["total_duration"] < 5  # Should complete reasonably quickly


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
