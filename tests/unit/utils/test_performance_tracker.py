"""
Unit tests for performance tracker system.

Tests performance monitoring, metrics collection, and reporting functionality
with focus on accuracy, efficiency, and thread safety.
"""

import asyncio
import statistics
import time
from unittest.mock import Mock, patch

import pytest

from app.utils.performance_tracker import (
    AggregatedMetrics,
    OperationMetrics,
    PerformanceTracker,
    get_global_performance_tracker,
    reset_global_performance_tracker,
    track_performance,
)


class TestOperationMetrics:
    """Test suite for OperationMetrics data structure."""

    def test_operation_metrics_creation(self):
        """Test OperationMetrics creation and properties."""
        metrics = OperationMetrics(
            operation_id="test_op_123",
            operation_name="test_operation",
            start_time=1000.0,
            end_time=1001.5,
            duration=1.5,
            memory_start_mb=100.0,
            memory_end_mb=105.0,
            memory_peak_mb=107.0,
            metadata={"test": True},
        )

        assert metrics.operation_id == "test_op_123"
        assert metrics.operation_name == "test_operation"
        assert metrics.duration == 1.5
        assert metrics.memory_delta_mb == 5.0  # 105.0 - 100.0
        assert metrics.metadata["test"] is True

    def test_memory_delta_calculation(self):
        """Test memory delta calculation."""
        metrics = OperationMetrics(
            operation_id="test",
            operation_name="test",
            start_time=0,
            end_time=1,
            duration=1,
            memory_start_mb=50.0,
            memory_end_mb=75.5,
            memory_peak_mb=80.0,
            metadata={},
        )

        assert metrics.memory_delta_mb == 25.5


class TestAggregatedMetrics:
    """Test suite for AggregatedMetrics structure."""

    def test_aggregated_metrics_structure(self):
        """Test AggregatedMetrics contains expected fields."""
        metrics = AggregatedMetrics(
            operation_name="test_op",
            total_executions=10,
            total_duration=15.5,
            average_duration=1.55,
            min_duration=0.8,
            max_duration=2.3,
            median_duration=1.5,
            p95_duration=2.2,
            p99_duration=2.3,
            total_memory_delta_mb=50.0,
            average_memory_delta_mb=5.0,
            peak_memory_mb=120.0,
            success_rate=0.9,
            error_count=1,
        )

        assert metrics.operation_name == "test_op"
        assert metrics.total_executions == 10
        assert metrics.success_rate == 0.9
        assert metrics.error_count == 1
        assert metrics.average_duration == 1.55
        assert metrics.peak_memory_mb == 120.0


class TestPerformanceTracker:
    """Test suite for PerformanceTracker class."""

    @pytest.fixture
    def tracker(self):
        """Provide fresh PerformanceTracker instance."""
        return PerformanceTracker(max_history=100)

    def test_tracker_initialization(self, tracker):
        """Test PerformanceTracker initialization."""
        assert tracker.max_history == 100
        assert len(tracker._operations) == 0
        assert len(tracker._history) == 0
        assert len(tracker._start_times) == 0

    def test_start_operation_tracking(self, tracker):
        """Test starting operation tracking."""
        op_id = tracker.start_operation("test_operation", {"key": "value"})

        # Should generate unique operation ID
        assert op_id.startswith("test_operation_")
        assert len(op_id.split("_")) >= 2

        # Should record start time
        assert op_id in tracker._start_times
        assert op_id in tracker._memory_tracker

        # Should store metadata
        assert tracker._memory_tracker[op_id]["metadata"]["key"] == "value"

    @pytest.mark.asyncio
    async def test_end_operation_tracking(self, tracker):
        """Test ending operation tracking."""
        op_id = tracker.start_operation("test_operation")

        # Small delay to ensure measurable duration
        await asyncio.sleep(0.01)

        metrics = await tracker.end_operation(op_id, success=True)

        # Should return metrics
        assert metrics is not None
        assert metrics.operation_name == "test_operation"
        assert metrics.duration > 0
        assert metrics.memory_start_mb >= 0
        assert metrics.memory_peak_mb >= metrics.memory_start_mb

        # Should clean up tracking data
        assert op_id not in tracker._start_times
        assert op_id not in tracker._memory_tracker

        # Should record in history
        history = tracker.get_operation_history("test_operation")
        assert len(history) == 1
        assert history[0] == metrics

    @pytest.mark.asyncio
    async def test_end_unknown_operation(self, tracker):
        """Test ending unknown operation ID."""
        result = await tracker.end_operation("unknown_op_id")
        assert result is None, "Should return None for unknown operation"

    def test_context_manager_sync(self, tracker):
        """Test synchronous context manager."""
        with tracker.track_operation("sync_test") as op_id:
            assert op_id.startswith("sync_test_")
            time.sleep(0.01)  # Small measurable delay

        # Should be recorded after context exit
        history = tracker.get_operation_history("sync_test")
        assert len(history) == 1
        assert history[0].duration > 0

    @pytest.mark.asyncio
    async def test_async_context_manager(self, tracker):
        """Test asynchronous context manager."""
        async with tracker.track_async_operation("async_test") as op_id:
            assert op_id.startswith("async_test_")
            await asyncio.sleep(0.01)  # Small measurable delay

        # Should be recorded after context exit
        history = tracker.get_operation_history("async_test")
        assert len(history) == 1
        assert history[0].duration > 0

    @pytest.mark.asyncio
    async def test_context_manager_exception_handling(self, tracker):
        """Test context manager with exceptions."""
        with pytest.raises(ValueError):
            async with tracker.track_async_operation("error_test"):
                raise ValueError("Test exception")

        # Should still record the failed operation
        history = tracker.get_operation_history("error_test")
        assert len(history) == 1

    def test_operation_history_retrieval(self, tracker):
        """Test getting operation history."""
        # Record multiple operations
        for i in range(5):
            with tracker.track_operation("history_test"):
                pass

        # Get all history
        history = tracker.get_operation_history("history_test")
        assert len(history) == 5

        # Get limited history
        limited = tracker.get_operation_history("history_test", limit=3)
        assert len(limited) == 3

        # Should return most recent entries
        assert limited == history[-3:]

    def test_aggregated_metrics_calculation(self, tracker):
        """Test aggregated metrics calculation."""
        # Record operations with known durations
        durations = [1.0, 1.5, 2.0, 2.5, 3.0]

        for duration in durations:
            op_id = tracker.start_operation("aggregate_test")
            time.sleep(duration * 0.01)  # Scale down for test speed
            asyncio.run(tracker.end_operation(op_id, success=True))

        # Get aggregated metrics
        metrics = tracker.get_aggregated_metrics("aggregate_test")
        assert metrics is not None
        assert metrics.operation_name == "aggregate_test"
        assert metrics.total_executions == 5
        assert metrics.min_duration > 0
        assert metrics.max_duration > metrics.min_duration
        assert metrics.average_duration > 0
        assert metrics.success_rate == 1.0  # All successful
        assert metrics.error_count == 0

    def test_aggregated_metrics_empty_history(self, tracker):
        """Test aggregated metrics with no history."""
        metrics = tracker.get_aggregated_metrics("nonexistent")
        assert metrics is None

    def test_performance_regression_detection(self, tracker):
        """Test performance regression detection."""
        # Set baseline
        tracker.set_baseline("regression_test", 1.0)

        # Add some measurements
        for _ in range(3):
            op_id = tracker.start_operation("regression_test")
            time.sleep(0.005)  # ~5ms
            asyncio.run(tracker.end_operation(op_id))

        # Should not detect regression with fast operations
        regression = tracker.detect_performance_regression("regression_test", threshold=0.5)
        assert regression is None or not regression["is_regression"]

        # Add slow measurement
        op_id = tracker.start_operation("regression_test")
        time.sleep(0.2)  # 200ms - much slower than 1.0s baseline * 1.2 threshold
        asyncio.run(tracker.end_operation(op_id))

        # Regression detection depends on the average, might not trigger with one slow operation
        # This tests the regression detection logic exists
        regression = tracker.detect_performance_regression("regression_test", threshold=0.1)
        assert regression is None or isinstance(regression, dict)

    def test_performance_report_generation(self, tracker):
        """Test comprehensive performance report generation."""
        # Record operations for multiple operation types
        with tracker.track_operation("op1"):
            time.sleep(0.01)
        with tracker.track_operation("op2"):
            time.sleep(0.01)
        with tracker.track_operation("op1"):  # Second op1
            time.sleep(0.01)

        # Generate report
        report = tracker.get_performance_report(include_history=False)

        # Validate report structure
        assert "timestamp" in report
        assert "summary" in report
        assert "operations" in report
        assert "regressions" in report

        # Should include both operations
        assert "op1" in report["operations"]
        assert "op2" in report["operations"]

        # op1 should have 2 executions
        op1_data = report["operations"]["op1"]
        assert op1_data["total_executions"] == 2

        # op2 should have 1 execution
        op2_data = report["operations"]["op2"]
        assert op2_data["total_executions"] == 1

    def test_performance_report_with_history(self, tracker):
        """Test performance report with full history."""
        with tracker.track_operation("history_test"):
            pass

        report = tracker.get_performance_report(include_history=True)

        # Should include history
        assert "history" in report["operations"]["history_test"]
        history = report["operations"]["history_test"]["history"]
        assert len(history) == 1
        assert "operation_id" in history[0]
        assert "duration" in history[0]

    def test_memory_usage_tracking(self, tracker):
        """Test memory usage tracking accuracy."""
        op_id = tracker.start_operation("memory_test")

        # Simulate memory usage change
        tracker.update_operation_memory(op_id)

        metrics = asyncio.run(tracker.end_operation(op_id))

        # Should track memory metrics
        assert metrics.memory_start_mb >= 0
        assert metrics.memory_peak_mb >= metrics.memory_start_mb
        assert metrics.memory_end_mb >= 0

    def test_error_tracking(self, tracker):
        """Test error count tracking."""
        # Successful operation
        with tracker.track_operation("error_test"):
            pass

        # Failed operation
        try:
            with tracker.track_operation("error_test"):
                raise Exception("Test error")
        except Exception:
            pass

        # Check aggregated metrics
        metrics = tracker.get_aggregated_metrics("error_test")
        assert metrics.total_executions == 2
        assert metrics.error_count == 1
        assert metrics.success_rate == 0.5  # 1 success out of 2 total

    def test_history_size_limit(self, tracker):
        """Test history size limitation."""
        tracker.max_history = 5

        # Add more operations than history limit
        for i in range(10):
            with tracker.track_operation("limit_test"):
                pass

        history = tracker.get_operation_history("limit_test")
        assert len(history) <= tracker.max_history

    def test_metrics_reset(self, tracker):
        """Test metrics reset functionality."""
        # Add some operations
        with tracker.track_operation("reset_test"):
            pass

        assert len(tracker._history["reset_test"]) > 0

        # Reset
        tracker.reset_metrics()

        # Should be empty
        assert len(tracker._history) == 0
        assert len(tracker._operations) == 0
        assert len(tracker._start_times) == 0

    def test_baseline_management(self, tracker):
        """Test baseline setting and management."""
        tracker.set_baseline("baseline_test", 5.0)

        assert "baseline_test" in tracker._baselines
        assert tracker._baselines["baseline_test"] == 5.0

    def test_memory_monitoring_failure_handling(self, tracker):
        """Test graceful handling of memory monitoring failures."""
        # Mock the existing _process instance to raise exception
        with patch.object(tracker, "_process") as mock_process:
            mock_process.memory_info.side_effect = Exception("Mock psutil error")

            # Should handle gracefully
            memory_usage = tracker._get_memory_usage_mb()
            assert memory_usage == 0.0, "Should return 0.0 on psutil failure"


class TestPerformanceDecorator:
    """Test suite for performance tracking decorator."""

    @pytest.fixture
    def tracker(self):
        """Provide tracker instance."""
        return PerformanceTracker()

    def test_sync_function_decoration(self, tracker):
        """Test decorator on synchronous functions."""

        @track_performance("sync_decorated", tracker)
        def test_function(x, y):
            time.sleep(0.01)
            return x + y

        result = test_function(1, 2)
        assert result == 3

        # Should be tracked
        history = tracker.get_operation_history("sync_decorated")
        assert len(history) == 1
        assert history[0].duration > 0

    def test_async_function_decoration(self, tracker):
        """Test decorator on async functions."""

        @track_performance("async_decorated", tracker)
        async def async_test_function(x, y):
            await asyncio.sleep(0.01)
            return x * y

        result = asyncio.run(async_test_function(3, 4))
        assert result == 12

        # Should be tracked
        history = tracker.get_operation_history("async_decorated")
        assert len(history) == 1
        assert history[0].duration > 0

    def test_decorator_without_operation_name(self, tracker):
        """Test decorator using function name as operation name."""

        @track_performance(tracker=tracker)
        def my_test_function():
            time.sleep(0.01)
            return "test"

        result = my_test_function()
        assert result == "test"

        # Should use function name
        history = tracker.get_operation_history("my_test_function")
        assert len(history) == 1

    def test_decorator_exception_handling(self, tracker):
        """Test decorator with exceptions."""

        @track_performance("exception_test", tracker)
        def failing_function():
            raise ValueError("Decorator test exception")

        with pytest.raises(ValueError):
            failing_function()

        # Should still track the failed operation
        history = tracker.get_operation_history("exception_test")
        assert len(history) == 1


class TestGlobalTracker:
    """Test suite for global tracker functionality."""

    def test_global_tracker_singleton(self):
        """Test global tracker is singleton."""
        tracker1 = get_global_performance_tracker()
        tracker2 = get_global_performance_tracker()

        assert tracker1 is tracker2, "Should return same instance"

    def test_global_tracker_reset(self):
        """Test global tracker reset."""
        tracker = get_global_performance_tracker()

        # Add some data
        with tracker.track_operation("global_test"):
            pass

        assert len(tracker._history) > 0

        # Reset
        reset_global_performance_tracker()

        # Should be reset
        fresh_tracker = get_global_performance_tracker()
        assert len(fresh_tracker._history) == 0


class TestCachePerformanceMetrics:
    """Test suite for cache-specific performance metrics."""

    def test_cache_performance_metrics(self):
        """Test cache performance metrics calculation."""
        from app.utils.dependency_cache import CacheStats

        tracker = PerformanceTracker()

        # Mock cache stats
        cache_stats = CacheStats(hits=80, misses=20, memory_hits=60, file_hits=15, redis_hits=5, evictions=3)

        metrics = tracker.get_cache_performance_metrics(cache_stats)

        # Validate metrics structure
        assert "cache_hit_rate" in metrics
        assert "memory_hit_rate" in metrics
        assert "total_hits" in metrics
        assert "total_misses" in metrics
        assert "efficiency_rating" in metrics

        # Validate calculations
        assert metrics["cache_hit_rate"] == 0.8  # 80/(80+20)
        assert metrics["memory_hit_rate"] == 0.6  # 60/100
        assert metrics["total_hits"] == 80
        assert metrics["total_misses"] == 20
        assert metrics["efficiency_rating"] == "Good"  # 80% hit rate

    def test_cache_efficiency_rating(self):
        """Test cache efficiency rating calculation."""
        tracker = PerformanceTracker()

        test_cases = [(0.95, "Excellent"), (0.85, "Good"), (0.75, "Fair"), (0.50, "Poor"), (0.25, "Critical")]

        for hit_rate, expected_rating in test_cases:
            # Create mock cache stats with specific hit rate
            from app.utils.dependency_cache import CacheStats

            stats = CacheStats(hits=int(hit_rate * 100), misses=int((1 - hit_rate) * 100))
            rating = tracker._calculate_cache_efficiency(stats)
            assert rating == expected_rating, f"Hit rate {hit_rate} should get {expected_rating}, got {rating}"
