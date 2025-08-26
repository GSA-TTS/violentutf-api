"""
Performance tracking and monitoring utilities for dependency operations.

Provides comprehensive performance monitoring, metrics collection, and
reporting capabilities for PyTestArch optimization tracking.

Implements ADR-015 performance monitoring requirements.
"""

import asyncio
import os
import statistics
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    TypeVar,
    Union,
    cast,
    overload,
)

if TYPE_CHECKING:
    from app.utils.dependency_cache import CacheStats
else:
    # Avoid circular imports at runtime
    CacheStats = Any

import psutil
from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class OperationMetrics:
    """Metrics for a single operation execution."""

    operation_id: str
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    memory_start_mb: float
    memory_end_mb: float
    memory_peak_mb: float
    metadata: Dict[str, Any]

    @property
    def memory_delta_mb(self) -> float:
        """Memory change during operation."""
        return self.memory_end_mb - self.memory_start_mb


@dataclass
class AggregatedMetrics:
    """Aggregated metrics for an operation type."""

    operation_name: str
    total_executions: int
    total_duration: float
    average_duration: float
    min_duration: float
    max_duration: float
    median_duration: float
    p95_duration: float
    p99_duration: float
    total_memory_delta_mb: float
    average_memory_delta_mb: float
    peak_memory_mb: float
    success_rate: float
    error_count: int


class PerformanceTracker:
    """
    High-performance tracking system for dependency operations.

    Provides:
    - Operation timing with microsecond precision
    - Memory usage monitoring
    - Statistical analysis and reporting
    - Performance regression detection
    - Resource usage optimization tracking
    """

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._operations: Dict[str, OperationMetrics] = {}
        self._history: defaultdict[str, deque[OperationMetrics]] = defaultdict(lambda: deque(maxlen=max_history))
        self._start_times: Dict[str, float] = {}
        self._memory_tracker: Dict[str, Dict[str, Any]] = {}
        self._error_counts: defaultdict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

        # Performance baselines for regression detection
        self._baselines: Dict[str, float] = {
            "dependency_scan": 120.0,  # Current baseline: 120s
            "package_metadata_fetch": 0.5,  # Per package
            "license_validation": 0.3,  # Per package
            "vulnerability_scan": 1.0,  # Per package
        }

        # Get process for memory monitoring
        self._process = psutil.Process(os.getpid())

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        try:
            return float(self._process.memory_info().rss / 1024 / 1024)
        except Exception:
            return 0.0

    def start_operation(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Start tracking an operation.

        Args:
            operation_name: Name of the operation being tracked
            metadata: Additional metadata to associate with the operation

        Returns:
            Unique operation ID for this execution
        """
        operation_id = f"{operation_name}_{uuid.uuid4().hex[:8]}"
        start_time = time.perf_counter()
        memory_mb = self._get_memory_usage_mb()

        self._start_times[operation_id] = start_time
        self._memory_tracker[operation_id] = {
            "start": memory_mb,
            "peak": memory_mb,
            "metadata": metadata or {},
        }

        logger.debug(
            "Started operation tracking",
            operation_id=operation_id,
            operation_name=operation_name,
            memory_mb=memory_mb,
        )

        return operation_id

    def update_operation_memory(self, operation_id: str) -> None:
        """Update peak memory usage for an operation."""
        if operation_id in self._memory_tracker:
            current_memory = self._get_memory_usage_mb()
            if current_memory > self._memory_tracker[operation_id]["peak"]:
                self._memory_tracker[operation_id]["peak"] = current_memory

    async def end_operation(self, operation_id: str, success: bool = True) -> Optional[OperationMetrics]:
        """
        End tracking an operation and record metrics.

        Args:
            operation_id: Operation ID from start_operation
            success: Whether the operation completed successfully

        Returns:
            OperationMetrics for the completed operation
        """
        if operation_id not in self._start_times:
            logger.warning("Attempted to end unknown operation", operation_id=operation_id)
            return None

        end_time = time.perf_counter()
        start_time = self._start_times.pop(operation_id)
        duration = end_time - start_time

        memory_info = self._memory_tracker.pop(operation_id, {})
        memory_start = memory_info.get("start", 0.0)
        memory_peak = memory_info.get("peak", 0.0)
        memory_end = self._get_memory_usage_mb()
        metadata: Dict[str, Any] = memory_info.get("metadata", {})

        # Extract operation name from ID
        operation_name = "_".join(operation_id.split("_")[:-1])

        metrics = OperationMetrics(
            operation_id=operation_id,
            operation_name=operation_name,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            memory_start_mb=memory_start,
            memory_end_mb=memory_end,
            memory_peak_mb=memory_peak,
            metadata=metadata,
        )

        async with self._lock:
            # Store in history
            self._history[operation_name].append(metrics)

            # Track errors
            if not success:
                self._error_counts[operation_name] += 1

        logger.info(
            "Operation completed",
            operation_name=operation_name,
            duration=duration,
            memory_delta_mb=metrics.memory_delta_mb,
            success=success,
        )

        return metrics

    @contextmanager
    def track_operation(
        self, operation_name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> Generator[str, None, None]:
        """
        Context manager for tracking operation performance.

        Usage:
            with tracker.track_operation("dependency_scan") as op_id:
                # Do work
                pass
        """
        operation_id = self.start_operation(operation_name, metadata)
        success = False
        try:
            yield operation_id
            success = True
        except Exception:
            success = False
            raise
        finally:
            # Use asyncio.create_task for async cleanup
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.end_operation(operation_id, success))
                else:
                    # Fallback for sync context
                    asyncio.run(self.end_operation(operation_id, success))
            except RuntimeError:
                # No event loop running, create new one
                asyncio.run(self.end_operation(operation_id, success))

    @asynccontextmanager
    async def track_async_operation(
        self, operation_name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[str, None]:
        """
        Async context manager for tracking operation performance.

        Usage:
            async with tracker.track_async_operation("dependency_scan") as op_id:
                # Do async work
                await some_async_function()
        """
        operation_id = self.start_operation(operation_name, metadata)
        success = False
        try:
            yield operation_id
            success = True
        except Exception:
            success = False
            raise
        finally:
            await self.end_operation(operation_id, success)

    def get_operation_history(self, operation_name: str, limit: Optional[int] = None) -> List[OperationMetrics]:
        """Get execution history for an operation."""
        history = list(self._history[operation_name])
        if limit:
            history = history[-limit:]
        return history

    def get_aggregated_metrics(self, operation_name: str) -> Optional[AggregatedMetrics]:
        """Get aggregated metrics for an operation type."""
        if operation_name not in self._history or not self._history[operation_name]:
            return None

        history = list(self._history[operation_name])
        durations = [op.duration for op in history]
        memory_deltas = [op.memory_delta_mb for op in history]

        if not durations:
            return None

        # Calculate statistics
        total_executions = len(history)
        total_duration = sum(durations)
        average_duration = statistics.mean(durations)
        min_duration = min(durations)
        max_duration = max(durations)
        median_duration = statistics.median(durations)

        # Percentiles
        sorted_durations = sorted(durations)
        p95_duration = (
            sorted_durations[int(0.95 * len(sorted_durations))] if len(sorted_durations) > 1 else sorted_durations[0]
        )
        p99_duration = (
            sorted_durations[int(0.99 * len(sorted_durations))] if len(sorted_durations) > 1 else sorted_durations[0]
        )

        # Memory statistics
        total_memory_delta = sum(memory_deltas)
        avg_memory_delta = statistics.mean(memory_deltas) if memory_deltas else 0.0
        peak_memory = max(op.memory_peak_mb for op in history)

        # Success rate
        error_count = self._error_counts[operation_name]
        success_rate = (total_executions - error_count) / total_executions if total_executions > 0 else 0.0

        return AggregatedMetrics(
            operation_name=operation_name,
            total_executions=total_executions,
            total_duration=total_duration,
            average_duration=average_duration,
            min_duration=min_duration,
            max_duration=max_duration,
            median_duration=median_duration,
            p95_duration=p95_duration,
            p99_duration=p99_duration,
            total_memory_delta_mb=total_memory_delta,
            average_memory_delta_mb=avg_memory_delta,
            peak_memory_mb=peak_memory,
            success_rate=success_rate,
            error_count=error_count,
        )

    def detect_performance_regression(self, operation_name: str, threshold: float = 0.2) -> Optional[Dict[str, Any]]:
        """
        Detect performance regression compared to baseline.

        Args:
            operation_name: Name of operation to check
            threshold: Regression threshold (20% = 0.2)

        Returns:
            Regression details if detected, None otherwise
        """
        if operation_name not in self._baselines:
            return None

        metrics = self.get_aggregated_metrics(operation_name)
        if not metrics:
            return None

        baseline = self._baselines[operation_name]
        current_avg = metrics.average_duration

        regression_factor = (current_avg - baseline) / baseline

        if regression_factor > threshold:
            return {
                "operation_name": operation_name,
                "baseline_duration": baseline,
                "current_avg_duration": current_avg,
                "regression_factor": regression_factor,
                "regression_percentage": regression_factor * 100,
                "threshold_percentage": threshold * 100,
                "is_regression": True,
                "sample_size": metrics.total_executions,
            }

        return None

    def get_performance_report(self, include_history: bool = False) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.

        Args:
            include_history: Whether to include full execution history

        Returns:
            Comprehensive performance report dictionary
        """
        report: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_operations_tracked": len(self._history),
                "total_executions": sum(len(history) for history in self._history.values()),
                "memory_usage_mb": self._get_memory_usage_mb(),
            },
            "operations": {},
            "regressions": [],
        }

        # Process each operation type
        for operation_name in self._history.keys():
            metrics = self.get_aggregated_metrics(operation_name)
            if metrics:
                report["operations"][operation_name] = asdict(metrics)

                # Check for regressions
                regression = self.detect_performance_regression(operation_name)
                if regression:
                    report["regressions"].append(regression)

                # Include history if requested
                if include_history:
                    history = self.get_operation_history(operation_name)
                    report["operations"][operation_name]["history"] = [asdict(op) for op in history]

        return report

    def get_cache_performance_metrics(self, cache_stats: CacheStats) -> Dict[str, Any]:
        """
        Generate cache-specific performance metrics.

        Args:
            cache_stats: CacheStats instance from DependencyCache

        Returns:
            Cache performance metrics
        """
        return {
            "cache_hit_rate": cache_stats.hit_rate,
            "memory_hit_rate": cache_stats.memory_hit_rate,
            "total_hits": cache_stats.hits,
            "total_misses": cache_stats.misses,
            "memory_hits": cache_stats.memory_hits,
            "file_hits": cache_stats.file_hits,
            "redis_hits": cache_stats.redis_hits,
            "evictions": cache_stats.evictions,
            "efficiency_rating": self._calculate_cache_efficiency(cache_stats),
        }

    def _calculate_cache_efficiency(self, cache_stats: CacheStats) -> str:
        """Calculate cache efficiency rating."""
        hit_rate = cache_stats.hit_rate

        if hit_rate >= 0.9:
            return "Excellent"
        elif hit_rate >= 0.8:
            return "Good"
        elif hit_rate >= 0.6:
            return "Fair"
        elif hit_rate >= 0.4:
            return "Poor"
        else:
            return "Critical"

    def reset_metrics(self) -> None:
        """Reset all tracked metrics."""
        self._operations.clear()
        self._history.clear()
        self._start_times.clear()
        self._memory_tracker.clear()
        self._error_counts.clear()

        logger.info("Performance metrics reset")

    def set_baseline(self, operation_name: str, duration: float) -> None:
        """Set performance baseline for regression detection."""
        self._baselines[operation_name] = duration
        logger.info(
            "Performance baseline set",
            operation=operation_name,
            baseline_duration=duration,
        )


# Type variables for the decorator
F = TypeVar("F", bound=Callable[..., Any])
AF = TypeVar("AF", bound=Callable[..., Awaitable[Any]])


# Decorator for automatic performance tracking
@overload
def track_performance(operation_name: str, tracker: Optional[PerformanceTracker] = None) -> Callable[[F], F]: ...


@overload
def track_performance(*, tracker: Optional[PerformanceTracker] = None) -> Callable[[F], F]: ...


def track_performance(
    operation_name: Optional[str] = None, tracker: Optional[PerformanceTracker] = None
) -> Callable[[F], F]:
    """
    Decorator to automatically track function performance.

    Usage:
        @track_performance("my_operation")
        def my_function():
            pass

        @track_performance()  # Uses function name
        async def my_async_function():
            pass
    """

    def decorator(func: F) -> F:
        nonlocal operation_name, tracker

        if operation_name is None:
            operation_name = func.__name__

        if tracker is None:
            tracker = get_global_performance_tracker()

        if asyncio.iscoroutinefunction(func):

            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                async with tracker.track_async_operation(operation_name):
                    return await func(*args, **kwargs)

            return cast(F, async_wrapper)
        else:

            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                with tracker.track_operation(operation_name):
                    return func(*args, **kwargs)

            return cast(F, sync_wrapper)

    return decorator


# Global performance tracker instance
_global_tracker: Optional[PerformanceTracker] = None


def get_global_performance_tracker() -> PerformanceTracker:
    """Get global performance tracker instance."""
    global _global_tracker

    if _global_tracker is None:
        _global_tracker = PerformanceTracker()

    return _global_tracker


def reset_global_performance_tracker() -> None:
    """Reset global performance tracker."""
    global _global_tracker

    if _global_tracker is not None:
        _global_tracker.reset_metrics()
    else:
        _global_tracker = PerformanceTracker()
