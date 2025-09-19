"""Tests for runtime dependency tracer."""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.dependency.runtime_tracer import (
    DependencyPattern,
    RuntimeDependencyAnalysis,
    RuntimeDependencyTracer,
    RuntimeTrace,
)


class TestRuntimeDependencyTracer:
    """Test cases for RuntimeDependencyTracer."""

    @pytest.fixture
    def tracer(self):
        """Create a runtime dependency tracer instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield RuntimeDependencyTracer(temp_dir)

    def test_tracer_initialization(self, tracer):
        """Test tracer initialization."""
        assert tracer.project_root is not None
        assert len(tracer.traces) == 0
        assert tracer.current_trace is None
        assert len(tracer.trace_stack) == 0

    def test_trace_dependencies_context_manager(self, tracer):
        """Test dependency tracing with context manager."""
        operation_name = "test_operation"

        with tracer.trace_dependencies(operation_name) as trace:
            assert trace.operation_name == operation_name
            assert trace.start_time > 0
            assert tracer.current_trace == trace
            assert len(tracer.trace_stack) == 1

            # Simulate some work
            time.sleep(0.01)

        # After context exit
        assert tracer.current_trace is None
        assert len(tracer.trace_stack) == 0
        assert len(tracer.traces) == 1

        completed_trace = tracer.traces[0]
        assert completed_trace.operation_name == operation_name
        assert completed_trace.end_time > completed_trace.start_time
        assert completed_trace.duration > 0

    @pytest.mark.asyncio
    async def test_async_trace_dependencies(self, tracer):
        """Test async dependency tracing."""
        operation_name = "async_test_operation"

        async with tracer.async_trace_dependencies(operation_name) as trace:
            assert trace.operation_name == operation_name
            assert tracer.current_trace == trace

            # Simulate async work
            await asyncio.sleep(0.01)

        assert len(tracer.traces) == 1
        completed_trace = tracer.traces[0]
        assert completed_trace.operation_name == operation_name
        assert completed_trace.duration > 0

    def test_record_dependency_access(self, tracer):
        """Test recording dependency access."""
        with tracer.trace_dependencies("test_op") as trace:
            tracer.record_dependency_access("database", "query")
            tracer.record_dependency_access("cache", "get")
            tracer.record_dependency_access("database", "update")  # Duplicate

        completed_trace = tracer.traces[0]
        assert "database" in completed_trace.dependencies_accessed
        assert "cache" in completed_trace.dependencies_accessed
        assert len(completed_trace.dependencies_accessed) == 2  # No duplicates

    def test_record_database_query(self, tracer):
        """Test recording database query information."""
        with tracer.trace_dependencies("test_op") as trace:
            tracer.record_database_query("SELECT * FROM users WHERE id = ?", 0.05, "users", "SELECT")  # nosec B608

        completed_trace = tracer.traces[0]
        assert len(completed_trace.database_queries) == 1
        assert "database" in completed_trace.dependencies_accessed

        query_info = completed_trace.database_queries[0]
        assert query_info["operation"] == "SELECT"
        assert query_info["table"] == "users"
        assert query_info["duration"] == 0.05

    def test_record_cache_operation(self, tracer):
        """Test recording cache operation information."""
        with tracer.trace_dependencies("test_op") as trace:
            tracer.record_cache_operation("GET", "user:123", 0.01, True)
            tracer.record_cache_operation("SET", "user:456", 0.02, False)

        completed_trace = tracer.traces[0]
        assert len(completed_trace.cache_operations) == 2
        assert "cache" in completed_trace.dependencies_accessed

        get_op = completed_trace.cache_operations[0]
        assert get_op["operation"] == "GET"
        assert get_op["key"] == "user:123"
        assert get_op["hit"] is True

    def test_record_middleware_call(self, tracer):
        """Test recording middleware calls."""
        with tracer.trace_dependencies("test_op") as trace:
            tracer.record_middleware_call("AuthenticationMiddleware")
            tracer.record_middleware_call("AuthorizationMiddleware")

        completed_trace = tracer.traces[0]
        assert "AuthenticationMiddleware" in completed_trace.middleware_calls
        assert "AuthorizationMiddleware" in completed_trace.middleware_calls
        assert "middleware_AuthenticationMiddleware" in completed_trace.dependencies_accessed

    def test_record_repository_call(self, tracer):
        """Test recording repository method calls."""
        with tracer.trace_dependencies("test_op") as trace:
            tracer.record_repository_call("UserRepository", "get_by_id")
            tracer.record_repository_call("APIKeyRepository", "validate")

        completed_trace = tracer.traces[0]
        assert "UserRepository.get_by_id" in completed_trace.repository_calls
        assert "APIKeyRepository.validate" in completed_trace.repository_calls
        assert "repository_UserRepository" in completed_trace.dependencies_accessed

    def test_trace_error_handling(self, tracer):
        """Test error handling during tracing."""
        try:
            with tracer.trace_dependencies("error_test") as trace:
                raise ValueError("Test error")
        except ValueError:
            pass  # Expected

        completed_trace = tracer.traces[0]
        assert len(completed_trace.errors) == 1
        assert "Test error" in completed_trace.errors[0]

    def test_nested_traces(self, tracer):
        """Test nested dependency tracing."""
        with tracer.trace_dependencies("outer_operation") as outer_trace:
            tracer.record_dependency_access("database")

            with tracer.trace_dependencies("inner_operation") as inner_trace:
                tracer.record_dependency_access("cache")
                assert tracer.current_trace == inner_trace
                assert len(tracer.trace_stack) == 2

            # After inner trace completes
            assert tracer.current_trace == outer_trace
            assert len(tracer.trace_stack) == 1

        # Both traces should be recorded
        assert len(tracer.traces) == 2
        outer_completed = [t for t in tracer.traces if t.operation_name == "outer_operation"][0]
        inner_completed = [t for t in tracer.traces if t.operation_name == "inner_operation"][0]

        assert "database" in outer_completed.dependencies_accessed
        assert "cache" in inner_completed.dependencies_accessed

    def test_analyze_dependency_patterns_empty(self, tracer):
        """Test dependency pattern analysis with no traces."""
        analysis = tracer.analyze_dependency_patterns()

        assert isinstance(analysis, RuntimeDependencyAnalysis)
        assert analysis.metadata["total_traces"] == 0
        assert len(analysis.dependency_patterns) == 0

    def test_analyze_dependency_patterns_with_data(self, tracer):
        """Test dependency pattern analysis with trace data."""
        # Create multiple traces with patterns
        for i in range(5):
            with tracer.trace_dependencies(f"operation_{i}") as trace:
                tracer.record_database_query(f"SELECT * FROM table_{i}", 0.1 + i * 0.01)  # nosec B608
                tracer.record_cache_operation("GET", f"key_{i}", 0.01)
                tracer.record_repository_call("UserRepository", "get_by_id")

                if i % 2 == 0:  # Add errors to some traces
                    trace.errors.append(f"Error in operation {i}")

        analysis = tracer.analyze_dependency_patterns()

        assert analysis.metadata["total_traces"] == 5
        assert len(analysis.dependency_patterns) > 0

        # Check that database dependency pattern exists
        db_pattern = next((p for p in analysis.dependency_patterns if p.dependency_name == "database"), None)
        assert db_pattern is not None
        assert db_pattern.frequency == 5  # Used in all operations

        # Check performance summary
        assert "total_operations" in analysis.performance_summary
        assert analysis.performance_summary["total_operations"] == 5

    def test_bottleneck_identification(self, tracer):
        """Test bottleneck identification in dependency patterns."""
        # Create traces with different performance characteristics

        # High frequency dependency
        for i in range(10):
            with tracer.trace_dependencies(f"frequent_op_{i}"):
                tracer.record_dependency_access("high_frequency_service")

        # Slow dependency
        with tracer.trace_dependencies("slow_op"):
            time.sleep(0.1)  # Simulate slow operation
            tracer.record_dependency_access("slow_service")

        # Error-prone dependency
        for i in range(5):
            with tracer.trace_dependencies(f"error_op_{i}") as trace:
                tracer.record_dependency_access("error_prone_service")
                if i < 3:  # 60% error rate
                    trace.errors.append("Service error")

        analysis = tracer.analyze_dependency_patterns()

        # Check bottleneck analysis
        bottlenecks = analysis.bottleneck_analysis
        assert "high_frequency_dependencies" in bottlenecks
        assert "slow_dependencies" in bottlenecks
        assert "error_prone_dependencies" in bottlenecks
        assert "recommendations" in bottlenecks

        # Verify recommendations exist
        assert len(bottlenecks["recommendations"]) > 0

    def test_failure_pattern_analysis(self, tracer):
        """Test failure pattern analysis."""
        # Create traces with various error patterns
        errors = ["Connection timeout", "Database error", "Connection timeout"]

        for i, error in enumerate(errors):
            with tracer.trace_dependencies(f"error_op_{i}") as trace:
                trace.errors.append(error)

        analysis = tracer.analyze_dependency_patterns()
        failure_patterns = analysis.failure_patterns

        assert "common_errors" in failure_patterns
        assert failure_patterns["common_errors"]["Connection timeout"] == 2
        assert failure_patterns["common_errors"]["Database error"] == 1

    def test_performance_metrics_collection(self, tracer):
        """Test performance metrics collection during tracing."""
        with patch("psutil.Process") as mock_process:
            mock_instance = MagicMock()
            mock_instance.memory_info.return_value.rss = 1000000
            mock_instance.cpu_percent.return_value = 50.0
            mock_process.return_value = mock_instance

            with tracer.trace_dependencies("perf_test") as trace:
                time.sleep(0.01)

            completed_trace = tracer.traces[0]
            assert "memory_delta" in completed_trace.performance_metrics
            assert "cpu_usage" in completed_trace.performance_metrics
            assert "gc_collections" in completed_trace.performance_metrics

    def test_export_analysis(self, tracer):
        """Test exporting analysis results to JSON."""
        # Create some trace data
        with tracer.trace_dependencies("export_test") as trace:
            tracer.record_database_query("SELECT 1", 0.01)  # nosec B608
            tracer.record_cache_operation("GET", "test_key", 0.005, True)

        analysis = tracer.analyze_dependency_patterns()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            output_path = temp_file.name

        try:
            tracer.export_analysis(analysis, output_path)

            # Verify file was created and contains valid JSON
            assert Path(output_path).exists()

            with open(output_path, "r") as f:
                exported_data = json.load(f)

            assert "metadata" in exported_data
            assert "operation_traces" in exported_data
            assert "dependency_patterns" in exported_data
            assert "performance_summary" in exported_data

        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_clear_traces(self, tracer):
        """Test clearing collected traces."""
        # Create some traces
        with tracer.trace_dependencies("test1"):
            pass
        with tracer.trace_dependencies("test2"):
            pass

        assert len(tracer.traces) == 2

        tracer.clear_traces()

        assert len(tracer.traces) == 0
        assert tracer.current_trace is None
        assert len(tracer.trace_stack) == 0

    @pytest.mark.asyncio
    async def test_monitor_live_dependencies(self, tracer):
        """Test live dependency monitoring."""
        # Mock the monitoring duration to be very short
        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = asyncio.sleep(0.01)  # Very short sleep

            analysis = await tracer.monitor_live_dependencies(duration=1)

            assert isinstance(analysis, RuntimeDependencyAnalysis)
            assert analysis.metadata["total_traces"] >= 1

    def test_long_query_truncation(self, tracer):
        """Test that long database queries are truncated."""
        long_query = "SELECT * FROM users WHERE " + "x = 1 AND " * 100  # nosec B608 # Very long query

        with tracer.trace_dependencies("truncation_test"):
            tracer.record_database_query(long_query, 0.1)

        completed_trace = tracer.traces[0]
        recorded_query = completed_trace.database_queries[0]["query"]

        assert len(recorded_query) <= 500  # Should be truncated
        assert recorded_query in long_query  # Should be a substring

    def test_long_cache_key_truncation(self, tracer):
        """Test that long cache keys are truncated."""
        long_key = "user:data:" + "x" * 200  # Very long key

        with tracer.trace_dependencies("key_truncation_test"):
            tracer.record_cache_operation("GET", long_key, 0.01)

        completed_trace = tracer.traces[0]
        recorded_key = completed_trace.cache_operations[0]["key"]

        assert len(recorded_key) <= 100  # Should be truncated
        assert recorded_key in long_key  # Should be a substring

    def test_dependency_pattern_properties(self, tracer):
        """Test dependency pattern calculation properties."""
        # Create traces with known patterns
        durations = [0.1, 0.2, 0.3]  # Known durations

        for i, duration in enumerate(durations):
            with tracer.trace_dependencies(f"pattern_test_{i}"):
                tracer.record_dependency_access("test_service")
                time.sleep(duration)

        analysis = tracer.analyze_dependency_patterns()

        test_pattern = next((p for p in analysis.dependency_patterns if p.dependency_name == "test_service"), None)

        assert test_pattern is not None
        assert test_pattern.frequency == 3
        assert test_pattern.error_rate == 0.0  # No errors
        assert test_pattern.average_duration > 0
        assert len(test_pattern.peak_usage_times) == 3
