"""Runtime dependency tracing tool for ViolentUTF API."""

import asyncio
import gc
import json
import time
from collections import defaultdict
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import psutil
from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class RuntimeTrace:
    """Runtime dependency trace information."""

    operation_name: str
    start_time: float
    end_time: float
    duration: float
    dependencies_accessed: List[str]
    database_queries: List[Dict[str, Any]]
    cache_operations: List[Dict[str, Any]]
    middleware_calls: List[str]
    repository_calls: List[str]
    errors: List[str]
    performance_metrics: Dict[str, Any]


@dataclass
class DependencyPattern:
    """Dependency usage pattern."""

    dependency_name: str
    frequency: int
    average_duration: float
    error_rate: float
    peak_usage_times: List[str]
    bottleneck_indicators: List[str]


@dataclass
class RuntimeDependencyAnalysis:
    """Results of runtime dependency analysis."""

    metadata: Dict[str, Any]
    operation_traces: List[RuntimeTrace]
    dependency_patterns: List[DependencyPattern]
    performance_summary: Dict[str, Any]
    bottleneck_analysis: Dict[str, Any]
    failure_patterns: Dict[str, Any]


class RuntimeDependencyTracer:
    """Runtime dependency tracing and analysis."""

    def __init__(self, project_root: str = "."):
        """Initialize the runtime tracer."""
        self.project_root = Path(project_root)
        self.traces: List[RuntimeTrace] = []
        self.current_trace: Optional[RuntimeTrace] = None
        self.trace_stack: List[RuntimeTrace] = []
        self.dependency_stats = defaultdict(list)

        logger.info("RuntimeDependencyTracer initialized", project_root=str(self.project_root))

    @contextmanager
    def trace_dependencies(self, operation_name: str):
        """Trace dependencies during operation execution."""
        trace = RuntimeTrace(
            operation_name=operation_name,
            start_time=time.time(),
            end_time=0.0,
            duration=0.0,
            dependencies_accessed=[],
            database_queries=[],
            cache_operations=[],
            middleware_calls=[],
            repository_calls=[],
            errors=[],
            performance_metrics={},
        )

        # Store previous trace and set current
        previous_trace = self.current_trace
        self.current_trace = trace
        self.trace_stack.append(trace)

        try:
            logger.info("Starting dependency trace", operation=operation_name)

            # Capture initial system state
            initial_memory = psutil.Process().memory_info().rss
            initial_cpu = psutil.Process().cpu_percent()

            yield trace

            # Capture final system state
            final_memory = psutil.Process().memory_info().rss
            final_cpu = psutil.Process().cpu_percent()

            trace.end_time = time.time()
            trace.duration = trace.end_time - trace.start_time
            trace.performance_metrics = {
                "memory_delta": final_memory - initial_memory,
                "cpu_usage": final_cpu,
                "cpu_delta": final_cpu - initial_cpu,
                "gc_collections": gc.get_count(),
            }

            logger.info(
                "Dependency trace completed",
                operation=operation_name,
                duration=trace.duration,
                dependencies_count=len(trace.dependencies_accessed),
            )

        except Exception as e:
            trace.errors.append(str(e))
            logger.error("Error during dependency trace", operation=operation_name, error=str(e))
            raise
        finally:
            # Restore previous trace
            self.current_trace = previous_trace
            if self.trace_stack:
                self.trace_stack.pop()

            # Store completed trace
            self.traces.append(trace)

    @asynccontextmanager
    async def async_trace_dependencies(self, operation_name: str):
        """Async version of trace dependencies."""
        trace = RuntimeTrace(
            operation_name=operation_name,
            start_time=time.time(),
            end_time=0.0,
            duration=0.0,
            dependencies_accessed=[],
            database_queries=[],
            cache_operations=[],
            middleware_calls=[],
            repository_calls=[],
            errors=[],
            performance_metrics={},
        )

        previous_trace = self.current_trace
        self.current_trace = trace
        self.trace_stack.append(trace)

        try:
            logger.info("Starting async dependency trace", operation=operation_name)

            initial_memory = psutil.Process().memory_info().rss
            initial_cpu = psutil.Process().cpu_percent()

            yield trace

            final_memory = psutil.Process().memory_info().rss
            final_cpu = psutil.Process().cpu_percent()

            trace.end_time = time.time()
            trace.duration = trace.end_time - trace.start_time
            trace.performance_metrics = {
                "memory_delta": final_memory - initial_memory,
                "cpu_usage": final_cpu,
                "cpu_delta": final_cpu - initial_cpu,
                "gc_collections": gc.get_count(),
            }

            logger.info("Async dependency trace completed", operation=operation_name, duration=trace.duration)

        except Exception as e:
            trace.errors.append(str(e))
            logger.error("Error during async dependency trace", operation=operation_name, error=str(e))
            raise
        finally:
            self.current_trace = previous_trace
            if self.trace_stack:
                self.trace_stack.pop()
            self.traces.append(trace)

    def record_dependency_access(self, dependency_name: str, operation_type: str = "access"):
        """Record access to a dependency."""
        if self.current_trace:
            if dependency_name not in self.current_trace.dependencies_accessed:
                self.current_trace.dependencies_accessed.append(dependency_name)

            logger.debug(
                "Dependency access recorded",
                dependency=dependency_name,
                operation=operation_type,
                trace=self.current_trace.operation_name,
            )

    def record_database_query(
        self, query: str, duration: float = 0.0, table: Optional[str] = None, operation: str = "query"
    ):
        """Record database query information."""
        if self.current_trace:
            query_info = {
                "query": query[:500],  # Truncate long queries
                "duration": duration,
                "table": table,
                "operation": operation,
                "timestamp": time.time(),
            }
            self.current_trace.database_queries.append(query_info)
            self.record_dependency_access("database", "query")

    def record_cache_operation(self, operation: str, key: str, duration: float = 0.0, hit: bool = False):
        """Record cache operation information."""
        if self.current_trace:
            cache_info = {
                "operation": operation,
                "key": key[:100],  # Truncate long keys
                "duration": duration,
                "hit": hit,
                "timestamp": time.time(),
            }
            self.current_trace.cache_operations.append(cache_info)
            self.record_dependency_access("cache", operation)

    def record_middleware_call(self, middleware_name: str):
        """Record middleware call."""
        if self.current_trace:
            if middleware_name not in self.current_trace.middleware_calls:
                self.current_trace.middleware_calls.append(middleware_name)
            self.record_dependency_access(f"middleware_{middleware_name}", "call")

    def record_repository_call(self, repository_name: str, method: str):
        """Record repository method call."""
        if self.current_trace:
            call_info = f"{repository_name}.{method}"
            if call_info not in self.current_trace.repository_calls:
                self.current_trace.repository_calls.append(call_info)
            self.record_dependency_access(f"repository_{repository_name}", method)

    def analyze_dependency_patterns(self) -> RuntimeDependencyAnalysis:
        """Analyze runtime dependency patterns from collected traces."""
        logger.info("Analyzing dependency patterns", traces_count=len(self.traces))

        # Analyze patterns for each dependency
        dependency_stats = defaultdict(lambda: {"frequencies": [], "durations": [], "errors": [], "usage_times": []})

        for trace in self.traces:
            for dep in trace.dependencies_accessed:
                dependency_stats[dep]["frequencies"].append(1)
                dependency_stats[dep]["durations"].append(trace.duration)
                dependency_stats[dep]["errors"].extend(trace.errors)
                dependency_stats[dep]["usage_times"].append(datetime.fromtimestamp(trace.start_time).isoformat())

        # Generate dependency patterns
        patterns = []
        for dep_name, stats in dependency_stats.items():
            if stats["frequencies"]:
                pattern = DependencyPattern(
                    dependency_name=dep_name,
                    frequency=sum(stats["frequencies"]),
                    average_duration=sum(stats["durations"]) / len(stats["durations"]),
                    error_rate=len(stats["errors"]) / len(stats["frequencies"]),
                    peak_usage_times=stats["usage_times"][-10:],  # Last 10 usage times
                    bottleneck_indicators=self._identify_bottlenecks(dep_name, stats),
                )
                patterns.append(pattern)

        # Generate performance summary
        performance_summary = self._generate_performance_summary()

        # Generate bottleneck analysis
        bottleneck_analysis = self._analyze_bottlenecks(patterns)

        # Generate failure patterns
        failure_patterns = self._analyze_failure_patterns()

        result = RuntimeDependencyAnalysis(
            metadata={
                "analysis_date": datetime.now().isoformat(),
                "total_traces": len(self.traces),
                "analysis_duration": sum(trace.duration for trace in self.traces),
                "unique_dependencies": len(dependency_stats),
            },
            operation_traces=self.traces,
            dependency_patterns=patterns,
            performance_summary=performance_summary,
            bottleneck_analysis=bottleneck_analysis,
            failure_patterns=failure_patterns,
        )

        logger.info(
            "Dependency pattern analysis completed",
            patterns_count=len(patterns),
            unique_dependencies=len(dependency_stats),
        )

        return result

    def _identify_bottlenecks(self, dependency_name: str, stats: Dict[str, List]) -> List[str]:
        """Identify bottleneck indicators for a dependency."""
        bottlenecks = []

        if stats["durations"]:
            avg_duration = sum(stats["durations"]) / len(stats["durations"])
            max_duration = max(stats["durations"])

            if max_duration > avg_duration * 3:
                bottlenecks.append("high_duration_variance")

            if avg_duration > 1.0:  # > 1 second average
                bottlenecks.append("slow_average_response")

        if len(stats["errors"]) > len(stats["frequencies"]) * 0.1:  # > 10% error rate
            bottlenecks.append("high_error_rate")

        frequency = sum(stats["frequencies"])
        if frequency > len(self.traces) * 0.8:  # Used in > 80% of operations
            bottlenecks.append("high_frequency_usage")

        return bottlenecks

    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance summary from traces."""
        if not self.traces:
            return {}

        durations = [trace.duration for trace in self.traces]
        memory_deltas = [trace.performance_metrics.get("memory_delta", 0) for trace in self.traces]
        cpu_usages = [trace.performance_metrics.get("cpu_usage", 0) for trace in self.traces]

        return {
            "total_operations": len(self.traces),
            "average_duration": sum(durations) / len(durations),
            "max_duration": max(durations),
            "min_duration": min(durations),
            "average_memory_delta": sum(memory_deltas) / len(memory_deltas),
            "average_cpu_usage": sum(cpu_usages) / len(cpu_usages),
            "total_database_queries": sum(len(trace.database_queries) for trace in self.traces),
            "total_cache_operations": sum(len(trace.cache_operations) for trace in self.traces),
            "error_rate": len([t for t in self.traces if t.errors]) / len(self.traces),
        }

    def _analyze_bottlenecks(self, patterns: List[DependencyPattern]) -> Dict[str, Any]:
        """Analyze system bottlenecks from dependency patterns."""
        bottlenecks = {
            "high_frequency_dependencies": [],
            "slow_dependencies": [],
            "error_prone_dependencies": [],
            "recommendations": [],
        }

        for pattern in patterns:
            if "high_frequency_usage" in pattern.bottleneck_indicators:
                bottlenecks["high_frequency_dependencies"].append(
                    {
                        "name": pattern.dependency_name,
                        "frequency": pattern.frequency,
                        "average_duration": pattern.average_duration,
                    }
                )

            if "slow_average_response" in pattern.bottleneck_indicators:
                bottlenecks["slow_dependencies"].append(
                    {
                        "name": pattern.dependency_name,
                        "average_duration": pattern.average_duration,
                        "frequency": pattern.frequency,
                    }
                )

            if "high_error_rate" in pattern.bottleneck_indicators:
                bottlenecks["error_prone_dependencies"].append(
                    {"name": pattern.dependency_name, "error_rate": pattern.error_rate, "frequency": pattern.frequency}
                )

        # Generate recommendations
        bottlenecks["recommendations"] = self._generate_recommendations(bottlenecks)

        return bottlenecks

    def _analyze_failure_patterns(self) -> Dict[str, Any]:
        """Analyze failure patterns from traces."""
        failure_patterns = {
            "common_errors": defaultdict(int),
            "error_sequences": [],
            "failure_cascades": [],
            "recovery_times": [],
        }

        for trace in self.traces:
            for error in trace.errors:
                failure_patterns["common_errors"][error] += 1

        # Analyze error sequences (consecutive errors)
        error_sequences = []
        current_sequence = []

        for trace in self.traces:
            if trace.errors:
                current_sequence.append(
                    {"operation": trace.operation_name, "errors": trace.errors, "timestamp": trace.start_time}
                )
            else:
                if current_sequence:
                    error_sequences.append(current_sequence)
                    current_sequence = []

        if current_sequence:
            error_sequences.append(current_sequence)

        failure_patterns["error_sequences"] = error_sequences

        return failure_patterns

    def _generate_recommendations(self, bottlenecks: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on bottleneck analysis."""
        recommendations = []

        if bottlenecks["slow_dependencies"]:
            recommendations.append("Consider optimizing slow dependencies or implementing caching")

        if bottlenecks["high_frequency_dependencies"]:
            recommendations.append("High-frequency dependencies should be optimized for performance")

        if bottlenecks["error_prone_dependencies"]:
            recommendations.append("Implement better error handling and monitoring for error-prone dependencies")

        return recommendations

    def export_analysis(self, analysis: RuntimeDependencyAnalysis, output_path: str) -> None:
        """Export runtime analysis results to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary for JSON serialization
        result_dict = {
            "metadata": analysis.metadata,
            "operation_traces": [asdict(trace) for trace in analysis.operation_traces],
            "dependency_patterns": [asdict(pattern) for pattern in analysis.dependency_patterns],
            "performance_summary": analysis.performance_summary,
            "bottleneck_analysis": analysis.bottleneck_analysis,
            "failure_patterns": analysis.failure_patterns,
        }

        with open(output_file, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info("Runtime analysis exported", output_path=str(output_file))

    def clear_traces(self) -> None:
        """Clear collected traces."""
        self.traces.clear()
        self.current_trace = None
        self.trace_stack.clear()
        logger.info("Traces cleared")

    async def monitor_live_dependencies(self, duration: int = 60) -> RuntimeDependencyAnalysis:
        """Monitor live dependency usage for a specified duration."""
        logger.info("Starting live dependency monitoring", duration=duration)

        start_time = time.time()

        async with self.async_trace_dependencies("live_monitoring"):
            # Simulate monitoring by waiting
            await asyncio.sleep(duration)

            # In a real implementation, this would hook into the application
            # to capture actual dependency usage

        analysis = self.analyze_dependency_patterns()

        logger.info("Live dependency monitoring completed", duration=time.time() - start_time)

        return analysis


def main():
    """Main entry point for standalone execution."""
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = sys.argv[2] if len(sys.argv) > 2 else "runtime_dependency_analysis.json"
    # duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60  # TODO: Implement duration-based monitoring

    tracer = RuntimeDependencyTracer(project_root)

    # Example usage
    with tracer.trace_dependencies("example_operation"):
        tracer.record_database_query("SELECT * FROM users", 0.05, "users", "SELECT")
        tracer.record_cache_operation("GET", "user:123", 0.01, True)
        tracer.record_repository_call("UserRepository", "get_by_id")
        tracer.record_middleware_call("AuthenticationMiddleware")
        time.sleep(0.1)  # Simulate work

    analysis = tracer.analyze_dependency_patterns()
    tracer.export_analysis(analysis, output_path)

    print(f"Runtime dependency analysis completed. Results saved to {output_path}")


if __name__ == "__main__":
    main()
