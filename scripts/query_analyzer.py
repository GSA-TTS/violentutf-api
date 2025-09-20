#!/usr/bin/env python3
"""
Query Performance Analyzer Script for Issue #123 - Phase 5 Database Monitoring.

This script provides automated query analysis using existing repository patterns
for slow query detection, optimization recommendations, and performance baseline tracking.

Features:
- Slow query detection and reporting
- N+1 query pattern analysis
- Query performance baseline establishment
- Optimization recommendations
- Performance regression detection
"""

import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import argparse
import statistics

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.db.session import get_db
from app.utils.monitoring import track_database_query
from app.utils.performance_tracker import get_global_performance_tracker

logger = get_logger(__name__)


@dataclass
class QueryAnalysisResult:
    """Results from query performance analysis."""

    query_pattern: str
    total_executions: int
    average_duration: float
    median_duration: float
    p95_duration: float
    max_duration: float
    min_duration: float
    slow_query_count: int
    optimization_suggestions: List[str]
    n_plus_one_detected: bool
    execution_plan_summary: Optional[str] = None
    index_usage: Optional[Dict[str, Any]] = None


@dataclass
class PerformanceBaseline:
    """Performance baseline for a query pattern."""

    query_pattern: str
    baseline_duration: float
    baseline_p95: float
    sample_size: int
    established_date: datetime
    confidence_level: float


class QueryAnalyzer:
    """
    Advanced query performance analyzer for database optimization.

    Provides comprehensive analysis of query patterns, performance metrics,
    and optimization recommendations using existing ViolentUTF monitoring infrastructure.
    """

    def __init__(self, session: AsyncSession):
        """Initialize the query analyzer."""
        self.session = session
        self.performance_tracker = get_global_performance_tracker()
        self.slow_query_threshold = 0.5  # 500ms
        self.n_plus_one_threshold = 10  # queries per operation
        self.baselines: Dict[str, PerformanceBaseline] = {}

    async def analyze_slow_queries(self, time_window_hours: int = 24, limit: int = 100) -> List[QueryAnalysisResult]:
        """
        Analyze slow queries from the performance tracker history.

        Args:
            time_window_hours: Time window to analyze in hours
            limit: Maximum number of results to return

        Returns:
            List of query analysis results
        """
        logger.info("Starting slow query analysis", time_window_hours=time_window_hours)

        # Get performance history from the tracker
        query_patterns = defaultdict(list)

        # Extract query performance data from all operations
        for operation_name in self.performance_tracker._history.keys():
            history = self.performance_tracker.get_operation_history(operation_name)

            for operation in history:
                # Filter by time window
                operation_time = datetime.fromtimestamp(operation.start_time)
                if operation_time > datetime.now() - timedelta(hours=time_window_hours):
                    # Group by repository and operation pattern
                    pattern = f"{operation.metadata.get('repository', 'unknown')}.{operation.operation_name}"
                    query_patterns[pattern].append(operation)

        # Analyze each query pattern
        results = []
        for pattern, operations in query_patterns.items():
            if operations:
                result = await self._analyze_query_pattern(pattern, operations)
                if result:
                    results.append(result)

        # Sort by performance impact (slow query count * average duration)
        results.sort(key=lambda x: x.slow_query_count * x.average_duration, reverse=True)

        logger.info("Slow query analysis completed", patterns_analyzed=len(results))
        return results[:limit]

    async def _analyze_query_pattern(self, pattern: str, operations: List[Any]) -> Optional[QueryAnalysisResult]:
        """
        Analyze a specific query pattern for performance issues.

        Args:
            pattern: Query pattern identifier
            operations: List of operation metrics

        Returns:
            Query analysis result or None if insufficient data
        """
        if len(operations) < 5:  # Need minimum sample size
            return None

        durations = [op.duration for op in operations]

        # Calculate performance statistics
        avg_duration = statistics.mean(durations)
        median_duration = statistics.median(durations)
        max_duration = max(durations)
        min_duration = min(durations)

        # Calculate percentiles
        sorted_durations = sorted(durations)
        p95_duration = sorted_durations[int(0.95 * len(sorted_durations))]

        # Count slow queries
        slow_query_count = sum(1 for d in durations if d > self.slow_query_threshold)

        # Detect N+1 patterns
        n_plus_one_detected = await self._detect_n_plus_one_pattern(pattern, operations)

        # Generate optimization suggestions
        optimization_suggestions = self._generate_optimization_suggestions(
            pattern, avg_duration, slow_query_count, n_plus_one_detected, operations
        )

        # Get execution plan if available
        execution_plan = await self._get_execution_plan_summary(pattern)

        # Analyze index usage
        index_usage = await self._analyze_index_usage(pattern)

        return QueryAnalysisResult(
            query_pattern=pattern,
            total_executions=len(operations),
            average_duration=avg_duration,
            median_duration=median_duration,
            p95_duration=p95_duration,
            max_duration=max_duration,
            min_duration=min_duration,
            slow_query_count=slow_query_count,
            optimization_suggestions=optimization_suggestions,
            n_plus_one_detected=n_plus_one_detected,
            execution_plan_summary=execution_plan,
            index_usage=index_usage,
        )

    async def _detect_n_plus_one_pattern(self, pattern: str, operations: List[Any]) -> bool:
        """
        Detect N+1 query patterns by analyzing operation frequency.

        Args:
            pattern: Query pattern identifier
            operations: List of operation metrics

        Returns:
            True if N+1 pattern detected
        """
        # Group operations by short time windows to detect burst patterns
        time_windows: Dict[int, int] = defaultdict(int)

        for operation in operations:
            # Group by 1-second windows
            time_window = int(operation.start_time)
            time_windows[time_window] += 1

        # Check if any time window has excessive queries
        max_queries_per_second = max(time_windows.values()) if time_windows else 0

        return max_queries_per_second >= self.n_plus_one_threshold

    def _generate_optimization_suggestions(
        self, pattern: str, avg_duration: float, slow_query_count: int, n_plus_one_detected: bool, operations: List[Any]
    ) -> List[str]:
        """
        Generate optimization suggestions based on analysis.

        Args:
            pattern: Query pattern identifier
            avg_duration: Average query duration
            slow_query_count: Number of slow queries
            n_plus_one_detected: Whether N+1 pattern was detected
            operations: List of operation metrics

        Returns:
            List of optimization suggestions
        """
        suggestions = []

        # Slow query suggestions
        if avg_duration > self.slow_query_threshold:
            suggestions.append(
                f"Average duration ({avg_duration:.3f}s) exceeds threshold - consider query optimization"
            )

        if slow_query_count > len(operations) * 0.1:  # More than 10% slow queries
            suggestions.append("High percentage of slow queries - review query structure and indexes")

        # N+1 pattern suggestions
        if n_plus_one_detected:
            suggestions.append("N+1 query pattern detected - implement eager loading or batch queries")
            suggestions.append("Consider using selectinload() for related entities")

        # Pattern-specific suggestions
        if "list_with_pagination" in pattern:
            suggestions.append("For pagination queries, ensure proper indexing on sort columns")
            suggestions.append("Consider implementing cursor-based pagination for large datasets")

        if "get_by_id" in pattern and avg_duration > 0.1:
            suggestions.append("Single entity lookup is slow - check primary key index")

        if "update" in pattern and avg_duration > 0.5:
            suggestions.append("Update operations are slow - check for unnecessary column updates")
            suggestions.append("Consider bulk update operations for multiple records")

        # Memory usage suggestions
        memory_deltas = [op.memory_delta_mb for op in operations if hasattr(op, "memory_delta_mb")]
        if memory_deltas and statistics.mean(memory_deltas) > 100:  # >100MB average
            suggestions.append("High memory usage detected - review query result set size")
            suggestions.append("Consider implementing query result streaming for large datasets")

        return suggestions

    async def _get_execution_plan_summary(self, pattern: str) -> Optional[str]:
        """
        Get execution plan summary for a query pattern.

        Args:
            pattern: Query pattern identifier

        Returns:
            Execution plan summary or None
        """
        try:
            # This would require actual query text, which we don't have in this implementation
            # In a real scenario, you'd store the actual SQL queries and analyze their plans
            return f"Execution plan analysis not available for pattern: {pattern}"
        except Exception as e:
            logger.warning("Failed to get execution plan", pattern=pattern, error=str(e))
            return None

    async def _analyze_index_usage(self, pattern: str) -> Optional[Dict[str, Any]]:
        """
        Analyze index usage for a query pattern.

        Args:
            pattern: Query pattern identifier

        Returns:
            Index usage analysis or None
        """
        try:
            # Extract table/model information from pattern
            parts = pattern.split(".")
            if len(parts) >= 2:
                repository_name = parts[0]
                operation = parts[1]

                return {
                    "repository": repository_name,
                    "operation": operation,
                    "index_recommendations": [
                        "Ensure primary key indexes are properly configured",
                        "Consider composite indexes for multi-column filters",
                        "Review foreign key indexes for join operations",
                    ],
                }
        except Exception as e:
            logger.warning("Failed to analyze index usage", pattern=pattern, error=str(e))

        return None

    async def establish_performance_baselines(
        self, confidence_level: float = 0.95, min_samples: int = 100
    ) -> Dict[str, PerformanceBaseline]:
        """
        Establish performance baselines for all query patterns.

        Args:
            confidence_level: Statistical confidence level for baselines
            min_samples: Minimum number of samples required

        Returns:
            Dictionary of established baselines
        """
        logger.info("Establishing performance baselines", confidence_level=confidence_level)

        baselines = {}

        # Analyze each operation type
        for operation_name in self.performance_tracker._history.keys():
            history = self.performance_tracker.get_operation_history(operation_name)

            if len(history) >= min_samples:
                durations = [op.duration for op in history]

                baseline_duration = statistics.mean(durations)
                baseline_p95 = sorted(durations)[int(0.95 * len(durations))]

                baseline = PerformanceBaseline(
                    query_pattern=operation_name,
                    baseline_duration=baseline_duration,
                    baseline_p95=baseline_p95,
                    sample_size=len(history),
                    established_date=datetime.now(),
                    confidence_level=confidence_level,
                )

                baselines[operation_name] = baseline

                logger.info(
                    "Baseline established",
                    pattern=operation_name,
                    baseline_duration=baseline_duration,
                    sample_size=len(history),
                )

        self.baselines = baselines
        return baselines

    async def detect_performance_regressions(
        self, regression_threshold: float = 0.2  # 20% increase
    ) -> List[Dict[str, Any]]:
        """
        Detect performance regressions against established baselines.

        Args:
            regression_threshold: Threshold for regression detection (percentage)

        Returns:
            List of detected regressions
        """
        logger.info("Detecting performance regressions", threshold=regression_threshold)

        regressions = []

        for pattern, baseline in self.baselines.items():
            # Get recent performance data
            recent_history = self.performance_tracker.get_operation_history(pattern, limit=50)

            if len(recent_history) >= 10:  # Need minimum recent samples
                recent_durations = [op.duration for op in recent_history[-20:]]  # Last 20 operations
                recent_avg = statistics.mean(recent_durations)

                # Calculate regression percentage
                regression_factor = (recent_avg - baseline.baseline_duration) / baseline.baseline_duration

                if regression_factor > regression_threshold:
                    regression = {
                        "pattern": pattern,
                        "baseline_duration": baseline.baseline_duration,
                        "recent_avg_duration": recent_avg,
                        "regression_percentage": regression_factor * 100,
                        "sample_size": len(recent_durations),
                        "baseline_date": baseline.established_date.isoformat(),
                        "severity": "high" if regression_factor > 0.5 else "medium",
                    }

                    regressions.append(regression)

                    logger.warning(
                        "Performance regression detected",
                        pattern=pattern,
                        regression_percentage=regression_factor * 100,
                    )

        return regressions

    async def generate_comprehensive_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive query performance report.

        Args:
            output_file: Optional file to save the report

        Returns:
            Comprehensive performance report
        """
        logger.info("Generating comprehensive query performance report")

        # Perform all analyses
        slow_queries = await self.analyze_slow_queries()
        baselines = await self.establish_performance_baselines()
        regressions = await self.detect_performance_regressions()

        # Get overall performance metrics
        overall_metrics = self.performance_tracker.get_performance_report()

        report = {
            "generated_at": datetime.now().isoformat(),
            "analysis_summary": {
                "total_query_patterns": len(self.performance_tracker._history),
                "slow_query_patterns": len([q for q in slow_queries if q.slow_query_count > 0]),
                "baselines_established": len(baselines),
                "regressions_detected": len(regressions),
            },
            "slow_query_analysis": [asdict(q) for q in slow_queries],
            "performance_baselines": {k: asdict(v) for k, v in baselines.items()},
            "performance_regressions": regressions,
            "overall_metrics": overall_metrics,
            "recommendations": self._generate_global_recommendations(slow_queries, regressions),
        }

        # Save to file if specified
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info("Report saved", output_file=output_file)

        return report

    def _generate_global_recommendations(
        self, slow_queries: List[QueryAnalysisResult], regressions: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Generate global optimization recommendations.

        Args:
            slow_queries: List of slow query analyses
            regressions: List of detected regressions

        Returns:
            List of global recommendations
        """
        recommendations = []

        # High-level recommendations based on analysis
        if len(slow_queries) > 5:
            recommendations.append("Multiple slow query patterns detected - prioritize database optimization")

        if any(q.n_plus_one_detected for q in slow_queries):
            recommendations.append("N+1 query patterns found - implement eager loading strategies")

        if len(regressions) > 0:
            recommendations.append("Performance regressions detected - investigate recent changes")

        # Connection pool recommendations
        recommendations.extend(
            [
                "Monitor database connection pool utilization",
                "Consider implementing query result caching for frequently accessed data",
                "Review and optimize database indexes based on query patterns",
                "Implement query timeout configurations to prevent resource exhaustion",
            ]
        )

        return recommendations


async def main() -> None:
    """Main entry point for the query analyzer script."""
    parser = argparse.ArgumentParser(description="Query Performance Analyzer")
    parser.add_argument("--time-window", type=int, default=24, help="Analysis time window in hours")
    parser.add_argument("--output", type=str, help="Output file for the report")
    parser.add_argument("--baselines-only", action="store_true", help="Only establish baselines")
    parser.add_argument("--regressions-only", action="store_true", help="Only detect regressions")

    args = parser.parse_args()

    logger.info("Starting query analyzer", args=vars(args))

    try:
        # Get database session
        async with get_db() as session:
            analyzer = QueryAnalyzer(session)

            if args.baselines_only:
                baselines = await analyzer.establish_performance_baselines()
                print(f"Established {len(baselines)} performance baselines")

            elif args.regressions_only:
                regressions = await analyzer.detect_performance_regressions()
                print(f"Detected {len(regressions)} performance regressions")
                for regression in regressions:
                    print(f"  - {regression['pattern']}: {regression['regression_percentage']:.1f}% slower")

            else:
                # Generate comprehensive report
                report = await analyzer.generate_comprehensive_report(args.output)

                print("\n=== Query Performance Analysis Report ===")
                print(f"Analysis completed at: {report['generated_at']}")
                print(f"Total query patterns analyzed: {report['analysis_summary']['total_query_patterns']}")
                print(f"Slow query patterns found: {report['analysis_summary']['slow_query_patterns']}")
                print(f"Performance baselines established: {report['analysis_summary']['baselines_established']}")
                print(f"Performance regressions detected: {report['analysis_summary']['regressions_detected']}")

                if report["slow_query_analysis"]:
                    print("\n=== Top Slow Query Patterns ===")
                    for i, query in enumerate(report["slow_query_analysis"][:5], 1):
                        print(f"{i}. {query['query_pattern']}")
                        print(f"   Average duration: {query['average_duration']:.3f}s")
                        print(f"   Slow queries: {query['slow_query_count']}/{query['total_executions']}")
                        print(f"   Suggestions: {len(query['optimization_suggestions'])}")

                if report["performance_regressions"]:
                    print("\n=== Performance Regressions ===")
                    for regression in report["performance_regressions"]:
                        print(f"- {regression['pattern']}: {regression['regression_percentage']:.1f}% slower")

                print("\n=== Global Recommendations ===")
                for i, rec in enumerate(report["recommendations"], 1):
                    print(f"{i}. {rec}")

                if args.output:
                    print(f"\nDetailed report saved to: {args.output}")

    except Exception as e:
        logger.error("Query analyzer failed", error=str(e), exception_type=type(e).__name__)
        raise


if __name__ == "__main__":
    asyncio.run(main())
