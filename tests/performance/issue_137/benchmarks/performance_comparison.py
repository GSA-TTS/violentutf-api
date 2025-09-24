"""Performance comparison benchmarks for Issue #137 optimizations.

This module provides comprehensive benchmarking to validate the 60-70% performance
improvement target across all optimization areas.
"""

import asyncio
import gc
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from scripts.backup_coverage_audit import BackupCoverageAuditor
from scripts.config_baseline_manager import ConfigurationBaselineManager
from tools.dependency.comprehensive_analyzer import ComprehensiveDependencyAnalyzer
from tools.inventory.data_asset_inventory import DataAssetInventoryTool


class PerformanceBenchmark:
    """Performance benchmark runner for Issue #137 optimizations."""

    def __init__(self):
        """Initialize benchmark runner."""
        self.results = {}

    def run_benchmark(self, name: str, baseline_func, optimized_func, iterations: int = 5) -> Dict:
        """Run benchmark comparing baseline vs optimized implementation."""
        print(f"\n=== Running benchmark: {name} ===")

        # Warm up
        try:
            baseline_func()
        except Exception:
            pass
        try:
            optimized_func()
        except (AttributeError, NotImplementedError):
            # Expected for optimized functions not yet implemented
            pass

        # Baseline measurements
        baseline_times = []
        baseline_memory_peaks = []

        for i in range(iterations):
            # Force garbage collection
            gc.collect()

            # Memory tracking
            tracemalloc.start()

            start_time = time.time()
            try:
                baseline_func()
            except Exception as e:
                print(f"Baseline function failed: {e}")
                continue
            execution_time = time.time() - start_time

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            baseline_times.append(execution_time)
            baseline_memory_peaks.append(peak)

        # Optimized measurements
        optimized_times = []
        optimized_memory_peaks = []
        optimized_available = True

        for i in range(iterations):
            # Force garbage collection
            gc.collect()

            # Memory tracking
            tracemalloc.start()

            start_time = time.time()
            try:
                optimized_func()
                execution_time = time.time() - start_time

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                optimized_times.append(execution_time)
                optimized_memory_peaks.append(peak)
            except (AttributeError, NotImplementedError):
                # Optimized function not implemented yet
                optimized_available = False
                tracemalloc.stop()
                break
            except Exception as e:
                print(f"Optimized function failed: {e}")
                tracemalloc.stop()
                break

        # Calculate statistics
        avg_baseline_time = sum(baseline_times) / len(baseline_times) if baseline_times else 0
        avg_baseline_memory = sum(baseline_memory_peaks) / len(baseline_memory_peaks) if baseline_memory_peaks else 0

        result = {
            "name": name,
            "baseline": {
                "avg_time": avg_baseline_time,
                "avg_memory": avg_baseline_memory,
                "times": baseline_times,
                "memory_peaks": baseline_memory_peaks,
            },
            "optimized_available": optimized_available,
        }

        if optimized_available and optimized_times:
            avg_optimized_time = sum(optimized_times) / len(optimized_times)
            avg_optimized_memory = sum(optimized_memory_peaks) / len(optimized_memory_peaks)

            time_improvement = (
                ((avg_baseline_time - avg_optimized_time) / avg_baseline_time) * 100 if avg_baseline_time > 0 else 0
            )
            memory_improvement = (
                ((avg_baseline_memory - avg_optimized_memory) / avg_baseline_memory) * 100
                if avg_baseline_memory > 0
                else 0
            )

            result["optimized"] = {
                "avg_time": avg_optimized_time,
                "avg_memory": avg_optimized_memory,
                "times": optimized_times,
                "memory_peaks": optimized_memory_peaks,
                "time_improvement_percent": time_improvement,
                "memory_improvement_percent": memory_improvement,
            }

            print(f"Time improvement: {time_improvement:.1f}%")
            print(f"Memory improvement: {memory_improvement:.1f}%")
        else:
            print("Optimized implementation not available yet")

        self.results[name] = result
        return result

    def generate_report(self) -> str:
        """Generate comprehensive benchmark report."""
        report = ["# Performance Optimization Benchmark Report - Issue #137", ""]
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        total_benchmarks = len(self.results)
        implemented_optimizations = sum(1 for r in self.results.values() if r.get("optimized_available", False))

        report.append("## Summary")
        report.append(f"- Total benchmarks: {total_benchmarks}")
        report.append(f"- Implemented optimizations: {implemented_optimizations}")
        report.append(f"- Implementation progress: {(implemented_optimizations/total_benchmarks)*100:.1f}%")
        report.append("")

        # Individual benchmark results
        report.append("## Benchmark Results")
        report.append("")

        for name, result in self.results.items():
            report.append(f"### {name}")
            report.append("")

            baseline = result["baseline"]
            report.append(f"**Baseline Performance:**")
            report.append(f"- Average execution time: {baseline['avg_time']:.4f}s")
            report.append(f"- Average memory usage: {baseline['avg_memory']/1024/1024:.2f} MB")
            report.append("")

            if result.get("optimized_available") and "optimized" in result:
                optimized = result["optimized"]
                report.append(f"**Optimized Performance:**")
                report.append(f"- Average execution time: {optimized['avg_time']:.4f}s")
                report.append(f"- Average memory usage: {optimized['avg_memory']/1024/1024:.2f} MB")
                report.append(f"- **Time improvement: {optimized['time_improvement_percent']:.1f}%**")
                report.append(f"- **Memory improvement: {optimized['memory_improvement_percent']:.1f}%**")

                # Check if meets targets
                time_target_met = optimized["time_improvement_percent"] >= 60.0
                memory_target_met = optimized["memory_improvement_percent"] >= 30.0

                report.append("")
                report.append("**Target Achievement:**")
                report.append(f"- Time reduction target (60-70%): {'✓ ACHIEVED' if time_target_met else '✗ NOT MET'}")
                report.append(f"- Memory reduction target (30%+): {'✓ ACHIEVED' if memory_target_met else '✗ NOT MET'}")
            else:
                report.append("**Optimized Performance:** Not implemented yet")

            report.append("")

        # Overall assessment
        if implemented_optimizations > 0:
            avg_time_improvement = (
                sum(
                    r.get("optimized", {}).get("time_improvement_percent", 0)
                    for r in self.results.values()
                    if r.get("optimized_available")
                )
                / implemented_optimizations
            )

            avg_memory_improvement = (
                sum(
                    r.get("optimized", {}).get("memory_improvement_percent", 0)
                    for r in self.results.values()
                    if r.get("optimized_available")
                )
                / implemented_optimizations
            )

            report.append("## Overall Assessment")
            report.append(f"- Average time improvement across implemented optimizations: {avg_time_improvement:.1f}%")
            report.append(
                f"- Average memory improvement across implemented optimizations: {avg_memory_improvement:.1f}%"
            )

            overall_target_met = avg_time_improvement >= 60.0
            report.append(
                f"- **Overall 60-70% improvement target: {'✓ ACHIEVED' if overall_target_met else '✗ NOT MET'}**"
            )

        return "\n".join(report)


class TestDataAssetInventoryBenchmarks:
    """Benchmark tests for DataAssetInventoryTool optimizations."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_parallel_execution_benchmark(self):
        """Benchmark parallel execution optimization for data asset inventory."""
        benchmark = PerformanceBenchmark()

        tool = DataAssetInventoryTool(project_root="/tmp/test_project")  # nosec B108 test path

        # Baseline: sequential execution
        async def baseline_sequential():
            return await tool.perform_full_inventory()

        # Optimized: parallel execution (not implemented yet)
        async def optimized_parallel():
            return await tool.perform_full_inventory_parallel()

        # Run benchmark
        result = benchmark.run_benchmark(
            "Data Asset Inventory - Parallel Execution",
            lambda: asyncio.run(baseline_sequential()),
            lambda: asyncio.run(optimized_parallel()),
            iterations=3,
        )

        # Validate target if optimization is implemented
        if result.get("optimized_available"):
            time_improvement = result["optimized"]["time_improvement_percent"]
            assert time_improvement >= 60.0, f"Time improvement {time_improvement:.1f}% below 60% target"


class TestBackupAuditBenchmarks:
    """Benchmark tests for BackupCoverageAuditor optimizations."""

    @pytest.mark.performance
    def test_directory_traversal_benchmark(self):
        """Benchmark directory traversal optimization."""
        benchmark = PerformanceBenchmark()

        auditor = BackupCoverageAuditor()

        # Baseline: current implementation
        def baseline_traversal():
            return auditor.calculate_backup_storage_usage()

        # Optimized: streaming traversal (not implemented yet)
        def optimized_traversal():
            return auditor.calculate_backup_storage_usage_streaming()

        # Run benchmark
        result = benchmark.run_benchmark(
            "Backup Audit - Directory Traversal", baseline_traversal, optimized_traversal, iterations=5
        )

        # Validate memory improvement target if optimization is implemented
        if result.get("optimized_available"):
            memory_improvement = result["optimized"]["memory_improvement_percent"]
            assert memory_improvement >= 30.0, f"Memory improvement {memory_improvement:.1f}% below 30% target"

    @pytest.mark.performance
    def test_sorting_algorithm_benchmark(self):
        """Benchmark sorting algorithm optimization."""
        from scripts.backup_coverage_audit import BackupGap, CriticalityLevel

        benchmark = PerformanceBenchmark()
        auditor = BackupCoverageAuditor()

        # Create large test dataset
        large_gaps = [
            BackupGap(
                f"repo_{i}",
                CriticalityLevel.CRITICAL if i % 3 == 0 else CriticalityLevel.STANDARD,
                float(i % 168),
                None,
            )
            for i in range(2000)
        ]

        # Baseline: full sorting
        def baseline_sorting():
            return auditor.prioritize_backup_gaps(large_gaps)

        # Optimized: heap-based top-N (not implemented yet)
        def optimized_heap():
            return auditor.get_top_priority_gaps_heap(large_gaps, 100)

        # Run benchmark
        result = benchmark.run_benchmark(
            "Backup Audit - Sorting Algorithm", baseline_sorting, optimized_heap, iterations=3
        )

        # Validate improvement if optimization is implemented
        if result.get("optimized_available"):
            time_improvement = result["optimized"]["time_improvement_percent"]
            assert time_improvement >= 40.0, f"Algorithm improvement {time_improvement:.1f}% below 40% target"


class TestConfigurationBaselineBenchmarks:
    """Benchmark tests for ConfigurationBaselineManager optimizations."""

    @pytest.mark.performance
    def test_baseline_loading_benchmark(self):
        """Benchmark baseline loading optimization."""
        import json
        import tempfile

        benchmark = PerformanceBenchmark()

        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationBaselineManager(baseline_dir=temp_dir)

            # Create test baseline files
            baseline_dir = Path(temp_dir)
            for i in range(50):
                filename = f"env_{i}_v1.0_20240101_120000.json"
                content = {
                    "environment": f"env_{i}",
                    "configurations": {f"key_{j}": f"value_{j}" for j in range(100)},
                    "timestamp": "2024-01-01T12:00:00Z",
                }
                with open(baseline_dir / filename, "w") as f:
                    json.dump(content, f)

            # Baseline: load all baselines
            def baseline_loading():
                return manager.list_baselines()

            # Optimized: cached loading (not implemented yet)
            def optimized_cached():
                return manager.list_baselines_with_cache()

            # Run benchmark
            result = benchmark.run_benchmark(
                "Configuration Baseline - Loading", baseline_loading, optimized_cached, iterations=5
            )

            # Validate improvement if optimization is implemented
            if result.get("optimized_available"):
                time_improvement = result["optimized"]["time_improvement_percent"]
                memory_improvement = result["optimized"]["memory_improvement_percent"]
                assert time_improvement >= 50.0, f"Time improvement {time_improvement:.1f}% below 50% target"
                assert memory_improvement >= 20.0, f"Memory improvement {memory_improvement:.1f}% below 20% target"


class TestComprehensiveAnalyzerBenchmarks:
    """Benchmark tests for ComprehensiveDependencyAnalyzer optimizations."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_graph_generation_benchmark(self):
        """Benchmark graph generation optimization."""
        benchmark = PerformanceBenchmark()

        analyzer = ComprehensiveDependencyAnalyzer("/tmp/test_project")  # nosec B108 test path

        # Mock data for testing
        from unittest.mock import MagicMock

        mock_static_result = MagicMock()
        mock_static_result.service_dependencies = []
        mock_repo_result = MagicMock()
        mock_repo_result.repositories = []
        mock_repo_result.model_relationships = []

        # Baseline: sequential graph generation
        async def baseline_sequential():
            return await analyzer._generate_all_graphs(mock_static_result, mock_repo_result)

        # Optimized: parallel graph generation (not implemented yet)
        async def optimized_parallel():
            return await analyzer._generate_all_graphs_parallel(mock_static_result, mock_repo_result)

        # Run benchmark
        result = benchmark.run_benchmark(
            "Comprehensive Analyzer - Graph Generation",
            lambda: asyncio.run(baseline_sequential()),
            lambda: asyncio.run(optimized_parallel()),
            iterations=3,
        )

        # Validate improvement if optimization is implemented
        if result.get("optimized_available"):
            time_improvement = result["optimized"]["time_improvement_percent"]
            assert time_improvement >= 30.0, f"Graph generation improvement {time_improvement:.1f}% below 30% target"


@pytest.mark.performance
class TestOverallPerformanceBenchmark:
    """Overall performance benchmark for all optimizations."""

    def test_comprehensive_performance_benchmark(self):
        """Run comprehensive performance benchmark across all optimizations."""
        print("\n" + "=" * 80)
        print("COMPREHENSIVE PERFORMANCE BENCHMARK - ISSUE #137")
        print("=" * 80)

        benchmark = PerformanceBenchmark()

        # Run all individual benchmarks
        asyncio.run(self._run_data_inventory_benchmark(benchmark))
        self._run_backup_audit_benchmark(benchmark)
        self._run_config_baseline_benchmark(benchmark)
        asyncio.run(self._run_analyzer_benchmark(benchmark))

        # Generate and print report
        report = benchmark.generate_report()
        print("\n" + report)

        # Save report to file
        report_path = Path("docs/development/issue_137/performance_benchmark_report.md")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report)

        print(f"\nFull report saved to: {report_path}")

        # Overall validation
        implemented_count = sum(1 for r in benchmark.results.values() if r.get("optimized_available"))
        total_count = len(benchmark.results)

        if implemented_count > 0:
            avg_improvement = (
                sum(
                    r.get("optimized", {}).get("time_improvement_percent", 0)
                    for r in benchmark.results.values()
                    if r.get("optimized_available")
                )
                / implemented_count
            )

            print(f"\nOVERALL RESULTS:")
            print(f"- Implemented optimizations: {implemented_count}/{total_count}")
            print(f"- Average time improvement: {avg_improvement:.1f}%")
            print(f"- Target achievement: {'✓ SUCCESS' if avg_improvement >= 60.0 else '✗ IN PROGRESS'}")
        else:
            print(f"\nOVERALL RESULTS:")
            print(f"- No optimizations implemented yet")
            print(f"- Ready for TDD implementation phase")

    async def _run_data_inventory_benchmark(self, benchmark):
        """Run data inventory benchmark."""
        tool = DataAssetInventoryTool(project_root="/tmp/test")  # nosec B108 test path

        async def baseline():
            return await tool.perform_full_inventory()

        async def optimized():
            return await tool.perform_full_inventory_parallel()

        benchmark.run_benchmark(
            "Data Asset Inventory Optimization",
            lambda: asyncio.run(baseline()),
            lambda: asyncio.run(optimized()),
            iterations=2,
        )

    def _run_backup_audit_benchmark(self, benchmark):
        """Run backup audit benchmark."""
        auditor = BackupCoverageAuditor()

        def baseline():
            return auditor.calculate_backup_storage_usage()

        def optimized():
            return auditor.calculate_backup_storage_usage_streaming()

        benchmark.run_benchmark("Backup Audit Optimization", baseline, optimized, iterations=3)

    def _run_config_baseline_benchmark(self, benchmark):
        """Run configuration baseline benchmark."""
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationBaselineManager(baseline_dir=temp_dir)

            # Create test files
            for i in range(20):
                content = {"test": f"data_{i}"}
                with open(Path(temp_dir) / f"baseline_{i}.json", "w") as f:
                    json.dump(content, f)

            def baseline():
                return manager.list_baselines()

            def optimized():
                return manager.list_baselines_with_cache()

            benchmark.run_benchmark("Configuration Baseline Optimization", baseline, optimized, iterations=3)

    async def _run_analyzer_benchmark(self, benchmark):
        """Run analyzer benchmark."""
        analyzer = ComprehensiveDependencyAnalyzer("/tmp/test")  # nosec B108 test path

        from unittest.mock import MagicMock

        mock_static = MagicMock()
        mock_static.service_dependencies = []
        mock_repo = MagicMock()
        mock_repo.repositories = []
        mock_repo.model_relationships = []

        async def baseline():
            return await analyzer._generate_all_graphs(mock_static, mock_repo)

        async def optimized():
            return await analyzer._generate_all_graphs_parallel(mock_static, mock_repo)

        benchmark.run_benchmark(
            "Dependency Analyzer Optimization",
            lambda: asyncio.run(baseline()),
            lambda: asyncio.run(optimized()),
            iterations=2,
        )
