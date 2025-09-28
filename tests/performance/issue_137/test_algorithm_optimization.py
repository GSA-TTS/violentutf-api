"""Performance tests for algorithm optimization (Issue #137).

Tests for algorithm complexity improvements, focusing on replacing O(n²) operations
with more efficient algorithms following TDD methodology.
"""

import heapq
import time
from unittest.mock import MagicMock

import pytest

from scripts.backup_coverage_audit import BackupCoverageAuditor, BackupGap, CriticalityLevel


class TestSortingAlgorithmOptimization:
    """Test optimization of sorting algorithms in backup coverage audit."""

    @pytest.fixture
    def auditor(self):
        """Create BackupCoverageAuditor instance for testing."""
        return BackupCoverageAuditor()

    @pytest.fixture
    def large_gap_dataset(self):
        """Create large dataset of backup gaps for testing."""
        gaps = []
        for i in range(1000):
            gap = BackupGap(
                repository=f"repo_{i}",
                criticality=(
                    CriticalityLevel.CRITICAL
                    if i % 3 == 0
                    else CriticalityLevel.IMPORTANT if i % 2 == 0 else CriticalityLevel.STANDARD
                ),
                gap_hours=float(i % 168),  # 0-167 hours
                last_backup=None,
            )
            gaps.append(gap)
        return gaps

    def test_baseline_sorting_performance(self, auditor, large_gap_dataset):
        """Test baseline performance of current sorting implementation."""
        start_time = time.time()
        sorted_gaps = auditor.prioritize_backup_gaps(large_gap_dataset)
        execution_time = time.time() - start_time

        # Verify correctness
        assert len(sorted_gaps) == 1000
        assert isinstance(sorted_gaps[0], BackupGap)

        # Record baseline performance
        assert execution_time > 0  # Should take some measurable time
        return execution_time

    def test_heap_based_top_n_optimization(self, auditor, large_gap_dataset):
        """Test heap-based top-N selection optimization - THIS SHOULD FAIL INITIALLY."""
        # Test optimized top-N selection using heap
        n = 50  # Top 50 most critical gaps

        start_time = time.time()
        # This method should be implemented as part of optimization
        with pytest.raises(AttributeError):
            top_gaps = auditor.get_top_priority_gaps_heap(large_gap_dataset, n)
        execution_time = time.time() - start_time

        # When implemented, should be much faster than full sort
        # and return correct top N results

    def test_priority_queue_implementation(self, auditor):
        """Test priority queue implementation for gap processing."""
        gaps = [
            BackupGap("repo_1", CriticalityLevel.CRITICAL, 24.0, None),
            BackupGap("repo_2", CriticalityLevel.STANDARD, 12.0, None),
            BackupGap("repo_3", CriticalityLevel.IMPORTANT, 48.0, None),
        ]

        # Test priority queue implementation (should fail initially)
        with pytest.raises(AttributeError):
            pq = auditor.create_priority_queue(gaps)
            highest_priority = auditor.pop_highest_priority(pq)
            assert highest_priority.criticality == CriticalityLevel.CRITICAL

    def test_sorting_complexity_improvement(self, auditor, large_gap_dataset):
        """Test that sorting complexity is improved from O(n²) to O(n log n)."""
        # Create datasets of different sizes to test scaling
        small_dataset = large_gap_dataset[:100]
        medium_dataset = large_gap_dataset[:500]
        large_dataset = large_gap_dataset[:1000]

        # Measure baseline performance
        times = []
        for dataset in [small_dataset, medium_dataset, large_dataset]:
            start_time = time.time()
            auditor.prioritize_backup_gaps(dataset)
            times.append(time.time() - start_time)

        # Test optimized version (should fail initially)
        with pytest.raises(AttributeError):
            optimized_times = []
            for dataset in [small_dataset, medium_dataset, large_dataset]:
                start_time = time.time()
                auditor.prioritize_backup_gaps_optimized(dataset)
                optimized_times.append(time.time() - start_time)

            # Optimized should scale better (closer to O(n log n))
            # Check that larger datasets don't cause quadratic slowdown
            ratio_baseline = times[2] / times[0] if times[0] > 0 else float("inf")
            ratio_optimized = optimized_times[2] / optimized_times[0] if optimized_times[0] > 0 else float("inf")

            assert ratio_optimized < ratio_baseline, "Optimized version should scale better"

    def test_early_termination_optimization(self, auditor, large_gap_dataset):
        """Test early termination for processing when top N is sufficient."""
        # Test early termination implementation (should fail initially)
        with pytest.raises(AttributeError):
            # Should stop processing after finding enough high-priority items
            top_gaps = auditor.get_top_gaps_with_early_termination(large_gap_dataset, limit=10)
            assert len(top_gaps) == 10


class TestDataStructureOptimization:
    """Test optimization of data structures and access patterns."""

    @pytest.fixture
    def auditor(self):
        """Create BackupCoverageAuditor instance for testing."""
        return BackupCoverageAuditor()

    def test_redundant_iteration_elimination(self, auditor):
        """Test elimination of redundant iterations over data structures."""
        # Mock repository data
        mock_repos = [MagicMock(name=f"repo_{i}", is_backup_overdue=lambda: i % 2 == 0) for i in range(100)]

        # Test current implementation - multiple passes
        start_time = time.time()

        # Simulate current multiple-pass approach
        overdue_repos = [repo for repo in mock_repos if repo.is_backup_overdue()]
        compliant_repos = [repo for repo in mock_repos if not repo.is_backup_overdue()]
        total_count = len(mock_repos)

        baseline_time = time.time() - start_time

        # Test optimized single-pass implementation (should fail initially)
        with pytest.raises(AttributeError):
            start_time = time.time()
            result = auditor.analyze_repositories_single_pass(mock_repos)
            optimized_time = time.time() - start_time

            # Should be faster and return same results
            assert optimized_time < baseline_time
            assert len(result["overdue"]) == len(overdue_repos)
            assert len(result["compliant"]) == len(compliant_repos)

    def test_caching_computed_values(self, auditor):
        """Test caching of expensive computed values."""
        # Test result caching implementation (should fail initially)
        with pytest.raises(AttributeError):
            # Expensive computation should be cached
            result1 = auditor.get_cached_complexity_score("repo_1")
            result2 = auditor.get_cached_complexity_score("repo_1")  # Should be cached

            assert result1 == result2

    def test_memoization_implementation(self, auditor):
        """Test memoization for expensive operations."""
        # Test memoization decorator/implementation (should fail initially)
        with pytest.raises(AttributeError):
            # Function should be memoized
            auditor.enable_memoization()

            # First call - computes result
            result1 = auditor.expensive_calculation("input_1")

            # Second call - returns cached result
            result2 = auditor.expensive_calculation("input_1")

            assert result1 == result2


class TestHeapBasedAlgorithms:
    """Test implementation of heap-based algorithms for top-N operations."""

    def test_heapq_nlargest_implementation(self):
        """Test heapq.nlargest for top-N gap selection."""
        # Create test data
        gaps = [
            BackupGap("repo_1", CriticalityLevel.STANDARD, 12.0, None),
            BackupGap("repo_2", CriticalityLevel.CRITICAL, 24.0, None),
            BackupGap("repo_3", CriticalityLevel.IMPORTANT, 48.0, None),
            BackupGap("repo_4", CriticalityLevel.CRITICAL, 6.0, None),
            BackupGap("repo_5", CriticalityLevel.STANDARD, 72.0, None),
        ]

        def gap_priority_score(gap):
            """Calculate priority score for gap."""
            criticality_weights = {
                CriticalityLevel.CRITICAL: 100,
                CriticalityLevel.IMPORTANT: 50,
                CriticalityLevel.STANDARD: 10,
            }
            return criticality_weights.get(gap.criticality, 0) + gap.gap_hours

        # Test heapq.nlargest for top-3 selection
        top_3 = heapq.nlargest(3, gaps, key=gap_priority_score)

        # Verify results
        assert len(top_3) == 3
        assert top_3[0].criticality == CriticalityLevel.CRITICAL  # Highest priority
        assert all(gap_priority_score(top_3[i]) >= gap_priority_score(top_3[i + 1]) for i in range(len(top_3) - 1))

    def test_heap_vs_sort_performance(self):
        """Compare heap-based top-N vs full sort performance."""
        # Create large dataset
        import random

        gaps = [
            BackupGap(f"repo_{i}", random.choice(list(CriticalityLevel)), float(random.randint(1, 168)), None)
            for i in range(5000)
        ]

        def gap_priority_score(gap):
            criticality_weights = {
                CriticalityLevel.CRITICAL: 1000,
                CriticalityLevel.IMPORTANT: 100,
                CriticalityLevel.STANDARD: 10,
            }
            return criticality_weights.get(gap.criticality, 0) + gap.gap_hours

        n = 50  # Top 50

        # Full sort approach
        start_time = time.time()
        sorted_gaps = sorted(gaps, key=gap_priority_score, reverse=True)[:n]
        sort_time = time.time() - start_time

        # Heap approach
        start_time = time.time()
        heap_gaps = heapq.nlargest(n, gaps, key=gap_priority_score)
        heap_time = time.time() - start_time

        # Heap should be faster for top-N selection
        assert heap_time < sort_time, f"Heap time {heap_time:.4f}s should be less than sort time {sort_time:.4f}s"

        # Results should be equivalent
        assert len(sorted_gaps) == len(heap_gaps) == n
        # Top elements should match
        assert gap_priority_score(sorted_gaps[0]) == gap_priority_score(heap_gaps[0])

    def test_priority_queue_operations(self):
        """Test priority queue operations for gap processing."""
        gaps = [
            BackupGap("repo_critical", CriticalityLevel.CRITICAL, 24.0, None),
            BackupGap("repo_standard", CriticalityLevel.STANDARD, 12.0, None),
            BackupGap("repo_important", CriticalityLevel.IMPORTANT, 48.0, None),
        ]

        # Create priority queue (min-heap, so negate priorities for max behavior)
        def gap_priority(gap):
            weights = {
                CriticalityLevel.CRITICAL: -100,  # Negative for max-heap behavior
                CriticalityLevel.IMPORTANT: -50,
                CriticalityLevel.STANDARD: -10,
            }
            return weights.get(gap.criticality, 0) - gap.gap_hours

        pq = [(gap_priority(gap), gap) for gap in gaps]
        heapq.heapify(pq)

        # Pop items in priority order
        priorities = []
        while pq:
            priority, gap = heapq.heappop(pq)
            priorities.append(-priority)  # Convert back to positive

        # Should be in descending priority order
        assert priorities == sorted(priorities, reverse=True)


class TestAlgorithmComplexityBenchmarks:
    """Benchmark tests for algorithm complexity improvements."""

    @pytest.mark.performance
    def test_sorting_complexity_scaling(self):
        """Test that optimized algorithms scale better with data size."""
        auditor = BackupCoverageAuditor()

        # Test with different dataset sizes
        sizes = [100, 500, 1000, 2000]
        baseline_times = []

        for size in sizes:
            # Create dataset
            gaps = [
                BackupGap(
                    f"repo_{i}",
                    CriticalityLevel.CRITICAL if i % 3 == 0 else CriticalityLevel.STANDARD,
                    float(i % 100),
                    None,
                )
                for i in range(size)
            ]

            # Measure baseline performance
            start_time = time.time()
            result = auditor.prioritize_backup_gaps(gaps)
            baseline_times.append(time.time() - start_time)

            assert len(result) == size

        # Test scaling - should be roughly O(n log n)
        # For O(n log n), doubling size should increase time by ~2.1x
        if len(baseline_times) >= 2:
            scaling_factor = baseline_times[-1] / baseline_times[0] if baseline_times[0] > 0 else float("inf")
            size_factor = sizes[-1] / sizes[0]

            # Should scale better than O(n²)
            expected_quadratic_factor = size_factor**2
            assert (
                scaling_factor < expected_quadratic_factor
            ), f"Scaling factor {scaling_factor:.2f} suggests O(n²) behavior"

    @pytest.mark.performance
    def test_top_n_selection_performance(self):
        """Benchmark top-N selection performance."""
        # Create large dataset
        large_gaps = [
            BackupGap(
                f"repo_{i}",
                CriticalityLevel.CRITICAL if i % 4 == 0 else CriticalityLevel.STANDARD,
                float(i % 200),
                None,
            )
            for i in range(10000)
        ]

        n = 100  # Top 100

        # Full sort approach (baseline)
        start_time = time.time()

        def gap_priority_score(gap):
            weights = {CriticalityLevel.CRITICAL: 1000, CriticalityLevel.STANDARD: 10}
            return weights.get(gap.criticality, 0) + gap.gap_hours

        sorted_result = sorted(large_gaps, key=gap_priority_score, reverse=True)[:n]
        sort_time = time.time() - start_time

        # Heap approach (optimized)
        start_time = time.time()
        heap_result = heapq.nlargest(n, large_gaps, key=gap_priority_score)
        heap_time = time.time() - start_time

        # Heap should be significantly faster
        improvement = ((sort_time - heap_time) / sort_time) * 100
        assert improvement > 50.0, f"Performance improvement {improvement:.1f}% below 50% target"

        # Results should be equivalent
        assert len(sorted_result) == len(heap_result) == n
        assert gap_priority_score(sorted_result[0]) == gap_priority_score(heap_result[0])

    @pytest.mark.performance
    def test_algorithm_memory_efficiency(self):
        """Test memory efficiency of optimized algorithms."""
        import tracemalloc

        # Create test dataset
        gaps = [BackupGap(f"repo_{i}", CriticalityLevel.STANDARD, float(i), None) for i in range(5000)]

        def gap_score(gap):
            return gap.gap_hours

        n = 100

        # Full sort memory usage
        tracemalloc.start()
        sorted_result = sorted(gaps, key=gap_score, reverse=True)[:n]
        sort_current, sort_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Heap memory usage
        tracemalloc.start()
        heap_result = heapq.nlargest(n, gaps, key=gap_score)
        heap_current, heap_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Heap should use less peak memory
        memory_improvement = ((sort_peak - heap_peak) / sort_peak) * 100
        assert memory_improvement > 0, f"Heap should use less memory, got {memory_improvement:.1f}% improvement"

        # Results should be equivalent
        assert len(sorted_result) == len(heap_result) == n


class TestRedundancyElimination:
    """Test elimination of redundant operations and iterations."""

    @pytest.fixture
    def auditor(self):
        """Create BackupCoverageAuditor instance for testing."""
        return BackupCoverageAuditor()

    def test_single_pass_analysis(self, auditor):
        """Test single-pass analysis instead of multiple iterations."""
        # Create mock repositories
        repos = [MagicMock(name=f"repo_{i}") for i in range(100)]

        # Configure mock behavior
        for i, repo in enumerate(repos):
            repo.is_backup_overdue.return_value = i % 2 == 0
            repo.criticality = CriticalityLevel.CRITICAL if i % 4 == 0 else CriticalityLevel.STANDARD
            repo.data_size_mb = float(i * 10)

        # Current approach (multiple iterations)
        start_time = time.time()
        overdue_count = sum(1 for repo in repos if repo.is_backup_overdue())
        critical_count = sum(1 for repo in repos if repo.criticality == CriticalityLevel.CRITICAL)
        large_repos = sum(1 for repo in repos if repo.data_size_mb > 500)
        baseline_time = time.time() - start_time

        # Optimized single-pass approach (should fail initially)
        with pytest.raises(AttributeError):
            start_time = time.time()
            stats = auditor.analyze_repositories_single_pass(repos)
            optimized_time = time.time() - start_time

            # Should be faster and produce same results
            assert optimized_time < baseline_time
            assert stats["overdue_count"] == overdue_count
            assert stats["critical_count"] == critical_count
            assert stats["large_repos_count"] == large_repos

    def test_combined_operations(self, auditor):
        """Test combining multiple operations into single pass."""
        gaps = [
            BackupGap(
                f"repo_{i}",
                CriticalityLevel.CRITICAL if i % 3 == 0 else CriticalityLevel.STANDARD,
                float(i % 100),
                None,
            )
            for i in range(1000)
        ]

        # Current approach (multiple operations)
        start_time = time.time()
        critical_gaps = [gap for gap in gaps if gap.criticality == CriticalityLevel.CRITICAL]
        large_gaps = [gap for gap in gaps if gap.gap_hours > 48]
        urgent_gaps = [gap for gap in gaps if gap.gap_hours > 72]
        baseline_time = time.time() - start_time

        # Combined approach (should fail initially)
        with pytest.raises(AttributeError):
            start_time = time.time()
            categorized_gaps = auditor.categorize_gaps_single_pass(gaps)
            optimized_time = time.time() - start_time

            # Should be faster
            assert optimized_time < baseline_time
            assert len(categorized_gaps["critical"]) == len(critical_gaps)
            assert len(categorized_gaps["large"]) == len(large_gaps)
            assert len(categorized_gaps["urgent"]) == len(urgent_gaps)
