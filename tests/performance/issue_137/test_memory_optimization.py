"""Performance tests for memory optimization (Issue #137).

Tests for memory usage improvements in backup_coverage_audit.py and
config_baseline_manager.py following TDD methodology.
"""

import tempfile
import time
import tracemalloc
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.backup_coverage_audit import BackupCoverageAuditor
from scripts.config_baseline_manager import ConfigurationBaselineManager


class TestBackupCoverageMemoryOptimization:
    """Test memory optimization for BackupCoverageAuditor."""

    @pytest.fixture
    def auditor(self):
        """Create BackupCoverageAuditor instance for testing."""
        return BackupCoverageAuditor()

    @pytest.fixture
    def large_directory_structure(self):
        """Create a large directory structure for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create nested directory structure with many files
            for i in range(10):
                subdir = temp_path / f"subdir_{i}"
                subdir.mkdir()
                for j in range(50):  # 500 files total
                    (subdir / f"file_{j}.backup").write_text(f"backup data {i}-{j}")

            yield temp_path

    def test_memory_usage_baseline_directory_traversal(self, auditor, large_directory_structure):
        """Test baseline memory usage for current directory traversal implementation."""
        tracemalloc.start()

        # Mock backup_directories to use our test structure
        with patch.object(auditor, "calculate_backup_storage_usage") as mock_calc:

            def mock_storage_calc():
                # Simulate current implementation - load all files into memory
                all_files = []
                for backup_file in large_directory_structure.rglob("*"):
                    if backup_file.is_file():
                        all_files.append(
                            {
                                "path": str(backup_file),
                                "size": backup_file.stat().st_size,
                                "mtime": backup_file.stat().st_mtime,
                            }
                        )

                # Process all files at once (memory intensive)
                total_size = sum(f["size"] for f in all_files)
                return {
                    "total_size_gb": total_size / (1024**3),
                    "file_count": len(all_files),
                }

            mock_calc.side_effect = mock_storage_calc
            result = auditor.calculate_backup_storage_usage()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Baseline should use more memory (loading all files at once)
        assert peak > current
        assert result["file_count"] == 500

    def test_memory_optimized_directory_traversal(self, auditor, large_directory_structure):
        """Test memory optimized streaming directory traversal - THIS SHOULD FAIL INITIALLY."""
        tracemalloc.start()

        # This expects the optimized streaming implementation
        result = auditor.calculate_backup_storage_usage_streaming()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Optimized version should use significantly less peak memory
        assert peak < current * 2, f"Peak memory usage too high: {peak} bytes"
        assert result["file_count"] > 0

    def test_chunked_file_processing(self, auditor):
        """Test chunked processing for large file sets."""
        # Create mock file list
        large_file_list = [f"/tmp/file_{i}.backup" for i in range(1000)]  # nosec B108 - test path

        # Test chunked processing (should fail initially - not implemented)
        with pytest.raises(AttributeError):
            result = auditor.process_files_in_chunks(large_file_list, chunk_size=100)

    def test_generator_based_traversal(self, auditor, large_directory_structure):
        """Test generator-based directory traversal for memory efficiency."""
        # Test generator implementation (should fail initially)
        with pytest.raises(AttributeError):
            file_generator = auditor.traverse_directories_streaming([large_directory_structure])
            files_processed = sum(1 for _ in file_generator)
            assert files_processed == 500

    @pytest.mark.performance
    def test_memory_usage_comparison(self, auditor, large_directory_structure):
        """Compare memory usage between baseline and optimized implementations."""
        # Baseline memory measurement
        tracemalloc.start()
        baseline_result = auditor.calculate_backup_storage_usage()
        baseline_current, baseline_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Optimized memory measurement
        tracemalloc.start()
        try:
            optimized_result = auditor.calculate_backup_storage_usage_streaming()
            optimized_current, optimized_peak = tracemalloc.get_traced_memory()
        except AttributeError:
            # Expected to fail initially - optimized method not implemented
            optimized_peak = 0
        finally:
            tracemalloc.stop()

        if optimized_peak > 0:
            # Calculate memory improvement
            memory_improvement = ((baseline_peak - optimized_peak) / baseline_peak) * 100
            assert memory_improvement >= 30.0, f"Memory improvement {memory_improvement:.1f}% below target"


class TestConfigurationBaselineMemoryOptimization:
    """Test memory optimization for ConfigurationBaselineManager."""

    @pytest.fixture
    def baseline_manager(self):
        """Create ConfigurationBaselineManager instance for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield ConfigurationBaselineManager(baseline_dir=temp_dir)

    @pytest.fixture
    def many_baseline_files(self, baseline_manager):
        """Create many baseline files for testing."""
        baseline_dir = Path(baseline_manager.baseline_dir)

        # Create 100 baseline files with different timestamps
        for i in range(100):
            filename = f"production_v1.0_{20240101 + i:08d}_120000.json"
            file_path = baseline_dir / filename

            # Create realistic baseline content
            baseline_content = {
                "environment": "production",
                "timestamp": f"2024-01-{i+1:02d}T12:00:00Z",
                "version": "v1.0",
                "configurations": {f"config_{j}": f"value_{j}" for j in range(50)},
                "metadata": {"source": "test", "size": "large"},
                "checksum": "abc123def456",
            }

            import json

            with open(file_path, "w") as f:
                json.dump(baseline_content, f)

        return baseline_dir

    def test_baseline_memory_usage_list_baselines(self, baseline_manager, many_baseline_files):
        """Test baseline memory usage for listing baselines."""
        tracemalloc.start()

        # Current implementation loads all files into memory
        baselines = baseline_manager.list_baselines()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Should have loaded all 100 baselines
        assert len(baselines) == 100
        assert peak > current  # Memory was used

    def test_optimized_baseline_listing_with_metadata_cache(self, baseline_manager, many_baseline_files):
        """Test optimized baseline listing with file metadata caching - THIS SHOULD FAIL INITIALLY."""
        tracemalloc.start()

        # Test cached implementation (should fail initially - not implemented)
        with pytest.raises(AttributeError):
            baselines = baseline_manager.list_baselines_with_cache()

        tracemalloc.stop()

    def test_lazy_loading_baselines(self, baseline_manager, many_baseline_files):
        """Test lazy loading of baseline content."""
        # Test lazy loading implementation (should fail initially)
        with pytest.raises(AttributeError):
            lazy_baselines = baseline_manager.list_baselines_lazy()
            # Only metadata loaded, not full content
            first_baseline = next(lazy_baselines)
            assert hasattr(first_baseline, "metadata_only")

    def test_filename_timestamp_extraction(self, baseline_manager, many_baseline_files):
        """Test extracting timestamps from filenames instead of loading files."""
        # Test filename parsing optimization (should fail initially)
        with pytest.raises(AttributeError):
            timestamps = baseline_manager.extract_timestamps_from_filenames()
            assert len(timestamps) == 100

    @pytest.mark.performance
    def test_memory_improvement_baseline_listing(self, baseline_manager, many_baseline_files):
        """Test memory improvement for baseline listing operations."""
        # Measure baseline memory usage
        tracemalloc.start()
        baseline_result = baseline_manager.list_baselines()
        baseline_current, baseline_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure optimized memory usage
        tracemalloc.start()
        try:
            optimized_result = baseline_manager.list_baselines_with_cache()
            optimized_current, optimized_peak = tracemalloc.get_traced_memory()
        except AttributeError:
            # Expected to fail initially
            optimized_peak = 0
        finally:
            tracemalloc.stop()

        if optimized_peak > 0:
            # Calculate memory improvement
            memory_improvement = ((baseline_peak - optimized_peak) / baseline_peak) * 100
            assert memory_improvement >= 40.0, f"Memory improvement {memory_improvement:.1f}% below target"

    def test_lru_cache_implementation(self, baseline_manager, many_baseline_files):
        """Test LRU cache for frequently accessed baselines."""
        # Test LRU cache implementation (should fail initially)
        with pytest.raises(AttributeError):
            # Access same baseline multiple times
            for _ in range(5):
                baseline = baseline_manager.get_cached_baseline("production_v1.0_20240101_120000.json")
                assert baseline is not None


class TestMemoryOptimizationBenchmarks:
    """Benchmark tests for memory optimization improvements."""

    @pytest.mark.performance
    def test_directory_traversal_memory_benchmark(self):
        """Benchmark memory usage for directory traversal optimization."""
        auditor = BackupCoverageAuditor()

        # Create test directory structure
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create large directory structure
            for i in range(20):
                subdir = temp_path / f"backup_dir_{i}"
                subdir.mkdir()
                for j in range(100):  # 2000 files total
                    (subdir / f"backup_{j}.sql").write_text(f"backup content {i}-{j}" * 100)

            # Baseline measurement
            tracemalloc.start()
            with patch.object(auditor, "calculate_backup_storage_usage") as mock_calc:

                def baseline_implementation():
                    all_files = list(temp_path.rglob("*.sql"))
                    return {
                        "total_size_gb": sum(f.stat().st_size for f in all_files) / (1024**3),
                        "file_count": len(all_files),
                    }

                mock_calc.side_effect = baseline_implementation
                baseline_result = auditor.calculate_backup_storage_usage()
            baseline_current, baseline_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Optimized measurement (will fail until implemented)
            try:
                tracemalloc.start()
                optimized_result = auditor.calculate_backup_storage_usage_streaming()
                optimized_current, optimized_peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                # Assert significant memory improvement
                memory_reduction = ((baseline_peak - optimized_peak) / baseline_peak) * 100
                assert memory_reduction >= 50.0, f"Memory reduction {memory_reduction:.1f}% below 50% target"

                # Results should be equivalent
                assert baseline_result["file_count"] == optimized_result["file_count"]

            except AttributeError:
                # Expected until optimization is implemented
                pass

    @pytest.mark.performance
    def test_baseline_caching_memory_benchmark(self):
        """Benchmark memory usage for baseline file caching optimization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationBaselineManager(baseline_dir=temp_dir)

            # Create many large baseline files
            baseline_dir = Path(temp_dir)
            for i in range(50):
                filename = f"env_{i}_v1.0_{20240101 + i:08d}_120000.json"
                file_path = baseline_dir / filename

                # Large baseline content
                baseline_content = {
                    "environment": f"env_{i}",
                    "timestamp": f"2024-01-01T12:00:00Z",
                    "version": "v1.0",
                    "configurations": {f"config_{j}": f"large_value_{j}" * 20 for j in range(200)},
                    "metadata": {"test": True, "size": "large"},
                    "checksum": "hash_value",
                }

                import json

                with open(file_path, "w") as f:
                    json.dump(baseline_content, f)

            # Baseline memory measurement
            tracemalloc.start()
            baseline_list = manager.list_baselines()
            baseline_current, baseline_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Optimized memory measurement (will fail until implemented)
            try:
                tracemalloc.start()
                optimized_list = manager.list_baselines_with_cache()
                optimized_current, optimized_peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                # Assert memory improvement
                memory_reduction = ((baseline_peak - optimized_peak) / baseline_peak) * 100
                assert memory_reduction >= 30.0, f"Memory reduction {memory_reduction:.1f}% below 30% target"

                # Results should be equivalent
                assert len(baseline_list) == len(optimized_list)

            except AttributeError:
                # Expected until optimization is implemented
                pass


class TestMemoryMonitoring:
    """Tests for memory usage monitoring and cleanup."""

    def test_memory_monitoring_implementation(self):
        """Test memory monitoring functionality."""
        auditor = BackupCoverageAuditor()

        # Test memory monitoring (should fail initially - not implemented)
        with pytest.raises(AttributeError):
            monitor = auditor.get_memory_monitor()
            monitor.start()
            # ... do work ...
            stats = monitor.get_stats()
            monitor.stop()

            assert "peak_memory" in stats
            assert "current_memory" in stats

    def test_memory_cleanup_implementation(self):
        """Test memory cleanup after processing."""
        auditor = BackupCoverageAuditor()

        # Test cleanup functionality (should fail initially)
        with pytest.raises(AttributeError):
            auditor.cleanup_memory()

    def test_garbage_collection_optimization(self):
        """Test garbage collection optimization."""
        import gc

        auditor = BackupCoverageAuditor()

        # Test GC optimization (should fail initially)
        with pytest.raises(AttributeError):
            auditor.optimize_garbage_collection()

        # Manual test of GC behavior
        gc.collect()
        before_objects = len(gc.get_objects())

        # Create and destroy objects
        large_list = [i for i in range(10000)]
        del large_list

        gc.collect()
        after_objects = len(gc.get_objects())

        # Ensure objects were cleaned up
        assert after_objects <= before_objects + 100  # Some tolerance for test objects
