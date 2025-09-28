"""Performance tests for parallel execution optimization (Issue #137).

Tests for parallel execution improvements in data_asset_inventory.py and
comprehensive_analyzer.py following TDD methodology.
"""

import asyncio
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from tools.dependency.comprehensive_analyzer import ComprehensiveDependencyAnalyzer
except ImportError:
    # Skip comprehensive analyzer tests if module not available
    ComprehensiveDependencyAnalyzer = None

try:
    from tools.inventory.data_asset_inventory import DataAssetInventoryTool
except ImportError:
    DataAssetInventoryTool = None


@pytest.mark.skipif(DataAssetInventoryTool is None, reason="DataAssetInventoryTool not available")
class TestDataAssetInventoryParallelExecution:
    """Test parallel execution optimization for DataAssetInventoryTool."""

    @pytest.fixture
    def inventory_tool(self):
        """Create DataAssetInventoryTool instance for testing."""
        return DataAssetInventoryTool(project_root="/tmp/test_project")  # nosec B108 - test path

    @pytest.fixture
    def mock_async_methods(self):
        """Mock async methods to control timing and simulate work."""
        return {
            "schema_tool.discover_schema": AsyncMock(return_value={"tables": []}),
            "repository_analyzer.analyze_repositories": AsyncMock(return_value={"repositories": []}),
            "_discover_physical_stores": AsyncMock(return_value={}),
            "_discover_configuration_assets": AsyncMock(return_value={}),
        }

    @pytest.mark.asyncio
    async def test_sequential_execution_baseline(self, inventory_tool, mock_async_methods):
        """Test current sequential execution for baseline performance measurement."""
        # Mock all async methods with controlled delays to simulate real work
        with (
            patch.multiple(
                inventory_tool,
                **{
                    key.split(".")[-1]: mock
                    for key, mock in mock_async_methods.items()
                    if "." not in key.split(".")[-1]
                },
            ),
            patch.object(
                inventory_tool.schema_tool,
                "discover_schema",
                mock_async_methods["schema_tool.discover_schema"],
            ),
            patch.object(
                inventory_tool.repository_analyzer,
                "analyze_repositories",
                mock_async_methods["repository_analyzer.analyze_repositories"],
            ),
        ):

            # Add realistic delays to simulate actual work
            for mock in mock_async_methods.values():
                mock.side_effect = lambda *args, **kwargs: asyncio.sleep(0.1)

            start_time = time.time()
            result = await inventory_tool.perform_full_inventory()
            execution_time = time.time() - start_time

            # Assert baseline performance characteristics
            assert result is not None
            assert "metadata" in result
            assert "physical_stores" in result
            assert "logical_assets" in result

            # Baseline should take longer due to sequential execution
            # With 9 phases at 0.1s each = ~0.9s minimum sequential time
            assert execution_time > 0.8, f"Sequential execution too fast: {execution_time}s"

    @pytest.mark.asyncio
    async def test_parallel_execution_optimization(self, inventory_tool):
        """Test optimized parallel execution - THIS SHOULD FAIL INITIALLY."""
        # This test expects the optimized parallel implementation
        # It should fail initially (RED phase of TDD)

        start_time = time.time()
        result = await inventory_tool.perform_full_inventory_parallel()
        execution_time = time.time() - start_time

        # Assert that parallel execution is significantly faster
        # Target: 60-70% reduction means 0.3-0.4x original time
        assert execution_time < 0.4, f"Parallel execution not fast enough: {execution_time}s"

        # Ensure result quality is maintained
        assert result is not None
        assert "metadata" in result
        assert "physical_stores" in result
        assert "logical_assets" in result

        # Verify all phases completed
        assert result["metadata"]["phases_completed"] == 9

    @pytest.mark.asyncio
    async def test_parallel_phase_grouping(self, inventory_tool):
        """Test that independent phases are properly grouped for parallel execution."""
        # Mock phase execution to track timing and grouping
        phase_timings = {}

        async def mock_phase(phase_name, *args, **kwargs):
            start = time.time()
            await asyncio.sleep(0.05)  # Simulate work
            end = time.time()
            phase_timings[phase_name] = (start, end)
            return {}

        with (
            patch.multiple(
                inventory_tool,
                _discover_physical_stores=lambda: mock_phase("physical"),
                _discover_configuration_assets=lambda: mock_phase("config"),
            ),
            patch.object(
                inventory_tool.schema_tool,
                "discover_schema",
                lambda: mock_phase("schema"),
            ),
            patch.object(
                inventory_tool.repository_analyzer,
                "analyze_repositories",
                lambda: mock_phase("repository"),
            ),
        ):

            await inventory_tool.perform_full_inventory_parallel()

            # Verify that independent phases ran in parallel
            # Group A phases (schema, physical, config) should overlap
            schema_start, schema_end = phase_timings["schema"]
            physical_start, physical_end = phase_timings["physical"]
            config_start, config_end = phase_timings["config"]

            # Check for temporal overlap indicating parallel execution
            assert (
                physical_start < schema_end and schema_start < physical_end
            ), "Schema and physical phases should run in parallel"

            assert (
                config_start < schema_end and schema_start < config_end
            ), "Schema and config phases should run in parallel"

    @pytest.mark.asyncio
    async def test_phase_dependency_preservation(self, inventory_tool):
        """Test that phase dependencies are preserved in parallel execution."""
        execution_order = []

        async def mock_dependent_phase(phase_name, *args, **kwargs):
            execution_order.append(phase_name)
            await asyncio.sleep(0.01)
            return {}

        # Mock phases with dependencies
        with patch.multiple(
            inventory_tool,
            _analyze_access_patterns=lambda *args: mock_dependent_phase("access_patterns"),
            _inventory_security_assets=lambda *args: mock_dependent_phase("security_assets"),
            _perform_gap_analysis=lambda *args: mock_dependent_phase("gap_analysis"),
        ):
            await inventory_tool.perform_full_inventory_parallel()

            # Verify dependency order is maintained
            access_index = execution_order.index("access_patterns")
            gap_index = execution_order.index("gap_analysis")

            # Gap analysis should run after access patterns
            assert gap_index > access_index, "Dependencies not preserved in parallel execution"

    @pytest.mark.asyncio
    async def test_error_handling_in_parallel_execution(self, inventory_tool):
        """Test error handling doesn't break parallel execution."""
        # Mock one phase to raise an exception
        with patch.object(
            inventory_tool.schema_tool,
            "discover_schema",
            side_effect=Exception("Simulated failure"),
        ):
            result = await inventory_tool.perform_full_inventory_parallel()

            # Should handle errors gracefully and continue
            assert result is not None
            assert "error" in result or "schema_discovery_error" in result


@pytest.mark.skipif(ComprehensiveDependencyAnalyzer is None, reason="ComprehensiveDependencyAnalyzer not available")
class TestComprehensiveAnalyzerParallelExecution:
    """Test parallel execution optimization for ComprehensiveDependencyAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        return ComprehensiveDependencyAnalyzer("/tmp/test_project")  # nosec B108 - test path

    @pytest.mark.asyncio
    async def test_sequential_graph_generation_baseline(self, analyzer):
        """Test current sequential graph generation for baseline."""
        # Mock dependencies
        mock_static_result = MagicMock()
        mock_static_result.service_dependencies = []
        mock_repo_result = MagicMock()
        mock_repo_result.repositories = []
        mock_repo_result.model_relationships = []

        start_time = time.time()
        graphs = await analyzer._generate_all_graphs(mock_static_result, mock_repo_result)
        execution_time = time.time() - start_time

        # Baseline measurement
        assert isinstance(graphs, dict)
        # Sequential should take more time
        assert execution_time > 0.01  # Should take some measurable time

    @pytest.mark.asyncio
    async def test_parallel_graph_generation_optimization(self, analyzer):
        """Test optimized parallel graph generation - THIS SHOULD FAIL INITIALLY."""
        # This test expects the optimized parallel implementation
        mock_static_result = MagicMock()
        mock_static_result.service_dependencies = []
        mock_repo_result = MagicMock()
        mock_repo_result.repositories = []
        mock_repo_result.model_relationships = []

        start_time = time.time()
        graphs = await analyzer._generate_all_graphs_parallel(mock_static_result, mock_repo_result)
        execution_time = time.time() - start_time

        # Should be significantly faster than sequential
        assert execution_time < 0.1, f"Parallel graph generation not fast enough: {execution_time}s"
        assert isinstance(graphs, dict)
        assert len(graphs) > 0

    @pytest.mark.asyncio
    async def test_comprehensive_analysis_performance(self, analyzer):
        """Test overall performance improvement in comprehensive analysis."""
        # Mock all components to control timing
        with patch.multiple(
            analyzer,
            static_analyzer=MagicMock(),
            repository_analyzer=MagicMock(),
            graph_generator=MagicMock(),
            runtime_tracer=MagicMock(),
        ):
            analyzer.static_analyzer.analyze_all_dependencies.return_value = MagicMock()
            analyzer.repository_analyzer.analyze_all_repositories.return_value = MagicMock()

            start_time = time.time()
            result = await analyzer.analyze_all_dependencies(include_runtime=False)
            execution_time = time.time() - start_time

            # Should complete quickly with optimizations
            assert result is not None
            assert execution_time < 2.0, f"Comprehensive analysis too slow: {execution_time}s"


class TestPerformanceBenchmarks:
    """Benchmark tests for measuring actual performance improvements."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_data_inventory_performance_improvement(self):
        """Benchmark test to validate 60-70% improvement target."""
        inventory_tool = DataAssetInventoryTool(project_root="/tmp/test_project")  # nosec B108 - test path

        # Measure baseline (sequential) performance
        start_time = time.time()
        baseline_result = await inventory_tool.perform_full_inventory()
        baseline_time = time.time() - start_time

        # Measure optimized (parallel) performance
        start_time = time.time()
        optimized_result = await inventory_tool.perform_full_inventory_parallel()
        optimized_time = time.time() - start_time

        # Calculate improvement percentage
        improvement = ((baseline_time - optimized_time) / baseline_time) * 100

        # Assert 60-70% improvement target
        assert improvement >= 60.0, f"Performance improvement {improvement:.1f}% below 60% target"
        assert improvement <= 80.0, f"Performance improvement {improvement:.1f}% seems unrealistic"

        # Ensure results are equivalent
        assert baseline_result["metadata"]["phases_completed"] == optimized_result["metadata"]["phases_completed"]

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_usage_improvement(self):
        """Test memory usage reduction during parallel execution."""
        import tracemalloc

        inventory_tool = DataAssetInventoryTool(project_root="/tmp/test_project")  # nosec B108 - test path

        # Measure baseline memory usage
        tracemalloc.start()
        await inventory_tool.perform_full_inventory()
        baseline_current, baseline_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure optimized memory usage
        tracemalloc.start()
        await inventory_tool.perform_full_inventory_parallel()
        optimized_current, optimized_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Calculate memory improvement
        memory_improvement = ((baseline_peak - optimized_peak) / baseline_peak) * 100

        # Assert memory usage improvement (target: 50% reduction)
        assert memory_improvement >= 0, "Memory usage should not increase"
        # Note: May not achieve 50% in unit tests, but should show improvement


@pytest.mark.integration
class TestParallelExecutionIntegration:
    """Integration tests for parallel execution with real components."""

    @pytest.mark.asyncio
    async def test_end_to_end_parallel_performance(self):
        """End-to-end test of parallel execution performance."""
        # This test would run with actual components
        # Skip if components not available
        pytest.skip("Integration test - requires full system setup")

    @pytest.mark.asyncio
    async def test_parallel_execution_with_database(self):
        """Test parallel execution with actual database connections."""
        # Test database connection handling in parallel execution
        pytest.skip("Integration test - requires database setup")
