"""Test monitoring and tracking utilities."""

import asyncio
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from app.utils.monitoring import (
    check_dependency_health,
    decrement_connection_count,
    get_system_metrics,
    increment_connection_count,
    resource_usage,
    track_health_check,
    track_request_performance,
)


class TestHealthCheckTracking:
    """Test health check tracking decorator."""

    @pytest.mark.asyncio
    async def test_track_health_check_success(self) -> None:
        """Test health check tracking with successful result."""

        @track_health_check
        async def mock_health_check() -> dict[str, str]:
            return {"status": "healthy"}

        with (
            patch("app.utils.monitoring.health_check_total") as mock_counter,
            patch("app.utils.monitoring.health_check_duration") as mock_histogram,
        ):
            result = await mock_health_check()

            assert result == {"status": "healthy"}
            mock_counter.labels.assert_called_once_with(endpoint="mock_health_check", status="success")
            mock_counter.labels.return_value.inc.assert_called_once()
            mock_histogram.labels.assert_called_once_with(endpoint="mock_health_check")

    @pytest.mark.asyncio
    async def test_track_health_check_failure(self) -> None:
        """Test health check tracking with failure result."""

        @track_health_check
        async def mock_health_check() -> dict[str, str]:
            return {"status": "not ready"}

        with patch("app.utils.monitoring.health_check_total") as mock_counter:
            result = await mock_health_check()

            assert result == {"status": "not ready"}
            mock_counter.labels.assert_called_once_with(endpoint="mock_health_check", status="failure")

    @pytest.mark.asyncio
    async def test_track_health_check_exception(self) -> None:
        """Test health check tracking with exception."""

        @track_health_check
        async def mock_health_check() -> None:
            raise ValueError("Test error")

        with patch("app.utils.monitoring.health_check_total") as mock_counter:
            with pytest.raises(ValueError):
                await mock_health_check()

            mock_counter.labels.assert_called_once_with(endpoint="mock_health_check", status="error")

    @pytest.mark.asyncio
    async def test_track_health_check_ready_status(self) -> None:
        """Test health check tracking with ready status."""

        @track_health_check
        async def mock_health_check() -> dict[str, str]:
            return {"status": "ready"}

        with patch("app.utils.monitoring.health_check_total") as mock_counter:
            result = await mock_health_check()

            assert result == {"status": "ready"}
            mock_counter.labels.assert_called_once_with(endpoint="mock_health_check", status="success")


class TestRequestPerformanceTracking:
    """Test request performance tracking decorator."""

    def setup_method(self) -> None:
        """Reset resource usage before each test."""
        resource_usage["active_requests"] = 0

    @pytest.mark.asyncio
    async def test_track_request_performance_success(self) -> None:
        """Test request performance tracking with successful result."""

        @track_request_performance
        async def mock_endpoint() -> dict[str, str]:
            return {"data": "test"}

        with patch("app.utils.monitoring.request_duration") as mock_histogram:
            result = await mock_endpoint()

            assert result == {"data": "test"}
            mock_histogram.labels.assert_called_once_with(method="UNKNOWN", endpoint="mock_endpoint", status="success")
            mock_histogram.labels.return_value.observe.assert_called_once()

    @pytest.mark.asyncio
    async def test_track_request_performance_exception(self) -> None:
        """Test request performance tracking with exception."""

        @track_request_performance
        async def mock_endpoint() -> None:
            raise ValueError("Test error")

        with patch("app.utils.monitoring.request_duration") as mock_histogram:
            with pytest.raises(ValueError):
                await mock_endpoint()

            mock_histogram.labels.assert_called_once_with(method="UNKNOWN", endpoint="mock_endpoint", status="error")

    @pytest.mark.asyncio
    async def test_track_request_performance_active_requests(self) -> None:
        """Test that active requests counter is updated."""

        @track_request_performance
        async def mock_endpoint() -> dict[str, str]:
            # Check that active requests is incremented during execution
            assert resource_usage["active_requests"] == 1
            return {"data": "test"}

        initial_count = resource_usage["active_requests"]
        await mock_endpoint()
        final_count = resource_usage["active_requests"]

        assert initial_count == 0
        assert final_count == 0  # Should be decremented after completion

    @pytest.mark.asyncio
    async def test_track_request_performance_with_request_object(self) -> None:
        """Test request tracking with request object containing method."""
        mock_request = MagicMock()
        mock_request.method = "GET"

        @track_request_performance
        async def mock_endpoint(request: Any) -> dict[str, str]:
            return {"data": "test"}

        with patch("app.utils.monitoring.request_duration") as mock_histogram:
            await mock_endpoint(mock_request)

            mock_histogram.labels.assert_called_once_with(method="GET", endpoint="mock_endpoint", status="success")


class TestSystemMetrics:
    """Test system metrics collection."""

    @pytest.mark.asyncio
    async def test_get_system_metrics_success(self) -> None:
        """Test successful system metrics collection."""
        # Create mock psutil module
        mock_psutil = Mock()
        mock_psutil.cpu_percent.return_value = 25.5
        mock_memory = MagicMock()
        mock_memory.percent = 60.0
        mock_memory.available = 4 * 1024**3  # 4GB
        mock_psutil.virtual_memory.return_value = mock_memory

        mock_disk = MagicMock()
        mock_disk.used = 50 * 1024**3  # 50GB
        mock_disk.total = 100 * 1024**3  # 100GB
        mock_disk.free = 50 * 1024**3  # 50GB
        mock_psutil.disk_usage.return_value = mock_disk

        # Patch sys.modules to use our mock
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            # Set some application metrics
            resource_usage["active_requests"] = 5
            resource_usage["database_connections"] = 3

            metrics = await get_system_metrics()

            assert "timestamp" in metrics
            assert "system" in metrics
            assert "application" in metrics

            system_metrics = metrics["system"]
            assert system_metrics["cpu_percent"] == 25.5
            assert system_metrics["memory_percent"] == 60.0
            assert system_metrics["memory_available_gb"] == 4.0
            assert system_metrics["disk_percent"] == 50.0
            assert system_metrics["disk_free_gb"] == 50.0

            app_metrics = metrics["application"]
            assert app_metrics["active_requests"] == 5
            assert app_metrics["database_connections"] == 3

    @pytest.mark.asyncio
    async def test_get_system_metrics_exception(self) -> None:
        """Test system metrics collection with exception."""
        # Create mock psutil module that raises exception
        mock_psutil = Mock()
        mock_psutil.cpu_percent.side_effect = Exception("psutil error")

        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            metrics = await get_system_metrics()

            assert "timestamp" in metrics
            assert "error" in metrics
            assert "application" in metrics
            assert metrics["error"] == "psutil error"


class TestConnectionCounting:
    """Test connection counting utilities."""

    def setup_method(self) -> None:
        """Reset connection counts before each test."""
        resource_usage["database_connections"] = 0
        resource_usage["cache_connections"] = 0

    def test_increment_connection_count_database(self) -> None:
        """Test incrementing database connection count."""
        initial_count = resource_usage["database_connections"]

        increment_connection_count("database")

        assert resource_usage["database_connections"] == initial_count + 1

    def test_increment_connection_count_cache(self) -> None:
        """Test incrementing cache connection count."""
        initial_count = resource_usage["cache_connections"]

        increment_connection_count("cache")

        assert resource_usage["cache_connections"] == initial_count + 1

    def test_increment_connection_count_invalid_type(self) -> None:
        """Test incrementing invalid connection type does nothing."""
        initial_db = resource_usage["database_connections"]
        initial_cache = resource_usage["cache_connections"]

        increment_connection_count("invalid")

        assert resource_usage["database_connections"] == initial_db
        assert resource_usage["cache_connections"] == initial_cache

    def test_decrement_connection_count_database(self) -> None:
        """Test decrementing database connection count."""
        resource_usage["database_connections"] = 5

        decrement_connection_count("database")

        assert resource_usage["database_connections"] == 4

    def test_decrement_connection_count_zero(self) -> None:
        """Test decrementing connection count when already zero."""
        resource_usage["database_connections"] = 0

        decrement_connection_count("database")

        assert resource_usage["database_connections"] == 0

    def test_decrement_connection_count_invalid_type(self) -> None:
        """Test decrementing invalid connection type does nothing."""
        initial_db = resource_usage["database_connections"] = 5

        decrement_connection_count("invalid")

        assert resource_usage["database_connections"] == initial_db


class TestDependencyHealth:
    """Test comprehensive dependency health checking."""

    def setup_method(self) -> None:
        """Clear health check cache before each test."""
        from app.utils.monitoring import clear_health_check_cache

        clear_health_check_cache()

    @pytest.mark.asyncio
    async def test_check_dependency_health_all_healthy(self) -> None:
        """Test dependency health check when all services are healthy."""
        with (
            patch("app.db.session.check_database_health") as mock_db_health,
            patch("app.utils.cache.check_cache_health") as mock_cache_health,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db_health.return_value = True
            mock_cache_health.return_value = True
            mock_metrics.return_value = {"system": "metrics"}

            result = await check_dependency_health()

            assert result["overall_healthy"] is True
            assert result["checks"]["database"] is True
            assert result["checks"]["cache"] is True
            assert "check_duration_seconds" in result
            assert result["metrics"] == {"system": "metrics"}

    @pytest.mark.asyncio
    async def test_check_dependency_health_database_unhealthy(self) -> None:
        """Test dependency health check when database is unhealthy."""
        with (
            patch("app.db.session.check_database_health") as mock_db_health,
            patch("app.utils.cache.check_cache_health") as mock_cache_health,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db_health.return_value = False
            mock_cache_health.return_value = True
            mock_metrics.return_value = {"system": "metrics"}

            result = await check_dependency_health()

            assert result["overall_healthy"] is False
            assert result["checks"]["database"] is False
            assert result["checks"]["cache"] is True

    @pytest.mark.asyncio
    async def test_check_dependency_health_with_exceptions(self) -> None:
        """Test dependency health check when checks raise exceptions."""
        with (
            patch("app.db.session.check_database_health") as mock_db_health,
            patch("app.utils.cache.check_cache_health") as mock_cache_health,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db_health.side_effect = Exception("Database error")
            mock_cache_health.return_value = True
            mock_metrics.return_value = {"system": "metrics"}

            result = await check_dependency_health()

            assert result["overall_healthy"] is False
            assert result["checks"]["database"] is False
            assert result["checks"]["cache"] is True

    @pytest.mark.asyncio
    async def test_check_dependency_health_complete_failure(self) -> None:
        """Test dependency health check with complete failure."""
        with patch("app.db.session.check_database_health") as mock_db_health:
            mock_db_health.side_effect = Exception("Complete failure")

            result = await check_dependency_health()

            assert result["overall_healthy"] is False
            assert result["checks"]["database"] is False
            assert "check_duration_seconds" in result
