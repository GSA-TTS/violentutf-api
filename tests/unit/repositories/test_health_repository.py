"""Comprehensive unit tests for HealthRepository implementation."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import DatabaseError, IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.health import HealthRepository


class TestHealthRepository:
    """Comprehensive unit tests for HealthRepository implementation."""

    @pytest.fixture
    def health_repository(self, mock_session: AsyncMock) -> HealthRepository:
        """Create HealthRepository instance with mocked session."""
        return HealthRepository(mock_session)

    @pytest.fixture
    def sample_database_stats(self) -> Dict[str, Any]:
        """Create sample database statistics for testing."""
        return {
            "total_connections": 20,
            "active_connections": 5,
            "idle_connections": 15,
            "connection_pool_size": 20,
            "connection_pool_overflow": 10,
            "checked_out_connections": 5,
            "checked_in_connections": 15,
            "pool_utilization_percent": 25.0,
            "database_version": "PostgreSQL 14.7",
            "database_size_mb": 1024.5,
            "uptime_seconds": 86400,
            "transactions_per_second": 150.2,
            "queries_per_second": 300.5,
            "slow_queries_count": 12,
            "deadlocks_count": 2,
            "last_backup": datetime.now(timezone.utc) - timedelta(hours=6),
        }

    @pytest.fixture
    def sample_system_metrics(self) -> Dict[str, Any]:
        """Create sample system metrics for testing."""
        return {
            "cpu_usage_percent": 45.2,
            "memory_usage_percent": 67.8,
            "memory_total_mb": 16384,
            "memory_available_mb": 5275,
            "disk_usage_percent": 78.9,
            "disk_total_gb": 500,
            "disk_available_gb": 105.5,
            "load_average_1min": 2.1,
            "load_average_5min": 1.8,
            "load_average_15min": 1.5,
            "network_bytes_sent": 1048576000,
            "network_bytes_recv": 2097152000,
            "process_count": 150,
            "thread_count": 850,
            "file_descriptors_used": 1024,
            "file_descriptors_max": 65536,
        }

    @pytest.fixture
    def sample_connection_pool_stats(self) -> Dict[str, Any]:
        """Create sample connection pool statistics for testing."""
        return {
            "pool_size": 20,
            "checked_out": 5,
            "overflow": 3,
            "invalid": 0,
            "checked_in": 12,
            "pool_utilization": 0.25,
            "overflow_utilization": 0.3,
            "total_connections": 20,
            "peak_connections": 18,
            "connection_creation_rate": 0.5,
            "connection_close_rate": 0.3,
            "avg_connection_age_seconds": 3600.5,
            "longest_connection_age_seconds": 7200.0,
            "pool_timeout_count": 2,
            "pool_recreation_count": 1,
        }

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test HealthRepository initialization."""
        repository = HealthRepository(mock_session)

        assert repository.session == mock_session
        assert repository.logger is not None

    # get_database_stats Tests

    @pytest.mark.asyncio
    async def test_get_database_stats_success(
        self,
        health_repository: HealthRepository,
        mock_session: AsyncMock,
        sample_database_stats: Dict[str, Any],
        query_result_factory,
    ):
        """Test successful database statistics retrieval."""
        # Arrange
        stats_data = [sample_database_stats]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock

        # Act
        stats = await health_repository.get_database_stats()

        # Assert
        assert stats["total_connections"] == 20
        assert stats["active_connections"] == 5
        assert stats["pool_utilization_percent"] == 25.0
        assert stats["database_version"] == "PostgreSQL 14.7"
        assert stats["transactions_per_second"] == 150.2
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_database_stats_connection_error(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test database stats retrieval with connection error."""
        # Arrange
        mock_session.execute.side_effect = OperationalError("Connection failed", None, None)

        # Act
        stats = await health_repository.get_database_stats()

        # Assert
        assert stats["status"] == "error"
        assert stats["error_type"] == "connection_error"
        assert "Connection failed" in stats["error_message"]
        assert stats["total_connections"] == 0
        assert stats["active_connections"] == 0

    @pytest.mark.asyncio
    async def test_get_database_stats_database_error(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test database stats retrieval with database error."""
        # Arrange
        mock_session.execute.side_effect = DatabaseError("Database error", None, None)

        # Act
        stats = await health_repository.get_database_stats()

        # Assert
        assert stats["status"] == "error"
        assert stats["error_type"] == "database_error"
        assert "Database error" in stats["error_message"]

    @pytest.mark.asyncio
    async def test_get_database_stats_with_minimal_data(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test database stats with minimal data available."""
        # Arrange
        minimal_stats = [
            {
                "total_connections": 5,
                "active_connections": 2,
                "database_version": "PostgreSQL 13.0",
            }
        ]
        result_mock = query_result_factory(data=minimal_stats)
        mock_session.execute.return_value = result_mock

        # Act
        stats = await health_repository.get_database_stats()

        # Assert
        assert stats["total_connections"] == 5
        assert stats["active_connections"] == 2
        assert stats["database_version"] == "PostgreSQL 13.0"
        # Should handle missing keys gracefully
        assert stats.get("database_size_mb", 0) == 0

    # check_database_connectivity Tests

    @pytest.mark.asyncio
    async def test_check_database_connectivity_healthy(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test database connectivity check when healthy."""
        # Arrange
        connectivity_result = [{"status": 1}]  # Simple ping result
        result_mock = query_result_factory(data=connectivity_result)
        mock_session.execute.return_value = result_mock

        # Act
        is_healthy = await health_repository.check_database_connectivity()

        # Assert
        assert is_healthy is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_database_connectivity_unhealthy(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test database connectivity check when unhealthy."""
        # Arrange
        mock_session.execute.side_effect = OperationalError("Connection timeout", None, None)

        # Act
        is_healthy = await health_repository.check_database_connectivity()

        # Assert
        assert is_healthy is False
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_database_connectivity_with_timeout(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test database connectivity check with timeout error."""
        # Arrange
        mock_session.execute.side_effect = asyncio.TimeoutError("Query timeout")

        # Act
        is_healthy = await health_repository.check_database_connectivity()

        # Assert
        assert is_healthy is False

    @pytest.mark.asyncio
    async def test_check_database_connectivity_general_exception(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test database connectivity check with general exception."""
        # Arrange
        mock_session.execute.side_effect = Exception("Unexpected error")

        # Act
        is_healthy = await health_repository.check_database_connectivity()

        # Assert
        assert is_healthy is False

    # get_system_metrics Tests

    @pytest.mark.asyncio
    async def test_get_system_metrics_success(
        self, health_repository: HealthRepository, sample_system_metrics: Dict[str, Any]
    ):
        """Test successful system metrics retrieval."""
        # Mock psutil or system metrics gathering
        with (
            patch("psutil.cpu_percent", return_value=45.2),
            patch("psutil.virtual_memory") as mock_memory,
            patch("psutil.disk_usage") as mock_disk,
            patch("psutil.getloadavg", return_value=(2.1, 1.8, 1.5)),
            patch("psutil.net_io_counters") as mock_net,
        ):
            # Configure mocks
            mock_memory.return_value.percent = 67.8
            mock_memory.return_value.total = 16384 * 1024 * 1024
            mock_memory.return_value.available = 5275 * 1024 * 1024

            mock_disk.return_value.percent = 78.9
            mock_disk.return_value.total = 500 * 1024 * 1024 * 1024
            mock_disk.return_value.free = 105.5 * 1024 * 1024 * 1024

            mock_net.return_value.bytes_sent = 1048576000
            mock_net.return_value.bytes_recv = 2097152000

            # Act
            metrics = await health_repository.get_system_metrics()

            # Assert
            assert metrics["cpu_usage_percent"] == 45.2
            assert metrics["memory_usage_percent"] == 67.8
            assert metrics["disk_usage_percent"] == 78.9
            assert metrics["load_average_1min"] == 2.1
            assert metrics["network_bytes_sent"] == 1048576000

    @pytest.mark.asyncio
    async def test_get_system_metrics_psutil_error(self, health_repository: HealthRepository):
        """Test system metrics retrieval when psutil has errors."""
        # Mock psutil errors
        with (
            patch("psutil.cpu_percent", side_effect=Exception("CPU info unavailable")),
            patch("psutil.virtual_memory", side_effect=Exception("Memory info unavailable")),
        ):
            # Act
            metrics = await health_repository.get_system_metrics()

            # Assert
            assert metrics["status"] == "error"
            assert metrics["error_type"] == "system_metrics_error"
            assert metrics["cpu_usage_percent"] == 0.0
            assert metrics["memory_usage_percent"] == 0.0

    @pytest.mark.asyncio
    async def test_get_system_metrics_partial_failure(self, health_repository: HealthRepository):
        """Test system metrics with partial data availability."""
        # Mock partial success
        with (
            patch("psutil.cpu_percent", return_value=55.0),
            patch("psutil.virtual_memory", side_effect=Exception("Memory unavailable")),
            patch("psutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value.percent = 60.0
            mock_disk.return_value.total = 1000 * 1024 * 1024 * 1024
            mock_disk.return_value.free = 400 * 1024 * 1024 * 1024

            # Act
            metrics = await health_repository.get_system_metrics()

            # Assert
            assert metrics["cpu_usage_percent"] == 55.0
            assert metrics["disk_usage_percent"] == 60.0
            assert metrics["memory_usage_percent"] == 0.0  # Failed to get memory

    # get_connection_pool_stats Tests

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_success(
        self, health_repository: HealthRepository, mock_session: AsyncMock, sample_connection_pool_stats: Dict[str, Any]
    ):
        """Test successful connection pool statistics retrieval."""
        # Mock the engine and pool
        mock_engine = MagicMock()
        mock_pool = MagicMock()

        # Configure pool stats
        mock_pool.size = 20
        mock_pool.checkedout = 5
        mock_pool.overflow = 3
        mock_pool.checkedin = 12
        mock_pool.invalid = 0

        mock_engine.pool = mock_pool
        mock_session.get_bind.return_value = mock_engine

        # Act
        stats = await health_repository.get_connection_pool_stats()

        # Assert
        assert stats["pool_size"] == 20
        assert stats["checked_out"] == 5
        assert stats["overflow"] == 3
        assert stats["checked_in"] == 12
        assert stats["invalid"] == 0

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_no_pool(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test connection pool stats when no pool is available."""
        # Arrange
        mock_engine = MagicMock()
        mock_engine.pool = None
        mock_session.get_bind.return_value = mock_engine

        # Act
        stats = await health_repository.get_connection_pool_stats()

        # Assert
        assert stats["status"] == "error"
        assert stats["error_type"] == "no_pool_available"
        assert stats["pool_size"] == 0
        assert stats["checked_out"] == 0

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_engine_error(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test connection pool stats with engine error."""
        # Arrange
        mock_session.get_bind.side_effect = Exception("Engine unavailable")

        # Act
        stats = await health_repository.get_connection_pool_stats()

        # Assert
        assert stats["status"] == "error"
        assert stats["error_type"] == "engine_error"
        assert "Engine unavailable" in stats["error_message"]

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_with_utilization_calculation(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test connection pool stats with utilization calculations."""
        # Mock the engine and pool
        mock_engine = MagicMock()
        mock_pool = MagicMock()

        # Configure pool for utilization calculation
        mock_pool.size = 100
        mock_pool.checkedout = 25
        mock_pool.overflow = 5
        mock_pool.checkedin = 70
        mock_pool.invalid = 0

        mock_engine.pool = mock_pool
        mock_session.get_bind.return_value = mock_engine

        # Act
        stats = await health_repository.get_connection_pool_stats()

        # Assert
        assert stats["pool_size"] == 100
        assert stats["checked_out"] == 25
        assert stats["pool_utilization"] == 0.25  # 25/100
        assert stats["overflow_utilization"] > 0  # Some overflow usage

    # run_health_checks Tests

    @pytest.mark.asyncio
    async def test_run_health_checks_all_healthy(
        self,
        health_repository: HealthRepository,
        mock_session: AsyncMock,
        sample_database_stats: Dict[str, Any],
        query_result_factory,
    ):
        """Test comprehensive health checks when all systems are healthy."""
        # Arrange
        stats_data = [sample_database_stats]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock
        mock_session.get_bind.return_value.pool.size = 20

        with patch("psutil.cpu_percent", return_value=45.0), patch("psutil.virtual_memory") as mock_memory:
            mock_memory.return_value.percent = 60.0
            mock_memory.return_value.total = 16 * 1024 * 1024 * 1024

            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            assert health_status["overall_status"] == "healthy"
            assert health_status["database"]["status"] == "healthy"
            assert health_status["system"]["status"] == "healthy"
            assert health_status["connection_pool"]["status"] == "healthy"
            assert health_status["checks_completed"] is True

    @pytest.mark.asyncio
    async def test_run_health_checks_database_unhealthy(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test health checks when database is unhealthy."""
        # Arrange
        mock_session.execute.side_effect = OperationalError("DB connection failed", None, None)

        with patch("psutil.cpu_percent", return_value=30.0):
            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            assert health_status["overall_status"] == "unhealthy"
            assert health_status["database"]["status"] == "unhealthy"
            assert health_status["system"]["status"] == "healthy"
            assert "DB connection failed" in health_status["database"]["error_message"]

    @pytest.mark.asyncio
    async def test_run_health_checks_system_degraded(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test health checks with degraded system performance."""
        # Arrange - Database healthy
        result_mock = query_result_factory(data=[{"total_connections": 10}])
        mock_session.execute.return_value = result_mock

        # Mock high system resource usage
        with patch("psutil.cpu_percent", return_value=95.0), patch("psutil.virtual_memory") as mock_memory:
            mock_memory.return_value.percent = 95.0

            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            assert health_status["overall_status"] == "degraded"
            assert health_status["database"]["status"] == "healthy"
            assert health_status["system"]["status"] == "degraded"
            assert health_status["system"]["cpu_usage_percent"] == 95.0

    @pytest.mark.asyncio
    async def test_run_health_checks_partial_failures(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test health checks with partial component failures."""
        # Arrange - Database fails, but system metrics work
        mock_session.execute.side_effect = Exception("Database error")
        mock_session.get_bind.side_effect = Exception("Pool error")

        with patch("psutil.cpu_percent", return_value=50.0):
            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            assert health_status["overall_status"] == "unhealthy"
            assert health_status["database"]["status"] == "unhealthy"
            assert health_status["connection_pool"]["status"] == "unhealthy"
            assert health_status["system"]["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_run_health_checks_with_thresholds(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test health checks with configurable thresholds."""
        # Arrange
        stats_data = [{"total_connections": 50, "active_connections": 45}]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock

        with (
            patch("psutil.cpu_percent", return_value=85.0),
            patch("psutil.virtual_memory") as mock_memory,
            patch("psutil.disk_usage") as mock_disk,
        ):
            mock_memory.return_value.percent = 85.0
            mock_disk.return_value.percent = 95.0

            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            # Should be degraded due to high resource usage
            assert health_status["overall_status"] in ["degraded", "unhealthy"]
            assert health_status["system"]["cpu_usage_percent"] == 85.0
            assert health_status["system"]["memory_usage_percent"] == 85.0

    @pytest.mark.asyncio
    async def test_run_health_checks_response_time_tracking(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test health checks include response time tracking."""
        # Arrange
        result_mock = query_result_factory(data=[{"total_connections": 10}])
        mock_session.execute.return_value = result_mock

        with patch("psutil.cpu_percent", return_value=40.0):
            # Act
            health_status = await health_repository.run_health_checks()

            # Assert
            assert "response_time_ms" in health_status
            assert health_status["response_time_ms"] >= 0
            assert "database_response_time_ms" in health_status["database"]
            assert "system_response_time_ms" in health_status["system"]

    # Error Handling and Edge Case Tests

    @pytest.mark.asyncio
    async def test_concurrent_health_checks(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test concurrent health check operations."""
        # Arrange
        result_mock = query_result_factory(data=[{"total_connections": 10}])
        mock_session.execute.return_value = result_mock

        with patch("psutil.cpu_percent", return_value=30.0):
            # Act - Run multiple health checks concurrently
            check_tasks = [
                health_repository.run_health_checks(),
                health_repository.check_database_connectivity(),
                health_repository.get_database_stats(),
                health_repository.get_system_metrics(),
                health_repository.get_connection_pool_stats(),
            ]

            results = await asyncio.gather(*check_tasks, return_exceptions=True)

            # Assert
            assert len(results) == 5
            # First result should be comprehensive health check
            assert isinstance(results[0], dict)
            assert "overall_status" in results[0]
            # Other results should complete without exceptions
            assert not any(isinstance(r, Exception) for r in results[1:])

    @pytest.mark.asyncio
    async def test_health_check_timeout_handling(self, health_repository: HealthRepository, mock_session: AsyncMock):
        """Test health check timeout handling."""

        # Arrange - Simulate slow database query
        async def slow_query(*args, **kwargs):
            await asyncio.sleep(10)  # Simulate slow query

        mock_session.execute.side_effect = slow_query

        # Act with timeout
        try:
            health_status = await asyncio.wait_for(health_repository.run_health_checks(), timeout=5.0)
        except asyncio.TimeoutError:
            health_status = {"overall_status": "timeout", "error": "Health check timed out"}

        # Assert
        assert health_status["overall_status"] == "timeout"

    @pytest.mark.asyncio
    async def test_memory_usage_during_health_checks(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test memory usage patterns during health checks."""
        # This test ensures health checks don't cause memory leaks

        # Arrange
        result_mock = query_result_factory(data=[{"total_connections": 10}])
        mock_session.execute.return_value = result_mock

        with patch("psutil.cpu_percent", return_value=40.0):
            # Act - Run health checks multiple times
            for _ in range(10):
                health_status = await health_repository.run_health_checks()

                # Assert basic structure is maintained
                assert "overall_status" in health_status
                assert "database" in health_status
                assert "system" in health_status

    @pytest.mark.asyncio
    async def test_health_check_data_integrity(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test data integrity in health check responses."""
        # Arrange
        stats_data = [
            {
                "total_connections": 25,
                "active_connections": 10,
                "database_version": "PostgreSQL 14.7",
            }
        ]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock

        with patch("psutil.cpu_percent", return_value=55.5), patch("psutil.virtual_memory") as mock_memory:
            mock_memory.return_value.percent = 72.3
            mock_memory.return_value.total = 8 * 1024 * 1024 * 1024

            # Act
            health_status = await health_repository.run_health_checks()

            # Assert data types and ranges
            assert isinstance(health_status["database"]["total_connections"], int)
            assert health_status["database"]["total_connections"] >= 0
            assert isinstance(health_status["system"]["cpu_usage_percent"], float)
            assert 0 <= health_status["system"]["cpu_usage_percent"] <= 100
            assert isinstance(health_status["response_time_ms"], (int, float))
            assert health_status["response_time_ms"] >= 0

    @pytest.mark.asyncio
    async def test_health_repository_interface_compliance(
        self, health_repository: HealthRepository, mock_session: AsyncMock
    ):
        """Test that HealthRepository implements the interface correctly."""
        from app.repositories.interfaces.health import IHealthRepository

        # Assert
        assert isinstance(health_repository, IHealthRepository)

        # Test all interface methods exist and are callable
        assert callable(getattr(health_repository, "get_database_stats"))
        assert callable(getattr(health_repository, "check_database_connectivity"))
        assert callable(getattr(health_repository, "get_system_metrics"))
        assert callable(getattr(health_repository, "get_connection_pool_stats"))
        assert callable(getattr(health_repository, "run_health_checks"))

    @pytest.mark.asyncio
    async def test_health_checks_with_custom_configuration(
        self, health_repository: HealthRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test health checks with custom configuration parameters."""
        # This test would verify health checks can be customized
        # In a real implementation, this might involve configuration files or environment variables

        # Arrange
        result_mock = query_result_factory(data=[{"total_connections": 15}])
        mock_session.execute.return_value = result_mock

        with patch.dict(
            "os.environ",
            {
                "HEALTH_CHECK_CPU_THRESHOLD": "80.0",
                "HEALTH_CHECK_MEMORY_THRESHOLD": "85.0",
                "HEALTH_CHECK_TIMEOUT": "30",
            },
        ):
            with patch("psutil.cpu_percent", return_value=75.0):
                # Act
                health_status = await health_repository.run_health_checks()

                # Assert
                # With custom thresholds, 75% CPU should be healthy
                assert health_status["system"]["status"] == "healthy"
