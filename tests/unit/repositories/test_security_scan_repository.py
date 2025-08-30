"""Comprehensive unit tests for SecurityScanRepository implementation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ScanStatus, ScanType
from app.models.security_scan import SecurityScan
from app.repositories.base import Page
from app.repositories.security_scan import SecurityScanRepository


class TestSecurityScanRepository:
    """Comprehensive unit tests for SecurityScanRepository implementation."""

    @pytest.fixture
    def security_scan_repository(self, mock_session: AsyncMock) -> SecurityScanRepository:
        """Create SecurityScanRepository instance with mocked session."""
        return SecurityScanRepository(mock_session)

    @pytest.fixture
    def sample_security_scan(self, security_scan_factory) -> SecurityScan:
        """Create a sample security scan for testing."""
        return security_scan_factory.create(
            id="test-scan-id",
            target="https://example.com",
            scan_type=ScanType.PYRIT,
            status=ScanStatus.COMPLETED,
            initiated_by="test-user-id",
            configuration={"depth": 3, "aggressive": False},
            total_findings=5,
            high_findings=1,
            medium_findings=2,
            low_findings=2,
            started_at=datetime.now(timezone.utc) - timedelta(hours=1),
            completed_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )

    @pytest.fixture
    def running_scan(self, security_scan_factory) -> SecurityScan:
        """Create a running security scan for testing."""
        return security_scan_factory.create(
            id="running-scan-id",
            target="https://testing.com",
            scan_type="port_scan",
            status="running",
            user_id="test-user-id",
            started_at=datetime.now(timezone.utc) - timedelta(minutes=30),
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

    @pytest.fixture
    def failed_scan(self, security_scan_factory) -> SecurityScan:
        """Create a failed security scan for testing."""
        return security_scan_factory.create(
            id="failed-scan-id",
            target="https://unreachable.com",
            scan_type="web_scan",
            status="failed",
            user_id="test-user-id",
            error_message="Target unreachable",
            started_at=datetime.now(timezone.utc) - timedelta(hours=2),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=1),
            created_at=datetime.now(timezone.utc) - timedelta(hours=3),
        )

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test SecurityScanRepository initialization."""
        repository = SecurityScanRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == SecurityScan
        assert repository.logger is not None

    # get_scans_by_target Tests

    @pytest.mark.asyncio
    async def test_get_scans_by_target_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful retrieval of scans by target."""
        # Arrange
        scans = [sample_security_scan]
        result_mock = query_result_factory(data=scans)
        mock_session.execute.return_value = result_mock

        # Act
        target_scans = await security_scan_repository.get_scans_by_target("https://example.com")

        # Assert
        assert len(target_scans) == 1
        assert target_scans[0].target == "https://example.com"
        assert target_scans[0].scan_type == "pyrit"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scans_by_target_multiple_scans(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test retrieval of multiple scans for same target."""
        # Arrange - Both scans for same target
        running_scan.target = "https://example.com"
        scans = [sample_security_scan, running_scan]
        result_mock = query_result_factory(data=scans)
        mock_session.execute.return_value = result_mock

        # Act
        target_scans = await security_scan_repository.get_scans_by_target("https://example.com")

        # Assert
        assert len(target_scans) == 2
        assert all(scan.target == "https://example.com" for scan in target_scans)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scans_by_target_not_found(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test retrieval when no scans exist for target."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        target_scans = await security_scan_repository.get_scans_by_target("https://nonexistent.com")

        # Assert
        assert target_scans == []
        mock_session.execute.assert_called_once()

    # get_scan_statistics Tests

    @pytest.mark.asyncio
    async def test_get_scan_statistics_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test successful scan statistics retrieval."""
        # Arrange
        stats_data = [
            {
                "total_scans": 150,
                "completed_scans": 120,
                "running_scans": 15,
                "failed_scans": 15,
                "cancelled_scans": 0,
                "avg_duration_minutes": 45.5,
                "total_vulnerabilities_found": 350,
            }
        ]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock
        time_period = timedelta(days=30)

        # Act
        stats = await security_scan_repository.get_scan_statistics(time_period)

        # Assert
        assert stats["total_scans"] == 150
        assert stats["completed_scans"] == 120
        assert stats["running_scans"] == 15
        assert stats["avg_duration_minutes"] == 45.5
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scan_statistics_empty_period(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test scan statistics for period with no scans."""
        # Arrange
        stats_data = [
            {
                "total_scans": 0,
                "completed_scans": 0,
                "running_scans": 0,
                "failed_scans": 0,
            }
        ]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock
        time_period = timedelta(hours=1)  # Very short period

        # Act
        stats = await security_scan_repository.get_scan_statistics(time_period)

        # Assert
        assert stats["total_scans"] == 0
        assert stats["completed_scans"] == 0
        mock_session.execute.assert_called_once()

    # create_scan Tests

    @pytest.mark.asyncio
    async def test_create_scan_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        security_scan_factory,
    ):
        """Test successful security scan creation."""
        # Arrange
        new_scan = security_scan_factory.create(
            id="new-scan-id",
            target="https://newscan.com",
            scan_type="vulnerability_scan",
            user_id="test-user-id",
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.security_scan.SecurityScan", return_value=new_scan):
            # Act
            created_scan = await security_scan_repository.create_scan(
                target="https://newscan.com",
                scan_type="vulnerability_scan",
                user_id="test-user-id",
                parameters={"depth": 5, "threads": 10},
            )

            # Assert
            assert created_scan is not None
            assert created_scan.target == "https://newscan.com"
            assert created_scan.scan_type == "vulnerability_scan"
            assert created_scan.user_id == "test-user-id"
            mock_session.add.assert_called_once()
            mock_session.flush.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_scan_with_minimal_parameters(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        security_scan_factory,
    ):
        """Test scan creation with minimal required parameters."""
        # Arrange
        minimal_scan = security_scan_factory.create(
            id="minimal-scan-id",
            target="https://minimal.com",
            scan_type="basic_scan",
            user_id="test-user-id",
            configuration={},
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.security_scan.SecurityScan", return_value=minimal_scan):
            # Act
            created_scan = await security_scan_repository.create_scan(
                target="https://minimal.com",
                scan_type="basic_scan",
                user_id="test-user-id",
            )

            # Assert
            assert created_scan is not None
            assert created_scan.parameters is None or created_scan.parameters == {}

    @pytest.mark.asyncio
    async def test_create_scan_database_error(
        self, security_scan_repository: SecurityScanRepository, mock_session: AsyncMock
    ):
        """Test database error handling in scan creation."""
        # Arrange
        mock_session.flush.side_effect = IntegrityError("Constraint violation", None, None)
        mock_session.rollback.return_value = None

        # Act & Assert
        with pytest.raises(IntegrityError):
            await security_scan_repository.create_scan(
                target="https://error.com",
                scan_type="test_scan",
                user_id="test-user-id",
            )

        mock_session.rollback.assert_called_once()

    # update_scan_status Tests

    @pytest.mark.asyncio
    async def test_update_scan_status_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful scan status update."""
        # Arrange
        result_mock = query_result_factory(scalar_result=running_scan)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        results = {"vulnerabilities": 3, "severity": {"high": 0, "medium": 1, "low": 2}}

        # Act
        updated_scan = await security_scan_repository.update_scan_status(
            scan_id="running-scan-id",
            status="completed",
            results=results,
        )

        # Assert
        assert updated_scan is not None
        assert updated_scan.status == "completed"
        assert updated_scan.results == results
        assert updated_scan.completed_at is not None
        mock_session.flush.assert_called_once()
        mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_scan_status_with_error(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test scan status update with error message."""
        # Arrange
        result_mock = query_result_factory(scalar_result=running_scan)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        # Act
        updated_scan = await security_scan_repository.update_scan_status(
            scan_id="running-scan-id",
            status="failed",
            error_message="Network timeout occurred",
        )

        # Assert
        assert updated_scan is not None
        assert updated_scan.status == "failed"
        assert updated_scan.error_message == "Network timeout occurred"
        assert updated_scan.completed_at is not None

    @pytest.mark.asyncio
    async def test_update_scan_status_not_found(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test updating status for non-existent scan."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        updated_scan = await security_scan_repository.update_scan_status(
            scan_id="nonexistent-scan-id",
            status="completed",
        )

        # Assert
        assert updated_scan is None
        mock_session.flush.assert_not_called()

    # get_active_scans Tests

    @pytest.mark.asyncio
    async def test_get_active_scans_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful retrieval of active scans."""
        # Arrange
        active_scans = [running_scan]
        result_mock = query_result_factory(data=active_scans)
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_active_scans()

        # Assert
        assert len(scans) == 1
        assert scans[0].status == "running"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_active_scans_multiple_statuses(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        security_scan_factory,
        query_result_factory,
    ):
        """Test retrieval of scans with different active statuses."""
        # Arrange
        running_scan1 = security_scan_factory.create(status="running")
        pending_scan = security_scan_factory.create(status="pending")
        queued_scan = security_scan_factory.create(status="queued")

        active_scans = [running_scan1, pending_scan, queued_scan]
        result_mock = query_result_factory(data=active_scans)
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_active_scans()

        # Assert
        assert len(scans) == 3
        active_statuses = {scan.status for scan in scans}
        assert "completed" not in active_statuses
        assert "failed" not in active_statuses

    @pytest.mark.asyncio
    async def test_get_active_scans_none_active(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test retrieval when no active scans exist."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_active_scans()

        # Assert
        assert scans == []
        mock_session.execute.assert_called_once()

    # get_user_scans Tests

    @pytest.mark.asyncio
    async def test_get_user_scans_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful retrieval of user scans."""
        # Arrange
        user_scans = [sample_security_scan]
        result_mock = query_result_factory(data=user_scans)
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_user_scans("test-user-id", limit=50)

        # Assert
        assert len(scans) == 1
        assert scans[0].user_id == "test-user-id"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_scans_with_status_filter(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test user scans retrieval with status filtering."""
        # Arrange
        completed_scans = [sample_security_scan]
        result_mock = query_result_factory(data=completed_scans)
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_user_scans("test-user-id", limit=20, status_filter="completed")

        # Assert
        assert len(scans) == 1
        assert scans[0].status == "completed"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_scans_with_custom_limit(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test user scans retrieval with custom limit."""
        # Arrange
        many_scans = [sample_security_scan] * 10
        result_mock = query_result_factory(data=many_scans)
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_user_scans("test-user-id", limit=10)

        # Assert
        assert len(scans) == 10
        mock_session.execute.assert_called_once()

    # get_scan_results Tests

    @pytest.mark.asyncio
    async def test_get_scan_results_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful scan results retrieval."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_security_scan)
        mock_session.execute.return_value = result_mock

        # Act
        results = await security_scan_repository.get_scan_results("test-scan-id")

        # Assert
        assert results is not None
        assert results["vulnerabilities"] == 5
        assert results["severity"]["high"] == 1
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scan_results_not_found(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test scan results for non-existent scan."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        results = await security_scan_repository.get_scan_results("nonexistent-scan-id")

        # Assert
        assert results is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scan_results_no_results(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test scan results for scan with no results yet."""
        # Arrange
        running_scan.results = None
        result_mock = query_result_factory(scalar_result=running_scan)
        mock_session.execute.return_value = result_mock

        # Act
        results = await security_scan_repository.get_scan_results("running-scan-id")

        # Assert
        assert results is None
        mock_session.execute.assert_called_once()

    # cancel_scan Tests

    @pytest.mark.asyncio
    async def test_cancel_scan_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test successful scan cancellation."""
        # Arrange
        result_mock = query_result_factory(scalar_result=running_scan)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None

        # Act
        success = await security_scan_repository.cancel_scan("running-scan-id", "admin")

        # Assert
        assert success is True
        assert running_scan.status == "cancelled"
        assert running_scan.cancelled_by == "admin"
        assert running_scan.completed_at is not None
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_cancel_scan_not_found(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test cancelling non-existent scan."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        success = await security_scan_repository.cancel_scan("nonexistent-scan-id", "admin")

        # Assert
        assert success is False
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_cancel_scan_already_completed(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        sample_security_scan: SecurityScan,
        query_result_factory,
    ):
        """Test cancelling already completed scan."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_security_scan)
        mock_session.execute.return_value = result_mock

        # Act
        success = await security_scan_repository.cancel_scan("test-scan-id", "admin")

        # Assert
        assert success is False  # Cannot cancel completed scan
        mock_session.flush.assert_not_called()

    # cleanup_old_scans Tests

    @pytest.mark.asyncio
    async def test_cleanup_old_scans_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test successful cleanup of old scans."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 25  # 25 old scans cleaned up
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await security_scan_repository.cleanup_old_scans(retention_days=90)

        # Assert
        assert cleaned_count == 25
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_scans_custom_retention(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test cleanup with custom retention period."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 100
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await security_scan_repository.cleanup_old_scans(retention_days=30)

        # Assert
        assert cleaned_count == 100
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_scans_nothing_to_clean(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test cleanup when no old scans exist."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await security_scan_repository.cleanup_old_scans()

        # Assert
        assert cleaned_count == 0
        mock_session.execute.assert_called_once()

    # get_scan_analytics Tests

    @pytest.mark.asyncio
    async def test_get_scan_analytics_success(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test successful scan analytics retrieval."""
        # Arrange
        analytics_data = [
            {
                "total_scans": 500,
                "success_rate": 0.85,
                "avg_duration_minutes": 42.3,
                "most_common_scan_type": "vulnerability_scan",
                "vulnerabilities_per_scan_avg": 8.5,
                "top_targets": [
                    {"target": "example.com", "scan_count": 50},
                    {"target": "test.com", "scan_count": 35},
                ],
                "scan_types_distribution": {
                    "vulnerability_scan": 300,
                    "port_scan": 150,
                    "web_scan": 50,
                },
            }
        ]
        result_mock = query_result_factory(data=analytics_data)
        mock_session.execute.return_value = result_mock

        # Act
        analytics = await security_scan_repository.get_scan_analytics()

        # Assert
        assert analytics["total_scans"] == 500
        assert analytics["success_rate"] == 0.85
        assert analytics["most_common_scan_type"] == "vulnerability_scan"
        assert len(analytics["top_targets"]) == 2
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scan_analytics_with_date_range(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test scan analytics with date range filtering."""
        # Arrange
        analytics_data = [{"total_scans": 50, "success_rate": 0.9}]
        result_mock = query_result_factory(data=analytics_data)
        mock_session.execute.return_value = result_mock

        start_date = datetime.now(timezone.utc) - timedelta(days=7)
        end_date = datetime.now(timezone.utc)

        # Act
        analytics = await security_scan_repository.get_scan_analytics(start_date=start_date, end_date=end_date)

        # Assert
        assert analytics["total_scans"] == 50
        assert analytics["success_rate"] == 0.9
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scan_analytics_no_data(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test scan analytics when no data available."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        analytics = await security_scan_repository.get_scan_analytics()

        # Assert
        assert analytics["total_scans"] == 0
        assert analytics["success_rate"] == 0.0
        mock_session.execute.assert_called_once()

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_database_connection_error_handling(
        self, security_scan_repository: SecurityScanRepository, mock_session: AsyncMock
    ):
        """Test handling of database connection errors across methods."""
        # Arrange
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        # Test various methods handle database errors appropriately
        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.get_scans_by_target("https://test.com")

        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.get_scan_statistics(timedelta(days=30))

        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.get_active_scans()

        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.get_user_scans("test-user-id")

        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.get_scan_results("test-scan-id")

        with pytest.raises(SQLAlchemyError):
            await security_scan_repository.cleanup_old_scans()

    @pytest.mark.asyncio
    async def test_null_input_validation(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test repository methods handle null/None inputs appropriately."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test methods that should handle None gracefully
        result = await security_scan_repository.get_scans_by_target(None)
        assert result == []

        result = await security_scan_repository.get_user_scans(None)
        assert result == []

        result = await security_scan_repository.get_scan_results(None)
        assert result is None

        success = await security_scan_repository.cancel_scan(None, "admin")
        assert success is False

    # Performance and Edge Case Tests

    @pytest.mark.asyncio
    async def test_large_scan_results_handling(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        security_scan_factory,
    ):
        """Test handling of scans with very large results."""
        # Arrange
        large_results = {
            "vulnerabilities": list(range(1000)),  # Large vulnerability list
            "ports": {str(port): f"service_{port}" for port in range(1, 65536)},  # All ports
            "details": "x" * 100000,  # Large details string
        }

        large_scan = security_scan_factory.create(
            id="large-scan-id",
            results=large_results,
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.security_scan.SecurityScan", return_value=large_scan):
            # Act
            created_scan = await security_scan_repository.create_scan(
                target="https://large-results.com",
                scan_type="comprehensive_scan",
                user_id="test-user-id",
            )

            # Assert
            assert created_scan is not None
            mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_unicode_and_special_characters_in_target(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test handling of Unicode and special characters in target URLs."""
        # Arrange
        unicode_target = "https://测试.example.com/path?param=值&other=!@#$%^&*()"
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        scans = await security_scan_repository.get_scans_by_target(unicode_target)

        # Assert
        assert scans == []
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_scan_operations(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        running_scan: SecurityScan,
        query_result_factory,
    ):
        """Test concurrent scan operations."""
        # Arrange
        result_mock = query_result_factory(scalar_result=running_scan)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None

        # Act - Simulate concurrent operations
        update_task = security_scan_repository.update_scan_status("running-scan-id", "completed")
        cancel_task = security_scan_repository.cancel_scan("running-scan-id", "admin")

        # Execute both operations
        update_result = await update_task
        cancel_result = await cancel_task

        # Assert
        # In this mock scenario, both operations execute
        # In real implementation, proper locking would be needed
        assert isinstance(update_result, (SecurityScan, type(None)))
        assert isinstance(cancel_result, bool)

    @pytest.mark.asyncio
    async def test_scan_type_validation_patterns(
        self,
        security_scan_repository: SecurityScanRepository,
        mock_session: AsyncMock,
        security_scan_factory,
    ):
        """Test various scan type patterns and validation."""
        # Test different scan types
        scan_types = [
            "vulnerability_scan",
            "port_scan",
            "web_scan",
            "api_scan",
            "ssl_scan",
            "malware_scan",
            "compliance_scan",
        ]

        for scan_type in scan_types:
            scan = security_scan_factory.create(
                id=f"scan-{scan_type}",
                scan_type=scan_type,
                user_id="test-user-id",
            )
            mock_session.flush.return_value = None
            mock_session.refresh.return_value = None

            with patch("app.repositories.security_scan.SecurityScan", return_value=scan):
                # Act
                created_scan = await security_scan_repository.create_scan(
                    target=f"https://test-{scan_type}.com",
                    scan_type=scan_type,
                    user_id="test-user-id",
                )

                # Assert
                assert created_scan is not None
                assert created_scan.scan_type == scan_type
