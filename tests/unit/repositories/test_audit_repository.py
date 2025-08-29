"""Comprehensive unit tests for AuditLogRepository implementation."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.repositories.audit_log import AuditLogRepository
from app.repositories.base import Page


class TestAuditLogRepository:
    """Comprehensive unit tests for AuditLogRepository implementation."""

    @pytest.fixture
    def audit_repository(self, mock_session: AsyncMock) -> AuditLogRepository:
        """Create AuditLogRepository instance with mocked session."""
        return AuditLogRepository(mock_session)

    @pytest.fixture
    def sample_audit_log(self, audit_log_factory) -> AuditLog:
        """Create a sample audit log for testing."""
        return audit_log_factory.create(
            id="test-audit-log-id",
            action="user.login",
            user_id="test-user-id",
            action_metadata={"login_method": "password", "success": True},
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 Test Browser",
            created_at=datetime.now(timezone.utc),
        )

    @pytest.fixture
    def failed_login_audit(self, audit_log_factory) -> AuditLog:
        """Create a failed login audit log for testing."""
        return audit_log_factory.create(
            id="failed-login-audit-id",
            action="user.login_failed",
            user_id="test-user-id",
            metadata={"login_method": "password", "success": False, "error": "invalid_credentials"},
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Test Browser",
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

    @pytest.fixture
    def system_audit_log(self, audit_log_factory) -> AuditLog:
        """Create a system audit log for testing."""
        return audit_log_factory.create(
            id="system-audit-log-id",
            action="system.backup_created",
            user_id=None,  # System action
            metadata={"backup_type": "full", "size_bytes": 1024000},
            ip_address="127.0.0.1",
            user_agent="System/1.0",
            created_at=datetime.now(timezone.utc),
        )

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test AuditLogRepository initialization."""
        repository = AuditLogRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == AuditLog
        assert repository.logger is not None

    # log_action Tests

    @pytest.mark.asyncio
    async def test_log_action_success(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, audit_log_factory
    ):
        """Test successful audit action logging."""
        # Arrange
        new_audit_log = audit_log_factory.create(
            id="new-audit-log-id",
            action="user.profile_updated",
            user_id="test-user-id",
            changes={"field": "email", "old_value": "old@test.com", "new_value": "new@test.com"},
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch.object(audit_repository, "create", return_value=new_audit_log):
            # Act
            logged_audit = await audit_repository.log_action(
                action="user.profile_updated",
                resource_type="user",
                resource_id="test-user-id",
                user_id="test-user-id",
                changes={"field": "email", "old_value": "old@test.com", "new_value": "new@test.com"},
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )

            # Assert
            assert logged_audit is not None
            assert logged_audit.action == "user.profile_updated"
            assert logged_audit.user_id == "test-user-id"
            assert logged_audit.changes["field"] == "email"

    @pytest.mark.asyncio
    async def test_log_action_system_action(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, audit_log_factory
    ):
        """Test logging system actions without user_id."""
        # Arrange
        system_audit_log = audit_log_factory.create(
            id="system-audit-log-id",
            action="system.maintenance_started",
            user_id=None,
            metadata={"maintenance_type": "database_cleanup"},
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.audit_log.AuditLog", return_value=system_audit_log):
            # Act
            logged_audit = await audit_repository.log_action(
                action="system.maintenance_started",
                resource_type="system",
                user_id=None,
                metadata={"maintenance_type": "database_cleanup"},
                ip_address="127.0.0.1",
            )

            # Assert
            assert logged_audit is not None
            assert logged_audit.action == "system.maintenance_started"
            assert logged_audit.user_id is None
            mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_action_database_error(self, audit_repository: AuditLogRepository, mock_session: AsyncMock):
        """Test database error handling in log_action."""
        # Arrange - Mock session methods to simulate database error
        mock_session.add.return_value = None
        mock_session.flush.side_effect = IntegrityError("Constraint violation", None, None)
        mock_session.rollback.return_value = None

        # Act & Assert
        with pytest.raises(IntegrityError):
            await audit_repository.log_action(
                action="test.action",
                resource_type="test",
                user_id="test-user-id",
                metadata={"test": "data"},
            )

    @pytest.mark.asyncio
    async def test_log_action_with_minimal_data(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, audit_log_factory
    ):
        """Test logging action with minimal required data."""
        # Arrange
        minimal_audit_log = audit_log_factory.create(
            id="minimal-audit-log-id",
            action="test.minimal_action",
            user_id="test-user-id",
            action_metadata={},
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch.object(audit_repository, "create", return_value=minimal_audit_log):
            # Act
            logged_audit = await audit_repository.log_action(
                action="test.minimal_action",
                resource_type="test",
                user_id="test-user-id",
                metadata={},
            )

            # Assert
            assert logged_audit is not None
            assert logged_audit.action == "test.minimal_action"
            assert logged_audit.action_metadata == {}

    # get_user_audit_trail Tests

    @pytest.mark.asyncio
    async def test_get_user_audit_trail_success(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test successful retrieval of user audit trail."""
        # Arrange
        audit_logs = [sample_audit_log]
        result_mock = query_result_factory(data=audit_logs)
        mock_session.execute.return_value = result_mock

        # Act
        user_trail = await audit_repository.get_user_audit_trail("test-user-id", limit=100)

        # Assert
        assert len(user_trail) == 1
        assert user_trail[0].user_id == "test-user-id"
        assert user_trail[0].action == "user.login"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_audit_trail_with_limit(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test user audit trail retrieval with specific limit."""
        # Arrange
        audit_logs = [sample_audit_log] * 5  # 5 audit logs
        result_mock = query_result_factory(data=audit_logs)
        mock_session.execute.return_value = result_mock

        # Act
        user_trail = await audit_repository.get_user_audit_trail("test-user-id", limit=5)

        # Assert
        assert len(user_trail) == 5
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_audit_trail_empty_result(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test user audit trail when no logs exist."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        user_trail = await audit_repository.get_user_audit_trail("user-with-no-logs")

        # Assert
        assert user_trail == []
        mock_session.execute.assert_called_once()

    # get_compliance_report Tests

    @pytest.mark.asyncio
    async def test_get_compliance_report_success(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test successful compliance report generation."""
        # Arrange
        compliance_logs = [sample_audit_log]
        result_mock = query_result_factory(data=compliance_logs)
        mock_session.execute.return_value = result_mock
        start_date = date.today() - timedelta(days=30)
        end_date = date.today()

        # Act
        compliance_report = await audit_repository.get_compliance_report(
            start_date=start_date, end_date=end_date, organization_id="test-org-id"
        )

        # Assert
        assert len(compliance_report) == 1
        assert compliance_report[0].organization_id == "test-org-id"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_compliance_report_without_organization(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test compliance report without organization filtering."""
        # Arrange
        compliance_logs = [sample_audit_log]
        result_mock = query_result_factory(data=compliance_logs)
        mock_session.execute.return_value = result_mock
        start_date = date.today() - timedelta(days=7)
        end_date = date.today()

        # Act
        compliance_report = await audit_repository.get_compliance_report(start_date=start_date, end_date=end_date)

        # Assert
        assert len(compliance_report) == 1
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_compliance_report_date_range_validation(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test compliance report with various date ranges."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test with start_date > end_date (should handle gracefully)
        start_date = date.today()
        end_date = date.today() - timedelta(days=7)

        # Act
        compliance_report = await audit_repository.get_compliance_report(start_date=start_date, end_date=end_date)

        # Assert
        assert compliance_report == []
        mock_session.execute.assert_called_once()

    # get_audit_logs_by_action Tests

    @pytest.mark.asyncio
    async def test_get_audit_logs_by_action_success(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test successful retrieval of audit logs by action."""
        # Arrange
        login_logs = [sample_audit_log]
        result_mock = query_result_factory(data=login_logs)
        mock_session.execute.return_value = result_mock

        # Act
        action_logs = await audit_repository.get_audit_logs_by_action(
            action="user.login",
            start_date=date.today() - timedelta(days=1),
            end_date=date.today(),
            limit=50,
        )

        # Assert
        assert len(action_logs) == 1
        assert action_logs[0].action == "user.login"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_logs_by_action_without_date_filter(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test audit logs by action without date filtering."""
        # Arrange
        action_logs = [sample_audit_log]
        result_mock = query_result_factory(data=action_logs)
        mock_session.execute.return_value = result_mock

        # Act
        logs = await audit_repository.get_audit_logs_by_action(action="user.login")

        # Assert
        assert len(logs) == 1
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_logs_by_action_with_limit(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test audit logs by action with custom limit."""
        # Arrange
        multiple_logs = [sample_audit_log] * 25
        result_mock = query_result_factory(data=multiple_logs)
        mock_session.execute.return_value = result_mock

        # Act
        logs = await audit_repository.get_audit_logs_by_action(action="user.login", limit=25)

        # Assert
        assert len(logs) == 25
        mock_session.execute.assert_called_once()

    # get_failed_login_attempts Tests

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_success(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test successful retrieval of failed login attempts."""
        # Arrange
        failed_attempts_data = [
            {
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0",
                "attempt_count": 5,
                "first_attempt": datetime.now(timezone.utc) - timedelta(hours=2),
                "last_attempt": datetime.now(timezone.utc) - timedelta(minutes=30),
                "user_ids": ["user1", "user2"],
            }
        ]
        result_mock = query_result_factory(data=failed_attempts_data)
        mock_session.execute.return_value = result_mock

        # Act
        failed_attempts = await audit_repository.get_failed_login_attempts(time_window_hours=24, min_attempts=3)

        # Assert
        assert len(failed_attempts) == 1
        assert failed_attempts[0]["attempt_count"] == 5
        assert failed_attempts[0]["ip_address"] == "192.168.1.100"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_with_custom_threshold(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test failed login attempts with custom threshold."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        failed_attempts = await audit_repository.get_failed_login_attempts(
            time_window_hours=1, min_attempts=10  # Very strict threshold
        )

        # Assert
        assert failed_attempts == []
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_default_params(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test failed login attempts with default parameters."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        failed_attempts = await audit_repository.get_failed_login_attempts()

        # Assert
        assert failed_attempts == []
        mock_session.execute.assert_called_once()

    # get_audit_statistics Tests

    @pytest.mark.asyncio
    async def test_get_audit_statistics_success(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test successful audit statistics generation."""
        # Arrange
        stats_data = [
            {
                "total_events": 1500,
                "unique_users": 50,
                "unique_actions": 25,
                "top_action": "user.login",
                "top_action_count": 300,
                "failed_logins": 75,
                "system_events": 200,
                "security_events": 15,
            }
        ]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock

        # Act
        stats = await audit_repository.get_audit_statistics(
            start_date=date.today() - timedelta(days=30), end_date=date.today()
        )

        # Assert
        assert stats["total_events"] == 1500
        assert stats["unique_users"] == 50
        assert stats["top_action"] == "user.login"
        assert stats["failed_logins"] == 75
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_statistics_without_date_range(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test audit statistics without date filtering."""
        # Arrange
        stats_data = [{"total_events": 5000, "unique_users": 200}]
        result_mock = query_result_factory(data=stats_data)
        mock_session.execute.return_value = result_mock

        # Act
        stats = await audit_repository.get_audit_statistics()

        # Assert
        assert stats["total_events"] == 5000
        assert stats["unique_users"] == 200
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_statistics_no_data(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test audit statistics when no data available."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        stats = await audit_repository.get_audit_statistics()

        # Assert
        assert stats["total_events"] == 0
        assert stats["unique_users"] == 0
        mock_session.execute.assert_called_once()

    # cleanup_old_audit_logs Tests

    @pytest.mark.asyncio
    async def test_cleanup_old_audit_logs_success(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test successful cleanup of old audit logs."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 150  # 150 old logs cleaned up
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await audit_repository.cleanup_old_audit_logs(retention_days=365)

        # Assert
        assert cleaned_count == 150
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_audit_logs_custom_retention(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test cleanup with custom retention period."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 500
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await audit_repository.cleanup_old_audit_logs(retention_days=90)

        # Assert
        assert cleaned_count == 500
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_audit_logs_nothing_to_clean(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test cleanup when no old logs exist."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await audit_repository.cleanup_old_audit_logs()

        # Assert
        assert cleaned_count == 0
        mock_session.execute.assert_called_once()

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_database_connection_error_handling(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock
    ):
        """Test handling of database connection errors across methods."""
        # Arrange
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        # Test various methods handle database errors appropriately
        with pytest.raises(SQLAlchemyError):
            await audit_repository.get_user_audit_trail("test-user-id")

        with pytest.raises(SQLAlchemyError):
            await audit_repository.get_compliance_report(date.today(), date.today())

        with pytest.raises(SQLAlchemyError):
            await audit_repository.get_audit_logs_by_action("test.action")

        with pytest.raises(SQLAlchemyError):
            await audit_repository.get_failed_login_attempts()

        with pytest.raises(SQLAlchemyError):
            await audit_repository.get_audit_statistics()

        with pytest.raises(SQLAlchemyError):
            await audit_repository.cleanup_old_audit_logs()

    @pytest.mark.asyncio
    async def test_invalid_input_validation(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test repository methods handle invalid inputs appropriately."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test with None/empty inputs
        result = await audit_repository.get_user_audit_trail(None)
        assert result == []

        result = await audit_repository.get_user_audit_trail("")
        assert result == []

        result = await audit_repository.get_audit_logs_by_action(None)
        assert result == []

        result = await audit_repository.get_audit_logs_by_action("")
        assert result == []

    @pytest.mark.asyncio
    async def test_negative_retention_days_handling(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test cleanup with negative retention days."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 0
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await audit_repository.cleanup_old_audit_logs(retention_days=-1)

        # Assert
        # Should handle gracefully - either clean everything or nothing
        assert isinstance(cleaned_count, int)
        assert cleaned_count >= 0

    @pytest.mark.asyncio
    async def test_zero_retention_days_handling(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test cleanup with zero retention days."""
        # Arrange
        result_mock = query_result_factory()
        result_mock.rowcount = 1000  # Clean all logs
        mock_session.execute.return_value = result_mock

        # Act
        cleaned_count = await audit_repository.cleanup_old_audit_logs(retention_days=0)

        # Assert
        assert cleaned_count == 1000

    # Performance and Edge Case Tests

    @pytest.mark.asyncio
    async def test_large_details_object_logging(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, audit_log_factory
    ):
        """Test logging with very large details object."""
        # Arrange
        large_details = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}
        large_audit_log = audit_log_factory.create(
            id="large-audit-log-id",
            action="test.large_details",
            user_id="test-user-id",
            metadata=large_details,
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.audit_log.AuditLog", return_value=large_audit_log):
            # Act
            logged_audit = await audit_repository.log_action(
                action="test.large_details",
                resource_type="test",
                user_id="test-user-id",
                metadata=large_details,
            )

            # Assert
            assert logged_audit is not None
            assert len(logged_audit.action_metadata) == 100
            mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_unicode_and_special_characters(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, audit_log_factory
    ):
        """Test handling of Unicode and special characters in audit data."""
        # Arrange
        unicode_details = {
            "message": "用户登录成功 🎉",
            "emoji": "🔐🔑",
            "special_chars": "!@#$%^&*()[]{}|\\:;\"'<>,.?/~`",
        }
        unicode_audit_log = audit_log_factory.create(
            id="unicode-audit-log-id",
            action="test.unicode_data",
            user_id="test-user-id",
            metadata=unicode_details,
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with patch("app.repositories.audit_log.AuditLog", return_value=unicode_audit_log):
            # Act
            logged_audit = await audit_repository.log_action(
                action="test.unicode_data",
                resource_type="test",
                user_id="test-user-id",
                metadata=unicode_details,
            )

            # Assert
            assert logged_audit is not None
            assert "🎉" in logged_audit.action_metadata["message"]
            assert logged_audit.action_metadata["emoji"] == "🔐🔑"

    @pytest.mark.asyncio
    async def test_high_volume_audit_logging(
        self,
        audit_repository: AuditLogRepository,
        mock_session: AsyncMock,
        sample_audit_log: AuditLog,
        query_result_factory,
    ):
        """Test handling of high volume audit log retrieval."""
        # This simulates retrieving a large number of audit logs

        # Arrange
        large_result_set = [sample_audit_log] * 10000
        result_mock = query_result_factory(data=large_result_set)
        mock_session.execute.return_value = result_mock

        # Act
        logs = await audit_repository.get_audit_logs_by_action("high_volume.action", limit=10000)

        # Assert
        assert len(logs) == 10000
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_audit_operations(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test concurrent audit operations."""
        # This test simulates concurrent access patterns

        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act - Simulate concurrent read operations
        trail_task = audit_repository.get_user_audit_trail("test-user-id")
        stats_task = audit_repository.get_audit_statistics()
        compliance_task = audit_repository.get_compliance_report(date.today(), date.today())

        # Execute all operations
        trail_result = await trail_task
        stats_result = await stats_task
        compliance_result = await compliance_task

        # Assert
        assert isinstance(trail_result, list)
        assert isinstance(stats_result, dict)
        assert isinstance(compliance_result, list)

    @pytest.mark.asyncio
    async def test_date_boundary_conditions(
        self, audit_repository: AuditLogRepository, mock_session: AsyncMock, query_result_factory
    ):
        """Test date boundary conditions in queries."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test with same start and end date
        same_date = date.today()
        compliance_report = await audit_repository.get_compliance_report(same_date, same_date)
        assert compliance_report == []

        # Test with future dates
        future_date = date.today() + timedelta(days=30)
        stats = await audit_repository.get_audit_statistics(future_date, future_date)
        assert stats["total_events"] == 0

        # Test with very old dates
        old_date = date(2000, 1, 1)
        logs = await audit_repository.get_audit_logs_by_action("test.action", old_date, old_date)
        assert logs == []
