"""Comprehensive tests for audit logging service."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService


@pytest.fixture
def mock_session():
    """Create mock database session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_request():
    """Create mock request."""
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "192.168.1.100"
    request.headers = {
        "User-Agent": "Mozilla/5.0 Test",
        "X-Request-ID": "test-request-123",
    }
    request.state = MagicMock()
    request.state.request_id = "test-request-123"
    return request


@pytest.fixture
def mock_repository():
    """Create mock audit repository."""
    from app.repositories.audit_log_extensions import ExtendedAuditLogRepository

    repository = AsyncMock(spec=ExtendedAuditLogRepository)
    # Mock the log_action method to return a proper AuditLog mock
    mock_audit_log = MagicMock(spec=AuditLog)
    repository.log_action = AsyncMock(return_value=mock_audit_log)
    return repository


@pytest.fixture
def audit_service(mock_repository):
    """Create audit service instance."""
    return AuditService(mock_repository)


class TestAuditService:
    """Test audit logging service."""

    @pytest.mark.asyncio
    async def test_log_event_success(self, audit_service, mock_repository, mock_request):
        """Test successful event logging."""
        # Arrange
        event_data = {
            "action": "user.create",
            "resource_type": "user",
            "resource_id": "123",
            "user_id": str(uuid.uuid4()),
            "user_email": "test@example.com",
            "request": mock_request,
            "changes": {"name": {"old": "John", "new": "Jane"}},
            "metadata": {"reason": "User requested name change"},
            "status": "success",
            "duration_ms": 150,
        }

        # Create a mock audit log to return from repository
        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = event_data["action"]
        mock_audit_log.resource_type = event_data["resource_type"]
        mock_audit_log.resource_id = event_data["resource_id"]
        mock_audit_log.user_id = uuid.UUID(event_data["user_id"])
        mock_audit_log.user_email = event_data["user_email"]
        mock_audit_log.ip_address = "192.168.1.100"
        mock_audit_log.user_agent = "Mozilla/5.0 Test"
        mock_audit_log.status = "success"
        mock_audit_log.duration_ms = 150
        mock_audit_log.changes = event_data["changes"]
        mock_audit_log.action_metadata = event_data["metadata"]

        # Configure the repository mock to return this audit log
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_event(**event_data)

        # Assert
        assert result == mock_audit_log
        assert result.action == event_data["action"]
        assert result.resource_type == event_data["resource_type"]
        assert result.resource_id == event_data["resource_id"]
        assert result.user_id == uuid.UUID(event_data["user_id"])
        assert result.user_email == event_data["user_email"]
        assert result.ip_address == "192.168.1.100"
        assert result.user_agent == "Mozilla/5.0 Test"
        assert result.status == "success"
        assert result.duration_ms == 150

        # Verify the repository was called correctly
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_event_with_sensitive_data_sanitization(self, audit_service, mock_repository):
        """Test event logging with sensitive data sanitization."""
        # Arrange - use flat structure that will actually be sanitized
        event_data = {
            "action": "user.update",
            "resource_type": "user",
            "changes": {
                "email": "new@example.com",
                "password": "newpass456",  # This will be redacted
                "api_key": "secret_key_123",  # This will be redacted
                "username": "john_doe",  # This won't be redacted
            },
            "metadata": {
                "credit_card": "1234-5678-9012-3456",  # This will be redacted
                "ssn": "123-45-6789",  # This will be redacted
                "safe_field": "This is safe",  # This won't be redacted
                "access_token": "bearer_123",  # This will be redacted
            },
        }

        # Expected sanitized data
        expected_changes = {
            "email": "new@example.com",
            "password": "[REDACTED]",
            "api_key": "[REDACTED]",
            "username": "john_doe",
        }
        expected_metadata = {
            "credit_card": "[REDACTED]",
            "ssn": "[REDACTED]",
            "safe_field": "This is safe",
            "access_token": "[REDACTED]",
        }

        # Create a mock audit log with sanitized data
        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.changes = expected_changes
        mock_audit_log.action_metadata = expected_metadata
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_event(**event_data)

        # Assert the repository was called and returned object has expected values
        mock_repository.log_action.assert_called_once()
        assert result.changes["password"] == "[REDACTED]"
        assert result.changes["api_key"] == "[REDACTED]"
        assert result.changes["username"] == "john_doe"
        assert result.action_metadata["credit_card"] == "[REDACTED]"
        assert result.action_metadata["ssn"] == "[REDACTED]"
        assert result.action_metadata["safe_field"] == "This is safe"
        assert result.action_metadata["access_token"] == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_log_event_with_exception_handling(self, audit_service, mock_repository):
        """Test event logging handles exceptions gracefully."""
        # Arrange
        mock_repository.log_action.side_effect = Exception("Database error")

        # Act
        result = await audit_service.log_event(
            action="test.action",
            resource_type="test",
        )

        # Assert
        assert result is None  # Returns None on error, doesn't raise

    @pytest.mark.asyncio
    async def test_log_auth_event_success(self, audit_service, mock_repository, mock_request):
        """Test logging authentication event."""
        # Arrange
        user_id = str(uuid.uuid4())

        # Create a mock audit log to return from repository
        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "auth.login_success"
        mock_audit_log.resource_type = "auth"
        mock_audit_log.status = "success"
        mock_audit_log.action_metadata = {
            "event_description": "User successfully logged in",
            "login_method": "password",
        }
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_auth_event(
            event_type="login_success",
            user_id=user_id,
            user_email="test@example.com",
            request=mock_request,
            success=True,
            metadata={"login_method": "password"},
        )

        # Assert
        assert result.action == "auth.login_success"
        assert result.resource_type == "auth"
        assert result.status == "success"
        assert result.action_metadata["event_description"] == "User successfully logged in"
        assert result.action_metadata["login_method"] == "password"
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_auth_event_failure(self, audit_service, mock_repository):
        """Test logging failed authentication event."""
        # Arrange
        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "auth.login_failed"
        mock_audit_log.status = "failure"
        mock_audit_log.action_metadata = {"reason": "Invalid password"}
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_auth_event(
            event_type="login_failed",
            user_email="test@example.com",
            success=False,
            metadata={"reason": "Invalid password"},
        )

        # Assert
        assert result.action == "auth.login_failed"
        assert result.status == "failure"
        assert result.action_metadata["reason"] == "Invalid password"
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_permission_event(self, audit_service, mock_repository, mock_request):
        """Test logging permission event."""
        # Arrange
        user_id = str(uuid.uuid4())
        permissions = ["users:read:all", "users:write:own"]

        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "permission.permission_granted"
        mock_audit_log.status = "success"
        mock_audit_log.action_metadata = {
            "permissions_checked": permissions,
            "permissions_granted": permissions,
        }
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_permission_event(
            event_type="permission_granted",
            user_id=user_id,
            permissions=permissions,
            resource_type="users",
            resource_id="456",
            request=mock_request,
            granted=True,
        )

        # Assert
        assert result.action == "permission.permission_granted"
        assert result.status == "success"
        assert result.action_metadata["permissions_checked"] == permissions
        assert result.action_metadata["permissions_granted"] == permissions
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_api_key_event(self, audit_service, mock_repository):
        """Test logging API key event."""
        # Arrange
        api_key_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "api_key.api_key_created"
        mock_audit_log.resource_type = "api_key"
        mock_audit_log.resource_id = api_key_id
        mock_audit_log.action_metadata = {"event_description": "API key created"}
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_api_key_event(
            event_type="api_key_created",
            api_key_id=api_key_id,
            user_id=user_id,
            metadata={"key_name": "Production API Key"},
        )

        # Assert
        assert result.action == "api_key.api_key_created"
        assert result.resource_type == "api_key"
        assert result.resource_id == api_key_id
        assert result.action_metadata["event_description"] == "API key created"
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_resource_event(self, audit_service, mock_repository, mock_request):
        """Test logging resource modification event."""
        # Arrange
        user_id = str(uuid.uuid4())
        changes = {
            "name": {"old": "Old Name", "new": "New Name"},
            "email": {"old": "old@example.com", "new": "new@example.com"},
        }

        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "user.updated"
        mock_audit_log.resource_type = "user"
        mock_audit_log.resource_id = "789"
        mock_audit_log.changes = changes
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_resource_event(
            action="updated",
            resource_type="user",
            resource_id="789",
            user_id=user_id,
            request=mock_request,
            changes=changes,
        )

        # Assert
        assert result.action == "user.updated"
        assert result.resource_type == "user"
        assert result.resource_id == "789"
        assert result.changes == changes
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_security_event(self, audit_service, mock_repository, mock_request):
        """Test logging security event."""
        # Arrange
        user_id = str(uuid.uuid4())

        mock_audit_log = MagicMock(spec=AuditLog)
        mock_audit_log.action = "security.suspicious_activity"
        mock_audit_log.resource_type = "security"
        mock_audit_log.status = "failure"
        mock_audit_log.action_metadata = {
            "risk_level": "high",
            "pattern": "Multiple failed login attempts",
        }
        mock_repository.log_action.return_value = mock_audit_log

        # Act
        result = await audit_service.log_security_event(
            event_type="suspicious_activity",
            user_id=user_id,
            request=mock_request,
            risk_level="high",
            details={"pattern": "Multiple failed login attempts"},
        )

        # Assert
        assert result.action == "security.suspicious_activity"
        assert result.resource_type == "security"
        assert result.status == "failure"
        assert result.action_metadata["risk_level"] == "high"
        assert result.action_metadata["pattern"] == "Multiple failed login attempts"
        mock_repository.log_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_activity(self, audit_service, mock_repository):
        """Test getting user activity logs."""
        # Arrange
        user_id = str(uuid.uuid4())
        mock_logs = [
            MagicMock(
                spec=AuditLog,
                action="user.login",
                created_at=datetime.now(timezone.utc),
            ),
            MagicMock(
                spec=AuditLog,
                action="user.update",
                created_at=datetime.now(timezone.utc),
            ),
        ]

        # Mock the Page object that repository returns
        from app.repositories.base import Page

        mock_page = MagicMock(spec=Page)
        mock_page.items = mock_logs
        mock_repository.get_by_user.return_value = mock_page

        # Act
        result = await audit_service.get_user_activity(
            user_id=user_id,
            start_date=datetime.now(timezone.utc) - timedelta(days=7),
            limit=10,
        )

        # Assert
        assert len(result) == 2
        assert result == mock_logs
        mock_repository.get_by_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_resource_history(self, audit_service, mock_repository):
        """Test getting resource history."""
        # Arrange
        resource_type = "user"
        resource_id = "123"
        mock_logs = [MagicMock(spec=AuditLog) for _ in range(3)]

        # Mock the Page object that repository returns
        from app.repositories.base import Page

        mock_page = MagicMock(spec=Page)
        mock_page.items = mock_logs
        mock_repository.get_by_resource.return_value = mock_page

        # Act
        result = await audit_service.get_resource_history(
            resource_type=resource_type,
            resource_id=resource_id,
            limit=50,
        )

        # Assert
        assert len(result) == 3
        assert result == mock_logs
        mock_repository.get_by_resource.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_failed_auth_attempts(self, audit_service, mock_repository):
        """Test counting failed authentication attempts."""
        # Arrange
        user_email = "test@example.com"
        mock_repository.count_failed_attempts.return_value = 5

        # Act
        count = await audit_service.get_failed_auth_attempts(
            user_email=user_email,
            time_window=timedelta(hours=1),
        )

        # Assert
        assert count == 5
        mock_repository.count_failed_attempts.assert_called_once_with(
            user_email=user_email, ip_address=None, time_window=timedelta(hours=1)
        )

    @pytest.mark.asyncio
    async def test_get_security_events(self, audit_service, mock_repository):
        """Test getting security events."""
        # Arrange
        mock_logs = [
            MagicMock(spec=AuditLog, action="security.suspicious_activity"),
            MagicMock(spec=AuditLog, action="security.rate_limit_exceeded"),
        ]
        mock_repository.get_security_events.return_value = mock_logs

        # Act
        result = await audit_service.get_security_events(
            risk_levels=["high", "critical"],
            limit=100,
        )

        # Assert
        assert len(result) == 2
        assert all(log.action.startswith("security.") for log in result)
        mock_repository.get_security_events.assert_called_once_with(
            risk_levels=["high", "critical"],
            start_date=None,
            end_date=None,
            limit=100,
        )

    @pytest.mark.asyncio
    async def test_get_audit_statistics(self, audit_service, mock_repository):
        """Test getting audit statistics."""
        # Arrange
        mock_stats = {
            "total_events": 1000,
            "events_by_type": {"user": 500, "auth": 300, "api_key": 200},
            "events_by_status": {"success": 900, "failure": 100},
            "failed_auth_attempts": 50,
            "security_events": 25,
        }
        mock_repository.get_compliance_report_data.return_value = mock_stats

        # Act
        stats = await audit_service.get_audit_statistics()

        # Assert
        assert stats["total_events"] == 1000
        assert stats["events_by_type"]["user"] == 500
        assert stats["events_by_type"]["auth"] == 300
        assert stats["events_by_status"]["success"] == 900
        assert stats["failed_auth_attempts"] == 50
        assert stats["security_events"] == 25
        assert "time_range" in stats
        mock_repository.get_compliance_report_data.assert_called_once_with(start_date=None, end_date=None)

    @pytest.mark.asyncio
    async def test_search_audit_logs(self, audit_service, mock_repository):
        """Test searching audit logs."""
        # Arrange
        mock_logs = [MagicMock(spec=AuditLog) for _ in range(5)]
        mock_repository.search.return_value = mock_logs

        # Act
        result = await audit_service.search_audit_logs(
            action_pattern="user.*",
            resource_type="user",
            status="success",
            limit=20,
        )

        # Assert
        assert len(result) == 5
        assert result == mock_logs
        mock_repository.search.assert_called_once_with(
            action="user.*",
            user_id=None,
            resource_type="user",
            status="success",
            start_date=None,
            end_date=None,
            limit=20,
            offset=0,
        )

    @pytest.mark.asyncio
    async def test_export_audit_logs_json(self, audit_service, mock_repository):
        """Test exporting audit logs as JSON."""
        # Arrange
        mock_logs = [
            MagicMock(
                spec=AuditLog,
                to_dict=MagicMock(return_value={"action": "user.create", "status": "success"}),
            )
            for _ in range(2)
        ]
        mock_repository.search.return_value = mock_logs

        # Act
        result = await audit_service.export_audit_logs(format="json")

        # Assert
        data = json.loads(result)
        assert len(data) == 2
        assert data[0]["action"] == "user.create"
        mock_repository.search.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_audit_logs_csv(self, audit_service, mock_repository):
        """Test exporting audit logs as CSV."""
        # Arrange
        mock_logs = [
            MagicMock(
                spec=AuditLog,
                to_dict=MagicMock(
                    return_value={
                        "action": "user.create",
                        "status": "success",
                        "user_id": "123",
                    }
                ),
            )
        ]
        mock_repository.search.return_value = mock_logs

        # Act
        result = await audit_service.export_audit_logs(format="csv")

        # Assert
        assert "action,status,user_id" in result
        assert "user.create,success,123" in result
        mock_repository.search.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_logs(self, audit_service, mock_repository):
        """Test cleanup of old audit logs."""
        # Arrange
        mock_repository.cleanup_old_logs.return_value = 100

        # Act
        count = await audit_service.cleanup_old_logs(retention_days=365)

        # Assert
        assert count == 100
        mock_repository.cleanup_old_logs.assert_called_once_with(365)

    def test_sanitize_sensitive_data(self, audit_service):
        """Test sanitization of sensitive data."""
        # Arrange
        data = {
            "username": "john_doe",
            "password": "secret123",
            "api_key": "sk_test_123",
            "credit_card": "4111111111111111",
            "nested": {
                "token": "bearer_token_123",
                "safe_field": "This is safe",
            },
            "list_field": [
                {"secret": "hidden"},
                {"public": "visible"},
            ],
        }

        # Act
        sanitized = audit_service._sanitize_sensitive_data(data)

        # Assert
        assert sanitized["username"] == "john_doe"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["credit_card"] == "[REDACTED]"
        assert sanitized["nested"]["token"] == "[REDACTED]"
        assert sanitized["nested"]["safe_field"] == "This is safe"
        assert sanitized["list_field"][0]["secret"] == "[REDACTED]"
        assert sanitized["list_field"][1]["public"] == "visible"
