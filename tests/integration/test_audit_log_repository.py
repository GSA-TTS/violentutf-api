"""Integration tests for AuditLogRepository with real database operations."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.audit_log import AuditLogRepository
from app.repositories.user import UserRepository


class TestAuditLogRepository:
    """Test AuditLogRepository specific functionality."""

    @pytest_asyncio.fixture
    async def audit_repo(self, async_db_session: AsyncSession) -> AuditLogRepository:
        """Create an audit log repository."""
        return AuditLogRepository(async_db_session)

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> UserRepository:
        """Create a user repository."""
        return UserRepository(async_db_session)

    @pytest_asyncio.fixture
    async def test_user(self, user_repo: UserRepository, async_db_session: AsyncSession) -> User:
        """Create a test user."""
        user = await user_repo.create_user(username="audit_test_user", email="audit@example.com", password="password")
        await async_db_session.commit()
        return user

    @pytest.mark.asyncio
    async def test_log_action_basic(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test basic action logging."""
        audit_log = await audit_repo.log_action(
            action="user.login",
            resource_type="user",
            resource_id="12345",
            status="success",
        )
        await async_db_session.commit()

        assert audit_log.action == "user.login"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id == "12345"
        assert audit_log.status == "success"
        assert audit_log.created_by == "system"

    @pytest.mark.asyncio
    async def test_log_action_with_user(
        self,
        audit_repo: AuditLogRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test action logging with user information."""
        audit_log = await audit_repo.log_action(
            action="api_key.create",
            resource_type="api_key",
            resource_id="key123",
            user_id=test_user.id,
            user_email=test_user.email,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            status="success",
        )
        await async_db_session.commit()

        assert audit_log.user_id == test_user.id
        assert audit_log.user_email == test_user.email
        assert audit_log.ip_address == "192.168.1.100"
        assert audit_log.user_agent == "Mozilla/5.0"
        assert audit_log.created_by == test_user.id

    @pytest.mark.asyncio
    async def test_log_action_with_changes(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test action logging with change tracking."""
        changes = {
            "before": {"name": "Old Name", "email": "old@example.com"},
            "after": {"name": "New Name", "email": "new@example.com"},
        }

        audit_log = await audit_repo.log_action(
            action="user.update",
            resource_type="user",
            resource_id="user123",
            changes=changes,
            status="success",
        )
        await async_db_session.commit()

        # Changes should be stored as JSON string
        assert audit_log.changes is not None
        stored_changes = json.loads(audit_log.changes)
        assert stored_changes == changes

    @pytest.mark.asyncio
    async def test_log_action_with_metadata(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test action logging with metadata."""
        metadata = {"request_id": "req123", "api_version": "v2", "client_app": "mobile"}

        audit_log = await audit_repo.log_action(
            action="api.request",
            resource_type="endpoint",
            resource_id="/api/users",
            metadata=metadata,
            status="success",
        )
        await async_db_session.commit()

        # Metadata should be stored as JSON string
        assert audit_log.action_metadata is not None
        stored_metadata = json.loads(audit_log.action_metadata)
        assert stored_metadata == metadata

    @pytest.mark.asyncio
    async def test_log_action_with_error(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test action logging with error information."""
        audit_log = await audit_repo.log_action(
            action="user.delete",
            resource_type="user",
            resource_id="user456",
            status="error",
            error_message="User not found",
            duration_ms=150,
        )
        await async_db_session.commit()

        assert audit_log.status == "error"
        assert audit_log.error_message == "User not found"
        assert audit_log.duration_ms == 150

    @pytest.mark.asyncio
    async def test_log_action_with_uuid_user_id(
        self,
        audit_repo: AuditLogRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test action logging with UUID object as user_id."""
        user_uuid = uuid.UUID(test_user.id)

        audit_log = await audit_repo.log_action(
            action="test.uuid",
            resource_type="test",
            user_id=user_uuid,
            status="success",  # Pass UUID object
        )
        await async_db_session.commit()

        assert audit_log.user_id == test_user.id

    @pytest.mark.asyncio
    async def test_get_by_resource(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test getting audit logs by resource."""
        resource_type = "api_key"
        resource_id = "key789"

        # Create multiple audit logs for the resource
        for i in range(3):
            await audit_repo.log_action(
                action=f"api_key.action{i}",
                resource_type=resource_type,
                resource_id=resource_id,
                status="success",
            )

        # Create logs for different resource
        await audit_repo.log_action(
            action="user.login",
            resource_type="user",
            resource_id="user123",
            status="success",
        )
        await async_db_session.commit()

        # Get logs for specific resource
        page = await audit_repo.get_by_resource(resource_type, resource_id)

        assert len(page.items) == 3
        assert all(log.resource_type == resource_type for log in page.items)
        assert all(log.resource_id == resource_id for log in page.items)
        # Should be ordered by created_at desc
        if len(page.items) > 1:
            assert page.items[0].created_at >= page.items[1].created_at

    @pytest.mark.asyncio
    async def test_get_by_resource_pagination(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test pagination when getting by resource."""
        resource_type = "test"
        resource_id = "test123"

        # Create multiple logs
        for i in range(5):
            await audit_repo.log_action(
                action=f"test.action{i}",
                resource_type=resource_type,
                resource_id=resource_id,
                status="success",
            )
        await async_db_session.commit()

        # Get first page
        page = await audit_repo.get_by_resource(resource_type, resource_id, page=1, size=2)
        assert len(page.items) == 2
        assert page.has_next is True
        assert page.has_prev is False

    @pytest.mark.asyncio
    async def test_get_by_user(
        self,
        audit_repo: AuditLogRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting audit logs by user."""
        # Create logs for user
        for i in range(3):
            await audit_repo.log_action(
                action=f"user.action{i}",
                resource_type="test",
                user_id=test_user.id,
                status="success",
            )

        # Create logs for different user
        await audit_repo.log_action(
            action="other.action",
            resource_type="test",
            user_id=str(uuid.uuid4()),
            status="success",
        )
        await async_db_session.commit()

        # Get logs for specific user
        page = await audit_repo.get_by_user(test_user.id)

        assert len(page.items) >= 3
        assert all(log.user_id == test_user.id for log in page.items)

    @pytest.mark.asyncio
    async def test_get_by_user_with_action_pattern(
        self,
        audit_repo: AuditLogRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting user logs filtered by action pattern."""
        # Create logs with different actions
        await audit_repo.log_action(
            action="user.login",
            resource_type="user",
            user_id=test_user.id,
            status="success",
        )
        await audit_repo.log_action(
            action="user.logout",
            resource_type="user",
            user_id=test_user.id,
            status="success",
        )
        await audit_repo.log_action(
            action="api_key.create",
            resource_type="api_key",
            user_id=test_user.id,
            status="success",
        )
        await async_db_session.commit()

        # Get only user.* actions
        page = await audit_repo.get_by_user(test_user.id, action_pattern="user.")

        user_actions = [log for log in page.items if log.action.startswith("user.")]
        api_actions = [log for log in page.items if log.action.startswith("api_key.")]

        assert len(user_actions) >= 2
        assert len(api_actions) == 0

    @pytest.mark.asyncio
    async def test_get_by_user_with_date_range(
        self,
        audit_repo: AuditLogRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting user logs within date range."""
        now = datetime.now(timezone.utc)

        # Create log from yesterday
        yesterday_log = await audit_repo.log_action(
            action="old.action",
            resource_type="test",
            user_id=test_user.id,
            status="success",
        )
        yesterday_log.created_at = now - timedelta(days=1)

        # Create log from today
        await audit_repo.log_action(
            action="new.action",
            resource_type="test",
            user_id=test_user.id,
            status="success",
        )
        await async_db_session.commit()

        # Get logs from last 12 hours
        start_date = now - timedelta(hours=12)
        page = await audit_repo.get_by_user(test_user.id, start_date=start_date)

        # Should only include today's log
        actions = [log.action for log in page.items]
        assert "new.action" in actions
        assert "old.action" not in actions

    @pytest.mark.asyncio
    async def test_get_recent_actions(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test getting recent audit logs."""
        # Create recent logs
        for i in range(5):
            await audit_repo.log_action(action=f"recent.action{i}", resource_type="test", status="success")
        await async_db_session.commit()

        # Get recent actions
        recent = await audit_repo.get_recent_actions(limit=10)

        assert len(recent) >= 5
        # Should be ordered by created_at desc
        if len(recent) > 1:
            assert recent[0].created_at >= recent[1].created_at

    @pytest.mark.asyncio
    async def test_get_recent_actions_with_filters(
        self, audit_repo: AuditLogRepository, async_db_session: AsyncSession
    ):
        """Test getting recent logs with type filters."""
        # Create logs of different types
        await audit_repo.log_action(action="user.login", resource_type="user", status="success")
        await audit_repo.log_action(action="api_key.create", resource_type="api_key", status="success")
        await audit_repo.log_action(action="user.update", resource_type="user", status="success")
        await async_db_session.commit()

        # Filter by action types
        recent = await audit_repo.get_recent_actions(action_types=["user.login", "user.update"])

        actions = [log.action for log in recent]
        assert "user.login" in actions
        assert "user.update" in actions
        assert "api_key.create" not in actions

        # Filter by resource types
        recent = await audit_repo.get_recent_actions(resource_types=["api_key"])

        assert all(log.resource_type == "api_key" for log in recent)

    @pytest.mark.asyncio
    async def test_get_recent_actions_hours_back(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test getting recent logs with custom time window."""
        now = datetime.now(timezone.utc)

        # Create old log
        old_log = await audit_repo.log_action(action="old.action", resource_type="test", status="success")
        old_log.created_at = now - timedelta(hours=25)

        # Create recent log
        await audit_repo.log_action(action="recent.action", resource_type="test", status="success")
        await async_db_session.commit()

        # Get logs from last 24 hours (default)
        recent = await audit_repo.get_recent_actions()
        actions = [log.action for log in recent]
        assert "recent.action" in actions
        assert "old.action" not in actions

        # Get logs from last 48 hours
        recent = await audit_repo.get_recent_actions(hours_back=48)
        actions = [log.action for log in recent]
        assert "recent.action" in actions
        assert "old.action" in actions

    @pytest.mark.asyncio
    async def test_get_action_statistics_by_action(
        self, audit_repo: AuditLogRepository, async_db_session: AsyncSession
    ):
        """Test getting audit log statistics grouped by action."""
        # Create logs with different actions
        await audit_repo.log_action("user.login", "user", status="success")
        await audit_repo.log_action("user.login", "user", status="success")
        await audit_repo.log_action("user.login", "user", status="success")
        await audit_repo.log_action("user.logout", "user", status="success")
        await audit_repo.log_action("user.logout", "user", status="success")
        await audit_repo.log_action("api_key.create", "api_key", status="success")
        await async_db_session.commit()

        # Get statistics by action
        stats = await audit_repo.get_action_statistics(group_by="action")

        # Convert to dict for easy checking
        stats_dict = {s["action"]: s["count"] for s in stats}

        assert stats_dict.get("user.login", 0) >= 3
        assert stats_dict.get("user.logout", 0) >= 2
        assert stats_dict.get("api_key.create", 0) >= 1

        # Should be ordered by count desc
        if len(stats) > 1:
            assert stats[0]["count"] >= stats[1]["count"]

    @pytest.mark.asyncio
    async def test_get_action_statistics_by_resource_type(
        self, audit_repo: AuditLogRepository, async_db_session: AsyncSession
    ):
        """Test getting statistics grouped by resource type."""
        # Create logs
        for _ in range(3):
            await audit_repo.log_action("test.action", "user", status="success")
        for _ in range(2):
            await audit_repo.log_action("test.action", "api_key", status="success")
        await async_db_session.commit()

        # Get statistics by resource type
        stats = await audit_repo.get_action_statistics(group_by="resource_type")

        stats_dict = {s["resource_type"]: s["count"] for s in stats}
        assert stats_dict.get("user", 0) >= 3
        assert stats_dict.get("api_key", 0) >= 2

    @pytest.mark.asyncio
    async def test_get_action_statistics_by_status(
        self, audit_repo: AuditLogRepository, async_db_session: AsyncSession
    ):
        """Test getting statistics grouped by status."""
        # Create logs with different statuses
        for _ in range(5):
            await audit_repo.log_action("test.action", "test", status="success")
        for _ in range(2):
            await audit_repo.log_action("test.action", "test", status="failure")
        await audit_repo.log_action("test.action", "test", status="error")
        await async_db_session.commit()

        # Get statistics by status
        stats = await audit_repo.get_action_statistics(group_by="status")

        stats_dict = {s["status"]: s["count"] for s in stats}
        assert stats_dict.get("success", 0) >= 5
        assert stats_dict.get("failure", 0) >= 2
        assert stats_dict.get("error", 0) >= 1

    @pytest.mark.asyncio
    async def test_get_action_statistics_with_date_filter(
        self, audit_repo: AuditLogRepository, async_db_session: AsyncSession
    ):
        """Test getting statistics with date filters."""
        now = datetime.now(timezone.utc)

        # Create old log
        old_log = await audit_repo.log_action("old.action", "test", status="success")
        old_log.created_at = now - timedelta(days=2)

        # Create recent logs
        await audit_repo.log_action("new.action", "test", status="success")
        await audit_repo.log_action("new.action", "test", status="success")
        await async_db_session.commit()

        # Get statistics for last 24 hours
        start_date = now - timedelta(days=1)
        stats = await audit_repo.get_action_statistics(start_date=start_date, group_by="action")

        stats_dict = {s["action"]: s["count"] for s in stats}
        assert stats_dict.get("new.action", 0) >= 2
        assert stats_dict.get("old.action", 0) == 0

    @pytest.mark.asyncio
    async def test_get_action_statistics_invalid_group_by(self, audit_repo: AuditLogRepository):
        """Test statistics with invalid group_by field."""
        with pytest.raises(ValueError, match="group_by must be one of"):
            await audit_repo.get_action_statistics(group_by="invalid_field")

    @pytest.mark.asyncio
    async def test_search_logs(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test searching audit logs."""
        # Create logs with searchable content
        await audit_repo.log_action(
            action="user.password_reset",
            resource_type="user",
            user_email="search@example.com",
            error_message="Password reset failed",
            status="error",
        )
        await audit_repo.log_action(
            action="api_key.create",
            resource_type="api_key",
            user_email="other@example.com",
            status="success",
        )
        await async_db_session.commit()

        # Search for "password"
        page = await audit_repo.search_logs("password")

        # Should find the password reset log
        assert len(page.items) >= 1
        assert any(
            "password" in log.action.lower() or (log.error_message and "password" in log.error_message.lower())
            for log in page.items
        )

    @pytest.mark.asyncio
    async def test_search_logs_specific_fields(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test searching specific fields."""
        # Create logs
        await audit_repo.log_action(
            action="test.action",
            resource_type="user",
            user_email="specific@example.com",
            status="success",
        )
        await audit_repo.log_action(
            action="specific.action",
            resource_type="test",
            user_email="other@example.com",
            status="success",
        )
        await async_db_session.commit()

        # Search only in user_email field
        page = await audit_repo.search_logs("specific", search_fields=["user_email"])

        # Should only find the first log
        assert len(page.items) >= 1
        emails = [log.user_email for log in page.items if log.user_email]
        assert all("specific" in email for email in emails)

    @pytest.mark.asyncio
    async def test_search_logs_with_date_range(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test searching with date filters."""
        now = datetime.now(timezone.utc)

        # Create old log
        old_log = await audit_repo.log_action(action="searchable.old", resource_type="test", status="success")
        old_log.created_at = now - timedelta(days=2)

        # Create recent log
        await audit_repo.log_action(action="searchable.new", resource_type="test", status="success")
        await async_db_session.commit()

        # Search with date filter
        start_date = now - timedelta(days=1)
        page = await audit_repo.search_logs("searchable", start_date=start_date)

        # Should only find recent log
        actions = [log.action for log in page.items]
        assert "searchable.new" in actions
        assert "searchable.old" not in actions

    @pytest.mark.asyncio
    async def test_search_logs_pagination(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test search with pagination."""
        # Create many searchable logs
        for i in range(10):
            await audit_repo.log_action(action=f"searchterm.action{i}", resource_type="test", status="success")
        await async_db_session.commit()

        # Search with pagination
        page1 = await audit_repo.search_logs("searchterm", page=1, size=3)
        assert len(page1.items) == 3
        assert page1.has_next is True

        page2 = await audit_repo.search_logs("searchterm", page=2, size=3)
        assert len(page2.items) == 3
        assert page2.has_prev is True

    @pytest.mark.asyncio
    async def test_search_logs_invalid_fields(self, audit_repo: AuditLogRepository):
        """Test search with invalid field names."""
        with pytest.raises(ValueError, match="No valid search fields"):
            await audit_repo.search_logs("test", search_fields=["nonexistent_field"])

    @pytest.mark.asyncio
    async def test_delete_raises_error(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test that deleting audit logs is not allowed."""
        # Create a log
        log = await audit_repo.log_action(action="test.immutable", resource_type="test", status="success")
        await async_db_session.commit()

        # Try to delete - should raise error
        with pytest.raises(ValueError, match="Audit logs are immutable"):
            await audit_repo.delete(log.id, hard_delete=False)

        with pytest.raises(ValueError, match="Audit logs are immutable"):
            await audit_repo.delete(log.id, hard_delete=True)

    @pytest.mark.asyncio
    async def test_update_raises_error(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test that updating audit logs is not allowed."""
        # Create a log
        log = await audit_repo.log_action(action="test.immutable", resource_type="test", status="success")
        await async_db_session.commit()

        # Try to update - should raise error
        with pytest.raises(ValueError, match="Audit logs are immutable"):
            await audit_repo.update(log.id, action="modified.action")
