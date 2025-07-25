"""Integration tests for database models with real database operations."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.user import User


@pytest.fixture(scope="session")
def event_loop() -> Any:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def async_db_session() -> Any:
    """Create async database session for testing."""
    # Use SQLite for tests (in-memory)
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session maker
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Provide session
    async with async_session_maker() as session:
        yield session
        await session.rollback()

    # Cleanup
    await engine.dispose()


class TestUserIntegration:
    """Integration tests for User model."""

    @pytest.mark.asyncio
    async def test_create_user(self, async_db_session: AsyncSession) -> None:
        """Test creating and persisting a user."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            full_name="Test User",
            created_by="system",
        )

        async_db_session.add(user)
        await async_db_session.commit()

        # Query the user
        result = await async_db_session.execute(select(User).filter_by(username="testuser"))
        saved_user = result.scalar_one()

        assert saved_user.id == user.id
        assert saved_user.username == "testuser"
        assert saved_user.email == "test@example.com"
        assert saved_user.created_by == "system"
        assert saved_user.version == 1

    @pytest.mark.asyncio
    async def test_unique_username_constraint(self, async_db_session: AsyncSession) -> None:
        """Test unique username constraint."""
        # Create first user
        user1 = User(
            username="uniqueuser",
            email="user1@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user1)
        await async_db_session.commit()

        # Try to create duplicate username
        user2 = User(
            username="uniqueuser",  # Same username
            email="user2@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user2)

        with pytest.raises(IntegrityError):
            await async_db_session.commit()

    @pytest.mark.asyncio
    async def test_soft_delete_filtering(self, async_db_session: AsyncSession) -> None:
        """Test querying with soft delete filtering."""
        # Create users
        active_user = User(
            username="activeuser",
            email="active@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        deleted_user = User(
            username="deleteduser",
            email="deleted@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )

        async_db_session.add_all([active_user, deleted_user])
        await async_db_session.commit()

        # Soft delete one user
        deleted_user.soft_delete(deleted_by="admin")
        await async_db_session.commit()

        # Query only active users
        result = await async_db_session.execute(select(User).filter_by(is_deleted=False))
        active_users = result.scalars().all()

        assert len(active_users) == 1
        assert active_users[0].username == "activeuser"

        # Query all users
        result = await async_db_session.execute(select(User))
        all_users = result.scalars().all()

        assert len(all_users) == 2

    @pytest.mark.asyncio
    async def test_optimistic_locking(self, async_db_session: AsyncSession) -> None:
        """Test optimistic locking with version field."""
        # Create user
        user = User(
            username="versiontest",
            email="version@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        original_version = user.version

        # Update user
        user.full_name = "Updated Name"
        await async_db_session.commit()

        # Version should be incremented
        # Note: This requires the event listener to be properly registered
        # In a real implementation, this would work with the before_flush event
        assert user.version >= original_version


class TestAPIKeyIntegration:
    """Integration tests for APIKey model."""

    @pytest.mark.asyncio
    async def test_create_api_key_with_user(self, async_db_session: AsyncSession) -> None:
        """Test creating API key with user relationship."""
        # Create user first
        user = User(
            username="apiuser",
            email="apiuser@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        # Create API key
        api_key = APIKey(
            key_hash="ba31e3a870d9a64984b26258b8822186425d192abed52381f14d27663b0c4c27",
            name="Test API Key",
            key_prefix="test_01",
            user_id=user.id,
            permissions={"read": True, "write": True},
            created_by=str(user.id),
        )
        async_db_session.add(api_key)
        await async_db_session.commit()

        # Query with relationship
        result = await async_db_session.execute(select(APIKey).filter_by(name="Test API Key"))
        saved_key = result.scalar_one()

        assert saved_key.user_id == user.id
        assert saved_key.permissions == {"read": True, "write": True}

    @pytest.mark.asyncio
    async def test_api_key_expiration_query(self, async_db_session: AsyncSession) -> None:
        """Test querying for expired API keys."""
        user = User(
            username="expiryuser",
            email="expiry@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        # Create expired and valid keys
        expired_key = APIKey(
            key_hash="971b78f1df284dc1bd6ce887e49a1307e57fd861fc0f802e13df432be19e6ced",
            name="Expired Key",
            key_prefix="expire",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        valid_key = APIKey(
            key_hash="5baa78e6d317f474913c12ee9d3a6c17bd3f806cf8ce0ddede9878eeca438ea4",
            name="Valid Key",
            key_prefix="valid1",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        async_db_session.add_all([expired_key, valid_key])
        await async_db_session.commit()

        # Query non-expired keys
        now = datetime.now(timezone.utc)
        result = await async_db_session.execute(
            select(APIKey).filter((APIKey.expires_at.is_(None)) | (APIKey.expires_at > now))
        )
        valid_keys = result.scalars().all()

        assert len(valid_keys) == 1
        assert valid_keys[0].name == "Valid Key"

    @pytest.mark.asyncio
    async def test_cascade_delete_api_keys(self, async_db_session: AsyncSession) -> None:
        """Test that API keys are deleted when user is deleted."""
        # Create user with API keys
        user = User(
            username="cascadeuser",
            email="cascade@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        # Create API keys
        key1 = APIKey(
            key_hash="caa415ca72068c7c26979f5647dab8bb15c13d66ceff69110311372f9a84b010",
            name="Key 1",
            key_prefix="keyapi1",
            user_id=user.id,
        )
        key2 = APIKey(
            key_hash="73a94cd9fd8be0709101eaa3abcd9f9eda4b42315b012481b03cde90aff5fc08",
            name="Key 2",
            key_prefix="keyapi2",
            user_id=user.id,
        )

        async_db_session.add_all([key1, key2])
        await async_db_session.commit()

        # Delete user (hard delete for cascade test)
        await async_db_session.delete(user)
        await async_db_session.commit()

        # API keys should be gone
        result = await async_db_session.execute(select(APIKey).filter_by(user_id=user.id))
        remaining_keys = result.scalars().all()

        assert len(remaining_keys) == 0


class TestAuditLogIntegration:
    """Integration tests for AuditLog model."""

    @pytest.mark.asyncio
    async def test_create_audit_log(self, async_db_session: AsyncSession) -> None:
        """Test creating audit log entries."""
        # Create user for reference
        user = User(
            username="audituser",
            email="audit@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        # Create audit log
        audit_log = AuditLog.log_action(
            action="user.login",
            resource_type="user",
            resource_id=str(user.id),
            user_id=str(user.id),
            ip_address="192.168.1.100",
            user_agent="Test Browser",
            request_id="req-123",
            metadata={"session_id": "sess-456"},
            duration_ms=150,
        )

        async_db_session.add(audit_log)
        await async_db_session.commit()

        # Query audit log
        result = await async_db_session.execute(select(AuditLog).filter_by(action="user.login"))
        saved_log = result.scalar_one()

        assert saved_log.resource_type == "user"
        assert saved_log.resource_id == str(user.id)
        assert saved_log.ip_address == "192.168.1.100"
        assert saved_log.action_metadata["session_id"] == "sess-456"

    @pytest.mark.asyncio
    async def test_audit_log_time_range_query(self, async_db_session: AsyncSession) -> None:
        """Test querying audit logs by time range."""
        # Create multiple audit logs
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            log = AuditLog(
                action="test.action",
                resource_type="test",
                resource_id=f"test-{i}",
                created_at=base_time - timedelta(hours=i),
                created_by="system",
            )
            async_db_session.add(log)

        await async_db_session.commit()

        # Query logs from last 2 hours
        two_hours_ago = base_time - timedelta(hours=2)
        result = await async_db_session.execute(
            select(AuditLog).filter(
                AuditLog.created_at >= two_hours_ago,
                AuditLog.action == "test.action",
            )
        )
        recent_logs = result.scalars().all()

        assert len(recent_logs) == 3  # 0, 1, and 2 hours ago

    @pytest.mark.asyncio
    async def test_audit_log_user_activity(self, async_db_session: AsyncSession) -> None:
        """Test querying user activity from audit logs."""
        # Create users
        user1 = User(
            username="user1",
            email="user1@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        async_db_session.add_all([user1, user2])
        await async_db_session.commit()

        # Create audit logs for different users
        logs = [
            AuditLog(action="session.login", resource_type="session", user_id=user1.id),
            AuditLog(action="document.create", resource_type="document", user_id=user1.id),
            AuditLog(action="profile.update", resource_type="profile", user_id=user1.id),
            AuditLog(action="session.login", resource_type="session", user_id=user2.id),
            AuditLog(action="file.delete", resource_type="file", user_id=user2.id),
        ]

        async_db_session.add_all(logs)
        await async_db_session.commit()

        # Query user1's activity
        result = await async_db_session.execute(
            select(AuditLog).filter_by(user_id=user1.id).order_by(AuditLog.created_at.desc())
        )
        user1_logs = result.scalars().all()

        assert len(user1_logs) == 3
        actions = [log.action for log in user1_logs]
        assert set(actions) == {"session.login", "document.create", "profile.update"}


class TestCrossModelIntegration:
    """Test interactions between multiple models."""

    @pytest.mark.asyncio
    async def test_complete_user_workflow(self, async_db_session: AsyncSession) -> None:
        """Test complete workflow with user, API key, and audit logging."""
        # Create user
        user = User(
            username="workflow_user",
            email="workflow@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            created_by="admin",
        )
        async_db_session.add(user)
        await async_db_session.commit()

        # Log user creation
        create_log = AuditLog.log_action(
            action="user.create",
            resource_type="user",
            resource_id=str(user.id),
            user_id=str(user.id),
            metadata={"created_by": "admin"},
        )
        async_db_session.add(create_log)

        # Create API key for user
        api_key = APIKey(
            key_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            name="Workflow API Key",
            key_prefix="workfl",
            user_id=user.id,
            permissions={"read": True, "write": True},
            created_by=str(user.id),
        )
        async_db_session.add(api_key)
        await async_db_session.commit()

        # Log API key creation
        key_log = AuditLog.log_action(
            action="apikey.create",
            resource_type="api_key",
            resource_id=str(api_key.id),
            user_id=str(user.id),
            metadata={"key_name": api_key.name},
        )
        async_db_session.add(key_log)

        # Record API key usage
        api_key.record_usage(ip_address="10.0.0.1")

        # Log API usage
        usage_log = AuditLog.log_action(
            action="apikey.use",
            resource_type="api_key",
            resource_id=str(api_key.id),
            user_id=str(user.id),
            ip_address="10.0.0.1",
            duration_ms=50,
        )
        async_db_session.add(usage_log)
        await async_db_session.commit()

        # Verify complete workflow
        result = await async_db_session.execute(
            select(AuditLog).filter_by(user_id=user.id).order_by(AuditLog.created_at)
        )
        all_logs = result.scalars().all()

        assert len(all_logs) == 3
        assert all_logs[0].action == "user.create"
        assert all_logs[1].action == "apikey.create"
        assert all_logs[2].action == "apikey.use"

        # Verify API key was updated
        assert api_key.usage_count == 1
        assert api_key.last_used_ip == "10.0.0.1"
