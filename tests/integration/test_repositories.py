"""Integration tests for repository pattern with real database operations."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.base import BaseRepository, Page
from app.repositories.user import UserRepository


def get_test_password_hash():
    """Get a valid test password hash."""
    # This is a real Argon2 hash of "testpassword"
    return "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"


class TestBaseRepository:
    """Test BaseRepository with real database operations."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> BaseRepository[User]:
        """Create a user repository for testing."""
        return BaseRepository(async_db_session, User)

    @pytest.mark.asyncio
    async def test_create_with_auto_uuid(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test creating entity with auto-generated UUID."""
        user = await user_repo.create(
            username="test_user",
            email="test@example.com",
            password_hash=get_test_password_hash(),
            created_by="test",
        )

        assert user.id is not None
        assert isinstance(user.id, str)
        assert len(user.id) == 36  # UUID format
        assert user.username == "test_user"
        assert user.created_by == "test"

        await async_db_session.commit()

    @pytest.mark.asyncio
    async def test_create_with_provided_id(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test creating entity with provided ID."""
        custom_id = str(uuid.uuid4())
        user = await user_repo.create(
            id=custom_id,
            username="test_user2",
            email="test2@example.com",
            password_hash=get_test_password_hash(),
        )

        assert user.id == custom_id
        await async_db_session.commit()

    @pytest.mark.asyncio
    async def test_create_with_audit_fields(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test audit fields are set correctly."""
        user = await user_repo.create(
            username="test_user3",
            email="test3@example.com",
            password_hash=get_test_password_hash(),
            created_by="admin",
            updated_by="admin",
        )

        assert user.created_by == "admin"
        assert user.updated_by == "admin"
        await async_db_session.commit()

    @pytest.mark.asyncio
    async def test_create_with_constraint_violation(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test create fails with constraint violation."""
        # Create first user
        await user_repo.create(
            username="duplicate_user",
            email="dup@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Try to create duplicate
        with pytest.raises(IntegrityError):
            await user_repo.create(
                username="duplicate_user",  # Duplicate username
                email="other@example.com",
                password_hash=get_test_password_hash(),
            )
            await async_db_session.commit()

    @pytest.mark.asyncio
    async def test_get_by_id_existing(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test getting existing entity by ID."""
        # Create user
        user = await user_repo.create(
            username="test_get",
            email="get@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Get by ID
        found = await user_repo.get_by_id(user.id)
        assert found is not None
        assert found.id == user.id
        assert found.username == "test_get"

    @pytest.mark.asyncio
    async def test_get_by_id_nonexistent(self, user_repo: BaseRepository[User]):
        """Test getting non-existent entity by ID."""
        non_existent_id = str(uuid.uuid4())
        found = await user_repo.get_by_id(non_existent_id)
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_id_with_uuid_object(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test getting entity by UUID object."""
        # Create user
        user = await user_repo.create(
            username="test_uuid",
            email="uuid@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Get by UUID object
        uuid_obj = uuid.UUID(user.id)
        found = await user_repo.get_by_id(uuid_obj)
        assert found is not None
        assert found.id == user.id

    @pytest.mark.asyncio
    async def test_get_by_id_soft_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test getting soft-deleted entity returns None."""
        # Create and soft delete user
        user = await user_repo.create(
            username="to_delete",
            email="delete@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Soft delete
        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # Try to get soft-deleted user
        found = await user_repo.get_by_id(user.id)
        assert found is None

    @pytest.mark.asyncio
    async def test_update_existing(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test updating existing entity."""
        # Create user
        user = await user_repo.create(
            username="test_update",
            email="update@example.com",
            password_hash=get_test_password_hash(),
            full_name="Original Name",
        )
        await async_db_session.commit()
        original_version = user.version

        # Update
        updated = await user_repo.update(user.id, full_name="Updated Name", updated_by="updater")
        await async_db_session.commit()

        assert updated is not None
        assert updated.full_name == "Updated Name"
        assert updated.updated_by == "updater"
        assert updated.version == original_version + 1

    @pytest.mark.asyncio
    async def test_update_nonexistent(self, user_repo: BaseRepository[User]):
        """Test updating non-existent entity returns None."""
        result = await user_repo.update(str(uuid.uuid4()), full_name="Won't work")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_soft_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test updating soft-deleted entity returns None."""
        # Create and soft delete
        user = await user_repo.create(
            username="soft_del_update",
            email="softdel@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # Try to update
        result = await user_repo.update(user.id, full_name="Won't work")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_removes_id_from_kwargs(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test update removes id from kwargs."""
        # Create user
        user = await user_repo.create(
            username="test_id_removal",
            email="idremoval@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Try to update with id in kwargs
        updated = await user_repo.update(user.id, id="different_id", full_name="Updated")  # Should be ignored
        await async_db_session.commit()

        assert updated is not None
        assert updated.id == user.id  # ID unchanged
        assert updated.full_name == "Updated"

    @pytest.mark.asyncio
    async def test_soft_delete(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test soft delete functionality."""
        # Create user
        user = await user_repo.create(
            username="to_soft_delete",
            email="softdelete@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Soft delete
        result = await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        assert result is True

        # Check user is soft deleted
        stmt = select(User).where(User.id == user.id)
        result = await async_db_session.execute(stmt)
        user_in_db = result.scalar_one_or_none()

        assert user_in_db is not None
        assert user_in_db.is_deleted is True
        assert user_in_db.deleted_by == "system"
        assert user_in_db.deleted_at is not None

    @pytest.mark.asyncio
    async def test_hard_delete(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test hard delete functionality."""
        # Create user
        user = await user_repo.create(
            username="to_hard_delete",
            email="harddelete@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Hard delete
        result = await user_repo.delete(user.id, hard_delete=True)
        await async_db_session.commit()

        assert result is True

        # Check user is gone
        stmt = select(User).where(User.id == user.id)
        result = await async_db_session.execute(stmt)
        user_in_db = result.scalar_one_or_none()

        assert user_in_db is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, user_repo: BaseRepository[User]):
        """Test deleting non-existent entity."""
        result = await user_repo.delete(str(uuid.uuid4()), hard_delete=False)
        assert result is False

        result = await user_repo.delete(str(uuid.uuid4()), hard_delete=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_already_soft_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test deleting already soft-deleted entity."""
        # Create and soft delete
        user = await user_repo.create(
            username="double_delete",
            email="double@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # Try to soft delete again
        result = await user_repo.delete(user.id, hard_delete=False)
        assert result is False

    @pytest.mark.asyncio
    async def test_list_with_pagination_basic(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test basic pagination."""
        # Create multiple users
        for i in range(5):
            await user_repo.create(
                username=f"user_{i}",
                email=f"user{i}@example.com",
                password_hash=get_test_password_hash(),
            )
        await async_db_session.commit()

        # Get page 1
        page = await user_repo.list_with_pagination(page=1, size=2)

        assert isinstance(page, Page)
        assert len(page.items) == 2
        assert page.total >= 5
        assert page.page == 1
        assert page.size == 2
        assert page.has_next is True
        assert page.has_prev is False
        assert page.pages >= 3

    @pytest.mark.asyncio
    async def test_list_with_pagination_last_page(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test last page pagination."""
        # Get last page
        page = await user_repo.list_with_pagination(page=3, size=2)

        assert page.has_next is False
        assert page.has_prev is True

    @pytest.mark.asyncio
    async def test_list_with_pagination_filters(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test pagination with filters."""
        # Create users with specific attributes
        await user_repo.create(
            username="active_user",
            email="active@example.com",
            password_hash=get_test_password_hash(),
            is_active=True,
        )
        await user_repo.create(
            username="inactive_user",
            email="inactive@example.com",
            password_hash=get_test_password_hash(),
            is_active=False,
        )
        await async_db_session.commit()

        # Filter by is_active
        page = await user_repo.list_with_pagination(filters={"is_active": True})

        assert all(user.is_active for user in page.items)

    @pytest.mark.asyncio
    async def test_list_with_pagination_filter_list(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test pagination with list filters (IN clause)."""
        # Create users
        user1 = await user_repo.create(
            username="filter_user1",
            email="filter1@example.com",
            password_hash=get_test_password_hash(),
        )
        user2 = await user_repo.create(
            username="filter_user2",
            email="filter2@example.com",
            password_hash=get_test_password_hash(),
        )
        await user_repo.create(
            username="filter_user3",
            email="filter3@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Filter by list of IDs
        page = await user_repo.list_with_pagination(filters={"id": [user1.id, user2.id]})

        assert len(page.items) == 2
        assert all(user.id in [user1.id, user2.id] for user in page.items)

    @pytest.mark.asyncio
    async def test_list_with_pagination_invalid_filter(self, user_repo: BaseRepository[User]):
        """Test pagination with invalid filter field."""
        # Filter by non-existent field (should be ignored)
        page = await user_repo.list_with_pagination(filters={"non_existent_field": "value"})

        # Should return results without error
        assert isinstance(page, Page)

    @pytest.mark.asyncio
    async def test_list_with_pagination_exclude_deleted(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test pagination excludes soft-deleted by default."""
        # Create and soft delete a user
        user = await user_repo.create(
            username="deleted_user",
            email="deleted@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # List should not include soft-deleted
        page = await user_repo.list_with_pagination()

        assert all(not getattr(item, "is_deleted", False) for item in page.items)
        assert user.id not in [item.id for item in page.items]

    @pytest.mark.asyncio
    async def test_list_with_pagination_include_deleted(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test pagination includes soft-deleted when requested."""
        # Create and soft delete a user
        user = await user_repo.create(
            username="include_deleted",
            email="includedel@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # List with include_deleted=True
        page = await user_repo.list_with_pagination(include_deleted=True)

        # Should include the soft-deleted user
        user_ids = [item.id for item in page.items]
        assert user.id in user_ids

    @pytest.mark.asyncio
    async def test_list_with_pagination_ordering(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test pagination ordering."""
        # Create users with different creation times
        user1 = await user_repo.create(
            username="order_user1",
            email="order1@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Small delay to ensure different timestamps
        import asyncio

        await asyncio.sleep(0.1)

        user2 = await user_repo.create(
            username="order_user2",
            email="order2@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Default order (created_at DESC)
        page = await user_repo.list_with_pagination(order_by="created_at", order_desc=True)
        if len(page.items) >= 2:
            # Find our users in the results
            items = [item for item in page.items if item.username in ["order_user1", "order_user2"]]
            if len(items) == 2:
                assert items[0].username == "order_user2"  # Newer first
                assert items[1].username == "order_user1"

        # Reverse order
        page = await user_repo.list_with_pagination(order_by="created_at", order_desc=False)
        if len(page.items) >= 2:
            items = [item for item in page.items if item.username in ["order_user1", "order_user2"]]
            if len(items) == 2:
                assert items[0].username == "order_user1"  # Older first
                assert items[1].username == "order_user2"

    @pytest.mark.asyncio
    async def test_list_with_pagination_custom_order_field(self, user_repo: BaseRepository[User]):
        """Test pagination with custom order field."""
        # Order by username
        page = await user_repo.list_with_pagination(order_by="username", order_desc=False)

        # Check items are ordered by username
        if len(page.items) > 1:
            usernames = [item.username for item in page.items]
            assert usernames == sorted(usernames)

    @pytest.mark.asyncio
    async def test_list_with_pagination_invalid_order_field(self, user_repo: BaseRepository[User]):
        """Test pagination with invalid order field."""
        # Should not raise error, just use default ordering
        page = await user_repo.list_with_pagination(order_by="invalid_field")
        assert isinstance(page, Page)

    @pytest.mark.asyncio
    async def test_list_with_pagination_size_limits(self, user_repo: BaseRepository[User]):
        """Test pagination size limits."""
        # Test minimum size
        page = await user_repo.list_with_pagination(page=1, size=0)
        assert page.size == 1  # Should be at least 1

        # Test maximum size
        page = await user_repo.list_with_pagination(page=1, size=200)
        assert page.size == 100  # Should be capped at 100

    @pytest.mark.asyncio
    async def test_list_with_pagination_page_validation(self, user_repo: BaseRepository[User]):
        """Test pagination page validation."""
        # Test page < 1
        page = await user_repo.list_with_pagination(page=0, size=10)
        assert page.page == 1  # Should be at least 1

        # Test negative page
        page = await user_repo.list_with_pagination(page=-5, size=10)
        assert page.page == 1  # Should be at least 1

    @pytest.mark.asyncio
    async def test_count_basic(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test basic count functionality."""
        # Create some users
        for i in range(3):
            await user_repo.create(
                username=f"count_user_{i}",
                email=f"count{i}@example.com",
                password_hash=get_test_password_hash(),
            )
        await async_db_session.commit()

        count = await user_repo.count()
        assert count >= 3

    @pytest.mark.asyncio
    async def test_count_with_filters(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test count with filters."""
        # Create users with different statuses
        await user_repo.create(
            username="count_active",
            email="countactive@example.com",
            password_hash=get_test_password_hash(),
            is_active=True,
        )
        await user_repo.create(
            username="count_inactive",
            email="countinactive@example.com",
            password_hash=get_test_password_hash(),
            is_active=False,
        )
        await async_db_session.commit()

        # Count only active users
        count = await user_repo.count(filters={"is_active": True})
        assert count >= 1

        # Count only inactive users
        count = await user_repo.count(filters={"is_active": False})
        assert count >= 1

    @pytest.mark.asyncio
    async def test_count_exclude_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test count excludes soft-deleted by default."""
        # Create and soft delete a user
        user = await user_repo.create(
            username="count_deleted",
            email="countdel@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        count_before = await user_repo.count()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        count_after = await user_repo.count()
        assert count_after == count_before - 1

    @pytest.mark.asyncio
    async def test_count_include_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test count includes soft-deleted when requested."""
        # Get count including deleted
        count_with_deleted = await user_repo.count(include_deleted=True)
        count_without_deleted = await user_repo.count(include_deleted=False)

        # Should have more when including deleted (from previous tests)
        assert count_with_deleted >= count_without_deleted

    @pytest.mark.asyncio
    async def test_exists_true(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test exists returns True for existing entity."""
        user = await user_repo.create(
            username="exists_user",
            email="exists@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        exists = await user_repo.exists(user.id)
        assert exists is True

    @pytest.mark.asyncio
    async def test_exists_false(self, user_repo: BaseRepository[User]):
        """Test exists returns False for non-existent entity."""
        exists = await user_repo.exists(str(uuid.uuid4()))
        assert exists is False

    @pytest.mark.asyncio
    async def test_exists_soft_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test exists returns False for soft-deleted entity."""
        user = await user_repo.create(
            username="exists_deleted",
            email="existsdel@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        # Check exists before delete
        assert await user_repo.exists(user.id) is True

        # Soft delete
        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # Check exists after delete
        assert await user_repo.exists(user.id) is False

    @pytest.mark.asyncio
    async def test_restore(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test restoring soft-deleted entity."""
        # Create and soft delete
        user = await user_repo.create(
            username="restore_user",
            email="restore@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        await user_repo.delete(user.id, hard_delete=False)
        await async_db_session.commit()

        # Restore
        result = await user_repo.restore(user.id, restored_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check user is restored
        restored = await user_repo.get_by_id(user.id)
        assert restored is not None
        assert restored.is_deleted is False
        assert restored.deleted_by is None
        assert restored.deleted_at is None
        assert restored.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_restore_not_deleted(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test restoring non-deleted entity returns False."""
        user = await user_repo.create(
            username="not_deleted",
            email="notdel@example.com",
            password_hash=get_test_password_hash(),
        )
        await async_db_session.commit()

        result = await user_repo.restore(user.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_restore_nonexistent(self, user_repo: BaseRepository[User]):
        """Test restoring non-existent entity returns False."""
        result = await user_repo.restore(str(uuid.uuid4()))
        assert result is False


class TestBaseRepositoryWithoutSoftDelete:
    """Test BaseRepository with model that doesn't support soft delete (AuditLog)."""

    @pytest_asyncio.fixture
    async def audit_repo(self, async_db_session: AsyncSession) -> BaseRepository[AuditLog]:
        """Create an audit log repository for testing."""
        return BaseRepository(async_db_session, AuditLog)

    @pytest.mark.asyncio
    async def test_soft_delete_not_supported(
        self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession
    ):
        """Test soft delete on model without is_deleted field."""
        # Create audit log
        audit = await audit_repo.create(action="test.action", resource_type="test", status="success")
        await async_db_session.commit()

        # Try soft delete - should return False
        result = await audit_repo.delete(audit.id, hard_delete=False)
        assert result is False

        # Entity should still exist
        found = await audit_repo.get_by_id(audit.id)
        assert found is not None

    @pytest.mark.asyncio
    async def test_hard_delete_supported(self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession):
        """Test hard delete works on model without soft delete."""
        # Create audit log
        audit = await audit_repo.create(action="test.delete", resource_type="test", status="success")
        await async_db_session.commit()

        # Hard delete should work
        result = await audit_repo.delete(audit.id, hard_delete=True)
        assert result is True

        # Entity should be gone
        found = await audit_repo.get_by_id(audit.id)
        assert found is None

    @pytest.mark.asyncio
    async def test_restore_not_supported(self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession):
        """Test restore on model without soft delete support."""
        # Create audit log
        audit = await audit_repo.create(action="test.restore", resource_type="test", status="success")
        await async_db_session.commit()

        # Restore should return False
        result = await audit_repo.restore(audit.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_list_without_soft_delete_filter(
        self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession
    ):
        """Test listing works without soft delete filter."""
        # Create some audit logs
        for i in range(3):
            await audit_repo.create(action=f"test.action{i}", resource_type="test", status="success")
        await async_db_session.commit()

        # List should work without soft delete filter
        page = await audit_repo.list_with_pagination()
        assert len(page.items) >= 3

    @pytest.mark.asyncio
    async def test_count_without_soft_delete_filter(
        self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession
    ):
        """Test count works without soft delete filter."""
        # Create audit log
        await audit_repo.create(action="test.count", resource_type="test", status="success")
        await async_db_session.commit()

        # Count should work
        count = await audit_repo.count()
        assert count >= 1

    @pytest.mark.asyncio
    async def test_exists_without_soft_delete_filter(
        self, audit_repo: BaseRepository[AuditLog], async_db_session: AsyncSession
    ):
        """Test exists works without soft delete filter."""
        # Create audit log
        audit = await audit_repo.create(action="test.exists", resource_type="test", status="success")
        await async_db_session.commit()

        # Exists should work
        exists = await audit_repo.exists(audit.id)
        assert exists is True
