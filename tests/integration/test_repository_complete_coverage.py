"""Additional tests to achieve 100% coverage for repository layer."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.exc import SQLAlchemyError
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
    return "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"


class TestBaseRepositoryCoverage:
    """Test missing coverage in BaseRepository."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> BaseRepository[User]:
        return BaseRepository(async_db_session, User)

    @pytest.mark.asyncio
    async def test_page_getitem(self):
        """Test Page.__getitem__ (line 50)."""
        page = Page(items=["a", "b", "c"], total=3, page=1, size=10, has_next=False, has_prev=False)
        assert page[0] == "a"
        assert page[-1] == "c"

    @pytest.mark.asyncio
    async def test_create_exception(self, user_repo: BaseRepository[User]):
        """Test create exception (lines 108-110)."""
        with patch.object(user_repo.session, "add", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.create(
                    username="test", email="test@example.com", password_hash=get_test_password_hash()
                )

    @pytest.mark.asyncio
    async def test_get_by_id_model_without_soft_delete(self):
        """Test get_by_id for model without is_deleted (line 131)."""

        class SimpleModel:
            id = "test-id"

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = SimpleModel()
        mock_session.execute = AsyncMock(return_value=mock_result)

        repo = BaseRepository(mock_session, SimpleModel)
        result = await repo.get_by_id("test-id")
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_by_id_exception(self, user_repo: BaseRepository[User]):
        """Test get_by_id exception (lines 143-145)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.get_by_id("test-id")

    @pytest.mark.asyncio
    async def test_update_model_without_soft_delete(self):
        """Test update for model without is_deleted (line 183)."""

        class SimpleModel:
            id = "test-id"

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_session.execute = AsyncMock(return_value=mock_result)

        repo = BaseRepository(mock_session, SimpleModel)
        repo.get_by_id = AsyncMock(return_value=SimpleModel())

        result = await repo.update("test-id", name="updated")
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_exception(self, user_repo: BaseRepository[User]):
        """Test update exception (lines 196-198)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.update("test-id", full_name="New")

    @pytest.mark.asyncio
    async def test_delete_hard_multiple_steps(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test hard delete path (lines 216-221)."""
        # Create user
        user = await user_repo.create(
            username="harddelete", email="hard@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        # Hard delete
        deleted = await user_repo.delete(user.id, hard_delete=True)
        assert deleted is True
        await async_db_session.commit()

        # Verify gone
        assert await user_repo.exists(user.id) is False

    @pytest.mark.asyncio
    async def test_delete_model_without_soft_delete(self):
        """Test delete for model without soft delete (lines 240-241)."""

        class SimpleModel:
            id = "test-id"

        repo = BaseRepository(MagicMock(), SimpleModel)
        result = await repo.delete("test-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_not_found(self, user_repo: BaseRepository[User]):
        """Test delete when not found (line 244)."""
        result = await user_repo.delete(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_exception(self, user_repo: BaseRepository[User]):
        """Test delete exception (lines 248-250)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.delete("test-id")

    @pytest.mark.asyncio
    async def test_list_with_pagination_list_filter(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test pagination with list filter (line 295)."""
        # Create users
        users = []
        for i in range(3):
            user = await user_repo.create(
                username=f"listuser{i}", email=f"list{i}@example.com", password_hash=get_test_password_hash()
            )
            users.append(user)
        await async_db_session.commit()

        # Filter by list
        page = await user_repo.list_with_pagination(filters={"id": [users[0].id, users[2].id]})
        found_ids = [u.id for u in page.items]
        assert users[0].id in found_ids
        assert users[2].id in found_ids

    @pytest.mark.asyncio
    async def test_list_with_pagination_eager_load(self, user_repo: BaseRepository[User]):
        """Test pagination eager load (lines 302-304)."""
        # Should work even with non-existent relationship
        page = await user_repo.list_with_pagination(eager_load=["nonexistent"])
        assert isinstance(page, Page)

    @pytest.mark.asyncio
    async def test_list_with_pagination_order_asc(
        self, user_repo: BaseRepository[User], async_db_session: AsyncSession
    ):
        """Test pagination ascending order (line 317)."""
        # Create users
        for i in range(3):
            await user_repo.create(
                username=f"zuser{2-i}",  # zuser2, zuser1, zuser0
                email=f"z{i}@example.com",
                password_hash=get_test_password_hash(),
            )
        await async_db_session.commit()

        # Order ascending
        page = await user_repo.list_with_pagination(order_by="username", order_desc=False)
        usernames = [u.username for u in page.items if u.username.startswith("zuser")]
        assert usernames == sorted(usernames)

    @pytest.mark.asyncio
    async def test_list_with_pagination_exception(self, user_repo: BaseRepository[User]):
        """Test pagination exception (lines 349-351)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.list_with_pagination()

    @pytest.mark.asyncio
    async def test_count_all_paths(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test count with filters (lines 364-391)."""
        # Create test data
        user = await user_repo.create(
            username="countuser", email="count@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        # Count all
        count1 = await user_repo.count()
        assert count1 >= 1

        # Count with filter
        count2 = await user_repo.count(filters={"username": "countuser"})
        assert count2 >= 1

        # Count with list filter
        count3 = await user_repo.count(filters={"id": [user.id]})
        assert count3 == 1

    @pytest.mark.asyncio
    async def test_count_exception(self, user_repo: BaseRepository[User]):
        """Test count exception (lines 389-391)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.count()

    @pytest.mark.asyncio
    async def test_exists_all_paths(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test exists method (lines 403-423)."""
        # Create user
        user = await user_repo.create(
            username="existsuser", email="exists@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        # Test exists
        assert await user_repo.exists(user.id) is True
        assert await user_repo.exists(str(uuid.uuid4())) is False

    @pytest.mark.asyncio
    async def test_exists_model_without_soft_delete(self):
        """Test exists for model without is_deleted (line 412)."""

        class SimpleModel:
            id = "test-id"

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 1
        mock_session.execute = AsyncMock(return_value=mock_result)

        repo = BaseRepository(mock_session, SimpleModel)
        assert await repo.exists("test-id") is True

    @pytest.mark.asyncio
    async def test_exists_exception(self, user_repo: BaseRepository[User]):
        """Test exists exception (lines 421-423)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.exists("test-id")

    @pytest.mark.asyncio
    async def test_restore_all_paths(self, user_repo: BaseRepository[User], async_db_session: AsyncSession):
        """Test restore method (lines 436-469)."""
        # Create and soft delete user
        user = await user_repo.create(
            username="restoreuser", email="restore@example.com", password_hash=get_test_password_hash()
        )
        await async_db_session.commit()

        await user_repo.delete(user.id)
        await async_db_session.commit()

        # Restore
        restored = await user_repo.restore(user.id, restored_by="admin")
        assert restored is True

        # Verify restored
        user = await user_repo.get_by_id(user.id)
        assert user is not None
        assert user.is_deleted is False

    @pytest.mark.asyncio
    async def test_restore_not_found(self, user_repo: BaseRepository[User]):
        """Test restore not found (line 460)."""
        result = await user_repo.restore(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_restore_model_without_soft_delete(self):
        """Test restore for model without soft delete (lines 464-465)."""

        class SimpleModel:
            id = "test-id"

        repo = BaseRepository(MagicMock(), SimpleModel)
        result = await repo.restore("test-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_restore_exception(self, user_repo: BaseRepository[User]):
        """Test restore exception (lines 467-469)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.restore("test-id")


class TestUserRepositoryCoverage:
    """Test missing coverage in UserRepository."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> UserRepository:
        return UserRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_get_by_username_exception(self, user_repo: UserRepository):
        """Test get_by_username exception (lines 55-57)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.get_by_username("test")

    @pytest.mark.asyncio
    async def test_get_by_email_exception(self, user_repo: UserRepository):
        """Test get_by_email exception (lines 85-87)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.get_by_email("test@example.com")

    @pytest.mark.asyncio
    async def test_authenticate_exception(self, user_repo: UserRepository):
        """Test authenticate exception (lines 130-132)."""
        with patch.object(user_repo, "get_by_username", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.authenticate("test", "password")

    @pytest.mark.asyncio
    async def test_update_password_not_found(self, user_repo: UserRepository):
        """Test update password not found (line 254)."""
        result = await user_repo.update_password(str(uuid.uuid4()), "old", "new")
        assert result is False

    @pytest.mark.asyncio
    async def test_activate_user_not_found(self, user_repo: UserRepository):
        """Test activate user not found (lines 277-278)."""
        result = await user_repo.activate_user(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_activate_user_exception(self, user_repo: UserRepository):
        """Test activate user exception (lines 292-294)."""
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.activate_user("test-id")

    @pytest.mark.asyncio
    async def test_deactivate_user_not_found(self, user_repo: UserRepository):
        """Test deactivate user not found (lines 311-312)."""
        result = await user_repo.deactivate_user(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_deactivate_user_exception(self, user_repo: UserRepository):
        """Test deactivate user exception (lines 326-328)."""
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.deactivate_user("test-id")

    @pytest.mark.asyncio
    async def test_create_user_validations(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test create_user validations (lines 341-359)."""
        # Empty password
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repo.create_user("test", "test@example.com", "")

        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repo.create_user("test", "test@example.com", "   ")

        # Create first user
        await user_repo.create_user("dupuser", "first@example.com", "password")
        await async_db_session.commit()

        # Duplicate username
        with pytest.raises(ValueError, match="Username 'dupuser' already exists"):
            await user_repo.create_user("dupuser", "second@example.com", "password")

        # Duplicate email
        with pytest.raises(ValueError, match="Email 'first@example.com' already exists"):
            await user_repo.create_user("other", "first@example.com", "password")

        # Email lowercase
        user = await user_repo.create_user("emailtest", "TEST@EXAMPLE.COM", "password")
        assert user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_update_password_validations(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test update password validations (lines 372-390)."""
        # Create user
        user = await user_repo.create_user("pwduser", "pwd@example.com", "oldpassword")
        await async_db_session.commit()

        # Empty new password
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repo.update_password(user.id, "oldpassword", "")

        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repo.update_password(user.id, "oldpassword", "   ")

        # Wrong old password
        result = await user_repo.update_password(user.id, "wrongpassword", "newpassword")
        assert result is False

    @pytest.mark.asyncio
    async def test_update_password_exception(self, user_repo: UserRepository):
        """Test update password exception (lines 389-390)."""
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.update_password("test-id", "old", "new")

    @pytest.mark.asyncio
    async def test_verify_email_not_found(self, user_repo: UserRepository):
        """Test verify email not found (line 429)."""
        result = await user_repo.verify_email(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_email_exception(self, user_repo: UserRepository):
        """Test verify email exception (lines 433-435)."""
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.verify_email("test-id")

    @pytest.mark.asyncio
    async def test_get_active_users_exception(self, user_repo: UserRepository):
        """Test get_active_users exception (lines 466-468)."""
        with patch.object(user_repo, "list_with_pagination", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.get_active_users()

    @pytest.mark.asyncio
    async def test_get_unverified_users_exception(self, user_repo: UserRepository):
        """Test get_unverified_users exception (lines 512-514)."""
        with patch.object(user_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.get_unverified_users()


class TestAPIKeyRepositoryCoverage:
    """Test missing coverage in APIKeyRepository."""

    @pytest_asyncio.fixture
    async def api_key_repo(self, async_db_session: AsyncSession) -> APIKeyRepository:
        return APIKeyRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_create_user_not_found(self, api_key_repo: APIKeyRepository):
        """Test create user not found (lines 58-60)."""
        result = await api_key_repo.create(str(uuid.uuid4()), "Test Key", ["read"])
        assert result is None

    @pytest.mark.asyncio
    async def test_create_exception(self, api_key_repo: APIKeyRepository):
        """Test create exception (lines 85-87)."""
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.create("user-id", "Test Key", ["read"])

    @pytest.mark.asyncio
    async def test_validate_exception(self, api_key_repo: APIKeyRepository):
        """Test validate exception (lines 119-121)."""
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.validate("some-key")

    @pytest.mark.asyncio
    async def test_revoke_not_found(self, api_key_repo: APIKeyRepository):
        """Test revoke not found (lines 227-229)."""
        result = await api_key_repo.revoke(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_already_revoked(self, api_key_repo: APIKeyRepository, async_db_session: AsyncSession):
        """Test revoke already revoked (line 275)."""
        # Create user and key
        user_repo = UserRepository(async_db_session)
        user = await user_repo.create_user("apitest", "api@example.com", "password")
        await async_db_session.commit()

        key_data = await api_key_repo.create(user.id, "Test Key", ["read"])
        await api_key_repo.revoke(key_data.id)
        await async_db_session.commit()

        # Try to revoke again
        result = await api_key_repo.revoke(key_data.id)
        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_exception(self, api_key_repo: APIKeyRepository):
        """Test revoke exception (lines 282-284)."""
        with patch.object(api_key_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.revoke("test-id")

    @pytest.mark.asyncio
    async def test_update_permissions_not_found(self, api_key_repo: APIKeyRepository):
        """Test update permissions not found (lines 319-321)."""
        result = await api_key_repo.update_permissions(str(uuid.uuid4()), ["read"])
        assert result is False

    @pytest.mark.asyncio
    async def test_update_permissions_exception(self, api_key_repo: APIKeyRepository):
        """Test update permissions exception (lines 321-323)."""
        with patch.object(api_key_repo, "update", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.update_permissions("test-id", ["read"])

    @pytest.mark.asyncio
    async def test_list_user_keys_exception(self, api_key_repo: APIKeyRepository):
        """Test list_user_keys exception (lines 359-361)."""
        with patch.object(api_key_repo, "list_with_pagination", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.list_user_keys("user-id")

    @pytest.mark.asyncio
    async def test_check_permission_exception(self, api_key_repo: APIKeyRepository):
        """Test check_permission exception (lines 397-399)."""
        with patch.object(api_key_repo, "get_by_id", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.check_permission("test-id", "read")

    @pytest.mark.asyncio
    async def test_record_usage_exception(self, api_key_repo: APIKeyRepository):
        """Test record_usage exception (lines 427-429)."""
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.record_usage("test-id")


class TestAuditLogRepositoryCoverage:
    """Test missing coverage in AuditLogRepository."""

    @pytest_asyncio.fixture
    async def audit_repo(self, async_db_session: AsyncSession) -> AuditLogRepository:
        return AuditLogRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_create_exception(self, audit_repo: AuditLogRepository):
        """Test create exception (lines 118-122)."""
        with patch.object(audit_repo.session, "add", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.create("test.action", "Test", "123")

    @pytest.mark.asyncio
    async def test_search_exception(self, audit_repo: AuditLogRepository):
        """Test search exception (lines 166-173)."""
        with patch.object(audit_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.search()

    @pytest.mark.asyncio
    async def test_get_entity_history_exception(self, audit_repo: AuditLogRepository):
        """Test get_entity_history exception (line 212)."""
        with patch.object(audit_repo, "search", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_entity_history("User", "123")

    @pytest.mark.asyncio
    async def test_get_actor_activity_exception(self, audit_repo: AuditLogRepository):
        """Test get_actor_activity exception (lines 252-254)."""
        with patch.object(audit_repo, "search", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_actor_activity("actor-123")

    @pytest.mark.asyncio
    async def test_get_statistics_exception(self, audit_repo: AuditLogRepository):
        """Test get_statistics exception (lines 306-308)."""
        with patch.object(audit_repo.session, "execute", side_effect=SQLAlchemyError("Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_statistics()

    @pytest.mark.asyncio
    async def test_update_prevented(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test update prevented (line 343)."""
        # Create audit log
        audit_log = await audit_repo.create("test", "Test", "123")
        await async_db_session.commit()

        # Try to update - should return None
        with patch.object(audit_repo.logger, "warning") as mock_logger:
            result = await audit_repo.update(audit_log.id, action="modified")
            assert result is None
            mock_logger.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_prevented(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test delete prevented (line 421)."""
        # Create audit log
        audit_log = await audit_repo.create("test", "Test", "123")
        await async_db_session.commit()

        # Try to delete - should return False
        with patch.object(audit_repo.logger, "warning") as mock_logger:
            result = await audit_repo.delete(audit_log.id)
            assert result is False
            mock_logger.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
