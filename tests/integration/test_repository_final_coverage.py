"""Final tests to achieve 100% coverage for repository layer."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.user import UserRepository


class TestFinalUserRepositoryCoverage:
    """Final tests for UserRepository missing lines."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> UserRepository:
        return UserRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_update_password_complete_flow(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test update password complete flow (line 254)."""
        # Test user not found
        result = await user_repo.update_password(str(uuid.uuid4()), "old", "new")
        assert result is False

    @pytest.mark.asyncio
    async def test_create_user_all_validations(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test all create_user validations (lines 341-359)."""
        # Empty password validation
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repo.create_user("test", "test@example.com", "")

        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repo.create_user("test", "test@example.com", "   ")

        # Create first user
        user1 = await user_repo.create_user("testuser1", "test1@example.com", "password123")
        await async_db_session.commit()

        # Duplicate username validation
        with pytest.raises(ValueError, match="Username 'testuser1' already exists"):
            await user_repo.create_user("testuser1", "different@example.com", "password123")

        # Duplicate email validation
        with pytest.raises(ValueError, match="Email 'test1@example.com' already exists"):
            await user_repo.create_user("differentuser", "test1@example.com", "password123")

        # Email lowercase conversion
        user2 = await user_repo.create_user("testuser2", "TEST2@EXAMPLE.COM", "password123")
        await async_db_session.commit()
        assert user2.email == "test2@example.com"

    @pytest.mark.asyncio
    async def test_update_password_all_validations(self, user_repo: UserRepository, async_db_session: AsyncSession):
        """Test all update password validations (lines 372-390)."""
        # Create user
        user = await user_repo.create_user("pwdtestuser", "pwdtest@example.com", "oldpassword123")
        await async_db_session.commit()

        # Empty new password validation
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repo.update_password(user.id, "oldpassword123", "")

        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repo.update_password(user.id, "oldpassword123", "   ")

        # Wrong old password
        result = await user_repo.update_password(user.id, "wrongpassword", "newpassword123")
        assert result is False

        # Exception handling
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.update_password(user.id, "oldpassword123", "newpassword123")

    @pytest.mark.asyncio
    async def test_verify_email_complete(self, user_repo: UserRepository):
        """Test verify email complete flow (lines 429, 433-435)."""
        # User not found
        result = await user_repo.verify_email(str(uuid.uuid4()))
        assert result is False

        # Exception handling
        with patch.object(user_repo, "get_by_id", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await user_repo.verify_email("test-id")


class TestFinalAPIKeyRepositoryCoverage:
    """Final tests for APIKeyRepository missing lines."""

    @pytest_asyncio.fixture
    async def api_key_repo(self, async_db_session: AsyncSession) -> APIKeyRepository:
        return APIKeyRepository(async_db_session)

    @pytest_asyncio.fixture
    async def test_user(self, async_db_session: AsyncSession):
        user_repo = UserRepository(async_db_session)
        user = await user_repo.create_user("apikeyuser", "apikey@example.com", "password123")
        await async_db_session.commit()
        return user

    @pytest.mark.asyncio
    async def test_create_complete_flow(self, api_key_repo: APIKeyRepository):
        """Test create complete flow (lines 58-60, 85-87)."""
        # User not found
        result = await api_key_repo.create(str(uuid.uuid4()), "Test Key", ["read"])
        assert result is None

        # Exception handling
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.create("user-id", "Test Key", ["read"])

    @pytest.mark.asyncio
    async def test_validate_exception(self, api_key_repo: APIKeyRepository):
        """Test validate exception (lines 119-121)."""
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.validate("some-key")

    @pytest.mark.asyncio
    async def test_revoke_complete_flow(
        self, api_key_repo: APIKeyRepository, test_user, async_db_session: AsyncSession
    ):
        """Test revoke complete flow (lines 227-229, 275)."""
        # Key not found
        result = await api_key_repo.revoke(str(uuid.uuid4()))
        assert result is False

        # Create and revoke key
        key_data = await api_key_repo.create(test_user.id, "Test Key", ["read"])
        await async_db_session.commit()

        result1 = await api_key_repo.revoke(key_data.id)
        assert result1 is True
        await async_db_session.commit()

        # Try to revoke already revoked key
        result2 = await api_key_repo.revoke(key_data.id)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_check_permission_exception(self, api_key_repo: APIKeyRepository):
        """Test check_permission exception (lines 397-399)."""
        with patch.object(api_key_repo, "get_by_id", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.check_permission("test-id", "read")

    @pytest.mark.asyncio
    async def test_record_usage_exception(self, api_key_repo: APIKeyRepository):
        """Test record_usage exception (lines 427-429)."""
        with patch.object(api_key_repo.session, "execute", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await api_key_repo.record_usage("test-id")


class TestFinalAuditLogRepositoryCoverage:
    """Final tests for AuditLogRepository missing lines."""

    @pytest_asyncio.fixture
    async def audit_repo(self, async_db_session: AsyncSession) -> AuditLogRepository:
        return AuditLogRepository(async_db_session)

    @pytest.mark.asyncio
    async def test_create_exception(self, audit_repo: AuditLogRepository):
        """Test create exception (lines 118-122)."""
        with patch.object(audit_repo.session, "add", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.create("test.action", "Test", "123")

    @pytest.mark.asyncio
    async def test_search_exception(self, audit_repo: AuditLogRepository):
        """Test search exception (lines 166-173)."""
        with patch.object(audit_repo.session, "execute", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.search()

    @pytest.mark.asyncio
    async def test_get_entity_history_exception(self, audit_repo: AuditLogRepository):
        """Test get_entity_history exception (line 212)."""
        with patch.object(audit_repo, "search", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_entity_history("User", "123")

    @pytest.mark.asyncio
    async def test_get_actor_activity_exception(self, audit_repo: AuditLogRepository):
        """Test get_actor_activity exception (lines 252-254)."""
        with patch.object(audit_repo, "search", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_actor_activity("actor-123")

    @pytest.mark.asyncio
    async def test_get_statistics_exception(self, audit_repo: AuditLogRepository):
        """Test get_statistics exception (lines 306-308)."""
        with patch.object(audit_repo.session, "execute", side_effect=SQLAlchemyError("DB Error")):
            with pytest.raises(SQLAlchemyError):
                await audit_repo.get_statistics()

    @pytest.mark.asyncio
    async def test_update_prevented_warning(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test update prevented logs warning (line 343)."""
        # Create audit log
        audit_log = await audit_repo.create("test.action", "Test", "123")
        await async_db_session.commit()

        # Mock logger to verify warning is called
        with patch.object(audit_repo.logger, "warning") as mock_warning:
            result = await audit_repo.update(audit_log.id, action="modified")
            assert result is None
            mock_warning.assert_called_once_with(
                "Audit logs are immutable and cannot be updated",
                audit_log_id=audit_log.id,
            )

    @pytest.mark.asyncio
    async def test_delete_prevented_warning(self, audit_repo: AuditLogRepository, async_db_session: AsyncSession):
        """Test delete prevented logs warning (line 421)."""
        # Create audit log
        audit_log = await audit_repo.create("test.action", "Test", "123")
        await async_db_session.commit()

        # Mock logger to verify warning is called
        with patch.object(audit_repo.logger, "warning") as mock_warning:
            result = await audit_repo.delete(audit_log.id)
            assert result is False
            # Check that warning was called
            assert mock_warning.called


# Test for base repository line 304
class TestBaseRepositoryFinalCoverage:
    """Final test for base repository line 304."""

    @pytest.mark.asyncio
    async def test_eager_load_with_valid_relationship(self, async_db_session: AsyncSession):
        """Test eager load with valid relationship (line 304)."""
        from app.models.api_key import APIKey
        from app.repositories.base import BaseRepository

        # APIKey has a 'user' relationship
        repo = BaseRepository(async_db_session, APIKey)

        # This should work fine with valid relationship
        page = await repo.list_with_pagination(eager_load=["user"])
        assert page is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
