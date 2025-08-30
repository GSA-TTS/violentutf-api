"""Integration tests for APIKeyRepository with real database operations."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.models.user import User
from app.repositories.api_key import APIKeyRepository
from app.repositories.user import UserRepository


class TestAPIKeyRepository:
    """Test APIKeyRepository specific functionality."""

    @pytest_asyncio.fixture
    async def user_repo(self, async_db_session: AsyncSession) -> UserRepository:
        """Create a user repository."""
        return UserRepository(async_db_session)

    @pytest_asyncio.fixture
    async def api_key_repo(self, async_db_session: AsyncSession) -> APIKeyRepository:
        """Create an API key repository."""
        return APIKeyRepository(async_db_session)

    @pytest_asyncio.fixture
    async def test_user(self, user_repo: UserRepository, async_db_session: AsyncSession) -> User:
        """Create a test user."""
        user = await user_repo.create_user(username="api_test_user", email="apitest@example.com", password="password")
        await async_db_session.commit()
        return user

    @staticmethod
    def generate_key_hash(key: str) -> str:
        """Generate SHA256 hash of API key."""
        return hashlib.sha256(key.encode()).hexdigest()

    @pytest.mark.asyncio
    async def test_create_api_key_success(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test creating API key."""
        key = "test_api_key_12345"
        key_hash = self.generate_key_hash(key)
        key_prefix = key[:8]

        api_key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Test Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            permissions={"read": True, "write": False},
            description="Test API key",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_by="admin",
        )
        await async_db_session.commit()

        assert api_key.user_id == test_user.id
        assert api_key.name == "Test Key"
        assert api_key.key_hash == key_hash
        assert api_key.key_prefix == key_prefix
        assert api_key.permissions == {"read": True, "write": False}
        assert api_key.description == "Test API key"
        assert api_key.expires_at is not None
        assert api_key.usage_count == 0
        assert api_key.created_by == "admin"

    @pytest.mark.asyncio
    async def test_create_api_key_duplicate_name(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test creating API key with duplicate name for same user."""
        # Create first key
        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Duplicate Name",
            key_hash=self.generate_key_hash("key1"),
            key_prefix="key1_pre",
        )
        await async_db_session.commit()

        # Try to create duplicate
        with pytest.raises(ValueError, match="API key name 'Duplicate Name' already exists"):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name="Duplicate Name",
                key_hash=self.generate_key_hash("key2"),
                key_prefix="key2_pre",
            )

    @pytest.mark.asyncio
    async def test_create_api_key_invalid_hash(self, api_key_repo: APIKeyRepository, test_user: User):
        """Test creating API key with invalid hash."""
        with pytest.raises(ValueError, match="key_hash must be a valid SHA256 hash"):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name="Invalid Hash",
                key_hash="invalid",
                key_prefix="invalid_",  # Too short
            )

    @pytest.mark.asyncio
    async def test_create_api_key_short_prefix(self, api_key_repo: APIKeyRepository, test_user: User):
        """Test creating API key with short prefix."""
        with pytest.raises(ValueError, match="key_prefix must be at least 6 characters"):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name="Short Prefix",
                key_hash=self.generate_key_hash("key"),
                key_prefix="short",  # Too short
            )

    @pytest.mark.asyncio
    async def test_get_by_hash_existing(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting API key by hash."""
        key = "test_key_hash"
        key_hash = self.generate_key_hash(key)

        # Create key
        created = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Hash Test",
            key_hash=key_hash,
            key_prefix=key[:8],
        )
        await async_db_session.commit()

        # Get by hash
        found = await api_key_repo.get_by_hash(key_hash)
        assert found is not None
        assert found.id == created.id
        assert found.key_hash == key_hash

    @pytest.mark.asyncio
    async def test_get_by_hash_nonexistent(self, api_key_repo: APIKeyRepository):
        """Test getting non-existent API key by hash."""
        found = await api_key_repo.get_by_hash(self.generate_key_hash("nonexistent"))
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_hash_expired(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting expired API key by hash returns None."""
        key = "expired_key"
        key_hash = self.generate_key_hash(key)

        # Create expired key
        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Expired Key",
            key_hash=key_hash,
            key_prefix=key[:8],
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),  # Expired
        )
        await async_db_session.commit()

        # Get by hash should return None
        found = await api_key_repo.get_by_hash(key_hash)
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_hash_soft_deleted(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting soft-deleted API key by hash returns None."""
        key = "deleted_key"
        key_hash = self.generate_key_hash(key)

        # Create and delete key
        created = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Deleted Key",
            key_hash=key_hash,
            key_prefix=key[:8],
        )
        await async_db_session.commit()

        await api_key_repo.delete(created.id, hard_delete=False)
        await async_db_session.commit()

        # Get by hash should return None
        found = await api_key_repo.get_by_hash(key_hash)
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_prefix(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting API keys by prefix."""
        prefix = "prefix_"

        # Create multiple keys with same prefix
        for i in range(3):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name=f"Prefix Key {i}",
                key_hash=self.generate_key_hash(f"key_{i}"),
                key_prefix=prefix,
            )
        await async_db_session.commit()

        # Get by prefix
        keys = await api_key_repo.get_by_prefix(prefix)
        assert len(keys) == 3
        assert all(k.key_prefix == prefix for k in keys)
        # Should be ordered by created_at desc
        assert keys[0].created_at >= keys[1].created_at

    @pytest.mark.asyncio
    async def test_get_by_prefix_excludes_deleted(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting by prefix excludes soft-deleted keys."""
        prefix = "delprefix_"

        # Create two keys
        key1 = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Active Prefix",
            key_hash=self.generate_key_hash("active"),
            key_prefix=prefix,
        )
        key2 = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Deleted Prefix",
            key_hash=self.generate_key_hash("deleted"),
            key_prefix=prefix,
        )
        await async_db_session.commit()

        # Delete one
        await api_key_repo.delete(key2.id, hard_delete=False)
        await async_db_session.commit()

        # Get by prefix
        keys = await api_key_repo.get_by_prefix(prefix)
        assert len(keys) == 1
        assert keys[0].id == key1.id

    @pytest.mark.asyncio
    async def test_get_by_user_id(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting API keys by user ID."""
        # Create keys for user
        for i in range(3):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name=f"User Key {i}",
                key_hash=self.generate_key_hash(f"userkey_{i}"),
                key_prefix=f"userkey{i}",
            )
        await async_db_session.commit()

        # Get by user ID
        keys = await api_key_repo.get_by_user_id(test_user.id)
        assert len(keys) >= 3
        assert all(k.user_id == test_user.id for k in keys)

    @pytest.mark.asyncio
    async def test_get_by_user_id_excludes_expired(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting by user ID excludes expired keys by default."""
        # Create active and expired keys
        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Active Key",
            key_hash=self.generate_key_hash("active"),
            key_prefix="active_",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Expired Key",
            key_hash=self.generate_key_hash("expired"),
            key_prefix="expired",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        await async_db_session.commit()

        # Get without expired
        keys = await api_key_repo.get_by_user_id(test_user.id, include_expired=False)
        assert all(not k.is_expired() for k in keys)
        assert all("Expired" not in k.name for k in keys)

    @pytest.mark.asyncio
    async def test_get_by_user_id_include_expired(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting by user ID including expired keys."""
        # Create expired key
        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Include Expired",
            key_hash=self.generate_key_hash("include_exp"),
            key_prefix="inc_exp",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        await async_db_session.commit()

        # Get with expired
        keys = await api_key_repo.get_by_user_id(test_user.id, include_expired=True)
        expired_keys = [k for k in keys if k.is_expired()]
        assert len(expired_keys) > 0

    @pytest.mark.asyncio
    async def test_get_by_name_and_user(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting API key by name and user."""
        # Create key
        created = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Named Key",
            key_hash=self.generate_key_hash("named"),
            key_prefix="named__",
        )
        await async_db_session.commit()

        # Get by name and user
        found = await api_key_repo.get_by_name_and_user("Named Key", test_user.id)
        assert found is not None
        assert found.id == created.id

    @pytest.mark.asyncio
    async def test_get_by_name_and_user_nonexistent(self, api_key_repo: APIKeyRepository, test_user: User):
        """Test getting non-existent key by name and user."""
        found = await api_key_repo.get_by_name_and_user("Nonexistent", test_user.id)
        assert found is None

    @pytest.mark.asyncio
    async def test_record_usage(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test recording API key usage."""
        # Create key
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Usage Key",
            key_hash=self.generate_key_hash("usage"),
            key_prefix="usage__",
        )
        await async_db_session.commit()

        original_count = key.usage_count
        original_version = key.version

        # Record usage
        result = await api_key_repo.record_usage(
            key.id, ip_address="192.168.1.100", usage_metadata={"endpoint": "/api/test"}
        )
        await async_db_session.commit()

        assert result is True

        # Check updated
        updated = await api_key_repo.get_by_id(key.id)
        assert updated.usage_count == original_count + 1
        assert updated.last_used_at is not None
        assert updated.last_used_ip == "192.168.1.100"
        assert updated.version == original_version + 1

    @pytest.mark.asyncio
    async def test_record_usage_nonexistent(self, api_key_repo: APIKeyRepository):
        """Test recording usage for non-existent key."""
        result = await api_key_repo.record_usage(str(uuid.uuid4()))
        assert result is False

    @pytest.mark.asyncio
    async def test_check_permission_allowed(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test checking permission when allowed."""
        # Create key with permissions
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Permission Key",
            key_hash=self.generate_key_hash("perm"),
            key_prefix="perm___",
            permissions={"read": True, "write": True, "admin": False},
        )
        await async_db_session.commit()

        # Check permissions
        assert await api_key_repo.check_permission(key.id, "read") is True
        assert await api_key_repo.check_permission(key.id, "write") is True
        assert await api_key_repo.check_permission(key.id, "admin") is False
        assert await api_key_repo.check_permission(key.id, "nonexistent") is False

    @pytest.mark.asyncio
    async def test_check_permission_expired(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test checking permission on expired key."""
        # Create expired key
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Expired Perm",
            key_hash=self.generate_key_hash("exp_perm"),
            key_prefix="exp_per",
            permissions={"read": True},
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        await async_db_session.commit()

        # Check permission should fail
        assert await api_key_repo.check_permission(key.id, "read") is False

    @pytest.mark.asyncio
    async def test_check_permission_nonexistent(self, api_key_repo: APIKeyRepository):
        """Test checking permission for non-existent key."""
        result = await api_key_repo.check_permission(str(uuid.uuid4()), "read")
        assert result is False

    @pytest.mark.asyncio
    async def test_update_permissions(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test updating API key permissions."""
        # Create key
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Update Perms",
            key_hash=self.generate_key_hash("upd_perm"),
            key_prefix="upd_per",
            permissions={"read": True},
        )
        await async_db_session.commit()

        # Update permissions
        new_perms = {"read": True, "write": True, "delete": False}
        result = await api_key_repo.update_permissions(key.id, new_perms, updated_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check updated
        updated = await api_key_repo.get_by_id(key.id)
        assert updated.permissions == new_perms
        assert updated.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_update_permissions_nonexistent(self, api_key_repo: APIKeyRepository):
        """Test updating permissions for non-existent key."""
        result = await api_key_repo.update_permissions(str(uuid.uuid4()), {"read": True})
        assert result is False

    @pytest.mark.asyncio
    async def test_extend_expiration(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test extending API key expiration."""
        # Create key with expiration
        original_exp = datetime.now(timezone.utc) + timedelta(days=7)
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Extend Exp",
            key_hash=self.generate_key_hash("ext_exp"),
            key_prefix="ext_exp",
            expires_at=original_exp,
        )
        await async_db_session.commit()

        # Extend expiration
        new_exp = datetime.now(timezone.utc) + timedelta(days=30)
        result = await api_key_repo.extend_expiration(key.id, new_exp, updated_by="admin")
        await async_db_session.commit()

        assert result is True

        # Check updated
        updated = await api_key_repo.get_by_id(key.id)
        assert updated.expires_at > original_exp
        assert updated.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_extend_expiration_remove(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test removing expiration from API key."""
        # Create key with expiration
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Remove Exp",
            key_hash=self.generate_key_hash("rem_exp"),
            key_prefix="rem_exp",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await async_db_session.commit()

        # Remove expiration
        result = await api_key_repo.extend_expiration(key.id, None)
        await async_db_session.commit()

        assert result is True

        # Check updated
        updated = await api_key_repo.get_by_id(key.id)
        assert updated.expires_at is None

    @pytest.mark.asyncio
    async def test_extend_expiration_nonexistent(self, api_key_repo: APIKeyRepository):
        """Test extending expiration for non-existent key."""
        result = await api_key_repo.extend_expiration(str(uuid.uuid4()), datetime.now(timezone.utc))
        assert result is False

    @pytest.mark.asyncio
    async def test_get_expired_keys(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting expired keys for cleanup."""
        # Create mix of expired and active keys
        for i in range(3):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name=f"Expired {i}",
                key_hash=self.generate_key_hash(f"expired_{i}"),
                key_prefix=f"exp_{i}_",
                expires_at=datetime.now(timezone.utc) - timedelta(days=i + 1),
            )

        await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Active",
            key_hash=self.generate_key_hash("active"),
            key_prefix="active_",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        await async_db_session.commit()

        # Get expired keys
        expired = await api_key_repo.get_expired_keys(limit=10)

        assert len(expired) >= 3
        assert all(k.is_expired() for k in expired)
        # Should be ordered by expiration (oldest first)
        if len(expired) > 1:
            assert expired[0].expires_at <= expired[1].expires_at

    @pytest.mark.asyncio
    async def test_get_expired_keys_limit(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting expired keys respects limit."""
        # Create many expired keys
        for i in range(10):
            await api_key_repo.create_api_key(
                user_id=test_user.id,
                name=f"Exp Limited {i}",
                key_hash=self.generate_key_hash(f"exp_lim_{i}"),
                key_prefix=f"exlim{i}",
                expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            )
        await async_db_session.commit()

        # Get with limit
        expired = await api_key_repo.get_expired_keys(limit=5)
        assert len(expired) <= 5

    @pytest.mark.asyncio
    async def test_get_expired_keys_excludes_deleted(
        self,
        api_key_repo: APIKeyRepository,
        test_user: User,
        async_db_session: AsyncSession,
    ):
        """Test getting expired keys excludes soft-deleted."""
        # Create expired key and delete it
        key = await api_key_repo.create_api_key(
            user_id=test_user.id,
            name="Exp Deleted",
            key_hash=self.generate_key_hash("exp_del"),
            key_prefix="expdel_",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        await async_db_session.commit()

        await api_key_repo.delete(key.id, hard_delete=False)
        await async_db_session.commit()

        # Should not appear in expired list
        expired = await api_key_repo.get_expired_keys()
        expired_ids = [k.id for k in expired]
        assert key.id not in expired_ids
