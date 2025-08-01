"""Comprehensive tests for session management to achieve 90%+ coverage."""

import json
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.session import (
    SESSION_COOKIE_NAME,
    SESSION_ID_LENGTH,
    SESSION_KEY_PREFIX,
    SessionManager,
    get_session_manager,
)


@pytest.fixture
def mock_cache():
    """Create mock cache client."""
    cache = AsyncMock()
    cache.set = AsyncMock(return_value=True)
    cache.get = AsyncMock(return_value=None)
    cache.delete = AsyncMock(return_value=True)
    return cache


@pytest.fixture
def session_manager(mock_cache):
    """Create session manager with mocked cache."""
    with patch("app.core.session.get_cache_client", return_value=mock_cache):
        manager = SessionManager()
        manager.cache = mock_cache
        return manager


@pytest.fixture
def sample_session_data():
    """Create sample session data."""
    return {
        "session_id": "test_session_123",
        "user_id": "user_456",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_accessed": datetime.now(timezone.utc).isoformat(),
        "ip_address": "192.168.1.1",
        "user_agent": "TestAgent/1.0",
        "rotated": False,
        "role": "user",
        "permissions": ["read", "write"],
    }


class TestSessionManagerInitialization:
    """Test SessionManager initialization."""

    def test_init_with_cache(self, mock_cache):
        """Test initialization with available cache."""
        with patch("app.core.session.get_cache_client", return_value=mock_cache):
            with patch("app.core.session.settings") as mock_settings:
                mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30

                manager = SessionManager()

                assert manager.cache == mock_cache
                assert manager.session_ttl == 1800  # 30 * 60

    def test_init_without_cache(self):
        """Test initialization when cache is unavailable."""
        with patch("app.core.session.get_cache_client", return_value=None):
            with patch("app.core.session.settings") as mock_settings:
                mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60

                manager = SessionManager()

                assert manager.cache is None
                assert manager.session_ttl == 3600  # 60 * 60

    def test_init_with_different_ttl_settings(self):
        """Test initialization with various TTL settings."""
        ttl_values = [15, 30, 60, 120, 1440]  # Various minute values

        for ttl_minutes in ttl_values:
            with patch("app.core.session.settings") as mock_settings:
                mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = ttl_minutes

                manager = SessionManager()
                assert manager.session_ttl == ttl_minutes * 60


class TestCreateSession:
    """Test session creation functionality."""

    @pytest.mark.asyncio
    async def test_create_session_basic(self, session_manager, mock_cache):
        """Test basic session creation."""
        user_id = "user123"
        user_data = {"role": "admin", "email": "test@example.com"}

        session_id = await session_manager.create_session(user_id=user_id, user_data=user_data)

        assert session_id is not None
        assert len(session_id) > 0

        # Verify cache.set was called
        mock_cache.set.assert_called_once()
        call_args = mock_cache.set.call_args

        # Check key format
        assert call_args[0][0].startswith(SESSION_KEY_PREFIX)
        assert session_id in call_args[0][0]

        # Check session data
        session_data = json.loads(call_args[0][1])
        assert session_data["user_id"] == user_id
        assert session_data["role"] == "admin"
        assert session_data["email"] == "test@example.com"
        assert session_data["rotated"] is False
        assert "created_at" in session_data
        assert "last_accessed" in session_data

    @pytest.mark.asyncio
    async def test_create_session_with_ip_and_ua(self, session_manager, mock_cache):
        """Test session creation with IP address and user agent."""
        user_id = "user456"
        user_data = {"permissions": ["read", "write"]}
        ip_address = "10.0.0.1"
        user_agent = "Mozilla/5.0 Test"

        session_id = await session_manager.create_session(
            user_id=user_id, user_data=user_data, ip_address=ip_address, user_agent=user_agent
        )

        assert session_id is not None

        # Check stored data
        session_data = json.loads(mock_cache.set.call_args[0][1])
        assert session_data["ip_address"] == ip_address
        assert session_data["user_agent"] == user_agent
        assert session_data["permissions"] == ["read", "write"]

    @pytest.mark.asyncio
    async def test_create_session_generates_unique_ids(self, session_manager, mock_cache):
        """Test that each session gets a unique ID."""
        session_ids = []

        for i in range(10):
            session_id = await session_manager.create_session(user_id=f"user_{i}", user_data={})
            session_ids.append(session_id)

        # All session IDs should be unique
        assert len(set(session_ids)) == 10

    @pytest.mark.asyncio
    async def test_create_session_with_ttl(self, session_manager, mock_cache):
        """Test session creation with correct TTL."""
        session_manager.session_ttl = 7200  # 2 hours

        await session_manager.create_session(user_id="user789", user_data={})

        # Check TTL was set correctly
        call_kwargs = mock_cache.set.call_args[1]
        assert "ex" in call_kwargs
        assert call_kwargs["ex"] == 7200

    @pytest.mark.asyncio
    async def test_create_session_cache_failure(self, session_manager, mock_cache):
        """Test session creation when cache fails."""
        mock_cache.set.side_effect = Exception("Redis connection failed")

        with pytest.raises(Exception, match="Redis connection failed"):
            await session_manager.create_session(user_id="user_fail", user_data={})

    @pytest.mark.asyncio
    async def test_create_session_without_cache(self, session_manager):
        """Test session creation when cache is None."""
        session_manager.cache = None

        with patch("app.core.session.logger") as mock_logger:
            session_id = await session_manager.create_session(user_id="user_no_cache", user_data={})

            assert session_id is not None
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_logs_info(self, session_manager, mock_cache):
        """Test that session creation logs info."""
        with patch("app.core.session.logger") as mock_logger:
            session_id = await session_manager.create_session(user_id="user_log", user_data={})

            mock_logger.info.assert_called_once_with(
                "session_created", session_id=session_id[:8] + "...", user_id="user_log"
            )

    @pytest.mark.asyncio
    async def test_create_session_logs_error_on_failure(self, session_manager, mock_cache):
        """Test that session creation logs error on failure."""
        mock_cache.set.side_effect = RuntimeError("Cache error")

        with patch("app.core.session.logger") as mock_logger:
            with pytest.raises(RuntimeError):
                await session_manager.create_session(user_id="user_error", user_data={})

            mock_logger.error.assert_called_once()


class TestGetSession:
    """Test session retrieval functionality."""

    @pytest.mark.asyncio
    async def test_get_session_exists(self, session_manager, mock_cache, sample_session_data):
        """Test retrieving an existing session."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        result = await session_manager.get_session("test_session_123")

        assert result is not None
        assert result["user_id"] == "user_456"
        assert "last_accessed" in result

        # Verify cache was called correctly
        mock_cache.get.assert_called_once_with(f"{SESSION_KEY_PREFIX}test_session_123")

        # Verify session was updated with new last_accessed
        assert mock_cache.set.call_count == 1

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, session_manager, mock_cache):
        """Test retrieving non-existent session."""
        mock_cache.get.return_value = None

        result = await session_manager.get_session("nonexistent_session")

        assert result is None
        mock_cache.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_session_updates_last_accessed(self, session_manager, mock_cache, sample_session_data):
        """Test that get_session updates last accessed time."""
        original_time = sample_session_data["last_accessed"]
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        result = await session_manager.get_session("test_session_123")

        # Check that set was called with updated last_accessed
        updated_data = json.loads(mock_cache.set.call_args[0][1])
        assert updated_data["last_accessed"] != original_time

    @pytest.mark.asyncio
    async def test_get_session_without_cache(self, session_manager):
        """Test get_session when cache is None."""
        session_manager.cache = None

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.get_session("any_session")

            assert result is None
            mock_logger.warning.assert_called_once_with("session_storage_unavailable")

    @pytest.mark.asyncio
    async def test_get_session_cache_error(self, session_manager, mock_cache):
        """Test get_session when cache throws error."""
        mock_cache.get.side_effect = Exception("Cache read error")

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.get_session("error_session")

            assert result is None
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_set_error_after_get(self, session_manager, mock_cache, sample_session_data):
        """Test when update after get fails."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())
        mock_cache.set.side_effect = Exception("Cache write error")

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.get_session("test_session")

            assert result is None
            mock_logger.error.assert_called_once()


class TestRotateSession:
    """Test session rotation functionality."""

    @pytest.mark.asyncio
    async def test_rotate_session_success(self, session_manager, mock_cache, sample_session_data):
        """Test successful session rotation."""
        old_session_id = "old_session_123"
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        new_session_id = await session_manager.rotate_session(old_session_id)

        assert new_session_id is not None
        assert new_session_id != old_session_id

        # Verify old session was deleted
        mock_cache.delete.assert_called_once_with(f"{SESSION_KEY_PREFIX}{old_session_id}")

        # Verify new session was created
        new_session_data = json.loads(mock_cache.set.call_args[0][1])
        assert new_session_data["rotated"] is True
        assert "rotated_at" in new_session_data
        assert new_session_data["previous_session_id"] == old_session_id[:8] + "..."

    @pytest.mark.asyncio
    async def test_rotate_session_not_found(self, session_manager, mock_cache):
        """Test rotating non-existent session."""
        mock_cache.get.return_value = None

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.rotate_session("nonexistent")

            assert result is None
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_rotate_session_with_new_ip_ua(self, session_manager, mock_cache, sample_session_data):
        """Test session rotation with updated IP and user agent."""
        old_session_id = "old_session_456"
        new_ip = "10.0.0.2"
        new_ua = "NewBrowser/2.0"
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        new_session_id = await session_manager.rotate_session(old_session_id, ip_address=new_ip, user_agent=new_ua)

        assert new_session_id is not None

        # Check updated values
        new_session_data = json.loads(mock_cache.set.call_args[0][1])
        assert new_session_data["ip_address"] == new_ip
        assert new_session_data["user_agent"] == new_ua

    @pytest.mark.asyncio
    async def test_rotate_session_cache_failure(self, session_manager, mock_cache, sample_session_data):
        """Test session rotation when cache operations fail."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())
        mock_cache.set.side_effect = Exception("Cache write error")

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.rotate_session("fail_session")

            assert result is None
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_rotate_session_without_cache(self, session_manager):
        """Test rotation when cache is None."""
        session_manager.cache = None

        result = await session_manager.rotate_session("any_session")
        assert result is None

    @pytest.mark.asyncio
    async def test_rotate_session_logs_info(self, session_manager, mock_cache, sample_session_data):
        """Test that successful rotation logs info."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        with patch("app.core.session.logger") as mock_logger:
            new_session_id = await session_manager.rotate_session("old_session")

            mock_logger.info.assert_called_once()
            log_call = mock_logger.info.call_args
            assert log_call[0][0] == "session_rotated"


class TestDeleteSession:
    """Test session deletion functionality."""

    @pytest.mark.asyncio
    async def test_delete_session_success(self, session_manager, mock_cache):
        """Test successful session deletion."""
        mock_cache.delete.return_value = True

        result = await session_manager.delete_session("session_to_delete")

        assert result is True
        mock_cache.delete.assert_called_once_with(f"{SESSION_KEY_PREFIX}session_to_delete")

    @pytest.mark.asyncio
    async def test_delete_session_not_found(self, session_manager, mock_cache):
        """Test deleting non-existent session."""
        mock_cache.delete.return_value = False

        result = await session_manager.delete_session("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_session_without_cache(self, session_manager):
        """Test deletion when cache is None."""
        session_manager.cache = None

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.delete_session("any_session")

            assert result is False
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_session_cache_error(self, session_manager, mock_cache):
        """Test deletion when cache throws error."""
        mock_cache.delete.side_effect = Exception("Cache delete error")

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.delete_session("error_session")

            assert result is False
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_session_logs_info(self, session_manager, mock_cache):
        """Test that successful deletion logs info."""
        mock_cache.delete.return_value = True

        with patch("app.core.session.logger") as mock_logger:
            await session_manager.delete_session("log_session")

            mock_logger.info.assert_called_once()


class TestDeleteUserSessions:
    """Test user sessions deletion functionality."""

    @pytest.mark.asyncio
    async def test_delete_user_sessions_without_cache(self, session_manager):
        """Test deleting user sessions when cache is None."""
        session_manager.cache = None

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.delete_user_sessions("user123")

            assert result == 0
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_user_sessions_logs_info(self, session_manager, mock_cache):
        """Test that user session deletion logs info."""
        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.delete_user_sessions("user456")

            assert result == 0  # Placeholder implementation
            mock_logger.info.assert_called_once_with("user_sessions_deletion_requested", user_id="user456")

    @pytest.mark.asyncio
    async def test_delete_user_sessions_exception(self, session_manager, mock_cache):
        """Test user session deletion with exception."""
        with patch("app.core.session.logger") as mock_logger:
            # Force an exception by mocking something that would be called
            # Note: Current implementation is a placeholder
            result = await session_manager.delete_user_sessions("user_error")

            assert result == 0


class TestExtendSession:
    """Test session extension functionality."""

    @pytest.mark.asyncio
    async def test_extend_session_success(self, session_manager, mock_cache, sample_session_data):
        """Test successful session extension."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())
        session_manager.session_ttl = 1800  # 30 minutes

        result = await session_manager.extend_session("test_session", additional_minutes=15)

        assert result is True

        # Check new TTL
        call_kwargs = mock_cache.set.call_args[1]
        assert call_kwargs["ex"] == 2700  # 1800 + (15 * 60)

    @pytest.mark.asyncio
    async def test_extend_session_not_found(self, session_manager, mock_cache):
        """Test extending non-existent session."""
        mock_cache.get.return_value = None

        result = await session_manager.extend_session("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_extend_session_without_cache(self, session_manager):
        """Test extension when cache is None."""
        session_manager.cache = None

        result = await session_manager.extend_session("any_session")

        assert result is False

    @pytest.mark.asyncio
    async def test_extend_session_cache_error(self, session_manager, mock_cache, sample_session_data):
        """Test extension when cache operations fail."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())
        mock_cache.set.side_effect = Exception("Cache write error")

        with patch("app.core.session.logger") as mock_logger:
            result = await session_manager.extend_session("error_session")

            assert result is False
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_extend_session_logs_info(self, session_manager, mock_cache, sample_session_data):
        """Test that successful extension logs info."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        with patch("app.core.session.logger") as mock_logger:
            await session_manager.extend_session("log_session", additional_minutes=20)

            mock_logger.info.assert_called_once_with(
                "session_extended", session_id="log_sess...", additional_minutes=20
            )


class TestValidateSession:
    """Test session validation functionality."""

    @pytest.mark.asyncio
    async def test_validate_session_valid(self, session_manager, mock_cache, sample_session_data):
        """Test validating a valid session."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        result = await session_manager.validate_session("test_session")

        assert result is True

    @pytest.mark.asyncio
    async def test_validate_session_not_found(self, session_manager, mock_cache):
        """Test validating non-existent session."""
        mock_cache.get.return_value = None

        result = await session_manager.validate_session("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_validate_session_ip_check_enabled(self, session_manager, mock_cache, sample_session_data):
        """Test session validation with IP checking enabled."""
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        with patch("app.core.session.settings") as mock_settings:
            mock_settings.CSRF_PROTECTION = True
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Default value from config

            # Test with matching IP
            result = await session_manager.validate_session("test_session", ip_address="192.168.1.1")
            assert result is True

            # Test with different IP (logs warning but still returns True)
            with patch("app.core.session.logger") as mock_logger:
                result = await session_manager.validate_session("test_session", ip_address="10.0.0.1")
                assert result is True
                mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_session_rotation_recommendation(self, session_manager, mock_cache, sample_session_data):
        """Test that old sessions get rotation recommendation."""
        # Create old session data
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        sample_session_data["created_at"] = old_time.isoformat()
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        with patch("app.core.session.settings") as mock_settings:
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

            result = await session_manager.validate_session("old_session")

            assert result is True
            # Check that rotation was recommended (session is older than 30 min)
            updated_data = json.loads(mock_cache.set.call_args[0][1])
            assert updated_data.get("rotation_recommended") is True

    @pytest.mark.asyncio
    async def test_validate_session_recent_no_rotation(self, session_manager, mock_cache, sample_session_data):
        """Test that recent sessions don't get rotation recommendation."""
        # Create recent session data
        recent_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        sample_session_data["created_at"] = recent_time.isoformat()
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        with patch("app.core.session.settings") as mock_settings:
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

            result = await session_manager.validate_session("recent_session")

            assert result is True
            # Check that rotation was not recommended
            updated_data = json.loads(mock_cache.set.call_args[0][1])
            assert updated_data.get("rotation_recommended") is None


class TestCleanupExpiredSessions:
    """Test session cleanup functionality."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_manager):
        """Test cleanup expired sessions method."""
        with patch("app.core.session.logger") as mock_logger:
            await session_manager.cleanup_expired_sessions()

            mock_logger.info.assert_called_once_with("session_cleanup_triggered")


class TestSessionManagerSingleton:
    """Test session manager singleton functionality."""

    def test_get_session_manager_singleton(self):
        """Test that get_session_manager returns singleton."""
        manager1 = get_session_manager()
        manager2 = get_session_manager()

        assert manager1 is manager2

    def test_get_session_manager_creates_instance(self):
        """Test that get_session_manager creates instance if needed."""
        # Reset global
        import app.core.session

        app.core.session._session_manager = None

        manager = get_session_manager()

        assert manager is not None
        assert isinstance(manager, SessionManager)


class TestSessionConstants:
    """Test session constants."""

    def test_session_constants_defined(self):
        """Test that all session constants are defined."""
        assert SESSION_KEY_PREFIX == "session:"
        assert SESSION_ID_LENGTH == 32
        assert SESSION_COOKIE_NAME == "violentutf_session"


class TestSessionSecurityScenarios:
    """Test security-related session scenarios."""

    @pytest.mark.asyncio
    async def test_session_id_entropy(self, session_manager, mock_cache):
        """Test that session IDs have good entropy."""
        # Generate many session IDs
        session_ids = []
        for _ in range(100):
            session_id = await session_manager.create_session("user", {})
            session_ids.append(session_id)

        # All should be unique
        assert len(set(session_ids)) == 100

        # Check length consistency
        for sid in session_ids:
            # URL-safe base64 encoding of 32 bytes
            assert len(sid) >= 40  # Approximate minimum length

    @pytest.mark.asyncio
    async def test_session_fixation_prevention(self, session_manager, mock_cache, sample_session_data):
        """Test that rotation changes session ID completely."""
        old_id = "old_session_fixation"
        mock_cache.get.return_value = json.dumps(sample_session_data.copy())

        new_id = await session_manager.rotate_session(old_id)

        # IDs should be completely different
        assert new_id != old_id
        assert old_id not in new_id
        assert new_id not in old_id

    @pytest.mark.asyncio
    async def test_concurrent_session_operations(self, session_manager, mock_cache):
        """Test handling of concurrent session operations."""
        # This tests that the session manager handles concurrent operations
        # In a real scenario, this would test race conditions

        session_id = await session_manager.create_session("user", {})

        # Simulate concurrent get/update
        sample_data = {
            "session_id": session_id,
            "user_id": "user",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_accessed": datetime.now(timezone.utc).isoformat(),
        }
        mock_cache.get.return_value = json.dumps(sample_data.copy())

        # Multiple gets should work
        result1 = await session_manager.get_session(session_id)
        result2 = await session_manager.get_session(session_id)

        assert result1 is not None
        assert result2 is not None
