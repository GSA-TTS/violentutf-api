"""Tests for session manager core functionality."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.session import SessionManager, get_session_manager


@pytest.fixture
def mock_cache():
    """Mock cache client."""
    cache = AsyncMock()
    return cache


@pytest.fixture
def session_manager(mock_cache):
    """Create session manager with mocked cache."""
    with patch("app.core.session.get_cache_client", return_value=mock_cache):
        manager = SessionManager()
        manager.cache = mock_cache
        return manager


class TestSessionManager:
    """Test session manager functionality."""

    @pytest.mark.asyncio
    async def test_create_session_success(self, session_manager, mock_cache):
        """Test successful session creation."""
        mock_cache.set.return_value = None

        session_id = await session_manager.create_session(
            user_id="user_123",
            user_data={"role": "admin"},
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
        )

        assert session_id is not None
        assert len(session_id) > 0

        # Verify cache.set was called
        mock_cache.set.assert_called_once()
        call_args = mock_cache.set.call_args

        # Check session key format
        session_key = call_args[0][0]
        assert session_key.startswith("session:")
        assert session_id in session_key

        # Check session data (it's JSON-encoded)
        session_data_json = call_args[0][1]
        session_data = json.loads(session_data_json)
        assert session_data["user_id"] == "user_123"
        assert session_data["role"] == "admin"
        assert session_data["ip_address"] == "192.168.1.1"
        assert session_data["user_agent"] == "TestAgent/1.0"
        assert "created_at" in session_data
        assert "last_accessed" in session_data

    @pytest.mark.asyncio
    async def test_create_session_without_cache(self):
        """Test session creation when cache is unavailable."""
        with patch("app.core.session.get_cache_client", return_value=None):
            manager = SessionManager()

            session_id = await manager.create_session(user_id="user_123", user_data={"role": "admin"})

            # Should still return session ID even without cache
            assert session_id is not None

    @pytest.mark.asyncio
    async def test_get_session_success(self, session_manager, mock_cache):
        """Test successful session retrieval."""
        # Mock cache return value
        session_data = {
            "session_id": "test_session_123",
            "user_id": "user_456",
            "role": "user",
            "created_at": "2024-01-01T00:00:00Z",
            "last_accessed": "2024-01-01T00:05:00Z",
        }
        mock_cache.get.return_value = json.dumps(session_data)
        mock_cache.set.return_value = None  # For updating last_accessed

        result = await session_manager.get_session("test_session_123")

        assert result is not None
        assert result["user_id"] == "user_456"
        assert "last_accessed" in result

        # Verify cache was updated with new last_accessed time
        mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, session_manager, mock_cache):
        """Test session retrieval when session doesn't exist."""
        mock_cache.get.return_value = None

        result = await session_manager.get_session("nonexistent_session")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_session_without_cache(self):
        """Test session retrieval without cache."""
        with patch("app.core.session.get_cache_client", return_value=None):
            manager = SessionManager()

            result = await manager.get_session("test_session")

            assert result is None

    @pytest.mark.asyncio
    async def test_rotate_session_success(self, session_manager, mock_cache):
        """Test successful session rotation."""
        # Mock existing session
        old_session_data = {
            "session_id": "old_session_123",
            "user_id": "user_456",
            "role": "admin",
            "created_at": "2024-01-01T00:00:00Z",
            "last_accessed": "2024-01-01T00:05:00Z",
        }
        mock_cache.get.return_value = json.dumps(old_session_data)
        mock_cache.set.return_value = None
        mock_cache.delete.return_value = True

        new_session_id = await session_manager.rotate_session(
            "old_session_123", ip_address="192.168.1.2", user_agent="NewAgent/2.0"
        )

        assert new_session_id is not None
        assert new_session_id != "old_session_123"

        # Verify old session was deleted
        mock_cache.delete.assert_called_once()

        # Verify new session was created
        assert mock_cache.set.call_count >= 1  # At least one call for new session

    @pytest.mark.asyncio
    async def test_rotate_session_not_found(self, session_manager, mock_cache):
        """Test session rotation when original session doesn't exist."""
        mock_cache.get.return_value = None

        result = await session_manager.rotate_session("nonexistent_session")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_session_success(self, session_manager, mock_cache):
        """Test successful session deletion."""
        mock_cache.delete.return_value = True

        result = await session_manager.delete_session("test_session_123")

        assert result is True
        mock_cache.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_session_not_found(self, session_manager, mock_cache):
        """Test session deletion when session doesn't exist."""
        mock_cache.delete.return_value = False

        result = await session_manager.delete_session("nonexistent_session")

        assert result is False

    @pytest.mark.asyncio
    async def test_extend_session_success(self, session_manager, mock_cache):
        """Test successful session extension."""
        # Mock existing session
        session_data = {
            "session_id": "test_session_123",
            "user_id": "user_456",
            "created_at": "2024-01-01T00:00:00Z",
        }
        mock_cache.get.return_value = json.dumps(session_data)
        mock_cache.set.return_value = None

        result = await session_manager.extend_session("test_session_123", 60)

        assert result is True

        # Verify session was updated with new TTL
        mock_cache.set.assert_called()
        call_args = mock_cache.set.call_args

        # Check that expire parameter was set
        assert "ex" in call_args[1]
        expire_time = call_args[1]["ex"]
        assert expire_time > session_manager.session_ttl

    @pytest.mark.asyncio
    async def test_extend_session_not_found(self, session_manager, mock_cache):
        """Test session extension when session doesn't exist."""
        mock_cache.get.return_value = None

        result = await session_manager.extend_session("nonexistent_session", 60)

        assert result is False

    @pytest.mark.asyncio
    async def test_validate_session_success(self, session_manager, mock_cache):
        """Test successful session validation."""
        session_data = {
            "session_id": "test_session_123",
            "user_id": "user_456",
            "ip_address": "192.168.1.1",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        mock_cache.get.return_value = json.dumps(session_data)
        mock_cache.set.return_value = None

        result = await session_manager.validate_session("test_session_123", ip_address="192.168.1.1")

        assert result is True

    @pytest.mark.asyncio
    async def test_validate_session_not_found(self, session_manager, mock_cache):
        """Test session validation when session doesn't exist."""
        mock_cache.get.return_value = None

        result = await session_manager.validate_session("nonexistent_session")

        assert result is False

    @pytest.mark.asyncio
    async def test_validate_session_ip_mismatch(self, session_manager, mock_cache):
        """Test session validation with IP address mismatch."""
        session_data = {
            "session_id": "test_session_123",
            "user_id": "user_456",
            "ip_address": "192.168.1.1",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        mock_cache.get.return_value = json.dumps(session_data)
        mock_cache.set.return_value = None

        # Different IP address
        result = await session_manager.validate_session("test_session_123", ip_address="192.168.1.2")

        # Should still return True but log warning
        assert result is True

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_manager):
        """Test cleanup of expired sessions."""
        # This is mostly a placeholder method
        await session_manager.cleanup_expired_sessions()

        # No assertions needed as Redis handles TTL automatically

    @pytest.mark.asyncio
    async def test_session_manager_cache_error_handling(self, session_manager, mock_cache):
        """Test error handling when cache operations fail."""
        # Mock cache to raise exception
        mock_cache.set.side_effect = ConnectionError("Redis connection failed")

        # Should raise exception for create_session
        with pytest.raises(ConnectionError):
            await session_manager.create_session("user_123", {})

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method_name,args",
        [
            ("get_session", ("test_session",)),
            ("delete_session", ("test_session",)),
            ("extend_session", ("test_session", 60)),
        ],
    )
    async def test_cache_error_handling(self, session_manager, mock_cache, method_name, args):
        """Test error handling for various cache operations."""
        # Mock cache method to raise exception
        getattr(mock_cache, method_name.split("_")[0]).side_effect = Exception("Cache error")

        method = getattr(session_manager, method_name)
        result = await method(*args)

        # Should handle errors gracefully
        if method_name in ["delete_session", "extend_session"]:
            assert result is False
        else:
            assert result is None


class TestSessionManagerSingleton:
    """Test session manager singleton functionality."""

    def test_get_session_manager_singleton(self):
        """Test that get_session_manager returns the same instance."""
        manager1 = get_session_manager()
        manager2 = get_session_manager()

        assert manager1 is manager2

    def test_session_manager_initialization(self):
        """Test session manager initialization."""
        manager = SessionManager()

        assert manager.session_ttl > 0
        assert hasattr(manager, "cache")

    @patch("app.core.session.settings")
    def test_session_ttl_configuration(self, mock_settings):
        """Test session TTL configuration from settings."""
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60

        manager = SessionManager()

        assert manager.session_ttl == 3600  # 60 minutes * 60 seconds
