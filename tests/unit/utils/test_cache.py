"""Test Redis cache client functionality."""

import asyncio
from typing import Any
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from app.utils.cache import (
    check_cache_health,
    close_cache_connections,
    create_cache_client,
    delete_cached_value,
    get_cache_client,
    get_cached_value,
    set_cached_value,
)


class TestCacheClient:
    """Test cache client creation and management."""

    @patch("app.utils.cache.settings")
    def test_create_cache_client_no_url(self, mock_settings: Any) -> None:
        """Test cache client creation when no Redis URL is configured."""
        mock_settings.REDIS_URL = None

        client = create_cache_client()
        assert client is None

    @patch("app.utils.cache.settings")
    @patch("app.utils.cache.redis.from_url")
    def test_create_cache_client_success(self, mock_from_url: Any, mock_settings: Any) -> None:
        """Test successful cache client creation."""
        mock_settings.REDIS_URL = "redis://localhost:6379/0"
        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        client = create_cache_client()

        assert client == mock_client
        mock_from_url.assert_called_once_with(
            "redis://localhost:6379/0",
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
            retry_on_timeout=True,
            retry_on_error=[ANY, ANY],
            health_check_interval=30,
        )

    @patch("app.utils.cache.settings")
    @patch("app.utils.cache.redis.from_url")
    def test_create_cache_client_exception(self, mock_from_url: Any, mock_settings: Any) -> None:
        """Test cache client creation with exception."""
        mock_settings.REDIS_URL = "redis://invalid"
        mock_from_url.side_effect = Exception("Connection failed")

        client = create_cache_client()
        assert client is None

    def setup_method(self) -> None:
        """Reset global state before each test."""
        import app.utils.cache

        app.utils.cache.cache_client = None

    @patch("app.utils.cache.create_cache_client")
    def test_get_cache_client_creates_new(self, mock_create_client: Any) -> None:
        """Test get_cache_client creates new client when none exists."""
        mock_client = MagicMock()
        mock_create_client.return_value = mock_client

        client = get_cache_client()

        assert client == mock_client
        mock_create_client.assert_called_once()

    @patch("app.utils.cache.create_cache_client")
    def test_get_cache_client_cached(self, mock_create_client: Any) -> None:
        """Test get_cache_client returns cached client."""
        mock_client = MagicMock()
        mock_create_client.return_value = mock_client

        # First call
        client1 = get_cache_client()
        # Second call should use cached version
        client2 = get_cache_client()

        assert client1 == client2
        assert mock_create_client.call_count == 1


class TestCacheHealth:
    """Test cache health check functionality."""

    def setup_method(self) -> None:
        """Reset global state before each test."""
        import app.utils.cache

        app.utils.cache.cache_client = None

    @pytest.mark.asyncio
    @patch("app.utils.cache.settings")
    async def test_check_cache_health_no_url(self, mock_settings: Any) -> None:
        """Test health check when no Redis URL is configured."""
        mock_settings.REDIS_URL = None

        result = await check_cache_health()
        assert result is True

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_check_cache_health_no_client(self, mock_get_client: Any) -> None:
        """Test health check when client is None."""
        mock_get_client.return_value = None

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.REDIS_URL = "redis://localhost"

            result = await check_cache_health()
            assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_check_cache_health_success(self, mock_get_client: Any) -> None:
        """Test successful cache health check."""
        mock_client = AsyncMock()
        mock_client.ping.return_value = True
        mock_get_client.return_value = mock_client

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.REDIS_URL = "redis://localhost"

            result = await check_cache_health()
            assert result is True
            mock_client.ping.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_check_cache_health_no_pong(self, mock_get_client: Any) -> None:
        """Test health check when ping returns False."""
        mock_client = AsyncMock()
        mock_client.ping.return_value = False
        mock_get_client.return_value = mock_client

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.REDIS_URL = "redis://localhost"

            result = await check_cache_health()
            assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_check_cache_health_timeout(self, mock_get_client: Any) -> None:
        """Test health check timeout."""
        mock_client = AsyncMock()
        mock_client.ping.side_effect = asyncio.TimeoutError()
        mock_get_client.return_value = mock_client

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.REDIS_URL = "redis://localhost"

            result = await check_cache_health(timeout=0.1)
            assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_check_cache_health_exception(self, mock_get_client: Any) -> None:
        """Test health check with Redis exception."""
        mock_client = AsyncMock()
        mock_client.ping.side_effect = Exception("Redis error")
        mock_get_client.return_value = mock_client

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.REDIS_URL = "redis://localhost"

            result = await check_cache_health()
            assert result is False


class TestCacheOperations:
    """Test cache get/set/delete operations."""

    def setup_method(self) -> None:
        """Reset global state before each test."""
        import app.utils.cache

        app.utils.cache.cache_client = None

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_get_cached_value_no_client(self, mock_get_client: Any) -> None:
        """Test get_cached_value when client is None."""
        mock_get_client.return_value = None

        result = await get_cached_value("test_key")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_get_cached_value_success(self, mock_get_client: Any) -> None:
        """Test successful cache value retrieval."""
        mock_client = AsyncMock()
        mock_client.get.return_value = "test_value"
        mock_get_client.return_value = mock_client

        result = await get_cached_value("test_key")

        assert result == "test_value"
        mock_client.get.assert_called_once_with("test_key")

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_get_cached_value_exception(self, mock_get_client: Any) -> None:
        """Test get_cached_value with Redis exception."""
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Redis error")
        mock_get_client.return_value = mock_client

        result = await get_cached_value("test_key")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_set_cached_value_no_client(self, mock_get_client: Any) -> None:
        """Test set_cached_value when client is None."""
        mock_get_client.return_value = None

        result = await set_cached_value("test_key", "test_value")
        assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_set_cached_value_success(self, mock_get_client: Any) -> None:
        """Test successful cache value setting."""
        mock_client = AsyncMock()
        mock_client.setex.return_value = True
        mock_get_client.return_value = mock_client

        with patch("app.utils.cache.settings") as mock_settings:
            mock_settings.CACHE_TTL = 300

            result = await set_cached_value("test_key", "test_value")

            assert result is True
            mock_client.setex.assert_called_once_with("test_key", 300, "test_value")

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_set_cached_value_custom_ttl(self, mock_get_client: Any) -> None:
        """Test cache value setting with custom TTL."""
        mock_client = AsyncMock()
        mock_client.setex.return_value = True
        mock_get_client.return_value = mock_client

        result = await set_cached_value("test_key", "test_value", ttl=600)

        assert result is True
        mock_client.setex.assert_called_once_with("test_key", 600, "test_value")

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_set_cached_value_exception(self, mock_get_client: Any) -> None:
        """Test set_cached_value with Redis exception."""
        mock_client = AsyncMock()
        mock_client.setex.side_effect = Exception("Redis error")
        mock_get_client.return_value = mock_client

        result = await set_cached_value("test_key", "test_value")
        assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_delete_cached_value_no_client(self, mock_get_client: Any) -> None:
        """Test delete_cached_value when client is None."""
        mock_get_client.return_value = None

        result = await delete_cached_value("test_key")
        assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_delete_cached_value_success(self, mock_get_client: Any) -> None:
        """Test successful cache value deletion."""
        mock_client = AsyncMock()
        mock_client.delete.return_value = 1  # Number of keys deleted
        mock_get_client.return_value = mock_client

        result = await delete_cached_value("test_key")

        assert result is True
        mock_client.delete.assert_called_once_with("test_key")

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_delete_cached_value_not_found(self, mock_get_client: Any) -> None:
        """Test cache value deletion when key doesn't exist."""
        mock_client = AsyncMock()
        mock_client.delete.return_value = 0  # No keys deleted
        mock_get_client.return_value = mock_client

        result = await delete_cached_value("test_key")
        assert result is False

    @pytest.mark.asyncio
    @patch("app.utils.cache.get_cache_client")
    async def test_delete_cached_value_exception(self, mock_get_client: Any) -> None:
        """Test delete_cached_value with Redis exception."""
        mock_client = AsyncMock()
        mock_client.delete.side_effect = Exception("Redis error")
        mock_get_client.return_value = mock_client

        result = await delete_cached_value("test_key")
        assert result is False


class TestCacheShutdown:
    """Test cache connection cleanup."""

    @pytest.mark.asyncio
    async def test_close_cache_connections_no_client(self) -> None:
        """Test closing connections when no client exists."""
        import app.utils.cache

        app.utils.cache.cache_client = None

        # Should not raise exception
        await close_cache_connections()

    @pytest.mark.asyncio
    async def test_close_cache_connections_success(self) -> None:
        """Test successful connection closure."""
        mock_client = AsyncMock()

        with patch("app.utils.cache.cache_client", mock_client):
            await close_cache_connections()

            mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_cache_connections_resets_global(self) -> None:
        """Test that closing connections resets global client."""
        import app.utils.cache

        mock_client = AsyncMock()
        app.utils.cache.cache_client = mock_client

        await close_cache_connections()

        assert app.utils.cache.cache_client is None
