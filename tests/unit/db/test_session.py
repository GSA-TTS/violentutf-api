"""Test database session management."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.session import (
    check_database_health,
    close_database_connections,
    create_database_engine,
    get_db,
    get_session_maker,
)


class TestDatabaseEngine:
    """Test database engine creation."""

    @patch("app.db.session.settings")
    def test_create_database_engine_no_url(self, mock_settings: Any) -> None:
        """Test engine creation when no database URL is configured."""
        mock_settings.DATABASE_URL = None

        engine = create_database_engine()
        assert engine is None

    @patch("app.db.session.settings")
    @patch("app.db.session.create_async_engine")
    def test_create_database_engine_success(self, mock_create_engine: Any, mock_settings: Any) -> None:
        """Test successful engine creation."""
        mock_settings.DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/test"  # pragma: allowlist secret
        mock_settings.DEBUG = False
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine

        engine = create_database_engine()

        assert engine == mock_engine
        mock_create_engine.assert_called_once_with(
            "postgresql+asyncpg://user:pass@localhost/test",  # pragma: allowlist secret
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

    @patch("app.db.session.settings")
    @patch("app.db.session.create_async_engine")
    def test_create_database_engine_exception(self, mock_create_engine: Any, mock_settings: Any) -> None:
        """Test engine creation with exception."""
        mock_settings.DATABASE_URL = "invalid://url"
        mock_create_engine.side_effect = Exception("Connection failed")

        engine = create_database_engine()
        assert engine is None


class TestSessionMaker:
    """Test session maker functionality."""

    def setup_method(self) -> None:
        """Reset global state before each test."""
        import app.db.session

        app.db.session.engine = None
        app.db.session.async_session_maker = None

    @patch("app.db.session.create_database_engine")
    def test_get_session_maker_no_engine(self, mock_create_engine: Any) -> None:
        """Test session maker when engine creation fails."""
        mock_create_engine.return_value = None

        session_maker = get_session_maker()
        assert session_maker is None

    @patch("app.db.session.create_database_engine")
    @patch("app.db.session.async_sessionmaker")
    def test_get_session_maker_success(self, mock_sessionmaker: Any, mock_create_engine: Any) -> None:
        """Test successful session maker creation."""
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_session_maker = MagicMock()
        mock_sessionmaker.return_value = mock_session_maker

        session_maker = get_session_maker()

        assert session_maker == mock_session_maker
        mock_sessionmaker.assert_called_once()

    @patch("app.db.session.create_database_engine")
    def test_get_session_maker_cached(self, mock_create_engine: Any) -> None:
        """Test that session maker is cached after first creation."""
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine

        with patch("app.db.session.async_sessionmaker") as mock_sessionmaker:
            mock_session_maker = MagicMock()
            mock_sessionmaker.return_value = mock_session_maker

            # First call
            session_maker1 = get_session_maker()
            # Second call should use cached version
            session_maker2 = get_session_maker()

            assert session_maker1 == session_maker2
            assert mock_sessionmaker.call_count == 1


class TestDatabaseContext:
    """Test database context manager."""

    def setup_method(self) -> None:
        """Reset global state before each test."""
        import app.db.session

        app.db.session.engine = None
        app.db.session.async_session_maker = None

    @pytest.mark.asyncio
    async def test_get_db_no_session_maker(self) -> None:
        """Test get_db when session maker is None."""
        with patch("app.db.session.get_session_maker") as mock_get_session_maker:
            mock_get_session_maker.return_value = None

            with pytest.raises(RuntimeError, match="Database not configured"):
                async with get_db():
                    pass

    @pytest.mark.asyncio
    async def test_get_db_success(self) -> None:
        """Test successful database context usage."""
        mock_session = AsyncMock()
        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__.return_value = mock_session
        mock_session_maker.return_value.__aexit__.return_value = None

        with patch("app.db.session.get_session_maker") as mock_get_session_maker:
            mock_get_session_maker.return_value = mock_session_maker

            async with get_db() as db:
                assert db == mock_session

            mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_exception_rollback(self) -> None:
        """Test database context with exception triggers rollback."""
        mock_session = AsyncMock()
        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__.return_value = mock_session
        mock_session_maker.return_value.__aexit__.return_value = None

        with patch("app.db.session.get_session_maker") as mock_get_session_maker:
            mock_get_session_maker.return_value = mock_session_maker

            with pytest.raises(ValueError):
                async with get_db():
                    raise ValueError("Test exception")

            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()


class TestDatabaseHealth:
    """Test database health check functionality."""

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_database_health_no_url(self, mock_settings: Any) -> None:
        """Test health check when no database URL is configured."""
        mock_settings.DATABASE_URL = None

        result = await check_database_health()
        assert result is True

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_success(self, mock_get_db: Any) -> None:
        """Test successful database health check."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (1,)
        mock_session.execute.return_value = mock_result

        mock_get_db.return_value.__aenter__.return_value = mock_session
        mock_get_db.return_value.__aexit__.return_value = None

        with patch("app.db.session.settings") as mock_settings:
            mock_settings.DATABASE_URL = "postgresql://test"

            result = await check_database_health()
            assert result is True

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_wrong_result(self, mock_get_db: Any) -> None:
        """Test health check with unexpected query result."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (2,)  # Wrong result
        mock_session.execute.return_value = mock_result

        mock_get_db.return_value.__aenter__.return_value = mock_session
        mock_get_db.return_value.__aexit__.return_value = None

        with patch("app.db.session.settings") as mock_settings:
            mock_settings.DATABASE_URL = "postgresql://test"

            result = await check_database_health()
            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_timeout(self, mock_get_db: Any) -> None:
        """Test health check timeout."""
        mock_get_db.side_effect = asyncio.TimeoutError()

        with patch("app.db.session.settings") as mock_settings:
            mock_settings.DATABASE_URL = "postgresql://test"

            result = await check_database_health(timeout=0.1)
            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_exception(self, mock_get_db: Any) -> None:
        """Test health check with database exception."""
        mock_get_db.side_effect = Exception("Database error")

        with patch("app.db.session.settings") as mock_settings:
            mock_settings.DATABASE_URL = "postgresql://test"

            result = await check_database_health()
            assert result is False


class TestDatabaseShutdown:
    """Test database connection cleanup."""

    @pytest.mark.asyncio
    async def test_close_database_connections_no_engine(self) -> None:
        """Test closing connections when no engine exists."""
        import app.db.session

        app.db.session.engine = None

        # Should not raise exception
        await close_database_connections()

    @pytest.mark.asyncio
    async def test_close_database_connections_success(self) -> None:
        """Test successful connection closure."""
        mock_engine = AsyncMock()

        with patch("app.db.session.engine", mock_engine):
            await close_database_connections()

            mock_engine.dispose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_database_connections_resets_global(self) -> None:
        """Test that closing connections resets global engine."""
        import app.db.session

        mock_engine = AsyncMock()
        app.db.session.engine = mock_engine

        await close_database_connections()

        assert app.db.session.engine is None
