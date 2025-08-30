"""Comprehensive tests for database session management to achieve 90%+ coverage."""

import asyncio
from typing import AsyncGenerator, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, PropertyMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db.session import (
    check_database_health,
    close_database_connections,
    create_async_session_maker,
    create_database_engine,
    db_circuit_breaker,
    get_connection_pool_stats,
    get_db,
    get_session_maker,
    init_database,
    is_database_available,
    recover_database_connection,
    reset_circuit_breaker,
    validate_database_connection,
)
from app.utils.circuit_breaker import CircuitState


@pytest.fixture
def mock_settings():
    """Mock settings for tests."""
    with patch("app.db.session.settings") as mock:
        mock.DATABASE_URL = "sqlite+aiosqlite:///test.db"
        mock.DATABASE_POOL_SIZE = 5
        mock.DATABASE_MAX_OVERFLOW = 10
        mock.DEBUG = False
        mock.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        yield mock


@pytest.fixture
def mock_engine():
    """Mock async engine."""
    engine = AsyncMock(spec=AsyncEngine)
    engine.dispose = AsyncMock()

    # Mock pool for statistics
    pool = MagicMock()
    pool.size.return_value = 5
    pool.checkedin.return_value = 3
    pool.checkedout.return_value = 2
    pool.overflow.return_value = 0
    pool.invalid.return_value = 0
    engine.pool = pool

    return engine


@pytest.fixture
def mock_session():
    """Mock async session."""
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.close = AsyncMock()
    session.rollback = AsyncMock()
    return session


class TestCreateDatabaseEngine:
    """Test database engine creation."""

    def test_create_engine_no_url(self, mock_settings):
        """Test engine creation without database URL."""
        mock_settings.DATABASE_URL = None

        with patch("app.db.session.logger") as mock_logger:
            result = create_database_engine()

            assert result is None
            mock_logger.warning.assert_called_once()

    def test_create_engine_sqlite(self, mock_settings):
        """Test SQLite engine creation."""
        mock_settings.DATABASE_URL = "sqlite+aiosqlite:///test.db"

        with patch("app.db.session.create_async_engine") as mock_create:
            mock_engine = MagicMock()
            mock_create.return_value = mock_engine

            result = create_database_engine()

            assert result == mock_engine
            # Check SQLite-specific settings
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["pool_pre_ping"] is True
            assert "pool_size" not in call_kwargs  # SQLite doesn't support pool_size
            assert call_kwargs["connect_args"]["check_same_thread"] is False

    def test_create_engine_postgresql(self, mock_settings):
        """Test PostgreSQL engine creation."""
        mock_settings.DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/db"

        with patch("app.db.session.create_async_engine") as mock_create:
            mock_engine = MagicMock()
            mock_create.return_value = mock_engine

            result = create_database_engine()

            assert result == mock_engine
            # Check PostgreSQL settings
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["pool_size"] == 5
            assert call_kwargs["max_overflow"] == 10
            assert call_kwargs["pool_pre_ping"] is True
            assert call_kwargs["pool_recycle"] == 3600
            assert call_kwargs["pool_timeout"] == 30
            assert call_kwargs["pool_reset_on_return"] == "commit"

    def test_create_engine_debug_mode(self, mock_settings):
        """Test engine creation with debug mode."""
        mock_settings.DEBUG = True

        with patch("app.db.session.create_async_engine") as mock_create:
            mock_engine = MagicMock()
            mock_create.return_value = mock_engine

            result = create_database_engine()

            assert result == mock_engine
            assert mock_create.call_args[1]["echo"] is True

    def test_create_engine_exception(self, mock_settings):
        """Test engine creation with exception."""
        with patch("app.db.session.create_async_engine") as mock_create:
            mock_create.side_effect = Exception("Connection failed")

            with patch("app.db.session.logger") as mock_logger:
                result = create_database_engine()

                assert result is None
                mock_logger.error.assert_called_once()


class TestGetSessionMaker:
    """Test session maker functionality."""

    def test_get_session_maker_new(self, mock_settings, mock_engine):
        """Test creating new session maker."""
        with patch("app.db.session._async_session_maker", None):
            with patch("app.db.session._engine", None):
                with patch("app.db.session.create_database_engine", return_value=mock_engine):
                    with patch("app.db.session.async_sessionmaker") as mock_maker:
                        mock_session_maker = MagicMock()
                        mock_maker.return_value = mock_session_maker

                        result = get_session_maker()

                        assert result == mock_session_maker
                        mock_maker.assert_called_once_with(
                            bind=mock_engine,
                            class_=AsyncSession,
                            expire_on_commit=False,
                        )

    def test_get_session_maker_existing(self, mock_settings):
        """Test getting existing session maker."""
        mock_session_maker = MagicMock()

        with patch("app.db.session._async_session_maker", mock_session_maker):
            result = get_session_maker()
            assert result == mock_session_maker

    def test_get_session_maker_no_engine(self, mock_settings):
        """Test session maker when engine creation fails."""
        with patch("app.db.session._async_session_maker", None):
            with patch("app.db.session._engine", None):
                with patch("app.db.session.create_database_engine", return_value=None):
                    result = get_session_maker()
                    assert result is None


class TestGetDB:
    """Test database session context manager."""

    @pytest.mark.asyncio
    async def test_get_db_success(self, mock_session):
        """Test successful database session creation."""
        mock_session_maker = MagicMock()
        mock_session_maker.return_value = mock_session

        with patch("app.db.session.get_session_maker", return_value=mock_session_maker):
            with patch(
                "app.db.session.db_circuit_breaker.call",
                new=AsyncMock(return_value=mock_session),
            ):
                async with get_db() as db:
                    assert db == mock_session

                mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_sqlalchemy_error(self, mock_session):
        """Test database session with SQLAlchemy error."""
        mock_session.execute.side_effect = SQLAlchemyError("Query failed")
        mock_session_maker = MagicMock()
        mock_session_maker.return_value = mock_session

        with patch("app.db.session.get_session_maker", return_value=mock_session_maker):
            with patch(
                "app.db.session.db_circuit_breaker.call",
                new=AsyncMock(return_value=mock_session),
            ):
                with pytest.raises(SQLAlchemyError):
                    async with get_db() as db:
                        await db.execute(text("SELECT 1"))

                mock_session.rollback.assert_called_once()
                mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_general_error(self, mock_session):
        """Test database session with general error."""
        mock_session.execute.side_effect = RuntimeError("Unknown error")
        mock_session_maker = MagicMock()
        mock_session_maker.return_value = mock_session

        with patch("app.db.session.get_session_maker", return_value=mock_session_maker):
            with patch(
                "app.db.session.db_circuit_breaker.call",
                new=AsyncMock(return_value=mock_session),
            ):
                with pytest.raises(RuntimeError):
                    async with get_db() as db:
                        await db.execute(text("SELECT 1"))

                mock_session.rollback.assert_called_once()
                mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_no_session_maker(self):
        """Test get_db when session maker is None."""
        with patch("app.db.session.get_session_maker", return_value=None):
            with patch(
                "app.db.session.db_circuit_breaker.call",
                new=AsyncMock(side_effect=RuntimeError("Database not configured")),
            ):
                with pytest.raises(RuntimeError, match="Database not configured"):
                    async with get_db() as db:
                        pass


class TestCheckDatabaseHealth:
    """Test database health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_no_url(self, mock_settings):
        """Test health check without database URL."""
        mock_settings.DATABASE_URL = None

        with patch("app.db.session.logger") as mock_logger:
            result = await check_database_health()

            assert result is True  # Database is optional
            mock_logger.debug.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_session, mock_settings):
        """Test successful health check."""
        # Mock query result
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (1,)
        mock_session.execute.return_value = mock_result

        with patch("app.db.session.get_db") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            mock_get_db.return_value.__aexit__.return_value = None

            result = await check_database_health()

            assert result is True
            mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_timeout(self, mock_session, mock_settings):
        """Test health check timeout."""

        async def slow_execute(*args):
            await asyncio.sleep(10)  # Longer than timeout

        mock_session.execute = slow_execute

        with patch("app.db.session.get_db") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            mock_get_db.return_value.__aexit__.return_value = None

            with patch("app.db.session.logger") as mock_logger:
                result = await check_database_health(timeout=0.1)

                assert result is False
                mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_circuit_breaker_open(self, mock_settings):
        """Test health check when circuit breaker is open."""
        from app.utils.circuit_breaker import CircuitBreakerException

        with patch(
            "app.db.session.get_db",
            side_effect=CircuitBreakerException("Circuit open", "test-circuit"),
        ):
            with patch("app.db.session.logger") as mock_logger:
                result = await check_database_health()

                assert result is False
                mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_unexpected_result(self, mock_session, mock_settings):
        """Test health check with unexpected query result."""
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (2,)  # Not 1
        mock_session.execute.return_value = mock_result

        with patch("app.db.session.get_db") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            mock_get_db.return_value.__aexit__.return_value = None

            with patch("app.db.session.logger") as mock_logger:
                result = await check_database_health()

                assert result is False
                mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_sqlalchemy_error(self, mock_session, mock_settings):
        """Test health check with SQLAlchemy error."""
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        with patch("app.db.session.get_db") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            mock_get_db.return_value.__aexit__.return_value = None

            with pytest.raises(SQLAlchemyError):
                await check_database_health()


class TestConnectionPoolStats:
    """Test connection pool statistics."""

    def test_get_stats_with_engine(self, mock_engine):
        """Test getting stats with active engine."""
        with patch("app.db.session._engine", mock_engine):
            stats = get_connection_pool_stats()

            assert stats["pool_size"] == 5
            assert stats["checked_in"] == 3
            assert stats["checked_out"] == 2
            assert stats["overflow"] == 0
            assert stats["invalid"] == 0
            assert stats["total"] == 5  # 3 + 2
            assert stats["usage_percent"] == 100.0  # (5/5) * 100

    def test_get_stats_no_engine(self):
        """Test getting stats without engine."""
        with patch("app.db.session._engine", None):
            stats = get_connection_pool_stats()

            assert all(v == 0 or v == 0.0 for v in stats.values())

    def test_get_stats_null_pool(self, mock_engine):
        """Test getting stats with NullPool (no pooling)."""
        # Mock pool without callable methods (NullPool)
        pool = MagicMock()
        pool.size = 0  # Not callable
        pool.checkedin = 0
        pool.checkedout = 0
        pool.overflow = 0
        pool.invalid = 0
        mock_engine.pool = pool

        with patch("app.db.session._engine", mock_engine):
            stats = get_connection_pool_stats()

            assert stats["pool_size"] == 0
            assert stats["checked_in"] == 0
            assert stats["checked_out"] == 0

    def test_get_stats_exception(self, mock_engine):
        """Test getting stats with exception."""
        mock_engine.pool.size.side_effect = Exception("Pool error")

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session.logger") as mock_logger:
                stats = get_connection_pool_stats()

                assert all(v == 0 or v == 0.0 for v in stats.values())
                mock_logger.error.assert_called_once()


class TestCloseConnections:
    """Test connection closing functionality."""

    @pytest.mark.asyncio
    async def test_close_connections_success(self, mock_engine):
        """Test successful connection closing."""
        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session._async_session_maker", MagicMock()):
                with patch(
                    "app.db.session.get_connection_pool_stats",
                    return_value={"total": 5},
                ):
                    with patch("app.db.session.logger") as mock_logger:
                        await close_database_connections()

                        mock_engine.dispose.assert_called_once()
                        assert mock_logger.info.call_count == 2

    @pytest.mark.asyncio
    async def test_close_connections_no_engine(self):
        """Test closing when no engine exists."""
        with patch("app.db.session._engine", None):
            # Should not raise error
            await close_database_connections()

    @pytest.mark.asyncio
    async def test_close_connections_error(self, mock_engine):
        """Test connection closing with error."""
        mock_engine.dispose.side_effect = Exception("Dispose failed")

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session.logger") as mock_logger:
                with pytest.raises(Exception, match="Dispose failed"):
                    await close_database_connections()

                mock_logger.error.assert_called_once()


class TestValidateConnection:
    """Test connection validation."""

    @pytest.mark.asyncio
    async def test_validate_connection_healthy(self):
        """Test validation with healthy connection."""
        with patch("app.db.session.check_database_health", new=AsyncMock(return_value=True)):
            with patch("app.db.session.logger") as mock_logger:
                result = await validate_database_connection()

                assert result is True
                mock_logger.debug.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_connection_recovery_success(self, mock_engine):
        """Test successful connection recovery."""
        with patch(
            "app.db.session.check_database_health",
            new=AsyncMock(side_effect=[False, True]),
        ):
            with patch("app.db.session._engine", mock_engine):
                with patch("app.db.session.create_database_engine", return_value=mock_engine):
                    with patch("app.db.session.logger") as mock_logger:
                        result = await validate_database_connection()

                        assert result is True
                        mock_engine.dispose.assert_called_once()
                        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_validate_connection_recovery_failed(self, mock_engine):
        """Test failed connection recovery."""
        with patch("app.db.session.check_database_health", new=AsyncMock(return_value=False)):
            with patch("app.db.session._engine", mock_engine):
                with patch("app.db.session.create_database_engine", return_value=None):
                    with patch("app.db.session.logger") as mock_logger:
                        result = await validate_database_connection()

                        assert result is False
                        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_validate_connection_exception(self):
        """Test validation with exception."""
        with patch(
            "app.db.session.check_database_health",
            side_effect=Exception("Check failed"),
        ):
            with patch("app.db.session.logger") as mock_logger:
                result = await validate_database_connection()

                assert result is False
                mock_logger.error.assert_called_once()


class TestCircuitBreakerIntegration:
    """Test circuit breaker integration."""

    def test_is_database_available_no_url(self, mock_settings):
        """Test availability check without URL."""
        mock_settings.DATABASE_URL = None

        result = is_database_available()
        assert result is False

    def test_is_database_available_circuit_open(self, mock_settings):
        """Test availability when circuit is open."""
        with patch.object(db_circuit_breaker, "state", CircuitState.OPEN):
            result = is_database_available()
            assert result is False

    def test_is_database_available_ok(self, mock_settings):
        """Test availability when everything is OK."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            result = is_database_available()
            assert result is True

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_success(self):
        """Test successful circuit breaker reset."""
        with patch.object(db_circuit_breaker, "reset", new=AsyncMock()):
            with patch("app.db.session.check_database_health", new=AsyncMock(return_value=True)):
                with patch("app.db.session.logger") as mock_logger:
                    result = await reset_circuit_breaker()

                    assert result is True
                    assert mock_logger.info.call_count == 2

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_still_unhealthy(self):
        """Test circuit breaker reset with unhealthy database."""
        with patch.object(db_circuit_breaker, "reset", new=AsyncMock()):
            with patch(
                "app.db.session.check_database_health",
                new=AsyncMock(return_value=False),
            ):
                with patch("app.db.session.logger") as mock_logger:
                    result = await reset_circuit_breaker()

                    assert result is False
                    mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_exception(self):
        """Test circuit breaker reset with exception."""
        with patch.object(db_circuit_breaker, "reset", side_effect=Exception("Reset failed")):
            with patch("app.db.session.logger") as mock_logger:
                result = await reset_circuit_breaker()

                assert result is False
                mock_logger.error.assert_called_once()


class TestInitDatabase:
    """Test database initialization."""

    @pytest.mark.asyncio
    async def test_init_database_no_url(self, mock_settings):
        """Test initialization without URL."""
        mock_settings.DATABASE_URL = None

        with patch("app.db.session.logger") as mock_logger:
            await init_database()  # Should not raise
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_database_success(self, mock_settings):
        """Test successful initialization."""
        mock_session_maker = MagicMock()

        with patch("app.db.session.get_session_maker", return_value=mock_session_maker):
            with patch("app.db.session.check_database_health", new=AsyncMock(return_value=True)):
                with patch("app.db.session.logger") as mock_logger:
                    await init_database()

                    assert mock_logger.info.call_count == 2

    @pytest.mark.asyncio
    async def test_init_database_no_session_maker(self, mock_settings):
        """Test initialization when session maker fails."""
        with patch("app.db.session.get_session_maker", return_value=None):
            with pytest.raises(RuntimeError, match="Failed to create database session maker"):
                await init_database()

    @pytest.mark.asyncio
    async def test_init_database_health_check_failed(self, mock_settings):
        """Test initialization when health check fails."""
        mock_session_maker = MagicMock()

        with patch("app.db.session.get_session_maker", return_value=mock_session_maker):
            with patch(
                "app.db.session.check_database_health",
                new=AsyncMock(return_value=False),
            ):
                with pytest.raises(RuntimeError, match="Database health check failed"):
                    await init_database()


class TestRecoverConnection:
    """Test connection recovery functionality."""

    @pytest.mark.asyncio
    async def test_recover_connection_first_attempt(self):
        """Test successful recovery on first attempt."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            with patch.object(db_circuit_breaker, "reset", new=AsyncMock()):
                with patch(
                    "app.db.session.validate_database_connection",
                    new=AsyncMock(return_value=True),
                ):
                    with patch("app.db.session.logger") as mock_logger:
                        result = await recover_database_connection(max_attempts=3)

                        assert result is True
                        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_recover_connection_circuit_reset(self):
        """Test recovery with circuit breaker reset."""
        with patch.object(db_circuit_breaker, "state", CircuitState.OPEN):
            with patch.object(db_circuit_breaker, "reset", new=AsyncMock()):
                with patch(
                    "app.db.session.validate_database_connection",
                    new=AsyncMock(return_value=True),
                ):
                    result = await recover_database_connection(max_attempts=1)

                    assert result is True
                    db_circuit_breaker.reset.assert_called_once()

    @pytest.mark.asyncio
    async def test_recover_connection_multiple_attempts(self):
        """Test recovery requiring multiple attempts."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            with patch(
                "app.db.session.validate_database_connection",
                new=AsyncMock(side_effect=[False, False, True]),
            ):
                with patch("app.db.session.asyncio.sleep", new=AsyncMock()):
                    result = await recover_database_connection(max_attempts=3, retry_delay=0.1)

                    assert result is True

    @pytest.mark.asyncio
    async def test_recover_connection_all_attempts_failed(self):
        """Test recovery when all attempts fail."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            with patch(
                "app.db.session.validate_database_connection",
                new=AsyncMock(return_value=False),
            ):
                with patch("app.db.session.asyncio.sleep", new=AsyncMock()):
                    with patch("app.db.session.logger") as mock_logger:
                        result = await recover_database_connection(max_attempts=2, retry_delay=0.1)

                        assert result is False
                        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_recover_connection_with_exceptions(self):
        """Test recovery with exceptions during attempts."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            with patch(
                "app.db.session.validate_database_connection",
                side_effect=[Exception("Error 1"), Exception("Error 2"), True],
            ):
                with patch("app.db.session.asyncio.sleep", new=AsyncMock()):
                    with patch("app.db.session.logger") as mock_logger:
                        result = await recover_database_connection(max_attempts=3, retry_delay=0.1)

                        assert result is True
                        assert mock_logger.error.call_count == 2


class TestCreateAsyncSessionMaker:
    """Test async session maker creation."""

    def test_create_async_session_maker(self, mock_engine):
        """Test creating async session maker."""
        with patch("app.db.session.async_sessionmaker") as mock_maker:
            mock_session_maker = MagicMock()
            mock_maker.return_value = mock_session_maker

            result = create_async_session_maker(mock_engine)

            assert result == mock_session_maker
            mock_maker.assert_called_once_with(bind=mock_engine, class_=AsyncSession, expire_on_commit=False)
