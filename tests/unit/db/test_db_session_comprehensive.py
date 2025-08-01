"""Comprehensive tests for database session covering all error scenarios."""

import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool, QueuePool

from app.db.session import (
    check_database_health,
    close_database_connections,
    db_circuit_breaker,
    get_connection_pool_stats,
    get_db,
    get_engine,
    get_session_maker,
    recreate_database_pool,
    reset_circuit_breaker,
)
from app.utils.circuit_breaker import CircuitState


@pytest.fixture(autouse=True)
def reset_db_globals():
    """Reset database global state before each test."""
    import app.db.session

    # Reset all global variables to clean state
    app.db.session._engine = None
    app.db.session._async_session_maker = None
    app.db.session.engine = None

    yield

    # Clean up after test
    app.db.session._engine = None
    app.db.session._async_session_maker = None
    app.db.session.engine = None


class TestDatabaseEngineCreation:
    """Test database engine creation with different configurations."""

    @patch("app.db.session.create_async_engine")
    @patch("app.db.session.settings")
    def test_get_engine_postgresql(self, mock_settings, mock_create_engine):
        """Test engine creation for PostgreSQL."""
        # Configure for PostgreSQL
        mock_settings.DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/db"
        mock_settings.DATABASE_POOL_SIZE = 10
        mock_settings.DATABASE_MAX_OVERFLOW = 20
        mock_settings.DEBUG = False

        # Reset engine to force recreation
        import app.db.session

        app.db.session._engine = None
        app.db.session.engine = None

        # Get engine
        result = get_engine()

        # Verify PostgreSQL configuration
        mock_create_engine.assert_called_once()
        call_args = mock_create_engine.call_args

        assert call_args[0][0] == "postgresql+asyncpg://user:pass@localhost/db"
        assert call_args[1]["pool_size"] == 10
        assert call_args[1]["max_overflow"] == 20
        assert call_args[1]["pool_pre_ping"] is True
        assert call_args[1]["echo"] is False
        assert call_args[1]["pool_recycle"] == 3600
        assert "poolclass" not in call_args[1]  # Should use default pool

    @patch("app.db.session.create_async_engine")
    @patch("app.db.session.settings")
    def test_get_engine_sqlite(self, mock_settings, mock_create_engine):
        """Test engine creation for SQLite."""
        # Configure for SQLite
        mock_settings.DATABASE_URL = "sqlite+aiosqlite:///test.db"
        mock_settings.DATABASE_POOL_SIZE = 1
        mock_settings.DATABASE_MAX_OVERFLOW = 0
        mock_settings.DEBUG = True

        # Reset engine
        import app.db.session

        app.db.session._engine = None
        app.db.session.engine = None

        # Get engine
        result = get_engine()

        # Verify SQLite configuration
        mock_create_engine.assert_called_once()
        call_args = mock_create_engine.call_args

        assert call_args[0][0] == "sqlite+aiosqlite:///test.db"
        assert call_args[1]["echo"] is True
        assert "pool_size" not in call_args[1]  # SQLite doesn't use these
        assert "max_overflow" not in call_args[1]

    @patch("app.db.session.create_async_engine")
    @patch("app.db.session.settings")
    def test_get_engine_singleton(self, mock_settings, mock_create_engine):
        """Test engine is created as singleton."""
        mock_settings.DATABASE_URL = "postgresql+asyncpg://test"
        mock_settings.DATABASE_POOL_SIZE = 5
        mock_settings.DATABASE_MAX_OVERFLOW = 10
        mock_settings.DEBUG = False

        # Reset engine
        import app.db.session

        app.db.session._engine = None
        app.db.session.engine = None

        # Get engine twice
        engine1 = get_engine()
        engine2 = get_engine()

        # Should only create once
        assert mock_create_engine.call_count == 1
        assert engine1 is engine2


class TestDatabaseSessionMaker:
    """Test session maker creation."""

    @patch("app.db.session.async_sessionmaker")
    @patch("app.db.session.create_database_engine")
    def test_get_session_maker(self, mock_create_engine, mock_sessionmaker):
        """Test session maker creation."""
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_session_maker = MagicMock()
        mock_sessionmaker.return_value = mock_session_maker

        # Reset session maker
        import app.db.session

        app.db.session._async_session_maker = None
        app.db.session._engine = None

        # Get session maker
        result = get_session_maker()

        # Verify configuration
        mock_sessionmaker.assert_called_once_with(bind=mock_engine, class_=AsyncSession, expire_on_commit=False)
        assert result is mock_session_maker

    @patch("app.db.session.async_sessionmaker")
    @patch("app.db.session.create_database_engine")
    def test_get_session_maker_singleton(self, mock_create_engine, mock_sessionmaker):
        """Test session maker is singleton."""
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_session_maker = MagicMock()
        mock_sessionmaker.return_value = mock_session_maker

        # Reset session maker
        import app.db.session

        app.db.session._async_session_maker = None
        app.db.session._engine = None

        # Get session maker twice
        maker1 = get_session_maker()
        maker2 = get_session_maker()

        # Should only create once
        assert mock_sessionmaker.call_count == 1
        assert maker1 is maker2


class TestGetDbWithCircuitBreaker:
    """Test get_db function with circuit breaker scenarios."""

    @pytest.mark.asyncio
    @patch("app.db.session._create_database_session")
    async def test_get_db_success(self, mock_create_session):
        """Test successful database session creation."""
        # Mock session
        mock_session = AsyncMock(spec=AsyncSession)
        mock_create_session.return_value = mock_session

        # Reset circuit breaker
        await db_circuit_breaker.reset()

        # Get session
        async with get_db() as session:
            assert session is mock_session

        # Verify session was closed
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.db.session._create_database_session")
    async def test_get_db_with_exception(self, mock_create_session):
        """Test database session with exception during usage."""
        # Mock session that raises error
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute.side_effect = OperationalError("Connection failed", None, None)
        mock_create_session.return_value = mock_session

        # Reset circuit breaker
        await db_circuit_breaker.reset()

        # Use session and expect exception
        with pytest.raises(OperationalError):
            async with get_db() as session:
                await session.execute("SELECT 1")

        # Session should still be closed
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.db.session.logger")
    @patch("app.db.session._create_database_session")
    async def test_get_db_circuit_breaker_open(self, mock_create_session, mock_logger):
        """Test get_db when circuit breaker is open."""
        # Open the circuit breaker and ensure it stays open by setting recent failure
        db_circuit_breaker._state = CircuitState.OPEN
        db_circuit_breaker.stats.last_failure_time = time.time()  # Recent failure
        db_circuit_breaker.stats.failure_count = 10  # Well above threshold

        # Try to get session
        from app.utils.circuit_breaker import CircuitBreakerException

        with pytest.raises(CircuitBreakerException):
            async with get_db() as session:
                pass

        # Should not call create session due to circuit breaker
        mock_create_session.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.db.session._create_database_session")
    async def test_get_db_session_creation_failure(self, mock_create_session):
        """Test when session creation itself fails."""
        # Mock session creation that fails
        mock_create_session.side_effect = Exception("Cannot create session")

        # Reset circuit breaker
        await db_circuit_breaker.reset()

        # Should raise and increment circuit breaker
        with pytest.raises(Exception, match="Cannot create session"):
            async with get_db() as session:
                pass


class TestDatabaseHealthCheck:
    """Test database health check functionality."""

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_success(self, mock_get_db):
        """Test successful health check."""
        # Mock healthy database
        mock_session = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (1,)
        mock_session.execute.return_value = mock_result

        mock_get_db.return_value.__aenter__.return_value = mock_session
        mock_get_db.return_value.__aexit__.return_value = None

        # Check health
        result = await check_database_health(timeout=5.0)

        assert result is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_failure(self, mock_get_db):
        """Test health check with database error."""
        # Mock unhealthy database - use a non-SQLAlchemy error that won't be retried
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute.side_effect = Exception("Connection lost")

        mock_get_db.return_value.__aenter__.return_value = mock_session
        mock_get_db.return_value.__aexit__.return_value = None

        # Check health - non-SQLAlchemy errors return False
        result = await check_database_health()

        assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.logger")
    @patch("app.db.session.get_db")
    async def test_check_database_health_timeout(self, mock_get_db, mock_logger):
        """Test health check with timeout."""
        # Mock database that raises asyncio.TimeoutError
        mock_get_db.side_effect = asyncio.TimeoutError()

        # Check health with short timeout
        result = await check_database_health(timeout=0.1)

        assert result is False
        mock_logger.error.assert_called_with("Database health check timed out", timeout=0.1)

    @pytest.mark.asyncio
    @patch("app.db.session.get_db")
    async def test_check_database_health_circuit_breaker_open(self, mock_get_db):
        """Test health check when circuit breaker is open."""
        from app.utils.circuit_breaker import CircuitBreakerException

        # Mock circuit breaker open
        mock_get_db.side_effect = CircuitBreakerException("Circuit open", "test")

        # Check health
        result = await check_database_health()

        assert result is False


class TestConnectionPoolStats:
    """Test connection pool statistics."""

    @patch("app.db.session._engine")
    def test_get_connection_pool_stats_with_pool(self, mock_engine):
        """Test getting stats from a real pool."""
        # Mock engine with pool
        mock_pool = MagicMock()
        mock_pool.size.return_value = 10
        mock_pool.checkedin.return_value = 7
        mock_pool.checkedout.return_value = 3
        mock_pool.overflow.return_value = 2
        mock_pool.invalid.return_value = 0
        mock_engine.pool = mock_pool

        # Get stats
        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 10
        assert stats["checked_in"] == 7
        assert stats["checked_out"] == 3
        assert stats["overflow"] == 2
        assert stats["total"] == 10

    @patch("app.db.session._engine")
    def test_get_connection_pool_stats_null_pool(self, mock_engine):
        """Test getting stats from NullPool (SQLite)."""
        # Mock engine with NullPool (no size method, but other methods exist)
        mock_pool = MagicMock()
        # Remove size method to simulate NullPool
        mock_pool.size = MagicMock(side_effect=AttributeError("NullPool has no size"))
        mock_pool.checkedin.return_value = 0
        mock_pool.checkedout.return_value = 0
        mock_pool.overflow.return_value = 0
        mock_pool.invalid.return_value = 0
        mock_engine.pool = mock_pool

        # Get stats
        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 0
        assert stats["checked_in"] == 0
        assert stats["checked_out"] == 0
        assert stats["overflow"] == 0
        assert stats["total"] == 0

    @patch("app.db.session.logger")
    @patch("app.db.session._engine")
    def test_get_connection_pool_stats_error(self, mock_engine, mock_logger):
        """Test getting stats with error."""
        # Mock engine that raises error
        mock_engine.pool.size.side_effect = AttributeError("No size attribute")

        # Get stats - should handle error
        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 0
        assert stats["checked_in"] == 0
        assert stats["checked_out"] == 0
        assert stats["overflow"] == 0
        assert stats["total"] == 0
        mock_logger.error.assert_called()


class TestDatabaseShutdownAndRecovery:
    """Test database shutdown and recovery operations."""

    @pytest.mark.asyncio
    @patch("app.db.session.get_connection_pool_stats")
    @patch("app.db.session.logger")
    async def test_close_database_connections_success(self, mock_logger, mock_stats):
        """Test successful database shutdown."""
        # Mock engine with dispose
        mock_engine = AsyncMock()
        mock_stats.return_value = {"pool_size": 5, "checked_out": 2}

        # Set up global engine
        import app.db.session

        app.db.session._engine = mock_engine

        # Close connections
        await close_database_connections()

        # Verify shutdown sequence
        mock_engine.dispose.assert_called_once()
        mock_logger.info.assert_any_call("Database connections closed successfully")

        # Verify globals are reset
        assert app.db.session._engine is None
        assert app.db.session._async_session_maker is None
        assert app.db.session.engine is None

    @pytest.mark.asyncio
    @patch("app.db.session.get_connection_pool_stats")
    @patch("app.db.session.logger")
    async def test_close_database_connections_with_error(self, mock_logger, mock_stats):
        """Test database shutdown with error."""
        # Mock engine that fails to dispose
        mock_engine = AsyncMock()
        mock_engine.dispose.side_effect = Exception("Dispose failed")
        mock_stats.return_value = {"pool_size": 5}

        # Set up global engine
        import app.db.session

        app.db.session._engine = mock_engine

        # Close connections - should raise error
        with pytest.raises(Exception, match="Dispose failed"):
            await close_database_connections()

        # Should log error
        mock_logger.error.assert_called_with("Error closing database connections", error="Dispose failed")

    @pytest.mark.asyncio
    async def test_close_database_connections_no_engine(self):
        """Test closing when no engine exists."""
        # Set engine to None
        import app.db.session

        app.db.session._engine = None

        # Should not raise
        await close_database_connections()

    @pytest.mark.asyncio
    @patch("app.db.session.create_database_engine")
    @patch("app.db.session.async_sessionmaker")
    @patch("app.db.session.logger")
    async def test_recreate_database_pool_success(self, mock_logger, mock_sessionmaker, mock_create_engine):
        """Test successful pool recreation."""
        # Mock successful recreation
        mock_engine = AsyncMock()
        mock_old_engine = AsyncMock()
        mock_create_engine.return_value = mock_engine
        mock_session_maker = MagicMock()
        mock_sessionmaker.return_value = mock_session_maker

        # Set up existing engine
        import app.db.session

        app.db.session._engine = mock_old_engine

        # Recreate pool
        result = await recreate_database_pool()

        assert result is True
        mock_old_engine.dispose.assert_called_once()
        mock_create_engine.assert_called_once()
        mock_sessionmaker.assert_called_once()
        mock_logger.info.assert_any_call("Database pool recreated successfully")

    @pytest.mark.asyncio
    @patch("app.db.session.create_database_engine")
    @patch("app.db.session.logger")
    async def test_recreate_database_pool_engine_creation_fails(self, mock_logger, mock_create_engine):
        """Test pool recreation when engine creation fails."""
        # Mock failed engine creation
        mock_create_engine.return_value = None

        # Set up existing engine
        import app.db.session

        mock_old_engine = AsyncMock()
        app.db.session._engine = mock_old_engine

        # Recreate pool
        result = await recreate_database_pool()

        assert result is False
        mock_old_engine.dispose.assert_called_once()
        mock_logger.error.assert_called_with("Failed to recreate database engine")

    @pytest.mark.asyncio
    @patch("app.db.session.logger")
    async def test_recreate_database_pool_exception(self, mock_logger):
        """Test pool recreation with exception."""
        # Mock exception during dispose
        import app.db.session

        mock_old_engine = AsyncMock()
        mock_old_engine.dispose.side_effect = Exception("Recreation failed")
        app.db.session._engine = mock_old_engine

        # Recreate pool
        result = await recreate_database_pool()

        assert result is False
        mock_logger.error.assert_called_with("Failed to recreate database pool", error="Recreation failed")


class TestCircuitBreakerReset:
    """Test circuit breaker reset functionality."""

    @pytest.mark.asyncio
    @patch("app.db.session.check_database_health")
    @patch("app.db.session.logger")
    async def test_reset_circuit_breaker_success(self, mock_logger, mock_health):
        """Test successful circuit breaker reset."""
        # Set circuit breaker to open state
        db_circuit_breaker._state = CircuitState.OPEN

        # Mock healthy database
        mock_health.return_value = True

        # Reset circuit breaker
        result = await reset_circuit_breaker()

        assert result is True
        assert db_circuit_breaker.state == CircuitState.CLOSED
        mock_logger.info.assert_any_call("Database circuit breaker reset manually")
        mock_logger.info.assert_any_call("Database connection verified after circuit breaker reset")

    @pytest.mark.asyncio
    @patch("app.db.session.check_database_health")
    @patch("app.db.session.logger")
    async def test_reset_circuit_breaker_health_check_fails(self, mock_logger, mock_health):
        """Test circuit breaker reset when health check fails."""
        # Mock unhealthy database
        mock_health.return_value = False

        # Reset circuit breaker
        result = await reset_circuit_breaker()

        assert result is False
        mock_logger.warning.assert_called_with("Database still unhealthy after circuit breaker reset")

    @pytest.mark.asyncio
    @patch("app.db.session.check_database_health")
    @patch("app.db.session.logger")
    async def test_reset_circuit_breaker_exception(self, mock_logger, mock_health):
        """Test circuit breaker reset with exception."""
        # Mock exception
        mock_health.side_effect = Exception("Health check error")

        # Reset circuit breaker
        result = await reset_circuit_breaker()

        assert result is False
        mock_logger.error.assert_called_with("Failed to reset database circuit breaker", error="Health check error")
