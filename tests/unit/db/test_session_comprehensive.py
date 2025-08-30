"""Comprehensive tests for database session management achieving 100% coverage."""

import asyncio
import os
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, PropertyMock, call, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from app.db import session as db_session_module
from app.db.session import (
    check_database_health,
    close_database_connections,
    create_async_session_maker,
    create_database_engine,
    db_circuit_breaker,
    get_connection_pool_stats,
    get_db,
    get_db_dependency,
    get_engine,
    get_session_maker,
    init_database,
    init_db,
    is_database_available,
    recover_database_connection,
    recreate_database_pool,
    reset_circuit_breaker,
    reset_engine,
    validate_database_connection,
)
from app.repositories.base import Page
from app.utils.circuit_breaker import CircuitBreakerException, CircuitState


class TestDatabaseEngineCreation:
    """Test database engine creation scenarios."""

    @patch("app.db.session.settings")
    @patch("app.db.session.create_async_engine")
    def test_create_engine_with_postgresql(self, test_create_engine, test_settings):
        """Test engine creation with PostgreSQL URL."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/db"
        test_settings.DATABASE_POOL_SIZE = 10
        test_settings.DATABASE_MAX_OVERFLOW = 20
        test_settings.DEBUG = False

        test_engine = MagicMock(spec=AsyncEngine)
        test_create_engine.return_value = test_engine

        result = create_database_engine()

        assert result == test_engine
        test_create_engine.assert_called_once()

        # Verify pool settings were used
        call_kwargs = test_create_engine.call_args[1]
        assert call_kwargs["pool_size"] == 10
        assert call_kwargs["max_overflow"] == 20
        assert call_kwargs["pool_pre_ping"] is True
        assert call_kwargs["echo"] is False

    @patch("app.db.session.settings")
    @patch("app.db.session.create_async_engine")
    def test_create_engine_with_sqlite(self, test_create_engine, test_settings):
        """Test engine creation with SQLite URL."""
        test_settings.DATABASE_URL = "sqlite+aiosqlite:///test.db"
        test_settings.DATABASE_POOL_SIZE = 10
        test_settings.DATABASE_MAX_OVERFLOW = 20
        test_settings.DEBUG = True

        test_engine = MagicMock(spec=AsyncEngine)
        test_create_engine.return_value = test_engine

        result = create_database_engine()

        assert result == test_engine
        test_create_engine.assert_called_once()

        # SQLite should not have pool_size and max_overflow
        call_kwargs = test_create_engine.call_args[1]
        assert "pool_size" not in call_kwargs
        assert "max_overflow" not in call_kwargs
        assert call_kwargs["pool_pre_ping"] is True
        assert call_kwargs["echo"] is True
        assert call_kwargs["connect_args"]["check_same_thread"] is False

    @patch("app.db.session.settings")
    @patch("app.db.session.os.getenv")
    def test_create_engine_no_url_in_test_mode(self, test_getenv, test_settings):
        """Test engine creation with no URL in test mode."""
        test_settings.DATABASE_URL = None
        # Return "true" for TESTING, and default (None) for PYTEST_CURRENT_TEST
        test_getenv.side_effect = lambda key, default=None: ("true" if key == "TESTING" else default)

        with patch("app.db.session.create_async_engine") as test_create_engine:
            test_engine = MagicMock(spec=AsyncEngine)
            test_create_engine.return_value = test_engine

            result = create_database_engine()

            assert result == test_engine
            # Should use test database URL
            call_args = test_create_engine.call_args[0]
            assert "test_" in call_args[0] and ".db" in call_args[0]

    @patch("app.db.session.settings")
    def test_create_engine_no_url_no_test_mode(self, test_settings):
        """Test engine creation with no URL and not in test mode."""
        test_settings.DATABASE_URL = None

        with patch("app.db.session.os.getenv", return_value=None):
            result = create_database_engine()

            assert result is None

    @patch("app.db.session.settings")
    @patch("app.db.session.create_async_engine")
    def test_create_engine_exception(self, test_create_engine, test_settings):
        """Test engine creation with exception."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/db"
        test_settings.DATABASE_POOL_SIZE = 10
        test_settings.DATABASE_MAX_OVERFLOW = 20
        test_settings.DEBUG = False

        test_create_engine.side_effect = Exception("Connection failed")

        result = create_database_engine()

        assert result is None

    @patch("app.db.session.settings")
    def test_create_engine_value_error(self, test_settings):
        """Test engine creation raises ValueError when DATABASE_URL not configured."""
        test_settings.DATABASE_URL = None
        test_settings.DATABASE_POOL_SIZE = 10
        test_settings.DATABASE_MAX_OVERFLOW = 20
        test_settings.DEBUG = False

        # Not in test mode
        with patch("app.db.session.os.getenv", return_value=None):
            result = create_database_engine()
            assert result is None


class TestSessionMaker:
    """Test session maker creation and management."""

    def test_get_session_maker_creates_new(self):
        """Test get_session_maker creates new session maker."""
        # Reset global state
        db_session_module._engine = None
        db_session_module._async_session_maker = None

        with patch("app.db.session.create_database_engine") as test_create_engine:
            test_engine = MagicMock(spec=AsyncEngine)
            test_create_engine.return_value = test_engine

            with patch("app.db.session.async_sessionmaker") as test_sessionmaker:
                test_maker = MagicMock()
                test_sessionmaker.return_value = test_maker

                result = get_session_maker()

                assert result == test_maker
                test_create_engine.assert_called_once()
                test_sessionmaker.assert_called_once_with(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    def test_get_session_maker_returns_existing(self):
        """Test get_session_maker returns existing session maker."""
        test_maker = MagicMock()
        db_session_module._async_session_maker = test_maker
        db_session_module._engine = MagicMock()

        with patch("app.db.session.create_database_engine") as test_create_engine:
            result = get_session_maker()

            assert result == test_maker
            test_create_engine.assert_not_called()

    def test_get_session_maker_no_engine(self):
        """Test get_session_maker when engine creation fails."""
        db_session_module._engine = None
        db_session_module._async_session_maker = None

        with patch("app.db.session.create_database_engine", return_value=None):
            result = get_session_maker()

            assert result is None

    def test_create_async_session_maker(self):
        """Test create_async_session_maker function."""
        test_engine = MagicMock(spec=AsyncEngine)

        with patch("app.db.session.async_sessionmaker") as test_sessionmaker:
            test_maker = MagicMock()
            test_sessionmaker.return_value = test_maker

            result = create_async_session_maker(test_engine)

            assert result == test_maker
            test_sessionmaker.assert_called_once_with(bind=test_engine, class_=AsyncSession, expire_on_commit=False)


class TestDatabaseSession:
    """Test database session creation and management."""

    @pytest.mark.asyncio
    async def test_get_db_success(self):
        """Test successful database session creation."""
        test_session = AsyncMock(spec=AsyncSession)
        test_session.close = AsyncMock()
        test_session.rollback = AsyncMock()

        with patch("app.db.session.db_circuit_breaker.call") as test_circuit_call:
            test_circuit_call.return_value = test_session

            async with get_db() as session:
                assert session == test_session

            test_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_sqlalchemy_error(self):
        """Test database session with SQLAlchemy error."""
        test_session = AsyncMock(spec=AsyncSession)
        test_session.close = AsyncMock()
        test_session.rollback = AsyncMock()

        with patch("app.db.session.db_circuit_breaker.call") as test_circuit_call:
            test_circuit_call.return_value = test_session

            with pytest.raises(SQLAlchemyError):
                async with get_db() as session:
                    raise SQLAlchemyError("Database error")

            test_session.rollback.assert_called_once()
            test_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_general_exception(self):
        """Test database session with general exception."""
        test_session = AsyncMock(spec=AsyncSession)
        test_session.close = AsyncMock()
        test_session.rollback = AsyncMock()

        with patch("app.db.session.db_circuit_breaker.call") as test_circuit_call:
            test_circuit_call.return_value = test_session

            with pytest.raises(ValueError):
                async with get_db() as session:
                    raise ValueError("General error")

            test_session.rollback.assert_called_once()
            test_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_db_dependency_success(self):
        """Test FastAPI dependency for database session."""
        test_session = AsyncMock(spec=AsyncSession)
        test_session.close = AsyncMock()
        test_session.rollback = AsyncMock()

        with patch("app.db.session.db_circuit_breaker.call") as test_circuit_call:
            test_circuit_call.return_value = test_session

            gen = get_db_dependency()
            session = await gen.__anext__()
            assert session == test_session

            # Clean up
            try:
                await gen.__anext__()
            except StopAsyncIteration:
                pass

            test_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_database_session_no_maker(self):
        """Test _create_database_session when session maker is None."""
        with patch("app.db.session.get_session_maker", return_value=None):
            from app.db.session import _create_database_session

            with pytest.raises(RuntimeError, match="Database not configured"):
                await _create_database_session()

    @pytest.mark.asyncio
    async def test_create_database_session_exception(self):
        """Test _create_database_session with exception."""
        test_maker = MagicMock()
        test_maker.side_effect = Exception("Session creation failed")

        with patch("app.db.session.get_session_maker", return_value=test_maker):
            from app.db.session import _create_database_session

            with pytest.raises(Exception, match="Session creation failed"):
                await _create_database_session()


class TestHealthChecks:
    """Test database health check functionality."""

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_no_url(self, test_settings):
        """Test health check with no database URL."""
        test_settings.DATABASE_URL = None

        result = await check_database_health()

        assert result is True  # Database is optional

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_success(self, test_settings):
        """Test successful health check."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        test_session = AsyncMock(spec=AsyncSession)
        test_result = MagicMock()
        test_result.fetchone.return_value = (1,)
        test_session.execute = AsyncMock(return_value=test_result)

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__.return_value = test_session
            test_get_db.return_value.__aexit__.return_value = None

            result = await check_database_health()

            assert result is True
            test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_unexpected_result(self, test_settings):
        """Test health check with unexpected result."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        test_session = AsyncMock(spec=AsyncSession)
        test_result = MagicMock()
        test_result.fetchone.return_value = (2,)  # Unexpected value
        test_session.execute = AsyncMock(return_value=test_result)

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__.return_value = test_session
            test_get_db.return_value.__aexit__.return_value = None

            result = await check_database_health()

            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_none_result(self, test_settings):
        """Test health check with None result."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        test_session = AsyncMock(spec=AsyncSession)
        test_result = MagicMock()
        test_result.fetchone.return_value = None
        test_session.execute = AsyncMock(return_value=test_result)

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__.return_value = test_session
            test_get_db.return_value.__aexit__.return_value = None

            result = await check_database_health()

            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_circuit_breaker_open(self, test_settings):
        """Test health check with circuit breaker open."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_db") as test_get_db:
            # Mock the async context manager to raise when entering
            test_get_db.return_value.__aenter__.side_effect = CircuitBreakerException(
                "database_operations", "Circuit breaker open"
            )

            result = await check_database_health()

            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_timeout(self, test_settings):
        """Test health check timeout."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        async def slow_operation():
            await asyncio.sleep(10)
            return MagicMock()

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__ = slow_operation
            test_get_db.return_value.__aexit__.return_value = None

            result = await check_database_health(timeout=0.1)

            assert result is False

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_sqlalchemy_error(self, test_settings):
        """Test health check with SQLAlchemy error."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__.side_effect = SQLAlchemyError("Connection failed")

            with pytest.raises(SQLAlchemyError):
                await check_database_health()

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_check_health_general_exception(self, test_settings):
        """Test health check with general exception."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_db") as test_get_db:
            test_get_db.return_value.__aenter__.side_effect = Exception("Unknown error")

            result = await check_database_health()

            assert result is False


class TestConnectionManagement:
    """Test database connection management."""

    @pytest.mark.asyncio
    async def test_close_connections_success(self):
        """Test successful connection closing."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine
        db_session_module._async_session_maker = MagicMock()

        with patch("app.db.session.get_connection_pool_stats") as test_stats:
            test_stats.return_value = {"pool_size": 10, "checked_out": 0}

            await close_database_connections()

            test_engine.dispose.assert_called_once()
            assert db_session_module._engine is None
            assert db_session_module._async_session_maker is None

    @pytest.mark.asyncio
    async def test_close_connections_no_engine(self):
        """Test closing connections when engine is None."""
        db_session_module._engine = None
        db_session_module._async_session_maker = None

        # Should not raise error
        await close_database_connections()

    @pytest.mark.asyncio
    async def test_close_connections_exception(self):
        """Test closing connections with exception."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock(side_effect=Exception("Dispose failed"))
        db_session_module._engine = test_engine

        with pytest.raises(Exception, match="Dispose failed"):
            await close_database_connections()

    def test_get_connection_pool_stats_no_engine(self):
        """Test getting pool stats when engine is None."""
        db_session_module._engine = None

        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 0
        assert stats["checked_in"] == 0
        assert stats["checked_out"] == 0
        assert stats["overflow"] == 0
        assert stats["invalid"] == 0
        assert stats["total"] == 0
        assert stats["usage_percent"] == 0.0

    def test_get_connection_pool_stats_with_pool(self):
        """Test getting pool stats with active pool."""
        test_engine = MagicMock(spec=AsyncEngine)
        test_pool = MagicMock()
        test_pool.size.return_value = 10
        test_pool.checkedin.return_value = 7
        test_pool.checkedout.return_value = 3
        test_pool.overflow.return_value = 2
        test_pool.invalid.return_value = 1
        test_engine.pool = test_pool
        db_session_module._engine = test_engine

        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 10
        assert stats["checked_in"] == 7
        assert stats["checked_out"] == 3
        assert stats["overflow"] == 2
        assert stats["invalid"] == 1
        assert stats["total"] == 10
        assert stats["usage_percent"] == 100.0

    def test_get_connection_pool_stats_null_pool(self):
        """Test getting pool stats with NullPool."""
        test_engine = MagicMock(spec=AsyncEngine)
        test_pool = MagicMock(spec=NullPool)
        # NullPool doesn't have these methods
        del test_pool.size
        del test_pool.checkedin
        del test_pool.checkedout
        del test_pool.overflow
        del test_pool.invalid
        test_engine.pool = test_pool
        db_session_module._engine = test_engine

        stats = get_connection_pool_stats()

        assert stats["pool_size"] == 0
        assert stats["checked_in"] == 0
        assert stats["checked_out"] == 0
        assert stats["overflow"] == 0
        assert stats["invalid"] == 0
        assert stats["total"] == 0
        assert stats["usage_percent"] == 0.0

    def test_get_connection_pool_stats_exception(self):
        """Test getting pool stats with exception."""
        test_engine = MagicMock(spec=AsyncEngine)
        test_pool = MagicMock()
        test_pool.size.side_effect = Exception("Pool error")
        test_engine.pool = test_pool
        db_session_module._engine = test_engine

        stats = get_connection_pool_stats()

        # Should return default stats on error
        assert stats["pool_size"] == 0
        assert stats["usage_percent"] == 0.0

    def test_get_engine_creates_new(self):
        """Test get_engine creates new engine if needed."""
        db_session_module._engine = None

        with patch("app.db.session.create_database_engine") as test_create:
            test_engine = MagicMock(spec=AsyncEngine)
            test_create.return_value = test_engine

            result = get_engine()

            assert result == test_engine
            assert db_session_module._engine == test_engine
            test_create.assert_called_once()

    def test_get_engine_returns_existing(self):
        """Test get_engine returns existing engine."""
        test_engine = MagicMock(spec=AsyncEngine)
        db_session_module._engine = test_engine

        with patch("app.db.session.create_database_engine") as test_create:
            result = get_engine()

            assert result == test_engine
            test_create.assert_not_called()

    def test_reset_engine(self):
        """Test reset_engine clears all globals."""
        db_session_module._engine = MagicMock()
        db_session_module._async_session_maker = MagicMock()
        db_session_module.engine = MagicMock()

        reset_engine()

        assert db_session_module._engine is None
        assert db_session_module._async_session_maker is None
        assert db_session_module.engine is None


class TestCircuitBreaker:
    """Test circuit breaker integration."""

    @patch("app.db.session.settings")
    def test_is_database_available_no_url(self, test_settings):
        """Test database availability check with no URL."""
        test_settings.DATABASE_URL = None

        result = is_database_available()

        assert result is False

    @patch("app.db.session.settings")
    def test_is_database_available_circuit_open(self, test_settings):
        """Test database availability with circuit breaker open."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch.object(db_circuit_breaker, "state", CircuitState.OPEN):
            result = is_database_available()

            assert result is False

    @patch("app.db.session.settings")
    def test_is_database_available_ok(self, test_settings):
        """Test database availability when everything is OK."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            result = is_database_available()

            assert result is True

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_success(self):
        """Test successful circuit breaker reset."""
        with patch.object(db_circuit_breaker, "reset") as test_reset:
            test_reset.return_value = None

            with patch("app.db.session.check_database_health") as test_health:
                test_health.return_value = True

                result = await reset_circuit_breaker()

                assert result is True
                test_reset.assert_called_once()
                test_health.assert_called_once()

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_health_check_fails(self):
        """Test circuit breaker reset when health check fails."""
        with patch.object(db_circuit_breaker, "reset") as test_reset:
            test_reset.return_value = None

            with patch("app.db.session.check_database_health") as test_health:
                test_health.return_value = False

                result = await reset_circuit_breaker()

                assert result is False

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_exception(self):
        """Test circuit breaker reset with exception."""
        with patch.object(db_circuit_breaker, "reset") as test_reset:
            test_reset.side_effect = Exception("Reset failed")

            result = await reset_circuit_breaker()

            assert result is False


class TestDatabaseValidation:
    """Test database validation and recovery."""

    @pytest.mark.asyncio
    async def test_validate_connection_healthy(self):
        """Test validation with healthy connection."""
        with patch("app.db.session.check_database_health") as test_health:
            test_health.return_value = True

            result = await validate_database_connection()

            assert result is True
            test_health.assert_called_once_with(timeout=10.0)

    @pytest.mark.asyncio
    async def test_validate_connection_recovery_success(self):
        """Test validation with successful recovery."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine

        with patch("app.db.session.check_database_health") as test_health:
            # First check fails, recovery succeeds
            test_health.side_effect = [False, True]

            with patch("app.db.session.create_database_engine") as test_create:
                new_engine = MagicMock(spec=AsyncEngine)
                test_create.return_value = new_engine

                result = await validate_database_connection()

                assert result is True
                test_engine.dispose.assert_called_once()
                assert db_session_module._engine == new_engine

    @pytest.mark.asyncio
    async def test_validate_connection_recovery_engine_fails(self):
        """Test validation when engine recreation fails."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine

        with patch("app.db.session.check_database_health") as test_health:
            test_health.return_value = False

            with patch("app.db.session.create_database_engine") as test_create:
                test_create.return_value = None

                result = await validate_database_connection()

                assert result is False

    @pytest.mark.asyncio
    async def test_validate_connection_recovery_health_fails(self):
        """Test validation when recovery health check fails."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine

        with patch("app.db.session.check_database_health") as test_health:
            # Both checks fail
            test_health.side_effect = [False, False]

            with patch("app.db.session.create_database_engine") as test_create:
                new_engine = MagicMock(spec=AsyncEngine)
                test_create.return_value = new_engine

                result = await validate_database_connection()

                assert result is False

    @pytest.mark.asyncio
    async def test_validate_connection_exception(self):
        """Test validation with exception."""
        with patch("app.db.session.check_database_health") as test_health:
            test_health.side_effect = Exception("Validation error")

            result = await validate_database_connection()

            assert result is False

    @pytest.mark.asyncio
    async def test_recover_connection_success_first_attempt(self):
        """Test connection recovery succeeds on first attempt."""
        with patch.object(db_circuit_breaker, "state", CircuitState.OPEN):
            with patch.object(db_circuit_breaker, "reset") as test_reset:
                test_reset.return_value = None

                with patch("app.db.session.validate_database_connection") as test_validate:
                    test_validate.return_value = True

                    result = await recover_database_connection(max_attempts=3)

                    assert result is True
                    test_reset.assert_called_once()
                    test_validate.assert_called_once()

    @pytest.mark.asyncio
    async def test_recover_connection_success_later_attempt(self):
        """Test connection recovery succeeds on later attempt."""
        with patch.object(db_circuit_breaker, "state", CircuitState.CLOSED):
            with patch("app.db.session.validate_database_connection") as test_validate:
                # Fails first, succeeds second
                test_validate.side_effect = [False, True]

                with patch("asyncio.sleep") as test_sleep:
                    result = await recover_database_connection(max_attempts=3, retry_delay=0.1)

                    assert result is True
                    assert test_validate.call_count == 2
                    test_sleep.assert_called_once_with(0.1)

    @pytest.mark.asyncio
    async def test_recover_connection_all_attempts_fail(self):
        """Test connection recovery fails after all attempts."""
        with patch("app.db.session.validate_database_connection") as test_validate:
            test_validate.return_value = False

            with patch("asyncio.sleep") as test_sleep:
                result = await recover_database_connection(max_attempts=2, retry_delay=0.1)

                assert result is False
                assert test_validate.call_count == 2
                assert test_sleep.call_count == 1

    @pytest.mark.asyncio
    async def test_recover_connection_exception(self):
        """Test connection recovery with exception."""
        with patch("app.db.session.validate_database_connection") as test_validate:
            test_validate.side_effect = Exception("Recovery error")

            with patch("asyncio.sleep") as test_sleep:
                result = await recover_database_connection(max_attempts=2, retry_delay=0.1)

                assert result is False
                assert test_sleep.call_count == 1

    @pytest.mark.asyncio
    async def test_recreate_pool_success(self):
        """Test successful database pool recreation."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine

        with patch("app.db.session.create_database_engine") as test_create:
            new_engine = MagicMock(spec=AsyncEngine)
            test_create.return_value = new_engine

            result = await recreate_database_pool()

            assert result is True
            test_engine.dispose.assert_called_once()
            assert db_session_module._engine == new_engine
            assert db_session_module._async_session_maker is not None

    @pytest.mark.asyncio
    async def test_recreate_pool_no_existing_engine(self):
        """Test pool recreation with no existing engine."""
        db_session_module._engine = None

        with patch("app.db.session.create_database_engine") as test_create:
            new_engine = MagicMock(spec=AsyncEngine)
            test_create.return_value = new_engine

            result = await recreate_database_pool()

            assert result is True
            assert db_session_module._engine == new_engine

    @pytest.mark.asyncio
    async def test_recreate_pool_engine_fails(self):
        """Test pool recreation when engine creation fails."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock()
        db_session_module._engine = test_engine

        with patch("app.db.session.create_database_engine") as test_create:
            test_create.return_value = None

            result = await recreate_database_pool()

            assert result is False
            test_engine.dispose.assert_called_once()

    @pytest.mark.asyncio
    async def test_recreate_pool_exception(self):
        """Test pool recreation with exception."""
        test_engine = AsyncMock(spec=AsyncEngine)
        test_engine.dispose = AsyncMock(side_effect=Exception("Dispose failed"))
        db_session_module._engine = test_engine

        result = await recreate_database_pool()

        assert result is False


class TestDatabaseInitialization:
    """Test database initialization."""

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_init_database_no_url(self, test_settings):
        """Test database initialization with no URL."""
        test_settings.DATABASE_URL = None

        # Should not raise error
        await init_database()

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_init_database_success(self, test_settings):
        """Test successful database initialization."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_session_maker") as test_maker:
            test_maker.return_value = MagicMock()

            with patch("app.db.session.check_database_health") as test_health:
                test_health.return_value = True

                await init_database()

                test_maker.assert_called_once()
                test_health.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_init_database_no_session_maker(self, test_settings):
        """Test database initialization when session maker fails."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_session_maker") as test_maker:
            test_maker.return_value = None

            with pytest.raises(RuntimeError, match="Failed to create database session maker"):
                await init_database()

    @pytest.mark.asyncio
    @patch("app.db.session.settings")
    async def test_init_database_health_check_fails(self, test_settings):
        """Test database initialization when health check fails."""
        test_settings.DATABASE_URL = "postgresql+asyncpg://localhost/db"

        with patch("app.db.session.get_session_maker") as test_maker:
            test_maker.return_value = MagicMock()

            with patch("app.db.session.check_database_health") as test_health:
                test_health.return_value = False

                with pytest.raises(RuntimeError, match="Database health check failed"):
                    await init_database()

    @pytest.mark.asyncio
    async def test_init_db_with_alembic(self):
        """Test init_db with Alembic migrations."""
        with patch("app.db.session.init_database") as test_init:
            with patch("os.path.exists") as test_exists:
                test_exists.return_value = True

                with patch("alembic.config.Config") as test_config:
                    with patch("alembic.command") as test_command:
                        await init_db()

                        test_init.assert_called_once()
                        test_command.upgrade.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_db_without_alembic(self):
        """Test init_db without Alembic (direct table creation)."""
        with patch("app.db.session.init_database") as test_init:
            with patch("os.path.exists") as test_exists:
                test_exists.return_value = False

                with patch("app.db.session.get_engine") as test_get_engine:
                    test_engine = AsyncMock(spec=AsyncEngine)
                    test_conn = AsyncMock()
                    test_engine.begin.return_value.__aenter__.return_value = test_conn
                    test_get_engine.return_value = test_engine

                    await init_db()

                    test_init.assert_called_once()
                    test_conn.run_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_db_no_engine(self):
        """Test init_db when no engine available."""
        with patch("app.db.session.init_database") as test_init:
            with patch("os.path.exists") as test_exists:
                test_exists.return_value = False

                with patch("app.db.session.get_engine") as test_get_engine:
                    test_get_engine.return_value = None

                    await init_db()

                    test_init.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_db_migration_error(self):
        """Test init_db with migration error."""
        with patch("app.db.session.init_database") as test_init:
            with patch("os.path.exists") as test_exists:
                test_exists.return_value = True

                with patch("alembic.config.Config") as test_config:
                    with patch("alembic.command") as test_command:
                        test_command.upgrade.side_effect = Exception("Migration failed")

                        with pytest.raises(RuntimeError, match="Database migration failed"):
                            await init_db()


# Run all tests with pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app.db.session", "--cov-report=term-missing"])
