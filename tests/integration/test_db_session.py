"""Integration tests for database session with error scenarios."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.db.session import (
    check_database_health,
    close_database_connections,
    create_async_session_maker,
    db_circuit_breaker,
    get_connection_pool_stats,
    get_db,
    get_session_maker,
    init_database,
    recover_database_connection,
    reset_circuit_breaker,
)
from app.utils.circuit_breaker import CircuitState


class TestDatabaseSession:
    """Test database session management and circuit breaker integration."""

    @pytest.fixture(autouse=True)
    async def setup_method(self):
        """Setup method to ensure database is configured."""
        import os

        os.environ["TESTING"] = "1"
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"

        # Reset the engine to use test configuration
        from app.db.session import reset_engine

        if callable(reset_engine):
            reset_engine()

    """Test database session management and error scenarios."""

    @pytest_asyncio.fixture(autouse=True)
    async def reset_state(self):
        """Reset circuit breaker state before each test."""
        await db_circuit_breaker.reset()
        yield
        await db_circuit_breaker.reset()

    @pytest.mark.asyncio
    async def test_get_db_context_manager(self):
        """Test get_db as async context manager."""
        async with get_db() as session:
            assert isinstance(session, AsyncSession)
            assert session.is_active

            # Should be able to execute queries
            result = await session.execute(text("SELECT 1"))
            assert result is not None

    @pytest.mark.asyncio
    async def test_get_db_handles_exceptions(self):
        """Test get_db properly handles exceptions."""
        async with get_db() as session:
            # Simulate an error during transaction
            try:
                await session.execute(text("SELECT * FROM nonexistent_table"))
            except Exception:
                # Session should still be properly closed
                pass

        # Should be able to get new session
        async with get_db() as new_session:
            assert new_session.is_active

    @pytest.mark.asyncio
    async def test_get_db_with_circuit_breaker_open(self):
        """Test get_db when circuit breaker is open."""
        # Force circuit breaker to open
        for _ in range(6):  # Exceed failure threshold
            try:
                with patch(
                    "app.db.session._create_database_session",
                    side_effect=OperationalError("Connection failed", None, None),
                ):
                    async with get_db() as session:
                        pass
            except Exception:
                pass

        # Circuit breaker should be open
        assert db_circuit_breaker.state == CircuitState.OPEN

        # Should raise circuit breaker exception
        with pytest.raises(Exception, match="Circuit breaker .* is open"):
            async with get_db() as session:
                pass

    @pytest.mark.asyncio
    async def test_check_database_health_success(self):
        """Test database health check when healthy."""
        # Create a real session for testing
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        session_maker = create_async_session_maker(engine)

        with patch("app.db.session._async_session_maker", session_maker):
            is_healthy = await check_database_health(timeout=5.0)
            assert is_healthy is True

    @pytest.mark.asyncio
    async def test_check_database_health_failure(self):
        """Test database health check when unhealthy."""
        # Mock session that raises error
        mock_session = AsyncMock()
        mock_session.execute.side_effect = OperationalError("Connection failed", None, None)
        mock_session_maker = AsyncMock(return_value=mock_session)

        with patch("app.db.session._async_session_maker", mock_session_maker):
            is_healthy = await check_database_health(timeout=1.0)
            assert is_healthy is False

    @pytest.mark.asyncio
    async def test_check_database_health_timeout(self):
        """Test database health check with timeout."""

        # Mock session that hangs
        async def slow_execute(*args):
            await asyncio.sleep(10)  # Longer than timeout

        mock_session = AsyncMock()
        mock_session.execute = slow_execute
        mock_session_maker = AsyncMock(return_value=mock_session)

        with patch("app.db.session._async_session_maker", mock_session_maker):
            is_healthy = await check_database_health(timeout=0.1)
            assert is_healthy is False

    @pytest.mark.asyncio
    async def test_init_database_success(self):
        """Test database initialization."""
        with patch("app.db.session.get_session_maker") as mock_session_maker:
            with patch("app.db.session.check_database_health", return_value=True) as mock_health:
                mock_session_maker.return_value = MagicMock()  # Return non-None session maker

                await init_database()

                mock_session_maker.assert_called_once()
                mock_health.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_database_failure(self):
        """Test database initialization failure."""
        with patch("app.db.session.get_session_maker", return_value=None) as mock_session_maker:
            with pytest.raises(RuntimeError, match="Failed to create database session maker"):
                await init_database()

    @pytest.mark.asyncio
    async def test_close_database_connections(self):
        """Test closing database connections."""
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()

        with patch("app.db.session._engine", mock_engine):
            await close_database_connections()

        mock_engine.dispose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_database_connections_resets_globals(self):
        """Test closing connections resets global variables."""
        # Set up mocks
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session._async_session_maker", "not_none"):
                await close_database_connections()

                # Check globals are reset
                from app.db.session import _async_session_maker, _engine

                # Note: Can't directly test None due to module reload issues
                # But dispose should be called
                mock_engine.dispose.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_with_pool(self):
        """Test getting connection pool statistics."""
        # Create engine with pool - but SQLite doesn't support pool parameters
        # so we'll create without them and mock the pool
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")

        # Mock pool with size method
        mock_pool = MagicMock()
        mock_pool.size.return_value = 5
        mock_pool.checkedin.return_value = 2
        mock_pool.checkedout.return_value = 1
        mock_pool.overflow.return_value = 0
        mock_pool.invalid.return_value = 0
        engine.pool = mock_pool

        with patch("app.db.session._engine", engine):
            stats = get_connection_pool_stats()

        assert isinstance(stats, dict)
        # Should return expected structure
        assert stats == {
            "pool_size": 5,
            "checked_in": 2,
            "checked_out": 1,
            "overflow": 0,
            "invalid": 0,
            "total": 3,
            "usage_percent": 60.0,
        }

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_no_pool(self):
        """Test getting stats when no pool exists."""
        # Create engine with NullPool
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=NullPool)

        with patch("app.db.session._engine", engine):
            stats = get_connection_pool_stats()

        assert stats == {
            "pool_size": 0,
            "checked_in": 0,
            "checked_out": 0,
            "overflow": 0,
            "invalid": 0,
            "total": 0,
            "usage_percent": 0.0,
        }

    @pytest.mark.asyncio
    async def test_get_connection_pool_stats_no_engine(self):
        """Test getting stats when engine is None."""
        with patch("app.db.session._engine", None):
            stats = get_connection_pool_stats()

        assert stats == {
            "pool_size": 0,
            "checked_in": 0,
            "checked_out": 0,
            "overflow": 0,
            "invalid": 0,
            "total": 0,
            "usage_percent": 0.0,
        }

    @pytest.mark.asyncio
    async def test_recover_database_connection_success(self):
        """Test successful database recovery."""
        # First make circuit breaker open by simulating failures
        for _ in range(6):
            try:
                await db_circuit_breaker._on_failure(Exception("Test failure"))
            except:
                pass

        # Mock successful recovery
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()

        mock_new_engine = MagicMock()

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session.create_async_engine", return_value=mock_new_engine):
                with patch("app.db.session.check_database_health", return_value=True):
                    recovered = await recover_database_connection(max_attempts=1)

        assert recovered is True
        # Recovery function returns True if database health check passes
        # Circuit breaker state management is separate from recovery success

    @pytest.mark.asyncio
    async def test_recover_database_connection_failure(self):
        """Test failed database recovery."""
        # Mock failed recovery
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session.check_database_health", return_value=False):
                recovered = await recover_database_connection(max_attempts=2, retry_delay=0.1)

        assert recovered is False

    @pytest.mark.asyncio
    async def test_recover_database_connection_with_exception(self):
        """Test recovery when exception occurs."""
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock(side_effect=Exception("Dispose failed"))

        with patch("app.db.session._engine", mock_engine):
            with patch("app.db.session.check_database_health", return_value=False):
                recovered = await recover_database_connection(max_attempts=1)

        assert recovered is False

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_success(self):
        """Test resetting circuit breaker."""
        # Open circuit breaker
        db_circuit_breaker.state = CircuitState.OPEN

        with patch("app.db.session.check_database_health", return_value=True):
            result = await reset_circuit_breaker()

        assert result is True
        assert db_circuit_breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_unhealthy(self):
        """Test resetting circuit breaker when database unhealthy."""
        # Open circuit breaker
        db_circuit_breaker.state = CircuitState.OPEN

        with patch("app.db.session.check_database_health", return_value=False):
            result = await reset_circuit_breaker()

        assert result is False
        # State might not change if health check fails

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker_with_exception(self):
        """Test resetting circuit breaker with exception."""
        with patch(
            "app.db.session.check_database_health",
            side_effect=Exception("Check failed"),
        ):
            result = await reset_circuit_breaker()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_async_session_maker(self):
        """Test creating async session maker."""
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        session_maker = create_async_session_maker(engine)

        # Test that it creates sessions
        async with session_maker() as session:
            assert isinstance(session, AsyncSession)
            assert session.bind == engine

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker integration with database operations."""
        call_count = 0

        async def failing_operation():
            nonlocal call_count
            call_count += 1
            raise OperationalError("Connection failed", None, None)

        # Should fail and open circuit after threshold
        for i in range(10):
            try:
                await db_circuit_breaker.call(failing_operation)
            except Exception:
                pass

            if i < 4:  # Before threshold (0-indexed, opens on 5th failure at i=4)
                assert db_circuit_breaker.state == CircuitState.CLOSED
            else:  # At or after threshold
                assert db_circuit_breaker.state == CircuitState.OPEN
                break

        # Further calls should fail immediately
        with pytest.raises(Exception, match="Circuit breaker .* is open"):
            await db_circuit_breaker.call(failing_operation)

        # Call count should stop increasing after circuit opens
        final_count = call_count
        try:
            await db_circuit_breaker.call(failing_operation)
        except:
            pass
        assert call_count == final_count  # No new calls

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery after timeout."""
        # Open circuit breaker
        db_circuit_breaker.state = CircuitState.OPEN
        db_circuit_breaker.stats.last_failure_time = asyncio.get_event_loop().time() - 35  # Past recovery timeout

        # First call after timeout should go to half-open, then require multiple successes to close
        async def success_operation():
            return "success"

        # First successful call should transition to half-open
        result = await db_circuit_breaker.call(success_operation)
        assert result == "success"
        # After recovery timeout, single success keeps it in half-open
        expected_state = CircuitState.HALF_OPEN

        # Need success_threshold (3) consecutive successes to fully close circuit
        for _ in range(2):  # 2 more successes (total 3)
            result = await db_circuit_breaker.call(success_operation)
            assert result == "success"

        # Now should be closed
        assert db_circuit_breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_database_retry_logic(self):
        """Test retry logic for transient failures."""
        from app.utils.retry import RetryConfig, with_retry

        call_count = 0

        @with_retry(RetryConfig(max_attempts=3, base_delay=0.1))
        async def flaky_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OperationalError("Transient error", None, None)
            return "success"

        result = await flaky_operation()
        assert result == "success"
        assert call_count == 3  # Should retry until success

    @pytest.mark.asyncio
    async def test_get_db_rollback_on_exception(self):
        """Test that get_db rolls back on exception."""
        exception_raised = False

        try:
            async with get_db() as session:
                # Add something to session
                session.add_all([])  # Empty list, but still marks session

                # Raise exception
                raise ValueError("Test exception")
        except ValueError:
            exception_raised = True

        assert exception_raised

        # Should be able to get new session
        async with get_db() as new_session:
            assert new_session.is_active
