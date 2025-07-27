"""Database session management with connection pooling and health checks."""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional, Union

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from structlog.stdlib import get_logger

from ..core.config import settings
from ..utils.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerException, CircuitState
from ..utils.retry import with_retry

logger = get_logger(__name__)

# Global engine and session maker
_engine: Optional[AsyncEngine] = None
_async_session_maker: Optional[async_sessionmaker[AsyncSession]] = None

# Circuit breaker for database operations
db_circuit_breaker = CircuitBreaker(
    name="database_operations",
    config=CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=30.0,
    ),
)


def create_database_engine() -> Optional[AsyncEngine]:
    """Create database engine with enhanced connection pooling and resilience."""
    # For testing, allow override of database URL
    database_url = settings.DATABASE_URL
    if not database_url and os.getenv("TESTING"):
        database_url = "sqlite+aiosqlite:///./test.db"
        logger.info("Using test database URL", url=database_url)

    if not database_url:
        logger.warning("No database URL configured - database features disabled")
        return None

    try:
        # Enhanced connection pool settings based on ViolentUTF patterns
        pool_settings = {
            "pool_size": settings.DATABASE_POOL_SIZE,
            "max_overflow": settings.DATABASE_MAX_OVERFLOW,
            "pool_pre_ping": True,  # Validate connections before use
            "pool_recycle": 3600,  # Recycle connections after 1 hour
            "pool_timeout": 30,  # Timeout when getting connection from pool
            "pool_reset_on_return": "commit",  # Reset connections on return
        }

        # SQLite-specific optimizations
        if settings.DATABASE_URL and settings.DATABASE_URL.startswith(("sqlite", "sqlite+aiosqlite")):
            # SQLite doesn't support connection pooling parameters
            pool_settings = {
                "pool_pre_ping": True,  # Validate connections before use
                "pool_recycle": 3600,  # Recycle connections after 1 hour
                "pool_reset_on_return": "commit",  # Reset connections on return
            }
            logger.debug("Using SQLite-optimized connection settings")

        # Create async engine with enhanced settings
        if not settings.DATABASE_URL:
            raise ValueError("DATABASE_URL is not configured")

        db_engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            **pool_settings,
            # Additional resilience settings
            connect_args=(
                {
                    "check_same_thread": False,  # For SQLite async compatibility
                }
                if settings.DATABASE_URL and settings.DATABASE_URL.startswith("sqlite")
                else {}
            ),
        )

        logger.info(
            "Database engine created successfully",
            pool_size=pool_settings.get("pool_size", "N/A"),
            max_overflow=pool_settings.get("max_overflow", "N/A"),
            database_type="sqlite" if settings.DATABASE_URL and "sqlite" in settings.DATABASE_URL else "postgresql",
        )
        return db_engine

    except Exception as e:
        logger.error("Failed to create database engine", error=str(e))
        return None


def get_session_maker() -> Optional[async_sessionmaker[AsyncSession]]:
    """Get or create the session maker."""
    global _engine, _async_session_maker

    if _async_session_maker is None:
        _engine = create_database_engine()
        if _engine is None:
            return None

        _async_session_maker = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info("Database session maker created")

    return _async_session_maker


async def _create_database_session() -> AsyncSession:
    """Create a database session - used internally by circuit breaker."""
    session_maker = get_session_maker()
    if session_maker is None:
        logger.error("Cannot create session: database not configured")
        raise RuntimeError("Database not configured")

    try:
        session = session_maker()
        logger.debug("Database session created successfully")
        return session
    except Exception as e:
        logger.error("Failed to create database session", error=str(e))
        raise


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session with proper cleanup, circuit breaker protection, and retry logic.

    Usage:
        async with get_db() as db:
            result = await db.execute(text("SELECT 1"))
    """
    # Use circuit breaker to protect session creation
    session: AsyncSession = await db_circuit_breaker.call(_create_database_session)

    try:
        yield session
    except SQLAlchemyError as e:
        logger.error("Database SQLAlchemy error", error=str(e))
        await session.rollback()
        raise
    except Exception as e:
        logger.error("Database session error", error=str(e))
        await session.rollback()
        raise
    finally:
        await session.close()


@with_retry()
async def check_database_health(timeout: float = 5.0) -> bool:
    """
    Check database connectivity with timeout and retry logic.

    Args:
        timeout: Maximum time to wait for database response

    Returns:
        True if database is healthy, False otherwise
    """
    if not settings.DATABASE_URL:
        logger.debug("Database URL not configured - skipping health check")
        return True  # Database is optional

    try:
        async with asyncio.timeout(timeout):
            async with get_db() as db:
                # Simple query to test connectivity
                result = await db.execute(text("SELECT 1 as health_check"))
                row = result.fetchone()

                if row and row[0] == 1:
                    logger.debug("Database health check passed")
                    return True
                else:
                    logger.error("Database health check failed - unexpected result")
                    return False

    except CircuitBreakerException:
        logger.warning("Database health check skipped - circuit breaker open")
        return False
    except asyncio.TimeoutError:
        logger.error("Database health check timed out", timeout=timeout)
        return False
    except SQLAlchemyError as e:
        logger.error("Database health check failed - SQLAlchemy error", error=str(e))
        # Let retry logic handle SQLAlchemy errors
        raise
    except Exception as e:
        logger.error("Database health check failed - general error", error=str(e))
        return False


async def close_database_connections() -> None:
    """Close all database connections for graceful shutdown."""
    global _engine, _async_session_maker

    if _engine is not None:
        try:
            # Log connection pool statistics before closing
            pool_stats = get_connection_pool_stats()
            logger.info("Closing database connections", pool_stats=pool_stats)

            await _engine.dispose()
            _engine = None
            _async_session_maker = None

            logger.info("Database connections closed successfully")
        except Exception as e:
            logger.error("Error closing database connections", error=str(e))
            raise


def get_connection_pool_stats() -> Dict[str, Union[int, float]]:
    """
    Get connection pool statistics for monitoring.

    Returns:
        Dictionary with pool statistics
    """
    if _engine is None:
        return {
            "pool_size": 0,
            "checked_in": 0,
            "checked_out": 0,
            "overflow": 0,
            "invalid": 0,
            "total": 0,
            "usage_percent": 0.0,
        }

    try:
        pool = _engine.pool

        # Handle NullPool (no connection pooling)
        if hasattr(pool, "size") and callable(pool.size):
            pool_size = pool.size()
        else:
            # NullPool or other pools without size method
            pool_size = 0

        if hasattr(pool, "checkedin") and callable(pool.checkedin):
            checked_in = pool.checkedin()
        else:
            checked_in = 0

        if hasattr(pool, "checkedout") and callable(pool.checkedout):
            checked_out = pool.checkedout()
        else:
            checked_out = 0

        if hasattr(pool, "overflow") and callable(pool.overflow):
            overflow = pool.overflow()
        else:
            overflow = 0

        if hasattr(pool, "invalid") and callable(pool.invalid):
            invalid = pool.invalid()
        else:
            invalid = 0

        stats = {
            "pool_size": pool_size,
            "checked_in": checked_in,
            "checked_out": checked_out,
            "overflow": overflow,
            "invalid": invalid,
        }

        # Calculate total and utilization percentage
        total_connections = stats["checked_in"] + stats["checked_out"]
        stats["total"] = total_connections

        if pool_size > 0:
            stats["usage_percent"] = (total_connections / pool_size) * 100
        else:
            stats["usage_percent"] = 0.0

        return stats

    except Exception as e:
        logger.error("Failed to get connection pool stats", error=str(e))
        return {
            "pool_size": 0,
            "checked_in": 0,
            "checked_out": 0,
            "overflow": 0,
            "invalid": 0,
            "total": 0,
            "usage_percent": 0.0,
        }


async def validate_database_connection() -> bool:
    """
    Validate database connection and attempt recovery if needed.

    Returns:
        True if connection is valid or recovered, False otherwise
    """
    try:
        # First try a simple health check
        is_healthy = await check_database_health(timeout=10.0)

        if is_healthy:
            logger.debug("Database connection validated successfully")
            return True

        # If health check failed, try to recreate the engine
        logger.warning("Database connection validation failed, attempting recovery")

        global _engine, _async_session_maker

        # Close existing connections
        if _engine:
            await _engine.dispose()

        # Recreate engine and session maker
        _engine = create_database_engine()
        if _engine is None:
            logger.error("Failed to recreate database engine")
            return False

        _async_session_maker = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Test the new connection
        is_recovered = await check_database_health(timeout=10.0)

        if is_recovered:
            logger.info("Database connection recovered successfully")
            return True
        else:
            logger.error("Database connection recovery failed")
            return False

    except Exception as e:
        logger.error("Database connection validation failed", error=str(e))
        return False


def is_database_available() -> bool:
    """
    Quick check if database is configured and circuit breaker allows connections.

    Returns:
        True if database operations should be attempted, False otherwise
    """
    if not settings.DATABASE_URL:
        return False

    if db_circuit_breaker.state == CircuitState.OPEN:
        return False

    return True


async def reset_circuit_breaker() -> bool:
    """
    Manually reset the database circuit breaker after resolving issues.

    Returns:
        True if reset was successful, False otherwise
    """
    try:
        await db_circuit_breaker.reset()
        logger.info("Database circuit breaker reset manually")

        # Test the connection after reset
        is_healthy = await check_database_health()

        if is_healthy:
            logger.info("Database connection verified after circuit breaker reset")
            return True
        else:
            logger.warning("Database still unhealthy after circuit breaker reset")
            return False

    except Exception as e:
        logger.error("Failed to reset database circuit breaker", error=str(e))
        return False


async def init_database() -> None:
    """
    Initialize database connection and verify connectivity.

    Raises:
        RuntimeError: If database initialization fails
    """
    logger.info("Initializing database connection")

    if not settings.DATABASE_URL:
        logger.warning("No database URL configured - skipping initialization")
        return

    # Create the engine and session maker
    session_maker = get_session_maker()
    if session_maker is None:
        raise RuntimeError("Failed to create database session maker")

    # Verify connectivity
    is_healthy = await check_database_health()
    if not is_healthy:
        raise RuntimeError("Database health check failed during initialization")

    logger.info("Database initialized successfully")


def create_async_session_maker(bind_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """
    Create an async session maker with the given engine.

    Args:
        bind_engine: The async engine to bind sessions to

    Returns:
        Configured async session maker
    """
    return async_sessionmaker(
        bind=bind_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def recover_database_connection(max_attempts: int = 3, retry_delay: float = 1.0) -> bool:
    """
    Attempt to recover database connection with retries.

    Args:
        max_attempts: Maximum number of recovery attempts
        retry_delay: Delay between attempts in seconds

    Returns:
        True if recovery succeeded, False otherwise
    """
    logger.warning("Starting database connection recovery", max_attempts=max_attempts, retry_delay=retry_delay)

    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Recovery attempt {attempt}/{max_attempts}")

            # Reset circuit breaker if needed
            if db_circuit_breaker.state == CircuitState.OPEN:
                await db_circuit_breaker.reset()

            # Validate and potentially recreate connection
            is_valid = await validate_database_connection()

            if is_valid:
                logger.info(f"Database connection recovered on attempt {attempt}")
                return True

            # Wait before next attempt (except on last attempt)
            if attempt < max_attempts:
                await asyncio.sleep(retry_delay)
                retry_delay = retry_delay * 2  # Exponential backoff

        except Exception as e:
            logger.error(f"Recovery attempt {attempt} failed with exception", error=str(e))
            if attempt < max_attempts:
                await asyncio.sleep(retry_delay)
                retry_delay = retry_delay * 2

    logger.error("Database connection recovery failed after all attempts")
    return False


def reset_engine() -> None:
    """Reset the database engine for testing."""
    global _engine, _async_session_maker
    _engine = None
    _async_session_maker = None
