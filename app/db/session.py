"""Database session management with connection pooling and health checks."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)

# Global engine and session maker
engine: Optional[AsyncEngine] = None
async_session_maker: Optional[async_sessionmaker[AsyncSession]] = None


def create_database_engine() -> Optional[AsyncEngine]:
    """Create database engine with connection pooling."""
    if not settings.DATABASE_URL:
        logger.warning("No database URL configured - database features disabled")
        return None

    try:
        # Create async engine with connection pooling
        db_engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,  # Validate connections before use
            pool_recycle=3600,  # Recycle connections after 1 hour
        )
        logger.info("Database engine created successfully")
        return db_engine
    except Exception as e:
        logger.error("Failed to create database engine", error=str(e))
        return None


def get_session_maker() -> Optional[async_sessionmaker[AsyncSession]]:
    """Get or create the session maker."""
    global engine, async_session_maker

    if async_session_maker is None:
        engine = create_database_engine()
        if engine is None:
            return None

        async_session_maker = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info("Database session maker created")

    return async_session_maker


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session with proper cleanup.

    Usage:
        async with get_db() as db:
            result = await db.execute(text("SELECT 1"))
    """
    session_maker = get_session_maker()
    if session_maker is None:
        raise RuntimeError("Database not configured")

    async with session_maker() as session:
        try:
            yield session
        except Exception as e:
            logger.error("Database session error", error=str(e))
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_database_health(timeout: float = 5.0) -> bool:
    """
    Check database connectivity with timeout.

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

    except asyncio.TimeoutError:
        logger.error("Database health check timed out", timeout=timeout)
        return False
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return False


async def close_database_connections() -> None:
    """Close all database connections for graceful shutdown."""
    global engine

    if engine is not None:
        logger.info("Closing database connections")
        await engine.dispose()
        engine = None
        logger.info("Database connections closed")
