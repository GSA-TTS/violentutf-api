"""Database utilities and fixtures for testing."""

import asyncio
import os
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.sql import text

from app.core.config import settings
from app.db.base import Base


class DatabaseTestManager:
    """Manages test database lifecycle and operations."""

    def __init__(self) -> None:
        """Initialize test database manager."""
        self.engine: AsyncEngine | None = None
        self.session_maker: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self, database_url: str | None = None) -> None:
        """Initialize test database with tables."""
        if database_url is None:
            database_url = "sqlite+aiosqlite:///./test_violentutf.db"

        # Create async engine for testing
        # For SQLite, we need special handling to ensure transaction visibility
        connect_args = {}
        if "sqlite" in database_url:
            connect_args = {
                "check_same_thread": False,
                "isolation_level": None,  # Use autocommit mode for SQLite
            }

        self.engine = create_async_engine(
            database_url,
            echo=False,  # Reduce noise in tests
            pool_pre_ping=True,
            connect_args=connect_args,
        )

        # Create session maker
        self.session_maker = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )

        # Create all tables
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        print(f"Test database initialized: {database_url}")

    async def cleanup(self) -> None:
        """Clean up test database."""
        if self.engine:
            # Drop all tables
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.drop_all)

            # Dispose engine
            await self.engine.dispose()

        # Remove SQLite file if it exists
        db_file = "./test_violentutf.db"
        if os.path.exists(db_file):
            os.remove(db_file)

        print("Test database cleaned up")

    async def get_session(self) -> AsyncSession:
        """Get database session for testing."""
        if not self.session_maker:
            raise RuntimeError("Database not initialized")

        return self.session_maker()

    async def reset_database(self) -> None:
        """Reset database by truncating all tables."""
        if not self.engine:
            raise RuntimeError("Database not initialized")

        async with self.engine.begin() as connection:
            # Get all table names
            tables_result = await connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            )
            table_names = [row[0] for row in tables_result.fetchall()]

            # Disable foreign key constraints temporarily
            await connection.execute(text("PRAGMA foreign_keys = OFF"))

            # Truncate each table
            for table_name in table_names:
                await connection.execute(text(f"DELETE FROM {table_name}"))  # nosec B608

            # Re-enable foreign key constraints
            await connection.execute(text("PRAGMA foreign_keys = ON"))

        print("Test database reset completed")


# Global test database manager
_test_db_manager: DatabaseTestManager | None = None


async def get_test_db_manager() -> DatabaseTestManager:
    """Get or create test database manager."""
    global _test_db_manager

    if _test_db_manager is None:
        _test_db_manager = DatabaseTestManager()
        await _test_db_manager.initialize()

    return _test_db_manager


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_db_manager() -> AsyncGenerator[DatabaseTestManager, None]:
    """Provide test database manager for the entire test session."""
    manager = await get_test_db_manager()
    yield manager
    await manager.cleanup()


@pytest_asyncio.fixture
async def db_session(test_db_manager: DatabaseTestManager) -> AsyncGenerator[AsyncSession, None]:
    """
    Provide database session with transaction rollback for test isolation.

    Each test gets a fresh database state through transaction rollback.
    """
    session = await test_db_manager.get_session()

    # Begin a transaction
    transaction = await session.begin()

    try:
        yield session
    finally:
        # Always rollback the transaction to maintain test isolation
        await transaction.rollback()
        await session.close()


@pytest_asyncio.fixture
async def clean_db_session(test_db_manager: DatabaseTestManager) -> AsyncGenerator[AsyncSession, None]:
    """
    Provide database session that commits changes (for setup fixtures).

    Use this for creating test data that needs to persist across transactions.
    """
    session = await test_db_manager.get_session()

    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
