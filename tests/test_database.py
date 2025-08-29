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
            # Use unique database file per process to avoid conflicts
            from tests.helpers.windows_compat import get_test_db_path

            database_url = get_test_db_path()

        # Clean up any existing database file for SQLite
        if "sqlite" in database_url:
            from tests.helpers.windows_compat import cleanup_test_db_file

            cleanup_test_db_file(database_url)

        # Import all models to ensure they're registered with Base
        from app.models import (  # noqa: F401
            APIKey,
            AuditLog,
            MFABackupCode,
            MFAChallenge,
            MFADevice,
            MFAEvent,
            OAuthAccessToken,
            OAuthApplication,
            OAuthAuthorizationCode,
            OAuthRefreshToken,
            Permission,
            Role,
            Session,
            User,
            UserRole,
        )

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
            try:
                # Drop all tables
                async with self.engine.begin() as connection:
                    await connection.run_sync(Base.metadata.drop_all)
            except Exception as e:
                print(f"Warning: Error dropping tables: {e}")

            try:
                # Close all connections
                await self.engine.dispose()
            except Exception as e:
                print(f"Warning: Error disposing engine: {e}")

        # Windows-compatible file removal
        from tests.helpers.windows_compat import cleanup_test_db_file, force_close_sqlite_connections, safe_file_remove

        force_close_sqlite_connections()

        # Try to get the database URL from engine if available
        db_url = None
        if self.engine:
            db_url = str(self.engine.url)

        if db_url and cleanup_test_db_file(db_url):
            print("Test database cleaned up")
        else:
            print(f"Warning: Could not remove test database file")

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


# Removed global singleton - each module gets its own manager
async def get_test_db_manager() -> DatabaseTestManager:
    """Create test database manager."""
    manager = DatabaseTestManager()
    await manager.initialize()
    return manager


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="module")
async def test_db_manager() -> AsyncGenerator[DatabaseTestManager, None]:
    """Provide test database manager per module for better test isolation."""
    # Create fresh manager for each test module
    manager = DatabaseTestManager()
    await manager.initialize()
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
        # Rollback transaction only if it's still active
        try:
            if transaction.is_active:
                await transaction.rollback()
        except Exception as e:
            # Transaction might already be closed by service commits
            print(f"Transaction rollback failed (expected for committed transactions): {e}")

        # Close session safely
        try:
            await session.close()
        except Exception as e:
            print(f"Session close failed: {e}")

        print("Test database cleaned up")


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
