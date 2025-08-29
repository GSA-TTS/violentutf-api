"""Fixed test database management with proper lifecycle and isolation."""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base


class DatabaseTestManager:
    """Test database manager with proper lifecycle management."""

    def __init__(self, database_url: str | None = None):
        """Initialize test database manager."""
        if database_url:
            self.database_url = database_url
        else:
            try:
                from tests.helpers.windows_compat import get_test_db_path

                self.database_url = get_test_db_path()
            except ImportError:
                self.database_url = "sqlite+aiosqlite:///./test_violentutf.db"
        self.engine: AsyncEngine | None = None
        self.session_maker: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self) -> None:
        """Initialize test database with tables."""
        # ALWAYS clean up existing database for SQLite to ensure fresh schema
        if "sqlite" in self.database_url:
            db_file = self.database_url.replace("sqlite+aiosqlite:///", "")
            if os.path.exists(db_file):
                os.remove(db_file)
                print(f"Removed existing test database: {db_file}")

        # Import ALL models to ensure they're registered with Base
        # This is CRITICAL - must happen before create_all
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
        connect_args = {}
        if "sqlite" in self.database_url:
            connect_args = {
                "check_same_thread": False,
                "isolation_level": None,  # Use autocommit mode for SQLite
            }

        self.engine = create_async_engine(
            self.database_url,
            echo=False,
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

        # Create all tables with fresh schema
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)  # Drop existing tables
            await connection.run_sync(Base.metadata.create_all)  # Create fresh tables

        print(f"Test database initialized with fresh schema: {self.database_url}")

    async def cleanup(self) -> None:
        """Clean up test database."""
        if self.engine:
            # Drop all tables
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.drop_all)

            # Dispose engine
            await self.engine.dispose()

        # Remove SQLite file if it exists
        if "sqlite" in self.database_url:
            db_file = self.database_url.replace("sqlite+aiosqlite:///", "")
            if os.path.exists(db_file):
                os.remove(db_file)

        print("Test database cleaned up")

    async def get_session(self) -> AsyncSession:
        """Get database session for testing."""
        if not self.session_maker:
            raise RuntimeError("Database not initialized")
        return self.session_maker()

    @asynccontextmanager
    async def session_scope(self) -> AsyncGenerator[AsyncSession, None]:
        """Provide a transactional scope for a series of operations."""
        if not self.session_maker:
            raise RuntimeError("Database not initialized")

        async with self.session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def reset_database(self) -> None:
        """Reset database by truncating all tables."""
        if not self.engine:
            raise RuntimeError("Database not initialized")

        async with self.engine.begin() as connection:
            # Get all table names
            result = await connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            )
            table_names = [row[0] for row in result]

            # For SQLite, we need to disable foreign key constraints
            await connection.execute(text("PRAGMA foreign_keys = OFF"))

            # Truncate each table
            for table_name in table_names:
                await connection.execute(text(f"DELETE FROM {table_name}"))  # nosec B608

            # Re-enable foreign key constraints
            await connection.execute(text("PRAGMA foreign_keys = ON"))

        print("Test database reset completed")


# Create different scoped fixtures for different test needs


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="module")
async def module_db_manager() -> AsyncGenerator[DatabaseTestManager, None]:
    """Provide test database manager per module (for integration tests)."""
    manager = DatabaseTestManager()
    await manager.initialize()
    yield manager
    await manager.cleanup()


@pytest_asyncio.fixture(scope="function")
async def function_db_manager() -> AsyncGenerator[DatabaseTestManager, None]:
    """Provide test database manager per function (for unit tests with isolation)."""
    manager = DatabaseTestManager()
    await manager.initialize()
    yield manager
    await manager.cleanup()


@pytest_asyncio.fixture
async def db_session(module_db_manager: DatabaseTestManager) -> AsyncGenerator[AsyncSession, None]:
    """Provide database session with transaction rollback for test isolation."""
    async with module_db_manager.session_scope() as session:
        yield session


@pytest_asyncio.fixture
async def isolated_db_session(
    function_db_manager: DatabaseTestManager,
) -> AsyncGenerator[AsyncSession, None]:
    """Provide completely isolated database session for critical tests."""
    async with function_db_manager.session_scope() as session:
        yield session


# For backward compatibility, provide test_db_manager as module-scoped
@pytest_asyncio.fixture(scope="module")
async def test_db_manager(module_db_manager: DatabaseTestManager) -> DatabaseTestManager:
    """Backward compatible test database manager (module-scoped)."""
    return module_db_manager
