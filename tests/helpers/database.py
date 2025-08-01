"""Database test helpers for consistent test setup."""

import asyncio
import os
from typing import AsyncGenerator, Optional

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.db.session import get_engine, get_session_maker, reset_engine


@pytest_asyncio.fixture
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Provide a test database engine."""
    # Ensure test environment
    os.environ["TESTING"] = "1"
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

    # Reset any existing engine
    reset_engine()

    # Create test engine
    engine = get_engine()
    if engine is None:
        import pytest

        pytest.fail("Failed to create test database engine")

    yield engine

    # Cleanup
    await engine.dispose()
    reset_engine()


@pytest_asyncio.fixture
async def test_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a test database session."""
    session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    session = session_maker()

    try:
        yield session
    finally:
        await session.close()


async def ensure_test_database():
    """Ensure test database is properly configured."""
    os.environ.setdefault("TESTING", "1")
    os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

    # Reset engine to pick up test configuration
    reset_engine()

    # Verify engine creation
    engine = get_engine()
    if engine is None:
        raise RuntimeError("Failed to configure test database")

    return engine


def reset_test_database():
    """Reset test database state."""
    reset_engine()
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("TESTING", None)
