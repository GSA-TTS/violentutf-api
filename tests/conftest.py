"""Pytest configuration and fixtures."""

import asyncio
import os
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.core.config import Settings, get_settings
from app.main import create_application

# Import test fixtures - this makes them available to all tests
from tests.test_database import TestDatabaseManager, clean_db_session, db_session, test_db_manager  # noqa
from tests.test_fixtures import (  # noqa
    admin_token,
    admin_user,
    auth_token,
    fresh_admin_token,
    fresh_admin_user,
    fresh_user,
    fresh_user_token,
    test_user,
)


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings for testing."""
    # Use separate test database to avoid conflicts
    test_db_url = "sqlite+aiosqlite:///./test_violentutf.db"

    # Set environment variable for test database
    os.environ["DATABASE_URL"] = test_db_url
    os.environ["TESTING"] = "true"
    # Disable CSRF for tests
    os.environ["CSRF_ENABLED"] = "false"

    return Settings(
        SECRET_KEY="test-secret-key-for-testing-only-32chars",  # pragma: allowlist secret
        ENVIRONMENT="development",
        DEBUG=True,
        DATABASE_URL=test_db_url,
        REDIS_URL=None,  # Disable Redis for tests
        LOG_LEVEL="ERROR",  # Reduce log noise in tests
        LOG_FORMAT="text",
        RATE_LIMIT_ENABLED=False,
        ENABLE_METRICS=False,
        _env_file=None,  # Disable .env file loading for tests
    )


@pytest.fixture(scope="session")
def app(test_settings: Settings, test_db_manager: TestDatabaseManager) -> FastAPI:
    """Create application for testing."""
    from app.db.session import get_db

    # Override settings
    def get_settings_override() -> Settings:
        return test_settings

    # Override database dependency to use test database
    async def get_test_db():
        session = await test_db_manager.get_session()
        try:
            yield session
        finally:
            await session.close()

    app = create_application()
    app.dependency_overrides[get_settings] = get_settings_override
    app.dependency_overrides[get_db] = get_test_db
    return app


@pytest.fixture(scope="function")
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Create test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest_asyncio.fixture(scope="session")
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def reset_dependency_overrides(app: FastAPI) -> None:
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


# Set pytest markers for better test organization
pytest_plugins = ["asyncio"]


# Configure asyncio mode
def pytest_configure(config):
    """Configure pytest for async tests."""
    config.addinivalue_line("markers", "asyncio: mark test to run with asyncio")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "database: mark test as requiring database")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add asyncio marker to async tests
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)

        # Add integration marker to integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add database marker to tests that use db fixtures
        db_fixtures = [
            "db_session",
            "clean_db_session",
            "admin_user",
            "test_user",
            "fresh_user",
            "fresh_admin_user",
            "test_db_manager",
        ]
        if any(fixture in item.fixturenames for fixture in db_fixtures):
            item.add_marker(pytest.mark.database)
