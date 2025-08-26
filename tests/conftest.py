"""Pytest configuration and fixtures."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import TYPE_CHECKING, AsyncGenerator, Generator

# Clear any cached modules BEFORE importing anything from app
modules_to_remove = []
for module_name in list(sys.modules.keys()):
    if module_name.startswith("app."):
        modules_to_remove.append(module_name)

for module_name in modules_to_remove:
    del sys.modules[module_name]

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

if TYPE_CHECKING:
    from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402
from app.main import create_application  # noqa: E402

# Import test fixtures - this makes them available to all tests
from tests.test_database import DatabaseTestManager, clean_db_session, db_session, test_db_manager  # noqa
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

# Import our safe TestClient
from tests.utils.testclient import SafeTestClient  # noqa: E402


@pytest.fixture(autouse=True)
def non_mocked_hosts():
    """Configure pytest-httpx to not intercept TestClient requests."""
    # This is critical - it tells pytest-httpx to NOT mock these hosts
    # TestClient uses "testserver" as its default host
    return ["test", "testserver", "localhost", "127.0.0.1", "app", "http://test", "http://testserver"]


# Removed custom event_loop fixture - using pytest-asyncio's built-in management
# The pytest.ini configuration handles event loop management with:
# asyncio_mode = auto
# asyncio_default_fixture_loop_scope = function


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings for testing."""
    # Clear the settings cache to ensure test settings are used
    from app.core.config import get_settings

    get_settings.cache_clear()

    # Use separate test database to avoid conflicts
    test_db_url = "sqlite+aiosqlite:///./test_violentutf.db"

    # Set environment variable for test database
    os.environ["DATABASE_URL"] = test_db_url
    os.environ["TESTING"] = "true"
    # Disable security middleware for unit tests
    os.environ["CSRF_PROTECTION"] = "false"
    os.environ["REQUEST_SIGNING_ENABLED"] = "false"

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
        CSRF_PROTECTION=False,  # Disable CSRF for unit tests
        REQUEST_SIGNING_ENABLED=False,  # Disable request signing for unit tests
        _env_file=None,  # Disable .env file loading for tests
    )


@pytest.fixture(scope="module")
def app(test_settings: Settings, test_db_manager: DatabaseTestManager) -> FastAPI:
    """Create application for testing."""
    from app.db.session import get_db

    # Override settings
    def get_settings_override() -> Settings:
        return test_settings

    # Override database dependency to use test database
    from contextlib import asynccontextmanager
    from typing import AsyncGenerator

    from sqlalchemy.ext.asyncio import AsyncSession

    @asynccontextmanager
    async def get_test_db() -> AsyncGenerator[AsyncSession, None]:
        """Test database dependency that yields a session directly."""
        session = await test_db_manager.get_session()

        # For integration tests, we need to use real sessions with real commits
        # to ensure proper transaction isolation and visibility
        try:
            yield session
            await session.commit()  # Commit changes for integration tests
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    # Also create a non-context-manager version for get_db_dependency
    async def get_test_db_dependency() -> AsyncGenerator[AsyncSession, None]:
        """Test database dependency for direct generator use."""
        session = await test_db_manager.get_session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    # Import the actual dependencies we need to override
    from app.db.session import get_db_dependency

    app = create_application(custom_settings=test_settings)
    app.dependency_overrides[get_settings] = get_settings_override
    # Override BOTH get_db and get_db_dependency to ensure all endpoints use test database
    app.dependency_overrides[get_db] = get_test_db
    app.dependency_overrides[get_db_dependency] = get_test_db_dependency
    return app


@pytest.fixture(scope="function")
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Create test client."""
    # Use SafeTestClient to avoid pytest-httpx conflicts
    with SafeTestClient(app) as test_client:
        yield test_client


@pytest_asyncio.fixture(scope="module")
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def reset_dependency_overrides(app: FastAPI) -> None:
    """Reset dependency overrides after each test, but preserve core test dependencies."""
    from app.core.config import get_settings
    from app.db.session import get_db, get_db_dependency

    # Store the original overrides that should be preserved across tests
    preserved_overrides = {
        get_settings: app.dependency_overrides.get(get_settings),
        get_db: app.dependency_overrides.get(get_db),
        get_db_dependency: app.dependency_overrides.get(get_db_dependency),
    }

    yield

    # Clear all overrides, then restore the preserved ones
    app.dependency_overrides.clear()
    for dependency, override in preserved_overrides.items():
        if override is not None:
            app.dependency_overrides[dependency] = override


@pytest_asyncio.fixture
async def clean_database(test_db_manager: "DatabaseTestManager") -> None:
    """Clean database before each test for proper isolation."""
    # Clean the database before the test
    await test_db_manager.reset_database()
    yield
    # Optionally clean after test too, but not strictly necessary
    # since we clean before each test


@pytest_asyncio.fixture(autouse=True)
async def cleanup_database_connections() -> None:
    """Automatically cleanup database connections between tests to prevent state contamination."""
    yield
    # Clean up database connections after each test
    try:
        from app.db.session import close_database_connections

        await close_database_connections()
    except Exception:
        # Ignore cleanup errors to not interfere with test results
        pass


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
