"""Pytest configuration and fixtures."""

import asyncio
from typing import AsyncGenerator, Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.core.config import Settings, get_settings
from app.main import create_application


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings for testing."""
    return Settings(
        SECRET_KEY="test-secret-key-for-testing-only-32chars",  # pragma: allowlist secret
        ENVIRONMENT="development",
        DEBUG=True,
        DATABASE_URL="sqlite:///./test.db",
        REDIS_URL=None,
        LOG_LEVEL="DEBUG",
        LOG_FORMAT="text",
        RATE_LIMIT_ENABLED=False,
        ENABLE_METRICS=False,
        _env_file=None,  # Disable .env file loading for tests
    )


@pytest.fixture(scope="session")
def app(test_settings: Settings) -> FastAPI:
    """Create application for testing."""

    # Override settings
    def get_settings_override() -> Settings:
        return test_settings

    app = create_application()
    app.dependency_overrides[get_settings] = get_settings_override
    return app


@pytest.fixture(scope="function")
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Create test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="function")
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def reset_dependency_overrides(app: FastAPI) -> None:
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()
