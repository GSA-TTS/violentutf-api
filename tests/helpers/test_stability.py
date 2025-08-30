"""Test stability utilities for improving integration test reliability."""

import asyncio
import functools
import logging
import time
from typing import Any, Awaitable, Callable, TypeVar
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

T = TypeVar("T")


def retry_on_failure(max_retries: int = 3, delay: float = 0.1, backoff: float = 2.0):
    """Decorator to retry flaky integration tests with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay on each retry
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            current_delay = delay

            for attempt in range(max_retries + 1):
                try:
                    if attempt > 0:
                        logger.info(f"Retrying {func.__name__} (attempt {attempt + 1}/{max_retries + 1})")
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff

                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(f"Test {func.__name__} failed (attempt {attempt + 1}): {e}")
                    else:
                        logger.error(f"Test {func.__name__} failed after {max_retries + 1} attempts")
                        break

            raise last_exception or RuntimeError(f"Test {func.__name__} failed after retries")

        return wrapper

    return decorator


class DatabaseIsolationManager:
    """Manages database isolation for integration tests."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self._savepoints = []

    async def __aenter__(self):
        """Create a nested transaction savepoint."""
        # Create a savepoint for proper test isolation
        savepoint = await self.session.begin_nested()
        self._savepoints.append(savepoint)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Rollback to the savepoint to ensure test isolation."""
        if self._savepoints:
            savepoint = self._savepoints.pop()
            await savepoint.rollback()

    async def flush(self):
        """Flush changes without committing."""
        await self.session.flush()

    async def refresh(self, instance):
        """Refresh an instance from the database."""
        await self.session.refresh(instance)


class AsyncTestSynchronizer:
    """Synchronizes async operations to prevent race conditions."""

    def __init__(self):
        self._locks = {}

    def get_lock(self, key: str) -> asyncio.Lock:
        """Get or create a lock for the given key."""
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def synchronized(self, key: str, coro: Awaitable[T]) -> T:
        """Execute a coroutine with synchronization."""
        async with self.get_lock(key):
            return await coro


# Global synchronizer instance
_synchronizer = AsyncTestSynchronizer()


def synchronized_test(key: str):
    """Decorator to synchronize test execution by key."""

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await _synchronizer.synchronized(key, func(*args, **kwargs))

        return wrapper

    return decorator


class ConnectionPoolMonitor:
    """Monitors database connection pool for stability testing."""

    def __init__(self):
        self.active_connections = set()
        self.connection_history = []

    def track_connection(self, connection_id: str):
        """Track an active connection."""
        self.active_connections.add(connection_id)
        self.connection_history.append(("open", connection_id, time.time()))

    def untrack_connection(self, connection_id: str):
        """Untrack a connection."""
        self.active_connections.discard(connection_id)
        self.connection_history.append(("close", connection_id, time.time()))

    def get_active_count(self) -> int:
        """Get number of active connections."""
        return len(self.active_connections)

    def reset(self):
        """Reset tracking."""
        self.active_connections.clear()
        self.connection_history.clear()


# Global connection monitor
_connection_monitor = ConnectionPoolMonitor()


@pytest.fixture
async def isolated_db_session(db_session: AsyncSession):
    """Database session with automatic isolation and cleanup."""
    async with DatabaseIsolationManager(db_session) as isolation:
        # Track this session
        session_id = f"session_{id(db_session)}"
        _connection_monitor.track_connection(session_id)

        try:
            yield db_session
        finally:
            # Ensure cleanup
            _connection_monitor.untrack_connection(session_id)
            await db_session.rollback()


@pytest.fixture(scope="function")
def connection_monitor():
    """Provide connection monitoring for tests."""
    _connection_monitor.reset()
    yield _connection_monitor


def stable_integration_test(max_retries: int = 3, sync_key: str | None = None, timeout: float = 30.0):
    """Comprehensive decorator for stable integration tests.

    Args:
        max_retries: Number of retry attempts
        sync_key: Key for synchronization (prevents parallel execution)
        timeout: Test timeout in seconds
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        # Apply timeout
        func = pytest.mark.timeout(timeout)(func)

        # Apply synchronization if requested
        if sync_key:
            func = synchronized_test(sync_key)(func)

        # Apply retry logic
        func = retry_on_failure(max_retries=max_retries)(func)

        return func

    return decorator


class TestDataFactory:
    """Factory for creating isolated test data."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self._created_objects = []

    async def create_user(self, **kwargs) -> Any:
        """Create a test user with unique data."""
        from uuid import uuid4

        from app.models.user import User

        user_data = {
            "username": f"test_user_{uuid4().hex[:8]}",
            "email": f"test_{uuid4().hex[:8]}@example.com",
            "full_name": f"Test User {uuid4().hex[:4]}",
            "is_active": True,
            **kwargs,
        }

        user = User(**user_data)
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        self._created_objects.append(user)
        return user

    async def create_api_key(self, user_id: str, **kwargs) -> Any:
        """Create a test API key with unique data."""
        import hashlib
        from uuid import uuid4

        from app.models.api_key import APIKey

        # Generate unique key data
        key_data = f"test_key_{uuid4().hex}"
        key_hash = hashlib.sha256(key_data.encode()).hexdigest()

        api_key_data = {
            "name": f"test_api_key_{uuid4().hex[:8]}",
            "key_hash": key_hash,
            "key_prefix": key_hash[:8],
            "user_id": user_id,
            "permissions": {"read": True},
            **kwargs,
        }

        api_key = APIKey(**api_key_data)
        self.session.add(api_key)
        await self.session.flush()
        await self.session.refresh(api_key)
        self._created_objects.append(api_key)
        return api_key, key_data

    async def cleanup(self):
        """Clean up all created objects."""
        for obj in reversed(self._created_objects):
            try:
                await self.session.delete(obj)
            except Exception as e:
                logger.warning(f"Failed to cleanup object {obj}: {e}")

        self._created_objects.clear()
        await self.session.flush()


@pytest.fixture
async def test_data_factory(isolated_db_session):
    """Factory for creating isolated test data with automatic cleanup."""
    factory = TestDataFactory(isolated_db_session)
    yield factory
    await factory.cleanup()


class AsyncOperationWaiter:
    """Utility for waiting on async operations to complete."""

    @staticmethod
    async def wait_for_condition(
        condition: Callable[[], Awaitable[bool]],
        timeout: float = 5.0,
        poll_interval: float = 0.1,
    ) -> bool:
        """Wait for an async condition to become true."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                if await condition():
                    return True
            except Exception as e:
                logger.debug(f"Condition check failed: {e}")

            await asyncio.sleep(poll_interval)

        return False

    @staticmethod
    async def wait_for_database_consistency(
        session: AsyncSession,
        query_func: Callable[[], Awaitable[Any]],
        expected_result: Any,
        timeout: float = 5.0,
    ) -> bool:
        """Wait for database to reach a consistent state."""

        async def check_condition():
            result = await query_func()
            return result == expected_result

        return await AsyncOperationWaiter.wait_for_condition(check_condition, timeout)


# Export utilities for easy import
__all__ = [
    "retry_on_failure",
    "DatabaseIsolationManager",
    "AsyncTestSynchronizer",
    "synchronized_test",
    "ConnectionPoolMonitor",
    "stable_integration_test",
    "TestDataFactory",
    "AsyncOperationWaiter",
    "isolated_db_session",
    "test_data_factory",
    "connection_monitor",
]
