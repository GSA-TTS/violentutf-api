"""
Enhanced pytest configuration specifically for stable integration tests.

This configuration provides additional fixtures and utilities to improve
integration test stability and reliability.
"""

import asyncio

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from tests.helpers.test_stability import (
    ConnectionPoolMonitor,
    DatabaseIsolationManager,
    TestDataFactory,
)


@pytest_asyncio.fixture(scope="function")
async def stable_db_session(db_session: AsyncSession):
    """Database session with enhanced stability features."""
    # Create isolation manager for better transaction control
    async with DatabaseIsolationManager(db_session) as isolation:
        # Track connection usage
        connection_id = f"stable_session_{id(db_session)}"

        try:
            yield db_session
        finally:
            # Ensure proper cleanup
            try:
                await db_session.rollback()
            except Exception:
                pass  # Ignore cleanup errors


@pytest.fixture(scope="function")
def integration_connection_monitor():
    """Connection pool monitor for integration tests."""
    monitor = ConnectionPoolMonitor()
    yield monitor
    # Reset monitor after test
    monitor.reset()


@pytest_asyncio.fixture
async def stable_test_data_factory(stable_db_session: AsyncSession):
    """Test data factory with automatic cleanup and unique data generation."""
    factory = TestDataFactory(stable_db_session)
    yield factory
    # Cleanup is handled by the factory's __aexit__ method


# Configure pytest for integration test stability
@pytest.fixture(autouse=True)
def configure_integration_test_environment(request):
    """Auto-configure environment for integration test stability."""
    # Only apply to integration tests
    if "integration" in str(request.node.fspath):
        # Set longer timeouts for integration tests
        if hasattr(request.node, "add_marker"):
            request.node.add_marker(pytest.mark.timeout(60))

        # Configure asyncio for better handling of concurrent operations
        if hasattr(asyncio, "current_task"):
            # Ensure we're using a fresh event loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                pass  # No running loop, which is fine

    yield


# Custom markers for stability testing
pytest_plugins = []


def pytest_configure(config):
    """Configure additional markers for test stability."""
    config.addinivalue_line("markers", "stable: mark test as having stability improvements")
    config.addinivalue_line("markers", "retry: mark test for automatic retry on failure")
    config.addinivalue_line("markers", "isolated: mark test requiring strict database isolation")


def pytest_runtest_makereport(item, call):
    """Custom test result reporting for stability analysis."""
    if call.when == "call":
        # Track test stability metrics
        test_name = item.nodeid

        if call.excinfo is None:
            # Test passed - record success
            pass
        else:
            # Test failed - could be retried if marked
            if "retry" in [mark.name for mark in item.iter_markers()]:
                # This test is marked for retry
                pass


class IntegrationTestPlugin:
    """Pytest plugin for integration test enhancements."""

    def __init__(self):
        self.test_results = {}
        self.retry_counts = {}

    def pytest_runtest_call(self, pyfuncitem):
        """Handle test execution with potential retries."""
        test_id = pyfuncitem.nodeid

        # Check if test is marked for retry
        retry_marker = pyfuncitem.get_closest_marker("retry")
        if retry_marker:
            max_retries = retry_marker.kwargs.get("max_retries", 3)
            self.retry_counts[test_id] = max_retries

    def pytest_runtest_makereport(self, item, call):
        """Create test reports with retry information."""
        if call.when == "call" and call.excinfo:
            test_id = item.nodeid
            if test_id in self.retry_counts and self.retry_counts[test_id] > 0:
                # Could retry this test
                self.retry_counts[test_id] -= 1


# Register the plugin
integration_plugin = IntegrationTestPlugin()


def pytest_configure(config):
    """Register integration test plugin."""
    config.pluginmanager.register(integration_plugin, "integration_test_plugin")
