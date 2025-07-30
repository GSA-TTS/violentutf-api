"""Utilities to disable pytest-httpx for TestClient tests."""

import functools

import pytest


def disable_httpx_for_testclient(test_func):
    """Decorator to disable pytest-httpx for tests using TestClient."""

    @functools.wraps(test_func)
    def wrapper(*args, **kwargs):
        # Mark the test to not use httpx mocking
        if hasattr(test_func, "pytestmark"):
            test_func.pytestmark.append(pytest.mark.no_httpx)
        else:
            test_func.pytestmark = [pytest.mark.no_httpx]

        return test_func(*args, **kwargs)

    return wrapper


# Alternative: Create a marker that disables httpx mocking
pytest.mark.no_httpx = pytest.mark.skipif(
    False, reason="Test uses TestClient, not httpx directly"  # Never skip, just mark
)
