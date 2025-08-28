"""Pytest plugin to set up test environment before imports."""

import os
import sys


def pytest_configure(config):
    """Set up test environment before any test imports."""
    # Set test environment variables
    os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"
    # Use Windows-compatible database path
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    try:
        from tests.helpers.windows_compat import get_test_db_path

        os.environ["DATABASE_URL"] = get_test_db_path()
    except ImportError:
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_violentutf.db"
    os.environ["TESTING"] = "true"
    os.environ["CSRF_PROTECTION"] = "false"
    os.environ["REQUEST_SIGNING_ENABLED"] = "false"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DEBUG"] = "true"
    os.environ["LOG_LEVEL"] = "DEBUG"
    os.environ["LOG_FORMAT"] = "text"
    os.environ["RATE_LIMIT_ENABLED"] = "false"
    os.environ["ENABLE_METRICS"] = "false"

    # Clear any cached modules
    modules_to_remove = []
    for module_name in list(sys.modules.keys()):
        if any(
            pattern in module_name
            for pattern in ["app.core.config", "app.core.security", "app.middleware.authentication", "app.core.auth"]
        ):
            modules_to_remove.append(module_name)

    for module_name in modules_to_remove:
        del sys.modules[module_name]

    # Clear the lru_cache if the module was already imported
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
    except ImportError:
        pass
