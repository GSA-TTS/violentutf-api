"""Setup test environment variables before any imports."""

import os
import sys

# Set test environment variables BEFORE any imports
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"
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

# Clear any cached imports related to config
modules_to_remove = []
for module_name in sys.modules:
    if "app.core.config" in module_name or "app.core.security" in module_name:
        modules_to_remove.append(module_name)

for module_name in modules_to_remove:
    del sys.modules[module_name]

print("Test environment configured successfully")
