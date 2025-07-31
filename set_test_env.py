"""Set test environment variables before importing any modules."""

import os

# Set all test environment variables
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"  # pragma: allowlist secret
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_violentutf.db"
os.environ["TESTING"] = "true"
os.environ["CSRF_PROTECTION"] = "false"
os.environ["REQUEST_SIGNING_ENABLED"] = "false"
os.environ["ENVIRONMENT"] = "development"
os.environ["DEBUG"] = "true"
os.environ["LOG_LEVEL"] = "ERROR"
os.environ["LOG_FORMAT"] = "text"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["ENABLE_METRICS"] = "false"

print("Test environment variables set.")
