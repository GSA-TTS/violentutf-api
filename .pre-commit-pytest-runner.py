#!/usr/bin/env python3
"""Pre-commit pytest runner with proper PYTHONPATH setup."""
import os
import subprocess
import sys

# Get the repository root directory
repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()

# Set up PYTHONPATH to include the repository root
env = os.environ.copy()
env["PYTHONPATH"] = f"{repo_root}:{env.get('PYTHONPATH', '')}"

# Set up test environment variables (matching pytest_plugins/env_setup.py)
env["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"
env["DATABASE_URL"] = "sqlite+aiosqlite:///./test_violentutf.db"
env["TESTING"] = "true"
env["CSRF_PROTECTION"] = "false"
env["REQUEST_SIGNING_ENABLED"] = "false"
env["ENVIRONMENT"] = "development"
env["DEBUG"] = "true"
env["LOG_LEVEL"] = "ERROR"  # Reduce log noise
env["LOG_FORMAT"] = "text"
env["RATE_LIMIT_ENABLED"] = "false"
env["ENABLE_METRICS"] = "false"
env["REDIS_URL"] = ""  # Disable Redis for tests

# Debug output (will be visible in pre-commit logs)
print(f"Repository root: {repo_root}", file=sys.stderr)
print(f"PYTHONPATH: {env['PYTHONPATH']}", file=sys.stderr)
print(f"Python executable: {sys.executable}", file=sys.stderr)

# Run pytest with the specified arguments
cmd = [
    sys.executable,
    "-m",
    "pytest",
    "tests/unit/",
    "-v",
    "--tb=short",
    "--maxfail=50",
    "-m",
    "not slow and not integration and not docker",
    "--timeout=180",
]

# Execute the command with the modified environment
result = subprocess.run(cmd, env=env, cwd=repo_root)
sys.exit(result.returncode)
