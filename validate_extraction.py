#!/usr/bin/env python3
"""Validate the extraction was successful."""

import os
import sys
from pathlib import Path


def check_file_exists(filepath: str, description: str) -> bool:
    """Check if a file exists."""
    if Path(filepath).exists():
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description}: {filepath} NOT FOUND")
        return False


def check_no_dependencies(filepath: str, banned_imports: list[str]) -> bool:
    """Check that a file doesn't import banned dependencies."""
    try:
        with open(filepath, "r") as f:
            content = f.read()

        found_banned = []
        for banned in banned_imports:
            if f"import {banned}" in content or f"from {banned}" in content:
                found_banned.append(banned)

        if found_banned:
            print(f"❌ {filepath} contains banned imports: {', '.join(found_banned)}")
            return False
        else:
            print(f"✅ {filepath} is free of banned dependencies")
            return True
    except Exception as e:
        print(f"❌ Error checking {filepath}: {e}")
        return False


def check_core_files() -> bool:
    """Check that core application files exist."""
    print("Checking core files...")
    core_files = [
        ("app/main.py", "Main application"),
        ("app/core/config.py", "Configuration"),
        ("app/core/security.py", "Security utilities"),
        ("app/core/logging.py", "Logging setup"),
        ("app/core/errors.py", "Error handling"),
        ("app/middleware/security.py", "Security middleware"),
        ("app/middleware/request_id.py", "Request ID middleware"),
        ("app/api/endpoints/health.py", "Health endpoints"),
        ("app/api/routes.py", "API routes"),
    ]

    return all(check_file_exists(filepath, desc) for filepath, desc in core_files)


def check_test_files() -> bool:
    """Check that test files exist."""
    print("\nChecking test files...")
    test_files = [
        ("tests/conftest.py", "Test configuration"),
        ("tests/unit/test_config.py", "Config tests"),
        ("tests/unit/test_security.py", "Security tests"),
        ("tests/unit/test_health.py", "Health tests"),
        ("tests/integration/test_startup.py", "Integration tests"),
    ]

    return all(check_file_exists(filepath, desc) for filepath, desc in test_files)


def check_config_files() -> bool:
    """Check that configuration files exist."""
    print("\nChecking configuration files...")
    config_files = [
        ("requirements.txt", "Production dependencies"),
        ("requirements-dev.txt", "Development dependencies"),
        (".env.example", "Environment template"),
        (".pre-commit-config.yaml", "Pre-commit hooks"),
        ("pyproject.toml", "Project configuration"),
        ("Makefile", "Make commands"),
    ]

    return all(check_file_exists(filepath, desc) for filepath, desc in config_files)


def check_banned_dependencies() -> bool:
    """Check for banned dependencies in core files."""
    print("\nChecking for banned dependencies...")
    banned_imports = ["apisix", "keycloak", "mcp", "pyrit_orchestrator_service"]
    files_to_check = [
        "app/main.py",
        "app/core/config.py",
        "app/api/routes.py",
    ]

    for filepath in files_to_check:
        if Path(filepath).exists():
            if not check_no_dependencies(filepath, banned_imports):
                return False
    return True


def check_security_improvements() -> bool:
    """Check security-related dependencies and configurations."""
    print("\nChecking security improvements...")
    all_passed = True

    # Check PyJWT usage
    with open("requirements.txt", "r") as f:
        reqs = f.read()

    if "PyJWT" in reqs and "python-jose" not in reqs:
        print("✅ Using PyJWT instead of python-jose")
    else:
        print("❌ Security: Should use PyJWT, not python-jose")
        all_passed = False

    # Check Argon2 usage
    if "argon2" in reqs:
        print("✅ Using Argon2 for password hashing")
    else:
        print("❌ Security: Should use Argon2 for password hashing")
        all_passed = False

    # Check pip-audit
    if "pip-audit" in open("requirements-dev.txt").read():
        print("✅ Using pip-audit for vulnerability scanning")
    else:
        print("❌ Security: Should use pip-audit for vulnerability scanning")
        all_passed = False

    return all_passed


def main() -> None:
    """Run validation checks."""
    print("ViolentUTF API Extraction Validation")
    print("=====================================\n")

    # Run all validation checks
    checks = [
        check_core_files(),
        check_test_files(),
        check_config_files(),
        check_banned_dependencies(),
        check_security_improvements(),
    ]

    all_checks_passed = all(checks)

    print("\n=====================================")
    if all_checks_passed:
        print("✅ All validation checks passed!")
    else:
        print("❌ Some validation checks failed")


if __name__ == "__main__":
    sys.exit(main())
