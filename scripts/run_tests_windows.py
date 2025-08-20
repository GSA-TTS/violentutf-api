#!/usr/bin/env python3
"""Cross-platform test runner for ViolentUTF API."""
import argparse
import os
import subprocess
import sys
from pathlib import Path


def run_tests(test_dir: str = "tests/unit", install_deps: bool = False) -> int:
    """Run tests with proper cross-platform support."""
    # Get project root
    project_root = Path(__file__).parent.parent.absolute()
    os.chdir(project_root)

    # Install dependencies if requested
    if install_deps or "--install-deps" in sys.argv:
        print("Installing test dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    # Set PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root)

    # Run pytest with Windows-specific adjustments
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        test_dir,
        "-v",
        "--tb=short",
        "--cov=app",
        "--cov-report=xml",
        "--timeout=300",
    ]

    # Only add parallel execution if not on Windows or if explicitly enabled
    if os.name != "nt":
        cmd.extend(["-n", "auto"])
    else:
        # On Windows, use fewer workers to avoid process creation issues
        cmd.extend(["-n", "2"])

    print(f"Running tests in {test_dir}...")
    result = subprocess.run(cmd, env=env)
    return result.returncode


def main() -> None:
    """Run the main entry point."""
    parser = argparse.ArgumentParser(description="Run ViolentUTF API tests")
    parser.add_argument("--test-dir", default="tests/unit", help="Test directory to run (default: tests/unit)")
    parser.add_argument("--install-deps", action="store_true", help="Install dependencies before running tests")

    args = parser.parse_args()
    sys.exit(run_tests(args.test_dir, args.install_deps))


if __name__ == "__main__":
    main()
