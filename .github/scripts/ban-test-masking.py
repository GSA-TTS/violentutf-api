#!/usr/bin/env python3
"""
Pre-commit hook to prevent dangerous test result masking patterns.

This script detects and blocks patterns that mask test failures, which can
create false confidence in CI/CD pipelines and hide critical issues.

DANGEROUS PATTERNS DETECTED:
- || true (forces success regardless of command result)
- || exit 0 (forces success exit code)
- ; true (similar masking pattern)
- --continue-on-error without proper justification
- pytest ... || echo (masking pytest failures)

Usage:
  python3 ban-test-masking.py [files...]

Returns:
  0: No dangerous patterns found
  1: Dangerous patterns detected (blocks commit)
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Dangerous patterns that mask test failures
DANGEROUS_PATTERNS = [
    {
        "pattern": r"\|\|\s*true\b",
        "description": "Forces success with || true (masks failures)",
        "severity": "CRITICAL",
        "examples": ["pytest tests/ || true", "npm test || true"],
    },
    {
        "pattern": r"\|\|\s*exit\s+0\b",
        "description": "Forces success exit code (masks failures)",
        "severity": "CRITICAL",
        "examples": ["pytest tests/ || exit 0"],
    },
    {
        "pattern": r";\s*true\s*$",
        "description": "Forces success with ; true (masks failures)",
        "severity": "HIGH",
        "examples": ["pytest tests/ ; true"],
    },
    {
        "pattern": r"(pytest|npm\s+test|cargo\s+test|go\s+test|mvn\s+test).*\|\|\s*(echo|printf)",
        "description": "Test command with output redirection (likely masking)",
        "severity": "HIGH",
        "examples": ['pytest tests/ || echo "Tests completed"'],
    },
    {
        "pattern": r"continue-on-error:\s*true",
        "description": "GitHub Actions continue-on-error without justification",
        "severity": "MEDIUM",
        "examples": ["continue-on-error: true"],
    },
]

# File patterns to check
WORKFLOW_FILES = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
SCRIPT_FILES = ["*.sh", "*.bash", "scripts/*", "Makefile"]
CI_FILES = [".travis.yml", ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile"]

# Allowed exceptions (with required justification comments)
ALLOWED_EXCEPTIONS = [
    r"#\s*JUSTIFIED:\s*.*",  # Must have justification comment
    r"#\s*ALLOW_MASK:\s*.*",  # Explicit allowance with reason
]


def check_file_for_patterns(file_path: Path) -> List[Tuple[int, str, Dict[str, Any]]]:
    """Check a single file for dangerous patterns."""
    violations: List[Tuple[int, str, Dict[str, Any]]] = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (UnicodeDecodeError, IOError):
        return violations

    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()

        # Skip empty lines and comments
        if not line_stripped or line_stripped.startswith("#"):
            continue

        for pattern_info in DANGEROUS_PATTERNS:
            pattern = str(pattern_info["pattern"])
            if re.search(pattern, line, re.IGNORECASE):
                # Check if this line has an allowed exception
                has_exception = False
                for exception_pattern in ALLOWED_EXCEPTIONS:
                    if re.search(exception_pattern, line, re.IGNORECASE):
                        has_exception = True
                        break

                if not has_exception:
                    violations.append((line_num, line.strip(), pattern_info))

    return violations


def should_check_file(file_path: Path) -> bool:
    """Determine if a file should be checked based on its path and extension."""
    path_str = str(file_path)

    # Always check workflow files
    if ".github/workflows/" in path_str and path_str.endswith((".yml", ".yaml")):
        return True

    # Check CI configuration files
    ci_files = [".travis.yml", ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile"]
    if any(ci_file in path_str for ci_file in ci_files):
        return True

    # Check shell scripts
    if path_str.endswith((".sh", ".bash")) or "/scripts/" in path_str:
        return True

    # Check Makefiles
    if path_str.endswith("Makefile") or "Makefile" in path_str:
        return True

    return False


def format_violation_report(file_path: Path, violations: List[Tuple[int, str, Dict[str, Any]]]) -> str:
    """Format violations for human-readable output."""
    report = f"\n🚨 DANGEROUS PATTERNS DETECTED in {file_path}:\n"
    report += "=" * 60 + "\n"

    for line_num, line, pattern_info in violations:
        severity = pattern_info["severity"]
        description = pattern_info["description"]

        # Color coding for severity
        if severity == "CRITICAL":
            severity_icon = "🔴 CRITICAL"
        elif severity == "HIGH":
            severity_icon = "🟠 HIGH"
        else:
            severity_icon = "🟡 MEDIUM"

        report += f"\n{severity_icon}: {description}\n"
        report += f"  Line {line_num}: {line}\n"

        # Show examples
        if pattern_info.get("examples"):
            report += f"  Examples: {', '.join(pattern_info['examples'])}\n"

    report += "\n" + "=" * 60
    report += "\nWHY THIS IS DANGEROUS:"
    report += "\n• Masks test failures, creating false confidence"
    report += "\n• Hides critical bugs and security issues"
    report += "\n• Breaks the entire purpose of CI/CD testing"
    report += "\n• Can lead to deploying broken code to production"

    report += "\n\nHOW TO FIX:"
    report += "\n• Remove || true and similar masking patterns"
    report += "\n• Let tests fail properly when they should fail"
    report += "\n• Use 'continue-on-error: true' only for non-critical steps"
    report += "\n• Add justification comments for any exceptions"

    report += "\n\nALLOWED EXCEPTIONS (require justification):"
    report += "\n• # JUSTIFIED: reason for allowing this pattern"
    report += "\n• # ALLOW_MASK: specific reason why masking is needed"

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect dangerous test masking patterns")
    parser.add_argument("files", nargs="*", help="Files to check (default: all relevant files)")
    parser.add_argument("--fix", action="store_true", help="Suggest fixes for violations")
    parser.add_argument("--strict", action="store_true", help="Strict mode (fail on any violations)")

    args = parser.parse_args()

    if args.files:
        files_to_check = [Path(f) for f in args.files if Path(f).exists()]
    else:
        # Find all relevant files in the repository
        files_to_check = []
        for pattern in WORKFLOW_FILES + SCRIPT_FILES + CI_FILES:
            files_to_check.extend(Path(".").glob(pattern))

    total_violations = 0
    critical_violations = 0

    print("🔍 Scanning for dangerous test masking patterns...")
    print(f"📁 Checking {len(files_to_check)} files")

    for file_path in files_to_check:
        if should_check_file(file_path):
            violations = check_file_for_patterns(file_path)

            if violations:
                total_violations += len(violations)
                critical_count = sum(1 for _, _, p in violations if p["severity"] == "CRITICAL")
                critical_violations += critical_count

                print(format_violation_report(file_path, violations))

    # Summary
    print(f"\n📊 SCAN COMPLETE:")
    print(f"   Total violations: {total_violations}")
    print(f"   Critical violations: {critical_violations}")

    if total_violations == 0:
        print("✅ No dangerous patterns detected!")
        return 0
    else:
        print(f"\n❌ COMMIT BLOCKED: {total_violations} dangerous patterns detected")
        print("   Fix these issues before committing to protect CI/CD integrity")

        if args.strict or critical_violations > 0:
            return 1
        else:
            print("   (Use --strict to block all violations)")
            return 0


if __name__ == "__main__":
    sys.exit(main())
