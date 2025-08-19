#!/usr/bin/env python3
"""
Security audit script for git history parser and pattern matcher.
Checks for common vulnerabilities and security issues.
"""

import ast
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class SecurityAuditor:
    """Security auditor for code analysis."""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.issues: List[Dict[str, Any]] = []

    def audit_file(self, file_path: Path) -> None:
        """Audit a single Python file for security issues."""
        logger.info(f"Auditing {file_path}")

        try:
            content = file_path.read_text()

            # Check for various security issues
            self._check_regex_dos(file_path, content)
            self._check_command_injection(file_path, content)
            self._check_path_traversal(file_path, content)
            self._check_input_validation(file_path, content)
            self._check_error_handling(file_path, content)
            self._check_resource_limits(file_path, content)

        except Exception as e:
            logger.error(f"Error auditing {file_path}: {e}")

    def _check_regex_dos(self, file_path: Path, content: str) -> None:
        """Check for potential ReDoS vulnerabilities."""
        # Look for dangerous regex patterns
        dangerous_patterns = [
            r"\(\.\*\)\+",  # Nested quantifiers
            r"\(\.\+\)\+",
            r"\([^)]*\*\)\+",
            r"\([^)]*\+\)\+",
            r"\\s\*\\s\*",  # Repeated whitespace
            r"(?:.*){2,}",  # Repeated groups
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, content):
                self.issues.append(
                    {
                        "file": str(file_path),
                        "type": "ReDoS Risk",
                        "severity": "HIGH",
                        "description": f"Potential ReDoS vulnerability with pattern: {pattern}",
                    }
                )

    def _check_command_injection(self, file_path: Path, content: str) -> None:
        """Check for command injection vulnerabilities."""
        # Look for dangerous subprocess usage
        dangerous_calls = [
            (r"subprocess\.(call|run|Popen)\([^,)]*shell\s*=\s*True", "Shell=True usage"),
            (r"os\.system\(", "os.system usage"),
            (r"os\.popen\(", "os.popen usage"),
            (r"eval\(", "eval usage"),
            (r"exec\(", "exec usage"),
        ]

        for pattern, desc in dangerous_calls:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_no = content[: match.start()].count("\n") + 1
                self.issues.append(
                    {
                        "file": str(file_path),
                        "line": line_no,
                        "type": "Command Injection Risk",
                        "severity": "CRITICAL",
                        "description": desc,
                    }
                )

    def _check_path_traversal(self, file_path: Path, content: str) -> None:
        """Check for path traversal vulnerabilities."""
        # Look for unsafe path operations
        if "os.path.join" in content and ".." not in content:
            # Check if paths are validated
            if not re.search(r"(resolve|absolute|is_relative_to)", content):
                self.issues.append(
                    {
                        "file": str(file_path),
                        "type": "Path Traversal Risk",
                        "severity": "HIGH",
                        "description": "Path operations without validation",
                    }
                )

    def _check_input_validation(self, file_path: Path, content: str) -> None:
        """Check for input validation issues."""
        # Check git operations
        if "iter_commits" in content:
            # Check if max_commits is used
            if "max_commits" not in content:
                self.issues.append(
                    {
                        "file": str(file_path),
                        "type": "Resource Exhaustion",
                        "severity": "MEDIUM",
                        "description": "iter_commits without max_commits limit",
                    }
                )

        # Check for type validation
        if "def " in content:
            # Simple check for functions without type hints
            functions = re.findall(r"def\s+(\w+)\s*\([^)]*\)\s*:", content)
            for func in functions:
                if not func.startswith("_") and "->" not in content.split(f"def {func}")[1].split("\n")[0]:
                    self.issues.append(
                        {
                            "file": str(file_path),
                            "type": "Type Safety",
                            "severity": "LOW",
                            "description": f"Function {func} lacks return type annotation",
                        }
                    )

    def _check_error_handling(self, file_path: Path, content: str) -> None:
        """Check for proper error handling."""
        # Look for bare except clauses
        if re.search(r"except\s*:", content):
            self.issues.append(
                {
                    "file": str(file_path),
                    "type": "Error Handling",
                    "severity": "MEDIUM",
                    "description": "Bare except clause found",
                }
            )

        # Check for error information disclosure
        if "traceback.print_exc()" in content or "traceback.format_exc()" in content:
            self.issues.append(
                {
                    "file": str(file_path),
                    "type": "Information Disclosure",
                    "severity": "MEDIUM",
                    "description": "Full traceback exposed",
                }
            )

    def _check_resource_limits(self, file_path: Path, content: str) -> None:
        """Check for resource limit controls."""
        # Check for unbounded operations
        unbounded_operations = [
            (r"re\.compile\([^)]+\)", "regex compilation"),
            (r"for\s+\w+\s+in\s+[^:]+:", "loop iteration"),
        ]

        for pattern, op_type in unbounded_operations:
            matches = re.finditer(pattern, content)
            for match in matches:
                # Check if there's a limit nearby
                context = content[max(0, match.start() - 200) : match.end() + 200]
                if not any(limit in context for limit in ["[:100]", "enumerate", "range", "limit", "max_"]):
                    line_no = content[: match.start()].count("\n") + 1
                    self.issues.append(
                        {
                            "file": str(file_path),
                            "line": line_no,
                            "type": "Resource Control",
                            "severity": "LOW",
                            "description": f"Potentially unbounded {op_type}",
                        }
                    )

    def generate_report(self) -> str:
        """Generate security audit report."""
        report = ["# Security Audit Report\n"]

        # Group by severity
        by_severity: Dict[str, List[Dict[str, Any]]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for issue in self.issues:
            by_severity[issue["severity"]].append(issue)

        # Summary
        report.append("## Summary")
        report.append(f"- Total issues: {len(self.issues)}")
        for severity, issues in by_severity.items():
            if issues:
                report.append(f"- {severity}: {len(issues)}")
        report.append("")

        # Detailed findings
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            issues = by_severity[severity]
            if issues:
                report.append(f"\n## {severity} Severity Issues\n")
                for issue in issues:
                    report.append(f"### {issue['type']}")
                    report.append(f"- **File**: {issue['file']}")
                    if "line" in issue:
                        report.append(f"- **Line**: {issue['line']}")
                    report.append(f"- **Description**: {issue['description']}")
                    report.append("")

        return "\n".join(report)


def check_regex_patterns_safety() -> List[Tuple[str, str]]:
    """Check all regex patterns for ReDoS vulnerabilities."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher

    unsafe_patterns = []
    matcher = ArchitecturalFixPatternMatcher()

    for config in matcher.PATTERNS:
        pattern = config.pattern

        # Check for dangerous constructs
        if any(danger in pattern for danger in ["(.*)+", "(.+)+", "(.*)*", "\\s*\\s*"]):
            unsafe_patterns.append((pattern, "Nested quantifiers"))

        # Check for catastrophic backtracking
        if re.search(r"\([^)]*[*+]\)[*+]", pattern):
            unsafe_patterns.append((pattern, "Potential catastrophic backtracking"))

        # Test with malicious input
        try:
            test_input = "a" * 1000
            compiled = re.compile(pattern)
            import time

            start = time.time()
            compiled.search(test_input)
            elapsed = time.time() - start

            if elapsed > 0.1:  # More than 100ms is suspicious
                unsafe_patterns.append((pattern, f"Slow execution: {elapsed:.2f}s"))
        except Exception as e:
            unsafe_patterns.append((pattern, f"Failed to compile or test: {e}"))

    return unsafe_patterns


def check_dependencies() -> Dict[str, Any]:
    """Check for vulnerable dependencies."""
    vulnerabilities = {}

    try:
        # Check for known vulnerable versions
        result = subprocess.run(["pip", "list", "--format=json"], capture_output=True, text=True)

        if result.returncode == 0:
            import json

            packages = json.loads(result.stdout)

            # Known vulnerabilities (simplified)
            vulnerable_packages = {
                "gitpython": {"vulnerable": ["<3.1.30"], "cve": "CVE-2022-24439"},
            }

            for package in packages:
                name = package["name"].lower()
                version = package["version"]

                if name in vulnerable_packages:
                    vulnerabilities[name] = {"installed": version, "vulnerability": vulnerable_packages[name]}

    except Exception as e:
        logger.error(f"Error checking dependencies: {e}")

    return vulnerabilities


def main() -> None:
    """Run security audit."""
    base_path = Path(__file__).parent

    # Files to audit
    files_to_audit = [
        base_path / "git_pattern_matcher.py",
        base_path / "git_history_parser.py",
        base_path / "claude_code_auditor.py",
    ]

    auditor = SecurityAuditor(base_path)

    # Audit each file
    for file_path in files_to_audit:
        if file_path.exists():
            auditor.audit_file(file_path)

    # Check regex patterns
    logger.info("Checking regex patterns for ReDoS...")
    unsafe_patterns = check_regex_patterns_safety()
    for pattern, reason in unsafe_patterns:
        auditor.issues.append(
            {
                "file": "git_pattern_matcher.py",
                "type": "ReDoS Risk",
                "severity": "HIGH",
                "description": f'Pattern "{pattern[:50]}..." - {reason}',
            }
        )

    # Check dependencies
    logger.info("Checking dependencies...")
    vulns = check_dependencies()
    for package, info in vulns.items():
        auditor.issues.append(
            {
                "file": "dependencies",
                "type": "Vulnerable Dependency",
                "severity": "HIGH",
                "description": f'{package} {info["installed"]} - {info["vulnerability"]["cve"]}',
            }
        )

    # Generate report
    report = auditor.generate_report()

    # Save report
    report_path = base_path / "security_audit_report.md"
    report_path.write_text(report)
    logger.info(f"Security audit report saved to {report_path}")

    # Print summary
    print(report)

    # Exit with error if critical issues found
    critical_count = sum(1 for issue in auditor.issues if issue["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
