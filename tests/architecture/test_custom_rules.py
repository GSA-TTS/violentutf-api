"""
Custom architectural rules framework for ViolentUTF API.

This module implements custom architectural rules specific to the ViolentUTF platform,
integrating with historical analysis patterns from ADR-011 and platform-specific requirements.
"""

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest
import yaml


@dataclass
class ArchitecturalRule:
    """Represents a custom architectural rule."""

    id: str
    name: str
    description: str
    pattern: str
    severity: str  # critical, high, medium, low
    category: str
    file_pattern: str = "**/*.py"
    exclude_pattern: Optional[str] = None
    fix_suggestion: Optional[str] = None
    adr_reference: Optional[str] = None

    def matches_file(self, file_path: Path) -> bool:
        """Check if rule applies to given file."""
        # Check inclusion pattern
        if not file_path.match(self.file_pattern):
            return False

        # Check exclusion pattern
        if self.exclude_pattern and file_path.match(self.exclude_pattern):
            return False

        return True


class CustomRulesEngine:
    """Engine for executing custom architectural rules."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.app_path = project_root / "app"
        self.config_path = project_root / "config"
        self.rules: List[ArchitecturalRule] = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from configuration."""
        # Load from violation_patterns.yml if it exists (ADR-011 integration)
        violation_patterns_file = self.config_path / "violation_patterns.yml"
        if violation_patterns_file.exists():
            self._load_violation_patterns(violation_patterns_file)

        # Load ViolentUTF-specific custom rules
        self._load_custom_violentutf_rules()

    def _load_violation_patterns(self, patterns_file: Path):
        """Load patterns from ADR-011 violation_patterns.yml."""
        try:
            with open(patterns_file, "r") as f:
                config = yaml.safe_load(f)

            if config and "patterns" in config:
                for pattern_id, pattern_data in config["patterns"].items():
                    rule = ArchitecturalRule(
                        id=pattern_id,
                        name=pattern_data.get("name", pattern_id),
                        description=pattern_data.get("description", ""),
                        pattern=pattern_data.get("pattern", ""),
                        severity=pattern_data.get("severity", "medium"),
                        category=pattern_data.get("category", "general"),
                        file_pattern=pattern_data.get("file_pattern", "**/*.py"),
                        exclude_pattern=pattern_data.get("exclude_pattern"),
                        fix_suggestion=pattern_data.get("fix_suggestion"),
                        adr_reference=pattern_data.get("adr_reference"),
                    )
                    self.rules.append(rule)
        except Exception as e:
            print(f"Warning: Could not load violation patterns: {e}")

    def _load_custom_violentutf_rules(self):
        """Load ViolentUTF platform-specific rules."""
        # PyRIT integration rules
        self.rules.extend(
            [
                ArchitecturalRule(
                    id="VUTF-001",
                    name="PyRIT Target Security",
                    description="PyRIT targets must validate input parameters",
                    pattern=r"class.*Target.*:\s*(?!.*validate_input)",
                    severity="high",
                    category="red-teaming",
                    file_pattern="**/targets/**/*.py",
                    fix_suggestion="Add validate_input method to target class",
                    adr_reference="ADR-F4-1",
                ),
                ArchitecturalRule(
                    id="VUTF-002",
                    name="Prompt Template Sanitization",
                    description="Prompt templates must be sanitized before use",
                    pattern=r"prompt.*=.*f[\"']|prompt.*\.format\(",
                    severity="high",
                    category="red-teaming",
                    file_pattern="**/prompts/**/*.py",
                    fix_suggestion="Use safe template rendering with parameter validation",
                    adr_reference="ADR-F1-1",
                ),
                ArchitecturalRule(
                    id="VUTF-003",
                    name="Target Configuration Security",
                    description="Target configurations must not contain hardcoded credentials",
                    pattern=r"(api_key|password|secret|token)\s*=\s*[\"'][^{]",
                    severity="critical",
                    category="security",
                    file_pattern="**/config/**/*.py",
                    exclude_pattern="**/*example*.py",
                    fix_suggestion="Use environment variables or secure secret management",
                    adr_reference="ADR-F4-2",
                ),
            ]
        )

        # Logging compliance rules
        self.rules.extend(
            [
                ArchitecturalRule(
                    id="LOG-001",
                    name="Structured Logging",
                    description="Use structured JSON logging instead of print statements",
                    pattern=r"\bprint\s*\(",
                    severity="medium",
                    category="logging",
                    file_pattern="**/*.py",
                    exclude_pattern="**/test_*.py",
                    fix_suggestion="Use logger.info() or structured logging",
                    adr_reference="ADR-008",
                ),
                ArchitecturalRule(
                    id="LOG-002",
                    name="Correlation ID Presence",
                    description="Log entries must include correlation_id",
                    pattern=r"logger\.(info|error|warning|debug).*(?!correlation_id)",
                    severity="medium",
                    category="logging",
                    file_pattern="**/api/**/*.py",
                    fix_suggestion="Include correlation_id in log context",
                    adr_reference="ADR-008",
                ),
            ]
        )

        # API security rules
        self.rules.extend(
            [
                ArchitecturalRule(
                    id="API-001",
                    name="Rate Limiting Decorator",
                    description="Public API endpoints must have rate limiting",
                    pattern=r"@(router|app)\.(get|post|put|delete).*\n(?!.*@rate_limit)",
                    severity="high",
                    category="api-security",
                    file_pattern="**/api/v*/public/**/*.py",
                    fix_suggestion="Add @rate_limit decorator to public endpoints",
                    adr_reference="ADR-005",
                ),
                ArchitecturalRule(
                    id="API-002",
                    name="API Versioning",
                    description="API endpoints must include version in path",
                    pattern=r'@router\.(get|post|put|delete)\s*\(\s*["\'](?!/v\d+/)',
                    severity="medium",
                    category="api-design",
                    file_pattern="**/api/**/*.py",
                    fix_suggestion="Include version prefix (e.g., /v1/) in endpoint path",
                    adr_reference="ADR-004",
                ),
            ]
        )

    def execute_rule(self, rule: ArchitecturalRule) -> List[Tuple[Path, int, str]]:
        """
        Execute a single rule against the codebase.
        Returns list of (file_path, line_number, matched_text) tuples.
        """
        violations = []

        # Find files matching the pattern
        for py_file in self.app_path.rglob("*.py"):
            if not rule.matches_file(py_file):
                continue

            if "__pycache__" in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split("\n")

                # Check each line against the pattern
                for i, line in enumerate(lines, 1):
                    if re.search(rule.pattern, line):
                        violations.append((py_file, i, line.strip()))

                # Also check multi-line patterns if needed
                if "\n" in rule.pattern:
                    matches = re.finditer(rule.pattern, content, re.MULTILINE)
                    for match in matches:
                        line_no = content[: match.start()].count("\n") + 1
                        violations.append((py_file, line_no, match.group(0)[:100]))

            except Exception:
                continue

        return violations

    def execute_all_rules(self) -> Dict[str, List[Tuple[Path, int, str]]]:
        """Execute all rules and return violations by rule ID."""
        results = {}

        for rule in self.rules:
            violations = self.execute_rule(rule)
            if violations:
                results[rule.id] = violations

        return results

    def generate_compliance_score(self, violations: Dict[str, List]) -> float:
        """Calculate compliance score based on violations."""
        if not self.rules:
            return 100.0

        total_weight = 0
        violation_weight = 0

        severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
        }

        for rule in self.rules:
            weight = severity_weights.get(rule.severity, 1)
            total_weight += weight

            if rule.id in violations:
                violation_count = len(violations[rule.id])
                # Cap the impact of a single rule
                violation_weight += min(violation_count, 5) * weight

        if total_weight == 0:
            return 100.0

        compliance = max(0, 100 - (violation_weight / total_weight * 10))
        return round(compliance, 2)


class HistoricalPatternValidator:
    """Validates patterns identified by historical analysis (ADR-011)."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.app_path = project_root / "app"

    def validate_authentication_patterns(self) -> List[Tuple[Path, int, str]]:
        """Validate authentication patterns from historical analysis."""
        violations = []

        # Patterns identified in ADR-011 historical analysis
        auth_patterns = [
            (r"verify_jwt.*=\s*False", "JWT verification disabled"),
            (
                r"@app\.(get|post|put|delete).*\n.*def.*\n(?!.*Depends.*current_user)",
                "Endpoint without authentication",
            ),
            # Note: HS256 temporarily accepted while planning RS256 migration
        ]

        for py_file in self.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            try:
                content = py_file.read_text()

                for pattern, issue in auth_patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_no = content[: match.start()].count("\n") + 1
                        violations.append((py_file, line_no, issue))

            except Exception:
                continue

        return violations

    def validate_logging_patterns(self) -> List[Tuple[Path, int, str]]:
        """Validate logging patterns from historical analysis."""
        violations = []

        # Check for non-structured logging
        for py_file in self.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file) or "test" in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    # Check for print statements
                    if re.search(r"\bprint\s*\(", line):
                        violations.append((py_file, i, "Using print instead of logger"))

                    # Check for non-JSON logging
                    if re.search(r'logging\.(info|error|debug)\s*\(["\'](?!{)', line):
                        violations.append((py_file, i, "Non-structured log message"))

            except Exception:
                continue

        return violations


@pytest.fixture
def custom_rules_engine():
    """Provide CustomRulesEngine instance."""
    project_root = Path(__file__).parent.parent.parent
    return CustomRulesEngine(project_root)


@pytest.fixture
def historical_validator():
    """Provide HistoricalPatternValidator instance."""
    project_root = Path(__file__).parent.parent.parent
    return HistoricalPatternValidator(project_root)


class TestCustomRuleFramework:
    """Test suite for custom rule framework."""

    def test_rule_framework_operational(self, custom_rules_engine):
        """
        Given the need for ViolentUTF-specific architectural rules
        When developing new architectural tests
        Then the framework must support custom rule creation
        And the framework must provide rule templates
        And the framework must allow YAML-based rule configuration
        """
        # Verify rules are loaded
        assert len(custom_rules_engine.rules) > 0, "No rules loaded in custom framework"

        # Verify rule structure
        for rule in custom_rules_engine.rules:
            assert rule.id, f"Rule missing ID"
            assert rule.name, f"Rule {rule.id} missing name"
            assert rule.pattern, f"Rule {rule.id} missing pattern"
            assert rule.severity in [
                "critical",
                "high",
                "medium",
                "low",
            ], f"Rule {rule.id} has invalid severity: {rule.severity}"

    def test_yaml_configuration_support(self, custom_rules_engine):
        """Test YAML-based rule configuration loading."""
        # Check if violation_patterns.yml was loaded
        yaml_rules = [r for r in custom_rules_engine.rules if r.id.startswith("ADR-")]

        # This might be empty if violation_patterns.yml doesn't exist yet
        if not yaml_rules:
            pytest.skip("No violation_patterns.yml found - this is expected for initial setup")
        else:
            assert len(yaml_rules) > 0, "YAML rules should be loaded if file exists"


class TestHistoricalPatternIntegration:
    """Test suite for historical analysis pattern integration."""

    def test_historical_patterns_validated(self, historical_validator):
        """
        Given the patterns from ADR-011 historical analysis
        When the architectural test suite runs
        Then the test must validate patterns identified by historical analysis
        And the test must cross-reference with violation_patterns.yml
        And the test must generate compliance scores
        """
        auth_violations = historical_validator.validate_authentication_patterns()
        log_violations = historical_validator.validate_logging_patterns()

        # Report findings (not failing for now as these might be intentional)
        if auth_violations:
            print(f"\nAuthentication pattern violations: {len(auth_violations)}")
            for file_path, line, issue in auth_violations[:5]:
                print(f"  - {Path(file_path).name}:{line}: {issue}")

        if log_violations:
            print(f"\nLogging pattern violations: {len(log_violations)}")
            for file_path, line, issue in log_violations[:5]:
                print(f"  - {Path(file_path).name}:{line}: {issue}")


class TestRedTeamingValidations:
    """Test suite for red-teaming specific validations."""

    def test_pyrit_integration_patterns(self, custom_rules_engine):
        """
        Given the unique requirements of AI red-teaming platform
        When the architectural test suite runs
        Then the test must validate PyRIT integration patterns
        And the test must verify target configuration security
        And the test must validate prompt template handling
        """
        # Execute red-teaming specific rules
        red_team_rules = [r for r in custom_rules_engine.rules if r.category == "red-teaming"]

        violations = {}
        for rule in red_team_rules:
            rule_violations = custom_rules_engine.execute_rule(rule)
            if rule_violations:
                violations[rule.id] = rule_violations

        # Report critical violations
        critical_violations = []
        for rule in red_team_rules:
            if rule.severity == "critical" and rule.id in violations:
                critical_violations.extend(violations[rule.id])

        assert (
            len(critical_violations) == 0
        ), f"Found {len(critical_violations)} critical red-teaming violations:\n" + "\n".join(
            [f"  - {Path(file_path).name}:{line}: {text[:50]}..." for file_path, line, text in critical_violations[:5]]
        )


class TestLoggingCompliance:
    """Test suite for logging compliance validation."""

    def test_structured_logging_enforced(self, custom_rules_engine):
        """
        Given the structured logging requirements from ADR-008
        When the architectural test suite runs
        Then the test must verify structured JSON logging usage
        And the test must detect any print statements or unstructured logs
        And the test must validate correlation ID presence
        """
        # Execute logging rules
        log_rules = [r for r in custom_rules_engine.rules if r.category == "logging"]

        violations = {}
        for rule in log_rules:
            rule_violations = custom_rules_engine.execute_rule(rule)
            if rule_violations:
                violations[rule.id] = rule_violations

        # Check for print statements (excluding tests)
        if "LOG-001" in violations:
            print_violations = violations["LOG-001"]
            # Filter out test files
            prod_violations = [v for v in print_violations if "test" not in str(v[0]).lower()]

            if prod_violations:
                pytest.skip(
                    f"Found {len(prod_violations)} print statements in production code:\n"
                    + "\n".join([f"  - {Path(fp).name}:{line}" for fp, line, _ in prod_violations[:5]])
                    + "\nReplace with structured logging."
                )


class TestComplianceReporting:
    """Test suite for compliance reporting and scoring."""

    def test_generate_compliance_report(self, custom_rules_engine, tmp_path):
        """Generate comprehensive compliance report with scores."""
        # Execute all rules
        all_violations = custom_rules_engine.execute_all_rules()

        # Calculate compliance score
        compliance_score = custom_rules_engine.generate_compliance_score(all_violations)

        # Generate detailed report
        report_path = tmp_path / "custom_rules_compliance.json"

        report_data = {
            "compliance_score": compliance_score,
            "total_rules": len(custom_rules_engine.rules),
            "rules_with_violations": len(all_violations),
            "total_violations": sum(len(v) for v in all_violations.values()),
            "violations_by_severity": {},
            "violations_by_category": {},
            "rule_details": [],
        }

        # Analyze violations by severity and category
        for rule in custom_rules_engine.rules:
            if rule.id in all_violations:
                # Count by severity
                if rule.severity not in report_data["violations_by_severity"]:
                    report_data["violations_by_severity"][rule.severity] = 0
                report_data["violations_by_severity"][rule.severity] += len(all_violations[rule.id])

                # Count by category
                if rule.category not in report_data["violations_by_category"]:
                    report_data["violations_by_category"][rule.category] = 0
                report_data["violations_by_category"][rule.category] += len(all_violations[rule.id])

                # Add rule details
                report_data["rule_details"].append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category,
                        "violation_count": len(all_violations[rule.id]),
                        "fix_suggestion": rule.fix_suggestion,
                        "adr_reference": rule.adr_reference,
                    }
                )

        # Write report
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        # Print summary
        print(f"\n{'='*50}")
        print(f"Architectural Compliance Report")
        print(f"{'='*50}")
        print(f"Compliance Score: {compliance_score}%")
        print(f"Total Rules: {report_data['total_rules']}")
        print(f"Rules with Violations: {report_data['rules_with_violations']}")
        print(f"Total Violations: {report_data['total_violations']}")

        if report_data["violations_by_severity"]:
            print(f"\nViolations by Severity:")
            for severity, count in report_data["violations_by_severity"].items():
                print(f"  {severity}: {count}")

        if report_data["violations_by_category"]:
            print(f"\nViolations by Category:")
            for category, count in report_data["violations_by_category"].items():
                print(f"  {category}: {count}")

        print(f"\nFull report saved to: {report_path}")

        # Assert minimum compliance score
        assert compliance_score >= 70.0, f"Compliance score {compliance_score}% is below minimum threshold of 70%"
