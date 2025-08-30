#!/usr/bin/env python3
"""
Pattern-Based Architectural Analyzer for CI/CD

This analyzer provides pattern-based architectural analysis for environments
where Claude API access is not available (e.g., GitHub Actions). It maintains
consistency with the smart analyzer but uses only pattern matching.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class PatternViolation:
    """Represents a pattern-based violation"""

    file_path: str
    line_number: int
    pattern_id: str
    adr_id: str
    severity: str
    description: str
    code_snippet: str = ""
    confidence: float = 0.7  # Pattern matching has lower confidence than semantic analysis
    fix_suggestion: str = ""


@dataclass
class PatternRule:
    """Defines a pattern matching rule"""

    id: str
    adr_id: str
    description: str
    patterns: List[str]  # Regex patterns
    anti_patterns: List[str]  # Patterns that should NOT exist
    severity: str = "medium"
    file_filters: List[str] = field(default_factory=list)  # File patterns to check

    def compile_patterns(self) -> None:
        """Compile regex patterns for efficiency"""
        self.compiled_patterns = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in self.patterns]
        self.compiled_anti_patterns = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in self.anti_patterns]


class PatternAnalyzer:
    """Pattern-based analyzer for CI environments without Claude API access"""

    def __init__(self, config_path: str = "config/ci_violation_patterns.yml"):
        self.config_path = Path(config_path)
        self.patterns = self._load_patterns()
        self.results_cache: Dict[str, Any] = {}

    def _load_patterns(self) -> List[PatternRule]:
        """Load violation patterns from configuration"""
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
                patterns = []
                for rule_config in config.get("pattern_rules", []):
                    rule = PatternRule(**rule_config)
                    rule.compile_patterns()
                    patterns.append(rule)
                return patterns
        else:
            # Default patterns if config doesn't exist
            return self._get_default_patterns()

    def _get_default_patterns(self) -> List[PatternRule]:
        """Get default architectural patterns"""
        patterns = [
            PatternRule(
                id="AUTH-001",
                adr_id="ADR-002",
                description="Direct database access in API endpoints",
                patterns=[
                    r"@app\.(get|post|put|delete).*\n.*db\.(query|execute)",
                    r"from.*models.*import.*\n.*@app\.(route|get|post)",
                ],
                anti_patterns=[],
                severity="high",
                file_filters=["app/api/endpoints/*.py"],
            ),
            PatternRule(
                id="AUTH-002",
                adr_id="ADR-002",
                description="Missing authentication decorator",
                patterns=[
                    r"@app\.(get|post|put|delete)(?!.*@authenticate)",
                ],
                anti_patterns=[
                    r"@authenticate",
                    r"@require_auth",
                ],
                severity="critical",
                file_filters=[
                    "app/api/endpoints/*.py",
                    "!app/api/endpoints/public*.py",
                ],
            ),
            PatternRule(
                id="SEC-001",
                adr_id="ADR-005",
                description="Hardcoded secrets or credentials",
                patterns=[
                    r"(password|secret|api_key|token)\s*=\s*[\"'][^\"']+[\"']",
                    r"(AWS|AZURE|GCP)_.*KEY\s*=\s*[\"'][^\"']+[\"']",
                ],
                anti_patterns=[
                    r"os\.getenv",
                    r"config\.get",
                ],
                severity="critical",
                file_filters=["**/*.py"],
            ),
            PatternRule(
                id="ARCH-001",
                adr_id="ADR-003",
                description="Business logic in API layer",
                patterns=[
                    r"class.*Controller.*\n([^}])*def.*calculate|process|transform",
                    r"@app\..*\n([^}])*\n.*for.*in.*:\n.*if.*:",
                ],
                anti_patterns=[],
                severity="medium",
                file_filters=["app/api/**/*.py"],
            ),
            PatternRule(
                id="RATE-001",
                adr_id="ADR-005",
                description="Missing rate limiting",
                patterns=[
                    r"@app\.(get|post|put|delete)(?!.*@rate_limit)",
                ],
                anti_patterns=[
                    r"@rate_limit",
                    r"RateLimiter",
                ],
                severity="high",
                file_filters=["app/api/endpoints/*.py"],
            ),
        ]

        # Compile patterns
        for pattern in patterns:
            pattern.compile_patterns()

        return patterns

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path to prevent path traversal attacks"""
        try:
            path = Path(file_path)
            if ".." in str(path):
                return False

            abs_path = path.resolve()
            repo_path = Path.cwd().resolve()

            try:
                abs_path.relative_to(repo_path)
                return True
            except ValueError:
                return False
        except Exception:
            return False

    def analyze_file(self, file_path: str) -> List[PatternViolation]:
        """Analyze a single file for pattern violations"""
        violations: List[PatternViolation] = []

        # Validate file path for security
        if not self._validate_file_path(file_path):
            print(f"Warning: Invalid file path detected: {file_path}")
            return violations

        # Check if file exists
        if not os.path.exists(file_path):
            return violations

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            # Check each pattern rule
            for rule in self.patterns:
                # Check if file matches filters
                if not self._file_matches_filters(file_path, rule.file_filters):
                    continue

                # Check for pattern matches
                for pattern in rule.compiled_patterns:
                    for match in pattern.finditer(content):
                        # Get line number
                        line_number = content[: match.start()].count("\n") + 1

                        # Extract code snippet
                        start_line = max(0, line_number - 2)
                        end_line = min(len(lines), line_number + 2)
                        code_snippet = "\n".join(lines[start_line:end_line])

                        # Check if anti-patterns are present (which would negate the violation)
                        if self._has_anti_pattern(content, match, rule.compiled_anti_patterns):
                            continue

                        violation = PatternViolation(
                            file_path=file_path,
                            line_number=line_number,
                            pattern_id=rule.id,
                            adr_id=rule.adr_id,
                            severity=rule.severity,
                            description=rule.description,
                            code_snippet=code_snippet,
                            fix_suggestion=self._generate_fix_suggestion(rule),
                        )
                        violations.append(violation)

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

        return violations

    def _file_matches_filters(self, file_path: str, filters: List[str]) -> bool:
        """Check if file matches the filter patterns"""
        if not filters:
            return True

        # Normalize path separators
        file_path = file_path.replace("\\", "/")

        matched = False
        for filter_pattern in filters:
            if filter_pattern.startswith("!"):
                # Exclusion pattern
                pattern = filter_pattern[1:]
                if self._match_pattern(file_path, pattern):
                    return False
            else:
                # Inclusion pattern
                if self._match_pattern(file_path, filter_pattern):
                    matched = True

        return matched

    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Match file path against glob pattern"""
        # Convert glob to regex
        pattern = pattern.replace("**", ".*")
        pattern = pattern.replace("*", "[^/]*")
        pattern = f".*{pattern}$"  # Match end of path

        return bool(re.match(pattern, path))

    def _has_anti_pattern(self, content: str, match: re.Match[str], anti_patterns: List[re.Pattern[str]]) -> bool:
        """Check if anti-patterns are present near the match"""
        # Look for anti-patterns within 5 lines of the match
        start = max(0, match.start() - 200)
        end = min(len(content), match.end() + 200)
        context = content[start:end]

        for anti_pattern in anti_patterns:
            if anti_pattern.search(context):
                return True
        return False

    def _generate_fix_suggestion(self, rule: PatternRule) -> str:
        """Generate fix suggestion based on rule"""
        suggestions = {
            "AUTH-001": "Move database queries to repository layer and inject as dependency",
            "AUTH-002": "Add @authenticate decorator to protect this endpoint",
            "SEC-001": "Use environment variables: os.getenv('SECRET_KEY')",
            "ARCH-001": "Move business logic to service layer",
            "RATE-001": "Add @rate_limit decorator with appropriate limits",
        }
        return suggestions.get(rule.id, "Review architectural patterns and refactor accordingly")

    def analyze_files(self, files: List[str], parallel: bool = True) -> Dict[str, Any]:
        """Analyze multiple files for violations"""
        start_time = datetime.now()
        all_violations = []

        if parallel and len(files) > 1:
            # Parallel analysis
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future_to_file = {executor.submit(self.analyze_file, f): f for f in files}

                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        violations = future.result()
                        all_violations.extend(violations)
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
        else:
            # Sequential analysis
            for file_path in files:
                violations = self.analyze_file(file_path)
                all_violations.extend(violations)

        # Group violations
        violations_by_severity = defaultdict(list)
        violations_by_adr = defaultdict(list)

        for violation in all_violations:
            violations_by_severity[violation.severity].append(violation)
            violations_by_adr[violation.adr_id].append(violation)

        # Calculate compliance score
        total_files = len(files)
        files_with_violations = len(set(v.file_path for v in all_violations))
        compliance_score = max(0, 100 * (1 - files_with_violations / max(total_files, 1)))

        execution_time = (datetime.now() - start_time).total_seconds()

        return {
            "analysis_type": "pattern_based",
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": len(files),
            "execution_time": execution_time,
            "compliance_score": compliance_score,
            "total_violations": len(all_violations),
            "violations": [self._violation_to_dict(v) for v in all_violations],
            "violations_by_severity": {
                "critical": len(violations_by_severity.get("critical", [])),
                "high": len(violations_by_severity.get("high", [])),
                "medium": len(violations_by_severity.get("medium", [])),
                "low": len(violations_by_severity.get("low", [])),
            },
            "violations_by_adr": {adr: len(violations) for adr, violations in violations_by_adr.items()},
        }

    def _violation_to_dict(self, violation: PatternViolation) -> Dict[str, Any]:
        """Convert violation to dictionary"""
        return {
            "file": violation.file_path,
            "line": violation.line_number,
            "pattern_id": violation.pattern_id,
            "adr_id": violation.adr_id,
            "severity": violation.severity,
            "description": violation.description,
            "confidence": violation.confidence,
            "fix_suggestion": violation.fix_suggestion,
            "code_snippet": violation.code_snippet,
        }

    def analyze_changed_files_only(self, base_ref: str = "origin/master") -> Dict[str, Any]:
        """Analyze only files changed in PR/commit"""
        # Get changed files using git
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=AMR", base_ref],
                capture_output=True,
                text=True,
                check=True,
            )

            changed_files = []
            for line in result.stdout.strip().split("\n"):
                if line and line.endswith(".py"):  # Only Python files
                    changed_files.append(line)

            if not changed_files:
                return {
                    "analysis_type": "pattern_based",
                    "timestamp": datetime.now().isoformat(),
                    "files_analyzed": 0,
                    "compliance_score": 100.0,
                    "total_violations": 0,
                    "violations": [],
                }

            return self.analyze_files(changed_files)

        except subprocess.CalledProcessError as e:
            print(f"Error getting changed files: {e}")
            return {
                "error": f"Failed to get changed files: {e}",
                "analysis_type": "pattern_based",
                "timestamp": datetime.now().isoformat(),
            }

    def generate_github_comment(self, results: Dict[str, Any]) -> str:
        """Generate GitHub PR comment from results"""
        violations = results.get("violations", [])

        if not violations:
            return """## ✅ Architectural Compliance Check Passed

No architectural violations detected in the changed files.

**Analysis Summary:**
- Files analyzed: {files_analyzed}
- Compliance score: {compliance_score:.1f}%
- Execution time: {execution_time:.1f}s

*Note: This is pattern-based analysis. For deeper semantic analysis, run locally with Claude Code.*
""".format(
                **results
            )

        # Group violations by file
        violations_by_file = defaultdict(list)
        for violation in violations:
            violations_by_file[violation["file"]].append(violation)

        comment = f"""## ⚠️ Architectural Compliance Issues Found

Found **{len(violations)}** architectural violations in **{len(violations_by_file)}** files.

**Analysis Summary:**
- Compliance score: {results['compliance_score']:.1f}%
- Critical violations: {results['violations_by_severity']['critical']}
- High severity: {results['violations_by_severity']['high']}
- Medium severity: {results['violations_by_severity']['medium']}

### Violations by File:

"""

        for file_path, file_violations in violations_by_file.items():
            comment += f"\n#### 📄 `{file_path}`\n\n"

            for v in file_violations:
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(v["severity"], "⚪")

                comment += f"""**Line {v['line']}** {severity_emoji} {v['severity'].upper()}: {v['description']}
- ADR: {v['adr_id']}
- Pattern: {v['pattern_id']}
- Suggestion: {v['fix_suggestion']}

<details>
<summary>Code snippet</summary>

```python
{v['code_snippet']}
```

</details>

"""

        comment += """
### 💡 How to Fix

1. **Local Analysis**: Run `pre-commit install` to enable Claude Code analysis locally
2. **Quick Fixes**: Follow the suggestions above for each violation
3. **Documentation**: See [Architectural Guidelines](docs/architecture/README.md)

*Note: This is pattern-based analysis. Local Claude Code analysis provides more accurate semantic understanding.*
"""

        return comment


def main() -> None:
    """Main entry point for CI pattern analysis"""
    parser = argparse.ArgumentParser(description="Pattern-based Architectural Analyzer for CI")
    parser.add_argument("files", nargs="*", help="Files to analyze")
    parser.add_argument("--mode", choices=["ci", "full"], default="ci", help="Analysis mode")
    parser.add_argument(
        "--config",
        default="config/ci_violation_patterns.yml",
        help="Pattern config file",
    )
    parser.add_argument(
        "--output",
        choices=["json", "github-comment"],
        default="json",
        help="Output format",
    )
    parser.add_argument("--output-file", help="Output file path")
    parser.add_argument("--changed-files-only", action="store_true", help="Analyze only changed files")
    parser.add_argument("--base-ref", default="origin/master", help="Base reference for changed files")
    parser.add_argument(
        "--fail-on-violations",
        action="store_true",
        help="Exit with error if violations found",
    )

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = PatternAnalyzer(args.config)

    # Run analysis
    if args.changed_files_only or args.mode == "ci":
        results = analyzer.analyze_changed_files_only(args.base_ref)
    elif args.files:
        results = analyzer.analyze_files(args.files)
    else:
        # Analyze all Python files
        py_files = []
        for root, _, files in os.walk("."):
            for file in files:
                if file.endswith(".py") and not any(skip in root for skip in ["venv", "__pycache__", ".git"]):
                    py_files.append(os.path.join(root, file))
        results = analyzer.analyze_files(py_files)

    # Output results
    if args.output == "github-comment":
        output = analyzer.generate_github_comment(results)
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)
    else:
        # JSON output
        if args.output_file:
            with open(args.output_file, "w") as f:
                json.dump(results, f, indent=2)
        else:
            print(json.dumps(results, indent=2))

    # Exit code
    if args.fail_on_violations and results.get("total_violations", 0) > 0:
        critical = results.get("violations_by_severity", {}).get("critical", 0)
        high = results.get("violations_by_severity", {}).get("high", 0)

        if critical > 0:
            sys.exit(2)  # Critical violations
        elif high > 0:
            sys.exit(1)  # High severity violations

    sys.exit(0)


if __name__ == "__main__":
    main()
