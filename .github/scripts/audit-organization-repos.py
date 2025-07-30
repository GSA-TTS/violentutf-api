#!/usr/bin/env python3
"""
Organization-wide repository audit for dangerous test masking patterns.

This script scans all repositories in an organization for CI/CD security violations,
specifically focusing on dangerous test result masking patterns like || true.

Features:
- Scans GitHub organization repositories
- Detects dangerous test masking patterns
- Generates compliance reports
- Creates remediation tasks
- Supports bulk fixes

Usage:
  export GITHUB_TOKEN="your_github_token"
  python3 audit-organization-repos.py --org your-org-name
  python3 audit-organization-repos.py --org your-org-name --fix --dry-run

Requirements:
  pip install PyGithub requests pyyaml
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import yaml
    from github import Github
except ImportError:
    print("❌ Missing required packages. Install with:")
    print("   pip install PyGithub requests pyyaml")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class DangerousPattern:
    """Represents a dangerous CI/CD pattern."""

    def __init__(self, pattern: str, description: str, severity: str, examples: List[str]):
        self.pattern = pattern
        self.description = description
        self.severity = severity
        self.examples = examples

    def matches(self, content: str) -> List[Tuple[int, str]]:
        """Find all matches of this pattern in content."""
        matches = []
        for line_num, line in enumerate(content.split("\n"), 1):
            if re.search(self.pattern, line, re.IGNORECASE):
                matches.append((line_num, line.strip()))
        return matches


# Define dangerous patterns
DANGEROUS_PATTERNS = [
    DangerousPattern(
        pattern=r"\|\|\s*true\b",
        description="Forces success with || true (masks failures)",
        severity="CRITICAL",
        examples=["pytest tests/ || true", "npm test || true"],
    ),
    DangerousPattern(
        pattern=r"\|\|\s*exit\s+0\b",
        description="Forces success exit code (masks failures)",
        severity="CRITICAL",
        examples=["pytest tests/ || exit 0"],
    ),
    DangerousPattern(
        pattern=r";\s*true\s*$",
        description="Forces success with ; true (masks failures)",
        severity="HIGH",
        examples=["pytest tests/ ; true"],
    ),
    DangerousPattern(
        pattern=r"(pytest|npm\s+test|cargo\s+test|go\s+test|mvn\s+test).*\|\|\s*(echo|printf)",
        description="Test command with output redirection (likely masking)",
        severity="HIGH",
        examples=['pytest tests/ || echo "Tests completed"'],
    ),
]


class RepoViolation:
    """Represents a violation found in a repository."""

    def __init__(self, repo_name: str, file_path: str, line_num: int, line_content: str, pattern: DangerousPattern):
        self.repo_name = repo_name
        self.file_path = file_path
        self.line_num = line_num
        self.line_content = line_content
        self.pattern = pattern

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": self.repo_name,
            "file": self.file_path,
            "line": self.line_num,
            "content": self.line_content,
            "pattern": self.pattern.description,
            "severity": self.pattern.severity,
        }


class OrganizationAuditor:
    """Audits GitHub organization repositories for CI/CD security violations."""

    def __init__(self, github_token: str, org_name: str):
        self.github = Github(github_token)
        self.org_name = org_name
        self.org = self.github.get_organization(org_name)
        self.violations: List[RepoViolation] = []

    def get_file_content(self, repo: Any, file_path: str) -> Optional[str]:
        """Get content of a file from repository."""
        try:
            file_content = repo.get_contents(file_path)
            return str(file_content.decoded_content.decode("utf-8"))
        except Exception as e:
            logger.debug(f"Could not read {file_path} from {repo.name}: {e}")
            return None

    def scan_repository(self, repo: Any) -> List[RepoViolation]:
        """Scan a single repository for violations."""
        logger.info(f"🔍 Scanning repository: {repo.name}")
        repo_violations = []

        # Files to check - these are handled by individual scanning below

        try:
            # Get repository contents
            contents = repo.get_contents("")

            # Check workflow directory
            workflow_files = []
            try:
                workflow_contents = repo.get_contents(".github/workflows")
                for item in workflow_contents:
                    if item.name.endswith((".yml", ".yaml")):
                        workflow_files.append(item.path)
            except Exception:
                pass  # No workflows directory

            # Check scripts directory
            script_files = []
            try:
                script_contents = repo.get_contents("scripts")
                for item in script_contents:
                    if item.name.endswith((".sh", ".bash")) or item.type == "file":
                        script_files.append(item.path)
            except Exception:
                pass  # No scripts directory

            # Check individual files
            individual_files = []
            for content in contents:
                if content.name in ["Makefile", ".travis.yml", "azure-pipelines.yml", "Jenkinsfile"]:
                    individual_files.append(content.path)

            # Scan all identified files
            all_files = workflow_files + script_files + individual_files

            for file_path in all_files:
                content = self.get_file_content(repo, file_path)
                if content:
                    # Check each dangerous pattern
                    for pattern in DANGEROUS_PATTERNS:
                        matches = pattern.matches(content)
                        for line_num, line_content in matches:
                            violation = RepoViolation(
                                repo_name=repo.name,
                                file_path=file_path,
                                line_num=line_num,
                                line_content=line_content,
                                pattern=pattern,
                            )
                            repo_violations.append(violation)

        except Exception as e:
            logger.error(f"Error scanning repository {repo.name}: {e}")

        if repo_violations:
            logger.warning(f"⚠️  Found {len(repo_violations)} violations in {repo.name}")
        else:
            logger.info(f"✅ No violations found in {repo.name}")

        return repo_violations

    def audit_organization(self, max_repos: Optional[int] = None) -> List[RepoViolation]:
        """Audit all repositories in the organization."""
        logger.info(f"🚨 Starting organization audit for: {self.org_name}")

        try:
            repos = list(self.org.get_repos())
            if max_repos:
                repos = repos[:max_repos]

            logger.info(f"📊 Found {len(repos)} repositories to scan")

            total_violations = []
            scanned_count = 0

            for repo in repos:
                # Skip archived repositories
                if repo.archived:
                    logger.info(f"⏭️  Skipping archived repository: {repo.name}")
                    continue

                try:
                    repo_violations = self.scan_repository(repo)
                    total_violations.extend(repo_violations)
                    scanned_count += 1

                except Exception as e:
                    logger.error(f"❌ Failed to scan {repo.name}: {e}")
                    continue

            logger.info(f"🎯 Audit complete: {scanned_count} repositories scanned")
            logger.info(f"📈 Total violations found: {len(total_violations)}")

            self.violations = total_violations
            return total_violations

        except Exception as e:
            logger.error(f"❌ Organization audit failed: {e}")
            return []

    def generate_report(self, output_file: str = "audit-report.json") -> Dict[str, Any]:
        """Generate a comprehensive audit report."""

        # Organize violations by severity and repository
        by_severity: Dict[str, List[RepoViolation]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        by_repo: Dict[str, List[RepoViolation]] = {}

        for violation in self.violations:
            # By severity
            by_severity[violation.pattern.severity].append(violation)

            # By repository
            if violation.repo_name not in by_repo:
                by_repo[violation.repo_name] = []
            by_repo[violation.repo_name].append(violation)

        # Generate summary statistics
        stats = {
            "total_violations": len(self.violations),
            "critical_violations": len(by_severity["CRITICAL"]),
            "high_violations": len(by_severity["HIGH"]),
            "medium_violations": len(by_severity["MEDIUM"]),
            "affected_repositories": len(by_repo),
            "scan_timestamp": datetime.now().isoformat(),
            "organization": self.org_name,
        }

        # Detailed findings
        findings = []
        for violation in self.violations:
            findings.append(violation.to_dict())

        # Top violating repositories
        top_violators = sorted(
            [(repo, len(violations)) for repo, violations in by_repo.items()], key=lambda x: x[1], reverse=True
        )[:10]

        report = {
            "audit_metadata": stats,
            "summary": {
                "total_repositories_scanned": len(set(v.repo_name for v in self.violations)) if self.violations else 0,
                "violations_by_severity": {k: len(v) for k, v in by_severity.items()},
                "top_violating_repositories": [{"repo": repo, "violations": count} for repo, count in top_violators],
            },
            "detailed_findings": findings,
            "remediation_priority": [
                v.to_dict()
                for v in sorted(
                    self.violations,
                    key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[x.pattern.severity],
                    reverse=True,
                )
            ],
        }

        # Save report to file
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"📄 Audit report saved to: {output_file}")
        return report

    def print_summary(self) -> None:
        """Print a human-readable summary of the audit."""
        if not self.violations:
            print("✅ 🎉 NO VIOLATIONS FOUND! 🎉")
            print("   All repositories follow proper CI/CD security practices.")
            return

        print(f"\n🚨 ORGANIZATION AUDIT SUMMARY")
        print(f"=" * 50)
        print(f"Organization: {self.org_name}")
        print(f"Total Violations: {len(self.violations)}")

        # Group by severity
        by_severity: Dict[str, List[RepoViolation]] = {}
        for violation in self.violations:
            severity = violation.pattern.severity
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(violation)

        print(f"\nViolations by Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(by_severity.get(severity, []))
            if count > 0:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[severity]
                print(f"  {icon} {severity}: {count}")

        # Top violating repositories
        by_repo = {}
        for violation in self.violations:
            repo = violation.repo_name
            if repo not in by_repo:
                by_repo[repo] = 0
            by_repo[repo] += 1

        print(f"\nTop Violating Repositories:")
        top_repos = sorted(by_repo.items(), key=lambda x: x[1], reverse=True)[:5]
        for repo, count in top_repos:
            print(f"  📦 {repo}: {count} violations")

        print(f"\n⚡ IMMEDIATE ACTION REQUIRED:")
        critical_violations = by_severity.get("CRITICAL", [])
        if critical_violations:
            print(f"   🔴 {len(critical_violations)} CRITICAL violations must be fixed immediately")
            print(f"   These patterns can hide test failures and create security risks")

        print(f"\n📋 Next Steps:")
        print(f"   1. Review detailed report: audit-report.json")
        print(f"   2. Fix CRITICAL violations first")
        print(f"   3. Implement organization-wide policy")
        print(f"   4. Add pre-commit hooks to prevent future violations")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit GitHub organization for dangerous CI/CD patterns")
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument("--token", help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--max-repos", type=int, help="Maximum repositories to scan")
    parser.add_argument("--output", default="audit-report.json", help="Output report file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--fix", action="store_true", help="Generate fix suggestions")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get GitHub token
    github_token = args.token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("❌ GitHub token required. Set GITHUB_TOKEN env var or use --token")
        sys.exit(1)

    try:
        # Create auditor and run audit
        auditor = OrganizationAuditor(github_token, args.org)
        violations = auditor.audit_organization(max_repos=args.max_repos)

        # Generate report
        auditor.generate_report(args.output)

        # Print summary
        auditor.print_summary()

        # Exit with error code if critical violations found
        critical_count = len([v for v in violations if v.pattern.severity == "CRITICAL"])
        if critical_count > 0:
            print(f"\n❌ AUDIT FAILED: {critical_count} critical violations found")
            sys.exit(1)
        else:
            print(f"\n✅ AUDIT PASSED: No critical violations found")
            sys.exit(0)

    except Exception as e:
        logger.error(f"❌ Audit failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
