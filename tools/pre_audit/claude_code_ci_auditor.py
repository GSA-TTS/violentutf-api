#!/usr/bin/env python3
"""
Claude Code CI/CD Auditor.

Optimized architectural auditor for CI/CD pipeline integration with GitHub Actions.
Provides fast, targeted analysis for pull requests and continuous integration.

Based on the Claude Code Enhanced Auditor Improvement Plan.

Author: ViolentUTF API Audit Team
License: MIT
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from claude_code_auditor import ClaudeCodeArchitecturalAuditor, EnterpriseClaudeCodeConfig
from dotenv import load_dotenv

try:
    from claude_code_sdk import ClaudeCodeOptions, query
except ImportError:
    print("ERROR: Claude Code SDK is required for CI/CD architectural analysis.")
    print("Install with: pip install claude-code-sdk")
    print("Or install Claude Code CLI: npm install -g @anthropic/claude-code")
    raise ImportError("Claude Code SDK is required but not available")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


class ClaudeCodeCIAuditor:
    """Claude Code auditor optimized for CI/CD pipeline integration."""

    def __init__(self, mode: str = "full"):
        self.mode = mode  # full, pull-request, incremental
        self.repo_path = Path.cwd()
        self.config = EnterpriseClaudeCodeConfig()

        # CI-specific configuration
        self.pr_mode = os.getenv("GITHUB_EVENT_NAME") == "pull_request"
        self.github_repository = os.getenv("GITHUB_REPOSITORY", "")
        self.github_sha = os.getenv("GITHUB_SHA", "")
        self.github_ref = os.getenv("GITHUB_REF", "")

        # Ensure CI reports directory exists
        self.ci_reports_dir = self.config.reports_dir / "ci"
        self.ci_reports_dir.mkdir(parents=True, exist_ok=True)

    def _extract_message_content(self, message: Any) -> str:
        """Extract text content from a Claude Code SDK message."""
        if not hasattr(message, "content") or not message.content:
            return ""

        content = ""
        try:
            for block in message.content:
                if hasattr(block, "text"):
                    content += block.text
        except (TypeError, AttributeError):
            # Handle case where content might be a string
            if isinstance(message.content, str):
                content = message.content
            else:
                content = str(message.content)

        return content.strip()

    def _create_ci_system_prompt(self) -> str:
        """Create CI-optimized system prompt."""
        return """You are a CI/CD architectural auditor focused on rapid, accurate analysis.

Your priorities:
- Fast, accurate violation detection for continuous integration
- Clear, actionable feedback for developers
- Integration-friendly output formats
- Risk-based prioritization (block only critical violations)

CI/CD Focus Areas:
1. New architectural violations introduced in changed files
2. Critical security and architectural risks
3. ADR compliance for modified code areas
4. Integration impact with existing codebase

Output Requirements:
- JSON format for automated processing
- Specific file paths and line numbers
- Risk-based violation categorization
- Quick remediation guidance
- Execution time optimization

Available tools: Read, Grep, Glob, Bash for fast codebase analysis."""

    def _create_ci_analysis_options(self, max_turns: int = 15) -> ClaudeCodeOptions:
        """Create CI-optimized Claude Code options."""
        return ClaudeCodeOptions(
            system_prompt=self._create_ci_system_prompt(),
            max_turns=max_turns,
            cwd=self.repo_path,
            allowed_tools=["Read", "Grep", "Glob", "Bash"],
            permission_mode="default",
        )

    async def get_changed_files(self) -> List[str]:
        """Get list of changed files for PR or incremental analysis."""
        try:
            if self.pr_mode:
                # Get changed files in PR
                result = subprocess.run(
                    ["git", "diff", "--name-only", "origin/main...HEAD"],
                    capture_output=True,
                    text=True,
                    cwd=self.repo_path,
                )
            else:
                # Get changed files in last commit
                result = subprocess.run(
                    ["git", "diff", "--name-only", "HEAD~1", "HEAD"], capture_output=True, text=True, cwd=self.repo_path
                )

            if result.returncode == 0:
                changed_files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
                # Filter for relevant file types
                relevant_files = [
                    f
                    for f in changed_files
                    if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".c", ".cs"))
                ]
                return relevant_files
            else:
                logger.warning(f"Git command failed: {result.stderr}")
                return []

        except subprocess.SubprocessError as e:
            logger.error(f"Error getting changed files: {e}")
            return []

    async def run_ci_audit(self) -> Dict[str, Any]:
        """Run architectural audit optimized for CI/CD pipeline."""
        logger.info(f"Starting CI audit in {self.mode} mode")
        start_time = time.time()

        options = self._create_ci_analysis_options()

        if self.mode == "pull-request":
            audit_prompt = await self._create_pr_audit_prompt()
        elif self.mode == "incremental":
            audit_prompt = await self._create_incremental_audit_prompt()
        else:
            audit_prompt = await self._create_full_audit_prompt()

        # Initialize results structure
        audit_results = {
            "ci_metadata": {
                "mode": self.mode,
                "repository": self.github_repository,
                "sha": self.github_sha,
                "ref": self.github_ref,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_time_seconds": 0,
            },
            "compliance_score": 0,
            "violations": [],
            "critical_violations": [],
            "high_violations": [],
            "medium_violations": [],
            "low_violations": [],
            "recommendations": [],
            "blocking_issues": [],
        }

        # Run analysis
        messages = []
        async for message in query(prompt=audit_prompt, options=options):
            messages.append(message)

        # Parse results
        audit_results.update(await self._parse_ci_audit_results(messages))
        if isinstance(audit_results, dict) and "ci_metadata" in audit_results:
            metadata = audit_results["ci_metadata"]
            if isinstance(metadata, dict):
                metadata["execution_time_seconds"] = time.time() - start_time

        # Generate CI-specific outputs
        await self._generate_ci_outputs(audit_results)

        exec_time = 0.0
        if isinstance(audit_results, dict) and "ci_metadata" in audit_results:
            metadata = audit_results["ci_metadata"]
            if isinstance(metadata, dict):
                exec_time = metadata.get("execution_time_seconds", 0.0)
        logger.info(f"CI audit completed in {exec_time:.2f} seconds")
        return audit_results

    async def _create_pr_audit_prompt(self) -> str:
        """Create audit prompt focused on pull request changes."""
        changed_files = await self.get_changed_files()

        return f"""
        Perform architectural audit focused on pull request changes:

        Changed files: {', '.join(changed_files) if changed_files else 'No relevant files changed'}

        Analysis Focus:
        1. New architectural violations introduced in these files
        2. Impact on existing ADR compliance
        3. Integration risks with unchanged parts of the codebase
        4. Security implications of the changes

        Prioritize violations that:
        - Break existing architectural decisions (CRITICAL)
        - Introduce security vulnerabilities (CRITICAL)
        - Create significant technical debt (HIGH)
        - Violate established coding patterns (MEDIUM)

        For each changed file:
        1. Read the file to understand the changes
        2. Check against relevant ADRs using Grep to find related patterns
        3. Assess architectural impact and compliance

        Return JSON format:
        {{
            "compliance_score": 85.5,
            "violations": [
                {{
                    "file_path": "path/to/file.py",
                    "line_number": 42,
                    "adr_id": "ADR-002",
                    "description": "Direct database access bypasses repository pattern",
                    "risk_level": "high",
                    "remediation_suggestion": "Use UserRepository.find_by_id() instead",
                    "confidence": 0.95,
                    "is_new_violation": true
                }}
            ],
            "blocking_issues": ["List of critical issues that should block merge"],
            "recommendations": ["Quick suggestions for improvement"]
        }}

        Provide fast, actionable feedback for developers.
        """

    async def _create_incremental_audit_prompt(self) -> str:
        """Create audit prompt for incremental analysis."""
        changed_files = await self.get_changed_files()

        return f"""
        Perform incremental architectural audit on recent changes:

        Changed files: {', '.join(changed_files) if changed_files else 'No relevant files changed'}

        Quick Analysis Focus:
        1. Critical architectural violations in changed files only
        2. Security implications of modifications
        3. ADR compliance for modified areas
        4. Integration risks

        Skip detailed analysis of unchanged files for speed.
        Focus on violations that require immediate attention.

        Return concise JSON with critical findings only.
        """

    async def _create_full_audit_prompt(self) -> str:
        """Create prompt for full codebase audit (CI schedule)."""
        return """
        Perform comprehensive CI architectural audit:

        Full Analysis Scope:
        1. All ADR compliance validation
        2. Architectural hotspot identification
        3. Security vulnerability assessment
        4. Technical debt quantification

        Use efficient analysis:
        1. Start with Glob to identify key files
        2. Use Grep for pattern-based preliminary screening
        3. Read detailed analysis for high-risk areas only
        4. Generate prioritized violation list

        Focus on actionable insights for development team planning.
        Return comprehensive JSON results.
        """

    async def _parse_ci_audit_results(self, messages: List[Any]) -> Dict[str, Any]:
        """Parse CI audit results from Claude Code responses."""
        results: Dict[str, Any] = {
            "compliance_score": 0,
            "violations": [],
            "blocking_issues": [],
            "recommendations": [],
        }

        for message in messages:
            content = self._extract_message_content(message)
            if content:
                try:
                    # Try to extract JSON from response
                    if "{" in content and "}" in content:
                        start_idx = content.find("{")
                        end_idx = content.rfind("}") + 1
                        json_str = content[start_idx:end_idx]
                        parsed_result = json.loads(json_str)

                        # Update results with parsed data
                        if "compliance_score" in parsed_result:
                            results["compliance_score"] = parsed_result["compliance_score"]

                        if "violations" in parsed_result:
                            results["violations"].extend(parsed_result["violations"])

                        if "blocking_issues" in parsed_result:
                            results["blocking_issues"].extend(parsed_result["blocking_issues"])

                        if "recommendations" in parsed_result:
                            results["recommendations"].extend(parsed_result["recommendations"])

                        break  # Use first valid JSON response

                except json.JSONDecodeError:
                    logger.warning("Could not parse CI audit response as JSON")
                    continue

        # Categorize violations by risk level
        for violation in results["violations"]:
            risk_level = violation.get("risk_level", "medium").lower()
            if risk_level == "critical":
                results.setdefault("critical_violations", []).append(violation)
            elif risk_level == "high":
                results.setdefault("high_violations", []).append(violation)
            elif risk_level == "medium":
                results.setdefault("medium_violations", []).append(violation)
            else:
                results.setdefault("low_violations", []).append(violation)

        return results

    async def _generate_ci_outputs(self, audit_results: Dict[str, Any]) -> None:
        """Generate CI-specific output formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate GitHub Actions summary
        github_summary = self._create_github_summary(audit_results)
        github_summary_file = self.ci_reports_dir / "github-summary.md"
        with open(github_summary_file, "w", encoding="utf-8") as f:
            f.write(github_summary)

        # Generate PR comment data
        pr_summary = self._create_pr_summary(audit_results)
        pr_summary_file = self.ci_reports_dir / "pr-summary.json"
        with open(pr_summary_file, "w", encoding="utf-8") as f:
            json.dump(pr_summary, f, indent=2)

        # Generate SARIF for GitHub Security tab
        sarif_output = self._create_sarif_output(audit_results)
        sarif_file = self.ci_reports_dir / "architectural-violations.sarif"
        with open(sarif_file, "w", encoding="utf-8") as f:
            json.dump(sarif_output, f, indent=2)

        # Generate CI results JSON
        ci_results_file = self.ci_reports_dir / f"ci_audit_{timestamp}.json"
        with open(ci_results_file, "w", encoding="utf-8") as f:
            json.dump(audit_results, f, indent=2)

        logger.info(f"CI outputs generated in {self.ci_reports_dir}")

    def _create_github_summary(self, audit_results: Dict[str, Any]) -> str:
        """Create GitHub Actions summary markdown."""
        compliance_score = audit_results.get("compliance_score", 0)
        critical_count = len(audit_results.get("critical_violations", []))
        high_count = len(audit_results.get("high_violations", []))
        medium_count = len(audit_results.get("medium_violations", []))

        status_emoji = "✅" if critical_count == 0 else "❌"

        return f"""# 🏗️ Architectural Audit Results {status_emoji}

## Overview
- **Compliance Score**: {compliance_score:.1f}%
- **Analysis Mode**: {audit_results['ci_metadata']['mode']}
- **Execution Time**: {audit_results['ci_metadata']['execution_time_seconds']:.2f}s

## Violation Summary
| Risk Level | Count |
|------------|-------|
| Critical   | {critical_count} |
| High       | {high_count} |
| Medium     | {medium_count} |
| Low        | {len(audit_results.get('low_violations', []))} |

## Status
{f"❌ **BLOCKING**: {critical_count} critical violations must be fixed before merging" if critical_count > 0 else "✅ **PASSING**: No critical architectural violations detected"}

## Top Issues
{self._format_top_violations(audit_results.get('violations', [])[:5])}

## Recommendations
{chr(10).join(f"- {rec}" for rec in audit_results.get('recommendations', [])[:3])}
"""

    def _format_top_violations(self, violations: List[Dict[str, Any]]) -> str:
        """Format top violations for markdown display."""
        if not violations:
            return "No violations detected."

        formatted = []
        for v in violations[:5]:
            formatted.append(
                f"- **{v.get('adr_id', 'Unknown')}**: {v.get('description', 'No description')} ({v.get('file_path', 'unknown')}:{v.get('line_number', '?')})"
            )

        return "\n".join(formatted)

    def _create_pr_summary(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create PR comment summary data."""
        return {
            "compliance_score": audit_results.get("compliance_score", 0),
            "critical_violations": audit_results.get("critical_violations", []),
            "high_violations": audit_results.get("high_violations", []),
            "medium_violations": audit_results.get("medium_violations", []),
            "blocking_issues": audit_results.get("blocking_issues", []),
            "top_issues": audit_results.get("violations", [])[:5],
            "recommendations": audit_results.get("recommendations", [])[:3],
            "execution_time": audit_results["ci_metadata"]["execution_time_seconds"],
        }

    def _create_sarif_output(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create SARIF format output for GitHub Security tab."""
        results = []

        for violation in audit_results.get("violations", []):
            results.append(
                {
                    "ruleId": violation.get("adr_id", "architectural-violation"),
                    "message": {"text": violation.get("description", "Architectural violation detected")},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": violation.get("file_path", "unknown")},
                                "region": {"startLine": violation.get("line_number", 1)},
                            }
                        }
                    ],
                    "level": self._sarif_level_from_risk(violation.get("risk_level", "medium")),
                    "properties": {
                        "confidence": violation.get("confidence", 1.0),
                        "remediation_suggestion": violation.get("remediation_suggestion", ""),
                    },
                }
            )

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Claude Code CI Architectural Auditor",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/anthropics/claude-code",
                            "rules": self._generate_sarif_rules(audit_results),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _generate_sarif_rules(self, audit_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from violations."""
        rules = {}

        for violation in audit_results.get("violations", []):
            adr_id = violation.get("adr_id", "architectural-violation")
            if adr_id not in rules:
                rules[adr_id] = {
                    "id": adr_id,
                    "name": f"Architectural Decision Record {adr_id}",
                    "shortDescription": {"text": f"Violation of {adr_id}"},
                    "fullDescription": {"text": f"Code violates architectural decision record {adr_id}"},
                    "defaultConfiguration": {
                        "level": self._sarif_level_from_risk(violation.get("risk_level", "medium"))
                    },
                }

        return list(rules.values())

    def _sarif_level_from_risk(self, risk_level: str) -> str:
        """Convert risk level to SARIF level."""
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        return mapping.get(risk_level.lower(), "warning")

    async def should_block_merge(self, audit_results: Dict[str, Any]) -> bool:
        """Determine if audit results should block merge."""
        critical_violations = len(audit_results.get("critical_violations", []))
        blocking_issues = len(audit_results.get("blocking_issues", []))

        return critical_violations > 0 or blocking_issues > 0


# CLI Interface for CI/CD
async def main() -> None:
    """Main CLI interface for CI/CD auditor."""
    import argparse

    parser = argparse.ArgumentParser(description="Claude Code CI/CD Architectural Auditor")
    parser.add_argument("--mode", choices=["full", "pull-request", "incremental"], default="full", help="Analysis mode")
    parser.add_argument(
        "--output-format", choices=["json", "github-actions", "sarif"], default="json", help="Output format"
    )
    parser.add_argument(
        "--fail-on-critical-violations", action="store_true", help="Exit with error code if critical violations found"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        auditor = ClaudeCodeCIAuditor(args.mode)
        results = await auditor.run_ci_audit()

        # Output results based on format
        if args.output_format == "json":
            print(json.dumps(results, indent=2))
        elif args.output_format == "github-actions":
            print(f"::notice title=Compliance Score::{results['compliance_score']:.1f}%")
            critical_count = len(results.get("critical_violations", []))
            if critical_count > 0:
                print(f"::error title=Critical Violations::{critical_count} critical violations found")
            else:
                print("::notice title=Status::No critical violations detected")

        # Exit with error code if critical violations and flag is set
        if args.fail_on_critical_violations:
            should_block = await auditor.should_block_merge(results)
            if should_block:
                print("Exiting with error code due to critical violations")
                exit(1)

        print(f"Analysis completed in {results['ci_metadata']['execution_time_seconds']:.2f} seconds")

    except Exception as e:
        logger.error(f"CI audit failed: {e}")
        if args.fail_on_critical_violations:
            exit(1)
        raise


if __name__ == "__main__":
    asyncio.run(main())
