#!/usr/bin/env python3
"""
Historical Code Analysis for Violation Hotspots.

This module implements a comprehensive Git history analysis tool to identify
architectural violation hotspots by analyzing the intersection of code churn
and complexity metrics.

Based on the principles outlined in ADRtool_HistoryAuditor.md, this tool:
1. Parses Git history to identify architectural fix commits
2. Matches commits to ADR violations using pattern matching
3. Calculates multi-factor risk scores combining frequency, recency, severity, and complexity
4. Generates actionable hotspot reports for audit prioritization

Author: ViolentUTF API Audit Team
License: MIT
"""

import argparse
import json
import logging
import os
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# Third-party dependencies
try:
    from lizard import analyze_file
    from pydriller import Commit, ModifiedFile, Repository
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install: pip install pydriller lizard")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ArchitecturalViolation:
    """Represents a single architectural violation instance."""

    def __init__(
        self, commit_hash: str, adr_id: str, timestamp: datetime, message: str, modified_files: List[str]
    ) -> None:
        """Initialize violation instance."""
        self.commit_hash = commit_hash
        self.adr_id = adr_id
        self.timestamp = timestamp
        self.message = message
        self.modified_files = modified_files

    def __repr__(self) -> str:
        """Return string representation of violation."""
        return f"ArchitecturalViolation({self.adr_id}, {self.commit_hash[:8]})"


class FileViolationStats:
    """Statistics for violations in a specific file."""

    def __init__(self, filepath: str) -> None:
        """Initialize file violation statistics."""
        self.filepath = filepath
        self.total_violations = 0
        self.violations_by_adr: Dict[str, int] = defaultdict(int)
        self.violation_instances: List[ArchitecturalViolation] = []
        self.first_violation: Optional[datetime] = None
        self.last_violation: Optional[datetime] = None
        self.complexity_score: Optional[float] = None
        self.risk_score: Optional[float] = None

    def add_violation(self, violation: ArchitecturalViolation) -> None:
        """Add a violation instance to this file's statistics."""
        self.total_violations += 1
        self.violations_by_adr[violation.adr_id] += 1
        self.violation_instances.append(violation)

        if self.first_violation is None or violation.timestamp < self.first_violation:
            self.first_violation = violation.timestamp

        if self.last_violation is None or violation.timestamp > self.last_violation:
            self.last_violation = violation.timestamp

    def calculate_risk_score(self, severity_weights: Dict[str, float], analysis_start_date: datetime) -> float:
        """Calculate multi-factor risk score for this file."""
        if self.total_violations == 0:
            return 0.0

        # Factor 1: Frequency (raw violation count)
        frequency = self.total_violations

        # Factor 2: Recency Weight (decay function for older violations)
        total_recency_weight = 0.0
        analysis_window_days = (datetime.now(timezone.utc) - analysis_start_date).days

        for violation in self.violation_instances:
            days_ago = (datetime.now(timezone.utc) - violation.timestamp).days
            # Linear decay: 1.0 for today, 0.1 for analysis window start
            recency_weight = max(0.1, 1.0 - (days_ago / analysis_window_days) * 0.9)
            total_recency_weight += recency_weight

        avg_recency_weight = total_recency_weight / len(self.violation_instances)

        # Factor 3: Severity Weight (average of all ADR severities for this file)
        total_severity = sum(
            severity_weights.get(adr_id, 1.0) * count for adr_id, count in self.violations_by_adr.items()
        )
        avg_severity_weight = total_severity / self.total_violations

        # Factor 4: Complexity Score (default to 1.0 if not available)
        complexity_score = self.complexity_score if self.complexity_score else 1.0

        # Apply the risk formula: (Frequency × RecencyWeight) × SeverityWeight × ComplexityScore
        risk_score = (frequency * avg_recency_weight) * avg_severity_weight * complexity_score

        return risk_score


class ConventionalCommitParser:
    """Parser for Conventional Commits format."""

    # Regex to parse Conventional Commit header: <type>(<scope>): <description>
    CONVENTIONAL_COMMIT_REGEX = re.compile(r"^(?P<type>\w+)(?:\((?P<scope>[^)]*)\))?:\s*(?P<description>.*)$")

    # Commit types that indicate architectural fixes
    FIX_COMMIT_TYPES = {"fix", "refactor", "chore", "perf", "revert"}

    @classmethod
    def parse_commit_message(cls, message: str) -> Optional[Dict[str, str]]:
        """
        Parse a conventional commit message.

        Returns:
            Dict with 'type', 'scope', 'description', and 'body' or None if not conventional
        """
        lines = message.strip().split("\n")
        if not lines:
            return None

        header = lines[0]
        body = "\n".join(lines[1:]).strip()

        match = cls.CONVENTIONAL_COMMIT_REGEX.match(header)
        if not match:
            return None

        result = match.groupdict()
        result["body"] = body

        return result

    @classmethod
    def is_architectural_fix(cls, commit_type: str) -> bool:
        """Check if commit type indicates an architectural fix."""
        return commit_type.lower() in cls.FIX_COMMIT_TYPES


class ADRPatternMatcher:
    """Matches commits to ADR violations using configured patterns."""

    def __init__(self, patterns_config: Dict[str, Any]) -> None:
        """Initialize pattern matcher with configuration."""
        self.patterns_config = patterns_config
        self.severity_weights = self._extract_severity_weights()

    def _extract_severity_weights(self) -> Dict[str, float]:
        """Extract severity weights from configuration."""
        weights = {}
        for adr in self.patterns_config.get("adrs", []):
            weights[adr["id"]] = adr.get("severity_weight", 1.0)
        return weights

    def find_violation_in_commit(self, commit_msg: str) -> Optional[str]:
        """
        Analyze a commit message to identify ADR violations.

        Returns:
            ADR ID if a violation pattern is matched, None otherwise
        """
        parsed = ConventionalCommitParser.parse_commit_message(commit_msg)
        if not parsed:
            # Try fallback pattern matching on the raw message
            return self._fallback_pattern_match(commit_msg)

        commit_type = parsed.get("type", "").lower()
        commit_scope = (parsed.get("scope") or "").lower()
        commit_body = parsed.get("body", "").lower()
        commit_description = parsed.get("description", "").lower()

        # Only analyze commits that indicate fixes or architectural changes
        if not ConventionalCommitParser.is_architectural_fix(commit_type):
            return None

        # Search through all ADR patterns
        for adr in self.patterns_config.get("adrs", []):
            patterns = adr.get("patterns", {})

            # High confidence: exact scope match
            expected_scope = patterns.get("conventional_commit_scope", "").lower()
            if expected_scope and commit_scope == expected_scope:
                return str(adr["id"])

            # Medium confidence: keyword match in body or description
            keywords = patterns.get("keywords", [])
            search_text = f"{commit_description} {commit_body}"

            for keyword in keywords:
                if keyword.lower() in search_text:
                    return str(adr["id"])

        return None

    def _fallback_pattern_match(self, commit_msg: str) -> Optional[str]:
        """Fallback pattern matching for non-conventional commits."""
        commit_lower = commit_msg.lower()

        for adr in self.patterns_config.get("adrs", []):
            keywords = adr.get("patterns", {}).get("keywords", [])
            for keyword in keywords:
                if keyword.lower() in commit_lower:
                    return str(adr["id"])

        return None


class ComplexityAnalyzer:
    """Analyzes code complexity using Lizard."""

    # File extensions to analyze
    SUPPORTED_EXTENSIONS = {".py", ".js", ".java", ".cpp", ".c", ".cs", ".php", ".rb", ".go"}

    @classmethod
    def analyze_file_complexity(cls, file_path: str) -> Optional[float]:
        """
        Analyze the complexity of a single file.

        Returns:
            Average cyclomatic complexity or None if analysis fails
        """
        if not os.path.exists(file_path):
            return None

        file_ext = Path(file_path).suffix.lower()
        if file_ext not in cls.SUPPORTED_EXTENSIONS:
            return None

        try:
            analysis = analyze_file(file_path)
            if not analysis.function_list:
                return 1.0  # Simple file with no functions

            # Calculate average cyclomatic complexity
            complexities = [func.cyclomatic_complexity for func in analysis.function_list]
            return float(statistics.mean(complexities))

        except Exception as e:
            logger.warning(f"Failed to analyze complexity for {file_path}: {e}")
            return None

    @classmethod
    def is_source_file(cls, file_path: str) -> bool:
        """Check if file is a source code file we can analyze."""
        if not file_path:
            return False

        file_ext = Path(file_path).suffix.lower()
        return file_ext in cls.SUPPORTED_EXTENSIONS


class HistoricalAnalyzer:
    """Main analyzer class orchestrating the historical analysis."""

    def __init__(self, repo_path: str, config_path: Optional[str] = None, analysis_window_days: int = 180) -> None:
        """Initialize historical analyzer."""
        self.repo_path = repo_path
        self.analysis_window_days = analysis_window_days
        self.analysis_start_date = datetime.now(timezone.utc) - timedelta(days=analysis_window_days)

        # Load configuration
        config_path = config_path or os.path.join(repo_path, "config", "violation_patterns.yml")
        self.config = self._load_config(config_path)

        # Initialize components
        self.pattern_matcher = ADRPatternMatcher(self.config)

        # Results storage
        self.file_stats: Dict[str, FileViolationStats] = {}
        self.all_violations: List[ArchitecturalViolation] = []
        self.processed_commits = 0
        self.violation_commits = 0

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load the violation patterns configuration."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                result = yaml.safe_load(f)
                return result if isinstance(result, dict) else {}
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML configuration: {e}")
            raise

    def analyze_repository(self) -> Dict[str, Any]:
        """
        Perform the complete historical analysis.

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting historical analysis of {self.repo_path}")
        logger.info(
            f"Analysis window: {self.analysis_window_days} days "
            f"(since {self.analysis_start_date.strftime('%Y-%m-%d')})"
        )

        # Phase 1: Parse git history and identify violations
        self._parse_git_history()

        # Phase 2: Analyze complexity for files with violations
        self._analyze_complexity()

        # Phase 3: Calculate risk scores
        self._calculate_risk_scores()

        # Generate analysis summary
        results = self._generate_analysis_summary()

        logger.info(
            f"Analysis complete. Processed {self.processed_commits} commits, "
            f"found {self.violation_commits} violation commits affecting "
            f"{len(self.file_stats)} files"
        )

        return results

    def _parse_git_history(self) -> None:
        """Parse git history to identify architectural violations."""
        logger.info("Parsing git commit history...")

        try:
            # Use PyDriller to traverse commits in the analysis window
            repo = Repository(
                self.repo_path,
                since=self.analysis_start_date,
                only_no_merge=True,  # Skip merge commits for cleaner signal
            )

            for commit in repo.traverse_commits():
                self.processed_commits += 1

                if self.processed_commits % 100 == 0:
                    logger.info(f"Processed {self.processed_commits} commits...")

                # Check if this commit represents an architectural violation fix
                violated_adr = self.pattern_matcher.find_violation_in_commit(commit.msg)
                if not violated_adr:
                    continue

                self.violation_commits += 1

                # Get the list of modified source files
                modified_source_files = [
                    mf.new_path or mf.old_path
                    for mf in commit.modified_files
                    if mf.new_path and ComplexityAnalyzer.is_source_file(mf.new_path)
                ]

                if not modified_source_files:
                    continue

                # Create violation record
                violation = ArchitecturalViolation(
                    commit_hash=commit.hash,
                    adr_id=violated_adr,
                    timestamp=commit.committer_date,
                    message=commit.msg,
                    modified_files=modified_source_files,
                )

                self.all_violations.append(violation)

                # Update file statistics
                for file_path in modified_source_files:
                    if file_path not in self.file_stats:
                        self.file_stats[file_path] = FileViolationStats(file_path)

                    self.file_stats[file_path].add_violation(violation)

        except Exception as e:
            logger.error(f"Error parsing git history: {e}")
            raise

    def _analyze_complexity(self) -> None:
        """Analyze complexity for all files with violations."""
        logger.info(f"Analyzing complexity for {len(self.file_stats)} files...")

        for file_path, stats in self.file_stats.items():
            full_path = os.path.join(self.repo_path, file_path)
            complexity = ComplexityAnalyzer.analyze_file_complexity(full_path)
            stats.complexity_score = complexity

        logger.info("Complexity analysis complete")

    def _calculate_risk_scores(self) -> None:
        """Calculate risk scores for all files."""
        logger.info("Calculating risk scores...")

        severity_weights = self.pattern_matcher.severity_weights

        for stats in self.file_stats.values():
            stats.risk_score = stats.calculate_risk_score(severity_weights, self.analysis_start_date)

    def _generate_analysis_summary(self) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        # Sort files by risk score
        sorted_files = sorted(self.file_stats.values(), key=lambda x: x.risk_score or 0, reverse=True)

        # ADR violation summary
        adr_violations: Dict[str, int] = defaultdict(int)
        for violation in self.all_violations:
            adr_violations[violation.adr_id] += 1

        return {
            "analysis_metadata": {
                "repository_path": self.repo_path,
                "analysis_date": datetime.now(timezone.utc).isoformat(),
                "analysis_window_days": self.analysis_window_days,
                "analysis_start_date": self.analysis_start_date.isoformat(),
                "total_commits_processed": self.processed_commits,
                "violation_commits_found": self.violation_commits,
                "files_with_violations": len(self.file_stats),
            },
            "hotspot_files": [
                {
                    "filepath": stats.filepath,
                    "risk_score": round(stats.risk_score or 0, 2),
                    "total_violations": stats.total_violations,
                    "complexity_score": round(stats.complexity_score or 0, 2),
                    "violations_by_adr": dict(stats.violations_by_adr),
                    "first_violation": stats.first_violation.isoformat() if stats.first_violation else None,
                    "last_violation": stats.last_violation.isoformat() if stats.last_violation else None,
                }
                for stats in sorted_files[:20]  # Top 20 high-risk files
            ],
            "adr_violation_summary": dict(adr_violations),
            "top_violated_adrs": sorted(adr_violations.items(), key=lambda x: x[1], reverse=True)[:10],
        }


class ReportGenerator:
    """Generates comprehensive Markdown reports from analysis results."""

    def __init__(self, analysis_results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Initialize report generator."""
        self.results = analysis_results
        self.config = config
        self.adr_metadata = self._build_adr_metadata()

    def _build_adr_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Build ADR metadata lookup."""
        metadata = {}
        for adr in self.config.get("adrs", []):
            metadata[adr["id"]] = {
                "name": adr.get("name", "Unknown"),
                "description": adr.get("description", ""),
                "severity_weight": adr.get("severity_weight", 1.0),
            }
        return metadata

    def generate_markdown_report(self) -> str:
        """Generate comprehensive Markdown report."""
        metadata = self.results["analysis_metadata"]

        report = f"""# Architectural Violation Hotspots Analysis Report

**Generated:** {datetime.fromisoformat(metadata['analysis_date']).strftime('%Y-%m-%d %H:%M:%S UTC')}
**Repository:** `{metadata['repository_path']}`
**Analysis Period:** {metadata['analysis_window_days']} days (since {datetime.fromisoformat(metadata['analysis_start_date']).strftime('%Y-%m-%d')})

## Executive Summary

This report analyzes Git commit history to identify architectural violation hotspots - code areas with frequent architectural violations that require focused audit attention.

### Key Findings

- **Total Commits Analyzed:** {metadata['total_commits_processed']:,}
- **Violation Commits Found:** {metadata['violation_commits_found']:,} ({(metadata['violation_commits_found']/metadata['total_commits_processed']*100):.1f}% of all commits)
- **Files with Violations:** {metadata['files_with_violations']:,}
- **Unique ADRs Violated:** {len(self.results['adr_violation_summary'])}

## Top 10 High-Risk Files

The following files represent the highest architectural risk based on a multi-factor risk score combining violation frequency, recency, severity, and code complexity:

| Rank | File Path | Risk Score | Violations | Complexity | Primary ADRs Violated |
|------|-----------|------------|------------|------------|----------------------|
"""

        # Add top 10 high-risk files
        for i, file_info in enumerate(self.results["hotspot_files"][:10], 1):
            primary_adrs = sorted(file_info["violations_by_adr"].items(), key=lambda x: x[1], reverse=True)[
                :3
            ]  # Top 3 ADRs for this file

            adr_list = ", ".join([f"{adr_id} ({count})" for adr_id, count in primary_adrs])

            report += f"| {i} | `{file_info['filepath']}` | {file_info['risk_score']} | {file_info['total_violations']} | {file_info['complexity_score']} | {adr_list} |\n"

        report += f"""
## Detailed File Analysis

### High-Risk Files (Risk Score > 5.0)

"""
        high_risk_files = [f for f in self.results["hotspot_files"] if f["risk_score"] > 5.0]

        if high_risk_files:
            for file_info in high_risk_files:
                report += f"""#### `{file_info['filepath']}`

- **Risk Score:** {file_info['risk_score']} (HIGH)
- **Total Violations:** {file_info['total_violations']}
- **Complexity Score:** {file_info['complexity_score']}
- **Violation Period:** {datetime.fromisoformat(file_info['first_violation']).strftime('%Y-%m-%d') if file_info['first_violation'] else 'N/A'} to {datetime.fromisoformat(file_info['last_violation']).strftime('%Y-%m-%d') if file_info['last_violation'] else 'N/A'}

**ADR Violations:**
"""
                for adr_id, count in sorted(file_info["violations_by_adr"].items(), key=lambda x: x[1], reverse=True):
                    adr_name = self.adr_metadata.get(adr_id, {}).get("name", "Unknown")
                    severity = self.adr_metadata.get(adr_id, {}).get("severity_weight", 1.0)
                    report += f"- **{adr_id}** ({adr_name}): {count} violations (severity: {severity})\n"

                report += "\n"
        else:
            report += "No files with risk score > 5.0 found.\n\n"

        report += f"""## ADR Violation Summary

The following table shows which architectural decisions are being violated most frequently:

| ADR ID | ADR Name | Violation Count | Severity Weight | Description |
|--------|----------|----------------|----------------|-------------|
"""

        for adr_id, count in self.results["top_violated_adrs"]:
            adr_info = self.adr_metadata.get(adr_id, {})
            name = adr_info.get("name", "Unknown")
            severity = adr_info.get("severity_weight", 1.0)
            description = adr_info.get("description", "")[:100] + (
                "..." if len(adr_info.get("description", "")) > 100 else ""
            )

            report += f"| {adr_id} | {name} | {count} | {severity} | {description} |\n"

        report += f"""
## Recommendations

### Immediate Actions (High Priority)

1. **Focus Audit Efforts:** Prioritize manual review of the top 5 high-risk files listed above
2. **Refactoring Targets:** Consider breaking down complex files (complexity > 10) with high violation counts
3. **Pattern Analysis:** Investigate why {self.results['top_violated_adrs'][0][0] if self.results['top_violated_adrs'] else 'certain ADRs'} are being violated most frequently

### Medium-Term Improvements

1. **Developer Training:** Focus on ADRs with highest violation counts
2. **Tooling Integration:** Implement pre-commit hooks to catch violations early
3. **Documentation Review:** Update ADR documentation for frequently violated principles

### Tracking Effectiveness

- **Baseline Established:** This report serves as the baseline for measuring improvement
- **Re-run Frequency:** Recommended monthly analysis to track trends
- **Success Metrics:** Target 20% reduction in high-risk files within 3 months

## Methodology

This analysis uses a multi-factor risk scoring model:

```
Risk Score = (Frequency × Recency Weight) × Severity Weight × Complexity Score
```

- **Frequency:** Total violation count in the analysis period
- **Recency Weight:** Decay factor giving more weight to recent violations (1.0 = today, 0.1 = {metadata['analysis_window_days']} days ago)
- **Severity Weight:** ADR-specific impact multiplier (configured in violation_patterns.yml)
- **Complexity Score:** Average cyclomatic complexity from static analysis

Files are considered "hotspots" when they have both high violation frequency AND high complexity, indicating they are both unstable and difficult to maintain.

---

*This report was generated by the ViolentUTF API Historical Analyzer*
*For questions or issues, please refer to the ADR Compliance Audit documentation*
"""

        return report

    def save_report(self, output_path: str) -> None:
        """Save the Markdown report to a file."""
        report_content = self.generate_markdown_report()

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Report saved to: {output_path}")


def main() -> None:
    """Run historical analyzer main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Git history for architectural violation hotspots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python historical_analyzer.py /path/to/repo
  python historical_analyzer.py /path/to/repo --config custom_patterns.yml --days 90
  python historical_analyzer.py /path/to/repo --output custom_report.md
        """,
    )

    parser.add_argument("repository_path", help="Path to the Git repository to analyze")

    parser.add_argument("--config", "-c", help="Path to violation patterns YAML configuration file")

    parser.add_argument("--days", "-d", type=int, default=180, help="Number of days to analyze (default: 180)")

    parser.add_argument(
        "--output",
        "-o",
        default="reports/hotspot_analysis.md",
        help="Output path for the analysis report (default: reports/hotspot_analysis.md)",
    )

    parser.add_argument("--json-output", help="Also save results as JSON to specified file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate repository path
    if not os.path.exists(args.repository_path):
        logger.error(f"Repository path does not exist: {args.repository_path}")
        sys.exit(1)

    if not os.path.exists(os.path.join(args.repository_path, ".git")):
        logger.error(f"Not a Git repository: {args.repository_path}")
        sys.exit(1)

    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        # Run the analysis
        analyzer = HistoricalAnalyzer(
            repo_path=args.repository_path, config_path=args.config, analysis_window_days=args.days
        )

        results = analyzer.analyze_repository()

        # Generate and save the report
        report_generator = ReportGenerator(results, analyzer.config)
        report_generator.save_report(args.output)

        # Save JSON output if requested
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"JSON results saved to: {args.json_output}")

        # Print summary
        print(f"\n✅ Analysis Complete!")
        print(f"📊 Processed {results['analysis_metadata']['total_commits_processed']:,} commits")
        print(f"🔍 Found {results['analysis_metadata']['violation_commits_found']:,} violation commits")
        print(f"📁 Analyzed {results['analysis_metadata']['files_with_violations']} files with violations")
        print(f"📋 Report saved to: {args.output}")

        # Show top 3 hotspots
        if results["hotspot_files"]:
            print(f"\n🔥 Top 3 Hotspots:")
            for i, file_info in enumerate(results["hotspot_files"][:3], 1):
                print(
                    f"  {i}. {file_info['filepath']} (Risk: {file_info['risk_score']}, "
                    f"Violations: {file_info['total_violations']})"
                )

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
