"""
Git history parser for identifying architectural fixes.

This module implements the git history parser described in issue #42,
which identifies commits related to architectural fixes by analyzing
commit messages and changed files.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import git

    HAS_GIT = True
except ImportError:
    HAS_GIT = False

from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher, FixMatch, FixType

logger = logging.getLogger(__name__)


@dataclass
class ArchitecturalFix:
    """Represents an architectural fix found in git history."""

    commit_hash: str
    commit_message: str
    author: str
    date: datetime
    files_changed: List[str]
    fix_type: FixType
    confidence: float
    adr_references: List[str]
    pattern_matched: str
    lines_added: int = 0
    lines_deleted: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
            "author": self.author,
            "date": self.date.isoformat(),
            "files_changed": self.files_changed,
            "fix_type": self.fix_type.value,
            "confidence": self.confidence,
            "adr_references": self.adr_references,
            "pattern_matched": self.pattern_matched,
            "lines_added": self.lines_added,
            "lines_deleted": self.lines_deleted,
        }


@dataclass
class FileChangePattern:
    """Represents a pattern of file changes."""

    files: Set[str]
    frequency: int
    commits: List[str]
    is_architectural: bool = False


class GitHistoryParser:
    """Parser for analyzing git repository history and extracting commit data."""

    def _validate_path_input(self, path: Union[str, Path]) -> Path:
        """Validate path input to prevent directory traversal."""
        path = Path(path).resolve()

        # Check if path is absolute and doesn't contain suspicious patterns
        suspicious_patterns = ["..", "~", "$", "`", ";", "|", "&", ">", "<"]
        path_str = str(path)

        for pattern in suspicious_patterns:
            if pattern in path_str:
                raise ValueError(f"Suspicious pattern '{pattern}' in path: {path_str}")

        # Ensure path exists and is a directory
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")

        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")

        return path

    def _sanitize_commit_message(self, message: str) -> str:
        """Sanitize commit message to prevent injection attacks."""
        # Remove null bytes
        message = message.replace("\x00", "")

        # Limit length to prevent DoS
        max_length = 10000
        if len(message) > max_length:
            message = message[:max_length] + "... (truncated)"

        return message

    """
    Parser for git repository history that identifies architectural fixes.

    This class implements the requirements from issue #42:
    - Uses GitPython library for repository analysis
    - Implements pattern matching for architectural fix keywords
    - Parses commit messages for ADR references
    - Tracks file change patterns
    """

    def __init__(self, repo_path: Path, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the git history parser.

        Args:
            repo_path: Path to the git repository
            config: Optional configuration dictionary
        """
        self.repo_path = self._validate_path_input(repo_path)
        self.config = config or {}
        self.pattern_matcher = ArchitecturalFixPatternMatcher()

        if not HAS_GIT:
            raise ImportError("GitPython is required. Install with: pip install gitpython")

        try:
            self.repo = git.Repo(repo_path)
            if self.repo.bare:
                raise ValueError("Cannot analyze bare repository")
        except (git.InvalidGitRepositoryError, git.NoSuchPathError) as e:
            raise ValueError(f"Invalid git repository at {repo_path}: {e}")

    def find_architectural_fixes(
        self,
        since_months: int = 6,
        adr_id: Optional[str] = None,
        branch: Optional[str] = None,
        max_commits: Optional[int] = None,
    ) -> List[ArchitecturalFix]:
        """
        Find commits that represent architectural fixes.

        Args:
            since_months: Number of months to look back
            adr_id: Optional specific ADR to filter for
            branch: Optional branch name (defaults to current branch)
            max_commits: Optional maximum number of commits to analyze

        Returns:
            List of ArchitecturalFix objects
        """
        fixes: List[ArchitecturalFix] = []
        since_date = datetime.now(timezone.utc) - timedelta(days=30 * since_months)

        # Get commits
        try:
            if branch:
                commits = list(self.repo.iter_commits(branch, since=since_date))
            else:
                commits = list(self.repo.iter_commits(since=since_date))

            if max_commits:
                commits = commits[:max_commits]

        except (git.GitCommandError, ValueError) as e:
            # ValueError can occur with empty repositories
            logger.warning(f"Error getting commits (possibly empty repository): {e}")
            return fixes

        # Analyze each commit
        for commit in commits:
            fix = self._analyze_commit(commit, adr_id)
            if fix:
                fixes.append(fix)

        # Sort by confidence and date
        fixes.sort(key=lambda f: (f.confidence, f.date), reverse=True)

        return fixes

    def _analyze_commit(self, commit: git.Commit, target_adr: Optional[str] = None) -> Optional[ArchitecturalFix]:
        """
        Analyze a single commit for architectural fixes.

        Args:
            commit: Git commit object
            target_adr: Optional ADR to filter for

        Returns:
            ArchitecturalFix if found, None otherwise
        """
        # Get changed files
        changed_files = []
        lines_added = 0
        lines_deleted = 0

        try:
            for file_path, stats in commit.stats.files.items():
                changed_files.append(file_path)
                lines_added += stats["insertions"]
                lines_deleted += stats["deletions"]
        except Exception as e:
            logger.warning(f"Error getting commit stats: {e}")
            return None

        # Use pattern matcher to analyze commit
        matches = self.pattern_matcher.match_commit(commit.message, changed_files)

        if not matches:
            return None

        # Filter by ADR if specified
        if target_adr:
            adr_matches = []
            for match in matches:
                if target_adr in match.adr_references:
                    adr_matches.append(match)

            # If no direct ADR match, don't include this commit
            if not adr_matches:
                return None
            else:
                matches = adr_matches

        # Get the best match
        best_match = max(matches, key=lambda m: m.confidence)

        # Extract all ADR references from all matches
        all_adr_refs = set()
        for match in matches:
            all_adr_refs.update(match.adr_references)

        return ArchitecturalFix(
            commit_hash=commit.hexsha,
            commit_message=commit.message.strip(),
            author=commit.author.name,
            date=commit.committed_datetime,
            files_changed=changed_files,
            fix_type=best_match.fix_type,
            confidence=best_match.confidence,
            adr_references=sorted(list(all_adr_refs)),
            pattern_matched=best_match.pattern_name,
            lines_added=lines_added,
            lines_deleted=lines_deleted,
        )

    def find_file_change_patterns(self, since_months: int = 6, min_frequency: int = 3) -> List[FileChangePattern]:
        """
        Find patterns of files that frequently change together.

        Args:
            since_months: Number of months to look back
            min_frequency: Minimum frequency to be considered a pattern

        Returns:
            List of FileChangePattern objects
        """
        patterns: Dict[frozenset[str], FileChangePattern] = {}
        since_date = datetime.now(timezone.utc) - timedelta(days=30 * since_months)

        try:
            commits = list(self.repo.iter_commits(since=since_date))
        except (git.GitCommandError, ValueError) as e:
            # ValueError can occur with empty repositories
            logger.warning(f"Error getting commits (possibly empty repository): {e}")
            return []

        # Analyze co-changes
        for commit in commits:
            try:
                changed_files = set(commit.stats.files.keys())

                # Only consider commits with 2-10 files (avoid large refactorings)
                if 2 <= len(changed_files) <= 10:
                    file_set = frozenset(changed_files)

                    if file_set in patterns:
                        patterns[file_set].frequency += 1
                        patterns[file_set].commits.append(commit.hexsha[:8])
                    else:
                        patterns[file_set] = FileChangePattern(
                            files=changed_files, frequency=1, commits=[commit.hexsha[:8]]
                        )

            except Exception as e:
                logger.warning(f"Error analyzing commit {commit.hexsha[:8]}: {e}")
                continue

        # Filter by frequency and check if architectural
        result = []
        for pattern in patterns.values():
            if pattern.frequency >= min_frequency:
                # Check if any of the files are architectural
                pattern.is_architectural = any(self._is_architectural_file(f) for f in pattern.files)
                result.append(pattern)

        # Sort by frequency
        result.sort(key=lambda p: p.frequency, reverse=True)

        return result

    def _is_architectural_file(self, file_path: str) -> bool:
        """Check if a file path indicates architectural significance."""
        arch_indicators = [
            "arch",
            "architecture",
            "design",
            "structure",
            "core",
            "base",
            "foundation",
            "framework",
            "boundary",
            "boundaries",
            "layer",
            "layers",
            "module",
            "component",
            "auth",  # Authentication is often architectural
            "security",  # Security is architectural
            "middleware",  # Middleware is architectural
        ]

        path_lower = file_path.lower()
        # Check each part of the path separately to avoid partial matches
        # For example, 'core' should match 'core/base.py' but not 'score.py'
        path_parts = path_lower.replace("/", " ").replace("\\", " ").replace("_", " ").replace("-", " ").split()

        for part in path_parts:
            if part in arch_indicators:
                return True

        # Also check if indicators appear as whole segments in the path
        for indicator in arch_indicators:
            # Check if indicator appears as a directory or file name
            if (
                f"/{indicator}/" in path_lower
                or path_lower.startswith(f"{indicator}/")
                or path_lower.endswith(f"/{indicator}")
            ):
                return True
            # Check with file extensions
            if path_lower.endswith(f"/{indicator}.py") or path_lower == f"{indicator}.py":
                return True

        return False

    def get_fix_statistics(self, fixes: List[ArchitecturalFix]) -> Dict[str, Any]:
        """
        Calculate statistics about architectural fixes.

        Args:
            fixes: List of architectural fixes

        Returns:
            Dictionary with statistics
        """
        if not fixes:
            return {
                "total_fixes": 0,
                "fix_types": {},
                "adr_references": {},
                "top_contributors": [],
                "average_confidence": 0.0,
                "date_range": None,
            }

        # Count by fix type
        fix_types: Dict[str, int] = {}
        for fix in fixes:
            fix_type = fix.fix_type.value
            fix_types[fix_type] = fix_types.get(fix_type, 0) + 1

        # Count by ADR
        adr_refs: Dict[str, int] = {}
        for fix in fixes:
            for adr in fix.adr_references:
                adr_refs[adr] = adr_refs.get(adr, 0) + 1

        # Count by author
        authors: Dict[str, int] = {}
        for fix in fixes:
            authors[fix.author] = authors.get(fix.author, 0) + 1

        # Top contributors
        top_contributors = sorted(authors.items(), key=lambda x: x[1], reverse=True)[:5]

        # Date range
        dates = [fix.date for fix in fixes]
        date_range = {"earliest": min(dates).isoformat(), "latest": max(dates).isoformat()}

        return {
            "total_fixes": len(fixes),
            "fix_types": fix_types,
            "adr_references": adr_refs,
            "top_contributors": [{"author": author, "fixes": count} for author, count in top_contributors],
            "average_confidence": sum(f.confidence for f in fixes) / len(fixes),
            "date_range": date_range,
            "total_lines_changed": sum(f.lines_added + f.lines_deleted for f in fixes),
        }

    def export_fixes_summary(self, fixes: List[ArchitecturalFix], output_format: str = "json") -> Optional[str]:
        """
        Export fixes summary in specified format.

        Args:
            fixes: List of architectural fixes
            output_format: Output format (json, csv, markdown)

        Returns:
            Formatted string or None if no fixes
        """
        if not fixes:
            return None

        if output_format == "json":
            import json

            data = {
                "fixes": [fix.to_dict() for fix in fixes],
                "statistics": self.get_fix_statistics(fixes),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            return json.dumps(data, indent=2)

        elif output_format == "csv":
            lines = ["commit_hash,date,author,fix_type,confidence,adr_references,files_changed"]
            for fix in fixes:
                adr_refs = ";".join(fix.adr_references)
                files = ";".join(fix.files_changed)
                lines.append(
                    f"{fix.commit_hash[:8]},{fix.date.isoformat()},{fix.author},"
                    f"{fix.fix_type.value},{fix.confidence:.2f},{adr_refs},{files}"
                )
            return "\n".join(lines)

        elif output_format == "markdown":
            lines = ["# Architectural Fixes Summary", ""]
            stats = self.get_fix_statistics(fixes)

            lines.append(f"**Total Fixes**: {stats['total_fixes']}")
            lines.append(f"**Date Range**: {stats['date_range']['earliest']} to {stats['date_range']['latest']}")
            lines.append(f"**Average Confidence**: {stats['average_confidence']:.2f}")
            lines.append("")

            lines.append("## Fix Types")
            for fix_type, count in stats["fix_types"].items():
                lines.append(f"- {fix_type}: {count}")
            lines.append("")

            lines.append("## Top Contributors")
            for contrib in stats["top_contributors"]:
                lines.append(f"- {contrib['author']}: {contrib['fixes']} fixes")
            lines.append("")

            lines.append("## Recent Fixes")
            for fix in fixes[:10]:
                lines.append(f"### {fix.commit_hash[:8]} - {fix.date.strftime('%Y-%m-%d')}")
                lines.append(f"**Author**: {fix.author}")
                lines.append(f"**Type**: {fix.fix_type.value} (confidence: {fix.confidence:.2f})")
                lines.append(f"**Message**: {fix.commit_message.split(chr(10))[0]}")
                if fix.adr_references:
                    lines.append(f"**ADRs**: {', '.join(fix.adr_references)}")
                lines.append("")

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported format: {output_format}")


# Resource limits configuration
MAX_COMMITS_PER_ANALYSIS = 1000
MAX_FILES_PER_COMMIT = 100
MAX_FILE_PATH_LENGTH = 500
MAX_PATTERN_MATCHES = 50
MAX_ADR_REFERENCES = 20
MAX_EXECUTION_TIME = 300  # 5 minutes


class ResourceLimiter:
    """Helper class to enforce resource limits."""

    def __init__(self) -> None:
        self.start_time = time.time()
        self.operation_count = 0

    def check_time_limit(self) -> None:
        """Check if execution time limit exceeded."""
        if time.time() - self.start_time > MAX_EXECUTION_TIME:
            raise TimeoutError(f"Execution time exceeded {MAX_EXECUTION_TIME} seconds")

    def check_operation_limit(self, limit: int) -> None:
        """Check if operation count exceeded."""
        self.operation_count += 1
        if self.operation_count > limit:
            raise ResourceWarning(f"Operation count exceeded {limit}")
