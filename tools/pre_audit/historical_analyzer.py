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
import fnmatch
import json
import logging
import math
import os
import re
import statistics
import sys
import time
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
        self,
        commit_hash: str,
        adr_id: str,
        timestamp: datetime,
        message: str,
        modified_files: List[str],
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
        """Calculate multi-factor risk score for this file with enhanced validation."""
        if self.total_violations == 0:
            return 0.0

        # Input validation
        if not isinstance(severity_weights, dict):
            logger.warning("Invalid severity_weights provided, using defaults")  # type: ignore[unreachable]
            severity_weights = {}

        # Ensure timezone consistency
        if analysis_start_date.tzinfo is None:
            analysis_start_date = analysis_start_date.replace(tzinfo=timezone.utc)

        # Factor 1: Frequency (raw violation count)
        frequency = self.total_violations

        # Factor 2: Recency Weight with robust edge case handling
        current_time = datetime.now(timezone.utc)
        analysis_window_days = max(1, (current_time - analysis_start_date).days)  # Prevent division by zero

        total_recency_weight = 0.0
        for violation in self.violation_instances:
            # Ensure timezone consistency
            violation_time = violation.timestamp
            if violation_time.tzinfo is None:
                violation_time = violation_time.replace(tzinfo=timezone.utc)

            days_ago = (current_time - violation_time).days
            days_ago = max(0, days_ago)  # Handle future dates gracefully

            # Linear decay with bounds checking
            if days_ago <= analysis_window_days:
                recency_weight = max(0.1, 1.0 - (days_ago / analysis_window_days) * 0.9)
            else:
                recency_weight = 0.1  # Minimum weight for very old violations

            total_recency_weight += recency_weight

        # Prevent division by zero
        avg_recency_weight = total_recency_weight / max(1, len(self.violation_instances))

        # Factor 3: Severity Weight with validation and missing ADR handling
        total_severity = 0.0
        missing_adrs: List[str] = []

        for adr_id, count in self.violations_by_adr.items():
            severity = severity_weights.get(adr_id, 1.0)
            if adr_id not in severity_weights:
                missing_adrs.append(adr_id)

            # Validate severity weight bounds (should be between 0.1 and 3.0)
            severity = max(0.1, min(3.0, severity))
            total_severity += severity * count

        # Log warning for missing ADRs
        if missing_adrs:
            logger.warning(f"Using default severity weight for ADRs: {missing_adrs}")

        avg_severity_weight = total_severity / self.total_violations

        # Factor 4: Complexity Score with bounds validation
        complexity_score = self.complexity_score if self.complexity_score else 1.0

        # Validate complexity bounds (reasonable range: 1.0 to 100.0)
        if complexity_score <= 0:
            logger.warning(f"Invalid complexity score {complexity_score}, using 1.0")
            complexity_score = 1.0
        elif complexity_score > 100:
            logger.warning(f"Extremely high complexity score {complexity_score}, capping at 100.0")
            complexity_score = 100.0

        # Apply the risk formula with normalization for very high scores
        base_risk = (frequency * avg_recency_weight) * avg_severity_weight * complexity_score

        # Apply logarithmic normalization for very high scores to prevent range explosion
        if base_risk > 100:
            risk_score = 100 + math.log10(base_risk / 100) * 20
        else:
            risk_score = base_risk

        return round(risk_score, 2)


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
    """Matches commits to ADR violations using configured patterns with advanced diff analysis."""

    def __init__(self, patterns_config: Dict[str, Any]) -> None:
        """Initialize pattern matcher with configuration."""
        self.patterns_config = patterns_config
        self.severity_weights = self._extract_severity_weights()
        self.file_pattern_cache: Dict[str, Set[str]] = {}
        self.diff_pattern_cache: Dict[str, Set[str]] = {}
        self._compile_patterns()

    def _extract_severity_weights(self) -> Dict[str, float]:
        """Extract severity weights from configuration."""
        weights = {}
        for adr in self.patterns_config.get("adrs", []):
            weights[adr["id"]] = adr.get("severity_weight", 1.0)
        return weights

    def _compile_patterns(self) -> None:
        """Pre-compile pattern matching for performance."""

        for adr in self.patterns_config.get("adrs", []):
            adr_id = adr["id"]
            patterns = adr.get("patterns", {})

            # Compile file patterns
            file_patterns = patterns.get("file_patterns", [])
            self.file_pattern_cache[adr_id] = set(file_patterns)

            # Compile diff patterns for advanced analysis
            diff_patterns = patterns.get("diff_patterns", [])
            self.diff_pattern_cache[adr_id] = set(diff_patterns)

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

    def find_violation_in_file_changes(self, commit: Commit, modified_files: List[str]) -> List[Tuple[str, str, float]]:
        """
        Advanced diff analysis to find ADR violations in file changes.

        Args:
            commit: PyDriller commit object
            modified_files: List of modified file paths

        Returns:
            List of tuples: (adr_id, file_path, confidence_score)
        """
        violations = []

        try:
            for modified_file in commit.modified_files:
                if not modified_file.filename:
                    continue

                file_path = modified_file.filename

                # Skip if file should be excluded
                if self._should_exclude_file_for_diff(file_path):
                    continue

                # Analyze file path patterns
                file_violations = self._analyze_file_path_patterns(file_path)
                violations.extend(file_violations)

                # Analyze diff content if available
                if modified_file.diff:
                    diff_violations = self._analyze_diff_patterns(file_path, modified_file.diff)
                    violations.extend(diff_violations)

                # Analyze source code content for deeper mapping
                if modified_file.source_code_after:
                    code_violations = self._analyze_code_content(file_path, modified_file.source_code_after)
                    violations.extend(code_violations)

        except Exception as e:
            logger.warning(f"Error analyzing file changes in commit: {e}")

        return violations

    def _analyze_file_path_patterns(self, file_path: str) -> List[Tuple[str, str, float]]:
        """Analyze file path against ADR file patterns."""
        violations = []

        for adr_id, file_patterns in self.file_pattern_cache.items():
            for pattern in file_patterns:
                if self._matches_glob_pattern(file_path, pattern):
                    confidence = 0.7  # High confidence for file pattern match
                    violations.append((adr_id, file_path, confidence))
                    break  # Only count once per ADR

        return violations

    def _analyze_diff_patterns(self, file_path: str, diff_content: str) -> List[Tuple[str, str, float]]:
        """Analyze diff content against ADR diff patterns."""
        violations = []
        diff_lower = diff_content.lower()

        for adr_id, diff_patterns in self.diff_pattern_cache.items():
            for pattern in diff_patterns:
                if pattern.lower() in diff_lower:
                    confidence = 0.8  # High confidence for diff pattern match
                    violations.append((adr_id, file_path, confidence))
                    break  # Only count once per ADR

        return violations

    def _analyze_code_content(self, file_path: str, source_code: str) -> List[Tuple[str, str, float]]:
        """Analyze source code content for ADR-specific patterns."""
        violations = []
        code_lower = source_code.lower()

        # Enhanced code analysis based on ADR patterns
        for adr in self.patterns_config.get("adrs", []):
            adr_id = str(adr["id"])

            # Check for advanced code patterns based on ADR type
            violation_confidence = self._calculate_code_violation_confidence(adr_id, code_lower, file_path)

            if violation_confidence > 0.5:  # Only report medium+ confidence violations
                violations.append((adr_id, file_path, violation_confidence))

        return violations

    def _calculate_code_violation_confidence(self, adr_id: str, code_content: str, file_path: str) -> float:
        """Calculate confidence score for code-based ADR violations."""
        confidence = 0.0

        # ADR-002 Authentication Strategy patterns
        if adr_id == "ADR-002":
            auth_indicators = [
                ("jwt", 0.3),
                ("token", 0.2),
                ("auth", 0.2),
                ("login", 0.2),
                ("rs256", 0.4),
                ("algorithm", 0.3),
                ("secret", 0.3),
                ("bearer", 0.3),
                ("authorization", 0.3),
            ]
            for pattern, weight in auth_indicators:
                if pattern in code_content:
                    confidence += weight

        # ADR-005 Rate Limiting patterns
        elif adr_id == "ADR-005":
            rate_limit_indicators = [
                ("rate", 0.3),
                ("limit", 0.3),
                ("throttle", 0.4),
                ("bucket", 0.4),
                ("redis", 0.3),
                ("429", 0.5),
                ("too many requests", 0.5),
                ("x-ratelimit", 0.5),
                ("organization_id", 0.3),
            ]
            for pattern, weight in rate_limit_indicators:
                if pattern in code_content:
                    confidence += weight

        # ADR-008 Logging patterns
        elif adr_id == "ADR-008":
            logging_indicators = [
                ("structlog", 0.5),
                ("json", 0.2),
                ("correlation_id", 0.4),
                ("organization_id", 0.3),
                ("user_id", 0.3),
                ("redact", 0.4),
                ("logger", 0.2),
                ("log", 0.1),
                ("audit", 0.3),
            ]
            for pattern, weight in logging_indicators:
                if pattern in code_content:
                    confidence += weight

        # Boost confidence for files in relevant directories
        if "/auth" in file_path and adr_id == "ADR-002":
            confidence += 0.2
        elif "/middleware" in file_path and adr_id in ["ADR-005", "ADR-008"]:
            confidence += 0.2
        elif "/logging" in file_path and adr_id == "ADR-008":
            confidence += 0.3

        return min(confidence, 1.0)  # Cap at 1.0

    def _matches_glob_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches glob pattern."""

        try:
            return fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(file_path.lower(), pattern.lower())
        except Exception:
            return False

    def _should_exclude_file_for_diff(self, file_path: str) -> bool:
        """Check if file should be excluded from diff analysis."""

        exclude_patterns = [
            "test*",
            "*_test.py",
            "tests/*",
            "*.md",
            "docs/*",
            "*.txt",
            "*.json",
            "*.yml",
            "*.yaml",
            "*.xml",
            "*.csv",
        ]

        for pattern in exclude_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False

    def analyze_code_to_adr_mapping(self, file_path: str, content: str) -> Dict[str, float]:
        """
        Deep analysis to map code content to specific ADRs.

        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze

        Returns:
            Dictionary mapping ADR IDs to confidence scores
        """
        mappings = {}
        content_lower = content.lower()

        # Enhanced mapping based on comprehensive ADR analysis
        adr_mappings = {
            "ADR-002": {
                "keywords": [
                    "jwt",
                    "token",
                    "auth",
                    "login",
                    "rs256",
                    "algorithm",
                    "secret",
                    "bearer",
                ],
                "functions": [
                    "encode_jwt",
                    "decode_jwt",
                    "verify_token",
                    "authenticate",
                    "login",
                ],
                "imports": ["jwt", "jose", "pyjwt", "authentication"],
                "file_indicators": ["/auth", "/middleware/auth", "/jwt", "/token"],
            },
            "ADR-005": {
                "keywords": [
                    "rate",
                    "limit",
                    "throttle",
                    "bucket",
                    "redis",
                    "429",
                    "x-ratelimit",
                ],
                "functions": ["rate_limit", "throttle", "check_rate", "limit_requests"],
                "imports": ["redis", "rate_limit", "throttle"],
                "file_indicators": [
                    "/rate",
                    "/throttle",
                    "/middleware/rate",
                    "/limiting",
                ],
            },
            "ADR-008": {
                "keywords": [
                    "structlog",
                    "correlation_id",
                    "organization_id",
                    "audit",
                    "redact",
                ],
                "functions": [
                    "log_",
                    "audit_",
                    "redact_",
                    "get_logger",
                    "setup_logging",
                ],
                "imports": ["structlog", "logging", "audit"],
                "file_indicators": ["/logging", "/audit", "/middleware/log"],
            },
        }

        for adr_id, patterns in adr_mappings.items():
            confidence = 0.0

            # Keyword matching
            for keyword in patterns["keywords"]:
                if keyword in content_lower:
                    confidence += 0.1

            # Function name matching
            for func_name in patterns["functions"]:
                if f"def {func_name}" in content_lower or f"function {func_name}" in content_lower:
                    confidence += 0.3

            # Import statement matching
            for import_name in patterns["imports"]:
                if f"import {import_name}" in content_lower or f"from {import_name}" in content_lower:
                    confidence += 0.2

            # File path matching
            for indicator in patterns["file_indicators"]:
                if indicator in file_path.lower():
                    confidence += 0.3

            if confidence > 0.3:  # Only include medium+ confidence mappings
                mappings[adr_id] = min(confidence, 1.0)

        return mappings


class ComplexityAnalyzer:
    """Analyzes code complexity using Lizard with caching."""

    # File extensions to analyze
    SUPPORTED_EXTENSIONS = {
        ".py",
        ".js",
        ".java",
        ".cpp",
        ".c",
        ".cs",
        ".php",
        ".rb",
        ".go",
    }

    # Cache for complexity results to avoid duplicate analysis
    _complexity_cache: Dict[str, Optional[float]] = {}

    @classmethod
    def analyze_file_complexity(cls, file_path: str) -> Optional[float]:
        """
        Analyze the complexity of a single file with caching and security validation.

        Returns:
            Average cyclomatic complexity or None if analysis fails
        """
        # Validate file path first for security
        if not cls._is_safe_file_path(file_path):
            logger.warning("Refusing to analyze potentially unsafe file path")
            return None

        # Check cache first
        if file_path in cls._complexity_cache:
            return cls._complexity_cache[file_path]

        if not os.path.exists(file_path):
            cls._complexity_cache[file_path] = None
            return None

        file_ext = Path(file_path).suffix.lower()
        if file_ext not in cls.SUPPORTED_EXTENSIONS:
            cls._complexity_cache[file_path] = None
            return None

        try:
            # Additional security: Check file size before analysis
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"File too large for analysis: {file_path}")
                cls._complexity_cache[file_path] = None
                return None

            analysis = analyze_file(file_path)
            if not analysis.function_list:
                result = 1.0  # Simple file with no functions
            else:
                # Calculate average cyclomatic complexity
                complexities = [func.cyclomatic_complexity for func in analysis.function_list]
                if not complexities:  # Safety check
                    result = 1.0
                else:
                    result = float(statistics.mean(complexities))

            cls._complexity_cache[file_path] = result
            return result

        except Exception:
            logger.warning("Failed to analyze file complexity")
            cls._complexity_cache[file_path] = None
            return None

    @classmethod
    def _is_safe_file_path(cls, file_path: str) -> bool:
        """Validate file path for security."""
        if not file_path or len(file_path) > 1000:
            return False

        # Check for path traversal
        if ".." in file_path or file_path.startswith("/"):
            return False

        # Normalize and validate
        try:
            normalized = os.path.normpath(file_path)
            if normalized.startswith(".."):
                return False
        except (ValueError, OSError):
            return False

        return True

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the complexity cache to prevent memory leaks."""
        cls._complexity_cache.clear()

    @classmethod
    def is_source_file(cls, file_path: str) -> bool:
        """Check if file is a source code file we can analyze."""
        if not file_path:
            return False

        file_ext = Path(file_path).suffix.lower()
        return file_ext in cls.SUPPORTED_EXTENSIONS


class HistoricalAnalyzer:
    """Main analyzer class orchestrating the historical analysis."""

    def __init__(
        self,
        repo_path: str,
        config_path: Optional[str] = None,
        analysis_window_days: int = 180,
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Initialize historical analyzer."""
        self.repo_path = repo_path
        self.analysis_window_days = analysis_window_days
        self.analysis_start_date = datetime.now(timezone.utc) - timedelta(days=analysis_window_days)
        self.exclude_patterns = exclude_patterns or [
            "test*",
            "*_test.py",
            "tests/*",
            "*.md",
            "docs/*",
        ]

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
        self.analysis_start_time = time.time()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load the violation patterns configuration with validation."""
        # Validate config path is within expected bounds
        config_path = os.path.abspath(config_path)
        if not config_path.endswith((".yml", ".yaml")):
            raise ValueError("Configuration file must be a YAML file")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                result = yaml.safe_load(f)

            # Validate loaded configuration structure
            if not isinstance(result, dict):
                logger.warning("Configuration is not a dictionary, using empty config")
                return {}

            # Validate required structure
            if "adrs" not in result:
                logger.warning("Configuration missing 'adrs' section, using empty config")
                return {}

            if not isinstance(result["adrs"], list):
                logger.warning("Configuration 'adrs' section is not a list, using empty config")
                return {}

            # Validate each ADR entry
            validated_adrs: List[Dict[str, Any]] = []
            for adr in result["adrs"]:
                if not isinstance(adr, dict):
                    continue
                if "id" not in adr or "name" not in adr:
                    continue
                # Sanitize string fields
                adr["id"] = str(adr["id"])[:50]  # Limit ID length
                adr["name"] = str(adr["name"])[:100]  # Limit name length
                validated_adrs.append(adr)

            result["adrs"] = validated_adrs
            return result

        except FileNotFoundError:
            logger.error("Configuration file not found")
            raise
        except yaml.YAMLError:
            logger.error("Invalid YAML configuration")
            raise
        except Exception as e:
            logger.error("Failed to load configuration")
            raise ValueError("Configuration loading failed") from e

    def _should_exclude_file(self, file_path: str) -> bool:
        """Check if file should be excluded from analysis with security validation."""

        # Security: Validate file path doesn't contain path traversal
        if not self._is_safe_path(file_path):
            logger.warning(f"Excluding potentially unsafe path: {file_path[:50]}...")
            return True

        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                return True
        return False

    def _is_safe_path(self, file_path: str) -> bool:
        """Validate that file path is safe and within repository bounds."""
        if not file_path:
            return False

        # Check for path traversal attempts
        if ".." in file_path or file_path.startswith("/"):
            return False

        # Normalize path and check it's within repo
        try:
            normalized_path = os.path.normpath(file_path)
            if normalized_path.startswith(".."):
                return False

            # Check against repo path if available
            if hasattr(self, "repo_path"):
                full_path = os.path.join(self.repo_path, normalized_path)
                repo_abs = os.path.abspath(self.repo_path)
                file_abs = os.path.abspath(full_path)
                if not file_abs.startswith(repo_abs):
                    return False

        except (ValueError, OSError):
            return False

        return len(file_path) < 1000  # Reasonable path length limit

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

        # Add performance metrics with safety checks
        analysis_duration = max(0.001, time.time() - self.analysis_start_time)  # Prevent division by zero
        results["analysis_metadata"]["analysis_duration_seconds"] = round(analysis_duration, 2)
        results["analysis_metadata"]["commits_per_second"] = round(self.processed_commits / analysis_duration, 2)

        # Clean up cache to prevent memory leaks
        ComplexityAnalyzer.clear_cache()

        logger.info(
            f"Analysis complete. Processed {self.processed_commits} commits, "
            f"found {self.violation_commits} violation commits affecting "
            f"{len(self.file_stats)} files in {analysis_duration:.2f}s"
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

                # Get the list of modified source files with security filtering
                modified_source_files = []
                for mf in commit.modified_files:
                    file_path = mf.new_path or mf.old_path
                    if (
                        file_path
                        and self._is_safe_path(file_path)
                        and ComplexityAnalyzer.is_source_file(file_path)
                        and not self._should_exclude_file(file_path)
                    ):
                        modified_source_files.append(file_path)

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
                    "first_violation": (stats.first_violation.isoformat() if stats.first_violation else None),
                    "last_violation": (stats.last_violation.isoformat() if stats.last_violation else None),
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
                for adr_id, count in sorted(
                    file_info["violations_by_adr"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
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
        """Save the Markdown report to a file with enhanced naming."""
        report_content = self.generate_markdown_report()

        # Generate descriptive report name with ADRaudit_ prefix
        enhanced_path = self._generate_enhanced_report_path(output_path)

        with open(enhanced_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Report saved to: {enhanced_path}")

    def _generate_enhanced_report_path(self, original_path: str) -> str:
        """Generate enhanced report path with descriptive ADRaudit_ prefix."""
        try:
            # Parse the original path
            path_obj = Path(original_path)
            directory = path_obj.parent
            extension = path_obj.suffix

            # Generate descriptive name based on analysis results
            metadata = self.results.get("analysis_metadata", {})

            # Create descriptive components
            timestamp = datetime.now().strftime("%Y%m%d")
            total_violations = metadata.get("violation_commits_found", 0)
            total_files = metadata.get("files_with_violations", 0)

            # Get top violated ADR for context
            top_adr = "General"
            if self.results.get("top_violated_adrs"):
                top_adr_id = self.results["top_violated_adrs"][0][0]
                top_adr = top_adr_id.replace("ADR-", "").replace("-", "")

            # Create descriptive report name
            descriptive_name = f"ADRaudit_{top_adr}Violations_{total_violations}commits_{total_files}files_{timestamp}"

            # Ensure the directory exists (reports folder)
            reports_dir = directory / "reports" if directory.name != "reports" else directory
            reports_dir.mkdir(exist_ok=True)

            # Generate final path
            enhanced_path = reports_dir / f"{descriptive_name}{extension}"

            return str(enhanced_path)

        except Exception as e:
            logger.warning(f"Failed to generate enhanced report name, using original: {e}")
            return original_path


def _validate_repository_path(repo_path: str) -> bool:
    """Validate repository path for security and existence."""
    if not repo_path or len(repo_path) > 500:
        return False

    try:
        # Normalize path and check for traversal
        abs_path = os.path.abspath(repo_path)
        if ".." in repo_path or not os.path.exists(abs_path):
            return False

        # Verify it's actually a git repository
        git_dir = os.path.join(abs_path, ".git")
        if not os.path.isdir(git_dir):
            return False

        # Check for basic git repository structure
        required_git_items = ["config", "HEAD", "objects", "refs"]
        for item in required_git_items:
            if not os.path.exists(os.path.join(git_dir, item)):
                return False

        return True

    except (OSError, ValueError):
        return False


def _validate_output_path(output_path: str) -> bool:
    """Validate output path for security."""
    if not output_path or len(output_path) > 500:
        return False

    try:
        # Normalize and validate path
        abs_path = os.path.abspath(output_path)

        # Check for path traversal
        if ".." in output_path:
            return False

        # Check file extension is safe
        allowed_extensions = {".md", ".txt", ".json", ".csv"}
        _, ext = os.path.splitext(output_path)
        if ext.lower() not in allowed_extensions:
            return False

        # Check parent directory exists or can be created
        parent_dir = os.path.dirname(abs_path)
        if not os.path.exists(parent_dir):
            # Check if we can create it (parent must exist)
            grandparent = os.path.dirname(parent_dir)
            if not os.path.exists(grandparent):
                return False

        return True

    except (OSError, ValueError):
        return False


def _validate_config_path(config_path: str) -> bool:
    """Validate configuration file path."""
    if not config_path or len(config_path) > 500:
        return False

    try:
        abs_path = os.path.abspath(config_path)

        # Check for path traversal
        if ".." in config_path:
            return False

        # Must exist and be readable
        if not os.path.isfile(abs_path) or not os.access(abs_path, os.R_OK):
            return False

        # Check file extension
        _, ext = os.path.splitext(config_path)
        if ext.lower() not in {".yml", ".yaml"}:
            return False

        return True

    except (OSError, ValueError):
        return False


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

    parser.add_argument(
        "--days",
        "-d",
        type=int,
        default=180,
        help="Number of days to analyze (default: 180)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="docs/reports/ADRaudit-claudecode/hotspot_analysis.md",
        help="Output path for the analysis report (default: docs/reports/ADRaudit-claudecode/hotspot_analysis.md)",
    )

    parser.add_argument("--json-output", help="Also save results as JSON to specified file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument(
        "--exclude",
        "-e",
        action="append",
        help="File patterns to exclude from analysis (can be used multiple times)",
    )

    parser.add_argument(
        "--min-risk",
        "-r",
        type=float,
        default=0.0,
        help="Minimum risk score threshold for reporting (default: 0.0)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Enhanced security validation for all inputs
    if not _validate_repository_path(args.repository_path):
        logger.error("Invalid repository path")
        sys.exit(1)

    if not _validate_output_path(args.output):
        logger.error("Invalid output path")
        sys.exit(1)

    if args.json_output and not _validate_output_path(args.json_output):
        logger.error("Invalid JSON output path")
        sys.exit(1)

    if args.config and not _validate_config_path(args.config):
        logger.error("Invalid config path")
        sys.exit(1)

    # Validate numeric parameters
    if args.days <= 0 or args.days > 3650:  # Max 10 years
        logger.error("Analysis window must be between 1 and 3650 days")
        sys.exit(1)

    # Create output directory securely
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, mode=0o755, exist_ok=True)
        except OSError:
            logger.error("Failed to create output directory")
            sys.exit(1)

    try:
        # Run the analysis
        analyzer = HistoricalAnalyzer(
            repo_path=args.repository_path,
            config_path=args.config,
            analysis_window_days=args.days,
            exclude_patterns=args.exclude,
        )

        results = analyzer.analyze_repository()

        # Generate and save the report
        report_generator = ReportGenerator(results, analyzer.config)
        report_generator.save_report(args.output)

        # Save JSON output if requested with secure file handling
        if args.json_output:
            try:
                with open(args.json_output, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, default=str, ensure_ascii=True)
                # Set secure file permissions
                os.chmod(args.json_output, 0o644)
                logger.info("JSON results saved successfully")
            except (OSError, IOError, json.JSONDecodeError):
                logger.error("Failed to save JSON output")
                # Continue execution, don't fail completely

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
