"""
Git commit pattern matcher for architectural fix detection.

This module provides sophisticated pattern matching capabilities to identify
architectural fixes, ADR references, and implicit architectural improvements
in git commit messages and file changes.
"""

import logging
import re
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from re import Match, Pattern
from typing import Any, Dict, List, Optional, Tuple

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


@contextmanager
def regex_timeout(seconds: int = 1) -> Any:
    """Context manager to timeout regex operations."""
    import sys
    import threading

    # Only use signal-based timeout in main thread on Unix-like systems
    if sys.platform != "win32" and hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread():

        def timeout_handler(signum: int, frame: Any) -> None:
            raise TimeoutError("Regex operation timed out")

        # Set the signal handler
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)

        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # On Windows, non-main threads, or systems without SIGALRM,
        # just yield without timeout. This is a compromise for compatibility.
        # In production, consider using threading.Timer or asyncio for timeouts
        yield


logger = logging.getLogger(__name__)


class FixType(Enum):
    """Types of architectural fixes that can be detected."""

    EXPLICIT_ADR_FIX = "explicit_adr_fix"
    ARCHITECTURAL_FIX = "architectural_fix"
    BOUNDARY_FIX = "boundary_fix"
    DEPENDENCY_FIX = "dependency_fix"
    REFACTORING_FIX = "refactoring_fix"
    IMPLICIT_FIX = "implicit_fix"
    UNKNOWN = "unknown"


@dataclass
class PatternConfig:
    """Configuration for a pattern matcher."""

    pattern: str
    fix_type: FixType
    confidence_base: float
    description: str
    capture_groups: Optional[List[str]] = None


@dataclass
class FixMatch:
    """Represents a matched architectural fix pattern."""

    fix_type: FixType
    confidence: float
    matched_text: str
    adr_references: List[str]
    context: Dict[str, Any]
    pattern_name: str


class ArchitecturalFixPatternMatcher:
    """
    Advanced pattern matcher for detecting architectural fixes in commit messages.

    This class implements a sophisticated pattern matching system that can:
    - Detect explicit ADR references and fixes
    - Identify implicit architectural improvements
    - Score confidence based on pattern strength and context
    - Extract ADR references in multiple formats
    """

    # Core architectural fix patterns with confidence scores
    PATTERNS: List[PatternConfig] = [
        # Explicit ADR fixes (highest confidence)
        PatternConfig(
            pattern=r"(?:fix|fixes|fixed|resolve[ds]?|address(?:es)?|closes?)\s+(?:issue\s+)?(?:#)?ADR-?(\d+)",
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence_base=0.95,
            description="Explicit ADR fix reference",
            capture_groups=["adr_number"],
        ),
        PatternConfig(
            pattern=r"(?:implement(?:s|ed)?|add(?:s|ed)?)\s+(?:support\s+for\s+)?ADR-?(\d+)",
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence_base=0.9,
            description="ADR implementation",
            capture_groups=["adr_number"],
        ),
        PatternConfig(
            pattern=r"(?:implement(?:s|ed)?|add(?:s|ed)?)\s+.*?\s+(?:from\s+)?ADR-?(\d+)",
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence_base=0.85,
            description="ADR implementation with context",
            capture_groups=["adr_number"],
        ),
        PatternConfig(
            pattern=r"ADR-?(\d+)(?:\s*[-:]?\s*)(.{0,100}(?:fix|compliance|violation|update))",
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence_base=0.85,
            description="ADR reference with fix context",
            capture_groups=["adr_number", "context"],
        ),
        # Architectural fixes (high confidence)
        PatternConfig(
            pattern=r"(?:fix|resolve|address|correct)(?:es|ed)?\s+(?:an?\s+)?(?:architectural?|arch\.?|architecture)\s+(?:violation|issue|problem|bug)",
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence_base=0.9,
            description="Explicit architectural fix",
        ),
        PatternConfig(
            pattern=r"(?:resolved?|fix(?:ed)?|address(?:ed)?)\s+(?:an?\s+)?(?:architectural?|arch\.?|architecture)\s+(?:violation|issue|problem|bug)",
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence_base=0.9,
            description="Past tense architectural fix",
        ),
        PatternConfig(
            pattern=r"(?:architectural?|architecture|arch\.?)\s+(?:fix|improvement|compliance|update)",
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence_base=0.85,
            description="Architectural improvement",
        ),
        PatternConfig(
            pattern=r"(?:architectural?|architecture|arch\.?)\s+(?:violation|issue|problem|bug)\s+(?:fix(?:ed)?|resolved?|addressed?)",
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence_base=0.85,
            description="Architectural violation fixed (reverse order)",
        ),
        PatternConfig(
            pattern=r"(?:enforce|ensure|maintain)\s+(?:architectural?|arch\.?|architecture)\s+(?:compliance|standards?|patterns?)",
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence_base=0.8,
            description="Architectural compliance enforcement",
        ),
        # Boundary and layer fixes (medium-high confidence)
        PatternConfig(
            pattern=r"(?:fix|correct|resolve|address)(?:es|ed)?\s+(?:layer|boundary|module)\s+(?:violation|leak|issue|coupling)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.85,
            description="Layer/boundary violation fix",
        ),
        PatternConfig(
            pattern=r"(?:fix|correct|resolve|address)(?:es|ed)?\s+(?:architectural?\s+)?(?:boundary|layer)\s+leaks?",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.85,
            description="Architectural boundary leak fix",
        ),
        PatternConfig(
            pattern=r"(?:resolved?|fix(?:ed)?|address(?:ed)?)\s+(?:layer|boundary|module)\s+(?:violation|leak|issue|coupling)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.85,
            description="Past tense boundary fix",
        ),
        PatternConfig(
            pattern=r"(?:separate|decouple|isolate)\s+(?:concerns|layers?|modules?|boundaries)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.75,
            description="Separation of concerns",
        ),
        PatternConfig(
            pattern=r"(?:improve|enhance|strengthen)\s+(?:architectural?\s+)?(?:boundaries|layers?|separation)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.7,
            description="Boundary improvement",
        ),
        PatternConfig(
            pattern=r"(?:decouple|separate)\s+.*?\s+from\s+.*?\s*(?:layer|module|component)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.75,
            description="Decoupling components",
        ),
        PatternConfig(
            pattern=r"(?:remove|eliminate)\s+(?:cross-?)?(?:layer|boundary|module)\s+(?:dependency|dependencies|coupling)",
            fix_type=FixType.BOUNDARY_FIX,
            confidence_base=0.8,
            description="Cross-layer dependency removal",
        ),
        # Dependency fixes (medium confidence)
        PatternConfig(
            pattern=r"(?:fix|resolve|update)\s+(?:circular|cyclic)\s+(?:dependency|dependencies)",
            fix_type=FixType.DEPENDENCY_FIX,
            confidence_base=0.85,
            description="Circular dependency fix",
        ),
        PatternConfig(
            pattern=r"(?:resolved?|fixed?)\s+(?:circular|cyclic)\s+(?:dependency|dependencies)",
            fix_type=FixType.DEPENDENCY_FIX,
            confidence_base=0.85,
            description="Past tense circular dependency fix",
        ),
        PatternConfig(
            pattern=r"(?:reduce|minimize|remove)\s+(?:unnecessary|unwanted|bad)\s+(?:coupling|dependencies)",
            fix_type=FixType.DEPENDENCY_FIX,
            confidence_base=0.75,
            description="Coupling reduction",
        ),
        PatternConfig(
            pattern=r"dependency\s+(?:fix|update|cleanup|refactor)",
            fix_type=FixType.DEPENDENCY_FIX,
            confidence_base=0.7,
            description="General dependency fix",
        ),
        # Refactoring fixes (medium confidence)
        PatternConfig(
            pattern=r"refactor(?:ing|ed)?\s+(?:to\s+)?(?:improve|ensure|maintain)\s+(?:architectural?|design)\s+(?:integrity|quality|patterns?)",
            fix_type=FixType.REFACTORING_FIX,
            confidence_base=0.8,
            description="Architectural refactoring",
        ),
        PatternConfig(
            pattern=r"refactor(?:ing|ed)?\s+(?:for\s+)?(?:better|improved|proper)\s+(?:separation|modularity|encapsulation)",
            fix_type=FixType.REFACTORING_FIX,
            confidence_base=0.75,
            description="Modular refactoring",
        ),
        PatternConfig(
            pattern=r"refactor(?:ing|ed)?\s+to\s+(?:improve|ensure)\s+.*\s+(?:integrity|patterns?|separation)",
            fix_type=FixType.REFACTORING_FIX,
            confidence_base=0.75,
            description="Generic refactoring for improvement",
        ),
        PatternConfig(
            pattern=r"extract(?:ed)?\s+(?:to\s+)?(?:separate|new)\s+(?:module|layer|component|service)",
            fix_type=FixType.REFACTORING_FIX,
            confidence_base=0.7,
            description="Component extraction",
        ),
        PatternConfig(
            pattern=r"extract\s+\w+\s+to\s+(?:separate|new)\s+(?:module|layer|component|service)",
            fix_type=FixType.REFACTORING_FIX,
            confidence_base=0.7,
            description="Specific component extraction",
        ),
        # Implicit fixes (lower confidence)
        PatternConfig(
            pattern=r"(?:move|moved|relocate)\s+(?:to\s+)?(?:proper|correct|appropriate)\s+(?:layer|module|package)",
            fix_type=FixType.IMPLICIT_FIX,
            confidence_base=0.65,
            description="Code relocation",
        ),
        PatternConfig(
            pattern=r"(?:move|moved|relocate)\s+\w+\s+(?:logic|code|functionality)\s+to\s+(?:proper|correct|appropriate)\s+(?:layer|module|package)",
            fix_type=FixType.IMPLICIT_FIX,
            confidence_base=0.65,
            description="Specific code relocation",
        ),
        PatternConfig(
            pattern=r"(?:relocated?|moved?)\s+\w+\s+to\s+(?:proper|correct|appropriate)\s+(?:layer|module|package)",
            fix_type=FixType.IMPLICIT_FIX,
            confidence_base=0.65,
            description="Past tense relocation",
        ),
        PatternConfig(
            pattern=r"(?:clean|cleanup|clean\s+up)\s+(?:code\s+)?(?:structure|organization|architecture)",
            fix_type=FixType.IMPLICIT_FIX,
            confidence_base=0.6,
            description="Structural cleanup",
        ),
        PatternConfig(
            pattern=r"(?:improve|enhance)\s+(?:code\s+)?(?:structure|organization|modularity)",
            fix_type=FixType.IMPLICIT_FIX,
            confidence_base=0.55,
            description="Structural improvement",
        ),
    ]

    # ADR reference patterns
    ADR_REFERENCE_PATTERNS = [
        (r"\bADR-?(\d{1,6})\b", 1.0),  # ADR-001, ADR001 (word boundary)
        (r"#ADR-?(\d{1,6})\b", 0.95),  # #ADR-001, #ADR001
        (r"\badr[-_]?(\d{1,6})\b", 0.9),  # adr-001, adr_001, adr001
        (r"\bADR\s+(\d{1,6})\b", 0.85),  # ADR 001
        (
            r"(?:architecture|architectural)\s+decision\s+(?:record\s+)?#?(\d{1,6})",
            0.8,
        ),  # Full form
    ]

    def __init__(self, custom_patterns: Optional[List[PatternConfig]] = None):
        """
        Initialize the pattern matcher.

        Args:
            custom_patterns: Optional list of custom patterns to add
        """
        self.patterns = self.PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Compile patterns for efficiency
        self._compiled_patterns: Dict[str, Tuple[Pattern[str], PatternConfig]] = {}
        for config in self.patterns:
            try:
                with regex_timeout(1):
                    compiled = re.compile(config.pattern, re.IGNORECASE | re.MULTILINE)
                self._compiled_patterns[config.pattern] = (compiled, config)
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{config.pattern}': {e}")

        # Compile ADR reference patterns
        self._compiled_adr_patterns: List[Tuple[Pattern[str], float]] = []
        for pattern_str, confidence in self.ADR_REFERENCE_PATTERNS:
            try:
                with regex_timeout(1):
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                self._compiled_adr_patterns.append((compiled, confidence))
            except re.error as e:
                logger.warning(f"Failed to compile ADR pattern '{pattern_str}': {e}")

    def match_commit(self, commit_message: str, file_paths: Optional[List[str]] = None) -> List[FixMatch]:
        """
        Match architectural fix patterns in a commit.

        Args:
            commit_message: The commit message to analyze
            file_paths: Optional list of changed file paths for context

        Returns:
            List of FixMatch objects representing found patterns
        """
        matches = []

        # Clean the commit message but keep original for ADR extraction
        clean_message = self._preprocess_message(commit_message)

        # Match against all patterns
        for pattern_str, (compiled_pattern, config) in self._compiled_patterns.items():
            for match in compiled_pattern.finditer(clean_message):
                # Calculate confidence based on context
                confidence = self._calculate_confidence(config.confidence_base, match, clean_message, file_paths)

                # Extract ADR references from the matched portion of the original message
                # Find the corresponding position in the original message
                matched_text = match.group(0)
                adr_refs = self.extract_adr_references(matched_text)

                # Also check the entire original message for ADR references
                # This ensures we catch ADRs mentioned elsewhere in the commit
                all_message_adrs = self.extract_adr_references(commit_message)
                adr_refs = sorted(list(set(adr_refs + all_message_adrs)))

                # Build context
                context = self._build_match_context(match, config, file_paths)

                fix_match = FixMatch(
                    fix_type=config.fix_type,
                    confidence=confidence,
                    matched_text=matched_text,
                    adr_references=adr_refs,
                    context=context,
                    pattern_name=config.description,
                )

                matches.append(fix_match)

        # Deduplicate overlapping matches
        matches = self._deduplicate_matches(matches)

        # Sort by confidence
        matches.sort(key=lambda m: m.confidence, reverse=True)

        return matches

    def extract_adr_references(self, text: str) -> List[str]:
        """
        Extract all ADR references from text.

        Args:
            text: Text to search for ADR references

        Returns:
            List of normalized ADR references (e.g., ["ADR-001", "ADR-023"])
        """
        references = set()

        for pattern, _ in self._compiled_adr_patterns:
            for match in pattern.finditer(text):
                adr_number = match.group(1)
                # Normalize to ADR-XXX format
                # Keep original length if it's already 3 or more digits
                if len(adr_number) >= 3:
                    normalized = f"ADR-{adr_number}"
                else:
                    normalized = f"ADR-{adr_number.zfill(3)}"
                references.add(normalized)

        return sorted(list(references))

    def _preprocess_message(self, message: str) -> str:
        """Preprocess commit message for better matching."""
        # Keep the original message but normalize whitespace between words
        # Don't collapse newlines to spaces - keep multiline structure
        lines = message.split("\n")
        processed_lines = []
        for line in lines:
            # Normalize whitespace within each line
            line = re.sub(r"[ \t]+", " ", line.strip())
            # Remove common prefixes but keep the content
            line = re.sub(
                r"^(?:feat|fix|chore|docs|style|refactor|test|build)(?:\([^)]+\))?:\s*",
                "",
                line,
                flags=re.IGNORECASE,
            )
            if line:  # Only add non-empty lines
                processed_lines.append(line)
        return "\n".join(processed_lines)

    def _calculate_confidence(
        self,
        base_confidence: float,
        match: Match[str],
        full_message: str,
        file_paths: Optional[List[str]],
    ) -> float:
        """
        Calculate confidence score based on multiple factors.

        Factors considered:
        - Base pattern confidence
        - Position in message (title vs body)
        - Presence of architectural keywords
        - File paths indicating architectural changes
        """
        confidence = base_confidence

        # Boost if in commit title (first line)
        if match.start() < len(full_message.split("\n")[0]):
            confidence *= 1.1

        # Boost for additional architectural keywords
        arch_keywords = [
            "architecture",
            "design",
            "pattern",
            "structure",
            "layer",
            "module",
            "boundary",
        ]
        keyword_count = sum(1 for kw in arch_keywords if kw in full_message.lower())
        confidence *= 1 + (keyword_count * 0.05)

        # Boost based on file paths
        if file_paths:
            arch_paths = [
                "arch",
                "architecture",
                "design",
                "structure",
                "core",
                "base",
                "foundation",
            ]
            path_boost = sum(0.05 for path in file_paths for arch_path in arch_paths if arch_path in path.lower())
            confidence *= 1 + path_boost

        # Cap at 0.99
        return min(confidence, 0.99)

    def _build_match_context(
        self, match: Match[str], config: PatternConfig, file_paths: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Build context information for a match."""
        groups_dict: Dict[str, str] = {}
        context = {
            "start_pos": match.start(),
            "end_pos": match.end(),
            "pattern": config.pattern,
            "groups": groups_dict,
        }

        # Extract named groups if specified
        if config.capture_groups:
            for i, group_name in enumerate(config.capture_groups, 1):
                if i <= len(match.groups()):
                    groups_dict[group_name] = match.group(i)

        # Add file context
        if file_paths:
            context["affected_files"] = file_paths
            context["file_count"] = len(file_paths)

        return context

    def _deduplicate_matches(self, matches: List[FixMatch]) -> List[FixMatch]:
        """Remove overlapping matches, keeping the highest confidence ones."""
        if not matches:
            return []

        # Sort by start position
        sorted_matches = sorted(matches, key=lambda m: m.context["start_pos"])

        deduped: List[FixMatch] = []
        for match in sorted_matches:
            # Check if this match overlaps with any already selected
            overlaps = False
            for selected in deduped:
                if (
                    match.context["start_pos"] < selected.context["end_pos"]
                    and match.context["end_pos"] > selected.context["start_pos"]
                ):
                    # Overlaps - keep the one with higher confidence
                    if match.confidence > selected.confidence:
                        deduped.remove(selected)
                        deduped.append(match)
                    overlaps = True
                    break

            if not overlaps:
                deduped.append(match)

        return deduped
