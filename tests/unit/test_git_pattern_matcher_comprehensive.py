"""
Comprehensive test suite for git pattern matcher.
Tests for robustness, security, and edge cases.
"""

import re
import time
from typing import List
from unittest.mock import Mock, patch

import pytest

from tools.pre_audit.git_pattern_matcher import (
    ArchitecturalFixPatternMatcher,
    FixMatch,
    FixType,
    PatternConfig,
)


class TestPatternMatcherSecurity:
    """Security-focused tests for pattern matcher."""

    @pytest.fixture
    def matcher(self):
        return ArchitecturalFixPatternMatcher()

    def test_redos_protection(self, matcher):
        """Test protection against ReDoS attacks."""
        # Create a malicious commit message that could cause ReDoS
        malicious_messages = [
            "a" * 10000 + "fix ADR-001" + "a" * 10000,  # Very long message
            "fix " + "a" * 1000 + " architectural " + "b" * 1000 + " violation",  # Nested repetition
            "refactor" + ("ing" * 1000) + " to improve architecture",  # Repeated groups
            "fix\n" * 1000 + "ADR-001",  # Many newlines
        ]

        for message in malicious_messages:
            start_time = time.time()
            matches = matcher.match_commit(message)
            elapsed_time = time.time() - start_time

            # Pattern matching should complete quickly even with malicious input
            assert elapsed_time < 1.0, f"Pattern matching took too long: {elapsed_time}s"

    def test_special_characters_handling(self, matcher):
        """Test handling of special regex characters in commit messages."""
        special_messages = [
            "Fix ADR-001: Handle $(rm -rf /) in patterns",  # Command injection attempt
            "Fix ADR-002: Process \\x00\\x01\\x02 bytes",  # Null bytes
            "Fix ADR-003: Support [a-z]* regex patterns",  # Regex metacharacters
            "Fix ADR-004: Handle ${HOME} variables",  # Shell variables
            "Fix ADR-005: Process ../ directory traversal",  # Path traversal
            "Fix ADR-006: Handle \"quotes\" and 'apostrophes'",  # Quotes
            "Fix ADR-007: Unicode 你好世界 🏗️ support",  # Unicode
        ]

        for message in special_messages:
            # Should not raise any exceptions
            matches = matcher.match_commit(message)
            assert isinstance(matches, list)

            # Should still detect ADR references
            if "ADR-" in message:
                assert len(matches) > 0
                adr_refs = []
                for match in matches:
                    adr_refs.extend(match.adr_references)
                assert any("ADR-" in ref for ref in adr_refs)

    def test_memory_exhaustion_protection(self, matcher):
        """Test protection against memory exhaustion attacks."""
        # Create messages that could cause memory issues
        huge_file_list = [f"file{i}.py" for i in range(10000)]

        # Should handle large file lists without memory issues
        matches = matcher.match_commit("Fix architectural violation", huge_file_list)
        assert isinstance(matches, list)

        # Check memory usage doesn't explode
        import sys

        if hasattr(sys, "getsizeof"):
            size = sys.getsizeof(matches)
            assert size < 10 * 1024 * 1024  # Less than 10MB


class TestPatternMatcherRobustness:
    """Robustness tests for pattern matcher."""

    @pytest.fixture
    def matcher(self):
        return ArchitecturalFixPatternMatcher()

    def test_empty_and_none_inputs(self, matcher):
        """Test handling of empty and None inputs."""
        test_cases = [
            ("", None),
            ("", []),
            (None, None),  # This should be handled gracefully
            ("Fix ADR-001", None),
            ("Fix ADR-001", []),
        ]

        for message, files in test_cases:
            if message is None:
                with pytest.raises((TypeError, AttributeError)):
                    matcher.match_commit(message, files)
            else:
                matches = matcher.match_commit(message, files)
                assert isinstance(matches, list)

    def test_multiline_edge_cases(self, matcher):
        """Test edge cases in multiline commit messages."""
        test_messages = [
            # Empty lines
            "Fix ADR-001\n\n\n\nMore details",
            # Mixed line endings
            "Fix ADR-001\r\nWindows line ending\rOld Mac\nUnix",
            # Very long lines
            "Fix ADR-001: " + "a" * 1000,
            # Many short lines
            "\n".join([f"Line {i}" for i in range(100)]) + "\nFix ADR-001",
            # Indented text
            "Fix ADR-001\n    Indented line\n        More indent",
            # Markdown-style formatting
            "# Fix ADR-001\n\n- Bullet point\n- Another point\n\n```\ncode block\n```",
        ]

        for message in test_messages:
            matches = matcher.match_commit(message)
            assert isinstance(matches, list)
            if "ADR-001" in message:
                assert any("ADR-001" in m.adr_references for match in matches for m in [match])

    def test_adr_reference_edge_cases(self, matcher):
        """Test edge cases in ADR reference extraction."""
        test_cases = [
            # Valid formats
            ("ADR-001", ["ADR-001"]),
            ("ADR001", ["ADR-001"]),
            ("adr-001", ["ADR-001"]),
            ("adr_001", ["ADR-001"]),
            ("#ADR-001", ["ADR-001"]),
            ("ADR 001", ["ADR-001"]),
            # Multiple references
            (
                "Fix ADR-001 and ADR-002, also ADR-003",
                ["ADR-001", "ADR-002", "ADR-003"],
            ),
            # Edge cases
            ("ADR-0", ["ADR-000"]),  # Zero-padded
            ("ADR-9999", ["ADR-9999"]),  # Maximum reasonable number
            ("ADR-00001", ["ADR-00001"]),  # Extra zeros
            # Invalid formats (should not match)
            ("ADR-", []),
            ("ADR-abc", []),
            ("ADR--001", []),
            ("XADR-001", []),  # Wrong prefix
        ]

        for text, expected in test_cases:
            refs = matcher.extract_adr_references(text)
            assert sorted(refs) == sorted(expected), f"Failed for '{text}': got {refs}"

    def test_pattern_priority_and_deduplication(self, matcher):
        """Test that overlapping patterns are properly deduplicated."""
        # Message that matches multiple patterns
        message = "Fix ADR-001: Resolved architectural violation and boundary leak"

        matches = matcher.match_commit(message)

        # Check no overlapping matches
        positions = []
        for match in matches:
            start = match.context["start_pos"]
            end = match.context["end_pos"]

            # Check this match doesn't overlap with any previous match
            for prev_start, prev_end in positions:
                assert not (start < prev_end and end > prev_start), "Found overlapping matches"

            positions.append((start, end))

        # Should prioritize higher confidence matches
        if len(matches) > 1:
            for i in range(len(matches) - 1):
                assert matches[i].confidence >= matches[i + 1].confidence

    def test_confidence_calculation_accuracy(self, matcher):
        """Test that confidence scores are calculated correctly."""
        test_cases = [
            # (message, files, min_confidence, max_confidence)
            ("Fix ADR-001", None, 0.9, 1.0),  # Explicit ADR fix
            (
                "Fix architectural violation",
                None,
                0.8,
                0.99,
            ),  # Architectural fix (capped at 0.99)
            ("Move code to proper layer", None, 0.5, 0.8),  # Implicit fix
            ("Random commit message", None, 0.0, 0.0),  # No match
            # With architectural files
            ("Fix boundary violation", ["app/architecture/boundary.py"], 0.8, 1.0),
            ("Fix boundary violation", ["app/utils/helper.py"], 0.7, 0.99),
        ]

        for message, files, min_conf, max_conf in test_cases:
            matches = matcher.match_commit(message, files)

            if min_conf > 0:
                assert len(matches) > 0, f"Expected matches for '{message}'"
                confidences = [m.confidence for m in matches]
                assert min(confidences) >= min_conf, f"Confidence too low for '{message}': {min(confidences)}"
                assert max(confidences) <= max_conf, f"Confidence too high for '{message}': {max(confidences)}"
            else:
                assert len(matches) == 0, f"Unexpected matches for '{message}'"


class TestPatternMatcherCompleteness:
    """Test completeness of pattern matching."""

    @pytest.fixture
    def matcher(self):
        return ArchitecturalFixPatternMatcher()

    def test_all_fix_types_covered(self, matcher):
        """Test that all FixType enums have corresponding patterns."""
        # Messages that should match each fix type
        fix_type_examples = {
            FixType.EXPLICIT_ADR_FIX: [
                "Fix ADR-001",
                "Fixes #ADR-023",
                "Implement ADR-100",
                "ADR-001: Fix compliance",
            ],
            FixType.ARCHITECTURAL_FIX: [
                "Fix architectural violation",
                "Resolved architecture issue",
                "Architectural compliance update",
                "Ensure architectural standards",
            ],
            FixType.BOUNDARY_FIX: [
                "Fix layer violation",
                "Resolved boundary leak",
                "Separate concerns",
                "Decouple service from repository layer",
            ],
            FixType.DEPENDENCY_FIX: [
                "Fix circular dependency",
                "Resolved cyclic dependencies",
                "Remove unnecessary coupling",
                "Dependency cleanup",
            ],
            FixType.REFACTORING_FIX: [
                "Refactor to improve architectural integrity",
                "Refactoring for better separation",
                "Extract service to separate module",
            ],
            FixType.IMPLICIT_FIX: [
                "Move auth logic to proper layer",
                "Clean up code structure",
                "Improve code organization",
            ],
        }

        for fix_type, examples in fix_type_examples.items():
            if fix_type == FixType.UNKNOWN:
                continue

            matched_any = False
            for example in examples:
                matches = matcher.match_commit(example)
                if any(m.fix_type == fix_type for m in matches):
                    matched_any = True
                    break

            assert matched_any, f"No patterns match {fix_type.value}"

    def test_real_world_commit_messages(self, matcher):
        """Test with real-world commit message examples."""
        real_commits = [
            # From popular open source projects
            "fix: resolve circular dependency between auth and user modules",
            "refactor(core): extract shared logic to reduce coupling",
            "chore: move utility functions to appropriate layer",
            "feat: implement ADR-042 for new authentication flow",
            "fix(api): correct layer violation in service calls",
            "style: reorganize imports to follow architectural boundaries",
            "perf: optimize by reducing cross-module dependencies",
            "test: add tests for architectural compliance",
            "docs: update ADR-001 with implementation details",
            "build: fix module boundaries in webpack config",
            # Complex real examples
            """fix: resolve architectural issues in payment module

            - Fixed layer violation where repository was calling service
            - Removed circular dependency between payment and order
            - Extracted shared interfaces to domain layer

            Fixes #1234, implements ADR-015""",
            """refactor: improve separation of concerns

            Moving business logic from controllers to service layer
            as per architectural guidelines in ADR-003.

            BREAKING CHANGE: API interface updated""",
        ]

        for commit in real_commits:
            matches = matcher.match_commit(commit)
            # Most real commits should match something
            assert isinstance(matches, list)

    def test_performance_with_large_inputs(self, matcher):
        """Test performance with large inputs."""
        # Large commit message
        large_message = "Fix ADR-001\n" + "\n".join([f"- Fixed issue in file{i}.py" for i in range(1000)])

        # Large file list
        large_file_list = [f"src/module{i}/file{j}.py" for i in range(100) for j in range(10)]

        start_time = time.time()
        matches = matcher.match_commit(large_message, large_file_list)
        elapsed = time.time() - start_time

        assert elapsed < 5.0, f"Processing took too long: {elapsed}s"
        assert isinstance(matches, list)
        assert len(matches) > 0  # Should find ADR-001


class TestCustomPatterns:
    """Test custom pattern functionality."""

    def test_custom_pattern_addition(self):
        """Test adding custom patterns to the matcher."""
        custom_patterns = [
            PatternConfig(
                pattern=r"SECURITY:\s*fix\s+(\w+)\s+vulnerability",
                fix_type=FixType.ARCHITECTURAL_FIX,
                confidence_base=0.95,
                description="Security vulnerability fix",
                capture_groups=["vulnerability_type"],
            ),
            PatternConfig(
                pattern=r"HOTFIX:\s*architectural\s+(\w+)",
                fix_type=FixType.ARCHITECTURAL_FIX,
                confidence_base=0.98,
                description="Architectural hotfix",
                capture_groups=["fix_area"],
            ),
        ]

        matcher = ArchitecturalFixPatternMatcher(custom_patterns=custom_patterns)

        # Test custom patterns work
        matches = matcher.match_commit("SECURITY: fix XSS vulnerability")
        assert len(matches) > 0
        assert matches[0].confidence >= 0.95
        assert "vulnerability_type" in matches[0].context["groups"]
        assert matches[0].context["groups"]["vulnerability_type"] == "XSS"

        # Test original patterns still work
        matches = matcher.match_commit("Fix ADR-001")
        assert len(matches) > 0
        assert any(m.fix_type == FixType.EXPLICIT_ADR_FIX for m in matches)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
