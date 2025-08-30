"""Unit tests for the git pattern matcher module."""

from typing import List

import pytest

from tools.pre_audit.git_pattern_matcher import (
    ArchitecturalFixPatternMatcher,
    FixMatch,
    FixType,
    PatternConfig,
)


class TestArchitecturalFixPatternMatcher:
    """Test cases for the ArchitecturalFixPatternMatcher class."""

    @pytest.fixture
    def matcher(self):
        """Create a pattern matcher instance."""
        return ArchitecturalFixPatternMatcher()

    def test_explicit_adr_fix_detection(self, matcher):
        """Test detection of explicit ADR fixes."""
        test_cases = [
            ("Fix ADR-001 violation in auth module", ["ADR-001"]),
            ("Fixes #ADR-023: Update service layer", ["ADR-023"]),
            ("Resolved ADR123 compliance issue", ["ADR-123"]),
            ("closes ADR-45", ["ADR-045"]),
            ("Addresses issue ADR-7", ["ADR-007"]),
        ]

        for message, expected_adrs in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"

            # Check fix type
            assert any(m.fix_type == FixType.EXPLICIT_ADR_FIX for m in matches)

            # Check ADR extraction
            all_adrs = []
            for match in matches:
                all_adrs.extend(match.adr_references)

            for expected_adr in expected_adrs:
                assert expected_adr in all_adrs, f"Expected {expected_adr} not found in {all_adrs}"

    def test_architectural_fix_detection(self, matcher):
        """Test detection of architectural fixes without ADR references."""
        test_cases = [
            "Fix architectural violation in payment service",
            "Resolved architecture issue with caching layer",
            "Address architectural problem in API design",
            "Corrected arch. violation",
            "Ensure architectural compliance in auth module",
            "Maintain architectural standards",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"
            assert any(m.fix_type == FixType.ARCHITECTURAL_FIX for m in matches)

    def test_boundary_fix_detection(self, matcher):
        """Test detection of boundary and layer violation fixes."""
        test_cases = [
            "Fix layer violation between service and repository",
            "Resolved boundary leak in domain layer",
            "Address module coupling issue",
            "Separate concerns between layers",
            "Decouple business logic from data layer",
            "Remove cross-layer dependency",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"
            assert any(m.fix_type == FixType.BOUNDARY_FIX for m in matches)

    def test_dependency_fix_detection(self, matcher):
        """Test detection of dependency-related fixes."""
        test_cases = [
            "Fix circular dependency between modules",
            "Resolve cyclic dependencies",
            "Reduce unnecessary coupling",
            "Remove unwanted dependencies",
            "Dependency cleanup in service layer",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"
            assert any(m.fix_type == FixType.DEPENDENCY_FIX for m in matches)

    def test_refactoring_fix_detection(self, matcher):
        """Test detection of refactoring that addresses architectural issues."""
        test_cases = [
            "Refactor to improve architectural integrity",
            "Refactoring for better separation of concerns",
            "Refactored to ensure design patterns",
            "Extract service to separate module",  # This could be BOUNDARY_FIX or REFACTORING_FIX
            "Refactor for improved modularity",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"
            # Accept either REFACTORING_FIX or BOUNDARY_FIX for extraction patterns
            acceptable_types = {FixType.REFACTORING_FIX, FixType.BOUNDARY_FIX}
            assert any(m.fix_type in acceptable_types for m in matches)

    def test_implicit_fix_detection(self, matcher):
        """Test detection of implicit architectural improvements."""
        test_cases = [
            "Move auth logic to proper layer",
            "Relocated services to correct module",
            "Clean up code structure",
            "Improve code organization",
            "Enhance modularity of payment system",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"No matches found for: {message}"
            assert any(m.fix_type == FixType.IMPLICIT_FIX for m in matches)

    def test_adr_reference_extraction(self, matcher):
        """Test extraction of ADR references in various formats."""
        test_cases = [
            (
                "Working on ADR-001, ADR-002, and ADR-003",
                ["ADR-001", "ADR-002", "ADR-003"],
            ),
            ("Implements #ADR001 and adr-2", ["ADR-001", "ADR-002"]),
            ("Related to adr_15 and ADR 7", ["ADR-015", "ADR-007"]),
            ("Architecture decision record 42", ["ADR-042"]),
            ("Multiple: ADR001, #ADR-002, adr_003", ["ADR-001", "ADR-002", "ADR-003"]),
        ]

        for text, expected_refs in test_cases:
            refs = matcher.extract_adr_references(text)
            assert len(refs) == len(expected_refs), f"Expected {len(expected_refs)} refs, got {len(refs)}"
            for expected_ref in expected_refs:
                assert expected_ref in refs, f"Expected {expected_ref} not found in {refs}"

    def test_confidence_scoring(self, matcher):
        """Test that confidence scores are calculated correctly."""
        # Explicit ADR fix should have high confidence
        matches = matcher.match_commit("Fix ADR-001 violation")
        assert len(matches) > 0
        assert matches[0].confidence >= 0.9

        # Implicit fix should have lower confidence
        matches = matcher.match_commit("Improve code structure")
        assert len(matches) > 0
        assert matches[0].confidence < 0.7

        # Multiple architectural keywords should boost confidence
        matches = matcher.match_commit("Refactor architecture: Fix layer violation and improve module structure")
        assert len(matches) > 0
        # Should have higher confidence due to multiple keywords
        assert any(m.confidence > 0.7 for m in matches)

    def test_file_path_context(self, matcher):
        """Test that file paths influence confidence scoring."""
        message = "Fix boundary violation"

        # Without file context
        matches_no_files = matcher.match_commit(message)

        # With architectural file paths
        arch_files = ["app/architecture/base.py", "core/boundaries.py"]
        matches_with_files = matcher.match_commit(message, arch_files)

        # Confidence should be higher with architectural file paths
        assert matches_with_files[0].confidence > matches_no_files[0].confidence

    def test_conventional_commit_handling(self, matcher):
        """Test handling of conventional commit formats."""
        test_cases = [
            "fix: ADR-001 compliance in auth module",
            "feat(auth): implement ADR-023 requirements",
            "refactor(core): improve architectural boundaries",
            "fix(api): resolve layer violation",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"Failed to match conventional commit: {message}"

    def test_multiline_commit_messages(self, matcher):
        """Test pattern matching in multiline commit messages."""
        message = """Fix authentication issues

This commit addresses ADR-001 violations in the auth module.
It also fixes architectural boundary leaks between the service
and repository layers.

- Resolved circular dependencies
- Improved separation of concerns
- Refactored for better modularity
"""

        matches = matcher.match_commit(message)

        # Should find multiple types of fixes
        fix_types = {m.fix_type for m in matches}
        assert FixType.EXPLICIT_ADR_FIX in fix_types
        assert FixType.BOUNDARY_FIX in fix_types
        assert FixType.DEPENDENCY_FIX in fix_types

    def test_no_false_positives(self, matcher):
        """Test that non-architectural commits don't produce false positives."""
        non_architectural_messages = [
            "Update README.md",
            "Add unit tests",
            "Bump version to 1.2.3",
            "Fix typo in documentation",
            "Update dependencies",
            "Add logging statements",
        ]

        for message in non_architectural_messages:
            matches = matcher.match_commit(message)
            # Should either have no matches or very low confidence
            if matches:
                assert all(m.confidence < 0.5 for m in matches)

    def test_match_deduplication(self, matcher):
        """Test that overlapping matches are deduplicated correctly."""
        # Message with overlapping patterns
        message = "Fix ADR-001: Resolve architectural violation"

        matches = matcher.match_commit(message)

        # Check that matches don't overlap
        for i, match1 in enumerate(matches):
            for match2 in matches[i + 1 :]:
                # No overlapping text ranges
                assert not (
                    match1.context["start_pos"] < match2.context["end_pos"]
                    and match2.context["start_pos"] < match1.context["end_pos"]
                )

    def test_custom_patterns(self):
        """Test adding custom patterns to the matcher."""
        custom_patterns = [
            PatternConfig(
                pattern=r"CUSTOM:\s*architectural\s+fix",
                fix_type=FixType.ARCHITECTURAL_FIX,
                confidence_base=0.99,
                description="Custom architectural fix",
            )
        ]

        matcher = ArchitecturalFixPatternMatcher(custom_patterns=custom_patterns)

        matches = matcher.match_commit("CUSTOM: architectural fix applied")
        assert len(matches) > 0
        assert matches[0].confidence >= 0.99
        assert matches[0].pattern_name == "Custom architectural fix"

    def test_case_insensitivity(self, matcher):
        """Test that pattern matching is case-insensitive."""
        test_cases = [
            "FIX ADR-001",
            "fix adr-001",
            "Fix Adr-001",
            "ARCHITECTURAL VIOLATION FIXED",
            "architectural violation fixed",
        ]

        for message in test_cases:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"Case-insensitive matching failed for: {message}"

    def test_capture_groups(self, matcher):
        """Test that capture groups are extracted correctly."""
        message = "Fix ADR-042: Resolve payment service architectural issues"

        matches = matcher.match_commit(message)

        # Find the explicit ADR fix match
        adr_match = next(m for m in matches if m.fix_type == FixType.EXPLICIT_ADR_FIX)

        # Check that ADR number was captured
        assert "groups" in adr_match.context
        assert "adr_number" in adr_match.context["groups"]
        assert adr_match.context["groups"]["adr_number"] == "042"


class TestFixMatchDataClass:
    """Test the FixMatch dataclass."""

    def test_fix_match_creation(self):
        """Test creating a FixMatch instance."""
        match = FixMatch(
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence=0.95,
            matched_text="Fix ADR-001",
            adr_references=["ADR-001"],
            context={"start_pos": 0, "end_pos": 11},
            pattern_name="Explicit ADR fix",
        )

        assert match.fix_type == FixType.EXPLICIT_ADR_FIX
        assert match.confidence == 0.95
        assert match.matched_text == "Fix ADR-001"
        assert match.adr_references == ["ADR-001"]
        assert match.pattern_name == "Explicit ADR fix"


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def matcher(self):
        return ArchitecturalFixPatternMatcher()

    def test_empty_commit_message(self, matcher):
        """Test handling of empty commit messages."""
        matches = matcher.match_commit("")
        assert matches == []

    def test_very_long_commit_message(self, matcher):
        """Test handling of very long commit messages."""
        # Create a very long message
        long_message = "Fix ADR-001 " + ("x" * 10000) + " Fix ADR-002"

        matches = matcher.match_commit(long_message)
        assert len(matches) > 0
        # Should find both ADR references
        all_adrs = []
        for match in matches:
            all_adrs.extend(match.adr_references)
        assert "ADR-001" in all_adrs
        assert "ADR-002" in all_adrs

    def test_invalid_adr_numbers(self, matcher):
        """Test handling of invalid ADR numbers."""
        # ADR numbers should be reasonable (1-9999)
        message = "Fix ADR-99999 and ADR-00000"

        refs = matcher.extract_adr_references(message)
        # Should still extract them but they might be filtered in practice
        assert len(refs) > 0

    def test_special_characters_in_message(self, matcher):
        """Test handling of special characters."""
        messages = [
            "Fix ADR-001: Handle @special #characters",
            "Resolve ADR-002 & architectural issues",
            "Fix layer violation (see ADR-003)",
            "ADR-004 fix [URGENT]",
        ]

        for message in messages:
            matches = matcher.match_commit(message)
            assert len(matches) > 0, f"Failed to handle special characters in: {message}"
