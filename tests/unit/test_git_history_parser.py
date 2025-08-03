"""
Unit tests for the git history parser module.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from tools.pre_audit.git_history_parser import ArchitecturalFix, FileChangePattern, FixType, GitHistoryParser


class TestArchitecturalFix:
    """Test the ArchitecturalFix dataclass."""

    def test_architectural_fix_creation(self):
        """Test creating an ArchitecturalFix instance."""
        fix = ArchitecturalFix(
            commit_hash="abc123def456",
            commit_message="Fix ADR-001 violation in auth module",
            author="John Doe",
            date=datetime.now(timezone.utc),
            files_changed=["app/auth.py", "app/models.py"],
            fix_type=FixType.EXPLICIT_ADR_FIX,
            confidence=0.95,
            adr_references=["ADR-001"],
            pattern_matched="Explicit ADR fix",
            lines_added=50,
            lines_deleted=30,
        )

        assert fix.commit_hash == "abc123def456"
        assert fix.author == "John Doe"
        assert len(fix.files_changed) == 2
        assert fix.fix_type == FixType.EXPLICIT_ADR_FIX
        assert fix.confidence == 0.95
        assert fix.adr_references == ["ADR-001"]

    def test_architectural_fix_to_dict(self):
        """Test converting ArchitecturalFix to dictionary."""
        date = datetime.now(timezone.utc)
        fix = ArchitecturalFix(
            commit_hash="abc123",
            commit_message="Fix issue",
            author="Test User",
            date=date,
            files_changed=["file1.py"],
            fix_type=FixType.BOUNDARY_FIX,
            confidence=0.8,
            adr_references=[],
            pattern_matched="Test pattern",
        )

        result = fix.to_dict()

        assert result["commit_hash"] == "abc123"
        assert result["author"] == "Test User"
        assert result["fix_type"] == "boundary_fix"
        assert result["confidence"] == 0.8
        assert result["date"] == date.isoformat()


class TestGitHistoryParser:
    """Test the GitHistoryParser class."""

    @pytest.fixture
    def mock_repo(self):
        """Create a mock git repository."""
        repo = Mock()
        repo.bare = False
        return repo

    @pytest.fixture
    def mock_commit(self):
        """Create a mock commit."""
        commit = Mock()
        commit.hexsha = "1234567890abcdef"
        commit.message = "Fix ADR-001 compliance issue"
        commit.author.name = "Test Author"
        commit.committed_datetime = datetime.now(timezone.utc)
        commit.stats.files = {
            "app/services/auth.py": {"insertions": 20, "deletions": 10},
            "app/models/user.py": {"insertions": 5, "deletions": 3},
        }
        return commit

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_parser_initialization(self, mock_git_repo, tmp_path):
        """Test initializing the parser."""
        mock_git_repo.return_value = Mock(bare=False)

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        parser = GitHistoryParser(test_repo_path)

        assert parser.repo_path == test_repo_path
        assert parser.pattern_matcher is not None
        mock_git_repo.assert_called_once_with(test_repo_path)

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_parser_initialization_bare_repo(self, mock_git_repo, tmp_path):
        """Test initialization fails for bare repository."""
        mock_repo = Mock(bare=True)
        mock_git_repo.return_value = mock_repo

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        with pytest.raises(ValueError, match="Cannot analyze bare repository"):
            GitHistoryParser(test_repo_path)

    @patch("tools.pre_audit.git_history_parser.HAS_GIT", False)
    def test_parser_no_gitpython(self, tmp_path):
        """Test initialization fails without GitPython."""
        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        with pytest.raises(ImportError, match="GitPython is required"):
            GitHistoryParser(test_repo_path)

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_find_architectural_fixes(self, mock_git_repo, tmp_path):
        """Test finding architectural fixes in history."""
        # Setup mock repo and commits
        mock_repo = Mock(bare=False)
        mock_git_repo.return_value = mock_repo

        # Create mock commits
        commits = []
        for i in range(3):
            commit = Mock()
            commit.hexsha = f"commit{i}"
            commit.message = f"Fix ADR-00{i+1} violation"
            commit.author.name = f"Author{i}"
            commit.committed_datetime = datetime.now(timezone.utc) - timedelta(days=i)
            commit.stats.files = {f"file{i}.py": {"insertions": 10, "deletions": 5}}
            commits.append(commit)

        mock_repo.iter_commits.return_value = commits

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        parser = GitHistoryParser(test_repo_path)
        fixes = parser.find_architectural_fixes(since_months=1)

        assert len(fixes) == 3
        assert all(isinstance(fix, ArchitecturalFix) for fix in fixes)
        assert fixes[0].commit_hash == "commit0"
        assert fixes[0].adr_references == ["ADR-001"]

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_find_architectural_fixes_with_adr_filter(self, mock_git_repo, tmp_path):
        """Test finding fixes for specific ADR."""
        mock_repo = Mock(bare=False)
        mock_git_repo.return_value = mock_repo

        # Create commits with different ADRs
        commits = []
        commit1 = Mock()
        commit1.hexsha = "commit1"
        commit1.message = "Fix ADR-001 compliance"
        commit1.author.name = "Author1"
        commit1.committed_datetime = datetime.now(timezone.utc)
        commit1.stats.files = {"file1.py": {"insertions": 10, "deletions": 5}}
        commits.append(commit1)

        commit2 = Mock()
        commit2.hexsha = "commit2"
        commit2.message = "Fix ADR-002 violation"
        commit2.author.name = "Author2"
        commit2.committed_datetime = datetime.now(timezone.utc)
        commit2.stats.files = {"file2.py": {"insertions": 15, "deletions": 8}}
        commits.append(commit2)

        mock_repo.iter_commits.return_value = commits

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        parser = GitHistoryParser(test_repo_path)
        fixes = parser.find_architectural_fixes(adr_id="ADR-001")

        assert len(fixes) == 1
        assert fixes[0].commit_hash == "commit1"
        assert "ADR-001" in fixes[0].adr_references

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_find_file_change_patterns(self, mock_git_repo, tmp_path):
        """Test finding file change patterns."""
        mock_repo = Mock(bare=False)
        mock_git_repo.return_value = mock_repo

        # Create commits with co-changing files
        commits = []

        # Pattern 1: file1.py and file2.py change together frequently
        for i in range(4):
            commit = Mock()
            commit.hexsha = f"commit{i}"
            commit.stats.files = {
                "app/file1.py": {"insertions": 10, "deletions": 5},
                "app/file2.py": {"insertions": 8, "deletions": 3},
            }
            commits.append(commit)

        # Pattern 2: Different files change together less frequently
        for i in range(2):
            commit = Mock()
            commit.hexsha = f"commit{i+4}"
            commit.stats.files = {
                "app/file3.py": {"insertions": 5, "deletions": 2},
                "app/file4.py": {"insertions": 3, "deletions": 1},
            }
            commits.append(commit)

        mock_repo.iter_commits.return_value = commits

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        parser = GitHistoryParser(test_repo_path)
        patterns = parser.find_file_change_patterns(min_frequency=2)

        assert len(patterns) == 2
        assert patterns[0].frequency == 4  # file1.py and file2.py
        assert patterns[1].frequency == 2  # file3.py and file4.py

    def test_is_architectural_file(self):
        """Test identifying architectural files."""
        # Create a minimal GitHistoryParser instance without full initialization
        parser = object.__new__(GitHistoryParser)
        parser.repo_path = Path("/test/repo")
        parser.config = {}
        parser.pattern_matcher = None

        arch_files = [
            "app/architecture/design.py",
            "core/base.py",
            "framework/foundation.py",
            "app/boundaries/service.py",
            "layers/presentation.py",
        ]

        non_arch_files = ["tests/test_user.py", "utils/helpers.py", "config/settings.py"]

        for file_path in arch_files:
            assert parser._is_architectural_file(file_path)

        for file_path in non_arch_files:
            assert not parser._is_architectural_file(file_path)

    def test_get_fix_statistics(self):
        """Test calculating fix statistics."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        # Create test fixes
        now = datetime.now(timezone.utc)
        fixes = [
            ArchitecturalFix(
                commit_hash="commit1",
                commit_message="Fix ADR-001",
                author="Author1",
                date=now - timedelta(days=10),
                files_changed=["file1.py"],
                fix_type=FixType.EXPLICIT_ADR_FIX,
                confidence=0.95,
                adr_references=["ADR-001"],
                pattern_matched="Test",
                lines_added=20,
                lines_deleted=10,
            ),
            ArchitecturalFix(
                commit_hash="commit2",
                commit_message="Fix boundary",
                author="Author1",
                date=now - timedelta(days=5),
                files_changed=["file2.py"],
                fix_type=FixType.BOUNDARY_FIX,
                confidence=0.8,
                adr_references=["ADR-001", "ADR-002"],
                pattern_matched="Test",
                lines_added=15,
                lines_deleted=5,
            ),
            ArchitecturalFix(
                commit_hash="commit3",
                commit_message="Fix another",
                author="Author2",
                date=now,
                files_changed=["file3.py"],
                fix_type=FixType.BOUNDARY_FIX,
                confidence=0.7,
                adr_references=["ADR-002"],
                pattern_matched="Test",
                lines_added=10,
                lines_deleted=8,
            ),
        ]

        stats = parser.get_fix_statistics(fixes)

        assert stats["total_fixes"] == 3
        assert stats["fix_types"]["explicit_adr_fix"] == 1
        assert stats["fix_types"]["boundary_fix"] == 2
        assert stats["adr_references"]["ADR-001"] == 2
        assert stats["adr_references"]["ADR-002"] == 2
        assert stats["top_contributors"][0]["author"] == "Author1"
        assert stats["top_contributors"][0]["fixes"] == 2
        assert stats["average_confidence"] == pytest.approx(0.816, rel=0.01)
        assert stats["total_lines_changed"] == 68

    def test_get_fix_statistics_empty(self):
        """Test statistics with no fixes."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        stats = parser.get_fix_statistics([])

        assert stats["total_fixes"] == 0
        assert stats["fix_types"] == {}
        assert stats["average_confidence"] == 0.0

    def test_export_fixes_summary_json(self):
        """Test exporting fixes as JSON."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        now = datetime.now(timezone.utc)
        fixes = [
            ArchitecturalFix(
                commit_hash="abc123",
                commit_message="Fix ADR-001",
                author="Test Author",
                date=now,
                files_changed=["file1.py"],
                fix_type=FixType.EXPLICIT_ADR_FIX,
                confidence=0.95,
                adr_references=["ADR-001"],
                pattern_matched="Test pattern",
                lines_added=10,
                lines_deleted=5,
            )
        ]

        result = parser.export_fixes_summary(fixes, "json")
        data = json.loads(result)

        assert "fixes" in data
        assert "statistics" in data
        assert len(data["fixes"]) == 1
        assert data["fixes"][0]["commit_hash"] == "abc123"

    def test_export_fixes_summary_csv(self):
        """Test exporting fixes as CSV."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        now = datetime.now(timezone.utc)
        fixes = [
            ArchitecturalFix(
                commit_hash="abc123def",
                commit_message="Fix ADR-001",
                author="Test Author",
                date=now,
                files_changed=["file1.py", "file2.py"],
                fix_type=FixType.EXPLICIT_ADR_FIX,
                confidence=0.95,
                adr_references=["ADR-001", "ADR-002"],
                pattern_matched="Test pattern",
            )
        ]

        result = parser.export_fixes_summary(fixes, "csv")
        lines = result.split("\n")

        assert len(lines) == 2  # Header + 1 fix
        assert "commit_hash,date,author,fix_type,confidence,adr_references,files_changed" in lines[0]
        assert "abc123de" in lines[1]  # First 8 chars of hash
        assert "Test Author" in lines[1]
        assert "ADR-001;ADR-002" in lines[1]

    def test_export_fixes_summary_markdown(self):
        """Test exporting fixes as Markdown."""
        parser = GitHistoryParser.__new__(GitHistoryParser)

        now = datetime.now(timezone.utc)
        fixes = [
            ArchitecturalFix(
                commit_hash="abc123",
                commit_message="Fix ADR-001 compliance issue\nDetailed description",
                author="Test Author",
                date=now,
                files_changed=["file1.py"],
                fix_type=FixType.EXPLICIT_ADR_FIX,
                confidence=0.95,
                adr_references=["ADR-001"],
                pattern_matched="Test pattern",
            )
        ]

        result = parser.export_fixes_summary(fixes, "markdown")

        assert "# Architectural Fixes Summary" in result
        assert "**Total Fixes**: 1" in result
        assert "Test Author" in result
        assert "ADR-001" in result

    @patch("tools.pre_audit.git_history_parser.git.Repo")
    def test_export_fixes_summary_invalid_format(self, mock_git_repo, tmp_path):
        """Test export with invalid format."""
        mock_git_repo.return_value = Mock(bare=False)

        # Use temp directory to satisfy path validation
        test_repo_path = tmp_path / "test_repo"
        test_repo_path.mkdir()

        parser = GitHistoryParser(test_repo_path)

        # Create a dummy fix to ensure we reach format validation
        fix = ArchitecturalFix(
            commit_hash="abc123",
            commit_message="Test fix",
            author="Test Author",
            date=datetime.now(timezone.utc),
            files_changed=["test.py"],
            fix_type=FixType.ARCHITECTURAL_FIX,
            confidence=0.9,
            adr_references=[],
            pattern_matched="Test pattern",
        )

        with pytest.raises(ValueError, match="Unsupported format"):
            parser.export_fixes_summary([fix], "invalid")


class TestIntegration:
    """Integration tests using real git operations."""

    @pytest.mark.integration
    def test_real_repository_analysis(self, tmp_path):
        """Test with a real git repository."""
        import subprocess

        # Create a temporary git repository
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)

        # Create some commits with architectural fixes
        test_file = repo_path / "test.py"

        # Commit 1: ADR fix
        test_file.write_text("# Initial code")
        subprocess.run(["git", "add", "test.py"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Fix ADR-001 compliance issue"], cwd=repo_path, check=True)

        # Commit 2: Boundary fix
        test_file.write_text("# Updated code\n# Fixed boundary")
        subprocess.run(["git", "add", "test.py"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Resolve layer violation"], cwd=repo_path, check=True)

        # Commit 3: Regular commit (not architectural)
        test_file.write_text("# Updated code\n# Fixed boundary\n# Added feature")
        subprocess.run(["git", "add", "test.py"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Add new feature"], cwd=repo_path, check=True)

        # Analyze the repository
        parser = GitHistoryParser(repo_path)
        fixes = parser.find_architectural_fixes()

        assert len(fixes) == 2  # Should find 2 architectural fixes
        assert any("ADR-001" in fix.adr_references for fix in fixes)
        assert any(fix.fix_type == FixType.BOUNDARY_FIX for fix in fixes)
