"""Unit tests for backup coverage audit functionality."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from scripts.backup_coverage_audit import (
    BackupCoverageAuditor,
    BackupCoverageReport,
    BackupGap,
    ComplianceStatus,
    CriticalityLevel,
    RepositoryInfo,
)


class TestBackupCoverageAuditor:
    """Test suite for backup coverage audit functionality."""

    @pytest.fixture
    def sample_repositories(self) -> List[RepositoryInfo]:
        """Create sample repository data for testing."""
        return [
            RepositoryInfo(
                name="user_repository",
                table_name="users",
                criticality=CriticalityLevel.CRITICAL,
                data_size_mb=150,
                last_backup=datetime.now() - timedelta(minutes=30),  # 30 minutes ago, within 2-hour limit
                backup_frequency="hourly",
                retention_required_days=90,
            ),
            RepositoryInfo(
                name="audit_log_repository",
                table_name="audit_logs",
                criticality=CriticalityLevel.CRITICAL,
                data_size_mb=500,
                last_backup=datetime.now() - timedelta(minutes=15),  # 15 minutes ago, within 2-hour limit
                backup_frequency="hourly",
                retention_required_days=365,
            ),
            RepositoryInfo(
                name="session_repository",
                table_name="sessions",
                criticality=CriticalityLevel.IMPORTANT,
                data_size_mb=50,
                last_backup=datetime.now() - timedelta(hours=6),
                backup_frequency="every_6_hours",
                retention_required_days=30,
            ),
            RepositoryInfo(
                name="template_repository",
                table_name="templates",
                criticality=CriticalityLevel.STANDARD,
                data_size_mb=25,
                last_backup=datetime.now() - timedelta(days=1),
                backup_frequency="daily",
                retention_required_days=30,
            ),
        ]

    @pytest.fixture
    def auditor(self) -> BackupCoverageAuditor:
        """Create backup coverage auditor instance."""
        return BackupCoverageAuditor()

    def test_auditor_initialization(self, auditor):
        """Test backup coverage auditor initializes correctly."""
        assert isinstance(auditor, BackupCoverageAuditor)
        assert auditor.repositories == []
        assert auditor.backup_policies is not None

    def test_discover_repositories_from_container(self, auditor):
        """Test repository discovery from service container."""
        with patch("app.core.container.get_container") as mock_container:
            # Mock container with registered repositories
            mock_container.return_value.get_all_repositories.return_value = {
                "user_repository": MagicMock(),
                "audit_log_repository": MagicMock(),
                "session_repository": MagicMock(),
            }

            discovered_repos = auditor.discover_repositories()

            assert len(discovered_repos) >= 3
            assert any(repo.name == "user_repository" for repo in discovered_repos)
            assert any(repo.name == "audit_log_repository" for repo in discovered_repos)

    def test_classify_repository_criticality_critical(self, auditor):
        """Test repository criticality classification for critical data."""
        # Test critical repositories
        critical_names = ["user_repository", "audit_log_repository", "api_key_repository"]

        for name in critical_names:
            criticality = auditor.classify_repository_criticality(name)
            assert criticality == CriticalityLevel.CRITICAL

    def test_classify_repository_criticality_important(self, auditor):
        """Test repository criticality classification for important data."""
        # Test important repositories
        important_names = ["session_repository", "mfa_policy_repository", "role_repository"]

        for name in important_names:
            criticality = auditor.classify_repository_criticality(name)
            assert criticality == CriticalityLevel.IMPORTANT

    def test_classify_repository_criticality_standard(self, auditor):
        """Test repository criticality classification for standard data."""
        # Test standard repositories
        standard_names = ["template_repository", "plugin_repository", "report_repository"]

        for name in standard_names:
            criticality = auditor.classify_repository_criticality(name)
            assert criticality == CriticalityLevel.STANDARD

    def test_analyze_backup_gaps_critical_overdue(self, auditor, sample_repositories):
        """Test backup gap analysis for overdue critical backups."""
        # Modify sample data to have overdue critical backup
        sample_repositories[0].last_backup = datetime.now() - timedelta(hours=25)

        gaps = auditor.analyze_backup_gaps(sample_repositories)

        # Should find gap for overdue critical backup
        critical_gaps = [gap for gap in gaps if gap.criticality == CriticalityLevel.CRITICAL]
        assert len(critical_gaps) > 0
        assert critical_gaps[0].gap_hours > 24

    def test_analyze_backup_gaps_no_gaps(self, auditor, sample_repositories):
        """Test backup gap analysis when all backups are current."""
        # All sample repositories have recent backups
        gaps = auditor.analyze_backup_gaps(sample_repositories)

        # Should find no significant gaps
        assert len(gaps) == 0

    def test_calculate_compliance_score_perfect(self, auditor, sample_repositories):
        """Test compliance score calculation with perfect compliance."""
        # All repositories are compliant
        score = auditor.calculate_compliance_score(sample_repositories)

        assert score == 100.0

    def test_calculate_compliance_score_partial(self, auditor, sample_repositories):
        """Test compliance score calculation with partial compliance."""
        # Make one repository non-compliant
        sample_repositories[0].last_backup = datetime.now() - timedelta(days=2)

        score = auditor.calculate_compliance_score(sample_repositories)

        assert 0 < score < 100

    def test_get_backup_frequency_requirements_critical(self, auditor):
        """Test backup frequency requirements for critical data."""
        requirements = auditor.get_backup_frequency_requirements(CriticalityLevel.CRITICAL)

        assert requirements["frequency"] == "hourly"
        assert requirements["max_age_hours"] <= 2
        assert requirements["retention_days"] >= 90

    def test_get_backup_frequency_requirements_important(self, auditor):
        """Test backup frequency requirements for important data."""
        requirements = auditor.get_backup_frequency_requirements(CriticalityLevel.IMPORTANT)

        assert requirements["frequency"] in ["every_6_hours", "every_4_hours"]
        assert requirements["max_age_hours"] <= 8
        assert requirements["retention_days"] >= 30

    def test_get_backup_frequency_requirements_standard(self, auditor):
        """Test backup frequency requirements for standard data."""
        requirements = auditor.get_backup_frequency_requirements(CriticalityLevel.STANDARD)

        assert requirements["frequency"] == "daily"
        assert requirements["max_age_hours"] <= 26
        assert requirements["retention_days"] >= 14

    def test_generate_coverage_report(self, auditor, sample_repositories):
        """Test backup coverage report generation."""
        report = auditor.generate_coverage_report(sample_repositories)

        assert isinstance(report, BackupCoverageReport)
        assert report.total_repositories == len(sample_repositories)
        assert report.compliance_score >= 0
        assert report.timestamp is not None

    def test_generate_coverage_report_with_gaps(self, auditor, sample_repositories):
        """Test coverage report generation with backup gaps."""
        # Create overdue backup
        sample_repositories[0].last_backup = datetime.now() - timedelta(hours=25)

        report = auditor.generate_coverage_report(sample_repositories)

        assert len(report.backup_gaps) > 0
        assert report.compliance_score < 100
        assert report.status == ComplianceStatus.NON_COMPLIANT

    def test_optimize_backup_schedule_critical_heavy(self, auditor):
        """Test backup schedule optimization for critical, high-volume data."""
        repo_info = RepositoryInfo(
            name="large_critical_repo",
            table_name="large_table",
            criticality=CriticalityLevel.CRITICAL,
            data_size_mb=2000,  # 2GB
            last_backup=datetime.now(),
            backup_frequency="hourly",
            retention_required_days=90,
        )

        optimized_schedule = auditor.optimize_backup_schedule([repo_info])

        # Should recommend more frequent incremental backups
        assert optimized_schedule[0]["frequency"] in ["every_30_minutes", "hourly"]
        assert optimized_schedule[0]["type"] in ["incremental", "mixed"]

    def test_optimize_backup_schedule_standard_light(self, auditor):
        """Test backup schedule optimization for standard, low-volume data."""
        repo_info = RepositoryInfo(
            name="small_standard_repo",
            table_name="small_table",
            criticality=CriticalityLevel.STANDARD,
            data_size_mb=10,  # 10MB
            last_backup=datetime.now(),
            backup_frequency="daily",
            retention_required_days=14,
        )

        optimized_schedule = auditor.optimize_backup_schedule([repo_info])

        # Should be fine with daily backups
        assert optimized_schedule[0]["frequency"] == "daily"
        assert optimized_schedule[0]["type"] == "full"

    def test_identify_backup_storage_usage(self, auditor, sample_repositories):
        """Test backup storage usage calculation."""
        with patch("scripts.backup_coverage_audit.Path.glob") as mock_glob:

            # Mock backup files with proper stat method
            mock_stat_obj = MagicMock()
            mock_stat_obj.st_size = 100 * 1024 * 1024  # 100MB each
            mock_stat_obj.st_mtime = 1642780800  # Fixed timestamp

            mock_files = []
            for i in range(10):
                mock_file = MagicMock()
                mock_file.stat.return_value = mock_stat_obj
                mock_file.name = f"backup_{i}.sql"
                mock_files.append(mock_file)

            mock_glob.return_value = mock_files

            storage_usage = auditor.calculate_backup_storage_usage()

            assert storage_usage["total_size_gb"] > 0
            assert storage_usage["file_count"] > 0
            assert "oldest_backup" in storage_usage
            assert "newest_backup" in storage_usage

    def test_validate_backup_retention_compliance(self, auditor, sample_repositories):
        """Test backup retention compliance validation."""
        # Test with compliant retention
        compliance_results = auditor.validate_retention_compliance(sample_repositories)

        for result in compliance_results:
            assert "repository" in result
            assert "compliant" in result
            assert "current_retention_days" in result
            assert "required_retention_days" in result

    def test_generate_backup_recommendations(self, auditor, sample_repositories):
        """Test backup recommendation generation."""
        # Create a scenario requiring recommendations
        sample_repositories[0].last_backup = datetime.now() - timedelta(days=2)
        sample_repositories[1].data_size_mb = 5000  # Very large

        recommendations = auditor.generate_recommendations(sample_repositories)

        assert len(recommendations) > 0
        assert any("frequency" in rec["action"] for rec in recommendations)
        assert any("overdue" in rec["reason"].lower() for rec in recommendations)

    def test_export_audit_report_json(self, auditor, sample_repositories):
        """Test audit report export to JSON format."""
        report = auditor.generate_coverage_report(sample_repositories)

        json_data = auditor.export_report_json(report)

        assert "total_repositories" in json_data
        assert "compliance_score" in json_data
        assert "backup_gaps" in json_data
        assert "timestamp" in json_data

    def test_export_audit_report_csv(self, auditor, sample_repositories):
        """Test audit report export to CSV format."""
        report = auditor.generate_coverage_report(sample_repositories)

        csv_data = auditor.export_report_csv(report)

        assert isinstance(csv_data, str)
        assert "Repository Name" in csv_data
        assert "Criticality" in csv_data
        assert "Last Backup" in csv_data

    def test_schedule_optimization_with_constraints(self, auditor):
        """Test backup schedule optimization with resource constraints."""
        # Create repositories with different characteristics
        repositories = [
            RepositoryInfo(
                name="heavy_repo_1",
                criticality=CriticalityLevel.CRITICAL,
                data_size_mb=1000,
                backup_frequency="hourly",
            ),
            RepositoryInfo(
                name="heavy_repo_2",
                criticality=CriticalityLevel.CRITICAL,
                data_size_mb=1200,
                backup_frequency="hourly",
            ),
        ]

        # Test with resource constraints
        constraints = {
            "max_concurrent_backups": 2,
            "backup_window_start": "02:00",
            "backup_window_end": "06:00",
            "max_storage_gb_per_day": 10,
        }

        optimized_schedule = auditor.optimize_backup_schedule(repositories, constraints)

        # Should spread backups to avoid conflicts
        assert len(set(schedule["start_time"] for schedule in optimized_schedule)) >= 2

    def test_backup_gap_prioritization(self, auditor):
        """Test backup gap prioritization by criticality and age."""
        gaps = [
            BackupGap(
                repository="critical_repo",
                criticality=CriticalityLevel.CRITICAL,
                gap_hours=30,
                last_backup=datetime.now() - timedelta(hours=30),
            ),
            BackupGap(
                repository="standard_repo",
                criticality=CriticalityLevel.STANDARD,
                gap_hours=48,
                last_backup=datetime.now() - timedelta(hours=48),
            ),
            BackupGap(
                repository="important_repo",
                criticality=CriticalityLevel.IMPORTANT,
                gap_hours=12,
                last_backup=datetime.now() - timedelta(hours=12),
            ),
        ]

        prioritized_gaps = auditor.prioritize_backup_gaps(gaps)

        # Critical should be first, regardless of gap duration
        assert prioritized_gaps[0].criticality == CriticalityLevel.CRITICAL

    def test_historical_compliance_tracking(self, auditor):
        """Test historical compliance score tracking."""
        from unittest.mock import mock_open

        # Mock historical data
        mock_data = [
            {"date": "2024-01-01", "compliance_score": 95.0},
            {"date": "2024-01-02", "compliance_score": 98.0},
            {"date": "2024-01-03", "compliance_score": 92.0},
        ]

        with (
            patch("scripts.backup_coverage_audit.Path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=json.dumps(mock_data))),
        ):

            historical_data = auditor.get_historical_compliance()

            assert len(historical_data) == 3
            assert all("compliance_score" in record for record in historical_data)

            # Test trend calculation
            trend = auditor.calculate_compliance_trend(historical_data)
            assert "direction" in trend
            assert "change_percentage" in trend


class TestRepositoryInfo:
    """Test repository information data structure."""

    def test_repository_info_creation(self):
        """Test repository info object creation."""
        repo = RepositoryInfo(
            name="test_repository",
            table_name="test_table",
            criticality=CriticalityLevel.CRITICAL,
            data_size_mb=100,
            last_backup=datetime.now(),
            backup_frequency="hourly",
            retention_required_days=90,
        )

        assert repo.name == "test_repository"
        assert repo.criticality == CriticalityLevel.CRITICAL
        assert repo.data_size_mb == 100

    def test_repository_info_is_backup_overdue(self):
        """Test backup overdue detection."""
        # Recent backup
        repo_recent = RepositoryInfo(
            name="recent_repo",
            criticality=CriticalityLevel.CRITICAL,
            last_backup=datetime.now() - timedelta(minutes=30),
            backup_frequency="hourly",
        )
        assert not repo_recent.is_backup_overdue()

        # Overdue backup
        repo_overdue = RepositoryInfo(
            name="overdue_repo",
            criticality=CriticalityLevel.CRITICAL,
            last_backup=datetime.now() - timedelta(hours=25),
            backup_frequency="hourly",
        )
        assert repo_overdue.is_backup_overdue()


class TestBackupCoverageReport:
    """Test backup coverage report data structure."""

    def test_coverage_report_creation(self):
        """Test coverage report object creation."""
        report = BackupCoverageReport(
            total_repositories=10,
            compliant_repositories=8,
            compliance_score=80.0,
            backup_gaps=[],
            timestamp=datetime.now(),
            status=ComplianceStatus.COMPLIANT,
        )

        assert report.total_repositories == 10
        assert report.compliance_score == 80.0
        assert report.status == ComplianceStatus.COMPLIANT

    def test_coverage_report_compliance_status(self):
        """Test compliance status determination."""
        # High compliance
        report_high = BackupCoverageReport(total_repositories=5, compliant_repositories=5, compliance_score=100.0)
        assert report_high.determine_status() == ComplianceStatus.COMPLIANT

        # Medium compliance
        report_medium = BackupCoverageReport(total_repositories=5, compliant_repositories=4, compliance_score=80.0)
        assert report_medium.determine_status() == ComplianceStatus.WARNING

        # Low compliance
        report_low = BackupCoverageReport(total_repositories=5, compliant_repositories=3, compliance_score=60.0)
        assert report_low.determine_status() == ComplianceStatus.NON_COMPLIANT


if __name__ == "__main__":
    pytest.main([__file__])
