"""
Unit tests for base reporting classes.

Tests ReportConfig, ReportGenerator base class, and ReportDataProcessor.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from tools.pre_audit.reporting.base import (
    ReportConfig,
    ReportDataProcessor,
    ReportGenerator,
    SecurityLevel,
)


class TestReportConfig:
    """Test suite for ReportConfig class."""

    @pytest.fixture
    def base_config(self):
        """Create base configuration from auditor."""
        config = MagicMock()
        # Use tempfile for test directory
        temp_dir = tempfile.mkdtemp(prefix="test_reports_")
        config.reports_dir = Path(temp_dir)
        return config

    def test_report_config_defaults(self):
        """Test ReportConfig with default values."""
        config = ReportConfig()

        assert config.enable_charts is True
        assert config.include_recommendations is True
        assert config.include_executive_summary is True
        assert config.max_violations_per_page == 100
        assert config.security_level == SecurityLevel.INTERNAL
        assert config.export_formats == ["html", "json"]

    def test_report_config_with_base_config(self, base_config):
        """Test ReportConfig inheriting from base config."""
        config = ReportConfig(base_config=base_config)

        assert config.output_dir == base_config.reports_dir

    def test_report_config_creates_output_dir(self):
        """Test that output directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "new_reports"
            config = ReportConfig(output_dir=output_dir)

            assert output_dir.exists()
            assert config.output_dir == output_dir

    def test_report_config_validates_security_level(self):
        """Test security level validation."""
        # Valid string should be converted to enum
        config = ReportConfig(security_level="public")
        assert config.security_level == SecurityLevel.PUBLIC

        # Invalid string should raise error
        with pytest.raises(ValueError) as exc_info:
            ReportConfig(security_level="invalid")
        assert "Invalid security level" in str(exc_info.value)

    def test_report_config_hotspot_settings(self):
        """Test hotspot-specific configuration."""
        config = ReportConfig(
            include_hotspots=True,
            hotspot_detail_level="minimal",
            statistical_confidence_threshold=0.99,
            temporal_window_months=12,
        )

        assert config.include_hotspots is True
        assert config.hotspot_detail_level == "minimal"
        assert config.statistical_confidence_threshold == 0.99
        assert config.temporal_window_months == 12


class ConcreteReportGenerator(ReportGenerator):
    """Concrete implementation for testing."""

    def generate(self, audit_data):
        return self._get_output_path("test")

    def validate_data(self, audit_data):
        return True

    def _generate_hotspot_section(self, hotspot_data):
        return "Test hotspot section"


class TestReportGenerator:
    """Test suite for ReportGenerator base class."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def config(self, temp_dir):
        """Create test configuration."""
        return ReportConfig(output_dir=temp_dir)

    @pytest.fixture
    def generator(self, config):
        """Create concrete generator instance."""
        return ConcreteReportGenerator(config)

    def test_generator_initialization(self, generator, config):
        """Test generator initialization."""
        assert generator.config == config
        assert generator.logger is not None

    def test_generator_validates_config(self, temp_dir):
        """Test that generator validates configuration."""
        # Create config with non-existent directory
        bad_dir = temp_dir / "nonexistent"
        config = ReportConfig()
        config.output_dir = bad_dir

        with pytest.raises(ValueError) as exc_info:
            ConcreteReportGenerator(config)
        assert "does not exist" in str(exc_info.value)

    def test_generator_checks_write_permissions(self, temp_dir):
        """Test that generator checks write permissions."""
        # Make directory read-only
        config = ReportConfig(output_dir=temp_dir)

        # Mock the write test to fail
        with patch("pathlib.Path.touch", side_effect=PermissionError("No write access")):
            with pytest.raises(PermissionError) as exc_info:
                ConcreteReportGenerator(config)
            assert "Cannot write to output directory" in str(exc_info.value)

    def test_sanitize_filename(self, generator):
        """Test filename sanitization."""
        test_cases = [
            ("report.pdf", "report.pdf"),
            ("my report.pdf", "my_report.pdf"),
            (
                "../../../etc/passwd",
                "__________etc_passwd",
            ),  # Path traversal properly sanitized
            (".hidden", "hidden"),
            ("a" * 300 + ".pdf", "a" * 250),  # Check without extension
        ]

        for input_name, expected_start in test_cases:
            result = generator._sanitize_filename(input_name)
            assert result.startswith(expected_start)
            assert len(result) <= 255

    def test_sanitize_filename_prevents_traversal(self, generator):
        """Test that path traversal attempts are sanitized."""
        dangerous_names = [
            "../../etc/passwd",
            "..\\windows\\system32",
            "file/with/slashes",
        ]

        for name in dangerous_names:
            result = generator._sanitize_filename(name)
            # Ensure dangerous characters are removed
            assert ".." not in result
            assert "/" not in result
            assert "\\" not in result
            assert len(result) <= 255

    def test_get_output_path(self, generator):
        """Test output path generation."""
        path = generator._get_output_path("pdf")

        assert path.parent == generator.config.output_dir
        assert path.suffix == ".pdf"
        assert "adr_audit_report_" in path.name
        # Check timestamp format YYYYMMDD_HHMMSS
        assert len(path.stem.split("_")[-2]) == 8  # Date part
        assert len(path.stem.split("_")[-1]) == 6  # Time part

    def test_generate_report_id(self, generator):
        """Test unique report ID generation."""
        id1 = generator._generate_report_id()
        id2 = generator._generate_report_id()

        assert id1 != id2
        assert len(id1) == 36  # UUID4 format
        assert "-" in id1


class TestReportDataProcessor:
    """Test suite for ReportDataProcessor class."""

    @pytest.fixture
    def processor(self):
        """Create ReportDataProcessor instance."""
        return ReportDataProcessor()

    @pytest.fixture
    def sample_audit_results(self):
        """Create sample audit results."""
        return {
            "audit_metadata": {
                "audit_version": "2.0.0",
                "repository_path": "/path/to/repo",
                "total_files_analyzed": 150,
                "execution_time_seconds": 45.2,
                "analysis_timestamp": "2024-01-15T10:30:00Z",
            },
            "overall_compliance_score": 75.5,
            "all_violations": [
                {
                    "file_path": "src/auth.py",
                    "line_number": 42,
                    "adr_id": "ADR-002",
                    "risk_level": "critical",
                    "message": "Missing authentication",
                    "technical_debt_hours": 4,
                },
                {
                    "file_path": "src/api.py",
                    "line_number": 100,
                    "adr_id": "ADR-001",
                    "risk_level": "high",
                    "message": "API versioning required",
                    "technical_debt_hours": 2,
                },
            ],
            "architectural_hotspots": [
                {
                    "file_path": "src/auth.py",
                    "risk_score": 85,
                    "churn_score": 45,
                    "complexity_score": 78,
                }
            ],
            "recommendations": [
                "Implement centralized authentication",
                "Add API versioning",
            ],
        }

    def test_prepare_report_data(self, processor, sample_audit_results):
        """Test complete report data preparation."""
        result = processor.prepare_report_data(sample_audit_results)

        assert "metadata" in result
        assert "summary" in result
        assert "violations" in result
        assert "hotspots" in result
        assert "recommendations" in result
        assert "trends" in result
        assert "metrics" in result

    def test_generate_metadata(self, processor, sample_audit_results):
        """Test metadata generation."""
        metadata = processor._generate_metadata(sample_audit_results)

        assert metadata["audit_version"] == "2.0.0"
        assert metadata["repository_path"] == "/path/to/repo"
        assert metadata["total_files_analyzed"] == 150
        assert metadata["analysis_duration"] == 45.2
        assert metadata["report_generator_version"] == "2.0.0"
        assert len(metadata["report_id"]) == 36  # UUID

    def test_generate_summary(self, processor, sample_audit_results):
        """Test summary generation."""
        summary = processor._generate_summary(sample_audit_results)

        assert summary["compliance_score"] == 75.5
        assert summary["total_violations"] == 2
        assert summary["critical_violations"] == 1
        assert summary["high_violations"] == 1
        assert summary["medium_violations"] == 0
        assert summary["low_violations"] == 0
        assert summary["technical_debt_hours"] == 6
        assert summary["technical_debt_days"] == 0.75
        assert len(summary["key_findings"]) > 0
        assert summary["risk_assessment"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_process_violations(self, processor, sample_audit_results):
        """Test violation processing and enrichment."""
        violations = processor._process_violations(sample_audit_results)

        assert len(violations) == 2
        # Should be sorted by risk level (critical first)
        assert violations[0]["risk_level"] == "critical"
        assert violations[1]["risk_level"] == "high"

        # Check enrichment
        assert "category" in violations[0]
        assert "impact_assessment" in violations[0]
        assert "fix_complexity" in violations[0]

    def test_process_hotspots(self, processor, sample_audit_results):
        """Test hotspot processing."""
        hotspots = processor._process_hotspots(sample_audit_results)

        assert len(hotspots) == 1
        assert hotspots[0]["file_path"] == "src/auth.py"
        assert "risk_category" in hotspots[0]
        assert hotspots[0]["risk_category"] == "Critical"  # 85 > 80

    def test_enhance_recommendations(self, processor, sample_audit_results):
        """Test recommendation enhancement."""
        recommendations = processor._enhance_recommendations(sample_audit_results)

        assert len(recommendations) == 2
        for rec in recommendations:
            assert "id" in rec
            assert "description" in rec
            assert "priority" in rec
            assert "category" in rec
            assert "estimated_effort" in rec
            assert "implementation_steps" in rec
            assert len(rec["implementation_steps"]) == 5

    def test_calculate_trends(self, processor, sample_audit_results):
        """Test trend calculation."""
        trends = processor._calculate_trends(sample_audit_results)

        assert "violations_by_adr" in trends
        assert "violations_by_file" in trends
        assert trends["total_unique_adrs"] == 2
        assert trends["total_affected_files"] == 2

    def test_calculate_metrics(self, processor, sample_audit_results):
        """Test metrics calculation."""
        metrics = processor._calculate_metrics(sample_audit_results)

        assert metrics["total_violations"] == 2
        assert metrics["total_hotspots"] == 1
        assert metrics["files_with_violations"] == 2
        assert metrics["average_violations_per_file"] == 1.0
        assert metrics["compliance_percentage"] == 75.5

    def test_extract_key_findings(self, processor, sample_audit_results):
        """Test key findings extraction."""
        findings = processor._extract_key_findings(sample_audit_results)

        assert len(findings) >= 2
        assert any("compliance score" in f for f in findings)
        assert any("critical violations" in f for f in findings)

    def test_assess_overall_risk(self, processor, sample_audit_results):
        """Test overall risk assessment."""
        # Test different scenarios
        test_cases = [
            (
                {
                    "overall_compliance_score": 45,
                    "all_violations": [{"risk_level": "critical"}] * 15,
                },
                "CRITICAL",
            ),
            (
                {
                    "overall_compliance_score": 65,
                    "all_violations": [{"risk_level": "critical"}] * 7,
                },
                "HIGH",
            ),
            (
                {
                    "overall_compliance_score": 80,
                    "all_violations": [{"risk_level": "critical"}] * 2,
                },
                "MEDIUM",
            ),
            ({"overall_compliance_score": 90, "all_violations": []}, "LOW"),
        ]

        for audit_data, expected_risk in test_cases:
            risk = processor._assess_overall_risk(audit_data)
            assert risk == expected_risk

    def test_categorize_violation(self, processor):
        """Test violation categorization."""
        test_cases = [
            ({"adr_id": "ADR-002"}, "Authentication"),
            ({"adr_id": "ADR-003"}, "Authorization"),
            ({"adr_id": "ADR-001"}, "API Design"),
            ({"adr_id": "ADR-008"}, "Logging/Auditing"),
            ({"adr_id": "ADR-005"}, "Rate Limiting"),
            ({"adr_id": "ADR-F1.1"}, "Template Security"),
            ({"adr_id": "ADR-999"}, "General"),
        ]

        for violation, expected_category in test_cases:
            category = processor._categorize_violation(violation)
            assert category == expected_category

    def test_empty_audit_results(self, processor):
        """Test handling of empty audit results."""
        empty_results = {
            "all_violations": [],
            "architectural_hotspots": [],
            "recommendations": [],
        }

        result = processor.prepare_report_data(empty_results)

        assert result["summary"]["total_violations"] == 0
        assert result["summary"]["technical_debt_days"] == 0
        assert len(result["violations"]) == 0
        assert len(result["hotspots"]) == 0
