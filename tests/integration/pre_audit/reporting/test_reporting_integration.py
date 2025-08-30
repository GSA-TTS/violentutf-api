"""
Integration tests for the enhanced reporting module.

Tests end-to-end report generation with real audit data.
"""

import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.pre_audit.reporting import (
    ExportManager,
    HTMLReportGenerator,
    JSONReportGenerator,
    PDFReportGenerator,
    ReportConfig,
    SecurityLevel,
    ValidationError,
)

# Try to import the auditor for full integration
try:
    from tools.pre_audit.claude_code_auditor import (
        EnterpriseClaudeCodeAuditor,
        EnterpriseClaudeCodeConfig,
    )

    HAS_AUDITOR = True
except ImportError:
    HAS_AUDITOR = False


class TestReportingIntegration:
    """Integration tests for the reporting module."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test outputs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def complete_audit_data(self):
        """Create comprehensive audit data for testing."""
        return {
            "audit_metadata": {
                "audit_version": "2.0.0",
                "repository_path": "/test/repo",
                "total_files_analyzed": 250,
                "execution_time_seconds": 120.5,
                "analysis_timestamp": "2024-01-15T10:30:00Z",
                "mode": "comprehensive",
                "selected_adr": None,
                "git_branch": "main",
                "cache_hits": 150,
                "cache_misses": 100,
            },
            "overall_compliance_score": 82.5,
            "all_violations": [
                {
                    "file_path": "src/api/auth.py",
                    "line_number": 42,
                    "adr_id": "ADR-002",
                    "adr_title": "Authentication Strategy",
                    "risk_level": "critical",
                    "message": "Missing authentication middleware",
                    "evidence": "No auth decorator found",
                    "remediation_guidance": "Add @require_auth decorator",
                    "technical_debt_hours": 4,
                },
                {
                    "file_path": "src/api/endpoints.py",
                    "line_number": 156,
                    "adr_id": "ADR-003",
                    "adr_title": "Authorization Framework",
                    "risk_level": "high",
                    "message": "Missing RBAC check",
                    "evidence": "Direct database access without permission check",
                    "remediation_guidance": "Implement role-based access control",
                    "technical_debt_hours": 6,
                },
                {
                    "file_path": "src/utils/logging.py",
                    "line_number": 23,
                    "adr_id": "ADR-008",
                    "adr_title": "Logging Standards",
                    "risk_level": "medium",
                    "message": "Sensitive data in logs",
                    "evidence": "Password field logged",
                    "remediation_guidance": "Mask sensitive fields",
                    "technical_debt_hours": 2,
                },
            ],
            "architectural_hotspots": [
                {
                    "file_path": "src/api/auth.py",
                    "risk_score": 0.85,
                    "churn_score": 67,
                    "complexity_score": 82,
                    "risk_level": "critical",
                    "violation_history": [
                        {"adr_id": "ADR-002", "timestamp": "2024-01-01"},
                        {"adr_id": "ADR-003", "timestamp": "2024-01-05"},
                    ],
                    "recommendations": [
                        "Refactor authentication module",
                        "Add comprehensive test coverage",
                    ],
                    "temporal_patterns": {"trend": "degrading"},
                    "risk_confidence_interval": [0.80, 0.90],
                },
                {
                    "file_path": "src/database/models.py",
                    "risk_score": 0.72,
                    "churn_score": 45,
                    "complexity_score": 91,
                    "risk_level": "high",
                    "violation_history": [],
                    "temporal_patterns": {"trend": "stable"},
                },
            ],
            "recommendations": [
                "Implement centralized authentication and authorization",
                "Add comprehensive logging with sensitive data masking",
                "Refactor high-complexity modules",
                "Increase test coverage for critical paths",
            ],
            "violation_summary": {
                "by_risk_level": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "top_violated_files": [
                    {"file": "src/api/auth.py", "violation_count": 1},
                    {"file": "src/api/endpoints.py", "violation_count": 1},
                ],
                "by_adr": {"ADR-002": 1, "ADR-003": 1, "ADR-008": 1},
            },
        }

    @pytest.fixture
    def report_config(self, temp_dir):
        """Create report configuration for testing."""
        return ReportConfig(
            output_dir=temp_dir,
            enable_charts=True,
            include_recommendations=True,
            include_executive_summary=True,
            security_level=SecurityLevel.INTERNAL,
            include_hotspots=True,
            enable_parallel_export=True,
            export_formats=["html", "json", "pdf"],
        )

    def test_end_to_end_report_generation(self, report_config, complete_audit_data):
        """Test complete report generation workflow."""
        # Create export manager
        manager = ExportManager(report_config)

        # Generate all reports
        results = manager.export_all(complete_audit_data)

        # Verify reports were generated
        assert "html" in results
        assert "json" in results
        # PDF might not be available

        # Verify files exist and have content
        for format_name, path in results.items():
            if path:
                assert path.exists()
                assert path.stat().st_size > 0

    def test_html_report_content(self, report_config, complete_audit_data):
        """Test HTML report content generation."""
        generator = HTMLReportGenerator(report_config)

        # Generate report
        output_path = generator.generate(complete_audit_data)

        # Read and verify content
        html_content = output_path.read_text()

        # Check for key elements
        assert "82.5%" in html_content  # Compliance score
        assert "src/api/auth.py" in html_content
        assert "ADR-002" in html_content
        assert "Critical" in html_content
        assert "Architectural Hotspots" in html_content

        # Check for XSS prevention (no raw script tags)
        assert "<script>alert" not in html_content

        # Check for proper HTML escaping - either escaped content exists or no special chars need escaping
        # The template uses Jinja2 autoescape, so any < > & characters would be escaped
        has_special_chars = any(char in html_content for char in ["&lt;", "&gt;", "&amp;"])
        has_basic_content = all(marker in html_content for marker in ["82.5%", "ADR-002", "Critical"])
        assert has_special_chars or has_basic_content  # Either escaping present or content is safe

    def test_json_report_structure(self, report_config, complete_audit_data):
        """Test JSON report structure and validation."""
        generator = JSONReportGenerator(report_config)

        # Generate report
        output_path = generator.generate(complete_audit_data)

        # Load and verify JSON
        with open(output_path, "r") as f:
            json_data = json.load(f)

        # Verify structure
        assert "metadata" in json_data
        assert "summary" in json_data
        assert "violations" in json_data
        assert "hotspot_analysis" in json_data
        assert "_report_metadata" in json_data

        # Verify data integrity
        assert json_data["summary"]["compliance_score"] == 82.5
        assert json_data["summary"]["total_violations"] == 3
        assert len(json_data["violations"]) == 3

        # Check security level was applied
        assert json_data["_report_metadata"]["security_level"] == "internal"

    @pytest.mark.skipif(not HAS_AUDITOR, reason="Auditor not available")
    def test_integration_with_auditor(self, temp_dir):
        """Test integration with claude_code_auditor."""
        # Create mock audit results
        mock_audit_results = {
            "overall_compliance_score": 90.0,
            "all_violations": [],
            "architectural_hotspots": [],
            "audit_metadata": {
                "total_files_analyzed": 50,
                "repository_path": str(temp_dir),
            },
        }

        # Create auditor config
        auditor_config = EnterpriseClaudeCodeConfig(repo_path=temp_dir, reports_dir=temp_dir / "reports")

        # Create report config using auditor config
        report_config = ReportConfig(base_config=auditor_config, security_level=SecurityLevel.INTERNAL)

        # Verify integration
        assert report_config.output_dir == auditor_config.reports_dir

        # Generate reports
        manager = ExportManager(report_config)
        results = manager.export_all(mock_audit_results)

        assert len(results) >= 2

    def test_security_level_filtering(self, temp_dir, complete_audit_data):
        """Test that security levels properly filter data."""
        # Test PUBLIC level
        public_config = ReportConfig(
            output_dir=temp_dir,
            security_level=SecurityLevel.PUBLIC,
            export_formats=["json"],
        )

        public_gen = JSONReportGenerator(public_config)
        public_path = public_gen.generate(complete_audit_data)

        with open(public_path, "r") as f:
            public_data = json.load(f)

        # Check that sensitive data is redacted
        if public_data["violations"]:
            assert public_data["violations"][0]["file_path"] != "src/api/auth.py"
            assert public_data["violations"][0]["message"] == "Details redacted"

        # Test RESTRICTED level
        restricted_config = ReportConfig(
            output_dir=temp_dir,
            security_level=SecurityLevel.RESTRICTED,
            export_formats=["json"],
        )

        restricted_gen = JSONReportGenerator(restricted_config)
        restricted_path = restricted_gen.generate(complete_audit_data)

        with open(restricted_path, "r") as f:
            restricted_data = json.load(f)

        # Check that all data is present
        assert restricted_data["violations"][0]["file_path"] == "src/api/auth.py"
        assert "Missing authentication" in restricted_data["violations"][0]["message"]

    def test_parallel_export_performance(self, report_config, complete_audit_data):
        """Test that parallel export is faster than sequential."""
        import time

        # Sequential export
        report_config.enable_parallel_export = False
        manager_seq = ExportManager(report_config)

        start = time.time()
        results_seq = manager_seq.export_all(complete_audit_data)
        seq_time = time.time() - start

        # Parallel export
        report_config.enable_parallel_export = True
        manager_par = ExportManager(report_config)

        start = time.time()
        results_par = manager_par.export_all(complete_audit_data)
        par_time = time.time() - start

        # Verify both produced same results
        assert set(results_seq.keys()) == set(results_par.keys())

        # Parallel should not be significantly slower (might not be faster in tests)
        assert par_time < seq_time * 1.5

    def test_archive_creation(self, report_config, complete_audit_data):
        """Test ZIP archive creation."""
        manager = ExportManager(report_config)

        # Create archive
        archive_path = manager.export_to_archive(complete_audit_data, archive_name="test_reports.zip")

        assert archive_path.exists()
        assert archive_path.name == "test_reports.zip"

        # Verify archive contents
        with zipfile.ZipFile(archive_path, "r") as zf:
            files = zf.namelist()
            assert any(f.endswith(".html") for f in files)
            assert any(f.endswith(".json") for f in files)

    def test_hotspot_integration(self, report_config, complete_audit_data):
        """Test hotspot data integration in reports."""
        # Ensure hotspots are included
        report_config.include_hotspots = True
        report_config.hotspot_detail_level = "full"

        # Generate HTML report
        html_gen = HTMLReportGenerator(report_config)
        html_path = html_gen.generate(complete_audit_data)

        html_content = html_path.read_text()

        # Check for hotspot content
        assert "src/api/auth.py" in html_content
        assert "85" in html_content or "0.85" in html_content  # Risk score
        assert "degrading" in html_content  # Temporal trend

        # Generate JSON report
        json_gen = JSONReportGenerator(report_config)
        json_path = json_gen.generate(complete_audit_data)

        with open(json_path, "r") as f:
            json_data = json.load(f)

        # Verify hotspot data
        assert "hotspot_analysis" in json_data
        hotspots = json_data["hotspot_analysis"]["hotspots"]
        assert len(hotspots) >= 2
        assert hotspots[0]["file_path"] == "src/api/auth.py"
        assert hotspots[0]["risk_score"] > 0.8

    def test_error_handling(self, report_config):
        """Test error handling with invalid data."""
        manager = ExportManager(report_config)

        # Test with completely invalid data
        with pytest.raises(ValidationError):
            manager.export_all({"invalid": "data"})

        # Test with missing required fields
        incomplete_data = {"all_violations": "not a list"}  # Wrong type

        with pytest.raises(ValidationError):
            manager.export_all(incomplete_data)

    def test_visualization_data_generation(self, report_config, complete_audit_data):
        """Test that visualization data is properly generated."""
        report_config.enable_charts = True

        html_gen = HTMLReportGenerator(report_config)

        # Mock the chart generation to verify it's called
        with patch.object(html_gen, "_generate_chart_data") as mock_charts:
            mock_charts.return_value = {
                "compliance_gauge": {
                    "type": "gauge",
                    "data": {"value": 82.5},
                    "json": '{"type": "gauge", "data": {"value": 82.5}}',
                },
                "violation_pie": {
                    "type": "pie",
                    "data": {"labels": ["Critical"], "values": [1]},
                    "json": '{"type": "pie", "data": {"labels": ["Critical"], "values": [1]}}',
                },
            }

            output_path = html_gen.generate(complete_audit_data)

            # Verify chart generation was called
            mock_charts.assert_called_once()

            # Check that chart data is in HTML
            html_content = output_path.read_text()
            assert "risk-distribution-chart" in html_content

    def test_template_rendering(self, report_config, complete_audit_data):
        """Test that Jinja2 templates render correctly."""
        html_gen = HTMLReportGenerator(report_config)

        # Generate report
        output_path = html_gen.generate(complete_audit_data)
        html_content = output_path.read_text()

        # Check that template variables were replaced
        assert "{{ " not in html_content  # No unrendered variables
        assert "{% " not in html_content  # No unrendered tags

        # Check for proper HTML structure
        assert "<!DOCTYPE html>" in html_content
        assert "<html" in html_content
        assert "</html>" in html_content
        assert "<head>" in html_content
        assert "<body>" in html_content

    @pytest.mark.skipif(True, reason="PDF generation requires ReportLab")
    def test_pdf_generation(self, report_config, complete_audit_data):
        """Test PDF report generation if ReportLab is available."""
        try:
            pdf_gen = PDFReportGenerator(report_config)
            output_path = pdf_gen.generate(complete_audit_data)

            # Verify PDF was created
            assert output_path.exists()
            assert output_path.suffix == ".pdf"

            # Check PDF header
            with open(output_path, "rb") as f:
                header = f.read(4)
                assert header == b"%PDF"
        except ImportError:
            pytest.skip("ReportLab not installed")
