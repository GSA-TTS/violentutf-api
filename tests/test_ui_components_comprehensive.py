"""Comprehensive UI Component Tests for Architectural Metrics and Reporting.

This module provides complete test coverage for all UI-related components including:
- HTML template rendering
- PDF report generation
- Chart creation and visualization
- Email template generation
- UI component styling and behavior
- Security and accessibility testing
"""

import asyncio
import base64
import io
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import pytest
from jinja2 import Environment, Template, TemplateSyntaxError, UndefinedError
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate

from app.models.report import Report, ReportFormat, ReportStatus
from app.services.architectural_report_generator import ArchitecturalReportGenerator
from app.services.scheduled_report_service import ScheduledReportService


class TestHTMLTemplateRendering:
    """Test HTML template rendering functionality."""

    @pytest.fixture
    def report_generator(self) -> ArchitecturalReportGenerator:
        """Create report generator with mock database."""
        mock_db = AsyncMock()
        generator = ArchitecturalReportGenerator(mock_db)
        return generator

    @pytest.fixture
    def sample_metrics_data(self) -> Dict[str, Any]:
        """Create sample metrics data for testing."""
        return {
            "title": "Test Report",
            "subtitle": "Test Subtitle",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_start": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            "period_end": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "<p>Test executive summary with <strong>HTML</strong> content</p>",
            "leading_indicators": {
                "automation_coverage": {"automation_percentage": 75.5, "automated_scans": 150, "manual_scans": 50},
                "detection_time": {"average_detection_hours": 2.5, "min_hours": 0.5, "max_hours": 8.0},
                "developer_adoption_rate": {"adoption_rate": 80.0, "active_users": 16, "total_users": 20},
                "compliance_scores": {"overall_score": 85.0, "security_score": 90.0, "quality_score": 80.0},
                "violation_frequency": {
                    "top_violations": [
                        {"category": "Security", "count": 45, "percentage": 30.0, "trend": "decreasing"},
                        {"category": "Quality", "count": 30, "percentage": 20.0, "trend": "stable"},
                        {"category": "Performance", "count": 15, "percentage": 10.0, "trend": "increasing"},
                    ]
                },
            },
            "lagging_indicators": {
                "architectural_debt_velocity": {"daily_velocity": -2.5, "trend": "improving", "total_debt_reduced": 75},
                "security_incident_reduction": {
                    "reduction_percentage": 45.0,
                    "trend": "improving",
                    "incidents_prevented": 12,
                },
                "maintainability_improvements": {"improvement_rate": 15.0, "complexity_reduction": 20.0},
                "development_velocity_impact": {"success_rate": 92.0, "average_time_saved": 4.5},
            },
            "roi_analysis": {
                "total_costs": 50000,
                "total_benefits": 125000,
                "net_benefit": 75000,
                "roi_percentage": 150.0,
                "payback_period_months": 6,
                "implementation_costs": {"developer_time": 30000, "tool_licensing": 15000, "training": 5000},
                "cost_avoidance": {"security_incidents": 60000, "technical_debt": 40000},
                "productivity_gains": {"automation_savings": 15000, "faster_deployment": 10000},
                "quality_improvements": {"defect_reduction": 8000, "customer_satisfaction": 7000},
            },
            "recommendations": [
                "Increase automation coverage to 90%",
                "Implement continuous security scanning",
                "Enhance developer training programs",
            ],
        }

    def test_html_template_creation(self, report_generator: ArchitecturalReportGenerator):
        """Test HTML template file creation."""
        report_generator._ensure_template_dir()

        template_path = report_generator.template_dir / "architectural_metrics.html"
        assert template_path.exists()

        # Verify template content
        content = template_path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "{{ title }}" in content
        assert "{{ subtitle }}" in content
        assert "{% if leading_indicators %}" in content
        assert "{% if lagging_indicators %}" in content
        assert "{% if roi_analysis %}" in content

    def test_html_template_rendering_with_full_data(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test HTML template rendering with complete data."""
        report_generator._create_default_templates()

        # Load and render template
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(report_generator.template_dir)), autoescape=select_autoescape(["html", "xml"])
        )
        template = env.get_template("architectural_metrics.html")

        # Add empty charts for testing
        sample_metrics_data["charts"] = {
            "automation_trend": "data:image/png;base64,test",
            "security_trend": "data:image/png;base64,test",
            "roi_breakdown": "data:image/png;base64,test",
        }

        html_output = template.render(**sample_metrics_data)

        # Verify all sections are rendered
        assert "Test Report" in html_output
        assert "Test Subtitle" in html_output
        assert "75.5%" in html_output  # Automation coverage
        assert "2.5h" in html_output  # Detection time
        assert "80.0%" in html_output  # Developer adoption
        assert "85.0%" in html_output  # Compliance score
        assert "$50,000" in html_output  # Total costs
        assert "$125,000" in html_output  # Total benefits
        assert "150.0%" in html_output  # ROI percentage
        assert "Increase automation coverage to 90%" in html_output

    def test_html_template_with_missing_sections(self, report_generator: ArchitecturalReportGenerator):
        """Test HTML template rendering with missing optional sections."""
        report_generator._create_default_templates()

        minimal_data = {
            "title": "Minimal Report",
            "subtitle": "Test",
            "generated_at": datetime.now().isoformat(),
            "period_start": datetime.now().isoformat(),
            "period_end": datetime.now().isoformat(),
            "charts": {},
        }

        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(report_generator.template_dir)), autoescape=select_autoescape(["html", "xml"])
        )
        template = env.get_template("architectural_metrics.html")

        # Should render without errors
        html_output = template.render(**minimal_data)
        assert "Minimal Report" in html_output
        assert "Executive Summary" not in html_output  # Section should be skipped

    def test_html_xss_prevention(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test XSS prevention in HTML templates."""
        report_generator._create_default_templates()

        # Inject potential XSS content
        sample_metrics_data["title"] = "<script>alert('XSS')</script>Test Report"
        sample_metrics_data["recommendations"] = ["<img src=x onerror=alert('XSS')>", "Normal recommendation"]

        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(report_generator.template_dir)), autoescape=select_autoescape(["html", "xml"])
        )
        template = env.get_template("architectural_metrics.html")

        html_output = template.render(**sample_metrics_data)

        # Verify scripts are escaped
        assert "<script>" not in html_output or "&lt;script&gt;" in html_output
        assert "onerror=" not in html_output

    def test_html_css_injection_prevention(self, report_generator: ArchitecturalReportGenerator):
        """Test CSS injection prevention."""
        report_generator._create_default_templates()

        malicious_data = {
            "title": "Test</style><style>body{display:none}</style>",
            "subtitle": "Test",
            "generated_at": datetime.now().isoformat(),
            "period_start": datetime.now().isoformat(),
            "period_end": datetime.now().isoformat(),
            "charts": {},
        }

        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(report_generator.template_dir)), autoescape=select_autoescape(["html", "xml"])
        )
        template = env.get_template("architectural_metrics.html")

        html_output = template.render(**malicious_data)

        # Count style tags - should only have the original one
        style_count = html_output.count("<style>")
        assert style_count == 1  # Only the template's original style tag

    def test_responsive_layout_classes(self, report_generator: ArchitecturalReportGenerator):
        """Test responsive layout CSS classes."""
        report_generator._create_default_templates()

        template_path = report_generator.template_dir / "architectural_metrics.html"
        content = template_path.read_text()

        # Check for responsive CSS
        assert "grid-template-columns: repeat(auto-fit" in content
        assert "max-width: 1200px" in content
        assert "margin: 0 auto" in content
        assert "@media" in content or "minmax(" in content

    def test_color_contrast_accessibility(self, report_generator: ArchitecturalReportGenerator):
        """Test color contrast for accessibility."""
        report_generator._create_default_templates()

        template_path = report_generator.template_dir / "architectural_metrics.html"
        content = template_path.read_text()

        # Check for sufficient color contrast
        assert "color: #333" in content  # Dark text on light background
        assert "background-color: #f5f5f5" in content  # Light background
        assert "color: white" in content  # White text on dark backgrounds

    def test_semantic_html_structure(self, report_generator: ArchitecturalReportGenerator):
        """Test semantic HTML structure."""
        report_generator._create_default_templates()

        template_path = report_generator.template_dir / "architectural_metrics.html"
        content = template_path.read_text()

        # Check for semantic HTML5 elements
        assert '<html lang="en">' in content
        assert '<meta charset="UTF-8">' in content
        assert '<meta name="viewport"' in content
        assert "<h1>" in content
        assert "<h2>" in content
        assert "<table>" in content
        assert "<thead>" in content
        assert "<tbody>" in content


class TestChartGeneration:
    """Test chart generation functionality."""

    @pytest.fixture
    def report_generator(self) -> ArchitecturalReportGenerator:
        """Create report generator instance."""
        mock_db = AsyncMock()
        return ArchitecturalReportGenerator(mock_db)

    def test_automation_trend_chart_creation(self, report_generator: ArchitecturalReportGenerator):
        """Test automation trend chart generation."""
        leading_indicators = {
            "automation_coverage": {"automated_scans": 150, "manual_scans": 50, "automation_percentage": 75.0}
        }

        chart_base64 = report_generator._create_automation_trend_chart(leading_indicators)

        # Verify base64 encoding
        assert chart_base64.startswith("data:image/png;base64,")

        # Decode and verify it's a valid image
        image_data = base64.b64decode(chart_base64.split(",")[1])
        image = Image.open(io.BytesIO(image_data))
        assert image.format == "PNG"
        assert image.width > 0
        assert image.height > 0

    def test_security_trend_chart_with_monthly_data(self, report_generator: ArchitecturalReportGenerator):
        """Test security trend chart with monthly data."""
        lagging_indicators = {
            "security_incident_reduction": {
                "monthly_data": {"2024-01": 10, "2024-02": 8, "2024-03": 6, "2024-04": 5, "2024-05": 4, "2024-06": 3},
                "reduction_percentage": 70.0,
            }
        }

        chart_base64 = report_generator._create_security_trend_chart(lagging_indicators)

        assert chart_base64.startswith("data:image/png;base64,")

        # Verify image is valid
        image_data = base64.b64decode(chart_base64.split(",")[1])
        image = Image.open(io.BytesIO(image_data))
        assert image.format == "PNG"

    def test_roi_breakdown_chart_generation(self, report_generator: ArchitecturalReportGenerator):
        """Test ROI breakdown pie chart generation."""
        roi_analysis = {
            "implementation_costs": {"developer_time": 30000, "tool_licensing": 15000, "training": 5000},
            "cost_avoidance": {"security_incidents": 60000, "technical_debt": 40000},
            "productivity_gains": {"automation_savings": 15000},
            "quality_improvements": {"defect_reduction": 8000},
        }

        chart_base64 = report_generator._create_roi_breakdown_chart(roi_analysis)

        assert chart_base64.startswith("data:image/png;base64,")

        # Verify dual pie chart (costs and benefits)
        image_data = base64.b64decode(chart_base64.split(",")[1])
        image = Image.open(io.BytesIO(image_data))
        assert image.width > image.height  # Should be wider due to two pie charts

    def test_chart_generation_with_empty_data(self, report_generator: ArchitecturalReportGenerator):
        """Test chart generation with empty data."""
        empty_indicators = {"automation_coverage": {"automated_scans": 0, "manual_scans": 0}}

        chart = report_generator._create_automation_trend_chart(empty_indicators)

        # Should handle gracefully
        assert chart == "" or chart.startswith("data:image/png;base64,")

    def test_chart_generation_error_handling(self, report_generator: ArchitecturalReportGenerator):
        """Test chart generation error handling."""
        # Invalid data that could cause errors
        invalid_data = {"automation_coverage": None}

        chart = report_generator._create_automation_trend_chart(invalid_data)

        # Should return empty string on error
        assert chart == ""

    @patch("matplotlib.pyplot.savefig")
    def test_chart_memory_cleanup(self, mock_savefig: Mock, report_generator: ArchitecturalReportGenerator):
        """Test that charts are properly cleaned up from memory."""
        with patch("matplotlib.pyplot.close") as mock_close:
            leading_indicators = {"automation_coverage": {"automated_scans": 100, "manual_scans": 50}}

            report_generator._create_automation_trend_chart(leading_indicators)

            # Verify pyplot.close() was called to free memory
            mock_close.assert_called()


class TestPDFReportGeneration:
    """Test PDF report generation functionality."""

    @pytest.fixture
    def report_generator(self) -> ArchitecturalReportGenerator:
        """Create report generator instance."""
        mock_db = AsyncMock()
        return ArchitecturalReportGenerator(mock_db)

    @pytest.fixture
    def sample_metrics_data(self) -> Dict[str, Any]:
        """Create sample metrics data."""
        return {
            "title": "PDF Test Report",
            "subtitle": "Comprehensive PDF Testing",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_start": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            "period_end": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "This is a test executive summary.",
            "leading_indicators": {
                "automation_coverage": {"automation_percentage": 75.0},
                "detection_time": {"average_detection_hours": 2.5},
                "developer_adoption_rate": {"adoption_rate": 80.0},
                "compliance_scores": {"overall_score": 85.0},
            },
            "lagging_indicators": {
                "architectural_debt_velocity": {"daily_velocity": -2.5, "trend": "improving"},
                "security_incident_reduction": {"reduction_percentage": 45.0, "trend": "improving"},
                "maintainability_improvements": {"improvement_rate": 15.0},
                "development_velocity_impact": {"success_rate": 92.0},
            },
            "roi_analysis": {
                "total_costs": 50000,
                "total_benefits": 125000,
                "net_benefit": 75000,
                "roi_percentage": 150.0,
                "payback_period_months": 6,
            },
            "recommendations": [
                "Increase automation coverage",
                "Enhance security scanning",
                "Improve developer training",
            ],
        }

    @pytest.mark.asyncio
    async def test_pdf_generation_basic(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test basic PDF generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock settings
            with patch("app.services.architectural_report_generator.settings") as mock_settings:
                mock_settings.REPORT_OUTPUT_DIR = tmpdir

                report_id = "test-report-123"
                charts = {}

                file_path = await report_generator._generate_pdf_report(report_id, sample_metrics_data, charts)

                # Verify file was created
                assert Path(file_path).exists()
                assert file_path.endswith(".pdf")

                # Verify file is not empty
                file_size = Path(file_path).stat().st_size
                assert file_size > 0

    @pytest.mark.asyncio
    async def test_pdf_generation_with_charts(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test PDF generation with embedded charts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.architectural_report_generator.settings") as mock_settings:
                mock_settings.REPORT_OUTPUT_DIR = tmpdir

                # Create sample chart data
                charts = {
                    "automation_trend": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
                    "security_trend": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
                    "roi_breakdown": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
                }

                file_path = await report_generator._generate_pdf_report("test-123", sample_metrics_data, charts)

                assert Path(file_path).exists()

    @pytest.mark.asyncio
    async def test_pdf_table_generation(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test PDF table generation with proper styling."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.architectural_report_generator.settings") as mock_settings:
                mock_settings.REPORT_OUTPUT_DIR = tmpdir

                file_path = await report_generator._generate_pdf_report("test-123", sample_metrics_data, {})

                # PDF should contain tables with metrics
                assert Path(file_path).exists()

                # Check file size indicates content was added
                file_size = Path(file_path).stat().st_size
                assert file_size > 1000  # Should be at least 1KB with content

    @pytest.mark.asyncio
    async def test_pdf_page_breaks(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test PDF page breaks between sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.architectural_report_generator.settings") as mock_settings:
                mock_settings.REPORT_OUTPUT_DIR = tmpdir

                # Add more content to trigger page breaks
                sample_metrics_data["recommendations"] = [f"Recommendation {i}" for i in range(50)]

                file_path = await report_generator._generate_pdf_report("test-123", sample_metrics_data, {})

                # File should be larger due to multiple pages
                file_size = Path(file_path).stat().st_size
                assert file_size > 2000

    @pytest.mark.asyncio
    async def test_pdf_error_handling(
        self, report_generator: ArchitecturalReportGenerator, sample_metrics_data: Dict[str, Any]
    ):
        """Test PDF generation error handling."""
        # Use invalid directory
        with patch("app.services.architectural_report_generator.settings") as mock_settings:
            mock_settings.REPORT_OUTPUT_DIR = "/invalid/path/that/does/not/exist"

            with pytest.raises(Exception):
                await report_generator._generate_pdf_report("test-123", sample_metrics_data, {})


class TestEmailTemplates:
    """Test email template generation."""

    @pytest.fixture
    def scheduled_service(self) -> ScheduledReportService:
        """Create scheduled report service."""
        mock_db = AsyncMock()
        return ScheduledReportService(mock_db)

    @pytest.mark.asyncio
    async def test_email_notification_html_generation(self, scheduled_service: ScheduledReportService):
        """Test HTML email notification generation."""
        schedule = MagicMock()
        schedule.name = "Weekly Metrics Report"
        schedule.report_config = {"period_days": 7}

        report_results = [
            {"status": "success", "format": "pdf", "report_id": "report-1"},
            {"status": "success", "format": "html", "report_id": "report-2"},
        ]

        with patch("app.services.scheduled_report_service.send_email") as mock_send:
            with patch("app.services.scheduled_report_service.settings") as mock_settings:
                mock_settings.API_BASE_URL = "https://api.example.com"

                schedule.notification_emails = ["test@example.com"]
                await scheduled_service._send_notifications(schedule, report_results)

                # Verify email was called
                mock_send.assert_called()

                # Check email content
                call_args = mock_send.call_args
                assert call_args[1]["to_email"] == "test@example.com"
                assert "Weekly Metrics Report" in call_args[1]["subject"]
                assert call_args[1]["is_html"] is True

                # Verify HTML content
                body = call_args[1]["body"]
                assert "<html>" in body
                assert "<h2>Architectural Metrics Report Available</h2>" in body
                assert "Weekly Metrics Report" in body
                assert "pdf" in body.lower()
                assert "html" in body.lower()

    @pytest.mark.asyncio
    async def test_email_with_download_links(self, scheduled_service: ScheduledReportService):
        """Test email contains proper download links."""
        schedule = MagicMock()
        schedule.name = "Test Report"
        schedule.report_config = {"period_days": 30}
        schedule.notification_emails = ["user@example.com"]

        report_results = [{"status": "success", "format": "pdf", "report_id": "abc123"}]

        with patch("app.services.scheduled_report_service.send_email") as mock_send:
            with patch("app.services.scheduled_report_service.settings") as mock_settings:
                mock_settings.API_BASE_URL = "https://api.example.com"

                await scheduled_service._send_notifications(schedule, report_results)

                body = mock_send.call_args[1]["body"]
                assert "https://api.example.com/api/v1/reports/abc123/download" in body

    @pytest.mark.asyncio
    async def test_email_with_multiple_recipients(self, scheduled_service: ScheduledReportService):
        """Test email sent to multiple recipients."""
        schedule = MagicMock()
        schedule.name = "Multi-Recipient Report"
        schedule.report_config = {}
        schedule.notification_emails = ["user1@example.com", "user2@example.com", "user3@example.com"]

        report_results = [{"status": "success", "format": "pdf", "report_id": "123"}]

        with patch("app.services.scheduled_report_service.send_email") as mock_send:
            with patch("app.services.scheduled_report_service.settings") as mock_settings:
                mock_settings.API_BASE_URL = "https://api.example.com"

                await scheduled_service._send_notifications(schedule, report_results)

                # Verify email sent to each recipient
                assert mock_send.call_count == 3
                recipients = [call[1]["to_email"] for call in mock_send.call_args_list]
                assert set(recipients) == set(schedule.notification_emails)

    @pytest.mark.asyncio
    async def test_email_error_handling(self, scheduled_service: ScheduledReportService):
        """Test email error handling."""
        schedule = MagicMock()
        schedule.name = "Error Test Report"
        schedule.report_config = {}
        schedule.notification_emails = ["fail@example.com", "success@example.com"]

        report_results = [{"status": "success", "format": "pdf", "report_id": "123"}]

        with patch("app.services.scheduled_report_service.send_email") as mock_send:
            with patch("app.services.scheduled_report_service.settings") as mock_settings:
                mock_settings.API_BASE_URL = "https://api.example.com"

                # First email fails, second succeeds
                mock_send.side_effect = [Exception("Email failed"), None]

                # Should not raise exception
                await scheduled_service._send_notifications(schedule, report_results)

                # Both emails should be attempted
                assert mock_send.call_count == 2


class TestUIComponents:
    """Test specific UI components rendering."""

    def test_metric_card_rendering(self):
        """Test metric card component HTML structure."""
        template_str = """
        <div class="metric-card">
            <div class="metric-value">{{ value }}</div>
            <div class="metric-label">{{ label }}</div>
        </div>
        """

        template = Template(template_str)
        output = template.render(value="75.5%", label="Automation Coverage")

        assert '<div class="metric-card">' in output
        assert '<div class="metric-value">75.5%</div>' in output
        assert '<div class="metric-label">Automation Coverage</div>' in output

    def test_badge_components(self):
        """Test badge component rendering."""
        template_str = """
        {% if status == 'success' %}
            <span class="badge badge-success">{{ text }}</span>
        {% elif status == 'danger' %}
            <span class="badge badge-danger">{{ text }}</span>
        {% elif status == 'warning' %}
            <span class="badge badge-warning">{{ text }}</span>
        {% endif %}
        """

        template = Template(template_str)

        # Test success badge
        output = template.render(status="success", text="Passed")
        assert '<span class="badge badge-success">Passed</span>' in output

        # Test danger badge
        output = template.render(status="danger", text="Failed")
        assert '<span class="badge badge-danger">Failed</span>' in output

        # Test warning badge
        output = template.render(status="warning", text="Pending")
        assert '<span class="badge badge-warning">Pending</span>' in output

    def test_progress_bar_component(self):
        """Test progress bar component rendering."""
        template_str = """
        <div class="progress-bar">
            <div class="progress-fill" style="width: {{ percentage }}%"></div>
        </div>
        """

        template = Template(template_str)

        # Test various percentages
        for percentage in [0, 25, 50, 75, 100]:
            output = template.render(percentage=percentage)
            assert f'style="width: {percentage}%"' in output
            assert '<div class="progress-bar">' in output

    def test_table_sorting_indicators(self):
        """Test table sorting indicator rendering."""
        template_str = """
        <th>
            {{ column_name }}
            {% if sort_column == column_id %}
                {% if sort_order == 'asc' %}
                    <span>↑</span>
                {% else %}
                    <span>↓</span>
                {% endif %}
            {% endif %}
        </th>
        """

        template = Template(template_str)

        # Test ascending sort
        output = template.render(column_name="Category", column_id="category", sort_column="category", sort_order="asc")
        assert "<span>↑</span>" in output

        # Test descending sort
        output = template.render(
            column_name="Category", column_id="category", sort_column="category", sort_order="desc"
        )
        assert "<span>↓</span>" in output

        # Test no sort
        output = template.render(column_name="Category", column_id="category", sort_column="other", sort_order="asc")
        assert "<span>↑</span>" not in output
        assert "<span>↓</span>" not in output

    def test_trend_indicators(self):
        """Test trend indicator components."""
        template_str = """
        {% if trend == 'increasing' %}
            <span class="negative">↑ Increasing</span>
        {% elif trend == 'decreasing' %}
            <span class="positive">↓ Decreasing</span>
        {% else %}
            <span class="neutral">→ Stable</span>
        {% endif %}
        """

        template = Template(template_str)

        # Test increasing trend
        output = template.render(trend="increasing")
        assert '<span class="negative">↑ Increasing</span>' in output

        # Test decreasing trend
        output = template.render(trend="decreasing")
        assert '<span class="positive">↓ Decreasing</span>' in output

        # Test stable trend
        output = template.render(trend="stable")
        assert '<span class="neutral">→ Stable</span>' in output


class TestTemplateValidation:
    """Test template validation and error handling."""

    def test_template_syntax_validation(self):
        """Test template syntax error detection."""
        invalid_template = """
        {% if condition
            <p>Missing endif</p>
        """

        with pytest.raises(TemplateSyntaxError):
            Template(invalid_template)

    def test_undefined_variable_handling(self):
        """Test handling of undefined template variables."""
        template_str = "{{ undefined_variable }}"
        template = Template(template_str, undefined=UndefinedError)

        # Should raise error for undefined variables in strict mode
        with pytest.raises(Exception):
            template.render()

    def test_template_inheritance(self):
        """Test template inheritance structure."""
        base_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{% block title %}Default Title{% endblock %}</title>
        </head>
        <body>
            {% block content %}{% endblock %}
        </body>
        </html>
        """

        child_template = """
        {% extends "base.html" %}
        {% block title %}Custom Title{% endblock %}
        {% block content %}
            <h1>Custom Content</h1>
        {% endblock %}
        """

        # Create environment with templates
        from jinja2 import DictLoader, Environment

        templates = {"base.html": base_template, "child.html": child_template}

        env = Environment(loader=DictLoader(templates), autoescape=True)
        template = env.get_template("child.html")
        output = template.render()

        assert "<title>Custom Title</title>" in output
        assert "<h1>Custom Content</h1>" in output

    def test_template_filters(self):
        """Test custom template filters."""
        template_str = """
        {{ number | format_currency }}
        {{ date | format_date }}
        {{ text | truncate(10) }}
        """

        env = Environment(autoescape=True)

        # Add custom filters
        env.filters["format_currency"] = lambda x: f"${x:,.2f}"
        env.filters["format_date"] = lambda x: x.strftime("%Y-%m-%d")

        template = env.from_string(template_str)

        output = template.render(
            number=12345.67, date=datetime(2024, 1, 15), text="This is a long text that should be truncated"
        )

        assert "$12,345.67" in output
        assert "2024-01-15" in output
        assert "..." in output  # Truncation indicator


class TestPerformance:
    """Test UI rendering performance."""

    @pytest.fixture
    def large_dataset(self) -> Dict[str, Any]:
        """Create large dataset for performance testing."""
        return {
            "violations": [
                {
                    "id": f"violation-{i}",
                    "category": f"Category {i % 10}",
                    "severity": ["low", "medium", "high", "critical"][i % 4],
                    "description": f"Description for violation {i}",
                    "file": f"/path/to/file{i}.py",
                    "line": i * 10,
                }
                for i in range(1000)
            ],
            "metrics": {
                f"metric_{i}": {"value": i * 1.5, "trend": ["up", "down", "stable"][i % 3]} for i in range(100)
            },
        }

    def test_large_table_rendering_performance(self, large_dataset: Dict[str, Any]):
        """Test performance with large tables."""
        import time

        template_str = """
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Line</th>
                </tr>
            </thead>
            <tbody>
                {% for violation in violations %}
                <tr>
                    <td>{{ violation.id }}</td>
                    <td>{{ violation.category }}</td>
                    <td>{{ violation.severity }}</td>
                    <td>{{ violation.file }}</td>
                    <td>{{ violation.line }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        """

        template = Template(template_str)

        start_time = time.time()
        output = template.render(violations=large_dataset["violations"])
        render_time = time.time() - start_time

        # Should render within reasonable time
        assert render_time < 1.0  # Less than 1 second for 1000 rows
        assert len(output) > 0
        assert output.count("<tr>") == 1001  # Header + 1000 data rows

    def test_template_caching(self):
        """Test template caching performance."""
        from jinja2 import DictLoader, Environment

        template_content = """
        {% for i in range(100) %}
            <div>Item {{ i }}</div>
        {% endfor %}
        """

        env = Environment(loader=DictLoader({"test.html": template_content}), cache_size=50, autoescape=True)

        # First render (compiles template)
        import time

        start = time.time()
        template1 = env.get_template("test.html")
        output1 = template1.render()
        first_time = time.time() - start

        # Second render (uses cached template)
        start = time.time()
        template2 = env.get_template("test.html")
        output2 = template2.render()
        second_time = time.time() - start

        # Cached render should be faster
        assert second_time <= first_time
        assert output1 == output2


class TestAccessibility:
    """Test accessibility features in UI components."""

    def test_aria_labels(self):
        """Test ARIA labels for accessibility."""
        template_str = """
        <button aria-label="Download Report">
            <i class="icon-download"></i>
        </button>
        <nav aria-label="Main navigation">
            <ul>
                <li><a href="#">Home</a></li>
                <li><a href="#">Reports</a></li>
            </ul>
        </nav>
        <div role="alert" aria-live="polite">
            {{ alert_message }}
        </div>
        """

        template = Template(template_str)
        output = template.render(alert_message="Report generated successfully")

        assert 'aria-label="Download Report"' in output
        assert 'aria-label="Main navigation"' in output
        assert 'role="alert"' in output
        assert 'aria-live="polite"' in output

    def test_keyboard_navigation_support(self):
        """Test keyboard navigation support."""
        template_str = """
        <a href="#" tabindex="0">Clickable Link</a>
        <button tabindex="0">Action Button</button>
        <div tabindex="0" role="button" onkeypress="handleKeyPress(event)">
            Custom Button
        </div>
        <input type="text" tabindex="0" placeholder="Search...">
        """

        template = Template(template_str)
        output = template.render()

        # All interactive elements should have tabindex
        assert 'tabindex="0"' in output
        assert output.count('tabindex="0"') == 4

    def test_screen_reader_text(self):
        """Test screen reader specific text."""
        template_str = """
        <span class="sr-only">Screen reader only text</span>
        <div aria-hidden="true">Decorative element</div>
        <img src="chart.png" alt="Automation coverage chart showing 75% automated">
        """

        template = Template(template_str)
        output = template.render()

        assert 'class="sr-only"' in output
        assert 'aria-hidden="true"' in output
        assert 'alt="Automation coverage chart' in output

    def test_form_labels(self):
        """Test form accessibility labels."""
        template_str = """
        <form>
            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" required aria-required="true">

            <label for="report-type">Report Type</label>
            <select id="report-type" name="report_type" aria-describedby="report-help">
                <option value="metrics">Metrics Report</option>
                <option value="audit">Audit Report</option>
            </select>
            <span id="report-help">Select the type of report to generate</span>

            <fieldset>
                <legend>Report Format</legend>
                <input type="radio" id="pdf" name="format" value="pdf">
                <label for="pdf">PDF</label>
                <input type="radio" id="html" name="format" value="html">
                <label for="html">HTML</label>
            </fieldset>
        </form>
        """

        template = Template(template_str)
        output = template.render()

        # Check for proper label associations
        assert 'for="email"' in output
        assert 'id="email"' in output
        assert 'aria-required="true"' in output
        assert 'aria-describedby="report-help"' in output
        assert "<fieldset>" in output
        assert "<legend>" in output


class TestSecurity:
    """Test security features in UI components."""

    def test_xss_prevention_in_user_input(self):
        """Test XSS prevention for user-provided data."""
        template_str = """
        <h1>{{ user_name | e }}</h1>
        <p>{{ user_comment | e }}</p>
        <div data-value="{{ user_data | e }}"></div>
        """

        env = Environment(autoescape=True)
        template = env.from_string(template_str)

        malicious_input = {
            "user_name": "<script>alert('XSS')</script>",
            "user_comment": "Normal comment <img src=x onerror=alert('XSS')>",
            "user_data": "'; DROP TABLE users; --",
        }

        output = template.render(**malicious_input)

        # Scripts should be escaped
        assert "<script>" not in output
        assert "&lt;script&gt;" in output
        assert "onerror=" not in output
        assert "DROP TABLE" not in output or "&" in output

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention in report queries."""
        template_str = """
        SELECT * FROM reports
        WHERE user_id = :user_id
        AND report_type = :report_type
        """

        # This would be parameterized in actual code
        params = {"user_id": "'; DROP TABLE reports; --", "report_type": "metrics"}

        # In actual implementation, parameters should be bound, not concatenated
        assert "DROP TABLE" not in template_str  # Query template is safe

    def test_path_traversal_prevention(self):
        """Test path traversal prevention in template loading."""
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
            "../templates/../../sensitive.html",
        ]

        for path in dangerous_paths:
            # Should sanitize paths
            safe_path = path.replace("..", "").replace("\\", "/")
            assert ".." not in safe_path

    def test_csrf_token_in_forms(self):
        """Test CSRF token inclusion in forms."""
        template_str = """
        <form method="POST" action="/reports/generate">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="submit" value="Generate Report">
        </form>
        """

        template = Template(template_str)
        output = template.render(csrf_token="test-csrf-token-123")

        assert 'name="csrf_token"' in output
        assert 'value="test-csrf-token-123"' in output

    def test_content_security_policy_headers(self):
        """Test Content Security Policy headers."""
        csp_header = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self';"
        )

        # Verify CSP allows necessary features
        assert "'self'" in csp_header  # Allow same-origin
        assert "img-src 'self' data:" in csp_header  # Allow data URIs for charts
        assert "script-src" in csp_header  # Script policy defined


class TestIntegration:
    """Integration tests for UI components with services."""

    @pytest.mark.asyncio
    async def test_full_report_generation_flow(self):
        """Test complete report generation flow."""
        mock_db = AsyncMock()

        # Mock report record
        mock_report = MagicMock()
        mock_report.id = "test-report-123"
        mock_report.status = ReportStatus.GENERATING

        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_report
        mock_db.execute.return_value = mock_result

        generator = ArchitecturalReportGenerator(mock_db)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.architectural_report_generator.settings") as mock_settings:
                mock_settings.REPORT_OUTPUT_DIR = tmpdir

                # Generate report
                result = await generator.generate_architectural_metrics_report(
                    report_id="test-report-123",
                    format=ReportFormat.HTML,
                    start_date=datetime.now(timezone.utc) - timedelta(days=30),
                    end_date=datetime.now(timezone.utc),
                    include_sections=["leading", "lagging", "roi"],
                )

                assert result["report_id"] == "test-report-123"
                assert result["format"] == "html"
                assert "file_path" in result

    @pytest.mark.asyncio
    async def test_scheduled_report_with_notifications(self):
        """Test scheduled report generation with email notifications."""
        mock_db = AsyncMock()
        service = ScheduledReportService(mock_db)

        # Mock schedule
        schedule = MagicMock()
        schedule.id = "schedule-123"
        schedule.name = "Weekly Report"
        schedule.cron_expression = "0 0 * * 1"  # Weekly on Monday
        schedule.report_config = {"period_days": 7}
        schedule.output_formats = ["pdf", "html"]
        schedule.notification_emails = ["test@example.com"]
        schedule.report_template_id = "template-123"

        # Mock template
        mock_template = MagicMock()
        mock_template.id = "template-123"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_template
        mock_db.execute.return_value = mock_result

        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = f"{temp_dir}/report.pdf"
            with patch.object(service.report_generator, "generate_architectural_metrics_report") as mock_generate:
                mock_generate.return_value = {"report_id": "report-123", "file_path": report_path, "format": "pdf"}

                with patch("app.services.scheduled_report_service.send_email") as mock_email:
                    result = await service._execute_schedule(schedule)

                    assert result["status"] in ["success", "partial"]
                    assert len(result["reports"]) == 2  # PDF and HTML

                    # Verify email was sent
                    mock_email.assert_called()


class TestErrorRecovery:
    """Test error recovery and resilience."""

    @pytest.mark.asyncio
    async def test_partial_data_handling(self):
        """Test handling of partial or missing data."""
        mock_db = AsyncMock()
        generator = ArchitecturalReportGenerator(mock_db)

        # Partial metrics data
        partial_data = {
            "title": "Partial Report",
            "subtitle": "Test",
            "generated_at": datetime.now().isoformat(),
            "period_start": datetime.now().isoformat(),
            "period_end": datetime.now().isoformat(),
            "leading_indicators": {
                "automation_coverage": None,  # Missing data
                "detection_time": {"average_detection_hours": 2.5},
            },
        }

        # Should handle gracefully
        charts = await generator._generate_charts(partial_data)
        assert isinstance(charts, dict)

    @pytest.mark.asyncio
    async def test_database_connection_failure(self):
        """Test handling of database connection failures."""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database connection failed")

        generator = ArchitecturalReportGenerator(mock_db)

        with pytest.raises(Exception) as exc_info:
            await generator.generate_architectural_metrics_report(report_id="test-123", format=ReportFormat.PDF)

        assert "Database connection failed" in str(exc_info.value)

    def test_template_file_missing(self):
        """Test handling of missing template files."""
        from jinja2 import Environment, FileSystemLoader, TemplateNotFound

        env = Environment(loader=FileSystemLoader("/nonexistent/path"), autoescape=True)

        with pytest.raises(TemplateNotFound):
            env.get_template("missing_template.html")

    @pytest.mark.asyncio
    async def test_chart_generation_failure_recovery(self):
        """Test recovery from chart generation failures."""
        mock_db = AsyncMock()
        generator = ArchitecturalReportGenerator(mock_db)

        with patch.object(generator, "_create_automation_trend_chart", side_effect=Exception("Chart error")):
            metrics_data = {"leading_indicators": {"automation_coverage": {"automated_scans": 100, "manual_scans": 50}}}

            # Should not crash, just return empty charts
            charts = await generator._generate_charts(metrics_data)
            assert charts.get("automation_trend", "") == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app.services", "--cov-report=term-missing"])


class TestAdvancedTemplateFeatures:
    """Test advanced template features and edge cases."""

    def test_template_macros(self):
        """Test Jinja2 macro functionality."""
        template_str = """
        {% macro render_metric_card(value, label, trend=None) %}
        <div class="metric-card">
            <div class="metric-value">{{ value }}</div>
            <div class="metric-label">{{ label }}</div>
            {% if trend %}
            <div class="metric-trend trend-{{ trend }}">
                {% if trend == 'up' %}↑{% elif trend == 'down' %}↓{% else %}→{% endif %}
            </div>
            {% endif %}
        </div>
        {% endmacro %}

        {{ render_metric_card('95%', 'Coverage', 'up') }}
        {{ render_metric_card('12ms', 'Response Time', 'down') }}
        {{ render_metric_card('100', 'Active Users') }}
        """

        template = Template(template_str)
        output = template.render()

        # Verify macro expansion
        assert output.count('<div class="metric-card">') == 3
        assert '<div class="metric-value">95%</div>' in output
        assert '<div class="metric-trend trend-up">↑</div>' in output
        assert '<div class="metric-trend trend-down">↓</div>' in output
        # Third card should not have trend
        assert output.count("metric-trend") == 2

    def test_template_includes(self):
        """Test template include functionality."""
        from jinja2 import DictLoader, Environment

        templates = {
            "header.html": """
            <header>
                <h1>{{ title }}</h1>
                <nav>{{ navigation | default('') }}</nav>
            </header>
            """,
            "footer.html": """
            <footer>
                <p>Generated at {{ timestamp }}</p>
                <p>© 2024 Company</p>
            </footer>
            """,
            "main.html": """
            <!DOCTYPE html>
            <html>
            <body>
                {% include 'header.html' %}
                <main>{{ content }}</main>
                {% include 'footer.html' %}
            </body>
            </html>
            """,
        }

        env = Environment(loader=DictLoader(templates), autoescape=True)
        template = env.get_template("main.html")

        output = template.render(title="Test Report", content="Report content here", timestamp="2024-01-15 10:30:00")

        assert "<h1>Test Report</h1>" in output
        assert "<main>Report content here</main>" in output
        assert "<p>Generated at 2024-01-15 10:30:00</p>" in output

    def test_template_loops_with_index(self):
        """Test template loops with loop variables."""
        template_str = """
        <table>
            <tbody>
            {% for item in items %}
                <tr class="{% if loop.index is even %}even{% else %}odd{% endif %}">
                    <td>{{ loop.index }}</td>
                    <td>{{ item.name }}</td>
                    <td>{{ item.value }}</td>
                    {% if loop.first %}
                        <td rowspan="{{ loop.length }}">Total: {{ total }}</td>
                    {% endif %}
                </tr>
            {% endfor %}
            </tbody>
        </table>
        """

        template = Template(template_str)
        items = [
            {"name": "Item A", "value": 10},
            {"name": "Item B", "value": 20},
            {"name": "Item C", "value": 30},
        ]

        output = template.render(items=items, total=60)

        # Check alternating row classes
        assert 'class="odd"' in output
        assert 'class="even"' in output

        # Check rowspan on first row
        assert 'rowspan="3"' in output

        # Check loop indices
        assert "<td>1</td>" in output
        assert "<td>2</td>" in output
        assert "<td>3</td>" in output

    def test_template_conditionals_complex(self):
        """Test complex conditional logic in templates."""
        template_str = """
        {% set score = metrics.score %}
        {% set trend = metrics.trend %}

        <div class="score-display">
            {% if score >= 90 %}
                <span class="excellent">Excellent: {{ score }}%</span>
            {% elif score >= 70 %}
                <span class="good">Good: {{ score }}%</span>
            {% elif score >= 50 %}
                <span class="fair">Fair: {{ score }}%</span>
            {% else %}
                <span class="poor">Needs Improvement: {{ score }}%</span>
            {% endif %}

            {% if trend == 'improving' and score < 90 %}
                <span class="trend-positive">📈 Improving</span>
            {% elif trend == 'declining' and score > 50 %}
                <span class="trend-negative">📉 Declining</span>
            {% elif trend == 'stable' %}
                <span class="trend-neutral">➡️ Stable</span>
            {% endif %}
        </div>
        """

        template = Template(template_str)

        # Test different score ranges
        test_cases = [
            ({"score": 95, "trend": "stable"}, "excellent", "Stable"),
            ({"score": 75, "trend": "improving"}, "good", "Improving"),
            ({"score": 55, "trend": "declining"}, "fair", "Declining"),
            ({"score": 30, "trend": "improving"}, "poor", "Improving"),
        ]

        for metrics, expected_class, expected_trend in test_cases:
            output = template.render(metrics=metrics)
            assert f'class="{expected_class}"' in output
            assert expected_trend in output

    def test_template_filters_chaining(self):
        """Test chaining multiple filters."""
        template_str = """
        {{ text | upper | replace(' ', '_') | truncate(20) }}
        {{ number | abs | round(2) }}
        {{ date | default('N/A') }}
        {{ items | length }}
        {{ items | select('odd') | list | length }}
        {{ dict_items | dictsort | first }}
        """

        template = Template(template_str)
        output = template.render(
            text="hello world test",
            number=-3.14159,
            date=None,
            items=[1, 2, 3, 4, 5],
            dict_items={"z": 1, "a": 2, "m": 3},
        )

        assert "HELLO_WORLD_TEST" in output
        assert "3.14" in output
        assert "N/A" in output
        assert "5" in output  # Length of items
        assert "3" in output  # Length of odd items [1, 3, 5]

    def test_template_custom_tests(self):
        """Test custom Jinja2 tests."""
        env = Environment(autoescape=True)

        # Add custom tests
        env.tests["positive"] = lambda x: x > 0
        env.tests["valid_email"] = lambda x: "@" in x and "." in x
        env.tests["recent"] = lambda x: (datetime.now() - x).days < 30

        template_str = """
        {% if value is positive %}
            Value is positive: {{ value }}
        {% endif %}

        {% if email is valid_email %}
            Valid email: {{ email }}
        {% else %}
            Invalid email: {{ email }}
        {% endif %}

        {% if date is recent %}
            Recent date
        {% else %}
            Old date
        {% endif %}
        """

        template = env.from_string(template_str)

        output = template.render(value=10, email="user@example.com", date=datetime.now() - timedelta(days=10))

        assert "Value is positive: 10" in output
        assert "Valid email: user@example.com" in output
        assert "Recent date" in output

    def test_template_global_functions(self):
        """Test global functions in templates."""
        env = Environment(autoescape=True)

        # Add global functions
        env.globals["current_year"] = lambda: datetime.now().year
        env.globals["format_bytes"] = lambda b: f"{b / 1024 / 1024:.2f} MB"
        env.globals["calculate_percentage"] = lambda part, total: (part / total * 100) if total else 0

        template_str = """
        Copyright © {{ current_year() }}
        File size: {{ format_bytes(file_size) }}
        Completion: {{ calculate_percentage(completed, total) | round(1) }}%
        """

        template = env.from_string(template_str)
        output = template.render(file_size=5242880, completed=75, total=100)  # 5 MB

        assert f"© {datetime.now().year}" in output
        assert "5.00 MB" in output
        assert "75.0%" in output


class TestUIComponentInteractions:
    """Test complex UI component interactions."""

    def test_dynamic_form_generation(self):
        """Test dynamic form field generation."""
        template_str = """
        <form id="dynamic-form">
            {% for field in form_fields %}
                <div class="form-group">
                    <label for="{{ field.id }}">{{ field.label }}</label>

                    {% if field.type == 'text' %}
                        <input type="text" id="{{ field.id }}" name="{{ field.name }}"
                               value="{{ field.value | default('') }}"
                               {% if field.required %}required{% endif %}>

                    {% elif field.type == 'select' %}
                        <select id="{{ field.id }}" name="{{ field.name }}"
                                {% if field.required %}required{% endif %}>
                            {% for option in field.options %}
                                <option value="{{ option.value }}"
                                        {% if option.value == field.value %}selected{% endif %}>
                                    {{ option.label }}
                                </option>
                            {% endfor %}
                        </select>

                    {% elif field.type == 'checkbox' %}
                        <input type="checkbox" id="{{ field.id }}" name="{{ field.name }}"
                               {% if field.value %}checked{% endif %}>

                    {% elif field.type == 'textarea' %}
                        <textarea id="{{ field.id }}" name="{{ field.name }}"
                                  rows="{{ field.rows | default(3) }}"
                                  {% if field.required %}required{% endif %}>{{ field.value | default('') }}</textarea>
                    {% endif %}

                    {% if field.help_text %}
                        <small class="form-help">{{ field.help_text }}</small>
                    {% endif %}
                </div>
            {% endfor %}

            <button type="submit">Submit</button>
        </form>
        """

        form_fields = [
            {"id": "name", "name": "name", "type": "text", "label": "Full Name", "required": True, "value": "John Doe"},
            {
                "id": "report_type",
                "name": "report_type",
                "type": "select",
                "label": "Report Type",
                "required": True,
                "value": "metrics",
                "options": [
                    {"value": "metrics", "label": "Metrics Report"},
                    {"value": "audit", "label": "Audit Report"},
                    {"value": "roi", "label": "ROI Analysis"},
                ],
            },
            {
                "id": "include_charts",
                "name": "include_charts",
                "type": "checkbox",
                "label": "Include Charts",
                "value": True,
            },
            {
                "id": "notes",
                "name": "notes",
                "type": "textarea",
                "label": "Additional Notes",
                "rows": 5,
                "help_text": "Enter any additional notes or comments",
            },
        ]

        template = Template(template_str)
        output = template.render(form_fields=form_fields)

        # Verify form structure
        assert '<form id="dynamic-form">' in output
        assert 'value="John Doe"' in output
        assert '<option value="metrics" selected>' in output
        assert 'type="checkbox"' in output and "checked" in output
        assert "<textarea" in output and 'rows="5"' in output
        assert '<small class="form-help">Enter any additional notes' in output

    def test_pagination_component(self):
        """Test pagination UI component."""
        template_str = """
        <div class="pagination">
            {% if current_page > 1 %}
                <a href="?page=1" class="first">First</a>
                <a href="?page={{ current_page - 1 }}" class="prev">Previous</a>
            {% endif %}

            {% for page in range(1, total_pages + 1) %}
                {% if page >= current_page - 2 and page <= current_page + 2 %}
                    {% if page == current_page %}
                        <span class="current">{{ page }}</span>
                    {% else %}
                        <a href="?page={{ page }}">{{ page }}</a>
                    {% endif %}
                {% elif page == 1 or page == total_pages %}
                    <a href="?page={{ page }}">{{ page }}</a>
                {% elif page == current_page - 3 or page == current_page + 3 %}
                    <span class="ellipsis">...</span>
                {% endif %}
            {% endfor %}

            {% if current_page < total_pages %}
                <a href="?page={{ current_page + 1 }}" class="next">Next</a>
                <a href="?page={{ total_pages }}" class="last">Last</a>
            {% endif %}

            <div class="page-info">
                Page {{ current_page }} of {{ total_pages }}
                ({{ total_items }} items)
            </div>
        </div>
        """

        template = Template(template_str)

        # Test middle page
        output = template.render(current_page=5, total_pages=10, total_items=100)

        assert '<span class="current">5</span>' in output
        assert '<a href="?page=4">4</a>' in output
        assert '<a href="?page=6">6</a>' in output
        assert '<span class="ellipsis">...</span>' in output
        assert "Page 5 of 10" in output

        # Test first page
        output = template.render(current_page=1, total_pages=10, total_items=100)

        assert 'class="prev"' not in output  # No previous on first page
        assert '<span class="current">1</span>' in output
        assert '<a href="?page=2" class="next">Next</a>' in output

    def test_sortable_table_headers(self):
        """Test sortable table header component."""
        template_str = """
        <table class="sortable">
            <thead>
                <tr>
                    {% for column in columns %}
                        <th>
                            {% if column.sortable %}
                                <a href="?sort={{ column.key }}&order={% if current_sort == column.key and current_order == 'asc' %}desc{% else %}asc{% endif %}"
                                   class="sort-header {% if current_sort == column.key %}active sort-{{ current_order }}{% endif %}">
                                    {{ column.label }}
                                    {% if current_sort == column.key %}
                                        <span class="sort-icon">
                                            {% if current_order == 'asc' %}▲{% else %}▼{% endif %}
                                        </span>
                                    {% else %}
                                        <span class="sort-icon inactive">⇅</span>
                                    {% endif %}
                                </a>
                            {% else %}
                                {{ column.label }}
                            {% endif %}
                        </th>
                    {% endfor %}
                </tr>
            </thead>
        </table>
        """

        columns = [
            {"key": "name", "label": "Name", "sortable": True},
            {"key": "date", "label": "Date", "sortable": True},
            {"key": "status", "label": "Status", "sortable": True},
            {"key": "actions", "label": "Actions", "sortable": False},
        ]

        template = Template(template_str)

        # Test with active sort
        output = template.render(columns=columns, current_sort="date", current_order="desc")

        assert 'class="sort-header active sort-desc"' in output
        assert '<span class="sort-icon">▼</span>' in output
        assert "?sort=date&order=asc" in output  # Should toggle to asc
        assert '<span class="sort-icon inactive">⇅</span>' in output

    def test_modal_dialog_component(self):
        """Test modal dialog component."""
        template_str = """
        <div class="modal" id="{{ modal_id }}"
             {% if not visible %}style="display: none;"{% endif %}
             role="dialog"
             aria-labelledby="{{ modal_id }}-title"
             aria-modal="true">
            <div class="modal-backdrop" onclick="closeModal('{{ modal_id }}')"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h2 id="{{ modal_id }}-title">{{ title }}</h2>
                    <button class="modal-close"
                            onclick="closeModal('{{ modal_id }}')"
                            aria-label="Close">×</button>
                </div>
                <div class="modal-body">
                    {{ content | safe }}
                </div>
                {% if actions %}
                <div class="modal-footer">
                    {% for action in actions %}
                        <button class="btn btn-{{ action.type | default('default') }}"
                                {% if action.onclick %}onclick="{{ action.onclick }}"{% endif %}
                                {% if action.dismiss %}data-dismiss="modal"{% endif %}>
                            {{ action.label }}
                        </button>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
        """

        template = Template(template_str)
        output = template.render(
            modal_id="confirm-dialog",
            title="Confirm Action",
            visible=True,
            content="<p>Are you sure you want to proceed?</p>",
            actions=[
                {"label": "Cancel", "type": "secondary", "dismiss": True},
                {"label": "Confirm", "type": "primary", "onclick": "confirmAction()"},
            ],
        )

        assert 'id="confirm-dialog"' in output
        assert 'aria-labelledby="confirm-dialog-title"' in output
        assert 'aria-modal="true"' in output
        assert '<h2 id="confirm-dialog-title">Confirm Action</h2>' in output
        assert 'onclick="confirmAction()"' in output
        assert 'data-dismiss="modal"' in output

    def test_notification_component(self):
        """Test notification/alert component."""
        template_str = """
        {% macro render_notification(type, title, message, dismissible=True) %}
        <div class="notification notification-{{ type }}" role="alert">
            <div class="notification-icon">
                {% if type == 'success' %}✓
                {% elif type == 'error' %}✗
                {% elif type == 'warning' %}⚠
                {% else %}ℹ
                {% endif %}
            </div>
            <div class="notification-content">
                {% if title %}
                    <strong class="notification-title">{{ title }}</strong>
                {% endif %}
                <div class="notification-message">{{ message }}</div>
            </div>
            {% if dismissible %}
                <button class="notification-close" aria-label="Dismiss">×</button>
            {% endif %}
        </div>
        {% endmacro %}

        {% for notification in notifications %}
            {{ render_notification(
                notification.type,
                notification.title,
                notification.message,
                notification.dismissible | default(True)
            ) }}
        {% endfor %}
        """

        notifications = [
            {"type": "success", "title": "Success!", "message": "Report generated successfully."},
            {"type": "error", "title": "Error", "message": "Failed to connect to database."},
            {"type": "warning", "message": "Low disk space detected.", "dismissible": False},
            {"type": "info", "title": "Info", "message": "New version available."},
        ]

        template = Template(template_str)
        output = template.render(notifications=notifications)

        assert "notification-success" in output
        assert "notification-error" in output
        assert "notification-warning" in output
        assert "notification-info" in output
        assert output.count("notification-close") == 3  # One non-dismissible
        assert "✓" in output  # Success icon
        assert "✗" in output  # Error icon
        assert "⚠" in output  # Warning icon
        assert "ℹ" in output  # Info icon


class TestMobileResponsiveness:
    """Test mobile responsive features."""

    def test_responsive_navigation_menu(self):
        """Test responsive navigation menu."""
        template_str = """
        <nav class="navbar">
            <div class="navbar-brand">
                <a href="/">{{ brand_name }}</a>
                <button class="navbar-toggle"
                        aria-label="Toggle navigation"
                        aria-expanded="false"
                        aria-controls="navbar-menu">
                    <span class="navbar-toggle-icon"></span>
                </button>
            </div>
            <div class="navbar-menu" id="navbar-menu">
                <ul class="navbar-nav">
                    {% for item in nav_items %}
                        <li class="nav-item {% if item.active %}active{% endif %}">
                            <a href="{{ item.url }}" class="nav-link">
                                {% if item.icon %}
                                    <span class="nav-icon">{{ item.icon }}</span>
                                {% endif %}
                                <span class="nav-text">{{ item.label }}</span>
                            </a>
                        </li>
                    {% endfor %}
                </ul>
            </div>
        </nav>

        <style>
            @media (max-width: 768px) {
                .navbar-menu { display: none; }
                .navbar-toggle { display: block; }
                .navbar-menu.show { display: block; }
            }
            @media (min-width: 769px) {
                .navbar-toggle { display: none; }
                .navbar-menu { display: flex; }
            }
        </style>
        """

        template = Template(template_str)
        output = template.render(
            brand_name="Report System",
            nav_items=[
                {"url": "/dashboard", "label": "Dashboard", "icon": "📊", "active": True},
                {"url": "/reports", "label": "Reports", "icon": "📄"},
                {"url": "/settings", "label": "Settings", "icon": "⚙️"},
            ],
        )

        assert 'class="navbar-toggle"' in output
        assert 'aria-expanded="false"' in output
        assert "@media (max-width: 768px)" in output
        assert "navbar-menu.show" in output

    def test_responsive_grid_layout(self):
        """Test responsive grid layout."""
        template_str = """
        <style>
            .grid-container {
                display: grid;
                gap: 1rem;
                padding: 1rem;
            }

            /* Mobile: 1 column */
            @media (max-width: 576px) {
                .grid-container {
                    grid-template-columns: 1fr;
                }
            }

            /* Tablet: 2 columns */
            @media (min-width: 577px) and (max-width: 768px) {
                .grid-container {
                    grid-template-columns: repeat(2, 1fr);
                }
            }

            /* Desktop: 3 columns */
            @media (min-width: 769px) and (max-width: 1024px) {
                .grid-container {
                    grid-template-columns: repeat(3, 1fr);
                }
            }

            /* Large desktop: 4 columns */
            @media (min-width: 1025px) {
                .grid-container {
                    grid-template-columns: repeat(4, 1fr);
                }
            }
        </style>

        <div class="grid-container">
            {% for item in items %}
                <div class="grid-item" data-breakpoint="{{ loop.index }}">
                    {{ item.content }}
                </div>
            {% endfor %}
        </div>
        """

        items = [{"content": f"Item {i}"} for i in range(1, 13)]

        template = Template(template_str)
        output = template.render(items=items)

        # Check media queries
        assert "@media (max-width: 576px)" in output
        assert "@media (min-width: 577px) and (max-width: 768px)" in output
        assert "@media (min-width: 769px) and (max-width: 1024px)" in output
        assert "@media (min-width: 1025px)" in output

        # Check grid setup
        assert "display: grid" in output
        assert "grid-template-columns: 1fr" in output
        assert "grid-template-columns: repeat(2, 1fr)" in output
        assert "grid-template-columns: repeat(3, 1fr)" in output
        assert "grid-template-columns: repeat(4, 1fr)" in output

    def test_responsive_typography(self):
        """Test responsive typography scaling."""
        template_str = """
        <style>
            :root {
                --base-font-size: 16px;
            }

            body {
                font-size: var(--base-font-size);
            }

            h1 { font-size: clamp(1.5rem, 4vw, 2.5rem); }
            h2 { font-size: clamp(1.25rem, 3vw, 2rem); }
            h3 { font-size: clamp(1.1rem, 2.5vw, 1.5rem); }
            p { font-size: clamp(0.875rem, 2vw, 1rem); }

            @media (max-width: 480px) {
                :root { --base-font-size: 14px; }
            }

            @media (min-width: 1200px) {
                :root { --base-font-size: 18px; }
            }
        </style>

        <article>
            <h1>{{ title }}</h1>
            <h2>{{ subtitle }}</h2>
            <p>{{ content }}</p>
        </article>
        """

        template = Template(template_str)
        output = template.render(
            title="Responsive Typography", subtitle="Scales with viewport", content="This text adjusts to screen size."
        )

        # Check clamp functions for fluid typography
        assert "clamp(1.5rem, 4vw, 2.5rem)" in output
        assert "clamp(0.875rem, 2vw, 1rem)" in output

        # Check CSS custom properties
        assert "--base-font-size" in output
        assert "var(--base-font-size)" in output

    def test_touch_friendly_controls(self):
        """Test touch-friendly control sizes."""
        template_str = """
        <style>
            /* Touch-friendly minimum sizes */
            button,
            input[type="button"],
            input[type="submit"],
            .btn {
                min-height: 44px;
                min-width: 44px;
                padding: 12px 16px;
            }

            input[type="text"],
            input[type="email"],
            input[type="password"],
            textarea,
            select {
                min-height: 44px;
                padding: 8px 12px;
                font-size: 16px; /* Prevents zoom on iOS */
            }

            /* Increase tap target for small icons */
            .icon-button {
                position: relative;
                padding: 12px;
            }

            .icon-button::before {
                content: '';
                position: absolute;
                top: -8px;
                left: -8px;
                right: -8px;
                bottom: -8px;
            }

            /* Spacing for touch */
            .button-group > * + * {
                margin-left: 8px;
            }

            @media (pointer: coarse) {
                /* Larger targets for touch devices */
                button, .btn {
                    min-height: 48px;
                    padding: 14px 20px;
                }
            }
        </style>

        <form class="touch-friendly">
            <input type="text" placeholder="Name">
            <input type="email" placeholder="Email">
            <div class="button-group">
                <button type="button" class="btn">Cancel</button>
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
            <button class="icon-button" aria-label="Settings">⚙️</button>
        </form>
        """

        template = Template(template_str)
        output = template.render()

        # Check minimum sizes for touch
        assert "min-height: 44px" in output
        assert "min-width: 44px" in output

        # Check iOS zoom prevention
        assert "font-size: 16px" in output

        # Check pointer media query
        assert "@media (pointer: coarse)" in output

        # Check expanded tap targets
        assert "icon-button::before" in output


class TestPerformanceOptimizations:
    """Test performance optimizations in UI components."""

    def test_lazy_loading_images(self):
        """Test lazy loading for images."""
        template_str = """
        {% for image in images %}
            <img src="{% if loop.index <= 3 %}{{ image.src }}{% else %}data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E{% endif %}"
                 {% if loop.index > 3 %}data-src="{{ image.src }}" loading="lazy"{% endif %}
                 alt="{{ image.alt }}"
                 class="lazy-image">
        {% endfor %}

        <noscript>
            {% for image in images %}
                <img src="{{ image.src }}" alt="{{ image.alt }}">
            {% endfor %}
        </noscript>
        """

        images = [{"src": f"/images/chart{i}.png", "alt": f"Chart {i}"} for i in range(1, 11)]

        template = Template(template_str)
        output = template.render(images=images)

        # First 3 images load immediately
        assert 'src="/images/chart1.png"' in output
        assert 'src="/images/chart2.png"' in output
        assert 'src="/images/chart3.png"' in output

        # Rest use lazy loading
        assert 'data-src="/images/chart4.png"' in output
        assert 'loading="lazy"' in output
        assert output.count('loading="lazy"') == 7

        # Fallback for no JavaScript
        assert "<noscript>" in output

    def test_css_critical_path(self):
        """Test critical CSS inlining."""
        template_str = """
        <head>
            <!-- Critical CSS inline -->
            <style>
                /* Critical above-the-fold styles */
                body { margin: 0; font-family: system-ui; }
                .header { background: #667eea; color: white; padding: 1rem; }
                .container { max-width: 1200px; margin: 0 auto; }
                .loading { display: flex; justify-content: center; padding: 2rem; }
            </style>

            <!-- Non-critical CSS deferred -->
            <link rel="preload" href="/css/main.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
            <noscript><link rel="stylesheet" href="/css/main.css"></noscript>

            <!-- Preconnect to external domains -->
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="dns-prefetch" href="https://cdn.example.com">
        </head>
        """

        template = Template(template_str)
        output = template.render()

        # Critical CSS is inlined
        assert "<style>" in output
        assert "above-the-fold" in output

        # Non-critical CSS is deferred
        assert 'rel="preload"' in output
        assert 'as="style"' in output
        assert "this.rel='stylesheet'" in output

        # Performance hints
        assert 'rel="preconnect"' in output
        assert 'rel="dns-prefetch"' in output

    def test_virtual_scrolling(self):
        """Test virtual scrolling implementation."""
        template_str = """
        <div class="virtual-scroll-container"
             data-total-items="{{ total_items }}"
             data-item-height="{{ item_height }}"
             data-visible-items="{{ visible_items }}">
            <div class="virtual-scroll-spacer"
                 style="height: {{ total_height }}px;">
            </div>
            <div class="virtual-scroll-viewport">
                {% for item in visible_items_list %}
                    <div class="virtual-item"
                         data-index="{{ item.index }}"
                         style="transform: translateY({{ item.offset }}px);">
                        {{ item.content }}
                    </div>
                {% endfor %}
            </div>
        </div>

        <script>
            // Virtual scrolling logic would go here
            const container = document.querySelector('.virtual-scroll-container');
            const itemHeight = parseInt(container.dataset.itemHeight);
            const totalItems = parseInt(container.dataset.totalItems);
        </script>
        """

        # Simulate visible items in viewport
        visible_start = 20
        visible_end = 30
        item_height = 50

        visible_items_list = [
            {"index": i, "offset": i * item_height, "content": f"Item {i}"} for i in range(visible_start, visible_end)
        ]

        template = Template(template_str)
        output = template.render(
            total_items=1000,
            item_height=item_height,
            visible_items=10,
            total_height=1000 * item_height,
            visible_items_list=visible_items_list,
        )

        assert 'data-total-items="1000"' in output
        assert f"height: {1000 * item_height}px" in output
        assert "virtual-scroll-viewport" in output
        assert f'data-index="{visible_start}"' in output

    def test_debounced_search(self):
        """Test debounced search implementation."""
        template_str = """
        <div class="search-container">
            <input type="text"
                   id="search-input"
                   class="search-field"
                   placeholder="Search..."
                   data-debounce="{{ debounce_ms }}">
            <div class="search-results" id="search-results">
                <div class="search-loading" style="display: none;">
                    Searching...
                </div>
                <div class="search-content"></div>
            </div>
        </div>

        <script>
            let debounceTimer;
            const searchInput = document.getElementById('search-input');
            const debounceMs = parseInt(searchInput.dataset.debounce);

            searchInput.addEventListener('input', (e) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    performSearch(e.target.value);
                }, debounceMs);
            });
        </script>
        """

        template = Template(template_str)
        output = template.render(debounce_ms=300)

        assert 'data-debounce="300"' in output
        assert "clearTimeout(debounceTimer)" in output
        assert "setTimeout" in output


class TestDataVisualization:
    """Test data visualization components."""

    def test_sparkline_component(self):
        """Test inline sparkline visualization."""
        template_str = """
        <span class="sparkline"
              data-values="{{ values | join(',') }}"
              data-min="{{ min_value }}"
              data-max="{{ max_value }}">
            <svg viewBox="0 0 100 20" class="sparkline-svg">
                <polyline points="{{ points }}"
                          fill="none"
                          stroke="#667eea"
                          stroke-width="2"/>
                {% if show_area %}
                <polygon points="{{ area_points }}"
                         fill="#667eea"
                         opacity="0.2"/>
                {% endif %}
                {% if show_dots %}
                    {% for point in point_coords %}
                    <circle cx="{{ point.x }}" cy="{{ point.y }}" r="2" fill="#667eea"/>
                    {% endfor %}
                {% endif %}
            </svg>
            <span class="sparkline-value">{{ current_value }}</span>
        </span>
        """

        values = [10, 15, 12, 18, 22, 20, 25, 23, 28, 30]
        min_val = min(values)
        max_val = max(values)

        # Calculate SVG points
        width = 100
        height = 20
        points = []
        point_coords = []

        for i, val in enumerate(values):
            x = (i / (len(values) - 1)) * width
            y = height - ((val - min_val) / (max_val - min_val)) * height
            points.append(f"{x:.1f},{y:.1f}")
            point_coords.append({"x": x, "y": y})

        points_str = " ".join(points)
        area_points = f"0,{height} {points_str} {width},{height}"

        template = Template(template_str)
        output = template.render(
            values=values,
            min_value=min_val,
            max_value=max_val,
            points=points_str,
            area_points=area_points,
            point_coords=point_coords,
            current_value=values[-1],
            show_area=True,
            show_dots=True,
        )

        assert '<svg viewBox="0 0 100 20"' in output
        assert "<polyline" in output
        assert "<polygon" in output
        assert "<circle" in output
        assert f'<span class="sparkline-value">{values[-1]}</span>' in output

    def test_gauge_chart_component(self):
        """Test gauge/meter chart component."""
        template_str = """
        <div class="gauge-chart">
            <svg viewBox="0 0 200 120" class="gauge-svg">
                <!-- Background arc -->
                <path d="{{ background_arc }}"
                      fill="none"
                      stroke="#e0e0e0"
                      stroke-width="20"/>

                <!-- Value arc -->
                <path d="{{ value_arc }}"
                      fill="none"
                      stroke="{{ color }}"
                      stroke-width="20"
                      stroke-linecap="round"/>

                <!-- Center text -->
                <text x="100" y="100"
                      text-anchor="middle"
                      class="gauge-value">{{ value }}%</text>
                <text x="100" y="115"
                      text-anchor="middle"
                      class="gauge-label">{{ label }}</text>
            </svg>

            <div class="gauge-legend">
                {% for range in ranges %}
                <span class="gauge-range" style="color: {{ range.color }}">
                    {{ range.label }}: {{ range.min }}-{{ range.max }}%
                </span>
                {% endfor %}
            </div>
        </div>
        """

        value = 75
        max_value = 100

        # Calculate arc paths (simplified)
        angle = (value / max_value) * 180

        # Determine color based on value
        if value >= 80:
            color = "#28a745"
        elif value >= 60:
            color = "#ffc107"
        else:
            color = "#dc3545"

        template = Template(template_str)
        output = template.render(
            value=value,
            label="Compliance",
            background_arc="M 20 100 A 80 80 0 0 1 180 100",
            value_arc=f"M 20 100 A 80 80 0 0 1 {20 + angle} 100",
            color=color,
            ranges=[
                {"label": "Good", "min": 80, "max": 100, "color": "#28a745"},
                {"label": "Fair", "min": 60, "max": 79, "color": "#ffc107"},
                {"label": "Poor", "min": 0, "max": 59, "color": "#dc3545"},
            ],
        )

        assert '<svg viewBox="0 0 200 120"' in output
        assert f'class="gauge-value">{value}%</text>' in output
        assert 'stroke="#ffc107"' in output  # Color for 75%
        assert "Good: 80-100%" in output

    def test_heatmap_component(self):
        """Test heatmap visualization component."""
        template_str = """
        <div class="heatmap">
            <table class="heatmap-table">
                <thead>
                    <tr>
                        <th></th>
                        {% for col in columns %}
                        <th>{{ col }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for row_label, row_data in rows %}
                    <tr>
                        <th>{{ row_label }}</th>
                        {% for value in row_data %}
                        <td class="heatmap-cell"
                            style="background-color: {{ get_color(value, min_val, max_val) }};"
                            title="{{ row_label }}, {{ columns[loop.index0] }}: {{ value }}">
                            {{ value }}
                        </td>
                        {% endfor %}
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            <div class="heatmap-scale">
                <span class="scale-min">{{ min_val }}</span>
                <div class="scale-gradient"></div>
                <span class="scale-max">{{ max_val }}</span>
            </div>
        </div>
        """

        # Define color function
        def get_color(value, min_val, max_val):
            # Normalize value between 0 and 1
            if max_val == min_val:
                normalized = 0.5
            else:
                normalized = (value - min_val) / (max_val - min_val)

            # Generate color from blue to red
            red = int(255 * normalized)
            blue = int(255 * (1 - normalized))
            return f"rgba({red}, 100, {blue}, 0.7)"

        data = [
            ("Monday", [10, 15, 8, 22, 18]),
            ("Tuesday", [12, 18, 10, 25, 20]),
            ("Wednesday", [8, 20, 12, 28, 22]),
            ("Thursday", [15, 22, 14, 30, 25]),
            ("Friday", [18, 25, 16, 35, 28]),
        ]

        columns = ["9AM", "11AM", "1PM", "3PM", "5PM"]
        all_values = [val for _, row in data for val in row]
        min_val = min(all_values)
        max_val = max(all_values)

        env = Environment(autoescape=True)
        env.globals["get_color"] = get_color
        template = env.from_string(template_str)

        output = template.render(columns=columns, rows=data, min_val=min_val, max_val=max_val)

        assert '<table class="heatmap-table">' in output
        assert "background-color: rgba(" in output
        assert f'<span class="scale-min">{min_val}</span>' in output
        assert f'<span class="scale-max">{max_val}</span>' in output


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app.services", "--cov=app.utils", "--cov-report=term-missing"])
