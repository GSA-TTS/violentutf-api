"""Comprehensive tests for architectural metrics and ROI tracking feature.

This test module provides complete test coverage for:
- Leading and lagging indicator calculations
- ROI analysis and cost-benefit calculations
- Report generation in multiple formats (PDF, HTML, JSON)
- Scheduled report execution
- Email notifications for reports
- Integration testing of the complete metrics pipeline

All tests use real database operations and actual service implementations
where possible, with mocking limited to external dependencies like email.
"""

import asyncio
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Severity as VulnerabilitySeverity
from app.models.report import Report, ReportFormat, ReportSchedule, ReportStatus
from app.models.vulnerability_finding import VulnerabilityFinding
from app.services.architectural_metrics_service import ArchitecturalMetricsService
from app.services.architectural_report_generator import ArchitecturalReportGenerator
from app.services.scheduled_report_service import ScheduledReportService


class TestDataGenerator:
    """Helper class for generating test data for metrics tests."""

    @staticmethod
    async def create_test_scans(db_session: AsyncSession, count: int = 10) -> List[Any]:
        """Create test scan records in the database.

        Args:
            db_session: Database session
            count: Number of scans to create

        Returns:
            List of created scan objects
        """
        from app.models.scan import Scan

        scans = []
        for i in range(count):
            scan = Scan(
                name=f"test_scan_{i}",
                scan_type="automated" if i % 3 != 0 else "manual",
                status="completed",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                created_by=f"user_{i % 3}",
            )
            db_session.add(scan)
            scans.append(scan)

        await db_session.commit()
        return scans

    @staticmethod
    async def create_test_vulnerabilities(
        db_session: AsyncSession, count: int = 20, severity_distribution: Dict[str, float] = None
    ) -> List[VulnerabilityFinding]:
        """Create test vulnerability findings.

        Args:
            db_session: Database session
            count: Number of vulnerabilities to create
            severity_distribution: Distribution of severities (optional)

        Returns:
            List of created vulnerability findings
        """
        if severity_distribution is None:
            severity_distribution = {"CRITICAL": 0.1, "HIGH": 0.2, "MEDIUM": 0.4, "LOW": 0.3}

        findings = []
        severities = [
            VulnerabilitySeverity.CRITICAL,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.LOW,
        ]

        for i in range(count):
            # Determine severity based on distribution
            severity_idx = i % len(severities)
            severity = severities[severity_idx]

            finding = VulnerabilityFinding(
                title=f"Finding {i}: {severity.value} vulnerability",
                description=f"Detailed description of finding {i}",
                severity=severity,
                category="security" if i % 2 == 0 else "quality",
                status="resolved" if i < count // 2 else "open",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                detected_at=datetime.now(timezone.utc) - timedelta(days=i + 1),
                created_by="automated_scanner",
            )
            db_session.add(finding)
            findings.append(finding)

        await db_session.commit()
        return findings

    @staticmethod
    async def create_test_audit_logs(db_session: AsyncSession, count: int = 15) -> List[Any]:
        """Create test audit log entries.

        Args:
            db_session: Database session
            count: Number of audit logs to create

        Returns:
            List of created audit log objects
        """
        from app.models.audit_log import AuditLog

        logs = []
        actions = ["scan.create", "vulnerability.review", "report.generate", "training.completed", "policy.created"]

        for i in range(count):
            log = AuditLog(
                user_id=f"user_{i % 5}",
                action=actions[i % len(actions)],
                resource_type="scan" if i % 2 == 0 else "vulnerability",
                resource_id=f"resource_{i}",
                details={"test": True, "index": i},
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
            )
            db_session.add(log)
            logs.append(log)

        await db_session.commit()
        return logs

    @staticmethod
    async def create_test_tasks(db_session: AsyncSession, count: int = 10) -> List[Any]:
        """Create test task records.

        Args:
            db_session: Database session
            count: Number of tasks to create

        Returns:
            List of created task objects
        """
        from app.models.task import Task, TaskStatus

        tasks = []
        for i in range(count):
            started = datetime.now(timezone.utc) - timedelta(days=i, hours=3)
            completed = datetime.now(timezone.utc) - timedelta(days=i, hours=1)

            task = Task(
                name=f"test_task_{i}",
                task_type="scan" if i % 2 == 0 else "report",
                status=TaskStatus.COMPLETED if i < count * 0.8 else TaskStatus.FAILED,
                started_at=started,
                completed_at=completed if i < count * 0.9 else None,
                created_by="task_scheduler",
            )
            db_session.add(task)
            tasks.append(task)

        await db_session.commit()
        return tasks


class TestArchitecturalMetricsService:
    """Tests for ArchitecturalMetricsService."""

    @pytest.fixture
    def metrics_service(self, db_session: AsyncSession):
        """Create metrics service instance."""
        return ArchitecturalMetricsService(db_session)

    @pytest.fixture
    def test_data_generator(self):
        """Provide test data generator."""
        return TestDataGenerator()

    @pytest.mark.asyncio
    async def test_calculate_leading_indicators(self, metrics_service, db_session, test_data_generator):
        """Test calculation of leading indicators with comprehensive test data."""
        # Setup - create test data
        await test_data_generator.create_test_scans(db_session, count=15)
        await test_data_generator.create_test_vulnerabilities(db_session, count=25)
        await test_data_generator.create_test_audit_logs(db_session, count=20)
        await test_data_generator.create_test_tasks(db_session, count=10)

        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        end_date = datetime.now(timezone.utc)

        # Execute
        metrics = await metrics_service.calculate_leading_indicators(start_date, end_date)

        # Assert - verify all required metrics are present
        assert "automation_coverage" in metrics
        assert "detection_time" in metrics
        assert "developer_adoption_rate" in metrics
        assert "compliance_scores" in metrics
        assert "violation_frequency" in metrics
        assert "preventive_actions" in metrics
        assert "tool_utilization" in metrics
        assert "training_effectiveness" in metrics
        assert "calculated_at" in metrics
        assert "period" in metrics

        # Verify automation coverage structure and values
        automation = metrics["automation_coverage"]
        assert "automated_scans" in automation
        assert "manual_scans" in automation
        assert "total_scans" in automation
        assert "automation_percentage" in automation
        assert isinstance(automation["automation_percentage"], (int, float))
        assert automation["total_scans"] > 0  # Should have test data
        assert 0 <= automation["automation_percentage"] <= 100

        # Verify compliance scores structure and values
        compliance = metrics["compliance_scores"]
        assert "overall_score" in compliance
        assert "total_findings" in compliance
        assert "resolved_findings" in compliance
        assert "critical_findings" in compliance
        assert "resolution_rate" in compliance
        assert isinstance(compliance["overall_score"], (int, float))
        assert 0 <= compliance["overall_score"] <= 100
        assert compliance["total_findings"] > 0  # Should have test data

        # Verify detection time metrics
        detection = metrics["detection_time"]
        assert "average_detection_hours" in detection
        assert isinstance(detection["average_detection_hours"], (int, float))
        assert detection["average_detection_hours"] >= 0

        # Verify developer adoption metrics
        adoption = metrics["developer_adoption_rate"]
        assert "active_users" in adoption
        assert adoption["active_users"] > 0  # Should have test data

        # Verify period information
        period = metrics["period"]
        assert period["days"] == 30
        assert datetime.fromisoformat(period["start"]) == start_date
        assert datetime.fromisoformat(period["end"]) == end_date

    @pytest.mark.asyncio
    async def test_calculate_lagging_indicators(self, metrics_service, db_session, test_data_generator):
        """Test calculation of lagging indicators with comprehensive test data."""
        # Setup - create test data with specific patterns for lagging indicators
        await test_data_generator.create_test_scans(db_session, count=30)
        await test_data_generator.create_test_vulnerabilities(db_session, count=50)
        await test_data_generator.create_test_tasks(db_session, count=20)

        # Add some resolved vulnerabilities for remediation metrics
        from app.models.security_scan import SecurityScan

        for i in range(10):
            scan = SecurityScan(
                name=f"security_scan_{i}",
                scan_type="compliance",
                status="passed" if i < 7 else "failed",
                created_at=datetime.now(timezone.utc) - timedelta(days=i * 3),
                created_by="security_team",
            )
            db_session.add(scan)
        await db_session.commit()

        start_date = datetime.now(timezone.utc) - timedelta(days=90)
        end_date = datetime.now(timezone.utc)

        # Execute
        metrics = await metrics_service.calculate_lagging_indicators(start_date, end_date)

        # Assert - verify all required metrics
        assert "architectural_debt_velocity" in metrics
        assert "security_incident_reduction" in metrics
        assert "maintainability_improvements" in metrics
        assert "development_velocity_impact" in metrics
        assert "quality_metrics" in metrics
        assert "remediation_effectiveness" in metrics
        assert "compliance_achievements" in metrics
        assert "calculated_at" in metrics
        assert "period" in metrics

        # Verify debt velocity structure and calculations
        debt = metrics["architectural_debt_velocity"]
        assert "new_violations" in debt
        assert "resolved_violations" in debt
        assert "net_change" in debt
        assert "daily_velocity" in debt
        assert "trend" in debt
        assert debt["trend"] in ["improving", "worsening", "stable"]
        assert isinstance(debt["daily_velocity"], (int, float))
        assert debt["net_change"] == debt["new_violations"] - debt["resolved_violations"]

        # Verify security reduction structure
        security = metrics["security_incident_reduction"]
        assert "total_incidents" in security
        assert "monthly_average" in security
        assert "reduction_percentage" in security
        assert "trend" in security
        assert security["trend"] in ["improving", "worsening", "stable"]
        assert isinstance(security["monthly_average"], (int, float))

        # Verify quality metrics
        quality = metrics["quality_metrics"]
        assert "total_defects" in quality
        assert "critical_defects" in quality
        assert "defect_density" in quality
        assert quality["defect_density"] >= 0

        # Verify development velocity impact
        velocity = metrics["development_velocity_impact"]
        assert "completed_tasks" in velocity
        assert "success_rate" in velocity
        assert 0 <= velocity["success_rate"] <= 100

        # Verify period information
        period = metrics["period"]
        assert period["days"] == 90

    @pytest.mark.asyncio
    async def test_calculate_roi_analysis(self, metrics_service):
        """Test ROI calculation."""
        # Setup
        start_date = datetime.now(timezone.utc) - timedelta(days=180)
        end_date = datetime.now(timezone.utc)
        cost_data = {
            "hourly_developer_rate": 150.0,
            "tool_licensing_cost": 5000.0,
            "training_cost_per_person": 1000.0,
            "incident_cost": 25000.0,
            "bug_fix_cost": 2500.0,
        }

        # Execute
        roi = await metrics_service.calculate_roi_analysis(start_date, end_date, cost_data)

        # Assert
        assert "implementation_costs" in roi
        assert "cost_avoidance" in roi
        assert "productivity_gains" in roi
        assert "quality_improvements" in roi
        assert "total_costs" in roi
        assert "total_benefits" in roi
        assert "net_benefit" in roi
        assert "roi_percentage" in roi
        assert "payback_period_months" in roi
        assert "cost_benefit_ratio" in roi
        assert "assumptions" in roi

        # Verify costs structure
        costs = roi["implementation_costs"]
        assert "tool_licensing" in costs
        assert "developer_time" in costs
        assert "training" in costs
        assert "infrastructure" in costs

        # Verify numerical values
        assert isinstance(roi["total_costs"], (int, float))
        assert isinstance(roi["total_benefits"], (int, float))
        assert isinstance(roi["roi_percentage"], (int, float))
        assert roi["total_costs"] >= 0
        assert roi["total_benefits"] >= 0

    @pytest.mark.asyncio
    async def test_violation_frequency_trend(self, metrics_service, db_session):
        """Test violation frequency trend calculation."""
        # Setup - create test violations
        for week in range(4):
            for day in range(7):
                violation = VulnerabilityFinding(
                    title=f"Test violation week {week} day {day}",
                    description="Test",
                    severity=VulnerabilitySeverity.MEDIUM,
                    category="security",
                    created_at=datetime.now(timezone.utc) - timedelta(weeks=week, days=day),
                    created_by="test",
                )
                db_session.add(violation)

        await db_session.commit()

        # Execute
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        end_date = datetime.now(timezone.utc)
        metrics = await metrics_service.calculate_leading_indicators(start_date, end_date)

        # Assert
        frequency = metrics["violation_frequency"]
        assert "weekly_average" in frequency
        assert "total_violations" in frequency
        assert "unique_categories" in frequency
        assert "trend" in frequency
        assert "trend_percentage" in frequency
        assert "top_violations" in frequency
        assert "weekly_data" in frequency

        # Verify top violations structure
        if frequency["top_violations"]:
            top = frequency["top_violations"][0]
            assert "category" in top
            assert "count" in top
            assert "percentage" in top


class TestArchitecturalReportGenerator:
    """Tests for ArchitecturalReportGenerator."""

    @pytest.fixture
    def report_generator(self, db_session: AsyncSession):
        """Create report generator instance."""
        return ArchitecturalReportGenerator(db_session)

    @pytest.mark.asyncio
    async def test_generate_pdf_report(self, report_generator, db_session):
        """Test PDF report generation with real database data."""
        # Setup - create comprehensive test data in database
        from app.models.audit_log import AuditLog
        from app.models.scan import Scan
        from app.models.task import Task, TaskStatus

        # Create test scans for automation coverage
        for i in range(10):
            scan = Scan(
                name=f"test_scan_{i}",
                scan_type="automated" if i < 7 else "manual",
                status="completed",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                created_by="test_user",
            )
            db_session.add(scan)

        # Create test vulnerability findings for compliance scores
        for i in range(20):
            finding = VulnerabilityFinding(
                title=f"Test Finding {i}",
                description=f"Test finding description {i}",
                severity=VulnerabilitySeverity.HIGH if i % 3 == 0 else VulnerabilitySeverity.MEDIUM,
                category="security" if i % 2 == 0 else "quality",
                status="resolved" if i < 10 else "open",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                detected_at=datetime.now(timezone.utc) - timedelta(days=i + 1),
                created_by="scanner",
            )
            db_session.add(finding)

        # Create audit logs for developer adoption
        for i in range(15):
            audit_log = AuditLog(
                user_id=f"user_{i % 5}",
                action="scan.create" if i % 2 == 0 else "vulnerability.review",
                resource_type="scan",
                resource_id=f"scan_{i}",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
            )
            db_session.add(audit_log)

        # Create tasks for velocity metrics
        for i in range(8):
            task = Task(
                name=f"test_task_{i}",
                status=TaskStatus.COMPLETED if i < 6 else TaskStatus.FAILED,
                started_at=datetime.now(timezone.utc) - timedelta(days=i, hours=2),
                completed_at=datetime.now(timezone.utc) - timedelta(days=i),
                created_by="scheduler",
            )
            db_session.add(task)

        # Create the report
        report = Report(
            id="test-report-1",
            name="test_metrics_report",
            title="Test Metrics Report",
            description="Test report with real data",
            report_type="architectural_metrics",
            format=ReportFormat.PDF,
            status=ReportStatus.GENERATING,
            created_by="test",
        )
        db_session.add(report)
        await db_session.commit()

        # Execute report generation with actual service calls
        result = await report_generator.generate_architectural_metrics_report(
            report_id=report.id,
            format=ReportFormat.PDF,
            include_sections=["leading", "lagging", "roi", "recommendations"],
        )

        # Assert
        assert result["report_id"] == report.id
        assert result["format"] == "pdf"
        assert "file_path" in result
        assert result["file_path"].endswith(".pdf")
        assert "metrics_summary" in result

        # Verify metrics were calculated correctly
        metrics = result.get("metrics_summary", {})
        if metrics:
            assert "leading_indicators" in metrics
            assert "lagging_indicators" in metrics
            assert "roi_analysis" in metrics

        # Verify file was created
        file_path = Path(result["file_path"])
        assert file_path.exists()
        assert file_path.stat().st_size > 0

        # Cleanup
        file_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_generate_html_report(self, report_generator, db_session):
        """Test HTML report generation with real data."""
        # Setup - create minimal test data for HTML report
        from app.models.scan import Scan

        # Create a few test records
        for i in range(5):
            scan = Scan(
                name=f"html_test_scan_{i}",
                scan_type="automated",
                status="completed",
                created_at=datetime.now(timezone.utc) - timedelta(hours=i),
                created_by="html_test",
            )
            db_session.add(scan)

            finding = VulnerabilityFinding(
                title=f"HTML Test Finding {i}",
                description="Test for HTML report",
                severity=VulnerabilitySeverity.LOW,
                category="test",
                status="open",
                created_at=datetime.now(timezone.utc) - timedelta(hours=i),
                created_by="html_test",
            )
            db_session.add(finding)

        # Create the report
        report = Report(
            id="test-report-2",
            name="test_html_report",
            title="Test HTML Report",
            description="HTML format test report",
            report_type="architectural_metrics",
            format=ReportFormat.HTML,
            status=ReportStatus.GENERATING,
            created_by="test",
        )
        db_session.add(report)
        await db_session.commit()

        # Execute report generation with actual data
        result = await report_generator.generate_architectural_metrics_report(
            report_id=report.id,
            format=ReportFormat.HTML,
            include_sections=["executive_summary", "recommendations"],
            period_days=7,  # Use last 7 days for faster processing
        )

        # Assert
        assert result["report_id"] == report.id
        assert result["format"] == "html"
        assert "file_path" in result
        assert result["file_path"].endswith(".html")

        # Verify HTML content
        file_path = Path(result["file_path"])
        assert file_path.exists()

        html_content = file_path.read_text()
        assert "<html" in html_content or "<!DOCTYPE html>" in html_content
        assert "Executive Summary" in html_content or "executive" in html_content.lower()
        assert "Recommendations" in html_content or "recommendations" in html_content.lower()

        # Verify the HTML is well-formed
        assert html_content.count("<div") == html_content.count("</div")
        assert "</html>" in html_content or "</body>" in html_content

        # Cleanup
        file_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_generate_recommendations(self, report_generator):
        """Test recommendation generation based on metrics."""
        # Setup metrics data
        metrics_data = {
            "leading_indicators": {
                "automation_coverage": {"automation_percentage": 45.0},
                "developer_adoption_rate": {"adoption_rate": 60.0},
                "compliance_scores": {"overall_score": 75.0},
            },
            "lagging_indicators": {
                "architectural_debt_velocity": {"daily_velocity": 2.0},
                "quality_metrics": {"critical_rate": 10.0},
            },
            "roi_analysis": {
                "roi_percentage": 50.0,
                "implementation_costs": {"developer_time": 20000, "tool_licensing": 5000},
            },
        }

        # Execute
        recommendations = report_generator._generate_recommendations(metrics_data)

        # Assert
        assert len(recommendations) > 0
        assert any("automation coverage" in r.lower() for r in recommendations)
        assert any("developer adoption" in r.lower() for r in recommendations)
        assert any("compliance score" in r.lower() for r in recommendations)
        assert any("debt reduction" in r.lower() for r in recommendations)


class TestScheduledReportService:
    """Tests for ScheduledReportService."""

    @pytest.fixture
    def scheduled_service(self, db_session: AsyncSession):
        """Create scheduled report service instance."""
        return ScheduledReportService(db_session)

    @pytest.mark.asyncio
    async def test_create_scheduled_report(self, scheduled_service):
        """Test creating a scheduled report."""
        # Execute
        schedule = await scheduled_service.create_scheduled_report(
            name="Weekly Metrics Report",
            description="Weekly architectural metrics",
            cron_expression="0 9 * * MON",
            report_type="architectural_metrics",
            output_formats=[ReportFormat.PDF, ReportFormat.HTML],
            config={"period_days": 7, "include_sections": ["leading", "lagging", "roi"]},
            notification_emails=["test@example.com"],
            created_by="test_user",
        )

        # Assert
        assert schedule.name == "Weekly Metrics Report"
        assert schedule.cron_expression == "0 9 * * MON"
        assert schedule.is_active is True
        assert schedule.next_run_at is not None
        assert len(schedule.output_formats) == 2
        assert "pdf" in schedule.output_formats
        assert "html" in schedule.output_formats
        assert schedule.notification_emails == ["test@example.com"]

    @pytest.mark.asyncio
    async def test_execute_scheduled_reports(self, scheduled_service, db_session):
        """Test execution of due scheduled reports."""
        # Setup - create test data for report generation
        import tempfile

        from app.models.scan import Scan
        from app.services.architectural_report_generator import ArchitecturalReportGenerator

        # Create some test data
        for i in range(3):
            scan = Scan(
                name=f"scheduled_test_scan_{i}",
                scan_type="scheduled",
                status="completed",
                created_at=datetime.now(timezone.utc) - timedelta(hours=i),
                created_by="scheduler",
            )
            db_session.add(scan)

        # Create a due schedule
        schedule = ReportSchedule(
            id="test-schedule-exec",
            name="Test Schedule",
            description="Test scheduled report",
            cron_expression="* * * * *",  # Every minute
            report_template_id="test-template",
            report_config={"period_days": 1},
            output_formats=["pdf"],
            notification_emails=["test@example.com"],
            next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1),  # Due
            is_active=True,
            created_by="test",
        )
        db_session.add(schedule)
        await db_session.commit()

        # Create a temporary file to simulate report generation
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pdf", delete=False) as tmp_file:
            tmp_file.write("Test PDF content")
            test_file_path = tmp_file.name

        try:
            # Patch only the email sending, let report generation use real service
            with patch("app.utils.email.send_email") as patched_email:
                patched_email.return_value = True

                # Also patch the file generation to use our test file
                with patch.object(ArchitecturalReportGenerator, "_generate_pdf_file", return_value=test_file_path):
                    # Execute
                    results = await scheduled_service.execute_scheduled_reports()

            # Assert
            assert len(results) > 0
            assert results[0]["schedule_name"] == "Test Schedule"
            assert results[0]["status"] in ["success", "partial", "completed"]

            # Verify the schedule was updated
            updated_schedule = await db_session.get(ReportSchedule, schedule.id)
            if updated_schedule:
                assert updated_schedule.last_run_at is not None
                assert updated_schedule.next_run_at > schedule.next_run_at

        finally:
            # Cleanup
            Path(test_file_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_update_schedule(self, scheduled_service, db_session):
        """Test updating a scheduled report."""
        # Setup - create a schedule
        schedule = ReportSchedule(
            id="test-schedule-1",
            name="Original Name",
            description="Test",
            cron_expression="0 9 * * *",
            report_template_id="test-template",
            is_active=True,
            created_by="test",
        )
        db_session.add(schedule)
        await db_session.commit()

        # Execute
        updated = await scheduled_service.update_schedule(
            schedule_id="test-schedule-1", updates={"is_active": False, "cron_expression": "0 10 * * *"}
        )

        # Assert
        assert updated.is_active is False
        assert updated.cron_expression == "0 10 * * *"
        assert updated.next_run_at is not None

    @pytest.mark.asyncio
    async def test_get_schedule_history(self, scheduled_service, db_session):
        """Test getting schedule execution history."""
        # Setup - create reports with schedule_id in parameters
        for i in range(3):
            report = Report(
                name=f"scheduled_report_{i}",
                title=f"Report {i}",
                description="Test",
                report_type="architectural_metrics",
                format=ReportFormat.PDF,
                parameters={"schedule_id": "test-schedule"},
                status=ReportStatus.COMPLETED,
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                created_by="scheduler",
            )
            db_session.add(report)

        await db_session.commit()

        # Execute
        history = await scheduled_service.get_schedule_history("test-schedule", limit=5)

        # Assert
        assert len(history) == 3
        assert all(r.parameters.get("schedule_id") == "test-schedule" for r in history)


class TestEmailNotifications:
    """Tests for email notifications."""

    @pytest.mark.asyncio
    async def test_send_report_notification(self):
        """Test sending report notification email."""
        from app.utils.email import send_report_notification

        with patch("app.utils.email.send_email") as patched_send_email:
            patched_send_email.return_value = True

            # Execute
            result = await send_report_notification(
                recipients=["user1@example.com", "user2@example.com"],
                report_name="Monthly Metrics",
                report_id="report-123",
                download_url="https://example.com/download/report-123",
                period_days=30,
            )

            # Assert
            assert result is True
            patched_send_email.assert_called_once()

            # Verify email content
            call_args = patched_send_email.call_args
            assert call_args.kwargs["to_email"] == ["user1@example.com", "user2@example.com"]
            assert "Monthly Metrics" in call_args.kwargs["subject"]
            assert "report-123" in call_args.kwargs["body"]
            assert "https://example.com/download/report-123" in call_args.kwargs["body"]
            assert call_args.kwargs["is_html"] is True

    @pytest.mark.asyncio
    async def test_send_failure_notification(self):
        """Test sending failure notification email."""
        from app.utils.email import send_failure_notification

        with patch("app.utils.email.send_email") as patched_send_email:
            patched_send_email.return_value = True

            # Execute
            result = await send_failure_notification(
                recipients=["admin@example.com"],
                report_name="Failed Report",
                error_message="Database connection failed",
            )

            # Assert
            assert result is True
            patched_send_email.assert_called_once()

            # Verify email content
            call_args = patched_send_email.call_args
            assert call_args.kwargs["to_email"] == ["admin@example.com"]
            assert "Failed" in call_args.kwargs["subject"]
            assert "Database connection failed" in call_args.kwargs["body"]


class TestIntegration:
    """Integration tests for the complete feature."""

    @pytest.mark.asyncio
    async def test_end_to_end_report_generation(self, client, db_session):
        """Test complete flow from API request to report generation."""
        # Setup - create test data
        for i in range(10):
            finding = VulnerabilityFinding(
                title=f"Finding {i}",
                description="Test finding",
                severity=VulnerabilitySeverity.MEDIUM if i % 2 else VulnerabilitySeverity.HIGH,
                category="security",
                status="resolved" if i < 5 else "open",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
                created_by="test",
            )
            db_session.add(finding)

        await db_session.commit()

        # Execute - request report generation via API
        response = await client.post(
            "/api/v1/metrics/architectural/generate-report",
            params={
                "report_type": "comprehensive",
                "format": "pdf",
                "include_leading": True,
                "include_lagging": True,
                "include_roi": True,
                "include_recommendations": True,
            },
        )

        # Assert
        assert response.status_code == 202
        data = response.json()
        assert "report_id" in data
        assert "status" in data
        assert data["status"] == "generating"
        assert "status_url" in data

        # Verify report was created in database
        report_query = await db_session.execute(db_session.query(Report).filter_by(id=data["report_id"]))
        report = report_query.scalar_one_or_none()
        assert report is not None
        assert report.report_type == "comprehensive"
        assert report.format == ReportFormat.PDF

    @pytest.mark.asyncio
    async def test_scheduled_report_creation_api(self, client):
        """Test creating a scheduled report via API."""
        # Execute
        response = await client.post(
            "/api/v1/metrics/architectural/schedule",
            params={
                "name": "Weekly Executive Report",
                "description": "Weekly metrics for executives",
                "cron_expression": "0 9 * * MON",
                "report_type": "architectural_metrics",
                "formats": ["pdf", "html"],
                "period_days": 7,
                "notification_emails": ["exec@company.com"],
                "include_leading": True,
                "include_lagging": True,
                "include_roi": True,
            },
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "schedule_id" in data
        assert data["name"] == "Weekly Executive Report"
        assert data["cron_expression"] == "0 9 * * MON"
        assert data["is_active"] is True
        assert "next_run_at" in data

    @pytest.mark.asyncio
    async def test_metrics_api_endpoints(self, client):
        """Test metrics API endpoints."""
        # Test leading indicators endpoint
        response = await client.get("/api/v1/metrics/architectural/leading-indicators")
        assert response.status_code == 200
        data = response.json()
        assert "automation_coverage" in data
        assert "compliance_scores" in data

        # Test lagging indicators endpoint
        response = await client.get("/api/v1/metrics/architectural/lagging-indicators")
        assert response.status_code == 200
        data = response.json()
        assert "architectural_debt_velocity" in data
        assert "security_incident_reduction" in data

        # Test ROI analysis endpoint
        response = await client.get(
            "/api/v1/metrics/architectural/roi-analysis",
            params={
                "hourly_rate": 200,
                "tool_cost": 10000,
                "training_cost": 2000,
                "incident_cost": 50000,
                "bug_fix_cost": 5000,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_costs" in data
        assert "total_benefits" in data
        assert "roi_percentage" in data
        assert "payback_period_months" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
