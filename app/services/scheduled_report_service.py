"""Scheduled Report Service for Architectural Metrics.

This service handles scheduled generation of architectural metrics reports
with email notifications for stakeholders.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.report import Report, ReportFormat, ReportSchedule, ReportStatus, ReportTemplate
from app.models.task import Task, TaskStatus
from app.models.user import User
from app.services.architectural_report_generator import ArchitecturalReportGenerator
from app.utils.email import send_email

logger = logging.getLogger(__name__)


class ScheduledReportService:
    """Service for managing scheduled architectural reports."""

    def __init__(self, db_session: AsyncSession):
        """Initialize the scheduled report service.

        Args:
            db_session: AsyncSQL database session
        """
        self.db = db_session
        self.report_generator = ArchitecturalReportGenerator(db_session)

    async def create_scheduled_report(
        self,
        name: str,
        description: str,
        cron_expression: str,
        report_type: str,
        output_formats: List[ReportFormat],
        config: Dict[str, Any],
        notification_emails: List[str],
        created_by: str,
    ) -> ReportSchedule:
        """Create a new scheduled report.

        Args:
            name: Schedule name
            description: Schedule description
            cron_expression: Cron expression for scheduling
            report_type: Type of report to generate
            output_formats: List of output formats
            config: Report configuration
            notification_emails: Email addresses for notifications
            created_by: Username of creator

        Returns:
            Created ReportSchedule instance
        """
        try:
            # Validate cron expression using APScheduler's CronTrigger
            try:
                cron_trigger = CronTrigger.from_crontab(cron_expression)
                next_run = cron_trigger.get_next_fire_time(None, datetime.now(timezone.utc))
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid cron expression: {cron_expression}") from e

            # Get or create template for architectural metrics
            template = await self._get_or_create_template(report_type)

            # Create schedule
            schedule = ReportSchedule(
                name=name,
                description=description,
                cron_expression=cron_expression,
                report_template_id=template.id,
                report_config=config,
                output_formats=[f.value for f in output_formats],
                notification_emails=notification_emails,
                next_run_at=next_run,
                created_by=created_by,
                is_active=True,
            )

            self.db.add(schedule)
            await self.db.commit()
            await self.db.refresh(schedule)

            logger.info(f"Created scheduled report: {schedule.name}")
            return schedule

        except Exception as e:
            logger.error(f"Error creating scheduled report: {e}")
            await self.db.rollback()
            raise

    async def execute_scheduled_reports(self) -> List[Dict[str, Any]]:
        """Execute all due scheduled reports.

        Returns:
            List of execution results
        """
        results = []

        try:
            # Find all active schedules due for execution
            now = datetime.now(timezone.utc)

            schedules_query = select(ReportSchedule).where(
                and_(ReportSchedule.is_active.is_(True), ReportSchedule.next_run_at <= now)
            )

            result = await self.db.execute(schedules_query)
            schedules = result.scalars().all()

            for schedule in schedules:
                try:
                    execution_result = await self._execute_schedule(schedule)
                    results.append(execution_result)

                    # Update next run time using APScheduler's CronTrigger
                    cron_trigger = CronTrigger.from_crontab(schedule.cron_expression)
                    schedule.next_run_at = cron_trigger.get_next_fire_time(None, now)
                    schedule.last_run_at = now
                    schedule.total_runs += 1

                    if execution_result["status"] == "success":
                        schedule.successful_runs += 1
                    else:
                        schedule.failed_runs += 1

                    await self.db.commit()

                except Exception as e:
                    logger.error(f"Error executing schedule {schedule.name}: {e}")
                    results.append(
                        {
                            "schedule_id": schedule.id,
                            "schedule_name": schedule.name,
                            "status": "failed",
                            "error": str(e),
                        }
                    )

            return results

        except Exception as e:
            logger.error(f"Error executing scheduled reports: {e}")
            raise

    async def _execute_schedule(self, schedule: ReportSchedule) -> Dict[str, Any]:
        """Execute a single scheduled report.

        Args:
            schedule: ReportSchedule to execute

        Returns:
            Execution result dictionary
        """
        try:
            # Determine date range based on config
            config = schedule.report_config
            period_days = config.get("period_days", 30)
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=period_days)

            report_results = []

            # Generate report in each requested format
            for format_str in schedule.output_formats:
                format_enum = ReportFormat(format_str)

                # Create report record
                report = Report(
                    name=f"{schedule.name}_{datetime.now().strftime('%Y%m%d')}",
                    title=f"Scheduled Report: {schedule.name}",
                    description=schedule.description,
                    report_type=config.get("report_type", "architectural_metrics"),
                    format=format_enum,
                    template_id=schedule.report_template_id,
                    config=config,
                    parameters={
                        "start_date": start_date.isoformat(),
                        "end_date": end_date.isoformat(),
                        "schedule_id": schedule.id,
                    },
                    status=ReportStatus.GENERATING,
                    created_by="system_scheduler",
                )

                self.db.add(report)
                await self.db.commit()
                await self.db.refresh(report)

                # Generate report
                try:
                    result = await self.report_generator.generate_architectural_metrics_report(
                        report_id=report.id,
                        format=format_enum,
                        start_date=start_date,
                        end_date=end_date,
                        include_sections=config.get(
                            "include_sections", ["leading", "lagging", "roi", "executive_summary", "recommendations"]
                        ),
                    )

                    report_results.append(
                        {
                            "report_id": report.id,
                            "format": format_str,
                            "file_path": result["file_path"],
                            "status": "success",
                        }
                    )

                except Exception as e:
                    logger.error(f"Error generating report {report.id}: {e}")
                    report.status = ReportStatus.FAILED
                    report.error_message = str(e)
                    await self.db.commit()

                    report_results.append(
                        {"report_id": report.id, "format": format_str, "status": "failed", "error": str(e)}
                    )

            # Send notifications
            if schedule.notification_emails and any(r["status"] == "success" for r in report_results):
                await self._send_notifications(schedule, report_results)

            return {
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "status": "success" if all(r["status"] == "success" for r in report_results) else "partial",
                "reports": report_results,
            }

        except Exception as e:
            logger.error(f"Error executing schedule {schedule.id}: {e}")
            return {"schedule_id": schedule.id, "schedule_name": schedule.name, "status": "failed", "error": str(e)}

    async def _get_or_create_template(self, report_type: str) -> ReportTemplate:
        """Get or create a report template for architectural metrics.

        Args:
            report_type: Type of report

        Returns:
            ReportTemplate instance
        """
        # Check if template exists
        template_query = select(ReportTemplate).where(ReportTemplate.name == f"architectural_{report_type}")
        result = await self.db.execute(template_query)
        template = result.scalar_one_or_none()

        if not template:
            # Create default template
            template = ReportTemplate(
                name=f"architectural_{report_type}",
                display_name=f"Architectural {report_type.replace('_', ' ').title()} Report",
                description="Template for architectural metrics and ROI tracking reports",
                template_type="custom_report",
                supported_formats=["pdf", "html"],
                template_content={
                    "sections": [
                        {"id": "executive_summary", "title": "Executive Summary", "required": False},
                        {"id": "leading_indicators", "title": "Leading Indicators", "required": True},
                        {"id": "lagging_indicators", "title": "Lagging Indicators", "required": True},
                        {"id": "roi_analysis", "title": "ROI Analysis", "required": False},
                        {"id": "recommendations", "title": "Recommendations", "required": False},
                    ]
                },
                default_config={"period_days": 30, "include_charts": True, "include_tables": True},
                category="architectural",
                tags=["metrics", "roi", "audit", "compliance"],
                is_active=True,
                created_by="system",
            )

            self.db.add(template)
            await self.db.commit()
            await self.db.refresh(template)

        return template

    async def _send_notifications(self, schedule: ReportSchedule, report_results: List[Dict[str, Any]]) -> None:
        """Send email notifications for completed reports.

        Args:
            schedule: ReportSchedule that was executed
            report_results: List of report generation results
        """
        try:
            # Filter successful reports
            successful_reports = [r for r in report_results if r["status"] == "success"]

            if not successful_reports:
                return

            # Build email content
            subject = f"Scheduled Report: {schedule.name} - {datetime.now().strftime('%Y-%m-%d')}"

            body = f"""
            <html>
            <body>
                <h2>Architectural Metrics Report Available</h2>
                <p>Your scheduled report <strong>{schedule.name}</strong> has been generated successfully.</p>

                <h3>Report Details:</h3>
                <ul>
                    <li><strong>Generated at:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                    <li><strong>Period:</strong> Last {schedule.report_config.get('period_days', 30)} days</li>
                    <li><strong>Formats:</strong> {', '.join(r['format'] for r in successful_reports)}</li>
                </ul>

                <h3>Download Links:</h3>
                <ul>
            """

            # Add download links
            base_url = settings.API_BASE_URL if hasattr(settings, "API_BASE_URL") else "http://localhost:8000"
            for report in successful_reports:
                download_url = f"{base_url}/api/v1/reports/{report['report_id']}/download"
                body += f'<li><a href="{download_url}">{report["format"].upper()} Report</a></li>'

            body += """
                </ul>

                <p>Best regards,<br>
                Architectural Audit System</p>
            </body>
            </html>
            """

            # Send emails
            for email in schedule.notification_emails:
                try:
                    await send_email(to_email=email, subject=subject, body=body, is_html=True)
                    logger.info(f"Sent notification to {email} for schedule {schedule.name}")
                except Exception as e:
                    logger.error(f"Failed to send email to {email}: {e}")

        except Exception as e:
            logger.error(f"Error sending notifications for schedule {schedule.id}: {e}")

    async def update_schedule(self, schedule_id: str, updates: Dict[str, Any]) -> ReportSchedule:
        """Update a scheduled report configuration.

        Args:
            schedule_id: Schedule ID to update
            updates: Dictionary of updates

        Returns:
            Updated ReportSchedule instance
        """
        try:
            # Get schedule
            schedule_query = select(ReportSchedule).where(ReportSchedule.id == schedule_id)
            result = await self.db.execute(schedule_query)
            schedule = result.scalar_one_or_none()

            if not schedule:
                raise ValueError(f"Schedule {schedule_id} not found")

            # Apply updates
            for key, value in updates.items():
                if hasattr(schedule, key):
                    setattr(schedule, key, value)

            # Update next run time if cron changed
            if "cron_expression" in updates:
                try:
                    cron_trigger = CronTrigger.from_crontab(updates["cron_expression"])
                    schedule.next_run_at = cron_trigger.get_next_fire_time(None, datetime.now(timezone.utc))
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Invalid cron expression: {updates['cron_expression']}") from e

            await self.db.commit()
            await self.db.refresh(schedule)

            return schedule

        except Exception as e:
            logger.error(f"Error updating schedule {schedule_id}: {e}")
            await self.db.rollback()
            raise

    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete (deactivate) a scheduled report.

        Args:
            schedule_id: Schedule ID to delete

        Returns:
            Success status
        """
        try:
            # Get schedule
            schedule_query = select(ReportSchedule).where(ReportSchedule.id == schedule_id)
            result = await self.db.execute(schedule_query)
            schedule = result.scalar_one_or_none()

            if not schedule:
                return False

            # Soft delete
            schedule.is_active = False
            schedule.updated_at = datetime.now(timezone.utc)

            await self.db.commit()

            logger.info(f"Deactivated schedule: {schedule.name}")
            return True

        except Exception as e:
            logger.error(f"Error deleting schedule {schedule_id}: {e}")
            await self.db.rollback()
            raise

    async def get_schedule_history(self, schedule_id: str, limit: int = 10) -> List[Report]:
        """Get execution history for a scheduled report.

        Args:
            schedule_id: Schedule ID
            limit: Maximum number of reports to return

        Returns:
            List of Report instances
        """
        try:
            # Query reports generated by this schedule
            reports_query = (
                select(Report)
                .where(Report.parameters["schedule_id"].astext == schedule_id)
                .order_by(desc(Report.created_at))
                .limit(limit)
            )

            result = await self.db.execute(reports_query)
            reports = result.scalars().all()

            return reports

        except Exception as e:
            logger.error(f"Error getting schedule history: {e}")
            raise
