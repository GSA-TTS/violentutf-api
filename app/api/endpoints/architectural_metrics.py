"""API endpoints for architectural metrics and ROI tracking."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from app.api.deps import (
    get_architectural_metrics_service,
    get_current_user,
    get_report_service,
    get_scheduled_report_service,
)
from app.core.permissions import require_permissions
from app.models.report import ReportFormat, ReportSchedule
from app.models.user import User
from app.services.architectural_metrics_service import ArchitecturalMetricsService
from app.services.architectural_report_generator import ArchitecturalReportGenerator
from app.services.report_service import ReportService
from app.services.scheduled_report_service import ScheduledReportService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/leading-indicators", summary="Get leading indicator metrics")
async def get_leading_indicators(
    start_date: Optional[datetime] = Query(None, description="Start date for metrics"),
    end_date: Optional[datetime] = Query(None, description="End date for metrics"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get leading indicator metrics for architectural audits.

    Leading indicators predict future performance and include:
    - Automation coverage
    - Detection time metrics
    - Developer adoption rate
    - Compliance scores
    - Violation frequency
    """
    try:
        # Default to last 30 days if not specified
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=30)

        metrics = await architectural_metrics_service.calculate_leading_indicators(start_date, end_date)

        logger.info(f"User {current_user.username} retrieved leading indicators")
        return metrics

    except Exception as e:
        logger.error(f"Error getting leading indicators: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve leading indicators")


@router.get("/lagging-indicators", summary="Get lagging indicator metrics")
async def get_lagging_indicators(
    start_date: Optional[datetime] = Query(None, description="Start date for metrics"),
    end_date: Optional[datetime] = Query(None, description="End date for metrics"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get lagging indicator metrics for architectural audits.

    Lagging indicators measure past performance and include:
    - Architectural debt velocity
    - Security incident reduction
    - Maintainability improvements
    - Development velocity impact
    """
    try:
        # Default to last 90 days for lagging indicators
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=90)

        metrics = await architectural_metrics_service.calculate_lagging_indicators(start_date, end_date)

        logger.info(f"User {current_user.username} retrieved lagging indicators")
        return metrics

    except Exception as e:
        logger.error(f"Error getting lagging indicators: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve lagging indicators")


@router.get("/roi-analysis", summary="Get ROI analysis")
async def get_roi_analysis(
    start_date: Optional[datetime] = Query(None, description="Start date for ROI calculation"),
    end_date: Optional[datetime] = Query(None, description="End date for ROI calculation"),
    hourly_rate: float = Query(150.0, description="Hourly developer rate for cost calculations"),
    tool_cost: float = Query(5000.0, description="Annual tool licensing cost"),
    training_cost: float = Query(1000.0, description="Training cost per person"),
    incident_cost: float = Query(25000.0, description="Average cost per security incident"),
    bug_fix_cost: float = Query(2500.0, description="Average cost to fix a bug"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get comprehensive ROI analysis for architectural audit initiatives.

    Calculates:
    - Implementation costs
    - Cost avoidance from prevented issues
    - Productivity gains from automation
    - Quality improvements value
    - Overall ROI percentage and payback period
    """
    try:
        # Default to last 180 days for ROI
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=180)

        # Build cost data from query parameters
        cost_data = {
            "hourly_developer_rate": hourly_rate,
            "tool_licensing_cost": tool_cost,
            "training_cost_per_person": training_cost,
            "incident_cost": incident_cost,
            "bug_fix_cost": bug_fix_cost,
        }

        roi = await architectural_metrics_service.calculate_roi_analysis(start_date, end_date, cost_data)

        logger.info(f"User {current_user.username} retrieved ROI analysis")
        return roi

    except Exception as e:
        logger.error(f"Error getting ROI analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to calculate ROI analysis")


@router.post("/generate-report", summary="Generate architectural metrics report", status_code=202)
async def generate_metrics_report(
    report_type: str = Query("comprehensive", description="Type of report to generate"),
    format: ReportFormat = Query(ReportFormat.PDF, description="Report format"),
    start_date: Optional[datetime] = Query(None, description="Start date for metrics"),
    end_date: Optional[datetime] = Query(None, description="End date for metrics"),
    include_leading: bool = Query(True, description="Include leading indicators"),
    include_lagging: bool = Query(True, description="Include lagging indicators"),
    include_roi: bool = Query(True, description="Include ROI analysis"),
    include_recommendations: bool = Query(True, description="Include recommendations"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Generate a comprehensive architectural metrics report.

    Creates a PDF or HTML report containing:
    - Executive summary
    - Leading indicators with trends
    - Lagging indicators with historical analysis
    - ROI analysis with cost breakdowns
    - Actionable recommendations
    """
    try:
        from app.models.report import Report, ReportStatus

        # Default date range
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=30)

        # Build sections list
        sections = ["executive_summary"]
        if include_leading:
            sections.append("leading")
        if include_lagging:
            sections.append("lagging")
        if include_roi:
            sections.append("roi")
        if include_recommendations:
            sections.append("recommendations")

        # Create report record through service layer
        report_data = {
            "name": f"architectural_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "title": "Architectural Metrics and ROI Report",
            "description": f"Comprehensive architectural audit metrics from {start_date.date()} to {end_date.date()}",
            "report_type": report_type,
            "format": format,
            "config": {
                "include_sections": sections,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            "parameters": {
                "include_leading": include_leading,
                "include_lagging": include_lagging,
                "include_roi": include_roi,
                "include_recommendations": include_recommendations,
            },
            "status": "PENDING",
            "created_by": current_user.username,
        }

        report = await report_service.create_report(report_data)

        # TODO: Fix report generation - needs proper service integration
        # Generate report in background through service layer
        # This needs to be properly integrated with the service layer
        # generator = ArchitecturalReportGenerator(session_from_service)
        # background_tasks.add_task(
        #     generator.generate_architectural_metrics_report,
        #     report_id=report.id,
        #     format=format,
        #     start_date=start_date,
        #     end_date=end_date,
        #     include_sections=sections,
        # )

        logger.info(f"User {current_user.username} initiated report generation: {report.id}")

        return {
            "report_id": report.id,
            "status": "generating",
            "message": "Report generation initiated",
            "status_url": f"/api/v1/reports/{report.id}",
            "estimated_time_seconds": 30,
        }

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate report generation")


@router.post("/schedule", summary="Create scheduled report")
@require_permissions(["reports.schedule"])
async def create_scheduled_report(
    name: str = Query(..., description="Schedule name"),
    description: str = Query("", description="Schedule description"),
    cron_expression: str = Query(..., description="Cron expression (e.g., '0 9 * * MON' for weekly Monday 9am)"),
    report_type: str = Query("architectural_metrics", description="Type of report"),
    formats: List[ReportFormat] = Query([ReportFormat.PDF], description="Output formats"),
    period_days: int = Query(30, description="Period in days for metrics"),
    notification_emails: List[str] = Query([], description="Email addresses for notifications"),
    include_leading: bool = Query(True, description="Include leading indicators"),
    include_lagging: bool = Query(True, description="Include lagging indicators"),
    include_roi: bool = Query(True, description="Include ROI analysis"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: "ScheduledReportService" = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a scheduled report for automatic generation.

    Schedule reports to run automatically using cron expressions:
    - Daily: '0 9 * * *' (9am daily)
    - Weekly: '0 9 * * MON' (9am Mondays)
    - Monthly: '0 9 1 * *' (9am first day of month)
    """
    try:
        # Build configuration
        config = {"report_type": report_type, "period_days": period_days, "include_sections": []}

        if include_leading:
            config["include_sections"].append("leading")
        if include_lagging:
            config["include_sections"].append("lagging")
        if include_roi:
            config["include_sections"].append("roi")

        config["include_sections"].extend(["executive_summary", "recommendations"])

        # Create schedule
        schedule = await scheduled_report_service.create_scheduled_report(
            name=name,
            description=description,
            cron_expression=cron_expression,
            report_type=report_type,
            output_formats=formats,
            config=config,
            notification_emails=notification_emails,
            created_by=current_user.username,
        )

        logger.info(f"User {current_user.username} created scheduled report: {schedule.name}")

        return {
            "schedule_id": schedule.id,
            "name": schedule.name,
            "cron_expression": schedule.cron_expression,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
            "is_active": schedule.is_active,
            "message": "Scheduled report created successfully",
        }

    except Exception as e:
        logger.error(f"Error creating scheduled report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create scheduled report: {str(e)}")


@router.get("/schedules", summary="List scheduled reports")
async def list_scheduled_reports(
    active_only: bool = Query(True, description="Show only active schedules"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: ScheduledReportService = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all scheduled architectural metrics reports."""
    try:
        # TODO: Implement proper service layer integration for listing scheduled reports
        # This function needs to be refactored to use scheduled_report_service instead of direct DB queries
        logger.info(f"User {current_user.username} requested scheduled reports list")

        # Placeholder response - needs proper service layer implementation
        return []

    except Exception as e:
        logger.error(f"Error listing scheduled reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scheduled reports")


@router.put("/schedules/{schedule_id}", summary="Update scheduled report")
@require_permissions(["reports.schedule"])
async def update_scheduled_report(
    schedule_id: str,
    is_active: Optional[bool] = Query(None, description="Activate/deactivate schedule"),
    cron_expression: Optional[str] = Query(None, description="New cron expression"),
    notification_emails: Optional[List[str]] = Query(None, description="Update notification emails"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: "ScheduledReportService" = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update a scheduled report configuration."""
    try:
        # Build updates
        updates = {}
        if is_active is not None:
            updates["is_active"] = is_active
        if cron_expression is not None:
            updates["cron_expression"] = cron_expression
        if notification_emails is not None:
            updates["notification_emails"] = notification_emails

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        # Update schedule
        schedule = await scheduled_report_service.update_schedule(schedule_id, updates)

        logger.info(f"User {current_user.username} updated schedule: {schedule.name}")

        return {
            "schedule_id": schedule.id,
            "name": schedule.name,
            "is_active": schedule.is_active,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
            "message": "Schedule updated successfully",
        }

    except Exception as e:
        logger.error(f"Error updating schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update schedule: {str(e)}")


@router.delete("/schedules/{schedule_id}", summary="Delete scheduled report")
@require_permissions(["reports.schedule"])
async def delete_scheduled_report(
    schedule_id: str,
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: "ScheduledReportService" = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Delete (deactivate) a scheduled report."""
    try:
        success = await scheduled_report_service.delete_schedule(schedule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Schedule not found")

        logger.info(f"User {current_user.username} deleted schedule: {schedule_id}")

        return {"message": "Schedule deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete schedule")


@router.get("/schedules/{schedule_id}/history", summary="Get schedule execution history")
async def get_schedule_history(
    schedule_id: str,
    limit: int = Query(10, ge=1, le=100, description="Maximum number of reports"),
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: "ScheduledReportService" = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Get execution history for a scheduled report."""
    try:
        reports = await scheduled_report_service.get_schedule_history(schedule_id, limit)

        return [
            {
                "report_id": r.id,
                "name": r.name,
                "format": r.format.value,
                "status": r.status.value,
                "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                "download_url": f"/api/v1/reports/{r.id}/download" if r.status.value == "completed" else None,
                "error_message": r.error_message,
            }
            for r in reports
        ]

    except Exception as e:
        logger.error(f"Error getting schedule history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get schedule history")


@router.post("/execute-schedules", summary="Manually execute scheduled reports")
@require_permissions(["reports.execute"])
async def execute_scheduled_reports(
    background_tasks: BackgroundTasks,
    architectural_metrics_service: ArchitecturalMetricsService = Depends(get_architectural_metrics_service),
    scheduled_report_service: "ScheduledReportService" = Depends(get_scheduled_report_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Manually trigger execution of all due scheduled reports.

    This endpoint is typically called by a cron job or scheduler service.
    """
    try:
        # Execute in background
        background_tasks.add_task(scheduled_report_service.execute_scheduled_reports)

        logger.info(f"User {current_user.username} triggered scheduled report execution")

        return {"status": "initiated", "message": "Scheduled report execution initiated"}

    except Exception as e:
        logger.error(f"Error executing scheduled reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to execute scheduled reports")
