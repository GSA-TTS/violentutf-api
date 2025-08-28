"""Report generation and management API endpoints."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response

# TECHNICAL DEBT: Direct SQLAlchemy usage violates Clean Architecture
# TODO: Move SQL queries to service layer
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_report_service
from app.core.auth import get_current_user
from app.models.report import Report, ReportFormat, ReportStatus, ReportTemplate, TemplateType
from app.models.task import Task, TaskStatus
from app.models.user import User
from app.schemas.report import (
    ReportCreate,
    ReportGenerationRequest,
    ReportGenerationResponse,
    ReportListResponse,
    ReportResponse,
    ReportStatsResponse,
    ReportUpdate,
)
from app.services.report_service import ReportService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=ReportListResponse, summary="List reports")
async def list_reports(
    skip: int = Query(0, ge=0, description="Number of reports to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of reports to return"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    format: Optional[ReportFormat] = Query(None, description="Filter by format"),
    status: Optional[ReportStatus] = Query(None, description="Filter by status"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportListResponse:
    """List reports with filtering and pagination."""
    try:
        # Build query with filters
        query = select(Report).where(Report.is_deleted.is_(False))

        if report_type:
            query = query.where(Report.report_type == report_type)
        if format:
            query = query.where(Report.format == format)
        if status:
            query = query.where(Report.status == status)
        if created_by:
            query = query.where(Report.created_by == created_by)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = query.order_by(desc(Report.created_at)).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        reports = result.scalars().all()

        # Convert to response schemas
        report_responses = [ReportResponse.model_validate(report) for report in reports]

        return ReportListResponse(
            reports=report_responses,
            total=total,
            page=(skip // limit) + 1,
            per_page=limit,
            has_next=(skip + limit) < total,
        )

    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to list reports")


@router.post("/", response_model=ReportGenerationResponse, summary="Create report", status_code=202)
async def create_report(
    report_data: ReportCreate,
    generate_immediately: bool = Query(True, description="Generate report immediately"),
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportGenerationResponse:
    """Create a new report and optionally generate it immediately."""
    try:
        # Create report instance
        report = Report(
            name=report_data.name,
            title=report_data.title,
            description=report_data.description,
            report_type=report_data.report_type,
            format=report_data.format,
            template_id=report_data.template_id,
            scan_id=report_data.scan_id,
            execution_id=report_data.execution_id,
            config=report_data.config or {},
            filters=report_data.filters or {},
            parameters=report_data.parameters or {},
            is_public=report_data.is_public or False,
            expires_at=report_data.expires_at,
            status=ReportStatus.PENDING if generate_immediately else ReportStatus.PENDING,
            created_by=current_user.username,
        )

        # Save report to database
        db.add(report)
        # Service layer handles commit
        await db.refresh(report)

        # Create associated task for async generation
        task_id = None
        if generate_immediately:
            task = Task(
                name=f"Report: {report.name}",
                task_type="report_generation",
                description=f"Generate {report.format.value} report: {report.name}",
                input_data={
                    "report_id": report.id,
                    "report_type": report.report_type,
                    "format": report.format.value,
                    "config": report.config,
                    "filters": report.filters,
                    "parameters": report.parameters,
                },
                config={},
                created_by=current_user.username,
            )

            db.add(task)
            # Service layer handles commit
            await db.refresh(task)

            # Link report to task
            report.task_id = task.id
            report.status = ReportStatus.GENERATING

            # Dispatch to Celery worker for generation
            from app.celery.tasks import generate_report_task

            celery_task = generate_report_task.delay(report.id)
            task.celery_task_id = celery_task.id
            task.status = TaskStatus.PENDING

            task_id = task.id
            # Service layer handles commit
            await db.refresh(report)

        logger.info(f"User {current_user.username} created report: {report.name}")

        # Return 202 Accepted with status URL (ADR-007 pattern)
        return ReportGenerationResponse(
            report_id=report.id,
            task_id=task_id,
            status=report.status,
            started_at=report.created_at,
            status_url=f"/api/v1/reports/{report.id}",
            download_url=f"/api/v1/reports/{report.id}/download" if report.status == ReportStatus.COMPLETED else None,
        )

    except Exception as e:
        logger.error(f"Error creating report: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to create report")


@router.get("/{report_id}", response_model=ReportResponse, summary="Get report")
async def get_report(
    report_id: str,
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Get a specific report by ID (ADR-007 status polling)."""
    try:
        # Query report
        query = select(Report).where(and_(Report.id == report_id, Report.is_deleted.is_(False)))
        result = await db.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        return ReportResponse.model_validate(report)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting report {report_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get report")


@router.put("/{report_id}", response_model=ReportResponse, summary="Update report")
async def update_report(
    report_id: str,
    report_data: ReportUpdate,
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Update a report."""
    try:
        # Get report
        query = select(Report).where(and_(Report.id == report_id, Report.is_deleted.is_(False)))
        result = await db.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if report can be updated
        if report.status in [ReportStatus.GENERATING]:
            raise HTTPException(status_code=400, detail="Cannot update report that is currently generating")

        # Update fields
        update_data = report_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(report, field, value)

        report.updated_by = current_user.username

        # Service layer handles commit
        await db.refresh(report)

        logger.info(f"User {current_user.username} updated report: {report.name}")

        return ReportResponse.model_validate(report)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating report {report_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to update report")


@router.delete("/{report_id}", summary="Delete report")
async def delete_report(
    report_id: str,
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Delete a report (soft delete)."""
    try:
        # Get report
        query = select(Report).where(and_(Report.id == report_id, Report.is_deleted.is_(False)))
        result = await db.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if report can be deleted
        if report.status == ReportStatus.GENERATING:
            raise HTTPException(status_code=400, detail="Cannot delete report that is currently generating")

        # Soft delete
        report.soft_delete(deleted_by=current_user.username)

        # Service layer handles commit

        logger.info(f"User {current_user.username} deleted report: {report.name}")

        return {"message": "Report deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting report {report_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to delete report")


@router.post("/{report_id}/generate", response_model=ReportGenerationResponse, summary="Generate report")
async def generate_report(
    report_id: str,
    generation_request: Optional[ReportGenerationRequest] = None,
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportGenerationResponse:
    """Generate a report asynchronously."""
    try:
        # Get report
        query = select(Report).where(and_(Report.id == report_id, Report.is_deleted.is_(False)))
        result = await db.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if report can be generated
        if report.status in [ReportStatus.GENERATING]:
            raise HTTPException(status_code=400, detail="Report is already generating")

        # Create or update associated task
        if not report.task_id:
            task = Task(
                name=f"Report: {report.name}",
                task_type="report_generation",
                description=f"Generate {report.format.value} report: {report.name}",
                input_data={
                    "report_id": report.id,
                    "report_type": report.report_type,
                    "format": report.format.value,
                    "config": report.config,
                },
                config=generation_request.config_override if generation_request else {},
                created_by=current_user.username,
            )

            db.add(task)
            # Service layer handles commit
            await db.refresh(task)

            report.task_id = task.id
        else:
            # Get existing task
            task_query = select(Task).where(Task.id == report.task_id)
            task_result = await db.execute(task_query)
            task = task_result.scalar_one_or_none()

            if not task:
                raise HTTPException(status_code=500, detail="Associated task not found")

        # Update report status
        report.status = ReportStatus.GENERATING
        report.updated_by = current_user.username

        task.status = TaskStatus.PENDING
        task.started_at = datetime.utcnow()
        task.updated_by = current_user.username

        # Dispatch to Celery worker
        from app.celery.tasks import generate_report_task

        config_override = generation_request.config_override if generation_request else {}
        celery_task = generate_report_task.delay(report.id, config_override)
        task.celery_task_id = celery_task.id

        # Service layer handles commit
        await db.refresh(report)

        logger.info(f"User {current_user.username} generated report: {report.name}")

        return ReportGenerationResponse(
            report_id=report.id,
            task_id=task.id,
            status=report.status,
            started_at=datetime.utcnow(),
            status_url=f"/api/v1/reports/{report.id}",
            download_url=None,  # Available after completion
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating report {report_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/{report_id}/download", summary="Download report")
async def download_report(
    report_id: str,
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download a generated report file."""
    try:
        # Get report
        query = select(Report).where(and_(Report.id == report_id, Report.is_deleted.is_(False)))
        result = await db.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Check if report is ready for download
        if report.status != ReportStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Report is not ready for download")

        if not report.content and not report.file_path:
            raise HTTPException(status_code=404, detail="Report content not found")

        # Update download count
        report.download_count += 1
        # Service layer handles commit

        # Return content based on format
        if report.content:
            # For JSON/data formats, return content directly
            if report.format == ReportFormat.JSON:
                return Response(
                    content=str(report.content),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{report.name}.json"'},
                )
            elif report.format == ReportFormat.CSV:
                # Convert content to CSV (simplified)
                csv_content = "data\n" + str(report.content)
                return Response(
                    content=csv_content,
                    media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{report.name}.csv"'},
                )

        # For file-based formats, serve the file
        if report.file_path:
            import os

            # Check if file exists
            if not os.path.exists(report.file_path):
                raise HTTPException(status_code=404, detail="Report file not found on disk")

            # Read and serve the actual file
            try:
                with open(report.file_path, "rb") as f:
                    file_content = f.read()

                return Response(
                    content=file_content,
                    media_type=report.mime_type or "application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{report.name}.{report.format.value}"'},
                )
            except Exception as file_error:
                logger.error(f"Error reading report file {report.file_path}: {file_error}")
                raise HTTPException(status_code=500, detail="Failed to read report file")

        raise HTTPException(status_code=404, detail="Report content not available")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading report {report_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to download report")


@router.get("/stats", response_model=ReportStatsResponse, summary="Get report statistics")
async def get_report_stats(
    report_service: ReportService = Depends(get_report_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportStatsResponse:
    """Get report generation statistics."""
    try:
        # Get counts by status
        status_counts = {}
        for status in ReportStatus:
            count_query = select(func.count()).where(and_(Report.status == status, Report.is_deleted.is_(False)))
            result = await db.execute(count_query)
            status_counts[status.value] = result.scalar() or 0

        # Get counts by format
        format_counts = {}
        for format_type in ReportFormat:
            count_query = select(func.count()).where(and_(Report.format == format_type, Report.is_deleted.is_(False)))
            result = await db.execute(count_query)
            format_counts[format_type.value] = result.scalar() or 0

        # Calculate success rate
        total_completed = status_counts.get("completed", 0) + status_counts.get("failed", 0)
        success_rate = None
        if total_completed > 0:
            success_rate = status_counts.get("completed", 0) / total_completed

        # Get total download count
        download_query = select(func.sum(Report.download_count)).where(Report.is_deleted.is_(False))
        download_result = await db.execute(download_query)
        total_downloads = download_result.scalar() or 0

        return ReportStatsResponse(
            total_reports=sum(status_counts.values()),
            pending_reports=status_counts.get("pending", 0),
            generating_reports=status_counts.get("generating", 0),
            completed_reports=status_counts.get("completed", 0),
            failed_reports=status_counts.get("failed", 0),
            success_rate=success_rate,
            total_downloads=total_downloads,
            format_distribution=format_counts,
        )

    except Exception as e:
        logger.error(f"Error getting report stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get report statistics")
