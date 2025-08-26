"""Scan management API endpoints."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_scan_service
from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.scan import Scan, ScanFinding, ScanReport, ScanStatus, ScanType
from app.models.task import Task, TaskStatus
from app.models.user import User
from app.schemas.scan import (
    ScanCreate,
    ScanExecutionRequest,
    ScanExecutionResponse,
    ScanFindingListResponse,
    ScanFindingResponse,
    ScanListResponse,
    ScanReportResponse,
    ScanResponse,
    ScanStatsResponse,
    ScanUpdate,
)
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=ScanListResponse, summary="List scans")
async def list_scans(
    skip: int = Query(0, ge=0, description="Number of scans to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of scans to return"),
    scan_type: Optional[ScanType] = Query(None, description="Filter by scan type"),
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    """List scans with filtering and pagination."""
    try:
        # Build query with filters
        query = select(Scan).where(Scan.is_deleted is False)

        if scan_type:
            query = query.where(Scan.scan_type == scan_type)
        if status:
            query = query.where(Scan.status == status)
        if created_by:
            query = query.where(Scan.created_by == created_by)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = query.order_by(desc(Scan.created_at)).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        scans = result.scalars().all()

        # Convert to response schemas
        scan_responses = [ScanResponse.model_validate(scan) for scan in scans]

        return ScanListResponse(
            scans=scan_responses,
            total=total,
            page=(skip // limit) + 1,
            per_page=limit,
            has_next=(skip + limit) < total,
        )

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.post("/", response_model=ScanExecutionResponse, summary="Create and execute scan", status_code=202)
async def create_scan(
    scan_data: ScanCreate,
    execute_immediately: bool = Query(True, description="Execute scan immediately"),
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanExecutionResponse:
    """Create a new scan and optionally execute it immediately (ADR-007 compliant)."""
    try:
        # Create scan instance
        scan = Scan(
            name=scan_data.name,
            scan_type=scan_data.scan_type,
            description=scan_data.description,
            target_config=scan_data.target_config,
            scan_config=scan_data.scan_config,
            parameters=scan_data.parameters,
            tags=scan_data.tags,
            status=ScanStatus.PENDING if execute_immediately else ScanStatus.PENDING,
            created_by=current_user.username,
        )

        # Save scan to database
        db.add(scan)
        # Service layer handles commit
        await db.refresh(scan)

        # Create associated task for async execution
        if execute_immediately:
            task = Task(
                name=f"Scan: {scan.name}",
                task_type=f"scan_{scan.scan_type.value}",
                description=f"Execute {scan.scan_type.value} scan: {scan.name}",
                input_data={
                    "scan_id": scan.id,
                    "scan_config": scan.scan_config,
                    "target_config": scan.target_config,
                    "parameters": scan.parameters,
                },
                config={
                    "webhook_url": scan_data.webhook_url,
                    "webhook_secret": scan_data.webhook_secret,
                },
                webhook_url=scan_data.webhook_url,
                webhook_secret=scan_data.webhook_secret,
                created_by=current_user.username,
            )

            db.add(task)
            # Service layer handles commit
            await db.refresh(task)

            # Link scan to task
            scan.task_id = task.id
            scan.status = ScanStatus.INITIALIZING
            scan.started_at = datetime.utcnow()

            # Dispatch to Celery worker for execution
            from app.celery.tasks import execute_scan_task

            celery_task = execute_scan_task.delay(scan.id, task.id)
            task.celery_task_id = celery_task.id
            task.status = TaskStatus.PENDING

            # Service layer handles commit
            await db.refresh(scan)

        logger.info(f"User {current_user.username} created scan: {scan.name}")

        # Return 202 Accepted with status URL (ADR-007 pattern)
        return ScanExecutionResponse(
            scan_id=scan.id,
            execution_id=scan.task_id or scan.id,
            task_id=scan.task_id,
            status=scan.status,
            started_at=scan.started_at or scan.created_at,
            status_url=f"/api/v1/scans/{scan.id}",
            webhook_configured=scan_data.webhook_url is not None,
        )

    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to create scan")


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan")
async def get_scan(
    scan_id: str,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Get a specific scan by ID (ADR-007 status polling)."""
    try:
        # Query scan
        query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        result = await db.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResponse.model_validate(scan)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan")


@router.put("/{scan_id}", response_model=ScanResponse, summary="Update scan")
async def update_scan(
    scan_id: str,
    scan_data: ScanUpdate,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Update a scan."""
    try:
        # Get scan
        query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        result = await db.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Check if scan can be updated
        if scan.status in [ScanStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Cannot update scan that is currently running")

        # Update fields
        update_data = scan_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scan, field, value)

        scan.updated_by = current_user.username

        # Service layer handles commit
        await db.refresh(scan)

        logger.info(f"User {current_user.username} updated scan: {scan.name}")

        return ScanResponse.model_validate(scan)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scan {scan_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to update scan")


@router.delete("/{scan_id}", summary="Delete scan")
async def delete_scan(
    scan_id: str,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Delete a scan (soft delete)."""
    try:
        # Get scan
        query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        result = await db.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Check if scan can be deleted
        if scan.status == ScanStatus.RUNNING:
            raise HTTPException(status_code=400, detail="Cannot delete running scan. Cancel it first.")

        # Soft delete
        scan.soft_delete(deleted_by=current_user.username)

        # Service layer handles commit

        logger.info(f"User {current_user.username} deleted scan: {scan.name}")

        return {"message": "Scan deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to delete scan")


@router.post("/{scan_id}/execute", response_model=ScanExecutionResponse, summary="Execute scan")
async def execute_scan(
    scan_id: str,
    execution_request: Optional[ScanExecutionRequest] = None,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanExecutionResponse:
    """Execute a scan asynchronously."""
    try:
        # Get scan
        query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        result = await db.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Check if scan can be executed
        if scan.status in [ScanStatus.RUNNING, ScanStatus.INITIALIZING]:
            raise HTTPException(status_code=400, detail="Scan is already running or initializing")

        # Create or update associated task
        if not scan.task_id:
            task = Task(
                name=f"Scan: {scan.name}",
                task_type=f"scan_{scan.scan_type.value}",
                description=f"Execute {scan.scan_type.value} scan: {scan.name}",
                input_data={
                    "scan_id": scan.id,
                    "scan_config": scan.scan_config,
                    "target_config": scan.target_config,
                    "parameters": scan.parameters,
                },
                config=execution_request.config_override if execution_request else {},
                created_by=current_user.username,
            )

            db.add(task)
            # Service layer handles commit
            await db.refresh(task)

            scan.task_id = task.id
        else:
            # Get existing task
            task_query = select(Task).where(Task.id == scan.task_id)
            task_result = await db.execute(task_query)
            task = task_result.scalar_one_or_none()

            if not task:
                raise HTTPException(status_code=500, detail="Associated task not found")

        # Update scan and task status
        scan.status = ScanStatus.INITIALIZING
        scan.started_at = datetime.utcnow()
        scan.progress = 0
        scan.current_phase = "Initializing"
        scan.updated_by = current_user.username

        task.status = TaskStatus.PENDING
        task.started_at = datetime.utcnow()
        task.updated_by = current_user.username

        # Dispatch to Celery worker
        from app.celery.tasks import execute_scan_task

        config_override = execution_request.config_override if execution_request else {}
        celery_task = execute_scan_task.delay(scan.id, task.id, config_override)
        task.celery_task_id = celery_task.id

        # Service layer handles commit
        await db.refresh(scan)

        logger.info(f"User {current_user.username} executed scan: {scan.name}")

        return ScanExecutionResponse(
            scan_id=scan.id,
            execution_id=task.id,
            task_id=task.id,
            status=scan.status,
            started_at=scan.started_at,
            status_url=f"/api/v1/scans/{scan.id}",
            webhook_configured=task.webhook_url is not None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing scan {scan_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to execute scan")


@router.post("/{scan_id}/cancel", summary="Cancel scan")
async def cancel_scan(
    scan_id: str,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Cancel a running scan."""
    try:
        # Get scan
        query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        result = await db.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Check if scan can be cancelled
        if scan.status not in [ScanStatus.PENDING, ScanStatus.INITIALIZING, ScanStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Can only cancel pending, initializing, or running scans")

        # Cancel scan
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        scan.current_phase = "Cancelled"
        scan.updated_by = current_user.username

        # Cancel associated task
        if scan.task_id:
            task_query = select(Task).where(Task.id == scan.task_id)
            task_result = await db.execute(task_query)
            task = task_result.scalar_one_or_none()

            if task:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.utcnow()
                task.progress_message = "Scan cancelled by user"
                task.updated_by = current_user.username

                # Cancel Celery task
                if task.celery_task_id:
                    from app.celery.celery import celery_app

                    celery_app.control.revoke(task.celery_task_id, terminate=True)

        # Service layer handles commit

        logger.info(f"User {current_user.username} cancelled scan: {scan.name}")

        return {"message": "Scan cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling scan {scan_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to cancel scan")


@router.get("/{scan_id}/findings", response_model=ScanFindingListResponse, summary="Get scan findings")
async def get_scan_findings(
    scan_id: str,
    skip: int = Query(0, ge=0, description="Number of findings to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of findings to return"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
    verified: Optional[bool] = Query(None, description="Filter by verification status"),
    false_positive: Optional[bool] = Query(None, description="Filter by false positive status"),
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanFindingListResponse:
    """Get findings for a specific scan."""
    try:
        # Verify scan exists
        scan_query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        scan_result = await db.execute(scan_query)
        scan = scan_result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Query findings
        query = select(ScanFinding).where(ScanFinding.scan_id == scan_id)

        if severity:
            query = query.where(ScanFinding.severity == severity)
        if category:
            query = query.where(ScanFinding.category == category)
        if verified is not None:
            query = query.where(ScanFinding.verified == verified)
        if false_positive is not None:
            query = query.where(ScanFinding.false_positive == false_positive)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = query.order_by(desc(ScanFinding.created_at)).offset(skip).limit(limit)

        result = await db.execute(query)
        findings = result.scalars().all()

        # Convert to response schemas
        finding_responses = [ScanFindingResponse.model_validate(f) for f in findings]

        return ScanFindingListResponse(
            findings=finding_responses,
            total=total,
            page=(skip // limit) + 1,
            per_page=limit,
            has_next=(skip + limit) < total,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan findings {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan findings")


@router.get("/{scan_id}/reports", response_model=List[ScanReportResponse], summary="Get scan reports")
async def get_scan_reports(
    scan_id: str,
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[ScanReportResponse]:
    """Get reports for a specific scan."""
    try:
        # Verify scan exists
        scan_query = select(Scan).where(and_(Scan.id == scan_id, Scan.is_deleted is False))
        scan_result = await db.execute(scan_query)
        scan = scan_result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Query reports
        query = select(ScanReport).where(ScanReport.scan_id == scan_id)
        query = query.order_by(desc(ScanReport.generated_at))

        result = await db.execute(query)
        reports = result.scalars().all()

        # Convert to response schemas
        return [ScanReportResponse.model_validate(r) for r in reports]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan reports {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan reports")


@router.get("/stats", response_model=ScanStatsResponse, summary="Get scan statistics")
async def get_scan_stats(
    scan_service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanStatsResponse:
    """Get scan execution statistics."""
    try:
        # Get counts by status
        status_counts = {}
        for status in ScanStatus:
            count_query = select(func.count()).where(and_(Scan.status == status, Scan.is_deleted is False))
            result = await db.execute(count_query)
            status_counts[status.value] = result.scalar() or 0

        # Get finding counts
        finding_counts = await db.execute(
            select(
                func.sum(Scan.critical_findings),
                func.sum(Scan.high_findings),
                func.sum(Scan.medium_findings),
                func.sum(Scan.low_findings),
                func.sum(Scan.findings_count),
            ).where(Scan.is_deleted is False)
        )
        finding_result = finding_counts.first()
        if finding_result:
            critical, high, medium, low, total_findings = finding_result
        else:
            critical = high = medium = low = total_findings = 0

        # Calculate success rate
        total_completed = status_counts.get("completed", 0) + status_counts.get("failed", 0)
        success_rate = None
        if total_completed > 0:
            success_rate = status_counts.get("completed", 0) / total_completed

        # TODO: Calculate average scan time
        avg_scan_time = None

        return ScanStatsResponse(
            total_scans=sum(status_counts.values()),
            pending_scans=status_counts.get("pending", 0),
            running_scans=status_counts.get("running", 0),
            completed_scans=status_counts.get("completed", 0),
            failed_scans=status_counts.get("failed", 0),
            total_findings=total_findings or 0,
            critical_findings=critical or 0,
            high_findings=high or 0,
            medium_findings=medium or 0,
            low_findings=low or 0,
            avg_scan_time=avg_scan_time,
            success_rate=success_rate,
        )

    except Exception as e:
        logger.error(f"Error getting scan stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan statistics")
