"""Security scan CRUD endpoints with comprehensive validation and security."""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_security_scan_service
from app.core.enums import ScanStatus, ScanType
from app.core.errors import NotFoundError, ValidationError

# TECHNICAL DEBT: Direct repository usage violates Clean Architecture
# TODO: Replace with complete service layer methods
from app.repositories.security_scan import SecurityScanRepository
from app.schemas.base import BaseResponse
from app.schemas.security_scan import (
    ScanCleanupRequest,
    ScanCleanupResponse,
    ScanComparisonRequest,
    ScanComparisonResponse,
    ScanProgressUpdate,
    SecurityScanCreate,
    SecurityScanFilter,
    SecurityScanListResponse,
    SecurityScanResponse,
    SecurityScanStatistics,
    SecurityScanUpdate,
)
from app.services.security_scan_service import SecurityScanService

router = APIRouter(prefix="/security-scans", tags=["Security Scans"])


@router.post(
    "/",
    response_model=BaseResponse[SecurityScanResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_scan(
    request: Request,
    scan_data: SecurityScanCreate,
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanResponse]:
    """Create a new security scan."""

    repo = SecurityScanRepository(db)

    # Convert to dict and add audit fields
    data = scan_data.model_dump()
    data["created_by"] = getattr(request.state, "user_id", "system")
    data["updated_by"] = data["created_by"]

    scan = await repo.create(data)
    # Service layer handles transactions automatically

    response_scan = SecurityScanResponse.model_validate(scan)
    return BaseResponse(
        data=response_scan,
        message="Security scan created successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/{scan_id}", response_model=BaseResponse[SecurityScanResponse])
async def get_scan(
    scan_id: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanResponse]:
    """Get a security scan by ID."""

    repo = SecurityScanRepository(db)
    scan = await repo.get_by_id(scan_id, organization_id)

    if not scan:
        raise NotFoundError(message="Security scan not found")

    # Add computed fields
    scan_dict = scan.__dict__.copy()
    if scan.duration_seconds and scan.total_findings > 0:
        scan_dict["findings_per_minute"] = scan.total_findings / (scan.duration_seconds / 60)

    # Calculate success rate based on completion and error status
    if scan.status == ScanStatus.COMPLETED and not scan.error_message:
        scan_dict["success_rate"] = 100.0
    elif scan.status == ScanStatus.FAILED:
        scan_dict["success_rate"] = 0.0
    elif scan.status == ScanStatus.COMPLETED and scan.error_message:
        scan_dict["success_rate"] = 75.0  # Completed with warnings

    response_scan = SecurityScanResponse.model_validate(scan_dict)
    return BaseResponse(
        data=response_scan,
        message="Security scan retrieved successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/", response_model=BaseResponse[SecurityScanListResponse])
async def list_scans(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    scan_type: Optional[ScanType] = Query(None, description="Filter by scan type"),
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    initiated_by: Optional[str] = Query(None, description="Filter by initiator"),
    target: Optional[str] = Query(None, description="Filter by target"),
    pipeline_id: Optional[str] = Query(None, description="Filter by pipeline ID"),
    is_baseline: Optional[bool] = Query(None, description="Filter by baseline status"),
    has_findings: Optional[bool] = Query(None, description="Filter by presence of findings"),
    search: Optional[str] = Query(None, min_length=1, max_length=100, description="Search term"),
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanListResponse]:
    """List security scans with filtering and pagination."""

    repo = SecurityScanRepository(db)

    # Build filters
    filters = {}
    if scan_type:
        filters["scan_type"] = scan_type
    if status:
        filters["status"] = status
    if initiated_by:
        filters["initiated_by"] = initiated_by
    if target:
        filters["target"] = target
    if pipeline_id:
        filters["pipeline_id"] = pipeline_id
    if is_baseline is not None:
        filters["is_baseline"] = is_baseline

    # Handle search separately
    if search:
        scans = await repo.search_scans(search, organization_id, limit=size * 5)
        # Apply other filters manually since search is separate
        if filters:
            filtered_scans = []
            for scan in scans:
                match = True
                for field, value in filters.items():
                    if hasattr(scan, field) and getattr(scan, field) != value:
                        match = False
                        break
                if match:
                    filtered_scans.append(scan)
            scans = filtered_scans

        # Handle has_findings filtering for search results
        if has_findings is not None:
            if has_findings:
                scans = [s for s in scans if s.total_findings > 0]
            else:
                scans = [s for s in scans if s.total_findings == 0]

        # Manual pagination for search results
        total = len(scans)
        start = (page - 1) * size
        end = start + size
        page_scans = scans[start:end]
        has_next = end < total
        has_prev = page > 1
    else:
        # Use repository pagination
        page_result = await repo.list_with_pagination(
            page=page,
            size=size,
            filters=filters,
            organization_id=organization_id,
            order_by="created_at",
            order_desc=True,
        )
        page_scans = page_result.items
        total = page_result.total
        has_next = page_result.has_next
        has_prev = page_result.has_prev

        # Handle has_findings filtering for paginated results
        if has_findings is not None:
            if has_findings:
                page_scans = [s for s in page_scans if s.total_findings > 0]
            else:
                page_scans = [s for s in page_scans if s.total_findings == 0]

    # Convert to response objects with computed fields
    response_scans = []
    for scan in page_scans:
        scan_dict = scan.__dict__.copy()

        # Add computed fields
        if scan.duration_seconds and scan.total_findings > 0:
            scan_dict["findings_per_minute"] = scan.total_findings / (scan.duration_seconds / 60)

        # Calculate success rate
        if scan.status == ScanStatus.COMPLETED and not scan.error_message:
            scan_dict["success_rate"] = 100.0
        elif scan.status == ScanStatus.FAILED:
            scan_dict["success_rate"] = 0.0
        elif scan.status == ScanStatus.COMPLETED and scan.error_message:
            scan_dict["success_rate"] = 75.0

        response_scans.append(SecurityScanResponse.model_validate(scan_dict))

    list_response = SecurityScanListResponse(
        scans=response_scans,
        total=total,
        page=page,
        size=size,
        has_next=has_next,
        has_prev=has_prev,
    )

    return BaseResponse(
        data=list_response,
        message=f"Retrieved {len(response_scans)} security scans",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.put("/{scan_id}", response_model=BaseResponse[SecurityScanResponse])
async def update_scan(
    scan_id: str,
    scan_update: SecurityScanUpdate,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanResponse]:
    """Update a security scan."""

    repo = SecurityScanRepository(db)

    # Check if scan exists
    existing_scan = await repo.get_by_id(scan_id, organization_id)
    if not existing_scan:
        raise NotFoundError(message="Security scan not found")

    # Update with audit fields
    update_data = scan_update.model_dump(exclude_unset=True)
    if update_data:
        update_data["updated_by"] = getattr(request.state, "user_id", "system")

        scan = await repo.update(scan_id, organization_id, **update_data)
        # Service layer handles transactions automatically

        if not scan:
            raise NotFoundError(message="Security scan not found")
    else:
        scan = existing_scan

    response_scan = SecurityScanResponse.model_validate(scan)
    return BaseResponse(
        data=response_scan,
        message="Security scan updated successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.delete("/{scan_id}", response_model=BaseResponse[dict])
async def delete_scan(
    scan_id: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    hard_delete: bool = Query(False, description="Whether to permanently delete (vs soft delete)"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[dict]:
    """Delete a security scan (soft delete by default)."""

    repo = SecurityScanRepository(db)

    success = await repo.delete(scan_id, organization_id, hard_delete=hard_delete)
    if not success:
        raise NotFoundError(message="Security scan not found")

    # Service layer handles transactions automatically

    return BaseResponse(
        data={"deleted": True, "scan_id": scan_id, "hard_delete": hard_delete},
        message=f"Security scan {'permanently deleted' if hard_delete else 'soft deleted'} successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/statistics/summary", response_model=BaseResponse[SecurityScanStatistics])
async def get_scan_statistics(
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    time_period_days: Optional[int] = Query(None, ge=1, le=365, description="Time period in days"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanStatistics]:
    """Get comprehensive statistics about security scans."""

    repo = SecurityScanRepository(db)
    stats = await repo.get_scan_statistics(organization_id, time_period_days)

    statistics = SecurityScanStatistics(**stats)
    return BaseResponse(
        data=statistics,
        message="Scan statistics retrieved successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/status/{status}", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_scans_by_status(
    status: ScanStatus,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of scans to return"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get scans by status."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_by_status(status, organization_id, limit)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} {status} scans",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/type/{scan_type}", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_scans_by_type(
    scan_type: ScanType,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    include_completed: bool = Query(True, description="Include completed scans"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of scans to return"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get scans by type."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_by_scan_type(scan_type, organization_id, include_completed, limit)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} {scan_type} scans",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/running/all", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_running_scans(
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get all currently running scans."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_running_scans(organization_id)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} running scans",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/stalled/all", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_stalled_scans(
    request: Request,
    timeout_minutes: int = Query(60, ge=10, le=1440, description="Consider scans stalled after this many minutes"),
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get scans that appear to be stalled (running longer than expected)."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_stalled_scans(timeout_minutes, organization_id)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} stalled scans (running > {timeout_minutes} minutes)",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/target/{target:path}", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_scans_by_target(
    target: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of scans to return"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get scans for a specific target."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_scans_by_target(target, organization_id, limit)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} scans for target {target}",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/initiator/{initiator}", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_scans_by_initiator(
    initiator: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    days_back: Optional[int] = Query(None, ge=1, le=365, description="Limit to scans from last N days"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get scans initiated by a specific user."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_scans_by_initiator(initiator, organization_id, days_back)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    message = f"Retrieved {len(response_scans)} scans initiated by {initiator}"
    if days_back:
        message += f" in the last {days_back} days"

    return BaseResponse(
        data=response_scans,
        message=message,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/baselines/all", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_baseline_scans(
    request: Request,
    scan_type: Optional[ScanType] = Query(None, description="Filter by scan type"),
    target: Optional[str] = Query(None, description="Filter by target"),
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get baseline scans for comparison purposes."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_baseline_scans(scan_type, target, organization_id)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} baseline scans",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/pipeline/{pipeline_id}", response_model=BaseResponse[List[SecurityScanResponse]])
async def get_scans_by_pipeline(
    pipeline_id: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[List[SecurityScanResponse]]:
    """Get all scans belonging to a specific pipeline."""

    repo = SecurityScanRepository(db)
    scans = await repo.get_scans_by_pipeline(pipeline_id, organization_id)

    response_scans = [SecurityScanResponse.model_validate(scan) for scan in scans]

    return BaseResponse(
        data=response_scans,
        message=f"Retrieved {len(response_scans)} scans for pipeline {pipeline_id}",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.put("/{scan_id}/progress", response_model=BaseResponse[SecurityScanResponse])
async def update_scan_progress(
    scan_id: str,
    progress_update: ScanProgressUpdate,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[SecurityScanResponse]:
    """Update scan progress and status."""

    repo = SecurityScanRepository(db)

    # Convert findings counts to the format expected by the repository
    findings_counts = None
    if progress_update.findings_counts:
        findings_counts = {
            "total_findings": sum(progress_update.findings_counts.values()),
            "critical_findings": progress_update.findings_counts.get("critical", 0),
            "high_findings": progress_update.findings_counts.get("high", 0),
            "medium_findings": progress_update.findings_counts.get("medium", 0),
            "low_findings": progress_update.findings_counts.get("low", 0),
            "info_findings": progress_update.findings_counts.get("info", 0),
        }

    scan = await repo.update_scan_progress(
        scan_id,
        progress_update.status,
        findings_counts,
        progress_update.error_message,
        organization_id,
    )

    if not scan:
        raise NotFoundError(message="Security scan not found")

    # Service layer handles transactions automatically

    response_scan = SecurityScanResponse.model_validate(scan)
    return BaseResponse(
        data=response_scan,
        message="Scan progress updated successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.put("/{scan_id}/baseline", response_model=BaseResponse[dict])
async def mark_scan_as_baseline(
    scan_id: str,
    request: Request,
    organization_id: Optional[str] = Query(None, description="Organization ID for multi-tenant filtering"),
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[dict]:
    """Mark a completed scan as a baseline scan."""

    repo = SecurityScanRepository(db)

    success = await repo.mark_scan_as_baseline(scan_id, organization_id)
    if not success:
        raise NotFoundError(message="Security scan not found or not completed")

    # Service layer handles transactions automatically

    return BaseResponse(
        data={"marked_as_baseline": True, "scan_id": scan_id},
        message="Scan marked as baseline successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/{scan_id}/compare", response_model=BaseResponse[ScanComparisonResponse])
async def compare_scans(
    scan_id: str,
    comparison_request: ScanComparisonRequest,
    request: Request,
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[ScanComparisonResponse]:
    """Compare a scan with a baseline scan."""

    repo = SecurityScanRepository(db)

    comparison_data = await repo.get_scan_comparison(
        scan_id, comparison_request.baseline_scan_id, comparison_request.organization_id
    )

    if not comparison_data:
        raise NotFoundError(message="One or both scans not found")

    response_data = ScanComparisonResponse(**comparison_data)
    return BaseResponse(
        data=response_data,
        message="Scan comparison completed successfully",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/cleanup", response_model=BaseResponse[ScanCleanupResponse])
async def cleanup_old_scans(
    cleanup_request: ScanCleanupRequest,
    request: Request,
    security_scan_service: SecurityScanService = Depends(get_security_scan_service),
    db: AsyncSession = Depends(get_db),
) -> BaseResponse[ScanCleanupResponse]:
    """Clean up old scan records (soft delete)."""

    repo = SecurityScanRepository(db)

    cleanup_result = await repo.cleanup_old_scans(
        cleanup_request.days_to_keep,
        cleanup_request.organization_id,
        cleanup_request.dry_run,
    )

    response_data = ScanCleanupResponse(**cleanup_result)
    return BaseResponse(
        data=response_data,
        message=f"Cleanup {'simulation' if cleanup_request.dry_run else 'execution'} completed",
        trace_id=getattr(request.state, "trace_id", None),
    )
