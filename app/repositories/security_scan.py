"""Repository for security scan management."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ScanStatus, ScanType, Severity
from app.models.security_scan import SecurityScan
from app.models.vulnerability_finding import VulnerabilityFinding
from app.repositories.base import BaseRepository


class SecurityScanRepository(BaseRepository[SecurityScan]):
    """Repository for security scan operations."""

    def __init__(self, session: AsyncSession):
        super().__init__(session, SecurityScan)

    async def get_by_status(
        self, status: ScanStatus, organization_id: Optional[str] = None, limit: int = 50
    ) -> List[SecurityScan]:
        """Get scans by status."""
        filters = [self.model.status == status, self.model.is_active == True]  # noqa: E712

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def get_by_scan_type(
        self,
        scan_type: ScanType,
        organization_id: Optional[str] = None,
        include_completed: bool = True,
        limit: int = 100,
    ) -> List[SecurityScan]:
        """Get scans by type."""
        filters = [self.model.scan_type == scan_type, self.model.is_active == True]  # noqa: E712

        if not include_completed:
            filters.append(self.model.status != ScanStatus.COMPLETED)

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def get_running_scans(self, organization_id: Optional[str] = None) -> List[SecurityScan]:
        """Get all currently running scans."""
        filters = [self.model.status == ScanStatus.RUNNING, self.model.is_active == True]  # noqa: E712

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.started_at.desc())
        )
        return list(result.scalars().all())

    async def get_stalled_scans(
        self, timeout_minutes: int = 60, organization_id: Optional[str] = None
    ) -> List[SecurityScan]:
        """Get scans that appear to be stalled (running longer than expected)."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)

        filters = [
            self.model.status == ScanStatus.RUNNING,
            self.model.started_at < cutoff_time,
            self.model.is_active == True,  # noqa: E712
        ]

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(select(self.model).where(and_(*filters)).order_by(self.model.started_at))
        return list(result.scalars().all())

    async def get_scans_by_target(
        self, target: str, organization_id: Optional[str] = None, limit: int = 50
    ) -> List[SecurityScan]:
        """Get scans for a specific target."""
        filters = [self.model.target == target, self.model.is_active == True]  # noqa: E712

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def get_scans_by_initiator(
        self, initiator: str, organization_id: Optional[str] = None, days_back: Optional[int] = None
    ) -> List[SecurityScan]:
        """Get scans initiated by a specific user."""
        filters = [self.model.initiated_by == initiator, self.model.is_active == True]  # noqa: E712

        if days_back:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            filters.append(self.model.created_at >= cutoff_date)

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_baseline_scans(
        self, scan_type: Optional[ScanType] = None, target: Optional[str] = None, organization_id: Optional[str] = None
    ) -> List[SecurityScan]:
        """Get baseline scans for comparison purposes."""
        filters = [
            self.model.is_baseline == True,  # noqa: E712
            self.model.status == ScanStatus.COMPLETED,
            self.model.is_active == True,  # noqa: E712
        ]

        if scan_type:
            filters.append(self.model.scan_type == scan_type)

        if target:
            filters.append(self.model.target == target)

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.completed_at.desc())
        )
        return list(result.scalars().all())

    async def get_scans_by_pipeline(
        self, pipeline_id: str, organization_id: Optional[str] = None
    ) -> List[SecurityScan]:
        """Get all scans belonging to a specific pipeline."""
        filters = [self.model.pipeline_id == pipeline_id, self.model.is_active == True]  # noqa: E712

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc())
        )
        return list(result.scalars().all())

    async def search_scans(
        self, search_term: str, organization_id: Optional[str] = None, limit: int = 50
    ) -> List[SecurityScan]:
        """Search scans by name, target, or description."""
        search_pattern = f"%{search_term}%"

        filters = [
            or_(
                self.model.name.ilike(search_pattern),
                self.model.target.ilike(search_pattern),
                self.model.description.ilike(search_pattern),
                self.model.initiated_by.ilike(search_pattern),
            ),
            self.model.is_active == True,  # noqa: E712
        ]

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters)).order_by(self.model.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def get_scan_statistics(
        self, organization_id: Optional[str] = None, time_period_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get comprehensive statistics about security scans."""
        base_filters = [self.model.is_active == True]  # noqa: E712

        if organization_id:
            base_filters.append(self.model.organization_id == organization_id)

        if time_period_days:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=time_period_days)
            base_filters.append(self.model.created_at >= cutoff_date)

        # Total scans by status
        status_result = await self.session.execute(
            select(self.model.status, func.count(self.model.id)).where(and_(*base_filters)).group_by(self.model.status)
        )
        status_counts = {str(status): count for status, count in status_result.all()}

        # Scans by type
        type_result = await self.session.execute(
            select(self.model.scan_type, func.count(self.model.id))
            .where(and_(*base_filters))
            .group_by(self.model.scan_type)
        )
        type_counts = {str(scan_type): count for scan_type, count in type_result.all()}

        # Success rate (completed successfully)
        completed_scans = status_counts.get("completed", 0)
        total_scans = sum(status_counts.values())
        success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0

        # Average scan duration for completed scans
        duration_result = await self.session.execute(
            select(func.avg(self.model.duration_seconds)).where(
                and_(*base_filters, self.model.status == ScanStatus.COMPLETED, self.model.duration_seconds.isnot(None))
            )
        )
        avg_duration_seconds = duration_result.scalar_one() or 0

        # Top finding counts
        findings_result = await self.session.execute(
            select(
                func.sum(self.model.total_findings).label("total"),
                func.sum(self.model.critical_findings).label("critical"),
                func.sum(self.model.high_findings).label("high"),
                func.sum(self.model.medium_findings).label("medium"),
                func.sum(self.model.low_findings).label("low"),
                func.sum(self.model.info_findings).label("info"),
            ).where(and_(*base_filters))
        )
        findings_totals = findings_result.first()

        # Most active initiators
        initiator_result = await self.session.execute(
            select(self.model.initiated_by, func.count(self.model.id).label("scan_count"))
            .where(and_(*base_filters))
            .group_by(self.model.initiated_by)
            .order_by(func.count(self.model.id).desc())
            .limit(5)
        )

        top_initiators = [{"initiator": initiator, "scan_count": count} for initiator, count in initiator_result.all()]

        # Most scanned targets
        target_result = await self.session.execute(
            select(
                self.model.target,
                func.count(self.model.id).label("scan_count"),
                func.sum(self.model.total_findings).label("total_findings"),
            )
            .where(and_(*base_filters))
            .group_by(self.model.target)
            .order_by(func.count(self.model.id).desc())
            .limit(10)
        )

        top_targets = [
            {"target": target, "scan_count": scan_count, "total_findings": total_findings or 0}
            for target, scan_count, total_findings in target_result.all()
        ]

        # Pipeline statistics
        pipeline_result = await self.session.execute(
            select(self.model.pipeline_id, func.count(self.model.id).label("scan_count"))
            .where(and_(*base_filters, self.model.pipeline_id.isnot(None)))
            .group_by(self.model.pipeline_id)
            .order_by(func.count(self.model.id).desc())
            .limit(5)
        )

        pipeline_stats = [{"pipeline_id": pipeline, "scan_count": count} for pipeline, count in pipeline_result.all()]

        return {
            "total_scans": total_scans,
            "by_status": status_counts,
            "by_type": type_counts,
            "success_rate_percent": round(success_rate, 2),
            "avg_duration_minutes": round(avg_duration_seconds / 60, 2) if avg_duration_seconds else 0,
            "findings_summary": {
                "total": findings_totals.total or 0 if findings_totals else 0,
                "critical": findings_totals.critical or 0 if findings_totals else 0,
                "high": findings_totals.high or 0 if findings_totals else 0,
                "medium": findings_totals.medium or 0 if findings_totals else 0,
                "low": findings_totals.low or 0 if findings_totals else 0,
                "info": findings_totals.info or 0 if findings_totals else 0,
            },
            "top_initiators": top_initiators,
            "top_targets": top_targets,
            "pipeline_stats": pipeline_stats,
        }

    async def update_scan_progress(
        self,
        scan_id: str,
        status: ScanStatus,
        findings_counts: Optional[Dict[str, int]] = None,
        error_message: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> Optional[SecurityScan]:
        """Update scan progress and status."""
        filters = [self.model.id == scan_id]
        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        update_data = {"status": status, "updated_by": "system"}

        # Set timestamps based on status
        now = datetime.now(timezone.utc)
        if status == ScanStatus.RUNNING:
            update_data["started_at"] = now
        elif status == ScanStatus.COMPLETED:
            update_data["completed_at"] = now
            # Calculate duration if we have started_at
            current_scan = await self.get_by_id(scan_id, organization_id)
            if current_scan and current_scan.started_at:
                duration = (now - current_scan.started_at).total_seconds()
                update_data["duration_seconds"] = int(duration)

        # Update findings counts if provided
        if findings_counts:
            update_data.update(findings_counts)

        # Set error message if provided
        if error_message:
            update_data["error_message"] = error_message

        result = await self.session.execute(update(self.model).where(and_(*filters)).values(**update_data))

        if result.rowcount > 0:
            return await self.get_by_id(scan_id, organization_id)
        return None

    async def mark_scan_as_baseline(self, scan_id: str, organization_id: Optional[str] = None) -> bool:
        """Mark a completed scan as a baseline scan."""
        filters = [self.model.id == scan_id, self.model.status == ScanStatus.COMPLETED]

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            update(self.model).where(and_(*filters)).values(is_baseline=True, updated_by="system")
        )

        return result.rowcount > 0

    async def get_scan_comparison(
        self, scan_id: str, baseline_scan_id: str, organization_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Compare a scan with a baseline scan."""
        filters = [self.model.is_active == True]  # noqa: E712
        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        result = await self.session.execute(
            select(self.model).where(and_(*filters, self.model.id.in_([scan_id, baseline_scan_id])))
        )

        scans = {scan.id: scan for scan in result.scalars().all()}

        if len(scans) != 2:
            return None

        current_scan = scans.get(scan_id)
        baseline_scan = scans.get(baseline_scan_id)

        if not current_scan or not baseline_scan:
            return None

        # Calculate differences
        findings_diff = {
            "total": current_scan.total_findings - baseline_scan.total_findings,
            "critical": current_scan.critical_findings - baseline_scan.critical_findings,
            "high": current_scan.high_findings - baseline_scan.high_findings,
            "medium": current_scan.medium_findings - baseline_scan.medium_findings,
            "low": current_scan.low_findings - baseline_scan.low_findings,
            "info": current_scan.info_findings - baseline_scan.info_findings,
        }

        return {
            "current_scan": {
                "id": current_scan.id,
                "name": current_scan.name,
                "completed_at": current_scan.completed_at.isoformat() if current_scan.completed_at else None,
                "total_findings": current_scan.total_findings,
                "findings_by_severity": {
                    "critical": current_scan.critical_findings,
                    "high": current_scan.high_findings,
                    "medium": current_scan.medium_findings,
                    "low": current_scan.low_findings,
                    "info": current_scan.info_findings,
                },
            },
            "baseline_scan": {
                "id": baseline_scan.id,
                "name": baseline_scan.name,
                "completed_at": baseline_scan.completed_at.isoformat() if baseline_scan.completed_at else None,
                "total_findings": baseline_scan.total_findings,
                "findings_by_severity": {
                    "critical": baseline_scan.critical_findings,
                    "high": baseline_scan.high_findings,
                    "medium": baseline_scan.medium_findings,
                    "low": baseline_scan.low_findings,
                    "info": baseline_scan.info_findings,
                },
            },
            "differences": {
                "total_change": findings_diff["total"],
                "by_severity": findings_diff,
                "trend": (
                    "improved"
                    if findings_diff["total"] < 0
                    else "worsened" if findings_diff["total"] > 0 else "unchanged"
                ),
                "critical_trend": (
                    "improved"
                    if findings_diff["critical"] < 0
                    else "worsened" if findings_diff["critical"] > 0 else "unchanged"
                ),
            },
        }

    async def cleanup_old_scans(
        self, days_to_keep: int = 90, organization_id: Optional[str] = None, dry_run: bool = True
    ) -> Dict[str, int]:
        """Clean up old scan records (soft delete)."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

        filters = [
            self.model.created_at < cutoff_date,
            self.model.is_active == True,  # noqa: E712
            self.model.is_baseline == False,  # Don't delete baseline scans  # noqa: E712
        ]

        if organization_id:
            filters.append(self.model.organization_id == organization_id)

        # Count what would be deleted
        count_result = await self.session.execute(select(func.count(self.model.id)).where(and_(*filters)))
        count_to_delete = count_result.scalar_one()

        if not dry_run and count_to_delete > 0:
            # Perform soft delete
            result = await self.session.execute(
                update(self.model)
                .where(and_(*filters))
                .values(
                    is_active=False,
                    deleted_at=datetime.now(timezone.utc),
                    deleted_by="system_cleanup",
                    updated_by="system_cleanup",
                )
            )
            await self.session.commit()
            actual_deleted = result.rowcount or 0
        else:
            actual_deleted = 0

        return {"scans_to_delete": count_to_delete, "scans_deleted": actual_deleted, "dry_run": dry_run}
