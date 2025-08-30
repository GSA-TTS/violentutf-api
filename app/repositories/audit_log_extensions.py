"""Extensions for audit log repository to support service layer requirements."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.audit_log import AuditLog
from .audit_log import AuditLogRepository


class ExtendedAuditLogRepository(AuditLogRepository):
    """Extended audit log repository with additional methods for service layer."""

    def __init__(self, session: AsyncSession):
        """Initialize extended audit log repository."""
        super().__init__(session)

    async def count_failed_attempts(
        self,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        time_window: timedelta = timedelta(minutes=15),
    ) -> int:
        """Count failed authentication attempts within time window."""
        since = datetime.now(timezone.utc) - time_window

        conditions = [
            AuditLog.action.in_(["auth.login_failed", "auth.mfa_failed"]),
            AuditLog.status == "failure",
            AuditLog.created_at >= since,
        ]

        if user_email:
            conditions.append(AuditLog.user_email == user_email)
        if ip_address:
            conditions.append(AuditLog.ip_address == ip_address)

        return await self.count(conditions)

    async def get_security_events(
        self,
        risk_levels: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get security events with optional filters."""
        conditions = []

        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)
        if risk_levels:
            # Assuming risk levels are stored in metadata
            # This is a simplified implementation
            pass

        query = select(self.model)
        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(self.model.created_at.desc()).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_compliance_report_data(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get compliance report data."""
        conditions = []
        if start_date:
            conditions.append(self.model.created_at >= start_date)
        if end_date:
            conditions.append(self.model.created_at <= end_date)

        # Total events
        total_query = select(func.count(self.model.id))
        if conditions:
            total_query = total_query.where(and_(*conditions))
        total_result = await self.session.execute(total_query)
        total_events = total_result.scalar() or 0

        # Events by type
        type_query = select(self.model.action, func.count(self.model.id).label("count")).group_by(self.model.action)
        if conditions:
            type_query = type_query.where(and_(*conditions))
        type_result = await self.session.execute(type_query)
        events_by_type = {row[0]: row[1] for row in type_result}

        # Events by status
        status_query = select(self.model.status, func.count(self.model.id).label("count")).group_by(self.model.status)
        if conditions:
            status_query = status_query.where(and_(*conditions))
        status_result = await self.session.execute(status_query)
        events_by_status = {row[0]: row[1] for row in status_result}

        # Failed auth attempts
        auth_conditions = conditions + [
            self.model.action.in_(["auth.login_failed", "auth.mfa_failed"]),
            self.model.status == "failure",
        ]
        auth_query = select(func.count(self.model.id)).where(and_(*auth_conditions))
        auth_result = await self.session.execute(auth_query)
        failed_auth_attempts = auth_result.scalar() or 0

        # Security events
        security_conditions = conditions + [self.model.action.like("security.%")]
        security_query = select(func.count(self.model.id)).where(and_(*security_conditions))
        security_result = await self.session.execute(security_query)
        security_events = security_result.scalar() or 0

        return {
            "total_events": total_events,
            "events_by_type": events_by_type,
            "events_by_status": events_by_status,
            "failed_auth_attempts": failed_auth_attempts,
            "security_events": security_events,
        }

    async def search_for_compliance(
        self,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """Search audit logs for compliance purposes."""
        return await self.search(
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            status=status,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )

    async def cleanup_old_logs(self, retention_days: int) -> int:
        """Clean up audit logs older than retention period."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Count logs to be deleted
        count_query = select(func.count(self.model.id)).where(self.model.created_at < cutoff_date)
        count_result = await self.session.execute(count_query)
        count = count_result.scalar() or 0

        if count > 0:
            # Delete old logs
            delete_query = delete(self.model).where(self.model.created_at < cutoff_date)
            await self.session.execute(delete_query)

        return count
