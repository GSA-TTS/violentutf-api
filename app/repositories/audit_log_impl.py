"""Audit Log repository implementation."""

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ..models.audit_log import AuditLog
from .base import BaseRepository
from .interfaces.audit import IAuditRepository

logger = get_logger(__name__)


class AuditLogRepository(BaseRepository[AuditLog], IAuditRepository):
    """
    Audit Log repository with comprehensive auditing capabilities.

    Implements IAuditRepository interface for audit logging, compliance
    reporting, and security monitoring.
    """

    def __init__(self, session: AsyncSession):
        """Initialize audit log repository."""
        super().__init__(session, AuditLog)

    async def log_action(
        self,
        action: str,
        user_id: Optional[str],
        details: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> AuditLog:
        """Log an audit action."""
        try:
            audit_data = {
                "action": action,
                "user_id": user_id,
                "details": details,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "organization_id": organization_id,
                "timestamp": datetime.now(timezone.utc),
                "created_by": user_id or "system",
            }

            audit_log = await self.create(audit_data)

            self.logger.debug(
                "Audit action logged",
                action=action,
                user_id=user_id,
                audit_id=audit_log.id,
            )

            return audit_log
        except Exception as e:
            self.logger.error("Failed to log audit action", action=action, user_id=user_id, error=str(e))
            raise

    async def get_user_audit_trail(self, user_id: str, limit: int = 100) -> List[AuditLog]:
        """Get audit trail for a specific user."""
        try:
            query = (
                select(self.model)
                .where(
                    and_(
                        self.model.user_id == user_id,
                        self.model.is_deleted == False,  # noqa: E712
                    )
                )
                .order_by(self.model.timestamp.desc())
                .limit(limit)
            )

            result = await self.session.execute(query)
            audit_logs = list(result.scalars().all())

            self.logger.debug("Retrieved user audit trail", user_id=user_id, count=len(audit_logs))
            return audit_logs
        except Exception as e:
            self.logger.error("Failed to get user audit trail", user_id=user_id, error=str(e))
            raise

    async def get_compliance_report(
        self,
        start_date: date,
        end_date: date,
        organization_id: Optional[str] = None,
    ) -> List[AuditLog]:
        """Get compliance report for a date range."""
        try:
            # Convert dates to datetime for comparison
            start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc)
            end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc)

            query = select(self.model).where(
                and_(
                    self.model.timestamp >= start_datetime,
                    self.model.timestamp <= end_datetime,
                    self.model.is_deleted == False,  # noqa: E712
                )
            )

            # Add organization filter if provided
            if organization_id:
                query = query.where(self.model.organization_id == organization_id)

            query = query.order_by(self.model.timestamp.desc())

            result = await self.session.execute(query)
            audit_logs = list(result.scalars().all())

            self.logger.debug(
                "Generated compliance report",
                start_date=start_date,
                end_date=end_date,
                organization_id=organization_id,
                count=len(audit_logs),
            )

            return audit_logs
        except Exception as e:
            self.logger.error(
                "Failed to generate compliance report",
                start_date=start_date,
                end_date=end_date,
                error=str(e),
            )
            raise

    async def get_audit_logs_by_action(
        self,
        action: str,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get audit logs filtered by action type."""
        try:
            query = select(self.model).where(
                and_(
                    self.model.action == action,
                    self.model.is_deleted == False,  # noqa: E712
                )
            )

            # Add date range filters if provided
            if start_date:
                start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc)
                query = query.where(self.model.timestamp >= start_datetime)

            if end_date:
                end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc)
                query = query.where(self.model.timestamp <= end_datetime)

            query = query.order_by(self.model.timestamp.desc()).limit(limit)

            result = await self.session.execute(query)
            audit_logs = list(result.scalars().all())

            self.logger.debug(
                "Retrieved audit logs by action",
                action=action,
                start_date=start_date,
                end_date=end_date,
                count=len(audit_logs),
            )

            return audit_logs
        except Exception as e:
            self.logger.error(
                "Failed to get audit logs by action",
                action=action,
                error=str(e),
            )
            raise

    async def get_failed_login_attempts(
        self,
        time_window_hours: int = 24,
        min_attempts: int = 3,
    ) -> List[Dict[str, Any]]:
        """Get failed login attempts that exceed threshold."""
        try:
            time_threshold = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)

            # Query for failed login attempts grouped by IP address
            query = (
                select(
                    self.model.ip_address,
                    func.count(self.model.id).label("attempt_count"),
                    func.max(self.model.timestamp).label("last_attempt"),
                )
                .where(
                    and_(
                        self.model.action == "failed_login",
                        self.model.timestamp >= time_threshold,
                        self.model.is_deleted == False,  # noqa: E712
                        self.model.ip_address.is_not(None),
                    )
                )
                .group_by(self.model.ip_address)
                .having(func.count(self.model.id) >= min_attempts)
                .order_by(func.count(self.model.id).desc())
            )

            result = await self.session.execute(query)
            failed_attempts = [
                {
                    "ip_address": row.ip_address,
                    "attempt_count": row.attempt_count,
                    "last_attempt": row.last_attempt,
                }
                for row in result
            ]

            self.logger.debug(
                "Retrieved failed login attempts",
                time_window_hours=time_window_hours,
                min_attempts=min_attempts,
                count=len(failed_attempts),
            )

            return failed_attempts
        except Exception as e:
            self.logger.error(
                "Failed to get failed login attempts",
                time_window_hours=time_window_hours,
                min_attempts=min_attempts,
                error=str(e),
            )
            raise

    async def get_audit_statistics(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> Dict[str, Any]:
        """Get audit statistics for a date range."""
        try:
            query = select(self.model).where(self.model.is_deleted == False)  # noqa: E712

            # Add date range filters if provided
            if start_date:
                start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc)
                query = query.where(self.model.timestamp >= start_datetime)

            if end_date:
                end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc)
                query = query.where(self.model.timestamp <= end_datetime)

            # Get total count
            total_result = await self.session.execute(select(func.count()).select_from(query.subquery()))
            total_count = total_result.scalar() or 0

            # Get action counts

            action_result = await self.session.execute(
                select(self.model.action, func.count(self.model.id).label("count"))
                .select_from(query.subquery())
                .group_by(self.model.action)
            )

            action_counts = {row.action: row.count for row in action_result}

            # Get user counts
            user_result = await self.session.execute(
                select(func.count(func.distinct(self.model.user_id))).select_from(query.subquery())
            )
            unique_users = user_result.scalar() or 0

            # Get recent activity (last 24 hours)
            recent_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_query = query.where(self.model.timestamp >= recent_threshold)
            recent_result = await self.session.execute(select(func.count()).select_from(recent_query.subquery()))
            recent_activity = recent_result.scalar() or 0

            statistics = {
                "total_audit_logs": total_count,
                "unique_users": unique_users,
                "recent_activity_24h": recent_activity,
                "action_counts": action_counts,
                "date_range": {
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None,
                },
            }

            self.logger.debug(
                "Generated audit statistics",
                total_count=total_count,
                start_date=start_date,
                end_date=end_date,
            )

            return statistics
        except Exception as e:
            self.logger.error(
                "Failed to get audit statistics",
                start_date=start_date,
                end_date=end_date,
                error=str(e),
            )
            raise

    async def cleanup_old_audit_logs(self, retention_days: int = 365) -> int:
        """Clean up old audit logs beyond retention period."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

            # Get count of logs to be deleted
            count_query = select(func.count(self.model.id)).where(
                and_(
                    self.model.timestamp < cutoff_date,
                    self.model.is_deleted == False,  # noqa: E712
                )
            )
            count_result = await self.session.execute(count_query)
            logs_to_delete = count_result.scalar() or 0

            if logs_to_delete > 0:
                # Soft delete old logs
                updated_logs = await self.session.execute(
                    select(self.model).where(
                        and_(
                            self.model.timestamp < cutoff_date,
                            self.model.is_deleted == False,  # noqa: E712
                        )
                    )
                )

                deleted_count = 0
                for log in updated_logs.scalars().all():
                    if await self.delete(log.id):
                        deleted_count += 1

                self.logger.info(
                    "Old audit logs cleaned up",
                    retention_days=retention_days,
                    deleted_count=deleted_count,
                )

                return deleted_count
            else:
                self.logger.debug("No old audit logs to clean up", retention_days=retention_days)
                return 0

        except Exception as e:
            self.logger.error("Failed to cleanup old audit logs", retention_days=retention_days, error=str(e))
            raise
