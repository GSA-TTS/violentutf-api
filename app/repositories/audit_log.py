"""Audit Log repository for immutable audit trail management."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement
from structlog.stdlib import get_logger

from ..models.audit_log import AuditLog
from .base import BaseRepository, Page

logger = get_logger(__name__)


class AuditLogRepository(BaseRepository[AuditLog]):
    """
    Audit Log repository for immutable audit trail management.

    This repository handles audit logging with immutable record creation
    and provides advanced querying capabilities for audit analysis.
    """

    def __init__(self, session: AsyncSession):
        """Initialize audit log repository."""
        super().__init__(session, AuditLog)

    async def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[Union[str, uuid.UUID]] = None,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        changes: Optional[Dict[str, object]] = None,
        metadata: Optional[Dict[str, object]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> AuditLog:
        """
        Log an action to the audit trail.

        This is the primary method for creating audit log entries.
        All audit logs are immutable once created.

        Args:
            action: Action performed (e.g., 'user.create', 'api_key.delete')
            resource_type: Type of resource affected (e.g., 'user', 'api_key')
            resource_id: Optional ID of affected resource
            user_id: Optional user who performed the action
            user_email: Optional email of user at time of action
            ip_address: Optional IP address of the request
            user_agent: Optional user agent string
            changes: Optional before/after values for updates
            metadata: Optional additional context
            status: Result status (success, failure, error)
            error_message: Optional error message if action failed
            duration_ms: Optional duration of the action in milliseconds

        Returns:
            Created audit log entry
        """
        try:
            # Convert user_id to string if UUID
            uuid_user_id = None
            if user_id:
                if isinstance(user_id, str):
                    uuid_user_id = user_id
                else:
                    uuid_user_id = str(user_id)

            # Serialize changes and metadata to JSON strings
            changes_json = None
            if changes:
                changes_json = json.dumps(changes, default=str, sort_keys=True)

            metadata_json = None
            if metadata:
                metadata_json = json.dumps(metadata, default=str, sort_keys=True)

            # Create audit log entry
            audit_data: Dict[str, object] = {
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "user_id": uuid_user_id,
                "user_email": user_email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "changes": changes_json,
                "action_metadata": metadata_json,
                "status": status,
                "error_message": error_message,
                "duration_ms": duration_ms,
                "created_by": uuid_user_id or "system",
                "updated_by": uuid_user_id or "system",
            }

            audit_log = await self.create(audit_data)

            self.logger.info(
                "Action logged to audit trail",
                audit_log_id=audit_log.id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=uuid_user_id,
                status=status,
            )

            return audit_log

        except Exception as e:
            self.logger.error(
                "Failed to log action to audit trail", action=action, resource_type=resource_type, error=str(e)
            )
            raise

    async def get_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        page: int = 1,
        size: int = 50,
    ) -> Page[AuditLog]:
        """
        Get audit logs for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: ID of the resource
            page: Page number
            size: Page size

        Returns:
            Page of audit logs for the resource
        """
        try:
            filters: Dict[str, object] = {
                "resource_type": resource_type,
                "resource_id": resource_id,
            }

            audit_logs = await self.list_with_pagination(
                page=page,
                size=size,
                filters=filters,
                order_by="created_at",
                order_desc=True,
            )

            self.logger.debug(
                "Audit logs retrieved for resource",
                resource_type=resource_type,
                resource_id=resource_id,
                count=len(audit_logs.items),
            )

            return audit_logs

        except Exception as e:
            self.logger.error(
                "Failed to get audit logs for resource",
                resource_type=resource_type,
                resource_id=resource_id,
                error=str(e),
            )
            raise

    async def get_by_user(
        self,
        user_id: Union[str, uuid.UUID],
        page: int = 1,
        size: int = 50,
        action_pattern: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Page[AuditLog]:
        """
        Get audit logs for specific user.

        Args:
            user_id: User identifier
            page: Page number
            size: Page size
            action_pattern: Optional action pattern to filter by
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Page of audit logs for the user
        """
        try:
            user_id_str = str(user_id)

            # Build base query
            query = select(self.model).where(self.model.user_id == user_id_str)

            # Apply action pattern filter
            if action_pattern:
                query = query.where(self.model.action.like(f"%{action_pattern}%"))

            # Apply date range filters
            if start_date:
                query = query.where(self.model.created_at >= start_date)
            if end_date:
                query = query.where(self.model.created_at <= end_date)

            # Order by creation time (newest first)
            query = query.order_by(desc(self.model.created_at))

            # Count total items
            count_query = select(func.count()).select_from(query.subquery())
            total_result = await self.session.execute(count_query)
            total = total_result.scalar()

            # Apply pagination
            offset = (page - 1) * size
            query = query.offset(offset).limit(size)

            # Execute query
            result = await self.session.execute(query)
            items = list(result.scalars().all())

            # Calculate pagination metadata
            has_next = offset + size < total if total is not None else False
            has_prev = page > 1

            audit_logs = Page(
                items=items,
                total=total or 0,
                page=page,
                size=size,
                has_next=has_next,
                has_prev=has_prev,
            )

            self.logger.debug(
                "Audit logs retrieved for user",
                user_id=user_id_str,
                count=len(audit_logs.items),
                action_pattern=action_pattern,
            )

            return audit_logs

        except Exception as e:
            self.logger.error("Failed to get audit logs for user", user_id=str(user_id), error=str(e))
            raise

    async def get_recent_actions(
        self,
        limit: int = 100,
        action_types: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None,
        hours_back: int = 24,
    ) -> List[AuditLog]:
        """
        Get recent audit log entries.

        Args:
            limit: Maximum number of entries to return
            action_types: Optional list of action types to filter by
            resource_types: Optional list of resource types to filter by
            hours_back: Number of hours back to search (default 24)

        Returns:
            List of recent audit log entries
        """
        try:
            # Calculate start time
            start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

            # Build query
            query = select(self.model).where(self.model.created_at >= start_time)

            # Apply action type filter
            if action_types:
                query = query.where(self.model.action.in_(action_types))

            # Apply resource type filter
            if resource_types:
                query = query.where(self.model.resource_type.in_(resource_types))

            # Order by creation time (newest first) and limit
            query = query.order_by(desc(self.model.created_at)).limit(limit)

            result = await self.session.execute(query)
            recent_logs = list(result.scalars().all())

            self.logger.debug(
                "Recent audit logs retrieved",
                count=len(recent_logs),
                hours_back=hours_back,
                action_types=action_types,
                resource_types=resource_types,
            )

            return recent_logs

        except Exception as e:
            self.logger.error("Failed to get recent audit logs", hours_back=hours_back, error=str(e))
            raise

    async def get_action_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        group_by: str = "action",
    ) -> List[Dict[str, object]]:
        """
        Get audit log statistics grouped by specified field.

        Args:
            start_date: Optional start date filter
            end_date: Optional end date filter
            group_by: Field to group by ('action', 'resource_type', 'status', 'user_id')

        Returns:
            List of statistics with counts
        """
        try:
            # Validate group_by field
            valid_fields = ["action", "resource_type", "status", "user_id"]
            if group_by not in valid_fields:
                raise ValueError(f"group_by must be one of: {valid_fields}")

            # Get the field to group by
            group_field = getattr(self.model, group_by)

            # Build query
            query = select(group_field, func.count().label("count")).group_by(group_field)

            # Apply date filters
            if start_date:
                query = query.where(self.model.created_at >= start_date)
            if end_date:
                query = query.where(self.model.created_at <= end_date)

            # Order by count (descending)
            query = query.order_by(desc(func.count()))

            result = await self.session.execute(query)
            rows = result.fetchall()

            # Convert to list of dictionaries
            statistics = []
            for row in rows:
                statistics.append(
                    {
                        group_by: row[0],
                        "count": row[1],
                    }
                )

            self.logger.debug(
                "Audit log statistics retrieved",
                group_by=group_by,
                result_count=len(statistics),
                start_date=start_date,
                end_date=end_date,
            )

            return statistics

        except Exception as e:
            self.logger.error("Failed to get audit log statistics", group_by=group_by, error=str(e))
            raise

    async def search_logs(
        self,
        search_term: str,
        search_fields: Optional[List[str]] = None,
        page: int = 1,
        size: int = 50,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Page[AuditLog]:
        """
        Search audit logs by text content.

        Args:
            search_term: Term to search for
            search_fields: Fields to search in (default: action, resource_type, user_email)
            page: Page number
            size: Page size
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Page of matching audit logs
        """
        try:
            if not search_fields:
                search_fields = ["action", "resource_type", "user_email", "error_message"]

            # Build search conditions
            search_conditions = []
            for field in search_fields:
                if hasattr(self.model, field):
                    field_attr = getattr(self.model, field)
                    search_conditions.append(field_attr.like(f"%{search_term}%"))

            if not search_conditions:
                raise ValueError("No valid search fields provided")

            # Build query - use OR to search across multiple fields
            query = select(self.model).where(
                or_(*search_conditions) if len(search_conditions) > 1 else search_conditions[0]
            )

            # Apply date filters
            if start_date:
                query = query.where(self.model.created_at >= start_date)
            if end_date:
                query = query.where(self.model.created_at <= end_date)

            # Count total items
            count_query = select(func.count()).select_from(query.subquery())
            total_result = await self.session.execute(count_query)
            total = total_result.scalar()

            # Order by creation time (newest first) and apply pagination
            query = query.order_by(desc(self.model.created_at))
            offset = (page - 1) * size
            query = query.offset(offset).limit(size)

            # Execute query
            result = await self.session.execute(query)
            items = list(result.scalars().all())

            # Calculate pagination metadata
            has_next = offset + size < total if total is not None else False
            has_prev = page > 1

            search_results = Page(
                items=items,
                total=total or 0,
                page=page,
                size=size,
                has_next=has_next,
                has_prev=has_prev,
            )

            self.logger.debug(
                "Audit log search completed",
                search_term=search_term,
                search_fields=search_fields,
                result_count=len(search_results.items),
                total=total,
            )

            return search_results

        except Exception as e:
            self.logger.error("Failed to search audit logs", search_term=search_term, error=str(e))
            raise

    # Override delete methods to prevent audit log deletion
    async def delete(self, entity_id: Union[str, uuid.UUID], hard_delete: bool = False) -> bool:
        """
        Audit logs are immutable and cannot be deleted.

        This method is overridden to prevent accidental deletion of audit records.
        """
        self.logger.warning("Attempt to delete audit log denied - audit logs are immutable", entity_id=str(entity_id))
        raise ValueError("Audit logs are immutable and cannot be deleted")

    # Override update method to prevent audit log modification
    async def update(self, entity_id: Union[str, uuid.UUID], **kwargs: object) -> Optional[AuditLog]:
        """
        Audit logs are immutable and cannot be updated.

        This method is overridden to prevent accidental modification of audit records.
        """
        self.logger.warning("Attempt to update audit log denied - audit logs are immutable", entity_id=str(entity_id))
        raise ValueError("Audit logs are immutable and cannot be updated")

    def _build_search_conditions(
        self,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[ColumnElement[bool]]:
        """
        Build search conditions for audit log queries.

        Args:
            action: Filter by action
            user_id: Filter by user ID
            resource_type: Filter by resource type
            status: Filter by status
            start_date: Filter by start date
            end_date: Filter by end date

        Returns:
            List of SQLAlchemy conditions
        """
        conditions: List[ColumnElement[bool]] = []

        if action:
            conditions.append(self.model.action == action)

        if user_id:
            user_uuid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id
            conditions.append(self.model.user_id == user_uuid)

        if resource_type:
            conditions.append(self.model.resource_type == resource_type)

        if status:
            conditions.append(self.model.status == status)

        if start_date:
            conditions.append(self.model.created_at >= start_date)

        if end_date:
            conditions.append(self.model.created_at <= end_date)

        return conditions

    def _apply_search_pagination(
        self,
        query: Select[tuple[AuditLog]],
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> Select[tuple[AuditLog]]:
        """
        Apply ordering and pagination to a query.

        Args:
            query: SQLAlchemy query object
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            Query with ordering and pagination applied
        """
        # Add ordering
        query = query.order_by(self.model.created_at.desc())

        # Apply pagination
        if limit:
            query = query.limit(limit)

        if offset:
            query = query.offset(offset)

        return query

    async def search(
        self,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: Optional[int] = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Search audit logs with optional filters.

        Args:
            action: Filter by action (e.g., 'user.create')
            user_id: Filter by user ID
            resource_type: Filter by resource type
            status: Filter by status (success, failure, error)
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of matching AuditLog instances
        """
        try:
            # Build query with filters
            query = select(self.model)
            conditions = self._build_search_conditions(
                action=action,
                user_id=user_id,
                resource_type=resource_type,
                status=status,
                start_date=start_date,
                end_date=end_date,
            )

            if conditions:
                query = query.where(and_(*conditions))

            # Apply ordering and pagination
            query = self._apply_search_pagination(query, limit=limit, offset=offset)

            # Execute query
            result = await self.session.execute(query)
            audit_logs = result.scalars().all()

            self.logger.debug(
                "Searched audit logs",
                count=len(audit_logs),
                filters={"action": action, "user_id": user_id, "resource_type": resource_type},
            )

            return list(audit_logs)

        except Exception as e:
            self.logger.error("Failed to search audit logs", error=str(e))
            raise

    async def get_statistics(self) -> Dict[str, object]:
        """
        Get audit log statistics and metrics.

        Returns:
            Dictionary containing audit log statistics
        """
        try:
            from sqlalchemy import func

            # Total audit logs
            total_query = select(func.count(self.model.id))
            total_result = await self.session.execute(total_query)
            total_logs = total_result.scalar() or 0

            # Actions by type
            actions_query = (
                select(self.model.action, func.count(self.model.id).label("count"))
                .group_by(self.model.action)
                .order_by(func.count(self.model.id).desc())
            )

            actions_result = await self.session.execute(actions_query)
            actions_stats = {row[0]: int(row[1]) for row in actions_result}

            # Status distribution
            status_query = select(self.model.status, func.count(self.model.id).label("count")).group_by(
                self.model.status
            )

            status_result = await self.session.execute(status_query)
            status_stats = {row[0]: int(row[1]) for row in status_result}

            # Recent activity (last 24 hours)
            from datetime import datetime, timedelta, timezone

            yesterday = datetime.now(timezone.utc) - timedelta(days=1)

            recent_query = select(func.count(self.model.id)).where(self.model.created_at >= yesterday)
            recent_result = await self.session.execute(recent_query)
            recent_activity = recent_result.scalar() or 0

            # Format statistics for API response
            total = int(total_logs)
            success_count = status_stats.get("success", 0)
            failure_count = status_stats.get("failure", 0)
            error_count = status_stats.get("error", 0)

            success_rate = (success_count / total * 100) if total > 0 else 0.0
            failure_rate = (failure_count / total * 100) if total > 0 else 0.0
            error_rate = (error_count / total * 100) if total > 0 else 0.0

            # Get top actions, users, and resource types
            top_actions = dict(list(actions_stats.items())[:10])

            # Users by activity
            users_query = (
                select(self.model.user_id, func.count(self.model.id).label("count"))
                .where(self.model.user_id.is_not(None))
                .group_by(self.model.user_id)
                .order_by(func.count(self.model.id).desc())
                .limit(10)
            )

            users_result = await self.session.execute(users_query)
            top_users = {str(row.user_id): row.count for row in users_result}

            # Resource types by activity
            resources_query = (
                select(self.model.resource_type, func.count(self.model.id).label("count"))
                .group_by(self.model.resource_type)
                .order_by(func.count(self.model.id).desc())
                .limit(10)
            )

            resources_result = await self.session.execute(resources_query)
            top_resource_types = {row.resource_type: row.count for row in resources_result}

            # Average duration
            avg_duration_query = select(func.avg(self.model.duration_ms)).where(self.model.duration_ms.is_not(None))
            avg_duration_result = await self.session.execute(avg_duration_query)
            avg_duration_ms = avg_duration_result.scalar()

            formatted_stats = {
                "total_logs": total,
                "logs_today": recent_activity,
                "success_rate": round(success_rate, 2),
                "failure_rate": round(failure_rate, 2),
                "error_rate": round(error_rate, 2),
                "avg_duration_ms": round(avg_duration_ms, 2) if avg_duration_ms else None,
                "top_actions": top_actions,
                "top_users": top_users,
                "top_resource_types": top_resource_types,
            }

            self.logger.debug("Generated audit log statistics", total_logs=total)
            return formatted_stats

        except Exception as e:
            self.logger.error("Failed to get audit log statistics", error=str(e))
            raise

    async def get_resource_summary(self, resource_type: str, resource_id: str) -> Optional[Dict[str, object]]:
        """
        Get audit summary for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: ID of the resource

        Returns:
            Summary dictionary or None if no logs found
        """
        try:
            # Check if any logs exist for this resource
            count_query = select(func.count(self.model.id)).where(
                and_(self.model.resource_type == resource_type, self.model.resource_id == resource_id)
            )
            count_result = await self.session.execute(count_query)
            total_actions = count_result.scalar() or 0

            if total_actions == 0:
                return None

            # Get first and last action timestamps
            timestamps_query = select(
                func.min(self.model.created_at).label("first_action"),
                func.max(self.model.created_at).label("last_action"),
            ).where(and_(self.model.resource_type == resource_type, self.model.resource_id == resource_id))
            timestamps_result = await self.session.execute(timestamps_query)
            timestamps_row = timestamps_result.first()

            # Get unique users count
            users_query = select(func.count(func.distinct(self.model.user_id))).where(
                and_(
                    self.model.resource_type == resource_type,
                    self.model.resource_id == resource_id,
                    self.model.user_id.is_not(None),
                )
            )
            users_result = await self.session.execute(users_query)
            unique_users = users_result.scalar() or 0

            # Get action breakdown
            actions_query = (
                select(self.model.action, func.count(self.model.id).label("count"))
                .where(and_(self.model.resource_type == resource_type, self.model.resource_id == resource_id))
                .group_by(self.model.action)
            )

            actions_result = await self.session.execute(actions_query)
            action_breakdown = {row.action: row.count for row in actions_result}

            # Get status breakdown
            status_query = (
                select(self.model.status, func.count(self.model.id).label("count"))
                .where(and_(self.model.resource_type == resource_type, self.model.resource_id == resource_id))
                .group_by(self.model.status)
            )

            status_result = await self.session.execute(status_query)
            status_breakdown = {row.status: row.count for row in status_result}

            summary = {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "total_actions": total_actions,
                "first_action_at": timestamps_row.first_action if timestamps_row else None,
                "last_action_at": timestamps_row.last_action if timestamps_row else None,
                "unique_users": unique_users,
                "action_breakdown": action_breakdown,
                "status_breakdown": status_breakdown,
            }

            self.logger.debug(
                "Generated resource audit summary",
                resource_type=resource_type,
                resource_id=resource_id,
                total_actions=total_actions,
            )

            return summary

        except Exception as e:
            self.logger.error(
                "Failed to get resource audit summary",
                resource_type=resource_type,
                resource_id=resource_id,
                error=str(e),
            )
            raise

    def _build_export_filter_conditions(self, filters: Optional[Dict[str, object]] = None) -> List[ColumnElement[bool]]:
        """
        Build filter conditions for export queries.

        Args:
            filters: Optional filters to apply

        Returns:
            List of SQLAlchemy conditions
        """
        conditions: List[ColumnElement[bool]] = []

        if not filters:
            return conditions

        for key, value in filters.items():
            if not value:
                continue

            if key == "user_id":
                conditions.append(self.model.user_id == value)
            elif key == "resource_type":
                conditions.append(self.model.resource_type == value)
            elif key == "action__in" and isinstance(value, list):
                conditions.append(self.model.action.in_(value))
            elif key == "created_at__gte":
                conditions.append(self.model.created_at >= value)
            elif key == "created_at__lte":
                conditions.append(self.model.created_at <= value)

        return conditions

    async def list_for_export(
        self, filters: Optional[Dict[str, object]] = None, include_metadata: bool = False, limit: int = 10000
    ) -> List[AuditLog]:
        """
        Get audit logs for export with optional filters.

        Args:
            filters: Optional filters to apply
            include_metadata: Whether to include metadata fields
            limit: Maximum number of records to export

        Returns:
            List of audit logs for export
        """
        try:
            query = select(self.model)
            conditions = self._build_export_filter_conditions(filters)

            if conditions:
                query = query.where(and_(*conditions))

            # Order by creation time and limit
            query = query.order_by(self.model.created_at.desc()).limit(limit)

            result = await self.session.execute(query)
            audit_logs = list(result.scalars().all())

            self.logger.info("Audit logs prepared for export", count=len(audit_logs), include_metadata=include_metadata)

            return audit_logs

        except Exception as e:
            self.logger.error("Failed to prepare audit logs for export", error=str(e))
            raise

    async def export_to_csv(self, audit_logs: List[AuditLog], include_metadata: bool = False) -> str:
        """
        Export audit logs to CSV format.

        Args:
            audit_logs: List of audit logs to export
            include_metadata: Whether to include metadata columns

        Returns:
            CSV content as string
        """
        try:
            import csv
            import io

            output = io.StringIO()

            # Define CSV headers
            headers = [
                "id",
                "action",
                "resource_type",
                "resource_id",
                "user_id",
                "user_email",
                "ip_address",
                "status",
                "error_message",
                "duration_ms",
                "created_at",
                "created_by",
            ]

            if include_metadata:
                headers.extend(["user_agent", "changes", "action_metadata"])

            writer = csv.writer(output)
            writer.writerow(headers)

            # Write data rows
            for log in audit_logs:
                row = [
                    str(log.id),
                    log.action,
                    log.resource_type,
                    log.resource_id or "",
                    str(log.user_id) if log.user_id else "",
                    log.user_email or "",
                    log.ip_address or "",
                    log.status,
                    log.error_message or "",
                    log.duration_ms or "",
                    log.created_at.isoformat() if log.created_at else "",
                    log.created_by or "",
                ]

                if include_metadata:
                    row.extend(
                        [
                            log.user_agent or "",
                            json.dumps(log.changes) if log.changes else "",
                            json.dumps(log.action_metadata) if log.action_metadata else "",
                        ]
                    )

                writer.writerow(row)

            return output.getvalue()

        except Exception as e:
            self.logger.error("Failed to export audit logs to CSV", error=str(e))
            raise

    async def export_to_json(self, audit_logs: List[AuditLog], include_metadata: bool = False) -> str:
        """
        Export audit logs to JSON format.

        Args:
            audit_logs: List of audit logs to export
            include_metadata: Whether to include metadata fields

        Returns:
            JSON content as string
        """
        try:
            export_data = []

            for log in audit_logs:
                log_data = {
                    "id": str(log.id),
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "user_id": str(log.user_id) if log.user_id else None,
                    "user_email": log.user_email,
                    "ip_address": log.ip_address,
                    "status": log.status,
                    "error_message": log.error_message,
                    "duration_ms": log.duration_ms,
                    "created_at": log.created_at.isoformat() if log.created_at else None,
                    "created_by": log.created_by,
                }

                if include_metadata:
                    log_data.update(
                        {
                            "user_agent": log.user_agent,
                            "changes": log.changes if isinstance(log.changes, (str, int)) else None,
                            "action_metadata": (
                                log.action_metadata if isinstance(log.action_metadata, (str, int)) else None
                            ),
                        }
                    )

                export_data.append(log_data)

            return json.dumps(export_data, indent=2, default=str)

        except Exception as e:
            self.logger.error("Failed to export audit logs to JSON", error=str(e))
            raise
