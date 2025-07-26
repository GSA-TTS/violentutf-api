"""Audit Log repository for immutable audit trail management."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
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
        changes: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
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
            audit_data = {
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

            audit_log = await self.create(**audit_data)

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
            filters = {
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
    ) -> List[Dict[str, Any]]:
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
    async def update(self, entity_id: Union[str, uuid.UUID], **kwargs: Any) -> Optional[AuditLog]:  # noqa: ANN401
        """
        Audit logs are immutable and cannot be updated.

        This method is overridden to prevent accidental modification of audit records.
        """
        self.logger.warning("Attempt to update audit log denied - audit logs are immutable", entity_id=str(entity_id))
        raise ValueError("Audit logs are immutable and cannot be updated")
