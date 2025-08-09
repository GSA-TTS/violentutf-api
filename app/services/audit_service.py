"""Comprehensive audit logging service for security and compliance tracking."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union

from fastapi import Request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import NotFoundError, ValidationError
from app.models.audit_log import AuditLog
from app.repositories.base import BaseRepository

logger = get_logger(__name__)


class AuditService:
    """Service for comprehensive audit logging and compliance tracking."""

    # Event categories for structured logging
    AUTH_EVENTS = {
        "login_success": "User successfully logged in",
        "login_failed": "Failed login attempt",
        "logout": "User logged out",
        "password_changed": "User changed password",  # pragma: allowlist secret
        "password_reset": "Password reset performed",  # pragma: allowlist secret
        "account_locked": "Account locked due to failed attempts",
        "account_unlocked": "Account unlocked",
        "mfa_enabled": "MFA enabled for account",
        "mfa_disabled": "MFA disabled for account",
        "mfa_verified": "MFA verification successful",
        "mfa_failed": "MFA verification failed",
    }

    PERMISSION_EVENTS = {
        "permission_granted": "Permission check passed",
        "permission_denied": "Permission check failed",
        "role_assigned": "Role assigned to user",
        "role_revoked": "Role revoked from user",
        "permission_added": "Permission added to role",
        "permission_removed": "Permission removed from role",
    }

    API_KEY_EVENTS = {
        "api_key_created": "API key created",  # pragma: allowlist secret
        "api_key_rotated": "API key rotated",  # pragma: allowlist secret
        "api_key_revoked": "API key revoked",  # pragma: allowlist secret
        "api_key_used": "API key used for authentication",  # pragma: allowlist secret
        "api_key_expired": "API key expired",  # pragma: allowlist secret
        "api_key_invalid": "Invalid API key used",  # pragma: allowlist secret
    }

    RESOURCE_EVENTS = {
        "created": "Resource created",
        "updated": "Resource updated",
        "deleted": "Resource deleted",
        "accessed": "Resource accessed",
        "exported": "Resource data exported",
        "imported": "Resource data imported",
    }

    SECURITY_EVENTS = {
        "suspicious_activity": "Suspicious activity detected",
        "rate_limit_exceeded": "Rate limit exceeded",
        "invalid_input": "Invalid input rejected",
        "sql_injection_attempt": "SQL injection attempt blocked",
        "xss_attempt": "XSS attempt blocked",
        "csrf_violation": "CSRF token validation failed",
        "unauthorized_access": "Unauthorized access attempt",
        "privilege_escalation": "Privilege escalation attempt",
    }

    def __init__(self, session: AsyncSession):
        """Initialize audit service.

        Args:
            session: Database session
        """
        self.session = session
        self.repository: BaseRepository[AuditLog] = BaseRepository(session, AuditLog)

    async def log_event(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        request: Optional[Request] = None,
        changes: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> AuditLog:
        """Log an audit event.

        Args:
            action: Action performed (e.g., 'user.create')
            resource_type: Type of resource affected
            resource_id: ID of affected resource
            user_id: User who performed action
            user_email: Email of user
            request: FastAPI request object
            changes: Before/after values for updates
            metadata: Additional context
            status: Result status (success/failure/error)
            error_message: Error message if failed
            duration_ms: Operation duration

        Returns:
            Created AuditLog entry
        """
        try:
            # Extract request information
            ip_address = None
            user_agent = None
            request_id = None

            if request:
                # Get IP address
                if request.client:
                    ip_address = request.client.host
                elif hasattr(request, "headers"):
                    # Check for forwarded headers
                    ip_address = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") or None

                # Get user agent
                user_agent = request.headers.get("User-Agent")

                # Get request ID
                request_id = getattr(request.state, "request_id", None)

            # Sanitize sensitive data from changes and metadata
            if changes:
                changes = self._sanitize_sensitive_data(changes)
            if metadata:
                metadata = self._sanitize_sensitive_data(metadata)

            # Create audit log entry
            # Handle user_id conversion safely
            converted_user_id = None
            if user_id:
                if isinstance(user_id, uuid.UUID):
                    # Already a UUID object
                    converted_user_id = user_id
                else:
                    try:
                        # Try to convert to UUID if it's a valid UUID string
                        converted_user_id = uuid.UUID(str(user_id))
                    except (ValueError, TypeError):
                        # If not a valid UUID, ignore it
                        logger.debug(f"Invalid user_id format: {user_id}")
                        converted_user_id = None

            audit_data = {
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "user_id": converted_user_id,
                "user_email": user_email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "changes": changes,
                "action_metadata": metadata,
                "status": status,
                "error_message": error_message,
                "duration_ms": duration_ms,
            }

            # Add request correlation
            if request_id:
                if not audit_data["action_metadata"]:
                    audit_data["action_metadata"] = {}
                audit_data["action_metadata"]["request_id"] = request_id

            audit_log = AuditLog(**audit_data)
            self.session.add(audit_log)

            # Commit is handled by the caller

            logger.info(
                "Audit event logged",
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=user_id,
                status=status,
            )

            return audit_log

        except Exception as e:
            logger.error(
                "Failed to log audit event",
                action=action,
                resource_type=resource_type,
                error=str(e),
            )
            # Don't raise - audit logging should not break operations
            return None

    async def log_auth_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        request: Optional[Request] = None,
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        """Log authentication event.

        Args:
            event_type: Type of auth event
            user_id: User involved
            user_email: User email
            request: Request object
            success: Whether operation succeeded
            metadata: Additional context

        Returns:
            Created AuditLog entry
        """
        if event_type not in self.AUTH_EVENTS:
            logger.warning(f"Unknown auth event type: {event_type}")

        action = f"auth.{event_type}"
        status = "success" if success else "failure"

        # Add event description to metadata
        if not metadata:
            metadata = {}
        metadata["event_description"] = self.AUTH_EVENTS.get(event_type, f"Authentication event: {event_type}")

        return await self.log_event(
            action=action,
            resource_type="auth",
            user_id=user_id,
            user_email=user_email,
            request=request,
            metadata=metadata,
            status=status,
        )

    async def log_permission_event(
        self,
        event_type: str,
        user_id: str,
        permissions: List[str],
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        request: Optional[Request] = None,
        granted: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        """Log permission/authorization event.

        Args:
            event_type: Type of permission event
            user_id: User being checked
            permissions: Permissions involved
            resource_type: Resource being accessed
            resource_id: ID of resource
            request: Request object
            granted: Whether permission was granted
            metadata: Additional context

        Returns:
            Created AuditLog entry
        """
        action = f"permission.{event_type}"
        status = "success" if granted else "failure"

        # Build metadata
        if not metadata:
            metadata = {}
        metadata.update(
            {
                "permissions_checked": permissions,
                "permissions_granted": permissions if granted else [],
                "event_description": self.PERMISSION_EVENTS.get(event_type, f"Permission event: {event_type}"),
            }
        )

        return await self.log_event(
            action=action,
            resource_type=resource_type or "permission",
            resource_id=resource_id,
            user_id=user_id,
            request=request,
            metadata=metadata,
            status=status,
        )

    async def log_api_key_event(
        self,
        event_type: str,
        api_key_id: str,
        user_id: Optional[str] = None,
        request: Optional[Request] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        """Log API key event.

        Args:
            event_type: Type of API key event
            api_key_id: API key involved
            user_id: User who owns/used the key
            request: Request object
            metadata: Additional context

        Returns:
            Created AuditLog entry
        """
        action = f"api_key.{event_type}"

        # Build metadata
        if not metadata:
            metadata = {}
        metadata["event_description"] = self.API_KEY_EVENTS.get(event_type, f"API key event: {event_type}")

        return await self.log_event(
            action=action,
            resource_type="api_key",
            resource_id=api_key_id,
            user_id=user_id,
            request=request,
            metadata=metadata,
        )

    async def log_resource_event(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        user_id: str,
        request: Optional[Request] = None,
        changes: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        """Log resource modification event.

        Args:
            action: Action performed (created, updated, deleted)
            resource_type: Type of resource
            resource_id: Resource identifier
            user_id: User performing action
            request: Request object
            changes: Before/after values
            metadata: Additional context

        Returns:
            Created AuditLog entry
        """
        full_action = f"{resource_type}.{action}"

        # Build metadata
        if not metadata:
            metadata = {}
        metadata["event_description"] = self.RESOURCE_EVENTS.get(action, f"Resource {action}")

        return await self.log_event(
            action=full_action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            request=request,
            changes=changes,
            metadata=metadata,
        )

    async def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        request: Optional[Request] = None,
        risk_level: str = "medium",
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        """Log security event.

        Args:
            event_type: Type of security event
            user_id: User involved (if any)
            request: Request object
            risk_level: Risk level (low, medium, high, critical)
            details: Event details

        Returns:
            Created AuditLog entry
        """
        action = f"security.{event_type}"

        # Build metadata
        metadata = {
            "risk_level": risk_level,
            "event_description": self.SECURITY_EVENTS.get(event_type, f"Security event: {event_type}"),
        }
        if details:
            metadata.update(details)

        return await self.log_event(
            action=action,
            resource_type="security",
            user_id=user_id,
            request=request,
            metadata=metadata,
            status="failure",  # Security events are typically failures
        )

    async def get_user_activity(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get audit logs for a specific user.

        Args:
            user_id: User identifier
            start_date: Start of date range
            end_date: End of date range
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        query = select(AuditLog).where(AuditLog.user_id == uuid.UUID(user_id))

        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)

        query = query.order_by(AuditLog.created_at.desc()).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        limit: int = 50,
    ) -> List[AuditLog]:
        """Get audit history for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        query = (
            select(AuditLog)
            .where(
                and_(
                    AuditLog.resource_type == resource_type,
                    AuditLog.resource_id == resource_id,
                )
            )
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_failed_auth_attempts(
        self,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        time_window: timedelta = timedelta(hours=1),
    ) -> int:
        """Count failed authentication attempts.

        Args:
            user_email: User email to check
            ip_address: IP address to check
            time_window: Time window to check

        Returns:
            Number of failed attempts
        """
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

        query = select(func.count(AuditLog.id)).where(and_(*conditions))

        result = await self.session.execute(query)
        return result.scalar() or 0

    async def get_security_events(
        self,
        risk_levels: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get security events.

        Args:
            risk_levels: Risk levels to filter by
            start_date: Start of date range
            end_date: End of date range
            limit: Maximum number of records

        Returns:
            List of security audit logs
        """
        query = select(AuditLog).where(AuditLog.action.like("security.%"))

        if risk_levels:
            # Filter by risk level in metadata
            query = query.where(AuditLog.action_metadata["risk_level"].in_(risk_levels))

        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)

        query = query.order_by(AuditLog.created_at.desc()).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_audit_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Get audit log statistics.

        Args:
            start_date: Start of date range
            end_date: End of date range

        Returns:
            Dictionary with statistics
        """
        # Base conditions
        conditions = []
        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)

        # Total events
        total_query = select(func.count(AuditLog.id))
        if conditions:
            total_query = total_query.where(and_(*conditions))
        total_result = await self.session.execute(total_query)
        total_events = total_result.scalar() or 0

        # Events by type
        type_query = select(AuditLog.resource_type, func.count(AuditLog.id).label("count")).group_by(
            AuditLog.resource_type
        )
        if conditions:
            type_query = type_query.where(and_(*conditions))
        type_result = await self.session.execute(type_query)
        events_by_type = {row[0]: row[1] for row in type_result}

        # Events by status
        status_query = select(AuditLog.status, func.count(AuditLog.id).label("count")).group_by(AuditLog.status)
        if conditions:
            status_query = status_query.where(and_(*conditions))
        status_result = await self.session.execute(status_query)
        events_by_status = {row[0]: row[1] for row in status_result}

        # Failed auth attempts
        auth_conditions = conditions + [
            AuditLog.action.in_(["auth.login_failed", "auth.mfa_failed"]),
            AuditLog.status == "failure",
        ]
        auth_query = select(func.count(AuditLog.id)).where(and_(*auth_conditions))
        auth_result = await self.session.execute(auth_query)
        failed_auth_attempts = auth_result.scalar() or 0

        # Security events
        security_conditions = conditions + [AuditLog.action.like("security.%")]
        security_query = select(func.count(AuditLog.id)).where(and_(*security_conditions))
        security_result = await self.session.execute(security_query)
        security_events = security_result.scalar() or 0

        return {
            "total_events": total_events,
            "events_by_type": events_by_type,
            "events_by_status": events_by_status,
            "failed_auth_attempts": failed_auth_attempts,
            "security_events": security_events,
            "time_range": {
                "start": start_date.isoformat() if start_date else None,
                "end": end_date.isoformat() if end_date else None,
            },
        }

    async def search_audit_logs(
        self,
        action_pattern: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """Search audit logs with filters.

        Args:
            action_pattern: Action pattern to match
            resource_type: Resource type filter
            user_id: User ID filter
            status: Status filter
            start_date: Start date filter
            end_date: End date filter
            limit: Maximum results
            offset: Results offset

        Returns:
            List of matching audit logs
        """
        query = select(AuditLog)
        conditions = []

        if action_pattern:
            conditions.append(AuditLog.action.like(f"%{action_pattern}%"))
        if resource_type:
            conditions.append(AuditLog.resource_type == resource_type)
        if user_id:
            conditions.append(AuditLog.user_id == uuid.UUID(user_id))
        if status:
            conditions.append(AuditLog.status == status)
        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)

        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _sanitize_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from data.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data
        """
        if not data:
            return {}

        sensitive_keys = {
            "password",
            "password_hash",
            "token",
            "secret",
            "api_key",
            "private_key",
            "credit_card",
            "ssn",
            "tax_id",
            "bank_account",
            "access_token",
            "refresh_token",
            "client_secret",
        }

        def sanitize_value(value: Any, key: str) -> Any:
            """Recursively sanitize values."""
            if isinstance(value, dict):
                return {k: sanitize_value(v, k) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item, key) for item in value]
            elif any(sensitive in key.lower() for sensitive in sensitive_keys):
                return "[REDACTED]"
            else:
                return value

        return {key: sanitize_value(value, key) for key, value in data.items()}

    async def export_audit_logs(
        self,
        format: str = "json",
        filters: Optional[Dict[str, Any]] = None,
    ) -> Union[str, bytes]:
        """Export audit logs in specified format.

        Args:
            format: Export format (json, csv)
            filters: Search filters

        Returns:
            Exported data
        """
        # Get audit logs with filters
        logs = await self.search_audit_logs(
            action_pattern=filters.get("action_pattern") if filters else None,
            resource_type=filters.get("resource_type") if filters else None,
            user_id=filters.get("user_id") if filters else None,
            status=filters.get("status") if filters else None,
            start_date=filters.get("start_date") if filters else None,
            end_date=filters.get("end_date") if filters else None,
            limit=filters.get("limit", 10000) if filters else 10000,
        )

        if format == "json":
            return json.dumps(
                [log.to_dict() for log in logs],
                indent=2,
                default=str,
            )
        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            if logs:
                fieldnames = logs[0].to_dict().keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for log in logs:
                    writer.writerow(log.to_dict())

            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")

    async def cleanup_old_logs(self, retention_days: int = 365) -> int:
        """Clean up old audit logs based on retention policy.

        Args:
            retention_days: Number of days to retain logs

        Returns:
            Number of logs deleted
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Count logs to be deleted
        count_query = select(func.count(AuditLog.id)).where(AuditLog.created_at < cutoff_date)
        count_result = await self.session.execute(count_query)
        count = count_result.scalar() or 0

        if count > 0:
            # Delete old logs
            delete_query = AuditLog.__table__.delete().where(AuditLog.created_at < cutoff_date)
            await self.session.execute(delete_query)

            logger.info(
                "Cleaned up old audit logs",
                count=count,
                retention_days=retention_days,
                cutoff_date=cutoff_date.isoformat(),
            )

        return count
