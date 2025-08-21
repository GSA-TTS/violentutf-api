"""Audit Log repository interface."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.audit_log import AuditLog

from .base import IBaseRepository


class IAuditLogRepository(IBaseRepository[AuditLog]):
    """Interface for audit log repository operations."""

    @abstractmethod
    async def log_action(
        self,
        action: str,
        user_id: Union[str, uuid.UUID],
        resource_type: str,
        resource_id: Optional[Union[str, uuid.UUID]] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        session_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> AuditLog:
        """
        Log an action to the audit trail.

        Args:
            action: Action performed
            user_id: User who performed the action
            resource_type: Type of resource affected
            resource_id: Optional ID of the resource affected
            details: Optional additional details
            ip_address: Optional IP address
            user_agent: Optional user agent
            organization_id: Optional organization ID for multi-tenant filtering
            session_id: Optional session ID

        Returns:
            Created audit log entry
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_audit_trail(
        self,
        user_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        limit: int = 100,
        offset: int = 0,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[AuditLog]:
        """
        Get audit trail for a specific user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of entries
            offset: Offset for pagination
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            List of audit log entries
        """
        raise NotImplementedError

    @abstractmethod
    async def get_resource_audit_trail(
        self,
        resource_type: str,
        resource_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Get audit trail for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource ID
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of entries
            offset: Offset for pagination

        Returns:
            List of audit log entries
        """
        raise NotImplementedError

    @abstractmethod
    async def get_security_events(
        self,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        severity: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Get security-related audit events.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            severity: Optional severity filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of entries
            offset: Offset for pagination

        Returns:
            List of security audit log entries
        """
        raise NotImplementedError

    @abstractmethod
    async def get_failed_login_attempts(
        self,
        user_id: Optional[Union[str, uuid.UUID]] = None,
        ip_address: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        hours: int = 24,
    ) -> List[AuditLog]:
        """
        Get failed login attempts within specified time window.

        Args:
            user_id: Optional user ID filter
            ip_address: Optional IP address filter
            organization_id: Optional organization ID for multi-tenant filtering
            hours: Time window in hours

        Returns:
            List of failed login attempts
        """
        raise NotImplementedError

    @abstractmethod
    async def get_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        report_type: Optional[str] = None,
    ) -> List[AuditLog]:
        """
        Generate compliance report for specified date range.

        Args:
            start_date: Start date for report
            end_date: End date for report
            organization_id: Optional organization ID for multi-tenant filtering
            report_type: Optional report type filter

        Returns:
            List of audit log entries for compliance report
        """
        raise NotImplementedError

    @abstractmethod
    async def get_audit_statistics(
        self,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get audit log statistics.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dictionary containing audit statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def search_audit_logs(
        self,
        query: str,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Search audit logs by action, resource type, or details.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of matching audit log entries
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_old_audit_logs(
        self,
        retention_days: int,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> int:
        """
        Clean up old audit logs based on retention policy.

        Args:
            retention_days: Number of days to retain audit logs
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of audit logs cleaned up
        """
        raise NotImplementedError

    @abstractmethod
    async def export_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        format_type: str = "json",
    ) -> List[Dict[str, Any]]:
        """
        Export audit logs for specified date range.

        Args:
            start_date: Start date for export
            end_date: End date for export
            organization_id: Optional organization ID for multi-tenant filtering
            format_type: Export format (json, csv, etc.)

        Returns:
            List of audit log entries formatted for export
        """
        raise NotImplementedError
