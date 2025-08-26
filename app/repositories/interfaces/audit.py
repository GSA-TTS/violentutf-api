"""Audit repository interface contract."""

from abc import ABC, abstractmethod
from datetime import date
from typing import Any, Dict, List, Optional

from ...models.audit_log import AuditLog


class IAuditRepository(ABC):
    """Interface contract for audit repository operations."""

    @abstractmethod
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
        pass

    @abstractmethod
    async def get_user_audit_trail(self, user_id: str, limit: int = 100) -> List[AuditLog]:
        """Get audit trail for a specific user."""
        pass

    @abstractmethod
    async def get_compliance_report(
        self,
        start_date: date,
        end_date: date,
        organization_id: Optional[str] = None,
    ) -> List[AuditLog]:
        """Get compliance report for a date range."""
        pass

    @abstractmethod
    async def get_audit_logs_by_action(
        self,
        action: str,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Get audit logs filtered by action type."""
        pass

    @abstractmethod
    async def get_failed_login_attempts(
        self,
        time_window_hours: int = 24,
        min_attempts: int = 3,
    ) -> List[Dict[str, Any]]:
        """Get failed login attempts that exceed threshold."""
        pass

    @abstractmethod
    async def get_audit_statistics(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> Dict[str, Any]:
        """Get audit statistics for a date range."""
        pass

    @abstractmethod
    async def cleanup_old_audit_logs(self, retention_days: int = 365) -> int:
        """Clean up old audit logs beyond retention period."""
        pass
