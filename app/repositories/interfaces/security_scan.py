"""Security Scan repository interface contract."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ...models.security_scan import SecurityScan


class ISecurityScanRepository(ABC):
    """Interface contract for security scan repository operations."""

    @abstractmethod
    async def get_by_target(self, target: str) -> List[SecurityScan]:
        """Get security scans by target."""
        pass

    @abstractmethod
    async def get_scan_statistics(self, time_period: timedelta) -> Dict[str, Any]:
        """Get scan statistics for a time period."""
        pass

    @abstractmethod
    async def create_scan(
        self,
        target: str,
        scan_type: str,
        user_id: str,
        organization_id: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SecurityScan:
        """Create a new security scan."""
        pass

    @abstractmethod
    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        results: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> Optional[SecurityScan]:
        """Update scan status and results."""
        pass

    @abstractmethod
    async def get_active_scans(self) -> List[SecurityScan]:
        """Get all currently running scans."""
        pass

    @abstractmethod
    async def get_user_scans(
        self,
        user_id: str,
        limit: int = 50,
        status_filter: Optional[str] = None,
    ) -> List[SecurityScan]:
        """Get scans for a specific user."""
        pass

    @abstractmethod
    async def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get results for a specific scan."""
        pass

    @abstractmethod
    async def cancel_scan(self, scan_id: str, cancelled_by: str) -> bool:
        """Cancel a running scan."""
        pass

    @abstractmethod
    async def cleanup_old_scans(self, retention_days: int = 90) -> int:
        """Clean up old scan records."""
        pass

    @abstractmethod
    async def get_scan_analytics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Get scan analytics and metrics."""
        pass
