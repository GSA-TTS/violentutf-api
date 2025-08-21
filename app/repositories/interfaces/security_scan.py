"""Security Scan repository interface."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.security_scan import SecurityScan

from .base import IBaseRepository


class ISecurityScanRepository(IBaseRepository[SecurityScan]):
    """Interface for security scan repository operations."""

    @abstractmethod
    async def get_by_target(
        self, target: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[SecurityScan]:
        """
        Get security scans by target.

        Args:
            target: Target URL or identifier
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of security scans for the target
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_status(
        self, status: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[SecurityScan]:
        """
        Get security scans by status.

        Args:
            status: Scan status
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of security scans with specified status
        """
        raise NotImplementedError

    @abstractmethod
    async def get_recent_scans(
        self, hours: int = 24, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[SecurityScan]:
        """
        Get recent security scans within specified time window.

        Args:
            hours: Time window in hours
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of recent security scans
        """
        raise NotImplementedError

    @abstractmethod
    async def get_scan_statistics(
        self,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get security scan statistics.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dictionary containing scan statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def get_scans_by_user(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 50
    ) -> List[SecurityScan]:
        """
        Get security scans initiated by a specific user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of security scans by the user
        """
        raise NotImplementedError

    @abstractmethod
    async def get_scans_with_findings(
        self, severity: Optional[str] = None, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[SecurityScan]:
        """
        Get security scans that have findings.

        Args:
            severity: Optional severity filter
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of security scans with findings
        """
        raise NotImplementedError

    @abstractmethod
    async def update_scan_status(
        self,
        scan_id: Union[str, uuid.UUID],
        status: str,
        progress: Optional[int] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update security scan status and progress.

        Args:
            scan_id: Security scan ID
            status: New status
            progress: Optional progress percentage
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def complete_scan(
        self,
        scan_id: Union[str, uuid.UUID],
        results: Dict[str, Any],
        findings_count: int = 0,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Mark security scan as completed with results.

        Args:
            scan_id: Security scan ID
            results: Scan results
            findings_count: Number of findings discovered
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if completion successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def search_scans(
        self, query: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[SecurityScan]:
        """
        Search security scans by target, description, or findings.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching security scans
        """
        raise NotImplementedError

    @abstractmethod
    async def get_scan_trends(
        self, organization_id: Optional[Union[str, uuid.UUID]] = None, days: int = 30
    ) -> Dict[str, Any]:
        """
        Get security scan trends over time.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            days: Number of days to analyze

        Returns:
            Dictionary containing scan trend data
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_old_scans(
        self, retention_days: int, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> int:
        """
        Clean up old security scans based on retention policy.

        Args:
            retention_days: Number of days to retain scans
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of scans cleaned up
        """
        raise NotImplementedError
