"""Scan management service for handling scan operations."""

from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from structlog.stdlib import get_logger

from app.core.errors import NotFoundError, ValidationError
from app.models.scan import Scan
from app.repositories.base import BaseRepository

logger = get_logger(__name__)


class ScanService:
    """Service for managing scans with transaction management."""

    def __init__(self, repository: BaseRepository):
        """Initialize scan service with repository.

        Args:
            repository: Scan repository for data access
        """
        self.repository = repository

    async def create_scan(self, scan_data: Dict[str, Any], user_id: str) -> Scan:
        """Create a new scan.

        Args:
            scan_data: Scan creation data
            user_id: User creating the scan

        Returns:
            Scan: Created scan instance

        Raises:
            ValidationError: If scan data is invalid
        """
        try:
            # Add audit fields
            scan_data.update({"id": str(uuid4()), "created_by": user_id, "updated_by": user_id, "status": "pending"})

            scan = await self.repository.create(scan_data)
            logger.info("scan_created", scan_id=scan.id, user_id=user_id)
            return scan

        except Exception as e:
            logger.error("failed_to_create_scan", error=str(e))
            raise ValidationError(f"Failed to create scan: {str(e)}")

    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan: Scan instance if found

        Raises:
            NotFoundError: If scan not found
        """
        scan = await self.repository.get(scan_id)
        if not scan:
            raise NotFoundError(f"Scan with ID {scan_id} not found")
        return scan

    async def list_scans(
        self, skip: int = 0, limit: int = 100, filters: Optional[Dict[str, Any]] = None, user_id: Optional[str] = None
    ) -> List[Scan]:
        """List scans with pagination and filtering.

        Args:
            skip: Number of scans to skip
            limit: Maximum number of scans to return
            filters: Optional filters to apply
            user_id: Optional user ID filter for user's scans

        Returns:
            List[Scan]: List of scans
        """
        if user_id and not filters:
            filters = {"created_by": user_id}
        elif user_id and filters:
            filters["created_by"] = user_id

        return await self.repository.list(skip=skip, limit=limit, filters=filters)

    async def update_scan(self, scan_id: str, update_data: Dict[str, Any], user_id: str) -> Scan:
        """Update scan.

        Args:
            scan_id: Scan identifier
            update_data: Data to update
            user_id: User performing update

        Returns:
            Scan: Updated scan instance

        Raises:
            NotFoundError: If scan not found
            ValidationError: If update fails
        """
        try:
            await self.get_scan(scan_id)  # Validate scan exists

            # Add audit fields
            update_data["updated_by"] = user_id

            updated_scan = await self.repository.update(scan_id, update_data)
            logger.info("scan_updated", scan_id=scan_id, user_id=user_id)
            return updated_scan

        except Exception as e:
            logger.error("failed_to_update_scan", scan_id=scan_id, error=str(e))
            raise ValidationError(f"Failed to update scan: {str(e)}")

    async def delete_scan(self, scan_id: str, user_id: str) -> bool:
        """Delete scan.

        Args:
            scan_id: Scan identifier
            user_id: User performing deletion

        Returns:
            bool: True if deletion successful

        Raises:
            NotFoundError: If scan not found
        """
        try:
            # Verify scan exists before operation
            await self.get_scan(scan_id)
            success = await self.repository.delete(scan_id)
            if success:
                logger.info("scan_deleted", scan_id=scan_id, user_id=user_id)
            return success

        except Exception as e:
            logger.error("failed_to_delete_scan", scan_id=scan_id, error=str(e))
            raise

    async def start_scan(self, scan_id: str, user_id: str) -> Scan:
        """Start a scan.

        Args:
            scan_id: Scan identifier
            user_id: User starting the scan

        Returns:
            Scan: Updated scan instance
        """
        return await self.update_scan(scan_id, {"status": "running", "started_at": "now()"}, user_id)

    async def stop_scan(self, scan_id: str, user_id: str) -> Scan:
        """Stop a running scan.

        Args:
            scan_id: Scan identifier
            user_id: User stopping the scan

        Returns:
            Scan: Updated scan instance
        """
        return await self.update_scan(scan_id, {"status": "stopped", "stopped_at": "now()"}, user_id)

    async def complete_scan(self, scan_id: str, results: Dict[str, Any]) -> Scan:
        """Mark scan as completed with results.

        Args:
            scan_id: Scan identifier
            results: Scan results data

        Returns:
            Scan: Updated scan instance
        """
        return await self.update_scan(
            scan_id, {"status": "completed", "completed_at": "now()", "results": results}, "system"
        )
