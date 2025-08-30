"""Security scan management service for handling security scan operations."""

from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import NotFoundError, ValidationError
from app.models.security_scan import SecurityScan
from app.repositories.security_scan import SecurityScanRepository

logger = get_logger(__name__)


class SecurityScanService:
    """Service for managing security scans using repository pattern."""

    def __init__(self, repository_or_session: Union[SecurityScanRepository, AsyncSession]):
        """Initialize security scan service with repository or database session.

        Args:
            repository_or_session: Security scan repository or AsyncSession
        """
        if isinstance(repository_or_session, AsyncSession):
            self.repository = SecurityScanRepository(repository_or_session)
        else:
            self.repository = repository_or_session

    async def create_security_scan(self, scan_data: Dict[str, Any], user_id: str) -> SecurityScan:
        """Create a new security scan.

        Args:
            scan_data: Security scan creation data
            user_id: User creating the scan

        Returns:
            SecurityScan: Created security scan instance

        Raises:
            ValidationError: If scan data is invalid
        """
        try:
            # Add audit fields
            scan_data.update({"created_by": user_id, "updated_by": user_id, "status": "pending"})

            scan = await self.repository.create(scan_data)
            logger.info("security_scan_created", scan_id=scan.id, user_id=user_id)
            return scan

        except Exception as e:
            logger.error("failed_to_create_security_scan", error=str(e))
            raise ValidationError(f"Failed to create security scan: {str(e)}")

    async def get_security_scan(self, scan_id: str) -> Optional[SecurityScan]:
        """Get security scan by ID.

        Args:
            scan_id: Security scan identifier

        Returns:
            SecurityScan: Security scan instance if found

        Raises:
            NotFoundError: If scan not found
        """
        scan = await self.repository.get(scan_id)
        if not scan:
            raise NotFoundError(f"Security scan with ID {scan_id} not found")
        return scan

    async def list_security_scans(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> List[SecurityScan]:
        """List security scans with pagination and filtering.

        Args:
            skip: Number of scans to skip
            limit: Maximum number of scans to return
            filters: Optional filters to apply
            user_id: Optional user ID filter for user's scans

        Returns:
            List[SecurityScan]: List of security scans
        """
        if user_id:
            if not filters:
                filters = {}
            filters["created_by"] = user_id

        return await self.repository.list(skip=skip, limit=limit, filters=filters)

    async def update_security_scan(self, scan_id: str, update_data: Dict[str, Any], user_id: str) -> SecurityScan:
        """Update security scan.

        Args:
            scan_id: Security scan identifier
            update_data: Data to update
            user_id: User performing update

        Returns:
            SecurityScan: Updated security scan instance

        Raises:
            NotFoundError: If scan not found
            ValidationError: If update fails
        """
        try:
            await self.get_security_scan(scan_id)  # Validate scan exists

            # Add audit fields
            update_data["updated_by"] = user_id

            updated_scan = await self.repository.update(scan_id, update_data)
            logger.info("security_scan_updated", scan_id=scan_id, user_id=user_id)
            return updated_scan

        except Exception as e:
            logger.error("failed_to_update_security_scan", scan_id=scan_id, error=str(e))
            raise ValidationError(f"Failed to update security scan: {str(e)}")

    async def delete_security_scan(self, scan_id: str, user_id: str) -> bool:
        """Delete security scan.

        Args:
            scan_id: Security scan identifier
            user_id: User performing deletion

        Returns:
            bool: True if deletion successful

        Raises:
            NotFoundError: If scan not found
        """
        try:
            # Verify security_scan exists before operation
            await self.get_security_scan(scan_id)
            success = await self.repository.delete(scan_id)

            if success:
                logger.info("security_scan_deleted", scan_id=scan_id, user_id=user_id)

            return success

        except Exception as e:
            logger.error("failed_to_delete_security_scan", scan_id=scan_id, error=str(e))
            raise

    async def execute_security_scan(self, scan_id: str, user_id: str) -> SecurityScan:
        """Execute a security scan.

        Args:
            scan_id: Security scan identifier
            user_id: User executing the scan

        Returns:
            SecurityScan: Updated scan instance
        """
        scan = await self.update_security_scan(scan_id, {"status": "running", "started_at": "now()"}, user_id)

        logger.info("security_scan_started", scan_id=scan_id, user_id=user_id)
        return scan

    async def complete_security_scan(
        self, scan_id: str, results: Dict[str, Any], findings_count: int = 0
    ) -> SecurityScan:
        """Complete a security scan with results.

        Args:
            scan_id: Security scan identifier
            results: Scan results data
            findings_count: Number of findings detected

        Returns:
            SecurityScan: Updated scan instance
        """
        update_data = {
            "status": "completed",
            "completed_at": "now()",
            "results": results,
            "findings_count": findings_count,
        }

        scan = await self.update_security_scan(scan_id, update_data, "system")

        logger.info("security_scan_completed", scan_id=scan_id, findings_count=findings_count)
        return scan

    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get results for a completed security scan.

        Args:
            scan_id: Security scan identifier

        Returns:
            Dict: Scan results data

        Raises:
            NotFoundError: If scan not found
            ValidationError: If scan not completed
        """
        scan = await self.get_security_scan(scan_id)

        if scan.status != "completed":
            raise ValidationError("Scan has not completed yet")

        return scan.results or {}
