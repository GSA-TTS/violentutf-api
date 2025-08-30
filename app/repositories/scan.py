"""Scan repository for data access operations."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.repositories.base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    """Repository for scan data access operations."""

    def __init__(self, session: AsyncSession):
        """Initialize scan repository.

        Args:
            session: Database session
        """
        super().__init__(session, Scan)
