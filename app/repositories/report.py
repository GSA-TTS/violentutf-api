"""Report repository for database operations."""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import Report
from app.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    """Repository for Report model operations."""

    def __init__(self, session: AsyncSession):
        """Initialize report repository.

        Args:
            session: Database session
        """
        super().__init__(session, Report)

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for reports."""
        return ["name", "report_type", "status", "title"]
