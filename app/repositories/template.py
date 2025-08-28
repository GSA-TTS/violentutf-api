"""Template repository for database operations."""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import ReportTemplate
from app.repositories.base import BaseRepository


class TemplateRepository(BaseRepository[ReportTemplate]):
    """Repository for ReportTemplate model operations."""

    def __init__(self, session: AsyncSession):
        """Initialize template repository.

        Args:
            session: Database session
        """
        super().__init__(session, ReportTemplate)

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for templates."""
        return ["name", "description", "template_type"]
