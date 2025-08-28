"""Task repository for database operations."""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.task import Task
from app.repositories.base import BaseRepository


class TaskRepository(BaseRepository[Task]):
    """Repository for Task model operations."""

    def __init__(self, session: AsyncSession):
        """Initialize task repository.

        Args:
            session: Database session
        """
        super().__init__(session, Task)

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for tasks."""
        return ["name", "description", "status"]
