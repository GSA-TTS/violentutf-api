"""Plugin repository for data access operations."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.plugin import Plugin
from app.repositories.base import BaseRepository


class PluginRepository(BaseRepository[Plugin]):
    """Repository for plugin data access operations."""

    def __init__(self, session: AsyncSession):
        """Initialize plugin repository.

        Args:
            session: Database session
        """
        super().__init__(session, Plugin)
