"""OAuth Scope repository implementation."""

from typing import List, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthScope
from .base import BaseRepository


class OAuthScopeRepository(BaseRepository[OAuthScope]):
    """Repository for OAuth scopes."""

    def __init__(self, session: AsyncSession):
        """Initialize OAuth scope repository."""
        super().__init__(session, OAuthScope)

    async def get_by_name(self, name: str) -> Optional[OAuthScope]:
        """Get scope by name."""
        query = select(self.model).where(self.model.name == name)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_active_scopes(self) -> List[OAuthScope]:
        """Get all active scopes."""
        query = select(self.model).where(self.model.is_active == True)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_names(self, names: List[str]) -> List[OAuthScope]:
        """Get scopes by names."""
        query = select(self.model).where(self.model.name.in_(names))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for OAuth scopes."""
        return ["name", "description"]
