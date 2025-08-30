"""OAuth Application repository implementation."""

import uuid
from typing import List, Optional, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthApplication
from .base import BaseRepository


class OAuthApplicationRepository(BaseRepository[OAuthApplication]):
    """Repository for OAuth applications."""

    def __init__(self, session: AsyncSession):
        """Initialize OAuth application repository."""
        super().__init__(session, OAuthApplication)

    async def get_by_client_id(self, client_id: str) -> Optional[OAuthApplication]:
        """Get application by client ID."""
        query = select(self.model).where(and_(self.model.client_id == client_id, self.model.is_deleted == False))
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_owner_id(self, owner_id: Union[str, uuid.UUID]) -> List[OAuthApplication]:
        """Get all applications owned by a user."""
        query = (
            select(self.model)
            .where(and_(self.model.owner_id == str(owner_id), self.model.is_deleted == False))
            .order_by(self.model.created_at.desc())
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_applications(self) -> List[OAuthApplication]:
        """Get all active applications."""
        query = select(self.model).where(and_(self.model.is_active == True, self.model.is_deleted == False))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for OAuth applications."""
        return ["name", "description", "client_id"]
