"""MFA Event repository implementation."""

import uuid
from typing import List, Optional, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.mfa import MFAEvent, MFAMethod
from .base import BaseRepository


class MFAEventRepository(BaseRepository[MFAEvent]):
    """Repository for MFA events."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA event repository."""
        super().__init__(session, MFAEvent)

    async def get_by_user_id(self, user_id: Union[str, uuid.UUID]) -> List[MFAEvent]:
        """Get all MFA events for a user."""
        query = select(self.model).where(self.model.user_id == str(user_id)).order_by(self.model.created_at.desc())
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_event_type(self, event_type: str) -> List[MFAEvent]:
        """Get events by type."""
        query = select(self.model).where(self.model.event_type == event_type).order_by(self.model.created_at.desc())
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_user_and_type(self, user_id: Union[str, uuid.UUID], event_type: str) -> List[MFAEvent]:
        """Get events by user and type."""
        query = (
            select(self.model)
            .where(and_(self.model.user_id == str(user_id), self.model.event_type == event_type))
            .order_by(self.model.created_at.desc())
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for MFA events."""
        return ["event_type", "event_status"]
