"""MFA Policy repository implementation."""

import json
from typing import Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.mfa import MFAPolicy
from .base import BaseRepository


class MFAPolicyRepository(BaseRepository[MFAPolicy]):
    """Repository for MFA policies."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA policy repository."""
        super().__init__(session, MFAPolicy)

    async def get_by_name(self, name: str) -> Optional[MFAPolicy]:
        """Get policy by name."""
        query = select(self.model).where(self.model.name == name)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_active_policies_ordered(self) -> List[MFAPolicy]:
        """Get all active policies ordered by priority (highest first)."""
        query = select(self.model).where(self.model.is_active == True).order_by(desc(self.model.priority))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def list_policies_paginated(
        self, active_only: bool = True, limit: int = 100, offset: int = 0
    ) -> List[MFAPolicy]:
        """List policies with pagination."""
        query = select(self.model)

        if active_only:
            query = query.where(self.model.is_active == True)

        query = query.order_by(desc(self.model.priority)).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for MFA policies."""
        return ["name", "description"]
