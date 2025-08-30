"""MFA Device repository implementation."""

import uuid
from typing import List, Optional, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.mfa import MFADevice, MFAMethod
from .base import BaseRepository


class MFADeviceRepository(BaseRepository[MFADevice]):
    """Repository for MFA devices."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA device repository."""
        super().__init__(session, MFADevice)

    async def get_by_user_id(self, user_id: Union[str, uuid.UUID]) -> List[MFADevice]:
        """Get all active MFA devices for a user."""
        query = select(self.model).where(
            and_(
                self.model.user_id == str(user_id),
                self.model.is_active == True,
                self.model.is_deleted == False,
            )
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_primary_device(self, user_id: Union[str, uuid.UUID]) -> Optional[MFADevice]:
        """Get the primary MFA device for a user."""
        query = select(self.model).where(
            and_(
                self.model.user_id == str(user_id),
                self.model.is_primary == True,
                self.model.is_active == True,
                self.model.is_deleted == False,
            )
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_user_and_method(self, user_id: Union[str, uuid.UUID], method: MFAMethod) -> Optional[MFADevice]:
        """Get MFA device by user ID and method."""
        query = select(self.model).where(
            and_(
                self.model.user_id == str(user_id),
                self.model.method == method,
                self.model.is_active == True,
                self.model.is_deleted == False,
            )
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def count_active_devices(self, user_id: Union[str, uuid.UUID]) -> int:
        """Count active MFA devices for a user."""
        return await self.count(filters={"user_id": str(user_id), "is_active": True})

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for MFA devices."""
        return ["name"]
