"""MFA Backup Code repository implementation."""

import uuid
from typing import List, Optional, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.mfa import MFABackupCode
from .base import BaseRepository


class MFABackupCodeRepository(BaseRepository[MFABackupCode]):
    """Repository for MFA backup codes."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA backup code repository."""
        super().__init__(session, MFABackupCode)

    async def get_by_hash(self, code_hash: str) -> Optional[MFABackupCode]:
        """Get backup code by hash."""
        query = select(self.model).where(self.model.code_hash == code_hash)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_user_codes(self, user_id: Union[str, uuid.UUID], unused_only: bool = True) -> List[MFABackupCode]:
        """Get backup codes for a user."""
        conditions = [self.model.user_id == str(user_id)]

        if unused_only:
            conditions.append(self.model.is_used == False)

        query = select(self.model).where(and_(*conditions))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count_unused_codes(self, user_id: Union[str, uuid.UUID]) -> int:
        """Count unused backup codes for a user."""
        return await self.count(filters={"user_id": str(user_id), "is_used": False})

    async def mark_code_used(self, code_id: Union[str, uuid.UUID]) -> bool:
        """Mark a backup code as used."""
        from datetime import datetime, timezone

        updated_code = await self.update(code_id, is_used=True, used_at=datetime.now(timezone.utc))
        return updated_code is not None

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for MFA backup codes."""
        return []  # No searchable fields for security reasons
