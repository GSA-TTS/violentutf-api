"""OAuth Authorization Code repository implementation."""

import uuid
from typing import List, Optional, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthAuthorizationCode
from .base import BaseRepository


class OAuthAuthorizationCodeRepository(BaseRepository[OAuthAuthorizationCode]):
    """Repository for OAuth authorization codes."""

    def __init__(self, session: AsyncSession):
        """Initialize OAuth authorization code repository."""
        super().__init__(session, OAuthAuthorizationCode)

    async def get_by_code_hash(self, code_hash: str) -> Optional[OAuthAuthorizationCode]:
        """Get authorization code by hash."""
        query = select(self.model).where(self.model.code_hash == code_hash)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: Union[str, uuid.UUID]) -> List[OAuthAuthorizationCode]:
        """Get all authorization codes for a user."""
        query = select(self.model).where(self.model.user_id == str(user_id))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for OAuth authorization codes."""
        return []  # No searchable fields for security reasons
