"""OAuth Refresh Token repository implementation."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthApplication, OAuthRefreshToken
from .base import BaseRepository


class OAuthRefreshTokenRepository(BaseRepository[OAuthRefreshToken]):
    """Repository for OAuth refresh tokens."""

    def __init__(self, session: AsyncSession):
        """Initialize OAuth refresh token repository."""
        super().__init__(session, OAuthRefreshToken)

    async def get_by_token_hash(self, token_hash: str) -> Optional[OAuthRefreshToken]:
        """Get refresh token by hash."""
        query = select(self.model).where(self.model.token_hash == token_hash)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_user_and_app(
        self, user_id: Union[str, uuid.UUID], application_id: Union[str, uuid.UUID]
    ) -> List[OAuthRefreshToken]:
        """Get all refresh tokens for a user-application pair."""
        query = select(self.model).where(
            and_(self.model.user_id == str(user_id), self.model.application_id == str(application_id))
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_user_authorizations(
        self, user_id: Union[str, uuid.UUID]
    ) -> List[Tuple[OAuthApplication, OAuthRefreshToken]]:
        """Get all active authorizations for a user."""
        now = datetime.now(timezone.utc)
        query = (
            select(OAuthApplication, OAuthRefreshToken)
            .join(OAuthRefreshToken, OAuthApplication.id == OAuthRefreshToken.application_id)
            .where(
                and_(
                    OAuthRefreshToken.user_id == str(user_id),
                    OAuthRefreshToken.is_revoked == False,
                    OAuthRefreshToken.expires_at > now,
                )
            )
            .distinct(OAuthApplication.id)
        )
        result = await self.session.execute(query)
        return list(result.all())

    async def revoke_user_app_tokens(
        self, user_id: Union[str, uuid.UUID], application_id: Union[str, uuid.UUID]
    ) -> int:
        """Revoke all refresh tokens for a user-application pair."""
        query = select(self.model).where(
            and_(
                self.model.user_id == str(user_id),
                self.model.application_id == str(application_id),
                self.model.is_revoked == False,
            )
        )
        result = await self.session.execute(query)
        tokens = list(result.scalars().all())

        count = 0
        for token in tokens:
            updated_token = await self.update(token.id, is_revoked=True, revoked_at=datetime.now(timezone.utc))
            if updated_token:
                count += 1

        return count

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for OAuth refresh tokens."""
        return []  # No searchable fields for security reasons
