"""OAuth Access Token repository implementation."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthAccessToken, OAuthApplication
from ..models.user import User
from .base import BaseRepository


class OAuthAccessTokenRepository(BaseRepository[OAuthAccessToken]):
    """Repository for OAuth access tokens."""

    def __init__(self, session: AsyncSession):
        """Initialize OAuth access token repository."""
        super().__init__(session, OAuthAccessToken)

    async def get_by_token_hash(self, token_hash: str) -> Optional[OAuthAccessToken]:
        """Get access token by hash."""
        query = select(self.model).where(self.model.token_hash == token_hash)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_with_user_and_app(self, token_hash: str) -> Optional[Tuple[OAuthAccessToken, User, OAuthApplication]]:
        """Get access token with associated user and application."""
        query = (
            select(OAuthAccessToken, User, OAuthApplication)
            .join(User, OAuthAccessToken.user_id == User.id)
            .join(OAuthApplication, OAuthAccessToken.application_id == OAuthApplication.id)
            .where(OAuthAccessToken.token_hash == token_hash)
        )
        result = await self.session.execute(query)
        row = result.one_or_none()
        return row if row else None

    async def get_by_user_and_app(
        self, user_id: Union[str, uuid.UUID], application_id: Union[str, uuid.UUID]
    ) -> List[OAuthAccessToken]:
        """Get all access tokens for a user-application pair."""
        query = select(self.model).where(
            and_(self.model.user_id == str(user_id), self.model.application_id == str(application_id))
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def revoke_user_app_tokens(
        self, user_id: Union[str, uuid.UUID], application_id: Union[str, uuid.UUID]
    ) -> int:
        """Revoke all tokens for a user-application pair."""
        tokens = await self.get_by_user_and_app(user_id, application_id)
        count = 0

        for token in tokens:
            if not token.is_revoked:
                updated_token = await self.update(token.id, is_revoked=True, revoked_at=datetime.now(timezone.utc))
                if updated_token:
                    count += 1

        return count

    async def revoke_by_refresh_token(self, refresh_token_id: Union[str, uuid.UUID]) -> int:
        """Revoke all access tokens associated with a refresh token."""
        query = select(self.model).where(self.model.refresh_token_id == str(refresh_token_id))
        result = await self.session.execute(query)
        tokens = list(result.scalars().all())

        count = 0
        for token in tokens:
            if not token.is_revoked:
                updated_token = await self.update(token.id, is_revoked=True, revoked_at=datetime.now(timezone.utc))
                if updated_token:
                    count += 1

        return count

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for OAuth access tokens."""
        return []  # No searchable fields for security reasons
