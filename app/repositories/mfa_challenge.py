"""MFA Challenge repository implementation."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Union

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.mfa import MFAChallenge, MFAMethod
from .base import BaseRepository


class MFAChallengeRepository(BaseRepository[MFAChallenge]):
    """Repository for MFA challenges."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA challenge repository."""
        super().__init__(session, MFAChallenge)

    async def get_by_challenge_id(self, challenge_id: str) -> Optional[MFAChallenge]:
        """Get challenge by challenge ID."""
        query = select(self.model).where(self.model.challenge_id == challenge_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_active_challenge(self, user_id: Union[str, uuid.UUID], method: MFAMethod) -> Optional[MFAChallenge]:
        """Get active challenge for user and method."""
        now = datetime.now(timezone.utc)
        query = select(self.model).where(
            and_(
                self.model.user_id == str(user_id),
                self.model.method == method,
                self.model.is_verified == False,
                self.model.expires_at > now,
                self.model.attempt_count < self.model.max_attempts,
            )
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_user_challenges(
        self, user_id: Union[str, uuid.UUID], include_expired: bool = False
    ) -> List[MFAChallenge]:
        """Get all challenges for a user."""
        conditions = [self.model.user_id == str(user_id)]

        if not include_expired:
            now = datetime.now(timezone.utc)
            conditions.append(self.model.expires_at > now)

        query = select(self.model).where(and_(*conditions))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def cleanup_expired_challenges(self) -> int:
        """Clean up expired challenges."""
        now = datetime.now(timezone.utc)

        # Get expired challenges
        query = select(self.model).where(self.model.expires_at < now)
        result = await self.session.execute(query)
        expired_challenges = list(result.scalars().all())

        # Delete them
        count = 0
        for challenge in expired_challenges:
            await self.delete_permanent(challenge.id)
            count += 1

        return count

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for MFA challenges."""
        return ["challenge_id"]
