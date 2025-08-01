"""Simple API Key Service that matches the test interface."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.models.api_key import APIKey
from app.models.user import User
from app.repositories.api_key import APIKeyRepository


class APIKeyService:
    """Simple API key service matching test interface."""

    KEY_PREFIX = "vutf_"

    def __init__(self, session: AsyncSession) -> None:
        """Initialize API key service."""
        self.session = session
        self.repository = APIKeyRepository(session)

    def _generate_secure_key(self, length: int = 32) -> str:
        """Generate a secure API key."""
        return self.KEY_PREFIX + secrets.token_urlsafe(length)

    def _hash_key(self, key: str) -> str:
        """Hash an API key."""
        return hashlib.sha256(key.encode()).hexdigest()

    async def create_api_key(
        self,
        user_id: str,
        name: str,
        scopes: List[str],
        expires_in_days: Optional[int] = None,
    ) -> Tuple[APIKey, str]:
        """Create a new API key."""
        # Validate inputs
        if not name or len(name) < 2:
            raise ValidationError("API key name must be at least 2 characters")
        if len(name) > 255:
            raise ValidationError("API key name cannot exceed 255 characters")
        if not scopes:
            raise ValidationError("At least one scope is required")

        # Generate key
        plain_key = self._generate_secure_key()
        key_hash = self._hash_key(plain_key)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        # Convert scopes list to permissions dict
        permissions = {scope: True for scope in scopes}

        # Create API key
        api_key = APIKey(
            user_id=uuid.UUID(user_id) if isinstance(user_id, str) else user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=plain_key[:10],  # Use first 10 chars as prefix
            permissions=permissions,
            expires_at=expires_at,
        )

        self.session.add(api_key)
        await self.session.flush()

        return api_key, plain_key

    async def validate_api_key(self, plain_key: str) -> Tuple[APIKey, User]:
        """Validate an API key."""
        key_hash = self._hash_key(plain_key)

        api_key = await self.repository.get_by_hash(key_hash)
        if not api_key:
            raise AuthenticationError("Invalid API key")

        if not api_key.is_active():
            raise AuthenticationError("API key is not active")

        if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
            raise AuthenticationError("API key has expired")

        if not api_key.user or not api_key.user.is_active:
            raise AuthenticationError("User account is not active")

        # Update last used
        api_key.last_used_at = datetime.now(timezone.utc)
        await self.session.flush()

        return api_key, api_key.user

    async def rotate_api_key(self, api_key_id: str) -> Tuple[APIKey, str]:
        """Rotate an API key."""
        api_key = await self.repository.get(api_key_id)
        if not api_key:
            raise NotFoundError("API key not found")

        # Deactivate old key
        api_key.is_deleted = True

        # Convert permissions dict back to scopes list for compatibility
        scopes = [k for k, v in api_key.permissions.items() if v]

        # Create new key
        new_api_key, plain_key = await self.create_api_key(
            user_id=str(api_key.user_id),
            name=f"{api_key.name} (Rotated)",
            scopes=scopes,
            expires_in_days=30 if api_key.expires_at else None,
        )

        await self.session.flush()
        return new_api_key, plain_key

    async def revoke_api_key(self, api_key_id: str) -> bool:
        """Revoke an API key."""
        api_key = await self.repository.get(api_key_id)
        if not api_key:
            raise NotFoundError("API key not found")

        if not api_key.is_active():
            return False

        api_key.is_deleted = True
        api_key.revoked_at = datetime.now(timezone.utc)
        await self.session.flush()

        return True

    async def list_user_api_keys(self, user_id: str, include_revoked: bool = False) -> List[APIKey]:
        """List user's API keys."""
        keys = await self.repository.list_user_keys(user_id)

        if not include_revoked:
            keys = [k for k in keys if k.is_active()]

        return keys

    def check_api_key_permissions(self, api_key: APIKey, required_permissions: List[str]) -> bool:
        """Check if API key has required permissions."""
        for required in required_permissions:
            # Check for exact match
            if api_key.permissions.get(required, False):
                continue

            # Check for wildcard
            resource = required.split(":")[0]
            if api_key.permissions.get(f"{resource}:*", False):
                continue

            # Check for admin wildcard
            if api_key.permissions.get("admin:*", False) or api_key.permissions.get("*", False):
                continue

            return False

        return True

    async def cleanup_expired_keys(self) -> int:
        """Cleanup expired API keys."""
        expired_keys = await self.repository.get_expired_keys()

        count = 0
        for key in expired_keys:
            if key.is_active():
                key.is_deleted = True
                count += 1

        await self.session.flush()
        return count
