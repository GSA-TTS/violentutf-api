"""API Key repository interface contract."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from ...models.api_key import APIKey


class IApiKeyRepository(ABC):
    """Interface contract for API key repository operations."""

    @abstractmethod
    async def get_by_key_hash(self, key_hash: str) -> Optional[APIKey]:
        """Get API key by key hash."""
        pass

    @abstractmethod
    async def get_user_api_keys(self, user_id: str, include_inactive: bool = False) -> List[APIKey]:
        """Get all API keys for a user."""
        pass

    @abstractmethod
    async def create_api_key(
        self,
        user_id: str,
        name: str,
        key_hash: str,
        expires_at: Optional[datetime] = None,
        scopes: Optional[List[str]] = None,
        created_by: str = "system",
    ) -> APIKey:
        """Create a new API key."""
        pass

    @abstractmethod
    async def revoke_api_key(self, key_id: str, revoked_by: str = "system") -> bool:
        """Revoke an API key."""
        pass

    @abstractmethod
    async def revoke_user_api_keys(self, user_id: str, revoked_by: str = "system") -> int:
        """Revoke all API keys for a user."""
        pass

    @abstractmethod
    async def update_last_used(self, key_id: str, ip_address: Optional[str] = None) -> bool:
        """Update the last used timestamp for an API key."""
        pass

    @abstractmethod
    async def get_expired_api_keys(self) -> List[APIKey]:
        """Get all expired API keys."""
        pass

    @abstractmethod
    async def cleanup_expired_api_keys(self) -> int:
        """Clean up expired API keys."""
        pass

    @abstractmethod
    async def rotate_api_key(
        self,
        key_id: str,
        new_key_hash: str,
        rotated_by: str = "system",
    ) -> Optional[APIKey]:
        """Rotate an API key with a new hash."""
        pass

    @abstractmethod
    async def get_api_key_usage_stats(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get API key usage statistics."""
        pass
