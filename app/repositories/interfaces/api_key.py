"""API Key repository interface."""

import uuid
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Union

from app.models.api_key import APIKey

from .base import IBaseRepository


class IApiKeyRepository(IBaseRepository[APIKey]):
    """Interface for API key repository operations."""

    @abstractmethod
    async def get_by_key_hash(
        self, key_hash: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[APIKey]:
        """
        Get API key by key hash with optional organization filtering.

        Args:
            key_hash: Hashed API key
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            API key if found and active, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_name(
        self, name: str, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[APIKey]:
        """
        Get API key by name for a specific user.

        Args:
            name: API key name
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            API key if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_api_keys(
        self,
        user_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_inactive: bool = False,
    ) -> List[APIKey]:
        """
        Get all API keys for a user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering
            include_inactive: Whether to include inactive API keys

        Returns:
            List of user's API keys
        """
        raise NotImplementedError

    @abstractmethod
    async def get_active_api_keys(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[APIKey]:
        """
        Get all active API keys.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of active API keys
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_api_key(
        self,
        api_key_id: Union[str, uuid.UUID],
        revoked_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Revoke an API key.

        Args:
            api_key_id: API key ID
            revoked_by: User who revoked the API key
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if revocation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_all_user_api_keys(
        self,
        user_id: Union[str, uuid.UUID],
        revoked_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> int:
        """
        Revoke all API keys for a user.

        Args:
            user_id: User ID
            revoked_by: User who revoked the API keys
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of API keys revoked
        """
        raise NotImplementedError

    @abstractmethod
    async def update_last_used(
        self,
        api_key_id: Union[str, uuid.UUID],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update API key last used information.

        Args:
            api_key_id: API key ID
            ip_address: Optional IP address
            user_agent: Optional user agent
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_api_key_usage_stats(
        self, api_key_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Dict[str, Any]:
        """
        Get usage statistics for an API key.

        Args:
            api_key_id: API key ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Dictionary containing usage statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def search_api_keys(
        self,
        query: str,
        user_id: Optional[Union[str, uuid.UUID]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        limit: int = 20,
    ) -> List[APIKey]:
        """
        Search API keys by name or description.

        Args:
            query: Search query
            user_id: Optional user ID to filter by
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching API keys
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_expired_api_keys(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> int:
        """
        Clean up expired API keys.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of API keys cleaned up
        """
        raise NotImplementedError
