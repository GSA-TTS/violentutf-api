"""Cache service interface for dependency injection."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ICacheService(ABC):
    """Abstract interface for cache services."""

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check.

        Returns:
            Health check result dictionary
        """
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value if found, None otherwise
        """
        pass

    @abstractmethod
    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
    ) -> bool:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            expire: Expiration time in seconds

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if successful, False otherwise
        """
        pass
