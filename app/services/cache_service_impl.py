"""
Cache service implementation for dependency injection.

This service implements cache interfaces while wrapping the existing
cache infrastructure to maintain Clean Architecture compliance.
"""

from typing import Any, Dict, Optional

from structlog.stdlib import get_logger

from app.core.cache import close_cache, get_cache
from app.core.interfaces.cache_interface import ICacheService

logger = get_logger(__name__)


class CacheServiceImpl(ICacheService):
    """Cache service implementation using existing cache infrastructure."""

    def __init__(self):
        """Initialize cache service."""
        self._cache = None

    async def _get_cache(self):
        """Get cache instance lazily."""
        if self._cache is None:
            self._cache = await get_cache()
        return self._cache

    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check.

        Returns:
            Health check result dictionary
        """
        try:
            cache = await self._get_cache()
            return await cache.health_check()
        except Exception as e:
            logger.error("Cache health check failed", error=str(e))
            return {
                "redis_available": False,
                "error": str(e),
                "redis_url_configured": False,
            }

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value if found, None otherwise
        """
        try:
            cache = await self._get_cache()
            return await cache.get(key)
        except Exception as e:
            logger.error("Cache get failed", key=key, error=str(e))
            return None

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
        try:
            cache = await self._get_cache()
            await cache.set(key, value, expire=expire)
            return True
        except Exception as e:
            logger.error("Cache set failed", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if successful, False otherwise
        """
        try:
            cache = await self._get_cache()
            await cache.delete(key)
            return True
        except Exception as e:
            logger.error("Cache delete failed", key=key, error=str(e))
            return False

    async def close(self) -> None:
        """Close cache connections."""
        try:
            await close_cache()
        except Exception as e:
            logger.error("Cache close failed", error=str(e))
