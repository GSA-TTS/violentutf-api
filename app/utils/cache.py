"""Redis cache client with health checks and connection management."""

import asyncio
from typing import TYPE_CHECKING, Any, Optional, Union

import redis.asyncio as redis
from structlog.stdlib import get_logger

from ..core.config import settings

RedisClient = redis.Redis[str]

logger = get_logger(__name__)

# Global Redis client
cache_client: Optional[RedisClient] = None


def create_cache_client() -> Optional[RedisClient]:
    """Create Redis cache client with connection pooling."""
    if not settings.REDIS_URL:
        logger.warning("No Redis URL configured - cache features disabled")
        return None

    try:
        # Create Redis client with connection pooling
        client: RedisClient = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
            retry_on_timeout=True,
            retry_on_error=[redis.ConnectionError, redis.TimeoutError],
            health_check_interval=30,
        )
        logger.info("Redis cache client created successfully")
        return client
    except Exception as e:
        logger.error("Failed to create Redis client", error=str(e))
        return None


def get_cache_client() -> Optional[RedisClient]:
    """Get or create the cache client."""
    global cache_client

    if cache_client is None:
        cache_client = create_cache_client()
        if cache_client:
            logger.info("Redis cache client initialized")

    return cache_client


async def check_cache_health(timeout: float = 5.0) -> bool:
    """
    Check Redis cache connectivity with timeout.

    Args:
        timeout: Maximum time to wait for Redis response

    Returns:
        True if cache is healthy, False otherwise
    """
    if not settings.REDIS_URL:
        logger.debug("Redis URL not configured - skipping cache health check")
        return True  # Cache is optional

    client = get_cache_client()
    if client is None:
        logger.error("Cache client not initialized")
        return False

    try:
        async with asyncio.timeout(timeout):
            # Test connectivity with ping
            pong = await client.ping()

            if pong:
                logger.debug("Cache health check passed")
                return True
            else:
                logger.error("Cache health check failed - no pong response")
                return False

    except asyncio.TimeoutError:
        logger.error("Cache health check timed out", timeout=timeout)
        return False
    except Exception as e:
        logger.error("Cache health check failed", error=str(e))
        return False


async def get_cached_value(key: str) -> Optional[str]:
    """
    Get value from cache.

    Args:
        key: Cache key

    Returns:
        Cached value or None if not found/error
    """
    client = get_cache_client()
    if client is None:
        return None

    try:
        value = await client.get(key)
        logger.debug("Cache get", key=key, found=value is not None)
        return str(value) if value is not None else None
    except Exception as e:
        logger.error("Cache get failed", key=key, error=str(e))
        return None


async def set_cached_value(key: str, value: Union[str, int, float], ttl: Optional[int] = None) -> bool:
    """
    Set value in cache.

    Args:
        key: Cache key
        value: Value to cache
        ttl: Time to live in seconds (uses settings.CACHE_TTL if None)

    Returns:
        True if successful, False otherwise
    """
    client = get_cache_client()
    if client is None:
        return False

    try:
        effective_ttl = ttl if ttl is not None else getattr(settings, "CACHE_TTL", 300)  # Default 5 minutes
        result = await client.setex(key, int(effective_ttl), str(value))
        logger.debug("Cache set", key=key, ttl=ttl, success=bool(result))
        return bool(result)
    except Exception as e:
        logger.error("Cache set failed", key=key, error=str(e))
        return False


async def delete_cached_value(key: str) -> bool:
    """
    Delete value from cache.

    Args:
        key: Cache key to delete

    Returns:
        True if successful, False otherwise
    """
    client = get_cache_client()
    if client is None:
        return False

    try:
        result = await client.delete(key)
        logger.debug("Cache delete", key=key, deleted_count=result)
        return bool(result > 0)
    except Exception as e:
        logger.error("Cache delete failed", key=key, error=str(e))
        return False


async def close_cache_connections() -> None:
    """Close cache connections for graceful shutdown."""
    global cache_client

    if cache_client is not None:
        logger.info("Closing cache connections")
        await cache_client.close()
        cache_client = None
        logger.info("Cache connections closed")
