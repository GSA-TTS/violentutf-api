"""Cache management with Redis integration and fallback support."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import redis.asyncio as redis
from redis.exceptions import ConnectionError as RedisConnectionError
from structlog.stdlib import get_logger

from app.core.config import settings

logger = get_logger(__name__)


class CacheManager:
    """Manages caching with Redis and fallback mechanisms."""

    def __init__(self, redis_url: Optional[str] = None):
        """Initialize cache manager."""
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis_client: Optional[redis.Redis] = None
        self._fallback_cache: Dict[str, Dict[str, Any]] = {}
        self._is_connected = False
        self._connection_failures = 0
        self._max_connection_failures = 3
        self._last_connection_attempt: Optional[datetime] = None
        self._connection_retry_delay = timedelta(seconds=30)

    async def connect(self) -> bool:
        """
        Connect to Redis with error handling.

        Returns:
            True if connected successfully
        """
        if not self.redis_url:
            logger.warning("Redis URL not configured, using in-memory fallback")
            return False

        # Check if we should retry connection
        if self._connection_failures >= self._max_connection_failures:
            if self._last_connection_attempt:
                time_since_last_attempt = datetime.now(timezone.utc) - self._last_connection_attempt
                if time_since_last_attempt < self._connection_retry_delay:
                    return False

        try:
            self._last_connection_attempt = datetime.now(timezone.utc)
            self._redis_client = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30,
            )

            # Test connection
            await self._redis_client.ping()

            self._is_connected = True
            self._connection_failures = 0
            logger.info("Redis connection established")
            return True

        except Exception as e:
            self._connection_failures += 1
            self._is_connected = False
            logger.error(
                "Redis connection failed",
                error=str(e),
                failures=self._connection_failures,
            )
            return False

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis_client:
            try:
                await self._redis_client.close()
            except Exception as e:
                logger.error("Error closing Redis connection", error=str(e))
            finally:
                self._redis_client = None
                self._is_connected = False

    async def get(self, key: str, default: Any = None, deserialize: bool = True) -> Any:
        """
        Get value from cache.

        Args:
            key: Cache key
            default: Default value if not found
            deserialize: Whether to deserialize JSON data

        Returns:
            Cached value or default
        """
        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                value = await self._redis_client.get(key)
                if value is not None:
                    if deserialize:
                        try:
                            # Try JSON first (value is bytes from Redis)
                            return json.loads(value.decode("utf-8"))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # For security, don't use pickle - return raw bytes
                            logger.warning(
                                "Cache value cannot be deserialized safely, returning raw bytes",
                                key=key,
                            )
                            return value
                    return value
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis get error", key=key, error=str(e))

        # Fall back to in-memory cache
        cache_entry = self._fallback_cache.get(key)
        if cache_entry:
            if cache_entry["expires_at"] and cache_entry["expires_at"] < datetime.now(timezone.utc):
                del self._fallback_cache[key]
                return default
            return cache_entry["value"]

        return default

    async def set(self, key: str, value: Any, ttl: Optional[int] = None, serialize: bool = True) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            serialize: Whether to serialize the value

        Returns:
            True if set successfully
        """
        if ttl is None:
            ttl = settings.CACHE_TTL

        # Serialize value if needed
        if serialize:
            try:
                # Use JSON for security - only allow JSON-serializable types
                serialized_value = json.dumps(value)
            except (TypeError, ValueError):
                # For security, don't pickle complex objects - raise error
                raise ValueError(
                    f"Cannot serialize complex object safely: {type(value)}. Use JSON-serializable types only."
                )
        else:
            serialized_value = value

        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                await self._redis_client.set(key, serialized_value, ex=ttl)

                # Also update fallback cache
                self._update_fallback_cache(key, value, ttl)
                return True

            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis set error", key=key, error=str(e))

        # Fall back to in-memory cache
        self._update_fallback_cache(key, value, ttl)
        return True

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if deleted successfully
        """
        deleted = False

        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                result = await self._redis_client.delete(key)
                deleted = result > 0
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis delete error", key=key, error=str(e))

        # Also delete from fallback cache
        if key in self._fallback_cache:
            del self._fallback_cache[key]
            deleted = True

        return deleted

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if key exists
        """
        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                count = await self._redis_client.exists(key)
                return bool(count > 0)
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis exists error", key=key, error=str(e))

        # Check fallback cache
        if key in self._fallback_cache:
            cache_entry = self._fallback_cache[key]
            if cache_entry["expires_at"] and cache_entry["expires_at"] < datetime.now(timezone.utc):
                del self._fallback_cache[key]
                return False
            return True

        return False

    async def get_many(self, keys: list[str]) -> Dict[str, Any]:
        """
        Get multiple values from cache.

        Args:
            keys: List of cache keys

        Returns:
            Dictionary of key-value pairs
        """
        result = {}

        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                values = await self._redis_client.mget(keys)
                for key, value in zip(keys, values):
                    if value is not None:
                        try:
                            result[key] = json.loads(value.decode("utf-8"))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # For security, don't use pickle - store raw bytes
                            result[key] = value
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis mget error", error=str(e))

        # Fill missing values from fallback cache
        for key in keys:
            if key not in result:
                value = await self.get(key)
                if value is not None:
                    result[key] = value

        return result

    async def set_many(self, mapping: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """
        Set multiple values in cache.

        Args:
            mapping: Dictionary of key-value pairs
            ttl: Time to live in seconds

        Returns:
            True if all set successfully
        """
        if ttl is None:
            ttl = settings.CACHE_TTL

        success = True

        # Serialize values
        serialized_mapping = {}
        for key, value in mapping.items():
            try:
                serialized_mapping[key] = json.dumps(value)
            except (TypeError, ValueError):
                # For security, don't pickle complex objects - raise error
                raise ValueError(
                    f"Cannot serialize complex object safely for key '{key}': {type(value)}. Use JSON-serializable types only."
                )

        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                # Use pipeline for atomic operation
                async with self._redis_client.pipeline() as pipe:
                    for key, value in serialized_mapping.items():
                        pipe.set(key, value, ex=ttl)
                    await pipe.execute()

                # Also update fallback cache
                for key, value in mapping.items():
                    self._update_fallback_cache(key, value, ttl)

            except RedisConnectionError:
                self._handle_connection_error()
                success = False
            except Exception as e:
                logger.error("Redis mset error", error=str(e))
                success = False
        else:
            success = False

        # Fall back to setting individually
        if not success:
            for key, value in mapping.items():
                await self.set(key, value, ttl)

        return True

    async def clear_pattern(self, pattern: str) -> int:
        """
        Clear all keys matching pattern.

        Args:
            pattern: Key pattern (e.g., "user:*")

        Returns:
            Number of keys deleted
        """
        count = 0

        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                # Use SCAN to avoid blocking
                cursor = 0
                while True:
                    cursor, keys = await self._redis_client.scan(cursor, match=pattern, count=100)
                    if keys:
                        count += await self._redis_client.delete(*keys)
                    if cursor == 0:
                        break
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis clear pattern error", pattern=pattern, error=str(e))

        # Clear from fallback cache
        keys_to_delete = [k for k in self._fallback_cache.keys() if self._match_pattern(k, pattern)]
        for key in keys_to_delete:
            del self._fallback_cache[key]
            count += 1

        return count

    async def get_ttl(self, key: str) -> Optional[int]:
        """
        Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            TTL in seconds or None if key doesn't exist
        """
        # Try Redis first
        if self._is_connected and self._redis_client:
            try:
                ttl = await self._redis_client.ttl(key)
                if ttl > 0:
                    return int(ttl)
            except RedisConnectionError:
                self._handle_connection_error()
            except Exception as e:
                logger.error("Redis ttl error", key=key, error=str(e))

        # Check fallback cache
        cache_entry = self._fallback_cache.get(key)
        if cache_entry and cache_entry["expires_at"]:
            remaining = (cache_entry["expires_at"] - datetime.now(timezone.utc)).total_seconds()
            if remaining > 0:
                return int(remaining)

        return None

    async def health_check(self) -> Dict[str, Any]:
        """
        Check cache health status.

        Returns:
            Health status dictionary
        """
        health: Dict[str, Any] = {
            "redis_connected": self._is_connected,
            "redis_url_configured": bool(self.redis_url),
            "fallback_cache_size": len(self._fallback_cache),
            "connection_failures": self._connection_failures,
        }

        # Test Redis connection
        if self._redis_client:
            try:
                start_time = datetime.now(timezone.utc)
                await self._redis_client.ping()
                response_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                health["redis_response_time_ms"] = response_time * 1000
                health["redis_available"] = True
            except Exception as e:
                health["redis_available"] = False
                health["redis_error"] = str(e)
        else:
            health["redis_available"] = False

        return health

    def _handle_connection_error(self) -> None:
        """Handle Redis connection error."""
        self._connection_failures += 1
        if self._connection_failures >= self._max_connection_failures:
            self._is_connected = False
            logger.error(
                "Redis connection lost, falling back to in-memory cache",
                failures=self._connection_failures,
            )

    def _update_fallback_cache(self, key: str, value: Any, ttl: int) -> None:
        """Update fallback cache with TTL."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl) if ttl > 0 else None
        self._fallback_cache[key] = {
            "value": value,
            "expires_at": expires_at,
        }

        # Implement simple LRU eviction if cache gets too large
        max_size = 10000  # Maximum number of entries
        if len(self._fallback_cache) > max_size:
            # Remove oldest entries
            sorted_keys = sorted(
                self._fallback_cache.keys(),
                key=lambda k: self._fallback_cache[k].get("expires_at", datetime.max),
            )
            for key in sorted_keys[: len(sorted_keys) // 10]:  # Remove 10%
                del self._fallback_cache[key]

    def _match_pattern(self, key: str, pattern: str) -> bool:
        """Simple pattern matching for fallback cache."""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)


# Global cache instance
_cache_manager: Optional[CacheManager] = None


async def get_cache() -> CacheManager:
    """Get global cache manager instance."""
    global _cache_manager

    if _cache_manager is None:
        _cache_manager = CacheManager()
        await _cache_manager.connect()

    return _cache_manager


async def close_cache() -> None:
    """Close cache connections."""
    global _cache_manager

    if _cache_manager:
        await _cache_manager.disconnect()
        _cache_manager = None
