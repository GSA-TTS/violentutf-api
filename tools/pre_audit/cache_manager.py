#!/usr/bin/env python3
"""
Multi-Tier Cache Manager for Architectural Analysis

Implements a sophisticated caching system with multiple tiers:
- Memory (fastest): LRU cache for immediate access
- Disk (persistent): File-based cache with TTL
- Remote (shared): Redis cache for team collaboration (optional)

Security Note: This module uses pickle for serialization which can execute arbitrary
code during deserialization. Only use with trusted data sources. For production
deployments with untrusted data, consider using JSON or other safe serialization formats.
"""

import asyncio
import hashlib
import json
import logging
import os
import pickle
import shutil
import threading
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import lz4.frame
import redis


@dataclass
class CacheEntry:
    """Represents a cached item"""

    key: str
    data: Any
    timestamp: datetime
    size_bytes: int
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheStats:
    """Cache performance statistics"""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_size_bytes: int = 0
    entries_count: int = 0
    tier_name: str = ""

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


class CacheTier(ABC):
    """Abstract base class for cache tiers"""

    def __init__(self, max_size_mb: int, ttl_hours: int):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.ttl = timedelta(hours=ttl_hours)
        self.stats = CacheStats()
        self.logger = logging.getLogger(f"CacheTier.{self.__class__.__name__}")

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Retrieve item from cache"""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Store item in cache"""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Remove item from cache"""
        pass

    @abstractmethod
    async def clear(self) -> int:
        """Clear all items from cache"""
        pass

    @abstractmethod
    async def get_size(self) -> int:
        """Get current cache size in bytes"""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        pass

    def is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired"""
        return datetime.now() - entry.timestamp > self.ttl

    def generate_key(self, *args: Any) -> str:
        """Generate cache key from arguments"""
        key_data = ":".join(str(arg) for arg in args)
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]


class MemoryCacheTier(CacheTier):
    """In-memory LRU cache tier"""

    def __init__(self, max_size_mb: int = 100, ttl_hours: int = 24):
        super().__init__(max_size_mb, ttl_hours)
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.current_size = 0

    async def get(self, key: str) -> Optional[Any]:
        """Get item from memory cache"""
        with self.lock:
            if key not in self.cache:
                self.stats.misses += 1
                return None

            entry = self.cache[key]

            # Check expiration
            if self.is_expired(entry):
                del self.cache[key]
                self.current_size -= entry.size_bytes
                self.stats.misses += 1
                return None

            # Update LRU order
            self.cache.move_to_end(key)
            entry.access_count += 1
            entry.last_accessed = datetime.now()

            self.stats.hits += 1
            return entry.data

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set item in memory cache"""
        try:
            # Serialize to get size
            serialized = pickle.dumps(value)  # nosec B301 - see security note in module docstring
            size = len(serialized)

            # Check if item fits
            if size > self.max_size_bytes:
                self.logger.warning(f"Item too large for cache: {size} bytes")
                return False

            with self.lock:
                # Evict items if necessary
                while self.current_size + size > self.max_size_bytes and self.cache:
                    self._evict_lru()

                # Add/update entry
                entry = CacheEntry(
                    key=key, data=value, timestamp=datetime.now(), size_bytes=size, metadata=metadata or {}
                )

                # Remove old entry if exists
                if key in self.cache:
                    old_entry = self.cache[key]
                    self.current_size -= old_entry.size_bytes

                self.cache[key] = entry
                self.current_size += size
                self.stats.entries_count = len(self.cache)
                self.stats.total_size_bytes = self.current_size

                return True

        except Exception as e:
            self.logger.error(f"Error setting cache: {e}")
            return False

    def _evict_lru(self) -> None:
        """Evict least recently used item"""
        if not self.cache:
            return

        # Get oldest item (first in OrderedDict)
        key, entry = self.cache.popitem(last=False)
        self.current_size -= entry.size_bytes
        self.stats.evictions += 1
        self.logger.debug(f"Evicted {key} (size: {entry.size_bytes})")

    async def delete(self, key: str) -> bool:
        """Delete item from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                del self.cache[key]
                self.current_size -= entry.size_bytes
                return True
        return False

    async def clear(self) -> int:
        """Clear all items"""
        with self.lock:
            count = len(self.cache)
            self.cache.clear()
            self.current_size = 0
            self.stats.entries_count = 0
            self.stats.total_size_bytes = 0
            return count

    async def get_size(self) -> int:
        """Get current cache size"""
        return self.current_size

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        with self.lock:
            return key in self.cache and not self.is_expired(self.cache[key])


class DiskCacheTier(CacheTier):
    """Persistent disk-based cache tier"""

    def __init__(self, cache_dir: str = ".cache/analysis", max_size_mb: int = 1024, ttl_hours: int = 72):
        super().__init__(max_size_mb, ttl_hours)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.cache_dir / "index.json"
        self.index = self._load_index()
        self.lock = threading.RLock()

    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load cache index from disk"""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except:
                self.logger.warning("Failed to load cache index, starting fresh")
        return {}

    def _save_index(self) -> None:
        """Save cache index to disk"""
        try:
            with open(self.index_file, "w") as f:
                json.dump(self.index, f)
        except Exception as e:
            self.logger.error(f"Failed to save cache index: {e}")

    def _get_cache_path(self, key: str) -> Path:
        """Get file path for cache key"""
        # Validate key to prevent path traversal
        if ".." in key or "/" in key or "\\" in key:
            raise ValueError(f"Invalid cache key: {key}")

        # Use subdirectories to avoid too many files in one directory
        subdir = key[:2]
        return self.cache_dir / subdir / f"{key}.lz4"

    async def get(self, key: str) -> Optional[Any]:
        """Get item from disk cache"""
        with self.lock:
            if key not in self.index:
                self.stats.misses += 1
                return None

            entry_info = self.index[key]

            # Check expiration
            timestamp = datetime.fromisoformat(entry_info["timestamp"])
            if datetime.now() - timestamp > self.ttl:
                await self.delete(key)
                self.stats.misses += 1
                return None

            cache_path = self._get_cache_path(key)
            if not cache_path.exists():
                # Index out of sync
                del self.index[key]
                self._save_index()
                self.stats.misses += 1
                return None

            try:
                # Read and decompress
                with open(cache_path, "rb") as f:
                    compressed = f.read()

                decompressed = lz4.frame.decompress(compressed)
                data = pickle.loads(decompressed)  # nosec B301 - see security note in module docstring

                # Update access info
                self.index[key]["access_count"] = entry_info.get("access_count", 0) + 1
                self.index[key]["last_accessed"] = datetime.now().isoformat()
                self._save_index()

                self.stats.hits += 1
                return data

            except Exception as e:
                self.logger.error(f"Error reading cache file {cache_path}: {e}")
                await self.delete(key)
                self.stats.misses += 1
                return None

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set item in disk cache"""
        try:
            # Serialize and compress
            serialized = pickle.dumps(value)  # nosec B301 - see security note in module docstring
            compressed = lz4.frame.compress(serialized)
            size = len(compressed)

            # Check size limit
            if size > self.max_size_bytes:
                self.logger.warning(f"Item too large for disk cache: {size} bytes")
                return False

            # Check total cache size and evict if necessary
            current_size = await self.get_size()
            while current_size + size > self.max_size_bytes:
                if not await self._evict_oldest():
                    break
                current_size = await self.get_size()

            # Write to disk
            cache_path = self._get_cache_path(key)
            cache_path.parent.mkdir(exist_ok=True)

            with open(cache_path, "wb") as f:
                f.write(compressed)

            # Update index
            with self.lock:
                self.index[key] = {
                    "timestamp": datetime.now().isoformat(),
                    "size": size,
                    "access_count": 0,
                    "last_accessed": datetime.now().isoformat(),
                    "metadata": metadata or {},
                }
                self._save_index()

            self.stats.entries_count = len(self.index)
            return True

        except Exception as e:
            self.logger.error(f"Error writing cache: {e}")
            return False

    async def _evict_oldest(self) -> bool:
        """Evict oldest entry"""
        with self.lock:
            if not self.index:
                return False

            # Find oldest entry
            oldest_key = None
            oldest_time = datetime.now()

            for key, info in self.index.items():
                timestamp = datetime.fromisoformat(info["timestamp"])
                if timestamp < oldest_time:
                    oldest_time = timestamp
                    oldest_key = key

            if oldest_key:
                await self.delete(oldest_key)
                self.stats.evictions += 1
                return True

            return False

    async def delete(self, key: str) -> bool:
        """Delete item from cache"""
        with self.lock:
            if key not in self.index:
                return False

            # Remove file
            cache_path = self._get_cache_path(key)
            try:
                if cache_path.exists():
                    cache_path.unlink()
            except:
                pass

            # Update index
            del self.index[key]
            self._save_index()
            return True

    async def clear(self) -> int:
        """Clear all cache files"""
        count = 0

        # Remove all cache files
        for subdir in self.cache_dir.iterdir():
            if subdir.is_dir() and subdir.name != "index.json":
                shutil.rmtree(subdir)

        with self.lock:
            count = len(self.index)
            self.index.clear()
            self._save_index()

        return count

    async def get_size(self) -> int:
        """Calculate total cache size"""
        total_size = 0
        with self.lock:
            for info in self.index.values():
                total_size += info.get("size", 0)
        return total_size

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        with self.lock:
            if key not in self.index:
                return False

            # Check expiration
            timestamp = datetime.fromisoformat(self.index[key]["timestamp"])
            return datetime.now() - timestamp <= self.ttl


class RedisCacheTier(CacheTier):
    """Remote Redis cache tier for team sharing"""

    def __init__(self, redis_url: str = "redis://localhost:6379", max_size_mb: int = 2048, ttl_hours: int = 168):
        super().__init__(max_size_mb, ttl_hours)
        self.redis_url = redis_url
        self.prefix = "arch_analysis:"
        self.redis_client: Optional[Any] = None  # redis.Redis with proper typing requires redis-stubs
        self._connect()

    def _connect(self) -> None:
        """Connect to Redis"""
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=False)
            self.redis_client.ping()
            self.logger.info("Connected to Redis cache")
        except Exception as e:
            self.logger.warning(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    async def get(self, key: str) -> Optional[Any]:
        """Get from Redis"""
        if not self.redis_client:
            return None

        full_key = f"{self.prefix}{key}"

        try:
            data = self.redis_client.get(full_key)
            if data:
                self.stats.hits += 1
                return pickle.loads(lz4.frame.decompress(data))  # nosec B301 - see security note in module docstring
            else:
                self.stats.misses += 1
                return None
        except Exception as e:
            self.logger.error(f"Redis get error: {e}")
            self.stats.misses += 1
            return None

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set in Redis"""
        if not self.redis_client:
            return False

        full_key = f"{self.prefix}{key}"

        try:
            # Serialize and compress
            serialized = pickle.dumps(value)  # nosec B301 - see security note in module docstring
            compressed = lz4.frame.compress(serialized)

            # Set with TTL
            self.redis_client.setex(full_key, int(self.ttl.total_seconds()), compressed)

            return True

        except Exception as e:
            self.logger.error(f"Redis set error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete from Redis"""
        if not self.redis_client:
            return False

        full_key = f"{self.prefix}{key}"

        try:
            return bool(self.redis_client.delete(full_key))
        except Exception as e:
            self.logger.error(f"Redis delete error: {e}")
            return False

    async def clear(self) -> int:
        """Clear all cache entries"""
        if not self.redis_client:
            return 0

        try:
            keys = self.redis_client.keys(f"{self.prefix}*")
            if keys:
                deleted = self.redis_client.delete(*keys)
                return int(deleted) if deleted is not None else 0
            return 0
        except Exception as e:
            self.logger.error(f"Redis clear error: {e}")
            return 0

    async def get_size(self) -> int:
        """Get approximate cache size"""
        if not self.redis_client:
            return 0

        try:
            # This is approximate
            info = self.redis_client.info("memory")
            used_memory = info.get("used_memory", 0) if isinstance(info, dict) else 0
            return int(used_memory)
        except:
            return 0

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self.redis_client:
            return False

        full_key = f"{self.prefix}{key}"

        try:
            return bool(self.redis_client.exists(full_key))
        except:
            return False


class MultiTierCacheManager:
    """Manages multiple cache tiers with waterfall lookup"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger("MultiTierCacheManager")

        # Initialize tiers
        self.tiers: List[CacheTier] = []

        # Memory tier (always enabled)
        memory_config = self.config.get("memory", {})
        self.memory_tier = MemoryCacheTier(
            max_size_mb=memory_config.get("max_size_mb", 100), ttl_hours=memory_config.get("ttl_hours", 24)
        )
        self.tiers.append(self.memory_tier)

        # Disk tier (optional)
        self.disk_tier: Optional[DiskCacheTier]
        if self.config.get("disk", {}).get("enabled", True):
            disk_config = self.config.get("disk", {})
            self.disk_tier = DiskCacheTier(
                cache_dir=disk_config.get("cache_dir", ".cache/analysis"),
                max_size_mb=disk_config.get("max_size_mb", 1024),
                ttl_hours=disk_config.get("ttl_hours", 72),
            )
            self.tiers.append(self.disk_tier)
        else:
            self.disk_tier = None

        # Redis tier (optional)
        self.redis_tier: Optional[RedisCacheTier]
        redis_config = self.config.get("redis", {})
        if redis_config.get("enabled", False) and redis_config.get("url"):
            try:
                self.redis_tier = RedisCacheTier(
                    redis_url=redis_config["url"],
                    max_size_mb=redis_config.get("max_size_mb", 2048),
                    ttl_hours=redis_config.get("ttl_hours", 168),
                )
                self.tiers.append(self.redis_tier)
            except:
                self.logger.warning("Failed to initialize Redis tier")
                self.redis_tier = None
        else:
            self.redis_tier = None

    async def get(self, key: str) -> Optional[Any]:
        """Get from cache with waterfall lookup"""
        # Try each tier in order
        for i, tier in enumerate(self.tiers):
            result = await tier.get(key)
            if result is not None:
                # Promote to faster tiers
                for j in range(i):
                    await self.tiers[j].set(key, result)
                return result

        return None

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set in all applicable tiers"""
        success = False

        for tier in self.tiers:
            if await tier.set(key, value, metadata):
                success = True

        return success

    async def delete(self, key: str) -> bool:
        """Delete from all tiers"""
        success = False

        for tier in self.tiers:
            if await tier.delete(key):
                success = True

        return success

    async def clear(self) -> int:
        """Clear all tiers"""
        total_cleared = 0

        for tier in self.tiers:
            total_cleared += await tier.clear()

        return total_cleared

    def get_stats(self) -> Dict[str, CacheStats]:
        """Get statistics from all tiers"""
        stats = {}

        for tier in self.tiers:
            tier_name = tier.__class__.__name__
            tier.stats.tier_name = tier_name
            stats[tier_name] = tier.stats

        return stats

    def generate_key(self, *args: Any) -> str:
        """Generate cache key"""
        return self.memory_tier.generate_key(*args)

    async def analyze_file_with_cache(self, file_path: str, analyzer_func: Any) -> Any:
        """Analyze file with caching"""
        # Generate cache key based on file path and content hash
        file_hash = self._get_file_hash(file_path)
        cache_key = self.generate_key("file_analysis", file_path, file_hash)

        # Try cache first
        cached_result = await self.get(cache_key)
        if cached_result:
            self.logger.debug(f"Cache hit for {file_path}")
            return cached_result

        # Analyze file
        self.logger.debug(f"Cache miss for {file_path}, analyzing...")
        result = await analyzer_func(file_path)

        # Cache result
        metadata = {"file_path": file_path, "file_hash": file_hash, "timestamp": datetime.now().isoformat()}
        await self.set(cache_key, result, metadata)

        return result

    def _get_file_hash(self, file_path: str) -> str:
        """Get hash of file content"""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except:
            return "unknown"


# Example usage
async def main() -> None:
    """Example usage of cache manager"""
    import asyncio

    # Configure cache
    config = {
        "memory": {"max_size_mb": 50, "ttl_hours": 24},
        "disk": {"enabled": True, "max_size_mb": 500, "ttl_hours": 72},
        "redis": {"enabled": False},  # Set to True and add URL to enable
    }

    cache = MultiTierCacheManager(config)

    # Example: Cache analysis results
    test_data = {"violations": [1, 2, 3], "score": 85.5}
    key = cache.generate_key("analysis", "file.py", "v1")

    # Set in cache
    await cache.set(key, test_data)

    # Get from cache
    retrieved = await cache.get(key)
    print(f"Retrieved: {retrieved}")

    # Get stats
    stats = cache.get_stats()
    for tier_name, tier_stats in stats.items():
        print(f"{tier_name}: Hit rate={tier_stats.hit_rate:.1%}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
