#!/usr/bin/env python3
"""
Safe Multi-Tier Cache Manager for Architectural Analysis

This is a JSON-based version of the cache manager that avoids pickle security issues.
It has some limitations compared to the pickle version:
- Can only cache JSON-serializable data
- May be slightly slower for complex objects
- Cannot cache arbitrary Python objects

For maximum security, use this version in production environments.
"""

import hashlib
import json
import logging
import os
import shutil
import threading
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import lz4.frame
import redis


@dataclass
class CacheEntry:
    """Represents a cached item"""

    key: str
    data: Any
    timestamp: str  # ISO format string
    size_bytes: int
    access_count: int = 0
    last_accessed: str = ""  # ISO format string
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.last_accessed:
            self.last_accessed = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "key": self.key,
            "data": self.data,
            "timestamp": self.timestamp,
            "size_bytes": self.size_bytes,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary"""
        return cls(**d)


class SafeMemoryCacheTier(ABC):
    """In-memory cache using JSON serialization"""

    def __init__(self, max_size_mb: int = 100, ttl_hours: int = 24):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.ttl = timedelta(hours=ttl_hours)
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.current_size = 0
        self.logger = logging.getLogger(f"SafeCacheTier.{self.__class__.__name__}")

    async def get(self, key: str) -> Optional[Any]:
        """Get item from memory cache"""
        with self.lock:
            if key not in self.cache:
                return None

            entry = self.cache[key]

            # Check expiration
            timestamp = datetime.fromisoformat(entry.timestamp)
            if datetime.now() - timestamp > self.ttl:
                del self.cache[key]
                self.current_size -= entry.size_bytes
                return None

            # Update LRU order
            self.cache.move_to_end(key)
            entry.access_count += 1
            entry.last_accessed = datetime.now().isoformat()

            return entry.data

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set item in memory cache"""
        try:
            # Serialize to JSON to ensure it's serializable
            serialized = json.dumps(value)
            size = len(serialized.encode("utf-8"))

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
                    key=key, data=value, timestamp=datetime.now().isoformat(), size_bytes=size, metadata=metadata or {}
                )

                # Remove old entry if exists
                if key in self.cache:
                    old_entry = self.cache[key]
                    self.current_size -= old_entry.size_bytes

                self.cache[key] = entry
                self.current_size += size

                return True

        except (TypeError, ValueError) as e:
            self.logger.error(f"Error serializing cache value: {e}")
            return False

    def _evict_lru(self) -> None:
        """Evict least recently used item"""
        if not self.cache:
            return

        # Get oldest item (first in OrderedDict)
        key, entry = self.cache.popitem(last=False)
        self.current_size -= entry.size_bytes
        self.logger.debug(f"Evicted {key} (size: {entry.size_bytes})")


class SafeDiskCacheTier(ABC):
    """Disk-based cache using JSON serialization"""

    def __init__(self, cache_dir: str = ".cache/analysis", max_size_mb: int = 1024, ttl_hours: int = 72):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.ttl = timedelta(hours=ttl_hours)
        self.index_file = self.cache_dir / "index.json"
        self.index = self._load_index()
        self.lock = threading.RLock()
        self.logger = logging.getLogger("SafeDiskCacheTier")

    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load cache index from disk"""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except Exception as e:
                self.logger.warning(f"Failed to load cache index, starting fresh: {e}")
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
        return self.cache_dir / subdir / f"{key}.json.lz4"

    async def get(self, key: str) -> Optional[Any]:
        """Get item from disk cache"""
        with self.lock:
            if key not in self.index:
                return None

            entry_info = self.index[key]

            # Check expiration
            timestamp = datetime.fromisoformat(entry_info["timestamp"])
            if datetime.now() - timestamp > self.ttl:
                await self.delete(key)
                return None

            cache_path = self._get_cache_path(key)
            if not cache_path.exists():
                # Index out of sync
                del self.index[key]
                self._save_index()
                return None

            try:
                # Read and decompress
                with open(cache_path, "rb") as f:
                    compressed = f.read()

                decompressed = lz4.frame.decompress(compressed)
                data = json.loads(decompressed.decode("utf-8"))

                # Update access info
                self.index[key]["access_count"] = entry_info.get("access_count", 0) + 1
                self.index[key]["last_accessed"] = datetime.now().isoformat()
                self._save_index()

                return data

            except Exception as e:
                self.logger.error(f"Error reading cache file {cache_path}: {e}")
                await self.delete(key)
                return None

    async def set(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Set item in disk cache"""
        try:
            # Serialize to JSON
            serialized = json.dumps(value)
            compressed = lz4.frame.compress(serialized.encode("utf-8"))
            size = len(compressed)

            # Check size limit
            if size > self.max_size_bytes:
                self.logger.warning(f"Item too large for disk cache: {size} bytes")
                return False

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

            return True

        except (TypeError, ValueError) as e:
            self.logger.error(f"Error serializing cache value: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error writing cache: {e}")
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
            except Exception:
                pass  # File deletion failures are non-critical

            # Update index
            del self.index[key]
            self._save_index()
            return True


class SafeMultiTierCacheManager:
    """Safe cache manager using JSON serialization instead of pickle"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger("SafeMultiTierCacheManager")

        # Initialize tiers
        self.tiers: List[Union[SafeMemoryCacheTier, SafeDiskCacheTier]] = []

        # Memory tier (always enabled)
        memory_config = self.config.get("memory", {})
        self.memory_tier = SafeMemoryCacheTier(
            max_size_mb=memory_config.get("max_size_mb", 100), ttl_hours=memory_config.get("ttl_hours", 24)
        )
        self.tiers.append(self.memory_tier)

        # Disk tier (optional)
        self.disk_tier: Optional[SafeDiskCacheTier]
        if self.config.get("disk", {}).get("enabled", True):
            disk_config = self.config.get("disk", {})
            self.disk_tier = SafeDiskCacheTier(
                cache_dir=disk_config.get("cache_dir", ".cache/analysis"),
                max_size_mb=disk_config.get("max_size_mb", 1024),
                ttl_hours=disk_config.get("ttl_hours", 72),
            )
            self.tiers.append(self.disk_tier)
        else:
            self.disk_tier = None

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

    def generate_key(self, *args: Any) -> str:
        """Generate cache key"""
        key_data = ":".join(str(arg) for arg in args)
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]


# For backward compatibility, create an alias
MultiTierCacheManager = SafeMultiTierCacheManager
