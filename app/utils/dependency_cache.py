"""
Multi-level dependency caching system for PyTestArch performance optimization.

This module provides a three-tier caching strategy:
- L1: In-memory LRU cache for immediate reuse
- L2: File-based cache with TTL for persistence
- L3: Redis cache for distributed/CI environments

Implements ADR-015 caching strategy with security and performance optimizations.
"""

import asyncio
import hashlib
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass

# datetime import removed as not used directly
from pathlib import Path
from typing import Any, Dict, List, Optional

from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class PackageInfo:
    """Structured package information for caching."""

    name: str
    version: str
    license: Optional[str] = None
    summary: Optional[str] = None
    home_page: Optional[str] = None
    author: Optional[str] = None
    requires: Optional[List[str]] = None
    last_updated: Optional[str] = None
    cached_at: float = 0.0

    def __post_init__(self) -> None:
        """Initialize cached_at timestamp if not provided."""
        if self.cached_at == 0.0:
            self.cached_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PackageInfo":
        """Create instance from dictionary."""
        return cls(**data)

    def is_expired(self, ttl: int) -> bool:
        """Check if cached data is expired."""
        return time.time() - self.cached_at > ttl


@dataclass
class CacheStats:
    """Cache performance statistics."""

    hits: int = 0
    misses: int = 0
    memory_hits: int = 0
    file_hits: int = 0
    redis_hits: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate overall hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    @property
    def memory_hit_rate(self) -> float:
        """Calculate memory cache hit rate."""
        return self.memory_hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0.0


class FileCacheManager:
    """File-based caching with TTL and integrity checking."""

    def __init__(self, cache_dir: Path, max_cache_size_mb: int = 100):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_cache_size = max_cache_size_mb * 1024 * 1024  # Convert to bytes
        self._ensure_cache_permissions()

    def _ensure_cache_permissions(self) -> None:
        """Ensure cache directory has proper permissions for security."""
        try:
            # Restrict to owner only (700 permissions)
            os.chmod(self.cache_dir, 0o700)
        except OSError as e:
            logger.warning("Could not set cache directory permissions", error=str(e))

    def _get_cache_file_path(self, key: str) -> Path:
        """Get cache file path with secure naming."""
        # Use HMAC-SHA256 hash for secure, consistent file naming
        safe_key = self._hash_key_secure(key)
        return self.cache_dir / f"{safe_key}.json"

    def _hash_key_secure(self, key: str) -> str:
        """Generate secure hash for cache keys."""
        from app.core.security import hash_cache_key

        return hash_cache_key(key)

    def _calculate_directory_size(self) -> int:
        """Calculate total size of cache directory."""
        total_size = 0
        try:
            for file_path in self.cache_dir.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except OSError:
            pass
        return total_size

    def _cleanup_old_files(self, target_size_reduction: int) -> None:
        """Remove oldest files to reduce cache size."""
        try:
            # Get all cache files with their modification times
            files_with_mtime = []
            for file_path in self.cache_dir.glob("*.json"):
                try:
                    stat = file_path.stat()
                    files_with_mtime.append((file_path, stat.st_mtime, stat.st_size))
                except OSError:
                    continue

            # Sort by modification time (oldest first)
            files_with_mtime.sort(key=lambda x: x[1])

            # Remove oldest files until we've freed enough space
            freed_space = 0
            for file_path, _, size in files_with_mtime:
                if freed_space >= target_size_reduction:
                    break
                try:
                    # Windows-compatible file removal
                    import platform

                    if platform.system() == "Windows":
                        import time

                        for attempt in range(3):
                            try:
                                file_path.unlink()
                                break
                            except PermissionError:
                                if attempt < 2:
                                    time.sleep(0.1 * (2**attempt))
                                    continue
                                else:
                                    raise
                    else:
                        file_path.unlink()
                    freed_space += size
                    logger.debug("Removed old cache file", file=str(file_path))
                except OSError:
                    continue

        except Exception as e:
            logger.error("Error during cache cleanup", error=str(e))

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached value from file system."""
        file_path = self._get_cache_file_path(key)

        try:
            if not file_path.exists():
                return None

            # Check file permissions for security
            stat = file_path.stat()
            if stat.st_mode & 0o077:  # Check if group/other have any permissions
                logger.warning("Cache file has insecure permissions", file=str(file_path))
                return None

            with open(file_path, "r") as f:
                data = json.load(f)

            # Validate cache entry structure
            if not isinstance(data, dict) or "cached_at" not in data:
                logger.warning("Invalid cache entry structure", file=str(file_path))
                file_path.unlink(missing_ok=True)
                return None

            return data

        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Error reading cache file", file=str(file_path), error=str(e))
            # Remove corrupted file
            file_path.unlink(missing_ok=True)
            return None

    async def set(self, key: str, value: Dict[str, Any], ttl: int = 86400) -> bool:
        """Set cached value in file system with TTL."""
        file_path = self._get_cache_file_path(key)

        try:
            # Add caching metadata
            cache_entry = {
                **value,
                "cached_at": time.time(),
                "ttl": ttl,
                "key_hash": self._hash_key_secure(key),
            }

            # Check cache size before writing
            current_size = self._calculate_directory_size()
            estimated_entry_size = len(json.dumps(cache_entry).encode())

            if current_size + estimated_entry_size > self.max_cache_size:
                # Cleanup 25% of cache size
                self._cleanup_old_files(self.max_cache_size // 4)

            # Write to temporary file first for atomic operation
            temp_file = file_path.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                json.dump(cache_entry, f, indent=2)

            # Set secure permissions before moving
            os.chmod(temp_file, 0o600)  # Owner read/write only

            # Atomic move to final location
            temp_file.rename(file_path)

            return True

        except OSError as e:
            logger.error("Error writing cache file", file=str(file_path), error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """Delete cached value."""
        file_path = self._get_cache_file_path(key)
        try:
            file_path.unlink(missing_ok=True)
            return True
        except OSError as e:
            logger.error("Error deleting cache file", file=str(file_path), error=str(e))
            return False

    async def clear(self) -> bool:
        """Clear all cached values."""
        try:
            for file_path in self.cache_dir.glob("*.json"):
                file_path.unlink(missing_ok=True)
            return True
        except OSError as e:
            logger.error("Error clearing cache", error=str(e))
            return False


class DependencyCache:
    """Multi-level cache for dependency information with performance optimization."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl: int = 86400,
        memory_cache_size: int = 1000,
        enable_file_cache: bool = True,
    ):
        self.ttl = ttl
        self.enable_file_cache = enable_file_cache

        # L1: In-memory LRU cache
        self._memory_cache: Dict[str, PackageInfo] = {}
        self._memory_cache_access: Dict[str, float] = {}  # Track access times for LRU
        self.memory_cache_size = memory_cache_size

        # L2: File-based cache
        if cache_dir is None:
            cache_dir = Path(tempfile.gettempdir()) / "violentutf_dependency_cache"
        self.cache_dir = cache_dir
        self.file_cache = FileCacheManager(cache_dir) if enable_file_cache else None

        # Cache statistics
        self.stats = CacheStats()

        # Requirements hash for cache versioning
        self._requirements_hash = self._compute_requirements_hash()

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    def _compute_requirements_hash(self) -> str:
        """Compute secure hash of requirements files for cache versioning."""
        import hmac

        from app.core.config import get_settings

        settings = get_settings()
        secret_key = (
            settings.SECRET_KEY.get_secret_value()
            if hasattr(settings.SECRET_KEY, "get_secret_value")
            else str(settings.SECRET_KEY)
        )
        # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for dependency versioning, not sensitive data storage
        hasher = hmac.new(secret_key.encode(), b"", hashlib.sha256)

        # Find requirements files
        current_dir = Path.cwd()
        requirements_files: List[Path] = []

        for pattern in ["requirements*.txt", "pyproject.toml", "setup.py"]:
            requirements_files.extend(current_dir.glob(pattern))

        # Sort for consistent hashing
        requirements_files.sort()

        for req_file in requirements_files:
            try:
                hasher.update(req_file.name.encode())
                if req_file.exists():
                    hasher.update(req_file.read_bytes())
            except OSError:
                # If file is not readable, include just the name
                hasher.update(req_file.name.encode())

        return hasher.hexdigest()[:16]  # Use first 16 chars for cache key

    def _generate_cache_key(self, package_name: str) -> str:
        """Generate versioned cache key."""
        return f"dep_v1_{self._requirements_hash}_{package_name.lower()}"

    def _evict_lru_memory_cache(self) -> None:
        """Evict least recently used items from memory cache."""
        # Evict items if we're at or over the limit
        if len(self._memory_cache) < self.memory_cache_size:
            return

        # Sort by access time and remove oldest items to make room
        sorted_items = sorted(self._memory_cache_access.items(), key=lambda x: x[1])

        # Calculate how many items to evict - ensure we're under the limit
        items_to_evict = len(self._memory_cache) - self.memory_cache_size + 1
        evict_count = max(1, items_to_evict)

        for key, _ in sorted_items[:evict_count]:
            self._memory_cache.pop(key, None)
            self._memory_cache_access.pop(key, None)
            self.stats.evictions += 1

    async def get_package_info(self, package_name: str) -> Optional[PackageInfo]:
        """Get package information from cache with fallback chain."""
        cache_key = self._generate_cache_key(package_name)

        async with self._lock:
            # L1: Memory cache
            if cache_key in self._memory_cache:
                pkg_info = self._memory_cache[cache_key]
                if not pkg_info.is_expired(self.ttl):
                    self._memory_cache_access[cache_key] = time.time()
                    self.stats.hits += 1
                    self.stats.memory_hits += 1
                    return pkg_info
                else:
                    # Expired, remove from memory cache
                    del self._memory_cache[cache_key]
                    self._memory_cache_access.pop(cache_key, None)

            # L2: File cache
            if self.file_cache:
                cached_data = await self.file_cache.get(cache_key)
                if cached_data:
                    try:
                        # Filter out metadata fields added by file cache
                        package_data = {k: v for k, v in cached_data.items() if k not in ["ttl", "key_hash"]}
                        pkg_info = PackageInfo.from_dict(package_data)
                        if not pkg_info.is_expired(self.ttl):
                            # Promote to memory cache
                            self._evict_lru_memory_cache()
                            self._memory_cache[cache_key] = pkg_info
                            self._memory_cache_access[cache_key] = time.time()

                            self.stats.hits += 1
                            self.stats.file_hits += 1
                            return pkg_info
                    except (ValueError, TypeError) as e:
                        logger.warning(
                            "Invalid cached package data",
                            package=package_name,
                            error=str(e),
                        )
                        await self.file_cache.delete(cache_key)

            # Cache miss
            self.stats.misses += 1
            return None

    async def set_package_info(self, package_name: str, pkg_info: PackageInfo) -> bool:
        """Set package information in all cache levels."""
        cache_key = self._generate_cache_key(package_name)

        async with self._lock:
            # Update cached_at timestamp
            pkg_info.cached_at = time.time()

            # L1: Memory cache
            self._evict_lru_memory_cache()
            self._memory_cache[cache_key] = pkg_info
            self._memory_cache_access[cache_key] = time.time()

            # L2: File cache
            if self.file_cache:
                success = await self.file_cache.set(cache_key, pkg_info.to_dict(), self.ttl)
                if not success:
                    logger.warning("Failed to write to file cache", package=package_name)
                    return False

            return True

    async def bulk_get_package_info(self, package_names: List[str]) -> Dict[str, PackageInfo]:
        """Get multiple package information entries efficiently."""
        results = {}

        # Process in batches to avoid holding lock too long
        batch_size = 50
        for i in range(0, len(package_names), batch_size):
            batch = package_names[i : i + batch_size]

            for package_name in batch:
                pkg_info = await self.get_package_info(package_name)
                if pkg_info:
                    results[package_name] = pkg_info

        return results

    async def invalidate_package(self, package_name: str) -> bool:
        """Invalidate cached package information."""
        cache_key = self._generate_cache_key(package_name)

        async with self._lock:
            # Remove from memory cache
            self._memory_cache.pop(cache_key, None)
            self._memory_cache_access.pop(cache_key, None)

            # Remove from file cache
            if self.file_cache:
                await self.file_cache.delete(cache_key)

        return True

    async def clear_cache(self) -> bool:
        """Clear all cached data."""
        async with self._lock:
            # Clear memory cache
            self._memory_cache.clear()
            self._memory_cache_access.clear()

            # Clear file cache
            if self.file_cache:
                await self.file_cache.clear()

            # Reset statistics
            self.stats = CacheStats()

        return True

    def get_cache_stats(self) -> CacheStats:
        """Get current cache statistics."""
        return self.stats

    def reset_cache_stats(self) -> None:
        """Reset cache statistics for clean measurement."""
        self.stats = CacheStats()

    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check."""
        health = {
            "memory_cache_size": len(self._memory_cache),
            "memory_cache_limit": self.memory_cache_size,
            "file_cache_enabled": self.file_cache is not None,
            "requirements_hash": self._requirements_hash,
            "cache_stats": asdict(self.stats),
            "ttl_seconds": self.ttl,
        }

        if self.file_cache:
            try:
                cache_dir_size = self.file_cache._calculate_directory_size()
                health["file_cache_size_bytes"] = cache_dir_size
                health["file_cache_size_mb"] = round(cache_dir_size / 1024 / 1024, 2)
                health["cache_directory"] = str(self.cache_dir)
                health["cache_directory_exists"] = self.cache_dir.exists()
            except Exception as e:
                health["file_cache_error"] = str(e)

        return health


# Global cache instance
_dependency_cache: Optional[DependencyCache] = None


def get_dependency_cache(
    cache_dir: Optional[Path] = None, ttl: int = 86400, memory_cache_size: int = 1000
) -> DependencyCache:
    """Get global dependency cache instance."""
    global _dependency_cache

    if _dependency_cache is None:
        _dependency_cache = DependencyCache(cache_dir=cache_dir, ttl=ttl, memory_cache_size=memory_cache_size)

    return _dependency_cache


async def close_dependency_cache() -> None:
    """Close and cleanup dependency cache."""
    global _dependency_cache

    if _dependency_cache is not None:
        await _dependency_cache.clear_cache()
        _dependency_cache = None
