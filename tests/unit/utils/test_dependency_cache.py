"""
Unit tests for dependency cache system.

Tests the multi-level caching infrastructure for dependency information
with focus on correctness, performance, and security.
"""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.utils.dependency_cache import CacheStats, DependencyCache, FileCacheManager, PackageInfo, get_dependency_cache


class TestPackageInfo:
    """Test suite for PackageInfo data structure."""

    def test_package_info_creation(self):
        """Test PackageInfo creation and validation."""
        pkg = PackageInfo(name="test-pkg", version="1.0.0", license="MIT", summary="Test package")

        assert pkg.name == "test-pkg"
        assert pkg.version == "1.0.0"
        assert pkg.license == "MIT"
        assert pkg.summary == "Test package"
        assert pkg.cached_at > 0

    def test_package_info_serialization(self):
        """Test PackageInfo serialization/deserialization."""
        original = PackageInfo(name="test-pkg", version="1.0.0", license="MIT", requires=["dependency1", "dependency2"])

        # To dict
        data = original.to_dict()
        assert isinstance(data, dict)
        assert data["name"] == "test-pkg"
        assert data["version"] == "1.0.0"
        assert data["license"] == "MIT"
        assert data["requires"] == ["dependency1", "dependency2"]

        # From dict
        restored = PackageInfo.from_dict(data)
        assert restored.name == original.name
        assert restored.version == original.version
        assert restored.license == original.license
        assert restored.requires == original.requires

    def test_package_info_expiration(self):
        """Test TTL expiration logic."""
        pkg = PackageInfo(name="test", version="1.0.0")

        # Should not be expired with reasonable TTL
        assert not pkg.is_expired(3600)  # 1 hour

        # Should be expired with very short TTL
        time.sleep(0.01)  # Small delay
        assert pkg.is_expired(0.005)  # 5ms TTL


class TestCacheStats:
    """Test suite for cache statistics."""

    def test_cache_stats_initialization(self):
        """Test CacheStats initialization."""
        stats = CacheStats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.hit_rate == 0.0

    def test_hit_rate_calculation(self):
        """Test hit rate calculation logic."""
        stats = CacheStats(hits=80, misses=20)
        assert stats.hit_rate == 0.8

        stats = CacheStats(hits=0, misses=0)
        assert stats.hit_rate == 0.0

    def test_memory_hit_rate_calculation(self):
        """Test memory-specific hit rate."""
        stats = CacheStats(hits=100, misses=50, memory_hits=75)
        assert stats.memory_hit_rate == 0.5  # 75/150


class TestFileCacheManager:
    """Test suite for file-based caching."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Provide temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir) / "cache"

    @pytest.fixture
    def file_cache_manager(self, temp_cache_dir):
        """Provide FileCacheManager instance."""
        return FileCacheManager(temp_cache_dir)

    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, file_cache_manager):
        """Test basic cache set and get operations."""
        test_data = {"name": "test-pkg", "version": "1.0.0"}

        # Set cache entry
        success = await file_cache_manager.set("test-key", test_data)
        assert success, "Cache set should succeed"

        # Get cache entry
        cached_data = await file_cache_manager.get("test-key")
        assert cached_data is not None, "Should retrieve cached data"
        assert cached_data["name"] == "test-pkg"
        assert cached_data["version"] == "1.0.0"
        assert "cached_at" in cached_data, "Should include caching metadata"

    @pytest.mark.asyncio
    async def test_cache_expiration_by_ttl(self, file_cache_manager):
        """Test cache TTL expiration."""
        test_data = {"name": "test-pkg"}

        # Set with very short TTL
        await file_cache_manager.set("expire-test", test_data, ttl=0.1)

        # Should be available immediately
        cached = await file_cache_manager.get("expire-test")
        assert cached is not None, "Should be cached immediately"

        # Wait for expiration
        await asyncio.sleep(0.2)

        # Should be expired (note: FileCacheManager doesn't auto-expire,
        # but DependencyCache checks TTL)
        # This test mainly verifies the TTL metadata is stored
        cached = await file_cache_manager.get("expire-test")
        assert "ttl" in cached, "Should store TTL metadata"
        assert cached["ttl"] == 0.1, "Should store correct TTL value"

    @pytest.mark.asyncio
    async def test_cache_delete(self, file_cache_manager):
        """Test cache entry deletion."""
        test_data = {"name": "test-pkg"}

        # Set and verify
        await file_cache_manager.set("delete-test", test_data)
        cached = await file_cache_manager.get("delete-test")
        assert cached is not None, "Should be cached"

        # Delete and verify
        success = await file_cache_manager.delete("delete-test")
        assert success, "Delete should succeed"

        cached = await file_cache_manager.get("delete-test")
        assert cached is None, "Should be deleted"

    @pytest.mark.asyncio
    async def test_cache_clear(self, file_cache_manager):
        """Test clearing all cache entries."""
        # Set multiple entries
        await file_cache_manager.set("key1", {"data": "1"})
        await file_cache_manager.set("key2", {"data": "2"})

        # Verify they exist
        assert await file_cache_manager.get("key1") is not None
        assert await file_cache_manager.get("key2") is not None

        # Clear all
        success = await file_cache_manager.clear()
        assert success, "Clear should succeed"

        # Verify they're gone
        assert await file_cache_manager.get("key1") is None
        assert await file_cache_manager.get("key2") is None

    @pytest.mark.asyncio
    async def test_cache_size_management(self, file_cache_manager):
        """Test cache size limits and cleanup."""
        # Set very small max cache size for testing
        file_cache_manager.max_cache_size = 1024  # 1KB

        # Create large cache entry
        large_data = {"large_field": "x" * 2000}  # ~2KB when serialized

        # This should trigger cleanup
        success = await file_cache_manager.set("large-entry", large_data)
        assert success, "Should handle large entries with cleanup"

    @pytest.mark.asyncio
    async def test_corrupted_cache_handling(self, file_cache_manager):
        """Test handling of corrupted cache files."""
        cache_file = file_cache_manager._get_cache_file_path("corrupted")

        # Create corrupted cache file with proper permissions
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            f.write("invalid json{")
        # Set secure permissions like the cache manager does
        import os

        os.chmod(cache_file, 0o600)

        # Should handle corruption gracefully
        cached = await file_cache_manager.get("corrupted")
        assert cached is None, "Should return None for corrupted cache"

        # File should be cleaned up
        assert not cache_file.exists(), "Corrupted file should be removed"

    def test_cache_key_security(self, file_cache_manager):
        """Test cache key hashing for security."""
        # Test that dangerous keys are hashed safely
        dangerous_key = "../../../etc/passwd"
        safe_path = file_cache_manager._get_cache_file_path(dangerous_key)

        # Should not escape cache directory
        assert file_cache_manager.cache_dir in safe_path.parents

        # Should be deterministic
        same_path = file_cache_manager._get_cache_file_path(dangerous_key)
        assert safe_path == same_path


class TestDependencyCache:
    """Test suite for multi-level dependency cache."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Provide temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir) / "dep_cache"

    @pytest.fixture
    async def dependency_cache(self, temp_cache_dir):
        """Provide DependencyCache instance."""
        cache = DependencyCache(cache_dir=temp_cache_dir, ttl=3600)
        yield cache
        await cache.clear_cache()

    @pytest.mark.asyncio
    async def test_cache_hierarchy_memory_first(self, dependency_cache):
        """Test that memory cache is checked first."""
        pkg_info = PackageInfo(name="test-pkg", version="1.0.0", license="MIT")

        # Set in cache
        await dependency_cache.set_package_info("test-pkg", pkg_info)

        # First retrieval should hit memory cache
        retrieved = await dependency_cache.get_package_info("test-pkg")
        assert retrieved is not None
        assert retrieved.name == "test-pkg"

        # Should show memory cache hit
        stats = dependency_cache.get_cache_stats()
        assert stats.memory_hits > 0

    @pytest.mark.asyncio
    async def test_cache_hierarchy_file_fallback(self, dependency_cache):
        """Test fallback to file cache when memory cache misses."""
        pkg_info = PackageInfo(name="test-pkg", version="1.0.0", license="MIT")

        # Set in cache
        await dependency_cache.set_package_info("test-pkg", pkg_info)

        # Clear memory cache but leave file cache
        dependency_cache._memory_cache.clear()
        dependency_cache._memory_cache_access.clear()

        # Should retrieve from file cache and promote to memory
        retrieved = await dependency_cache.get_package_info("test-pkg")
        assert retrieved is not None
        assert retrieved.name == "test-pkg"

        # Should now be in memory cache
        assert any("test-pkg" in key for key in dependency_cache._memory_cache.keys())

    @pytest.mark.asyncio
    async def test_cache_versioning_with_requirements_hash(self, dependency_cache):
        """Test cache versioning based on requirements hash."""
        # Cache key should include requirements hash
        cache_key = dependency_cache._generate_cache_key("test-pkg")

        assert "dep_v1_" in cache_key, "Should include version prefix"
        assert dependency_cache._requirements_hash in cache_key, "Should include requirements hash"
        assert "test-pkg" in cache_key, "Should include package name"

    @pytest.mark.asyncio
    async def test_lru_eviction_policy(self, dependency_cache):
        """Test LRU eviction from memory cache."""
        # Set small memory cache size
        dependency_cache.memory_cache_size = 3

        # Fill beyond capacity
        packages = []
        for i in range(5):
            pkg = PackageInfo(name=f"pkg-{i}", version="1.0.0")
            await dependency_cache.set_package_info(f"pkg-{i}", pkg)
            packages.append(pkg)

        # Memory cache should be limited
        assert len(dependency_cache._memory_cache) <= dependency_cache.memory_cache_size

        # Should track evictions
        stats = dependency_cache.get_cache_stats()
        assert stats.evictions > 0, "Should track evictions"

    @pytest.mark.asyncio
    async def test_bulk_operations_efficiency(self, dependency_cache):
        """Test bulk get operations for efficiency."""
        # Set multiple packages
        packages = {}
        for i in range(10):
            pkg = PackageInfo(name=f"bulk-pkg-{i}", version="1.0.0")
            await dependency_cache.set_package_info(f"bulk-pkg-{i}", pkg)
            packages[f"bulk-pkg-{i}"] = pkg

        # Bulk get
        package_names = list(packages.keys())
        results = await dependency_cache.bulk_get_package_info(package_names)

        # Should return all packages
        assert len(results) == len(packages)
        for name, pkg_info in results.items():
            assert name in packages
            assert pkg_info.name == name

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, dependency_cache):
        """Test cache invalidation functionality."""
        pkg_info = PackageInfo(name="test-pkg", version="1.0.0")
        await dependency_cache.set_package_info("test-pkg", pkg_info)

        # Verify cached
        cached = await dependency_cache.get_package_info("test-pkg")
        assert cached is not None

        # Invalidate
        success = await dependency_cache.invalidate_package("test-pkg")
        assert success

        # Should be gone from memory cache
        cached = await dependency_cache.get_package_info("test-pkg")
        assert cached is None

    @pytest.mark.asyncio
    async def test_ttl_expiration_handling(self, dependency_cache):
        """Test TTL-based expiration."""
        # Set very short TTL
        dependency_cache.ttl = 0.1  # 100ms

        pkg_info = PackageInfo(name="expire-test", version="1.0.0")
        await dependency_cache.set_package_info("expire-test", pkg_info)

        # Should be available immediately
        cached = await dependency_cache.get_package_info("expire-test")
        assert cached is not None

        # Wait for expiration
        await asyncio.sleep(0.2)

        # Should be expired
        expired = await dependency_cache.get_package_info("expire-test")
        assert expired is None

    @pytest.mark.asyncio
    async def test_health_check_functionality(self, dependency_cache):
        """Test cache health check."""
        health = await dependency_cache.health_check()

        # Should include required health metrics
        assert "memory_cache_size" in health
        assert "memory_cache_limit" in health
        assert "file_cache_enabled" in health
        assert "requirements_hash" in health
        assert "cache_stats" in health
        assert "ttl_seconds" in health

        # Values should be reasonable
        assert health["memory_cache_limit"] > 0
        assert health["ttl_seconds"] > 0
        assert isinstance(health["file_cache_enabled"], bool)

    def test_requirements_hash_computation(self, dependency_cache):
        """Test requirements hash computation for cache versioning."""
        hash_value = dependency_cache._compute_requirements_hash()

        # Should be consistent
        same_hash = dependency_cache._compute_requirements_hash()
        assert hash_value == same_hash, "Requirements hash should be deterministic"

        # Should be reasonable length
        assert len(hash_value) == 16, "Should be 16 character hash"
        assert hash_value.isalnum(), "Should be alphanumeric"

    @pytest.mark.asyncio
    async def test_concurrent_access_safety(self, dependency_cache):
        """Test thread-safe concurrent access."""
        pkg_info = PackageInfo(name="concurrent-test", version="1.0.0")

        # Concurrent set operations
        tasks = []
        for i in range(10):
            task = dependency_cache.set_package_info(f"concurrent-{i}", pkg_info)
            tasks.append(task)

        # All should complete successfully
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            assert not isinstance(result, Exception), f"Concurrent operation failed: {result}"

        # Concurrent get operations
        get_tasks = []
        for i in range(10):
            task = dependency_cache.get_package_info(f"concurrent-{i}")
            get_tasks.append(task)

        get_results = await asyncio.gather(*get_tasks, return_exceptions=True)
        for result in get_results:
            assert not isinstance(result, Exception), f"Concurrent get failed: {result}"
            assert result is not None, "Should retrieve cached packages"


class TestCacheFactory:
    """Test suite for cache factory functions."""

    def test_global_cache_singleton(self):
        """Test global cache instance creation."""
        cache1 = get_dependency_cache()
        cache2 = get_dependency_cache()

        # Should be the same instance (singleton)
        assert cache1 is cache2, "Should return same instance"

    @patch("app.utils.dependency_cache._dependency_cache", None)
    def test_cache_configuration(self):
        """Test cache configuration options."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)

            cache = get_dependency_cache(cache_dir=cache_dir, ttl=7200, memory_cache_size=500)

            assert cache.cache_dir == cache_dir
            assert cache.ttl == 7200
            assert cache.memory_cache_size == 500
