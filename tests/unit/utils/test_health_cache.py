"""Tests for health check caching functionality."""

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest

from app.utils.monitoring import (
    cache_health_check_result,
    check_dependency_health,
    clear_health_check_cache,
    get_cached_health_check,
    health_check_cache,
)


class TestHealthCheckCaching:
    """Test health check caching functions."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_health_check_cache()

    def test_cache_health_check_result(self) -> None:
        """Test caching a health check result."""
        result = {"status": "healthy", "checks": {"db": True, "cache": True}}
        cache_key = "test_health"

        # Cache the result
        cache_health_check_result(cache_key, result)

        # Verify it's in the cache
        assert cache_key in health_check_cache
        timestamp, cached_result = health_check_cache[cache_key]
        assert cached_result == result
        assert isinstance(timestamp, float)
        assert timestamp <= time.time()

    def test_get_cached_health_check_valid(self) -> None:
        """Test retrieving a valid cached result."""
        result = {"status": "healthy"}
        cache_key = "test_health"
        ttl = 60  # 60 seconds

        # Cache the result
        cache_health_check_result(cache_key, result)

        # Retrieve it immediately (should be valid)
        cached = get_cached_health_check(cache_key, ttl)
        assert cached == result

    def test_get_cached_health_check_expired(self) -> None:
        """Test retrieving an expired cached result."""
        result = {"status": "healthy"}
        cache_key = "test_health"
        ttl = 1  # 1 second

        # Cache the result with old timestamp
        health_check_cache[cache_key] = (time.time() - 2, result)  # 2 seconds ago

        # Try to retrieve (should be expired)
        cached = get_cached_health_check(cache_key, ttl)
        assert cached is None

        # Verify expired entry was removed
        assert cache_key not in health_check_cache

    def test_get_cached_health_check_not_found(self) -> None:
        """Test retrieving non-existent cached result."""
        cached = get_cached_health_check("non_existent", 60)
        assert cached is None

    def test_clear_health_check_cache(self) -> None:
        """Test clearing the cache."""
        # Add some entries
        cache_health_check_result("key1", {"status": "healthy"})
        cache_health_check_result("key2", {"status": "unhealthy"})

        assert len(health_check_cache) == 2

        # Clear the cache
        clear_health_check_cache()

        assert len(health_check_cache) == 0

    @pytest.mark.asyncio
    async def test_check_dependency_health_uses_cache(self) -> None:
        """Test that check_dependency_health uses caching."""
        # Pre-populate cache
        cached_result = {
            "overall_healthy": True,
            "checks": {"database": True, "cache": True},
            "metrics": {"cpu": 10},
            "check_duration_seconds": 0.01,
        }
        cache_health_check_result("dependency_health", cached_result)

        # Mock the actual health checks (they shouldn't be called)
        with (
            patch("app.db.session.check_database_health") as mock_db,
            patch("app.utils.cache.check_cache_health") as mock_cache,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db.return_value = False  # Should not be called
            mock_cache.return_value = False  # Should not be called
            mock_metrics.return_value = {"cpu": 99}  # Should not be called

            # Call with default cache_ttl (10 seconds)
            result = await check_dependency_health()

            # Should return cached result
            assert result == cached_result

            # Verify actual health checks were not called
            mock_db.assert_not_called()
            mock_cache.assert_not_called()
            mock_metrics.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_dependency_health_cache_expired(self) -> None:
        """Test check_dependency_health when cache is expired."""
        # Add expired cache entry
        old_result = {
            "overall_healthy": False,
            "checks": {"database": False, "cache": False},
            "metrics": {},
            "check_duration_seconds": 0.01,
        }
        health_check_cache["dependency_health"] = (
            time.time() - 20,
            old_result,
        )  # 20 seconds ago

        # Mock the actual health checks
        with (
            patch("app.db.session.check_database_health") as mock_db,
            patch("app.utils.cache.check_cache_health") as mock_cache,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db.return_value = True
            mock_cache.return_value = True
            mock_metrics.return_value = {"cpu": 50}

            # Call with short cache_ttl (5 seconds)
            result = await check_dependency_health(cache_ttl=5)

            # Should perform new health checks
            assert result["overall_healthy"] is True
            assert result["checks"]["database"] is True
            assert result["checks"]["cache"] is True

            # Verify actual health checks were called
            mock_db.assert_called_once()
            mock_cache.assert_called_once()
            mock_metrics.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_dependency_health_no_cache(self) -> None:
        """Test check_dependency_health performs checks when no cache exists."""
        # Ensure cache is empty
        clear_health_check_cache()

        # Mock the health checks
        with (
            patch("app.db.session.check_database_health") as mock_db,
            patch("app.utils.cache.check_cache_health") as mock_cache,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db.return_value = True
            mock_cache.return_value = True
            mock_metrics.return_value = {"cpu": 25}

            result = await check_dependency_health()

            # Verify health checks were performed
            assert result["overall_healthy"] is True
            mock_db.assert_called_once()
            mock_cache.assert_called_once()
            mock_metrics.assert_called_once()

            # Verify result was cached
            assert "dependency_health" in health_check_cache

    @pytest.mark.asyncio
    async def test_check_dependency_health_cache_ttl_zero(self) -> None:
        """Test that cache_ttl=0 disables caching."""
        # Pre-populate cache
        cached_result = {"overall_healthy": False}
        cache_health_check_result("dependency_health", cached_result)

        # Mock health checks
        with (
            patch("app.db.session.check_database_health") as mock_db,
            patch("app.utils.cache.check_cache_health") as mock_cache,
            patch("app.utils.monitoring.get_system_metrics") as mock_metrics,
        ):
            mock_db.return_value = True
            mock_cache.return_value = True
            mock_metrics.return_value = {}

            # Call with cache_ttl=0 (should bypass cache)
            result = await check_dependency_health(cache_ttl=0)

            # Should perform fresh checks
            assert result["overall_healthy"] is True
            mock_db.assert_called_once()

    def test_cache_expiration_timing(self) -> None:
        """Test precise cache expiration timing."""
        result = {"status": "healthy"}
        cache_key = "timing_test"
        ttl = 2  # 2 seconds

        # Cache the result
        cache_health_check_result(cache_key, result)

        # Should be valid immediately
        assert get_cached_health_check(cache_key, ttl) == result

        # Wait 1 second - should still be valid
        time.sleep(1)
        assert get_cached_health_check(cache_key, ttl) == result

        # Wait another 1.5 seconds - should be expired
        time.sleep(1.5)
        assert get_cached_health_check(cache_key, ttl) is None
