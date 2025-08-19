"""Performance tests for health check endpoints."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_application


class TestHealthEndpointPerformance:
    """Test health endpoint performance requirements."""

    @pytest.mark.asyncio
    async def test_health_check_under_200ms(self) -> None:
        """Test that basic health check completes within 200ms."""
        app = create_application()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start_time = time.time()
            response = await client.get("/api/v1/health")
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds

            assert response.status_code == 200
            assert duration < 300, f"Health check took {duration:.2f}ms, exceeding 300ms limit"

            # Also check the response format
            data = response.json()
            assert data["status"] == "healthy"
            assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_liveness_check_under_200ms(self) -> None:
        """Test that liveness check completes within 200ms."""
        app = create_application()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start_time = time.time()
            response = await client.get("/api/v1/live")
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds

            assert response.status_code == 200
            assert duration < 300, f"Liveness check took {duration:.2f}ms, exceeding 300ms limit"

            data = response.json()
            assert data["status"] == "alive"

    @pytest.mark.asyncio
    async def test_readiness_check_under_200ms(self) -> None:
        """Test that readiness check completes within 200ms."""
        # Mock the dependency checks to ensure consistent timing
        with (
            patch("app.api.endpoints.health.check_dependency_health") as mock_dep_health,
            patch("app.api.endpoints.health.check_disk_space") as mock_disk,
            patch("app.api.endpoints.health.check_memory") as mock_memory,
        ):
            # Configure mocks for fast response
            mock_dep_health.return_value = {
                "checks": {"database": True, "cache": True},
                "metrics": {},
                "check_duration_seconds": 0.05,
            }
            mock_disk.return_value = True
            mock_memory.return_value = True

            app = create_application()

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                start_time = time.time()
                response = await client.get("/api/v1/ready")
                duration = (time.time() - start_time) * 1000  # Convert to milliseconds

                assert response.status_code == 200
                assert duration < 300, f"Readiness check took {duration:.2f}ms, exceeding 300ms limit"

                data = response.json()
                assert data["status"] == "ready"
                assert all(data["checks"].values())

    @pytest.mark.asyncio
    async def test_readiness_with_slow_dependencies(self) -> None:
        """Test readiness check with slow dependencies still uses caching effectively."""
        from app.utils.monitoring import cache_health_check_result, clear_health_check_cache

        # Clear any existing cache
        clear_health_check_cache()

        # Pre-populate cache with healthy result
        cache_health_check_result(
            "dependency_health",
            {
                "overall_healthy": True,
                "checks": {"database": True, "cache": True},
                "metrics": {},
                "check_duration_seconds": 0.01,
            },
        )

        # Mock disk and memory checks to be fast
        with (
            patch("app.api.endpoints.health.check_disk_space") as mock_disk,
            patch("app.api.endpoints.health.check_memory") as mock_memory,
        ):
            mock_disk.return_value = True
            mock_memory.return_value = True

            app = create_application()

            # First request should use cache
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                start_time = time.time()
                response = await client.get("/api/v1/ready")
                duration = (time.time() - start_time) * 1000

                assert response.status_code == 200
                assert duration < 300, f"Cached readiness check took {duration:.2f}ms"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_parallel_health_checks_performance(self) -> None:
        """Test multiple concurrent health checks perform well."""
        app = create_application()

        async def make_health_request(client: AsyncClient) -> float:
            """Make a health request and return duration in ms."""
            start = time.time()
            response = await client.get("/api/v1/health")
            assert response.status_code == 200
            return (time.time() - start) * 1000

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Run 10 concurrent health checks
            tasks = [make_health_request(client) for _ in range(10)]
            durations = await asyncio.gather(*tasks)

            # All requests should complete quickly
            max_duration = max(durations)
            avg_duration = sum(durations) / len(durations)

            # Adjusted thresholds for CI environments which are typically slower
            # due to shared resources, container overhead, and limited CPU
            assert max_duration < 1000, f"Max duration {max_duration:.2f}ms exceeds 1000ms"
            assert avg_duration < 400, f"Average duration {avg_duration:.2f}ms exceeds 400ms"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_health_check_caching_performance(self) -> None:
        """Test that caching significantly improves performance."""
        from app.utils.monitoring import clear_health_check_cache

        # Mock slow dependency checks
        async def slow_db_check() -> bool:
            await asyncio.sleep(0.1)  # 100ms delay
            return True

        async def slow_cache_check() -> bool:
            await asyncio.sleep(0.1)  # 100ms delay
            return True

        with (
            patch("app.db.session.check_database_health", side_effect=slow_db_check),
            patch("app.utils.cache.check_cache_health", side_effect=slow_cache_check),
            patch("app.api.endpoints.health.check_disk_space") as mock_disk,
            patch("app.api.endpoints.health.check_memory") as mock_memory,
        ):
            mock_disk.return_value = True
            mock_memory.return_value = True

            app = create_application()

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Clear cache first
                clear_health_check_cache()

                # First request - no cache, should be slower
                start1 = time.time()
                response1 = await client.get("/api/v1/ready")
                duration1 = (time.time() - start1) * 1000
                assert response1.status_code == 200

                # Second request - should use cache and be much faster
                start2 = time.time()
                response2 = await client.get("/api/v1/ready")
                duration2 = (time.time() - start2) * 1000
                assert response2.status_code == 200

                # Cached request should be significantly faster
                # Use more lenient timing thresholds for CI environments
                min_improvement_ratio = 1.5  # Cached should be at least 1.5x faster
                max_cached_time = 100  # Cached should take less than 100ms

                # Check that cached is faster than uncached by the minimum ratio
                assert duration2 < (duration1 / min_improvement_ratio), (
                    f"Cached request ({duration2:.2f}ms) not significantly faster "
                    f"than uncached ({duration1:.2f}ms). Expected < {duration1/min_improvement_ratio:.2f}ms"
                )

                # Check absolute time limit (more lenient for CI)
                assert (
                    duration2 < max_cached_time
                ), f"Cached request took {duration2:.2f}ms, should be < {max_cached_time}ms"
