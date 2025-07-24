"""Test health check endpoints."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.api.endpoints.health import check_cache, check_database, check_disk_space, check_memory


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_check(self, client: Any) -> None:
        """Test basic health check endpoint."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["service"] == "ViolentUTF API"
        assert "version" in data
        assert "environment" in data

    def test_liveness_check(self, client: Any) -> None:
        """Test liveness probe endpoint."""
        response = client.get("/api/v1/live")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "alive"
        assert "timestamp" in data

    @patch("app.api.endpoints.health.check_database", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_cache", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_disk_space", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_memory", new_callable=AsyncMock)
    def test_readiness_check_all_healthy(
        self, mock_memory: AsyncMock, mock_disk: AsyncMock, mock_cache: AsyncMock, mock_db: AsyncMock, client: Any
    ) -> None:
        """Test readiness check when all dependencies are healthy."""
        # Mock all checks to return True
        mock_db.return_value = True
        mock_cache.return_value = True
        mock_disk.return_value = True
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ready"
        assert "timestamp" in data
        assert data["checks"]["database"] is True
        assert data["checks"]["cache"] is True
        assert data["checks"]["disk_space"] is True
        assert data["checks"]["memory"] is True
        assert len(data["details"]["failed_checks"]) == 0

    @patch("app.api.endpoints.health.check_database", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_cache", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_disk_space", new_callable=AsyncMock)
    @patch("app.api.endpoints.health.check_memory", new_callable=AsyncMock)
    def test_readiness_check_database_unhealthy(
        self, mock_memory: AsyncMock, mock_disk: AsyncMock, mock_cache: AsyncMock, mock_db: AsyncMock, client: Any
    ) -> None:
        """Test readiness check when database is unhealthy."""
        # Mock database check to return False
        mock_db.return_value = False
        mock_cache.return_value = True
        mock_disk.return_value = True
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 503  # Service Unavailable
        data = response.json()

        assert data["status"] == "not ready"
        assert data["checks"]["database"] is False
        assert "database" in data["details"]["failed_checks"]


class TestHealthCheckFunctions:
    """Test individual health check functions."""

    @pytest.mark.asyncio
    async def test_check_database_no_url(self, test_settings: Any) -> None:
        """Test database check when DATABASE_URL is not set."""
        test_settings.DATABASE_URL = None
        with patch("app.api.endpoints.health.settings", test_settings):
            result = await check_database()
            assert result is True  # Should return True when DB is optional

    @pytest.mark.asyncio
    async def test_check_cache_no_url(self, test_settings: Any) -> None:
        """Test cache check when REDIS_URL is not set."""
        test_settings.REDIS_URL = None
        with patch("app.api.endpoints.health.settings", test_settings):
            result = await check_cache()
            assert result is True  # Should return True when cache is optional

    def test_check_disk_space_healthy(self) -> None:
        """Test disk space check when healthy."""
        with patch("shutil.disk_usage") as mock_disk:
            # Mock 50% usage
            mock_disk.return_value.total = 1000
            mock_disk.return_value.used = 500

            result = asyncio.run(check_disk_space(threshold=0.9))
            assert result is True

    def test_check_disk_space_unhealthy(self) -> None:
        """Test disk space check when unhealthy."""
        with patch("shutil.disk_usage") as mock_disk:
            # Mock 95% usage
            mock_disk.return_value.total = 1000
            mock_disk.return_value.used = 950

            result = asyncio.run(check_disk_space(threshold=0.9))
            assert result is False

    def test_check_memory_healthy(self) -> None:
        """Test memory check when healthy."""
        with patch("psutil.virtual_memory") as mock_memory:
            # Mock 50% usage
            mock_memory.return_value.percent = 50.0

            result = asyncio.run(check_memory(threshold=0.9))
            assert result is True

    def test_check_memory_unhealthy(self) -> None:
        """Test memory check when unhealthy."""
        with patch("psutil.virtual_memory") as mock_memory:
            # Mock 95% usage
            mock_memory.return_value.percent = 95.0

            result = asyncio.run(check_memory(threshold=0.9))
            assert result is False
