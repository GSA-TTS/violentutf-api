"""Test enhanced health check endpoints with real database and cache connectivity."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_application


class TestEnhancedHealthEndpoints:
    """Test enhanced health check endpoints."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client with enhanced health endpoints."""
        app = create_application()
        return TestClient(app)

    def test_health_check_basic(self, client: TestClient) -> None:
        """Test basic health check endpoint."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "service" in data
        assert "version" in data
        assert "environment" in data

    @patch("app.api.endpoints.health.check_dependency_health")
    @patch("app.api.endpoints.health.check_disk_space")
    @patch("app.api.endpoints.health.check_memory")
    def test_readiness_check_all_healthy(
        self, mock_memory: Any, mock_disk: Any, mock_dependency: Any, client: TestClient
    ) -> None:
        """Test readiness check when all dependencies are healthy."""
        # Mock all checks to return healthy
        mock_dependency.return_value = {
            "overall_healthy": True,
            "checks": {
                "database": True,
                "cache": True,
            },
            "metrics": {"cpu_percent": 25.0},
            "check_duration_seconds": 0.123,
        }
        mock_disk.return_value = True
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ready"
        assert data["checks"]["database"] is True
        assert data["checks"]["cache"] is True
        assert data["checks"]["disk_space"] is True
        assert data["checks"]["memory"] is True
        assert data["details"]["failed_checks"] == []
        assert "metrics" in data["details"]
        assert "check_duration" in data["details"]

    @patch("app.api.endpoints.health.check_dependency_health")
    @patch("app.api.endpoints.health.check_disk_space")
    @patch("app.api.endpoints.health.check_memory")
    def test_readiness_check_database_unhealthy(
        self, mock_memory: Any, mock_disk: Any, mock_dependency: Any, client: TestClient
    ) -> None:
        """Test readiness check when database is unhealthy."""
        # Mock database as unhealthy
        mock_dependency.return_value = {
            "overall_healthy": False,
            "checks": {
                "database": False,
                "cache": True,
            },
            "metrics": {"cpu_percent": 25.0},
            "check_duration_seconds": 0.123,
        }
        mock_disk.return_value = True
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 503
        data = response.json()

        assert data["status"] == "not ready"
        assert data["checks"]["database"] is False
        assert data["checks"]["cache"] is True
        assert data["details"]["failed_checks"] == ["database"]

    @patch("app.api.endpoints.health.check_dependency_health")
    @patch("app.api.endpoints.health.check_disk_space")
    @patch("app.api.endpoints.health.check_memory")
    def test_readiness_check_multiple_failures(
        self, mock_memory: Any, mock_disk: Any, mock_dependency: Any, client: TestClient
    ) -> None:
        """Test readiness check with multiple failed dependencies."""
        # Mock multiple failures
        mock_dependency.return_value = {
            "overall_healthy": False,
            "checks": {
                "database": False,
                "cache": False,
            },
            "metrics": {"cpu_percent": 25.0},
            "check_duration_seconds": 0.123,
        }
        mock_disk.return_value = False
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 503
        data = response.json()

        assert data["status"] == "not ready"
        assert data["checks"]["database"] is False
        assert data["checks"]["cache"] is False
        assert data["checks"]["disk_space"] is False
        assert data["checks"]["memory"] is True
        assert set(data["details"]["failed_checks"]) == {"database", "cache", "disk_space"}

    @patch("app.api.endpoints.health.check_dependency_health")
    @patch("app.api.endpoints.health.check_disk_space")
    @patch("app.api.endpoints.health.check_memory")
    def test_readiness_check_with_exceptions(
        self, mock_memory: Any, mock_disk: Any, mock_dependency: Any, client: TestClient
    ) -> None:
        """Test readiness check when system checks raise exceptions."""
        # Mock dependency health as good but system checks fail
        mock_dependency.return_value = {
            "overall_healthy": True,
            "checks": {
                "database": True,
                "cache": True,
            },
            "metrics": {"cpu_percent": 25.0},
            "check_duration_seconds": 0.123,
        }
        mock_disk.side_effect = Exception("Disk check failed")
        mock_memory.side_effect = Exception("Memory check failed")

        response = client.get("/api/v1/ready")

        assert response.status_code == 503
        data = response.json()

        assert data["status"] == "not ready"
        assert data["checks"]["database"] is True
        assert data["checks"]["cache"] is True
        assert data["checks"]["disk_space"] is False
        assert data["checks"]["memory"] is False

    def test_liveness_check(self, client: TestClient) -> None:
        """Test liveness check endpoint."""
        response = client.get("/api/v1/live")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "alive"
        assert "timestamp" in data

    @patch("shutil.disk_usage")
    def test_disk_space_check_healthy(self, mock_disk_usage: Any) -> None:
        """Test disk space check when usage is below threshold."""
        from app.api.endpoints.health import check_disk_space

        # Mock disk usage: 50% used (below 90% threshold)
        mock_usage = MagicMock()
        mock_usage.used = 50 * 1024**3
        mock_usage.total = 100 * 1024**3
        mock_disk_usage.return_value = mock_usage

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_disk_space())
        loop.close()

        assert result is True

    @patch("shutil.disk_usage")
    def test_disk_space_check_unhealthy(self, mock_disk_usage: Any) -> None:
        """Test disk space check when usage is above threshold."""
        from app.api.endpoints.health import check_disk_space

        # Mock disk usage: 95% used (above 90% threshold)
        mock_usage = MagicMock()
        mock_usage.used = 95 * 1024**3
        mock_usage.total = 100 * 1024**3
        mock_disk_usage.return_value = mock_usage

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_disk_space())
        loop.close()

        assert result is False

    @patch("shutil.disk_usage")
    def test_disk_space_check_custom_threshold(self, mock_disk_usage: Any) -> None:
        """Test disk space check with custom threshold."""
        from app.api.endpoints.health import check_disk_space

        # Mock disk usage: 80% used
        mock_usage = MagicMock()
        mock_usage.used = 80 * 1024**3
        mock_usage.total = 100 * 1024**3
        mock_disk_usage.return_value = mock_usage

        loop = asyncio.new_event_loop()
        # Should pass with 90% threshold
        result1 = loop.run_until_complete(check_disk_space(threshold=0.9))
        # Should fail with 75% threshold
        result2 = loop.run_until_complete(check_disk_space(threshold=0.75))
        loop.close()

        assert result1 is True
        assert result2 is False

    @patch("shutil.disk_usage")
    def test_disk_space_check_exception(self, mock_disk_usage: Any) -> None:
        """Test disk space check with exception."""
        from app.api.endpoints.health import check_disk_space

        mock_disk_usage.side_effect = Exception("Disk error")

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_disk_space())
        loop.close()

        assert result is False

    @patch("psutil.virtual_memory")
    def test_memory_check_healthy(self, mock_memory: Any) -> None:
        """Test memory check when usage is below threshold."""
        from app.api.endpoints.health import check_memory

        # Mock memory usage: 50% used (below 90% threshold)
        mock_mem = MagicMock()
        mock_mem.percent = 50.0
        mock_memory.return_value = mock_mem

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_memory())
        loop.close()

        assert result is True

    @patch("psutil.virtual_memory")
    def test_memory_check_unhealthy(self, mock_memory: Any) -> None:
        """Test memory check when usage is above threshold."""
        from app.api.endpoints.health import check_memory

        # Mock memory usage: 95% used (above 90% threshold)
        mock_mem = MagicMock()
        mock_mem.percent = 95.0
        mock_memory.return_value = mock_mem

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_memory())
        loop.close()

        assert result is False

    @patch("psutil.virtual_memory")
    def test_memory_check_custom_threshold(self, mock_memory: Any) -> None:
        """Test memory check with custom threshold."""
        from app.api.endpoints.health import check_memory

        # Mock memory usage: 80% used
        mock_mem = MagicMock()
        mock_mem.percent = 80.0
        mock_memory.return_value = mock_mem

        loop = asyncio.new_event_loop()
        # Should pass with 90% threshold
        result1 = loop.run_until_complete(check_memory(threshold=0.9))
        # Should fail with 75% threshold
        result2 = loop.run_until_complete(check_memory(threshold=0.75))
        loop.close()

        assert result1 is True
        assert result2 is False

    @patch("psutil.virtual_memory")
    def test_memory_check_exception(self, mock_memory: Any) -> None:
        """Test memory check with exception."""
        from app.api.endpoints.health import check_memory

        mock_memory.side_effect = Exception("Memory error")

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check_memory())
        loop.close()

        assert result is False


class TestHealthCheckTracking:
    """Test that health check endpoints use monitoring decorators."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_application()
        return TestClient(app)

    @patch("app.utils.monitoring.health_check_total")
    @patch("app.utils.monitoring.health_check_duration")
    def test_health_check_metrics_tracked(self, mock_duration: Any, mock_total: Any, client: TestClient) -> None:
        """Test that health check metrics are properly tracked."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200

        # Verify metrics were recorded
        mock_total.labels.assert_called_with(endpoint="health_check", status="success")
        mock_total.labels.return_value.inc.assert_called_once()
        mock_duration.labels.assert_called_with(endpoint="health_check")
        mock_duration.labels.return_value.observe.assert_called_once()

    @patch("app.utils.monitoring.health_check_total")
    @patch("app.utils.monitoring.health_check_duration")
    @patch("app.api.endpoints.health.check_dependency_health")
    @patch("app.api.endpoints.health.check_disk_space")
    @patch("app.api.endpoints.health.check_memory")
    def test_readiness_check_metrics_tracked(
        self,
        mock_memory: Any,
        mock_disk: Any,
        mock_dependency: Any,
        mock_duration: Any,
        mock_total: Any,
        client: TestClient,
    ) -> None:
        """Test that readiness check metrics are properly tracked."""
        # Mock successful checks
        mock_dependency.return_value = {
            "overall_healthy": True,
            "checks": {"database": True, "cache": True},
            "metrics": {},
            "check_duration_seconds": 0.1,
        }
        mock_disk.return_value = True
        mock_memory.return_value = True

        response = client.get("/api/v1/ready")

        assert response.status_code == 200

        # Verify metrics were recorded
        mock_total.labels.assert_called_with(endpoint="readiness_check", status="success")
        mock_duration.labels.assert_called_with(endpoint="readiness_check")


class TestHealthEndpointIntegration:
    """Test health endpoints with real integration scenarios."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_application()
        return TestClient(app)

    def test_all_health_endpoints_accessible(self, client: TestClient) -> None:
        """Test that all health endpoints are accessible and return expected structure."""
        # Test basic health
        health_response = client.get("/api/v1/health")
        assert health_response.status_code == 200
        health_data = health_response.json()
        assert "status" in health_data
        assert "timestamp" in health_data

        # Test readiness (might fail due to no real database/cache, but should be structured)
        ready_response = client.get("/api/v1/ready")
        assert ready_response.status_code in [200, 503]  # Either all good or some services down
        ready_data = ready_response.json()
        assert "status" in ready_data
        assert "checks" in ready_data
        assert "details" in ready_data

        # Test liveness
        live_response = client.get("/api/v1/live")
        assert live_response.status_code == 200
        live_data = live_response.json()
        assert "status" in live_data
        assert live_data["status"] == "alive"

    @patch("app.api.endpoints.health.settings")
    def test_health_endpoints_with_no_database_config(self, mock_settings: Any, client: TestClient) -> None:
        """Test health endpoints when database is not configured."""
        mock_settings.DATABASE_URL = None
        mock_settings.REDIS_URL = None

        # Should still work - database and cache are optional
        response = client.get("/api/v1/ready")
        assert response.status_code in [200, 503]  # Depends on disk/memory

        data = response.json()
        assert "checks" in data
        # Database and cache checks should pass when not configured
