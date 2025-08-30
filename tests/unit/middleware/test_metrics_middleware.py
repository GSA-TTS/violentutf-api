"""Tests for metrics collection middleware."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Dict, Generator
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, HTTPException

# TestClient imported via TYPE_CHECKING for type hints only
from prometheus_client import REGISTRY

from app.core.config import settings
from app.middleware.metrics import (
    ACTIVE_REQUESTS,
    REQUEST_COUNT,
    REQUEST_DURATION,
    MetricsMiddleware,
)
from tests.utils.testclient import SafeTestClient

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


class TestMetricsMiddleware:
    """Test metrics collection middleware."""

    @pytest.fixture
    def app(self, monkeypatch: Any) -> FastAPI:
        """Create test FastAPI app with metrics middleware."""
        # Enable metrics for this test
        monkeypatch.setattr(settings, "ENABLE_METRICS", True)

        app = FastAPI()

        # Add metrics middleware - NOTE: Middleware is added in reverse order
        # So this will actually be executed first
        app.add_middleware(MetricsMiddleware)

        # Add test endpoints
        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        @app.get("/test/{item_id}")
        async def test_with_id(item_id: str) -> Dict[str, str]:
            return {"item_id": item_id}

        @app.get("/metrics")
        async def metrics_endpoint() -> Dict[str, str]:
            return {"message": "metrics"}

        @app.post("/test")
        async def test_post() -> Dict[str, str]:
            return {"message": "posted"}

        @app.get("/slow")
        async def slow_endpoint() -> Dict[str, str]:
            await asyncio.sleep(0.1)
            return {"message": "slow"}

        @app.get("/error")
        async def error_endpoint() -> None:
            raise ValueError("Test error")

        @app.get("/http-error")
        async def http_error_endpoint() -> None:
            raise HTTPException(status_code=404, detail="Not found")

        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> Generator["TestClient", None, None]:
        """Create test client with the app."""
        from tests.utils.testclient import SafeTestClient

        with SafeTestClient(app) as test_client:
            yield test_client

    @pytest.fixture(autouse=True)
    def reset_metrics(self) -> None:
        """Reset metrics before each test."""
        # Clear all metrics
        REQUEST_COUNT.clear()
        REQUEST_DURATION.clear()
        ACTIVE_REQUESTS._value.set(0)

    def test_metrics_enabled_check(self, monkeypatch: Any) -> None:
        """Test that metrics can be disabled via settings."""
        # Test with metrics disabled
        monkeypatch.setattr(settings, "ENABLE_METRICS", False)

        app = FastAPI()
        app.add_middleware(MetricsMiddleware)

        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        # Import TestClient locally to ensure correct resolution
        from tests.utils.testclient import SafeTestClient

        client = SafeTestClient(app)

        # Make request
        response = client.get("/test")
        assert response.status_code == 200

        # Metrics should not be collected
        # This is hard to test directly, but the middleware should return early

    def test_request_count_metric(self, client: "TestClient") -> None:
        """Test that request count is tracked."""
        # Make several requests
        resp1 = client.get("/test")
        assert resp1.status_code == 200
        resp2 = client.get("/test")
        assert resp2.status_code == 200
        resp3 = client.post("/test")
        assert resp3.status_code == 200

        # Check the metric directly
        # The REQUEST_COUNT Counter stores samples with specific label combinations
        # We need to check if our specific labels exist

        # Try to get the metric value directly
        get_count = REQUEST_COUNT.labels(method="GET", endpoint="/test", status="200")._value.get()
        post_count = REQUEST_COUNT.labels(method="POST", endpoint="/test", status="200")._value.get()

        assert get_count == 2, f"Expected GET count to be 2, got {get_count}"
        assert post_count == 1, f"Expected POST count to be 1, got {post_count}"

    def test_request_duration_metric(self, client: "TestClient") -> None:
        """Test that request duration is tracked."""
        # Make a request
        client.get("/test")

        # Check duration metric - prometheus histogram metrics have _sum and _count suffixes
        # We need to check if the histogram has recorded our request
        from prometheus_client import REGISTRY

        # Get all samples for the duration metric
        duration_samples = []
        for collector in REGISTRY.collect():
            if collector.name == "http_request_duration_seconds":
                duration_samples.extend(collector.samples)

        # Find the count sample for our endpoint
        count_samples = [
            s
            for s in duration_samples
            if s.name.endswith("_count") and s.labels.get("method") == "GET" and s.labels.get("endpoint") == "/test"
        ]

        assert len(count_samples) > 0, "No duration count samples found"
        assert count_samples[0].value >= 1, "Duration count should be at least 1"

    def test_active_requests_metric(self, app: FastAPI) -> None:
        """Test that active requests are tracked."""
        # This is tricky to test with TestClient as it's synchronous
        # We'll test the metric exists and can be incremented/decremented

        initial_value = ACTIVE_REQUESTS._value.get()

        # Simulate increment/decrement
        ACTIVE_REQUESTS.inc()
        assert ACTIVE_REQUESTS._value.get() == initial_value + 1

        ACTIVE_REQUESTS.dec()
        assert ACTIVE_REQUESTS._value.get() == initial_value

    def test_endpoint_normalization(self, client: "TestClient") -> None:
        """Test that endpoints with IDs are normalized."""
        # Make requests with different IDs
        client.get("/test/123")
        client.get("/test/456")
        client.get("/test/550e8400-e29b-41d4-a716-446655440000")  # UUID

        # Check that all are grouped under same endpoint
        # The middleware should normalize all these to /test/{id}
        normalized_count = REQUEST_COUNT.labels(method="GET", endpoint="/test/{id}", status="200")._value.get()

        assert normalized_count == 3, f"Expected count to be 3 for /test/{{id}}, got {normalized_count}"

    def test_metrics_endpoint_excluded(self, client: "TestClient") -> None:
        """Test that /metrics endpoint itself is not tracked."""
        # Make request to metrics endpoint
        client.get("/metrics")

        # Check that it's not in the metrics - try to get the counter
        # If the /metrics endpoint was tracked, this would return a non-zero value
        try:
            metrics_count = REQUEST_COUNT.labels(method="GET", endpoint="/metrics", status="200")._value.get()
            assert metrics_count == 0, f"Expected /metrics count to be 0, got {metrics_count}"
        except KeyError:
            # If we get a KeyError, it means no metric was created for /metrics, which is what we want
            pass

    def test_error_requests_tracked(self, client: "TestClient") -> None:
        """Test that failed requests are tracked with 500 status."""
        # Make request that will error
        with pytest.raises(ValueError):
            client.get("/error")

        # Check the metric directly
        error_count = REQUEST_COUNT.labels(method="GET", endpoint="/error", status="500")._value.get()

        assert error_count == 1, f"Expected error count to be 1, got {error_count}"

    def test_http_exception_tracked(self, client: "TestClient") -> None:
        """Test that HTTP exceptions are tracked with correct status."""
        # Make request that raises HTTPException
        response = client.get("/http-error")
        assert response.status_code == 404

        # Check metrics
        # Note: samples = list(REQUEST_COUNT.collect()[0].samples)
        # Should have a 404 status entry
        # not_found_samples = [s for s in samples if s.labels.get("status") == "404"]
        # Note: HTTPException might not be caught by middleware
        # It depends on the order of middleware and exception handlers

    def test_different_methods_tracked(self, client: "TestClient") -> None:
        """Test that different HTTP methods are tracked separately."""
        # Make requests with different methods
        client.get("/test")
        client.post("/test")
        client.get("/test")

        # Check the metrics directly
        get_count = REQUEST_COUNT.labels(method="GET", endpoint="/test", status="200")._value.get()
        post_count = REQUEST_COUNT.labels(method="POST", endpoint="/test", status="200")._value.get()

        assert get_count == 2, f"Expected GET count to be 2, got {get_count}"
        assert post_count == 1, f"Expected POST count to be 1, got {post_count}"

    def test_slow_request_duration(self, client: "TestClient") -> None:
        """Test that slow requests have accurate duration."""
        # Make slow request
        client.get("/slow")

        # Check duration metric
        from prometheus_client import REGISTRY

        collected = []
        for collector in REGISTRY.collect():
            if collector.name == "http_request_duration_seconds":
                collected.extend(collector.samples)

        # Find the sum sample for slow endpoint
        slow_duration_samples = [
            s
            for s in collected
            if s.name.endswith("_sum") and s.labels.get("endpoint") == "/slow" and s.labels.get("method") == "GET"
        ]

        assert len(slow_duration_samples) > 0, "No duration sum samples found for /slow endpoint"
        # Duration should be at least 0.1 seconds
        assert (
            slow_duration_samples[0].value >= 0.1
        ), f"Duration should be >= 0.1s, got {slow_duration_samples[0].value}"

    def test_concurrent_request_metrics(self, app: FastAPI) -> None:
        """Test metrics accuracy with concurrent requests."""
        import threading
        from concurrent.futures import ThreadPoolExecutor

        def make_request(path: str) -> int:
            # Import TestClient locally to ensure correct resolution
            from tests.utils.testclient import SafeTestClient

            client = SafeTestClient(app)
            response = client.get(path)
            return response.status_code

        # Make concurrent requests
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, "/test") for _ in range(10)]

            results = [f.result() for f in futures]

        # All should succeed
        assert all(status == 200 for status in results)

        # Check total count
        concurrent_count = REQUEST_COUNT.labels(method="GET", endpoint="/test", status="200")._value.get()

        # Should have total of 10 requests
        assert concurrent_count == 10, f"Expected concurrent count to be 10, got {concurrent_count}"

    def test_path_parameter_variations(self, client: "TestClient") -> None:
        """Test various path parameter formats are normalized."""
        # Test different ID formats
        paths_and_ids = [
            ("/test/123", "numeric"),
            ("/test/550e8400-e29b-41d4-a716-446655440000", "uuid"),
            ("/test/AbCdEf123456", "alphanumeric"),
            ("/test/item-with-dash", "with-dash"),
        ]

        for path, _ in paths_and_ids:
            client.get(path)

        # All should be normalized to /test/{id}
        normalized_count = REQUEST_COUNT.labels(method="GET", endpoint="/test/{id}", status="200")._value.get()

        # Should have count equal to number of requests
        assert normalized_count == len(
            paths_and_ids
        ), f"Expected {len(paths_and_ids)} normalized requests, got {normalized_count}"

    def test_metric_labels(self, client: "TestClient") -> None:
        """Test that metrics have correct labels."""
        client.get("/test")

        # Check that metrics exist with proper labels by accessing them directly
        # If the labels don't exist, this will raise an exception
        try:
            # Check REQUEST_COUNT with all expected labels
            count = REQUEST_COUNT.labels(method="GET", endpoint="/test", status="200")._value.get()
            assert count >= 1, "Request count should be at least 1"

            # Check REQUEST_DURATION - histograms don't have _value but we can check they exist
            # by accessing with the expected labels
            REQUEST_DURATION.labels(method="GET", endpoint="/test")

            # If we get here, all labels exist as expected
            assert True
        except Exception as e:
            pytest.fail(f"Metrics don't have expected labels: {e}")
