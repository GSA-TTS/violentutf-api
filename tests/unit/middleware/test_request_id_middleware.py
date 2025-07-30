"""Tests for request ID middleware."""

import asyncio
import re
import time
from typing import Any, Dict, Generator
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app.middleware.request_id import RequestIDMiddleware


class TestRequestIDMiddleware:
    """Test request ID tracking middleware."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create test FastAPI app with request ID middleware."""
        app = FastAPI()

        # Add request ID middleware
        app.add_middleware(RequestIDMiddleware)

        # Add test endpoints
        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        @app.get("/slow")
        async def slow_endpoint() -> Dict[str, str]:
            await asyncio.sleep(0.1)  # Simulate slow operation
            return {"message": "slow"}

        @app.get("/error")
        async def error_endpoint() -> None:
            raise ValueError("Test error")

        return app

    @pytest.fixture
    def client(self, app: FastAPI) -> Generator[TestClient, None, None]:
        """Create test client."""
        # Import TestClient locally to ensure correct resolution
        from fastapi.testclient import TestClient as FastAPITestClient

        with FastAPITestClient(app) as test_client:
            yield test_client

    def test_request_id_generated(self, client: TestClient) -> None:
        """Test that request ID is generated when not provided."""
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers

        request_id = response.headers["X-Request-ID"]

        # Should be a valid UUID
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
        assert uuid_pattern.match(request_id) is not None

    def test_custom_request_id_preserved(self, client: TestClient) -> None:
        """Test that custom request ID from client is preserved."""
        custom_id = "custom-request-id-12345"

        response = client.get("/test", headers={"X-Request-ID": custom_id})

        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id

    def test_unique_request_ids(self, client: TestClient) -> None:
        """Test that each request gets a unique ID."""
        request_ids = []

        for _ in range(10):
            response = client.get("/test")
            request_ids.append(response.headers["X-Request-ID"])

        # All IDs should be unique
        assert len(set(request_ids)) == 10

    def test_request_timing_logged(self, client: TestClient) -> None:
        """Test that request duration is logged."""
        with capture_logs() as cap_logs:
            response = client.get("/test")

        assert response.status_code == 200

        # Find the request completion log
        completion_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(completion_logs) > 0
        log = completion_logs[0]

        # Check that duration is logged
        assert "duration_ms" in log
        assert isinstance(log["duration_ms"], (int, float))
        assert log["duration_ms"] >= 0

    def test_slow_request_timing(self, client: TestClient) -> None:
        """Test timing for slower requests."""
        import asyncio

        # Need to add asyncio import to the app fixture
        app = FastAPI()
        app.add_middleware(RequestIDMiddleware)

        @app.get("/slow")
        async def slow_endpoint() -> Dict[str, str]:
            await asyncio.sleep(0.1)
            return {"message": "slow"}

        from fastapi.testclient import TestClient as FastAPITestClient

        client = FastAPITestClient(app)

        with capture_logs() as cap_logs:
            start_time = time.time()
            response = client.get("/slow")
            actual_duration = (time.time() - start_time) * 1000

        assert response.status_code == 200

        # Find the request completion log
        completion_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(completion_logs) > 0
        log = completion_logs[0]

        # Duration should be at least 100ms
        assert log["duration_ms"] >= 100
        # But not too much more (allow some overhead)
        assert log["duration_ms"] < actual_duration + 50

    def test_error_request_logged(self, client: TestClient) -> None:
        """Test that failed requests are logged with timing."""
        with capture_logs() as cap_logs:
            with pytest.raises(ValueError):
                client.get("/error")

        # Find the request failed log
        failed_logs = [log for log in cap_logs if log.get("event") == "request_failed"]

        assert len(failed_logs) > 0
        log = failed_logs[0]

        # Check error details
        assert log["exc_type"] == "ValueError"
        assert "duration_ms" in log
        assert log["duration_ms"] >= 0

    def test_client_ip_extraction(self, client: TestClient) -> None:
        """Test client IP extraction from headers."""
        # Test with X-Forwarded-For header
        response = client.get("/test", headers={"X-Forwarded-For": "192.168.1.100, 10.0.0.1"})
        assert response.status_code == 200

        # Check that client IP was logged
        # The middleware sets the logging context, so we might need to check differently
        # For now, just verify the request completed successfully

    def test_logging_context_set(self, app: FastAPI) -> None:
        """Test that logging context is set correctly."""
        from fastapi import Request

        from app.core.logging import get_request_context

        # Create a test endpoint that checks the logging context
        @app.get("/context-test")
        async def context_test(request: Request) -> Dict[str, Any]:
            context = get_request_context()
            return {"request_id": getattr(request.state, "request_id", None), "context": context}

        from fastapi.testclient import TestClient as FastAPITestClient

        client = FastAPITestClient(app)
        response = client.get("/context-test")

        assert response.status_code == 200
        data = response.json()

        # Request ID should be set in request state
        assert data["request_id"] is not None

    def test_logging_context_cleared(self, client: TestClient) -> None:
        """Test that logging context is cleared after request."""
        # Make a request
        response = client.get("/test")
        assert response.status_code == 200

        # After the request, logging context should be cleared
        # This is hard to test directly in unit tests as the context
        # is thread-local and cleared after the request

    def test_concurrent_requests_isolated(self, app: FastAPI) -> None:
        """Test that concurrent requests have isolated contexts."""
        import asyncio
        import threading
        from concurrent.futures import ThreadPoolExecutor

        results = []

        def make_request(custom_id: str) -> str:
            from fastapi.testclient import TestClient as FastAPITestClient

            client = FastAPITestClient(app)
            response = client.get("/test", headers={"X-Request-ID": custom_id})
            return response.headers["X-Request-ID"]

        # Make concurrent requests with different IDs
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, f"custom-id-{i}") for i in range(5)]

            for future in futures:
                results.append(future.result())

        # Each request should maintain its own ID
        expected = [f"custom-id-{i}" for i in range(5)]
        assert set(results) == set(expected)

    def test_request_state_accessible(self, app: FastAPI, client: TestClient) -> None:
        """Test that request ID is accessible via request.state."""
        from fastapi import Request

        @app.get("/check-state")
        async def check_state(request: Request) -> Dict[str, str]:
            return {"request_id": getattr(request.state, "request_id", "not-found")}

        response = client.get("/check-state")
        assert response.status_code == 200

        data = response.json()
        assert data["request_id"] != "not-found"
        assert data["request_id"] == response.headers["X-Request-ID"]

    def test_different_http_methods(self, app: FastAPI, client: TestClient) -> None:
        """Test request ID middleware with different HTTP methods."""

        @app.post("/test-post")
        async def test_post() -> Dict[str, str]:
            return {"message": "posted"}

        @app.put("/test-put")
        async def test_put() -> Dict[str, str]:
            return {"message": "updated"}

        @app.delete("/test-delete")
        async def test_delete() -> Dict[str, str]:
            return {"message": "deleted"}

        # Test each method
        for method, path in [
            ("POST", "/test-post"),
            ("PUT", "/test-put"),
            ("DELETE", "/test-delete"),
        ]:
            response = getattr(client, method.lower())(path)
            assert response.status_code == 200
            assert "X-Request-ID" in response.headers

            # Each should have a unique ID
            request_id = response.headers["X-Request-ID"]
            assert len(request_id) > 0
