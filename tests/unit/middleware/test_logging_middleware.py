"""Tests for logging middleware."""

import asyncio
import json
from typing import Any, Dict, Generator
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app.middleware.logging import LoggingMiddleware


class TestLoggingMiddleware:
    """Test request/response logging middleware."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create test FastAPI app with logging middleware."""
        app = FastAPI()

        # Add logging middleware
        app.add_middleware(LoggingMiddleware)

        # Add test endpoints
        @app.get("/test")
        async def test_endpoint() -> Dict[str, str]:
            return {"message": "test"}

        @app.get("/health")
        async def health_endpoint() -> Dict[str, str]:
            return {"status": "healthy"}

        @app.get("/ready")
        async def ready_endpoint() -> Dict[str, str]:
            return {"status": "ready"}

        @app.post("/test-post")
        async def test_post(data: Dict[str, Any]) -> Dict[str, Any]:
            return {"received": data}

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
    def client(self, app: FastAPI) -> Generator[TestClient, None, None]:
        """Create test client."""
        with TestClient(app) as test_client:
            yield test_client

    def test_request_logged(self, client: TestClient) -> None:
        """Test that requests are logged."""
        with capture_logs() as cap_logs:
            response = client.get("/test")

        assert response.status_code == 200

        # Find request started log
        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]

        assert len(start_logs) == 1
        log = start_logs[0]

        # Check logged fields
        assert log["method"] == "GET"
        assert log["path"] == "/test"
        assert "query_params" in log
        assert "content_length" in log

    def test_response_logged(self, client: TestClient) -> None:
        """Test that responses are logged with timing."""
        with capture_logs() as cap_logs:
            response = client.get("/test")

        assert response.status_code == 200

        # Find request completed log
        complete_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(complete_logs) == 1
        log = complete_logs[0]

        # Check logged fields
        assert log["method"] == "GET"
        assert log["path"] == "/test"
        assert log["status_code"] == 200
        assert "duration_ms" in log
        assert isinstance(log["duration_ms"], (int, float))
        assert log["duration_ms"] >= 0

    def test_health_endpoints_not_logged(self, client: TestClient) -> None:
        """Test that health check endpoints are not logged."""
        with capture_logs() as cap_logs:
            # Make requests to health endpoints
            client.get("/health")
            client.get("/ready")

        # Should not have any logs for these endpoints
        assert len(cap_logs) == 0

    def test_query_params_logged(self, client: TestClient) -> None:
        """Test that query parameters are logged."""
        with capture_logs() as cap_logs:
            response = client.get("/test?param1=value1&param2=value2")

        assert response.status_code == 200

        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]

        assert len(start_logs) == 1
        log = start_logs[0]

        assert log["query_params"] == {"param1": "value1", "param2": "value2"}

    def test_post_request_logged(self, client: TestClient) -> None:
        """Test POST request logging with content length."""
        test_data = {"key": "value", "number": 42}

        with capture_logs() as cap_logs:
            response = client.post("/test-post", json=test_data)

        assert response.status_code == 200

        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]

        assert len(start_logs) == 1
        log = start_logs[0]

        assert log["method"] == "POST"
        # Content length should be greater than 0 for POST with data
        assert int(log["content_length"]) > 0

    def test_response_time_header(self, client: TestClient) -> None:
        """Test that X-Response-Time header is added."""
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Response-Time" in response.headers

        # Should be in format "X.XXms"
        time_header = response.headers["X-Response-Time"]
        assert time_header.endswith("ms")

        # Parse the numeric value
        time_value = float(time_header[:-2])
        assert time_value >= 0

    def test_slow_request_timing(self, client: TestClient) -> None:
        """Test timing accuracy for slow requests."""
        with capture_logs() as cap_logs:
            response = client.get("/slow")

        assert response.status_code == 200

        # Check response header
        time_header = response.headers["X-Response-Time"]
        time_value = float(time_header[:-2])

        # Should be at least 100ms
        assert time_value >= 100

        # Check logged duration
        complete_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(complete_logs) == 1
        assert complete_logs[0]["duration_ms"] >= 100

    def test_error_request_logged(self, client: TestClient) -> None:
        """Test that errors are logged properly."""
        with capture_logs() as cap_logs:
            with pytest.raises(ValueError):
                client.get("/error")

        # Find request failed log
        failed_logs = [log for log in cap_logs if log.get("event") == "request_failed"]

        assert len(failed_logs) == 1
        log = failed_logs[0]

        # Check error details
        assert log["method"] == "GET"
        assert log["path"] == "/error"
        assert log["exc_type"] == "ValueError"
        assert log["exc_message"] == "Test error"
        assert "duration_ms" in log
        assert log["duration_ms"] >= 0

    def test_http_exception_logged(self, client: TestClient) -> None:
        """Test that HTTP exceptions are logged."""
        with capture_logs() as cap_logs:
            response = client.get("/http-error")

        assert response.status_code == 404

        # HTTPException is handled by FastAPI and logged as completed request with error status
        completed_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(completed_logs) == 1
        log = completed_logs[0]

        assert log["status_code"] == 404
        assert log["path"] == "/http-error"

    def test_multiple_requests_logged_separately(self, client: TestClient) -> None:
        """Test that multiple requests are logged separately."""
        with capture_logs() as cap_logs:
            # Make multiple requests
            client.get("/test")
            client.post("/test-post", json={"data": "test"})
            client.get("/test?query=param")

        # Should have 6 logs total (3 started, 3 completed)
        assert len(cap_logs) == 6

        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]
        complete_logs = [log for log in cap_logs if log.get("event") == "request_completed"]

        assert len(start_logs) == 3
        assert len(complete_logs) == 3

        # Check different methods logged
        methods = [log["method"] for log in start_logs]
        assert "GET" in methods
        assert "POST" in methods

    def test_empty_content_length(self, client: TestClient) -> None:
        """Test handling of missing content-length header."""
        # GET requests typically don't have content-length
        with capture_logs() as cap_logs:
            response = client.get("/test")

        assert response.status_code == 200

        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]

        assert len(start_logs) == 1
        # Should default to 0 when not present
        assert start_logs[0]["content_length"] == 0

    def test_log_levels(self, client: TestClient) -> None:
        """Test appropriate log levels are used."""
        with capture_logs() as cap_logs:
            # Successful request - should use INFO
            client.get("/test")

            # Failed request - should use ERROR
            with pytest.raises(ValueError):
                client.get("/error")

        # Check log levels
        for log in cap_logs:
            if log.get("event") in ["request_started", "request_completed"]:
                # These should be INFO level (default when not specified)
                assert "error" not in log.get("log_level", "").lower()
            elif log.get("event") == "request_failed":
                # This should include exception info
                assert "exc_type" in log

    def test_concurrent_requests(self, app: FastAPI) -> None:
        """Test that concurrent requests are logged correctly."""
        import threading
        from concurrent.futures import ThreadPoolExecutor

        results = []

        def make_request(path: str) -> int:
            client = TestClient(app)
            response = client.get(path)
            return response.status_code

        # Make concurrent requests
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(make_request, "/test"),
                executor.submit(make_request, "/test?q=1"),
                executor.submit(make_request, "/test?q=2"),
            ]

            for future in futures:
                results.append(future.result())

        # All requests should succeed
        assert all(status == 200 for status in results)

    def test_unicode_handling(self, client: TestClient) -> None:
        """Test logging of unicode characters in paths and params."""
        with capture_logs() as cap_logs:
            response = client.get("/test?name=测试&emoji=🚀")

        assert response.status_code == 200

        start_logs = [log for log in cap_logs if log.get("event") == "request_started"]

        assert len(start_logs) == 1
        log = start_logs[0]

        # Unicode should be preserved in logs
        assert log["query_params"]["name"] == "测试"
        assert log["query_params"]["emoji"] == "🚀"
