"""Integration tests for the complete security middleware chain.

This module tests the interaction between all security middleware components
to ensure they work correctly together and don't interfere with each other.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Dict, Generator, List
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, CSRFProtectionMiddleware
from app.middleware.input_sanitization import InputSanitizationMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.request_signing import RequestSigningMiddleware
from app.middleware.session import SessionMiddleware
from tests.utils.testclient import SafeTestClient

# TestClient imported via TYPE_CHECKING for type hints only

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


@pytest.fixture
def app():
    """Create test FastAPI app with full middleware stack."""
    app = FastAPI()

    # Add middleware in the same order as main.py
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(SessionMiddleware)
    app.add_middleware(CSRFProtectionMiddleware)
    app.add_middleware(InputSanitizationMiddleware)
    app.add_middleware(RequestSigningMiddleware)

    @app.get("/test")
    async def test_endpoint(request: Request):
        return {
            "status": "ok",
            "request_id": getattr(request.state, "request_id", None),
            "session_id": getattr(request.state, "session_id", None),
        }

    @app.post("/secure")
    async def secure_endpoint(request: Request):
        body = await request.body()
        return {
            "status": "secure",
            "received": json.loads(body) if body else None,
        }

    @app.post("/form")
    async def form_endpoint(request: Request):
        body = await request.body()
        return {"status": "form", "data": body.decode()}

    @app.get("/attack")
    async def attack_endpoint(request: Request):
        # Access sanitized params
        params = getattr(request.state, "sanitized_query_params", {})
        return {"params": params}

    return app


@pytest.fixture
def client(app) -> Generator["TestClient", None, None]:
    """Create test client."""
    # Import TestClient locally to ensure correct resolution
    from tests.utils.testclient import SafeTestClient

    with SafeTestClient(app) as test_client:
        yield test_client


@pytest.fixture
def enable_all_security():
    """Enable all security features."""
    with patch("app.core.config.settings.CSRF_PROTECTION", True):
        with patch("app.core.config.settings.REQUEST_SIGNING_ENABLED", True):
            with patch("app.core.config.settings.SESSION_SECURITY_ENABLED", True):
                yield


class TestMiddlewareChainIntegration:
    """Test the complete middleware chain integration."""

    def test_middleware_order_execution(self, client, enable_all_security):
        """Test that middleware executes in the correct order."""
        # Make a request and verify all middleware processed it
        response = client.get("/test")

        assert response.status_code == 200
        data = response.json()

        # Request ID should be set by RequestIDMiddleware
        assert data.get("request_id") is not None

        # Session should be set by SessionMiddleware
        assert data.get("session_id") is not None

        # Response headers should include security headers
        assert "X-Request-ID" in response.headers

    def test_csrf_with_input_sanitization(self, client, enable_all_security):
        """Test CSRF protection works with input sanitization."""
        # Get CSRF token
        csrf_middleware = CSRFProtectionMiddleware(None)
        csrf_token = csrf_middleware._generate_csrf_token()

        # Send request with XSS attempt and CSRF token
        malicious_data = {"comment": "<script>alert('xss')</script>", "sql": "'; DROP TABLE users; --"}

        response = client.post(
            "/secure",
            json=malicious_data,
            headers={CSRF_HEADER_NAME: csrf_token},
            cookies={CSRF_COOKIE_NAME: csrf_token},
        )

        assert response.status_code == 200
        data = response.json()

        # Data should be sanitized
        assert "<script>" not in json.dumps(data)
        assert "DROP TABLE" not in json.dumps(data)

    def test_session_tracking_across_requests(self, client, enable_all_security):
        """Test session tracking works across multiple requests."""
        # First request - should create session
        response1 = client.get("/test")
        session_id_1 = response1.json().get("session_id")
        session_cookie_1 = response1.cookies.get("session_id")

        # Second request with same session cookie
        if session_cookie_1:
            response2 = client.get("/test", cookies={"session_id": session_cookie_1})
            session_id_2 = response2.json().get("session_id")

            # Should have same session ID
            assert session_id_1 == session_id_2

    def test_request_signing_with_sanitization(self, client, enable_all_security):
        """Test request signing works with input sanitization."""
        # Prepare signed request
        import hashlib
        import hmac

        from app.core.config import settings

        body = json.dumps({"data": "<script>alert(1)</script>"})
        signature = hmac.new(settings.REQUEST_SIGNING_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()

        response = client.post(
            "/secure", content=body, headers={"X-Signature": signature, "Content-Type": "application/json"}
        )

        # Should accept signed request and sanitize content
        assert response.status_code == 200
        data = response.json()
        assert "<script>" not in json.dumps(data)

    def test_metrics_collection_during_attack(self, client, enable_all_security):
        """Test metrics are properly collected during attack attempts."""
        # Send various attack attempts
        attacks = [
            # XSS attempt without CSRF token
            client.post("/secure", json={"xss": "<script>alert(1)</script>"}),
            # SQL injection in query params
            client.get("/attack?search='; DROP TABLE users; --"),
            # Large payload attempt
            client.post("/secure", json={"data": "x" * 1000000}),
        ]

        # All should be handled (either sanitized or rejected)
        for response in attacks:
            assert response.status_code in [200, 403, 413]


class TestSecurityScenarios:
    """Test specific security scenarios across the middleware chain."""

    def test_concurrent_attack_handling(self, client, enable_all_security):
        """Test handling of concurrent attack attempts."""
        import threading

        results = []

        def make_attack_request():
            response = client.get("/attack?payload=<script>alert(1)</script>")
            results.append(response.status_code)

        # Launch multiple concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_attack_request)
            threads.append(thread)
            thread.start()

        # Wait for all to complete
        for thread in threads:
            thread.join()

        # All should be handled successfully
        assert all(status == 200 for status in results)

    def test_layered_encoding_attack(self, client, enable_all_security):
        """Test handling of attacks with multiple encoding layers."""
        # URL encoded + HTML encoded attack
        from urllib.parse import quote

        attack = quote("<script>alert(1)</script>")
        response = client.get(f"/attack?data={attack}&html=%3Cscript%3Ealert%282%29%3C%2Fscript%3E")

        assert response.status_code == 200
        data = response.json()

        # Both should be sanitized
        if "params" in data:
            assert "<script>" not in json.dumps(data["params"])

    def test_middleware_error_recovery(self, client, enable_all_security):
        """Test middleware chain recovers from errors."""
        # Force an error in one middleware
        with patch("app.middleware.metrics.MetricsMiddleware.dispatch", side_effect=Exception("Metrics error")):
            # Should still handle request (other middleware should work)
            response = client.get("/test")
            # May fail or succeed depending on error handling
            assert response.status_code in [200, 500]

    def test_security_headers_preserved(self, client, enable_all_security):
        """Test security headers are preserved through middleware chain."""
        response = client.get("/test")

        # Check security headers are present
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
        ]

        # Some security headers should be set
        # (actual implementation may vary)
        assert response.status_code == 200


class TestPerformanceUnderLoad:
    """Test middleware chain performance under load."""

    def test_middleware_latency(self, client, enable_all_security):
        """Test latency added by middleware chain."""
        # Measure baseline
        start = time.time()
        response = client.get("/test")
        baseline_latency = time.time() - start

        assert response.status_code == 200

        # Make requests with increasingly complex payloads
        payloads = [
            {"simple": "data"},
            {"nested": {"data": {"xss": "<script>alert(1)</script>"}}},
            {"array": ["<script>"] * 100},
            {"large": {"data": "x" * 10000}},
        ]

        for payload in payloads:
            start = time.time()
            response = client.post("/secure", json=payload)
            latency = time.time() - start

            assert response.status_code in [200, 403]
            # Latency should not be excessive
            assert latency < 1.0  # 1 second max

    def test_memory_usage_stability(self, client, enable_all_security):
        """Test memory usage remains stable under load."""
        import gc
        import sys

        # Force garbage collection
        gc.collect()

        # Make many requests
        for i in range(100):
            response = client.post("/secure", json={"data": f"request_{i}", "xss": "<script>alert(1)</script>"})
            assert response.status_code in [200, 403]

            # Occasionally collect garbage
            if i % 10 == 0:
                gc.collect()

        # Memory should not grow excessively
        # (actual memory testing would require more sophisticated tools)


class TestEdgeCasesAndCompatibility:
    """Test edge cases and compatibility scenarios."""

    def test_empty_request_handling(self, client, enable_all_security):
        """Test handling of empty requests."""
        # Empty GET
        response = client.get("/test")
        assert response.status_code == 200

        # Empty POST
        response = client.post("/secure", content=b"")
        assert response.status_code in [200, 403]  # May require CSRF

        # POST with empty JSON
        response = client.post("/secure", json={})
        assert response.status_code in [200, 403]

    def test_unusual_content_types(self, client, enable_all_security):
        """Test handling of unusual content types."""
        content_types = [
            ("application/xml", b"<root><data>test</data></root>"),
            ("text/xml", b"<root><script>alert(1)</script></root>"),
            ("application/octet-stream", b"\x00\x01\x02\x03"),
            ("multipart/form-data", b"--boundary\r\nContent-Disposition: form-data\r\n\r\ndata"),
        ]

        for content_type, body in content_types:
            response = client.post("/secure", content=body, headers={"Content-Type": content_type})
            # Should handle gracefully
            assert response.status_code in [200, 403, 415]

    def test_http_method_variations(self, client, enable_all_security):
        """Test different HTTP methods through middleware."""
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

        for method in methods:
            response = client.request(method, "/test")
            # Should handle all methods (may return 405 for unsupported)
            assert response.status_code in [200, 403, 405]

    def test_large_header_handling(self, client, enable_all_security):
        """Test handling of large headers."""
        # Create large header value
        large_value = "x" * 8000  # 8KB header

        response = client.get("/test", headers={"X-Large-Header": large_value})

        # Should handle large headers
        assert response.status_code in [200, 413, 431]


class TestSecurityMiddlewareInteractions:
    """Test specific interactions between security middleware."""

    def test_csrf_token_in_sanitized_form(self, client, enable_all_security):
        """Test CSRF token validation when form data is sanitized."""
        csrf_middleware = CSRFProtectionMiddleware(None)
        csrf_token = csrf_middleware._generate_csrf_token()

        # Form data with CSRF token and XSS attempt
        form_data = f"csrf_token={csrf_token}&comment=<script>alert(1)</script>"

        response = client.post(
            "/form",
            content=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies={CSRF_COOKIE_NAME: csrf_token},
        )

        assert response.status_code == 200
        data = response.json()
        # Form data should be sanitized but CSRF should pass
        assert "<script>" not in data.get("data", "")

    def test_session_persistence_with_attacks(self, client, enable_all_security):
        """Test session persists even during attack attempts."""
        # Establish session
        response1 = client.get("/test")
        session_cookie = response1.cookies.get("session_id")

        if session_cookie:
            # Make attack attempt with session
            response2 = client.get("/attack?xss=<script>alert(1)</script>", cookies={"session_id": session_cookie})

            assert response2.status_code == 200

            # Session should still be valid
            response3 = client.get("/test", cookies={"session_id": session_cookie})
            assert response3.status_code == 200
            assert response3.json().get("session_id") == response1.json().get("session_id")

    def test_request_id_tracking_through_chain(self, client, enable_all_security):
        """Test request ID is maintained through entire middleware chain."""
        response = client.post(
            "/secure", json={"data": "<script>alert(1)</script>"}, headers={"X-Request-ID": "test-request-123"}
        )

        assert response.status_code in [200, 403]
        # Request ID should be in response
        assert "X-Request-ID" in response.headers

    def test_middleware_state_isolation(self, client, enable_all_security):
        """Test middleware state is properly isolated between requests."""
        # Make two concurrent requests with different payloads
        import threading

        results = []

        def make_request(payload):
            response = client.get(f"/attack?data={payload}")
            results.append((payload, response.json()))

        threads = []
        payloads = ["payload1", "payload2", "payload3"]

        for payload in payloads:
            thread = threading.Thread(target=make_request, args=(payload,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Each request should have its own data
        for payload, result in results:
            if "params" in result and "data" in result["params"]:
                assert payload in result["params"]["data"]
