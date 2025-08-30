"""Enhanced comprehensive tests for request signing functionality.

This test suite provides extensive coverage for request signing,
including HMAC generation, nonce handling, and timestamp validation.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from typing import TYPE_CHECKING, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# TestClient imported via TYPE_CHECKING for type hints only
from starlette.middleware.base import BaseHTTPMiddleware

from app.middleware.request_signing import (
    API_KEY_HEADER,
    MAX_REQUEST_AGE,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIGNED_PATHS,
    TIMESTAMP_HEADER,
    RequestSigner,
    RequestSigningMiddleware,
    get_request_signer,
)
from tests.utils.testclient import SafeTestClient as FastAPITestClient


class TestRequestSigner:
    """Test RequestSigner utility class."""

    def test_request_signer_initialization(self):
        """Test RequestSigner initialization."""
        api_key = "test_key_123"
        api_secret = "test_secret_456"

        signer = RequestSigner(api_key, api_secret)
        assert signer.api_key == api_key
        assert signer.api_secret == api_secret

    def test_sign_request_basic(self):
        """Test basic request signing."""
        signer = RequestSigner("test_key", "test_secret")

        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            query_params={},
            headers={},
            body=b"",
        )

        # Check all required headers are present
        assert API_KEY_HEADER in headers
        assert SIGNATURE_HEADER in headers
        assert TIMESTAMP_HEADER in headers
        assert NONCE_HEADER in headers

        # Validate header values
        assert headers[API_KEY_HEADER] == "test_key"
        assert len(headers[SIGNATURE_HEADER]) == 64  # SHA256 hex digest
        assert headers[TIMESTAMP_HEADER].isdigit()
        assert len(headers[NONCE_HEADER]) > 0

    def test_sign_request_with_body(self):
        """Test signing request with body."""
        signer = RequestSigner("test_key", "test_secret")

        body = json.dumps({"data": "test"}).encode()
        headers = signer.sign_request(
            method="POST",
            path="/api/v1/users",
            body=body,
        )

        # Signature should be different with body
        headers_no_body = signer.sign_request(
            method="POST",
            path="/api/v1/users",
            body=b"",
        )

        assert headers[SIGNATURE_HEADER] != headers_no_body[SIGNATURE_HEADER]

    def test_sign_request_with_query_params(self):
        """Test signing request with query parameters."""
        signer = RequestSigner("test_key", "test_secret")

        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            query_params={"page": "1", "limit": "10"},
        )

        # Signature should include query params
        headers_no_params = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            query_params={},
        )

        assert headers[SIGNATURE_HEADER] != headers_no_params[SIGNATURE_HEADER]

    def test_sign_request_canonical_ordering(self):
        """Test that canonical request maintains consistent ordering."""
        signer = RequestSigner("test_key", "test_secret")

        # Same params in different order should produce same signature
        headers1 = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            query_params={"b": "2", "a": "1", "c": "3"},
        )

        headers2 = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            query_params={"c": "3", "a": "1", "b": "2"},
        )

        # Timestamps and nonces will differ, but algorithm should be consistent
        # Test by recreating with same timestamp/nonce
        with patch("time.time", return_value=1234567890):
            with patch("secrets.token_urlsafe", return_value="test_nonce"):
                h1 = signer.sign_request(
                    method="GET",
                    path="/api/v1/users",
                    query_params={"b": "2", "a": "1"},
                )
                h2 = signer.sign_request(
                    method="GET",
                    path="/api/v1/users",
                    query_params={"a": "1", "b": "2"},
                )
                assert h1[SIGNATURE_HEADER] == h2[SIGNATURE_HEADER]

    def test_sign_request_different_methods(self):
        """Test signing with different HTTP methods."""
        signer = RequestSigner("test_key", "test_secret")

        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        signatures = {}

        with patch("time.time", return_value=1234567890):
            with patch("secrets.token_urlsafe", return_value="test_nonce"):
                for method in methods:
                    headers = signer.sign_request(
                        method=method,
                        path="/api/v1/resource",
                    )
                    signatures[method] = headers[SIGNATURE_HEADER]

        # All methods should produce different signatures
        assert len(set(signatures.values())) == len(methods)

    def test_get_request_signer_factory(self):
        """Test get_request_signer factory function."""
        signer = get_request_signer("key", "secret")
        assert isinstance(signer, RequestSigner)
        assert signer.api_key == "key"
        assert signer.api_secret == "secret"


@pytest.mark.asyncio
class TestRequestSigningMiddleware:
    """Test RequestSigningMiddleware functionality."""

    @pytest.fixture
    async def mock_app(self):
        """Create mock ASGI app."""

        async def app(scope, receive, send):
            assert scope["type"] == "http"
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"application/json"]],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"status": "ok"}',
                }
            )

        return app

    @pytest.fixture
    async def middleware(self, mock_app):
        """Create middleware instance."""
        with patch("app.middleware.request_signing.get_cache_client") as mock_cache:
            mock_cache.return_value = AsyncMock()
            return RequestSigningMiddleware(mock_app)

    async def test_unsigned_path_passthrough(self, middleware):
        """Test that unsigned paths pass through without checking."""
        # Create request to unsigned path
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/health"  # Not in SIGNED_PATHS
        request.headers = {}

        async def call_next(req):
            return Response(content="OK", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200

    async def test_signed_path_without_headers(self, middleware):
        """Test signed path without required headers returns 401."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/admin/users"  # In SIGNED_PATHS
        request.headers = {}  # Missing all headers

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

        # Parse response
        body = json.loads(response.body.decode())
        assert "Request signing required" in body["detail"]

    async def test_signed_path_with_partial_headers(self, middleware):
        """Test signed path with incomplete headers returns 401."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/users/create"
        request.headers = {
            SIGNATURE_HEADER: "some_signature",
            TIMESTAMP_HEADER: str(int(time.time())),
            # Missing API_KEY_HEADER and NONCE_HEADER
        }

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

    async def test_expired_timestamp(self, middleware):
        """Test request with expired timestamp returns 401."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/admin/settings"
        request.headers = {
            SIGNATURE_HEADER: "signature",
            TIMESTAMP_HEADER: str(int(time.time()) - MAX_REQUEST_AGE - 1),  # Expired
            API_KEY_HEADER: "test_key",
            NONCE_HEADER: "test_nonce",
        }

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

        body = json.loads(response.body.decode())
        assert "timestamp expired" in body["detail"]

    async def test_future_timestamp(self, middleware):
        """Test request with future timestamp (clock skew)."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/admin/settings"
        request.headers = {
            SIGNATURE_HEADER: "signature",
            TIMESTAMP_HEADER: str(int(time.time()) + MAX_REQUEST_AGE + 1),  # Future
            API_KEY_HEADER: "test_key",
            NONCE_HEADER: "test_nonce",
        }

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

    async def test_invalid_timestamp_format(self, middleware):
        """Test request with invalid timestamp format."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/admin/settings"
        request.headers = {
            SIGNATURE_HEADER: "signature",
            TIMESTAMP_HEADER: "not-a-number",
            API_KEY_HEADER: "test_key",
            NONCE_HEADER: "test_nonce",
        }

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 400

        body = json.loads(response.body.decode())
        assert "Invalid timestamp" in body["detail"]

    async def test_nonce_replay_detection(self, middleware):
        """Test that replayed nonces are rejected."""
        # Set up cache to return that nonce exists
        middleware.cache.get = AsyncMock(return_value="used")

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/admin/settings"
        request.headers = {
            SIGNATURE_HEADER: "signature",
            TIMESTAMP_HEADER: str(int(time.time())),
            API_KEY_HEADER: "test_key",
            NONCE_HEADER: "already_used_nonce",
        }

        async def call_next(req):
            return Response(content="Should not reach", status_code=200)

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

        body = json.loads(response.body.decode())
        assert "Nonce replay detected" in body["detail"]

    async def test_invalid_api_key(self, middleware):
        """Test request with invalid API key."""
        # Mock _get_api_secret to return None
        with patch.object(middleware, "_get_api_secret", return_value=None):
            request = MagicMock(spec=Request)
            request.url.path = "/api/v1/admin/settings"
            request.headers = {
                SIGNATURE_HEADER: "signature",
                TIMESTAMP_HEADER: str(int(time.time())),
                API_KEY_HEADER: "invalid_key",
                NONCE_HEADER: "test_nonce",
            }

            async def call_next(req):
                return Response(content="Should not reach", status_code=200)

            response = await middleware.dispatch(request, call_next)
            assert response.status_code == 401

            body = json.loads(response.body.decode())
            assert "Invalid API key" in body["detail"]

    async def test_invalid_signature(self, middleware):
        """Test request with invalid signature."""
        # Set up valid API key
        with patch.object(middleware, "_get_api_secret", return_value="test_secret"):
            with patch.object(middleware, "_is_nonce_replayed", return_value=False):
                request = MagicMock(spec=Request)
                request.url.path = "/api/v1/admin/settings"
                request.method = "GET"
                request.url.query = ""
                request.query_params = {}
                request.headers = {
                    SIGNATURE_HEADER: "invalid_signature",
                    TIMESTAMP_HEADER: str(int(time.time())),
                    API_KEY_HEADER: "test_key",
                    NONCE_HEADER: "test_nonce",
                    "host": "example.com",
                    "content-type": "application/json",
                }
                request.body = AsyncMock(return_value=b"")

                # Mock has_cached_body and get_cached_body
                with patch("app.middleware.request_signing.has_cached_body", return_value=False):

                    async def call_next(req):
                        return Response(content="Should not reach", status_code=200)

                    response = await middleware.dispatch(request, call_next)
                    assert response.status_code == 403

                    body = json.loads(response.body.decode())
                    assert "Invalid signature" in body["detail"]

    async def test_valid_signature_accepted(self, middleware):
        """Test request with valid signature is accepted."""
        api_key = "test_key"
        api_secret = "test_secret"
        signer = RequestSigner(api_key, api_secret)

        # Create properly signed request
        body = b'{"data": "test"}'
        headers = signer.sign_request(
            method="POST",
            path="/api/v1/admin/settings",
            headers={
                "content-type": "application/json",
                "host": "example.com",
            },
            body=body,
        )

        # Set up middleware mocks
        with patch.object(middleware, "_get_api_secret", return_value=api_secret):
            with patch.object(middleware, "_is_nonce_replayed", return_value=False):
                with patch.object(middleware, "_store_nonce", return_value=None):
                    request = MagicMock(spec=Request)
                    request.url.path = "/api/v1/admin/settings"
                    request.method = "POST"
                    request.url.query = ""
                    request.query_params = {}
                    request.headers = {
                        **headers,
                        "content-type": "application/json",
                        "host": "example.com",
                    }
                    request.body = AsyncMock(return_value=body)
                    request.state = MagicMock()

                    with patch(
                        "app.middleware.request_signing.has_cached_body",
                        return_value=False,
                    ):

                        async def call_next(req):
                            # Verify state was set
                            assert req.state.api_key == api_key
                            assert req.state.signature_verified is True
                            return Response(content="Success", status_code=200)

                        response = await middleware.dispatch(request, call_next)
                        assert response.status_code == 200

    async def test_canonical_request_generation(self, middleware):
        """Test canonical request string generation."""
        # Test the _create_canonical_request method
        canonical = middleware._create_canonical_request(
            method="POST",
            path="/api/v1/users",
            query_params={"b": "2", "a": "1"},
            headers={
                "content-type": "application/json",
                "host": "api.example.com",
                "x-custom": "ignored",  # Not in signed headers
            },
            body=b'{"test": "data"}',
            timestamp="1234567890",
            nonce="test_nonce_123",
        )

        # Verify canonical format
        lines = canonical.split("\n")
        assert lines[0] == "POST"  # Method
        assert lines[1] == "/api/v1/users"  # Path
        assert lines[2] == "a=1&b=2"  # Sorted query params
        assert "content-type:application/json" in canonical
        assert "host:api.example.com" in canonical
        assert "x-custom" not in canonical  # Not signed
        assert "1234567890" in canonical  # Timestamp
        assert "test_nonce_123" in canonical  # Nonce

        # Body hash should be consistent
        body_hash = hashlib.sha256(b'{"test": "data"}').hexdigest()
        assert body_hash in canonical


class TestRequestSigningEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_cache_unavailable(self):
        """Test behavior when cache is unavailable."""
        app = FastAPI()

        # Middleware with no cache
        with patch("app.middleware.request_signing.get_cache_client", return_value=None):
            middleware = RequestSigningMiddleware(app)

            # Should log warning but allow request
            assert await middleware._is_nonce_replayed("nonce", "key") is False

            # Store should not crash
            await middleware._store_nonce("nonce", "key")

    @pytest.mark.asyncio
    async def test_cache_errors(self):
        """Test handling of cache errors."""
        app = FastAPI()
        middleware = RequestSigningMiddleware(app)

        # Mock cache to raise errors
        middleware.cache = AsyncMock()
        middleware.cache.get.side_effect = Exception("Cache error")
        middleware.cache.set.side_effect = Exception("Cache error")

        # Should handle gracefully
        result = await middleware._is_nonce_replayed("nonce", "key")
        assert result is False  # Fails open

        # Store should not crash
        await middleware._store_nonce("nonce", "key")

    def test_empty_body_handling(self):
        """Test signing with empty body."""
        signer = RequestSigner("key", "secret")

        # Empty body should work
        headers1 = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            body=b"",
        )

        # None body should be treated as empty
        headers2 = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            body=None,
        )

        # Both should work
        assert SIGNATURE_HEADER in headers1
        assert SIGNATURE_HEADER in headers2

    def test_special_characters_in_params(self):
        """Test signing with special characters in parameters."""
        signer = RequestSigner("key", "secret")

        # Special characters in query params
        headers = signer.sign_request(
            method="GET",
            path="/api/v1/search",
            query_params={
                "q": "test & test",
                "filter": "name='value'",
                "unicode": "café",
            },
        )

        assert SIGNATURE_HEADER in headers
        assert len(headers[SIGNATURE_HEADER]) == 64

    @pytest.mark.asyncio
    async def test_concurrent_nonce_checks(self):
        """Test concurrent nonce checks don't cause race conditions."""
        app = FastAPI()
        middleware = RequestSigningMiddleware(app)
        middleware.cache = AsyncMock()
        middleware.cache.get.return_value = None  # Not replayed

        # Simulate concurrent checks for same nonce
        nonce = "concurrent_nonce"
        api_key = "test_key"

        tasks = [middleware._is_nonce_replayed(nonce, api_key) for _ in range(10)]

        results = await asyncio.gather(*tasks)

        # All should return False (not replayed)
        assert all(r is False for r in results)

    def test_signature_timing_attack_resistance(self):
        """Test that signature comparison is timing-attack resistant."""
        import timeit

        app = FastAPI()
        middleware = RequestSigningMiddleware(app)

        correct_sig = "a" * 64
        wrong_sig_similar = "a" * 63 + "b"  # Differs at end
        wrong_sig_different = "b" * 64  # Completely different

        # Time comparisons
        def time_comparison(sig1, sig2):
            return timeit.timeit(lambda: hmac.compare_digest(sig1, sig2), number=10000)

        # Times should be similar (constant-time comparison)
        time_similar = time_comparison(correct_sig, wrong_sig_similar)
        time_different = time_comparison(correct_sig, wrong_sig_different)

        # Difference should be minimal (< 10% variance)
        variance = abs(time_similar - time_different) / min(time_similar, time_different)
        assert variance < 0.1


class TestRequestSigningIntegration:
    """Integration tests for request signing."""

    @pytest.mark.asyncio
    async def test_full_signing_flow(self):
        """Test complete signing flow with FastAPI."""
        app = FastAPI()

        # Add middleware
        app.add_middleware(RequestSigningMiddleware)

        # Add signed endpoint
        @app.post("/api/v1/admin/action")
        async def admin_action(request: Request):
            # Check that signing info is in state
            assert hasattr(request.state, "api_key")
            assert hasattr(request.state, "signature_verified")
            assert request.state.signature_verified is True
            return {"status": "success", "api_key": request.state.api_key}

        # Create client and signer
        api_key = "test_key"
        api_secret = "test_secret"
        signer = RequestSigner(api_key, api_secret)

        with FastAPITestClient(app) as client:
            # Unsigned request should fail
            response = client.post("/api/v1/admin/action", json={"data": "test"})
            assert response.status_code == 401

            # Signed request should succeed
            body = json.dumps({"data": "test"}).encode()
            headers = signer.sign_request(
                method="POST",
                path="/api/v1/admin/action",
                headers={
                    "content-type": "application/json",
                    "host": "testserver",
                },
                body=body,
            )

            # Mock the API secret lookup
            with patch(
                "app.middleware.request_signing.RequestSigningMiddleware._get_api_secret",
                return_value=api_secret,
            ):
                response = client.post(
                    "/api/v1/admin/action",
                    json={"data": "test"},
                    headers=headers,
                )

                # Should succeed
                assert response.status_code == 200
                assert response.json()["status"] == "success"
                assert response.json()["api_key"] == api_key

    @pytest.mark.asyncio
    async def test_signing_with_different_content_types(self):
        """Test signing with various content types."""
        signer = RequestSigner("key", "secret")

        # JSON content
        json_body = json.dumps({"key": "value"}).encode()
        json_headers = signer.sign_request(
            method="POST",
            path="/api/v1/data",
            headers={"content-type": "application/json"},
            body=json_body,
        )

        # Form data
        form_body = b"key=value&other=data"
        form_headers = signer.sign_request(
            method="POST",
            path="/api/v1/data",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=form_body,
        )

        # Different content types should produce different signatures
        assert json_headers[SIGNATURE_HEADER] != form_headers[SIGNATURE_HEADER]

    @pytest.mark.asyncio
    async def test_signing_preserves_other_headers(self):
        """Test that signing preserves other request headers."""
        app = FastAPI()
        app.add_middleware(RequestSigningMiddleware)

        @app.get("/api/v1/users/me")
        async def get_user(request: Request):
            # Check custom headers are preserved
            assert request.headers.get("x-custom-header") == "custom-value"
            assert request.headers.get("user-agent") == "TestClient/1.0"
            return {"user": "data"}

        with FastAPITestClient(app) as client:
            signer = RequestSigner("test_key", "test_secret")

            # Sign request
            signing_headers = signer.sign_request(
                method="GET",
                path="/api/v1/users/me",
                headers={"host": "testserver"},
            )

            # Add custom headers
            all_headers = {
                **signing_headers,
                "X-Custom-Header": "custom-value",
                "User-Agent": "TestClient/1.0",
            }

            with patch(
                "app.middleware.request_signing.RequestSigningMiddleware._get_api_secret",
                return_value="test_secret",
            ):
                response = client.get("/api/v1/users/me", headers=all_headers)
                assert response.status_code == 200


class TestRequestSigningConfiguration:
    """Test request signing configuration options."""

    def test_signed_paths_configuration(self):
        """Test SIGNED_PATHS configuration."""
        # Verify expected paths are configured
        assert "/api/v1/admin/" in SIGNED_PATHS
        assert "/api/v1/users/" in SIGNED_PATHS
        assert "/api/v1/api-keys/" in SIGNED_PATHS

        # Health endpoints should not be signed
        assert "/api/v1/health" not in SIGNED_PATHS
        assert "/api/v1/ready" not in SIGNED_PATHS

    def test_max_request_age_configuration(self):
        """Test MAX_REQUEST_AGE is reasonable."""
        # Should be between 1 minute and 1 hour
        assert 60 <= MAX_REQUEST_AGE <= 3600
        # Default is 5 minutes
        assert MAX_REQUEST_AGE == 300

    def test_header_names_configuration(self):
        """Test header names follow conventions."""
        # Should use X- prefix for custom headers
        assert SIGNATURE_HEADER.startswith("X-")
        assert TIMESTAMP_HEADER.startswith("X-")
        assert API_KEY_HEADER.startswith("X-")
        assert NONCE_HEADER.startswith("X-")

        # Should not conflict with standard headers
        standard_headers = [
            "Authorization",
            "Content-Type",
            "Accept",
            "User-Agent",
            "Host",
            "Content-Length",
        ]

        custom_headers = [
            SIGNATURE_HEADER,
            TIMESTAMP_HEADER,
            API_KEY_HEADER,
            NONCE_HEADER,
        ]

        for custom in custom_headers:
            assert custom not in standard_headers


class TestRequestSigningPerformance:
    """Test performance characteristics of request signing."""

    def test_signature_generation_performance(self):
        """Test that signature generation is fast."""
        import time

        signer = RequestSigner("key", "secret")
        iterations = 1000

        # Time signature generation
        start = time.perf_counter()
        for i in range(iterations):
            signer.sign_request(
                method="POST",
                path=f"/api/v1/users/{i}",
                body=f"data-{i}".encode(),
            )
        duration = time.perf_counter() - start

        # Should be fast (< 1ms per signature)
        avg_time = duration / iterations
        assert avg_time < 0.001, f"Signature generation too slow: {avg_time:.6f}s"

    @pytest.mark.asyncio
    async def test_middleware_overhead(self):
        """Test middleware performance overhead."""
        import time

        app = FastAPI()

        # Endpoint without middleware
        @app.get("/unsigned")
        async def unsigned():
            return {"status": "ok"}

        # Endpoint with middleware
        app_with_middleware = FastAPI()
        app_with_middleware.add_middleware(RequestSigningMiddleware)

        @app_with_middleware.get("/unsigned")
        async def unsigned_with_middleware():
            return {"status": "ok"}

        # Measure performance difference
        iterations = 100

        # Without middleware
        with FastAPITestClient(app) as client:
            start = time.perf_counter()
            for _ in range(iterations):
                client.get("/unsigned")
            time_without = time.perf_counter() - start

        # With middleware (unsigned path)
        with FastAPITestClient(app_with_middleware) as client:
            start = time.perf_counter()
            for _ in range(iterations):
                client.get("/unsigned")
            time_with = time.perf_counter() - start

        # Overhead should be minimal for unsigned paths
        overhead = time_with - time_without
        overhead_percent = (overhead / time_without) * 100
        assert overhead_percent < 20, f"Middleware overhead too high: {overhead_percent:.2f}%"
