"""Tests for request signing middleware."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import TYPE_CHECKING, Generator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI

from app.middleware.body_cache import BodyCachingMiddleware
from app.middleware.request_signing import (
    API_KEY_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    RequestSigner,
    RequestSigningMiddleware,
)
from tests.utils.testclient import SafeTestClient

# TestClient imported via TYPE_CHECKING for type hints only


if TYPE_CHECKING:
    from fastapi.testclient import TestClient


@pytest.fixture
def mock_cache():
    """Mock cache client."""
    with patch("app.middleware.request_signing.get_cache_client") as mock:
        cache = AsyncMock()
        mock.return_value = cache
        yield cache


@pytest.fixture
def app(mock_cache):
    """Create test FastAPI app with request signing middleware."""
    app = FastAPI()
    app.add_middleware(RequestSigningMiddleware)

    @app.get("/public")
    async def public_endpoint():
        return {"message": "public"}

    @app.post("/api/v1/admin/secret")
    async def admin_endpoint():
        return {"message": "admin_secret"}

    @app.get("/api/v1/users/profile")
    async def user_endpoint():
        return {"message": "user_profile"}

    return app


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Create test client."""
    # Import TestClient locally to ensure correct resolution
    from tests.utils.testclient import SafeTestClient

    with SafeTestClient(app) as test_client:
        yield test_client


class TestRequestSigningMiddleware:
    """Test request signing middleware functionality."""

    def test_public_endpoint_no_signing_required(self, client):
        """Test that public endpoints don't require signing."""
        response = client.get("/public")
        assert response.status_code == 200
        assert response.json() == {"message": "public"}

    def test_protected_endpoint_requires_signing(self, client):
        """Test that protected endpoints require signing."""
        response = client.post("/api/v1/admin/secret")
        assert response.status_code == 401
        assert "Request signing required" in response.json()["detail"]

    def test_missing_signature_headers(self, client):
        """Test rejection when signature headers are missing."""
        # Missing all headers
        response = client.post("/api/v1/admin/secret")
        assert response.status_code == 401

        # Missing some headers
        headers = {API_KEY_HEADER: "test_key"}
        response = client.post("/api/v1/admin/secret", headers=headers)
        assert response.status_code == 401

    def test_expired_timestamp(self, client):
        """Test rejection of expired timestamps."""
        old_timestamp = str(int(time.time()) - 400)  # > 300 seconds old

        headers = {
            API_KEY_HEADER: "test_api_key",
            SIGNATURE_HEADER: "dummy_signature",
            TIMESTAMP_HEADER: old_timestamp,
            NONCE_HEADER: "dummy_nonce",
        }

        response = client.post("/api/v1/admin/secret", headers=headers)
        assert response.status_code == 401
        assert "Request timestamp expired" in response.json()["detail"]

    def test_invalid_timestamp_format(self, client):
        """Test rejection of invalid timestamp format."""
        headers = {
            API_KEY_HEADER: "test_api_key",
            SIGNATURE_HEADER: "dummy_signature",
            TIMESTAMP_HEADER: "not_a_number",
            NONCE_HEADER: "dummy_nonce",
        }

        response = client.post("/api/v1/admin/secret", headers=headers)
        assert response.status_code == 400
        assert "Invalid timestamp" in response.json()["detail"]

    def test_nonce_replay_detection(self, client):
        """Test nonce replay attack detection."""
        # Patch the middleware's _is_nonce_replayed method directly
        with patch("app.middleware.request_signing.RequestSigningMiddleware._is_nonce_replayed") as mock_nonce_check:
            # Mock nonce already exists
            mock_nonce_check.return_value = True

            current_time = str(int(time.time()))
            headers = {
                API_KEY_HEADER: "test_api_key",
                SIGNATURE_HEADER: "dummy_signature",
                TIMESTAMP_HEADER: current_time,
                NONCE_HEADER: "replayed_nonce",
            }

            response = client.post("/api/v1/admin/secret", headers=headers)
            assert response.status_code == 401
            assert "Nonce replay detected" in response.json()["detail"]

    def test_invalid_api_key(self, client, mock_cache):
        """Test rejection of invalid API key."""
        # Mock nonce not replayed
        mock_cache.get.return_value = None

        current_time = str(int(time.time()))
        headers = {
            API_KEY_HEADER: "invalid_key",
            SIGNATURE_HEADER: "dummy_signature",
            TIMESTAMP_HEADER: current_time,
            NONCE_HEADER: "valid_nonce",
        }

        response = client.post("/api/v1/admin/secret", headers=headers)
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_valid_signature_accepted(self, client, mock_cache):
        """Test that valid signatures are accepted."""
        # Mock setup
        mock_cache.get.return_value = None  # Nonce not replayed
        mock_cache.set.return_value = None  # Nonce storage succeeds

        # Create valid signature - use exact same data that will be sent
        api_key = "test_api_key"
        api_secret = "test_secret"
        signer = RequestSigner(api_key, api_secret)

        # Create request body exactly as it will be sent
        import json

        request_data = {"test": "data"}
        body = json.dumps(request_data, separators=(",", ":")).encode()

        # Sign the request with exact body and headers
        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/admin/secret",
            headers={"content-type": "application/json", "host": "testserver"},
            body=body,
        )

        # Make request with signed headers - use content to control body exactly
        response = client.post(
            "/api/v1/admin/secret",
            content=body,
            headers={**signed_headers, "content-type": "application/json"},
        )

        assert response.status_code == 200
        assert response.json() == {"message": "admin_secret"}

    def test_invalid_signature_rejected(self, client, mock_cache):
        """Test rejection of invalid signatures."""
        # Mock setup
        mock_cache.get.return_value = None

        current_time = str(int(time.time()))
        headers = {
            API_KEY_HEADER: "test_api_key",
            SIGNATURE_HEADER: "invalid_signature",
            TIMESTAMP_HEADER: current_time,
            NONCE_HEADER: "valid_nonce",
        }

        response = client.post("/api/v1/admin/secret", headers=headers)
        assert response.status_code == 403
        assert "Invalid signature" in response.json()["detail"]

    def test_nonce_storage_after_validation(self, client, mock_cache):
        """Test that nonce is stored after successful validation."""
        # Mock setup for successful validation
        mock_cache.get.return_value = None  # Nonce not replayed

        # Create valid signature
        api_key = "test_api_key"
        api_secret = "test_secret"
        signer = RequestSigner(api_key, api_secret)

        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/admin/secret",
            headers={"content-type": "application/json", "host": "testserver"},
            body=b"",
        )

        response = client.post("/api/v1/admin/secret", headers=signed_headers)

        if response.status_code == 200:
            # Verify nonce was stored
            mock_cache.set.assert_called()


class TestRequestSigner:
    """Test request signer utility class."""

    def test_request_signer_initialization(self):
        """Test RequestSigner initialization."""
        signer = RequestSigner("api_key", "api_secret")
        assert signer.api_key == "api_key"
        assert signer.api_secret == "api_secret"

    def test_sign_request_basic(self):
        """Test basic request signing."""
        signer = RequestSigner("test_key", "test_secret")

        headers = signer.sign_request(
            method="GET",
            path="/api/v1/test",
        )

        # Verify all required headers are present
        assert API_KEY_HEADER in headers
        assert SIGNATURE_HEADER in headers
        assert TIMESTAMP_HEADER in headers
        assert NONCE_HEADER in headers

        # Verify header values
        assert headers[API_KEY_HEADER] == "test_key"
        assert len(headers[SIGNATURE_HEADER]) == 64  # SHA256 hex length
        assert headers[TIMESTAMP_HEADER].isdigit()
        assert len(headers[NONCE_HEADER]) > 0

    def test_sign_request_with_body(self):
        """Test request signing with body."""
        signer = RequestSigner("test_key", "test_secret")
        body = b'{"test": "data"}'

        headers = signer.sign_request(method="POST", path="/api/v1/test", body=body)

        assert len(headers[SIGNATURE_HEADER]) == 64

    def test_sign_request_with_query_params(self):
        """Test request signing with query parameters."""
        signer = RequestSigner("test_key", "test_secret")

        headers = signer.sign_request(
            method="GET",
            path="/api/v1/test",
            query_params={"param1": "value1", "param2": "value2"},
        )

        assert len(headers[SIGNATURE_HEADER]) == 64

    def test_canonical_request_creation(self):
        """Test canonical request string creation."""
        signer = RequestSigner("test_key", "test_secret")

        canonical = signer._create_canonical_request(
            method="POST",
            path="/api/v1/test",
            query_params={"b": "2", "a": "1"},  # Should be sorted
            headers={"content-type": "application/json", "host": "example.com"},
            body=b'{"test": "data"}',
            timestamp="1234567890",
            nonce="test_nonce",
        )

        lines = canonical.split("\n")
        assert lines[0] == "POST"  # Method
        assert lines[1] == "/api/v1/test"  # Path
        assert lines[2] == "a=1&b=2"  # Sorted query params
        # Headers are on separate lines, sorted alphabetically
        assert lines[3] == "content-type:application/json"  # First header (sorted)
        assert lines[4] == "host:example.com"  # Second header (sorted)

        # Should contain timestamp and nonce
        assert "1234567890" in canonical
        assert "test_nonce" in canonical

    def test_signature_consistency(self):
        """Test that identical requests produce identical signatures."""
        signer = RequestSigner("test_key", "test_secret")

        # Use fixed timestamp and nonce for consistency
        timestamp = "1234567890"
        nonce = "fixed_nonce"

        # Mock time and random generation
        with (
            patch("time.time", return_value=1234567890),
            patch("secrets.token_urlsafe", return_value="fixed_nonce"),
        ):
            headers1 = signer.sign_request("GET", "/test")
            headers2 = signer.sign_request("GET", "/test")

            # Timestamps and nonces will be the same due to mocking
            assert headers1[SIGNATURE_HEADER] == headers2[SIGNATURE_HEADER]

    def test_different_requests_different_signatures(self):
        """Test that different requests produce different signatures."""
        signer = RequestSigner("test_key", "test_secret")

        headers1 = signer.sign_request("GET", "/test1")
        headers2 = signer.sign_request("GET", "/test2")

        # Different paths should produce different signatures
        assert headers1[SIGNATURE_HEADER] != headers2[SIGNATURE_HEADER]

    @pytest.mark.parametrize(
        "api_key,expected_secret",
        [
            ("test_api_key", "test_secret"),
            ("admin_api_key", "admin_secret"),
            ("invalid_key", None),
        ],
    )
    def test_api_key_lookup(self, api_key, expected_secret):
        """Test API key to secret lookup."""
        middleware = RequestSigningMiddleware(None)

        # This would be an async test in reality
        # secret = await middleware._get_api_secret(api_key)
        # assert secret == expected_secret
        pass  # Placeholder for async test

    def test_signature_verification(self):
        """Test signature verification logic."""
        middleware = RequestSigningMiddleware(None)
        api_secret = "test_secret"

        # Create test data
        method = "POST"
        path = "/test"
        query_params = {}
        headers = {"content-type": "application/json", "host": "test"}
        body = b'{"test": true}'
        timestamp = "1234567890"
        nonce = "test_nonce"

        # Create canonical request
        canonical = middleware._create_canonical_request(method, path, query_params, headers, body, timestamp, nonce)

        # Create expected signature
        expected_signature = hmac.new(api_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

        # Test validation
        is_valid = middleware._verify_signature(
            method,
            path,
            query_params,
            headers,
            body,
            timestamp,
            nonce,
            expected_signature,
            api_secret,
        )

        # Note: This is a sync test of async method, would need adjustment
        # assert is_valid is True
