"""Tests for request signing framework."""

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import HTTPException, Request, status
from pydantic import BaseModel
from starlette.datastructures import URL, Headers

from app.core.decorators.request_signing import (
    require_admin_signature,
    require_request_signature,
    verify_webhook_signature,
)
from app.core.request_signing import (
    NonceCache,
    RequestSignature,
    SignatureAlgorithm,
    SignatureConfig,
    SignatureKeyStore,
    SignatureValidationResult,
    SignatureVersion,
    compute_body_hash,
    create_signing_string,
    format_authorization_header,
    get_hash_function,
    parse_authorization_header,
    sign_request,
    signature_key_store,
    verify_signature,
)


# Avoid pytest collection warning by not using Test prefix for non-test classes
class RequestData(BaseModel):
    """Test request model."""

    message: str
    value: int


class TestSignatureComponents:
    """Test signature components."""

    def test_get_hash_function(self):
        """Test hash function selection."""
        import hashlib

        # Test SHA256
        hash_func = get_hash_function(SignatureAlgorithm.HMAC_SHA256)
        assert hash_func == hashlib.sha256

        # Test SHA512
        hash_func = get_hash_function(SignatureAlgorithm.HMAC_SHA512)
        assert hash_func == hashlib.sha512

    def test_compute_body_hash(self):
        """Test body hash computation."""
        body = b"test body content"

        # Test SHA256
        hash_256 = compute_body_hash(body, "sha256")
        assert len(hash_256) == 64  # SHA256 hex length
        assert isinstance(hash_256, str)

        # Test SHA512
        hash_512 = compute_body_hash(body, "sha512")
        assert len(hash_512) == 128  # SHA512 hex length
        assert isinstance(hash_512, str)

        # Different content produces different hash
        different_hash = compute_body_hash(b"different content", "sha256")
        assert hash_256 != different_hash

        # Test invalid algorithm
        with pytest.raises(ValueError, match="Unsupported body hash algorithm"):
            compute_body_hash(body, "md5")

    def test_create_signing_string(self):
        """Test signing string creation."""
        method = "POST"
        path = "/api/test"
        headers = {
            "host": "example.com",
            "content-type": "application/json",
            "x-custom": "value",
        }
        query_params = {"page": "1", "limit": "10"}
        body_hash = "abc123"
        timestamp = 1234567890
        nonce = "nonce123"

        # Test with default config
        signing_string = create_signing_string(
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
        )

        # Verify components are included
        assert "POST" in signing_string
        assert "/api/test" in signing_string
        assert "host:example.com" in signing_string
        assert "content-type:application/json" in signing_string
        assert "limit=10&page=1" in signing_string  # Sorted query params
        assert "body-hash:abc123" in signing_string
        assert "timestamp:1234567890" in signing_string
        assert "nonce:nonce123" in signing_string

        # Test with custom config
        config = SignatureConfig(
            include_headers=["host"],
            include_query_params=False,
            include_body=False,
            require_timestamp=False,
            require_nonce=False,
        )

        signing_string = create_signing_string(
            method=method,
            path=path,
            headers=headers,
            config=config,
        )

        # Verify only included components
        assert "POST" in signing_string
        assert "/api/test" in signing_string
        assert "host:example.com" in signing_string
        assert "content-type" not in signing_string
        assert "limit=10" not in signing_string
        assert "body-hash" not in signing_string
        assert "timestamp" not in signing_string
        assert "nonce" not in signing_string


class TestRequestSigning:
    """Test request signing and verification."""

    def test_sign_request(self):
        """Test request signing."""
        secret_key = "test_secret_key_123"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com", "content-type": "application/json"}
        body = b'{"name": "test"}'

        # Sign request
        signature = sign_request(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            body=body,
            key_id="test_key",
        )

        # Verify signature properties
        assert isinstance(signature, RequestSignature)
        assert signature.key_id == "test_key"
        assert signature.algorithm == SignatureAlgorithm.HMAC_SHA256
        assert signature.version == SignatureVersion.V2
        assert signature.timestamp > 0
        assert signature.nonce is not None
        assert len(signature.signature) == 64  # SHA256 HMAC hex length
        assert signature.headers == ["host", "content-type", "content-length"]

    def test_verify_signature_valid(self):
        """Test signature verification with valid signature."""
        secret_key = "test_secret_key_123"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com", "content-type": "application/json"}
        body = b'{"name": "test"}'

        # Sign request
        signature = sign_request(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            body=body,
        )

        # Verify signature
        result = verify_signature(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            provided_signature=signature,
            body=body,
        )

        assert result.is_valid is True
        assert result.error is None
        assert result.signature_age is not None
        assert result.signature_age >= 0

    def test_verify_signature_invalid(self):
        """Test signature verification with invalid signature."""
        secret_key = "test_secret_key_123"
        wrong_secret = "wrong_secret_key"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com", "content-type": "application/json"}
        body = b'{"name": "test"}'

        # Sign with one key
        signature = sign_request(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            body=body,
        )

        # Verify with different key
        result = verify_signature(
            secret_key=wrong_secret,
            method=method,
            path=path,
            headers=headers,
            provided_signature=signature,
            body=body,
        )

        assert result.is_valid is False
        assert result.error == "Invalid signature"

    def test_verify_signature_expired(self):
        """Test signature verification with expired timestamp."""
        secret_key = "test_secret_key_123"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com"}

        # Create signature with old timestamp
        old_signature = RequestSignature(
            signature="dummy",
            timestamp=int(time.time()) - 400,  # 400 seconds ago
            nonce="test_nonce",
        )

        # Verify with max age of 300 seconds
        config = SignatureConfig(max_age_seconds=300)
        result = verify_signature(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            provided_signature=old_signature,
            config=config,
        )

        assert result.is_valid is False
        assert "expired" in result.error.lower()

    def test_verify_signature_future_timestamp(self):
        """Test signature verification with future timestamp."""
        secret_key = "test_secret_key_123"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com"}

        # Create signature with future timestamp
        future_signature = RequestSignature(
            signature="dummy",
            timestamp=int(time.time()) + 60,  # 60 seconds in future
            nonce="test_nonce",
        )

        result = verify_signature(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            provided_signature=future_signature,
        )

        assert result.is_valid is False
        assert "future" in result.error.lower()

    def test_verify_signature_replay_attack(self):
        """Test signature verification prevents replay attacks."""
        secret_key = "test_secret_key_123"
        method = "POST"
        path = "/api/users"
        headers = {"host": "api.example.com"}
        body = b'{"name": "test"}'

        # Create nonce cache (using a set for testing)
        nonce_cache = set()

        # Sign request
        signature = sign_request(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            body=body,
        )

        # First verification should succeed
        result1 = verify_signature(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            provided_signature=signature,
            body=body,
            nonce_cache=nonce_cache,
        )
        assert result1.is_valid is True

        # Second verification with same nonce should fail
        result2 = verify_signature(
            secret_key=secret_key,
            method=method,
            path=path,
            headers=headers,
            provided_signature=signature,
            body=body,
            nonce_cache=nonce_cache,
        )
        assert result2.is_valid is False
        assert "replay" in result2.error.lower()


class TestAuthorizationHeader:
    """Test authorization header parsing and formatting."""

    def test_parse_authorization_header_valid(self):
        """Test parsing valid authorization header."""
        auth_header = (
            'Signature keyId="test_key",algorithm="HMAC-SHA256",'
            + 'headers="host content-type",timestamp="1234567890",'
            + 'nonce="abc123",signature="def456"'
        )

        signature = parse_authorization_header(auth_header)

        assert signature is not None
        assert signature.key_id == "test_key"
        assert signature.algorithm == SignatureAlgorithm.HMAC_SHA256
        assert signature.headers == ["host", "content-type"]
        assert signature.timestamp == 1234567890
        assert signature.nonce == "abc123"
        assert signature.signature == "def456"

    def test_parse_authorization_header_invalid(self):
        """Test parsing invalid authorization headers."""
        # Missing Signature prefix
        assert parse_authorization_header("Bearer token123") is None

        # Empty header
        assert parse_authorization_header("") is None

        # Malformed header (missing required signature field)
        result = parse_authorization_header('Signature keyId="test"')
        # This might actually parse partially, so check it doesn't have a valid signature
        assert result is None or not result.signature

    def test_format_authorization_header(self):
        """Test formatting authorization header."""
        signature = RequestSignature(
            signature="abc123def456",
            key_id="test_key",
            algorithm=SignatureAlgorithm.HMAC_SHA512,
            headers=["host", "date"],
            timestamp=1234567890,
            nonce="nonce123",
        )

        header = format_authorization_header(signature)

        assert header.startswith("Signature ")
        assert 'keyId="test_key"' in header
        assert 'algorithm="HMAC-SHA512"' in header
        assert 'headers="host date"' in header
        assert 'timestamp="1234567890"' in header
        assert 'nonce="nonce123"' in header
        assert 'signature="abc123def456"' in header


class TestSignatureKeyStore:
    """Test signature key store."""

    def test_key_store_operations(self):
        """Test key store add, get, remove operations."""
        store = SignatureKeyStore()

        # Add keys
        store.add_key("key1", "secret1", {"type": "api"})
        store.add_key("key2", "secret2", {"type": "admin"})

        # Get keys
        assert store.get_key("key1") == "secret1"
        assert store.get_key("key2") == "secret2"
        assert store.get_key("nonexistent") is None

        # List keys
        keys = store.list_keys()
        assert "key1" in keys
        assert "key2" in keys
        assert len(keys) == 2

        # Remove key
        store.remove_key("key1")
        assert store.get_key("key1") is None
        assert len(store.list_keys()) == 1


class TestNonceCache:
    """Test nonce cache for replay prevention."""

    def test_nonce_cache_operations(self):
        """Test nonce cache add and contains."""
        cache = NonceCache(max_age_seconds=10)

        # Add nonce
        cache.add("nonce1")
        assert cache.contains("nonce1") is True
        assert cache.contains("nonce2") is False

        # Add more nonces
        cache.add("nonce2")
        cache.add("nonce3")
        assert cache.contains("nonce2") is True
        assert cache.contains("nonce3") is True

    def test_nonce_cache_expiration(self):
        """Test nonce cache expiration."""
        cache = NonceCache(max_age_seconds=1)

        # Add nonce
        cache.add("nonce1")
        assert cache.contains("nonce1") is True

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.contains("nonce1") is False

    def test_nonce_cache_clear(self):
        """Test nonce cache clear."""
        cache = NonceCache()

        # Add nonces
        cache.add("nonce1")
        cache.add("nonce2")
        assert cache.contains("nonce1") is True
        assert cache.contains("nonce2") is True

        # Clear cache
        cache.clear()
        assert cache.contains("nonce1") is False
        assert cache.contains("nonce2") is False


class TestRequestSigningDecorators:
    """Test request signing decorators."""

    @pytest.mark.asyncio
    async def test_require_request_signature_valid(self):
        """Test require_request_signature with valid signature."""
        # Setup
        signature_key_store.add_key("test_key", "test_secret")

        # Create a more complete mock request
        auth_header = format_authorization_header(
            sign_request(
                secret_key="test_secret",
                method="POST",
                path="/test",
                headers={"host": "example.com", "content-type": "application/json"},
                body=b'{"test": true}',
                key_id="test_key",
            )
        )

        # Create proper Request mock
        request = Mock(spec=Request)
        request.__class__ = Request  # Make isinstance work
        request.headers = Headers(
            {
                "authorization": auth_header,
                "host": "example.com",
                "content-type": "application/json",
            }
        )
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/test"
        request.query_params = {}
        request.body = AsyncMock(return_value=b'{"test": true}')
        request.state = Mock()

        # Create decorated function
        @require_request_signature()
        async def test_endpoint(request: Request, data: RequestData):
            return {"success": True}

        # Call endpoint
        result = await test_endpoint(request, RequestData(message="test", value=123))

        assert result["success"] is True
        assert hasattr(request.state, "signature")
        assert hasattr(request.state, "signature_key_id")

    @pytest.mark.asyncio
    async def test_require_request_signature_missing(self):
        """Test require_request_signature with missing signature."""
        # Create mock request without authorization header
        request = Mock(spec=Request)
        request.__class__ = Request  # Make isinstance work
        request.headers = Headers({"host": "example.com"})
        request.state = Mock()
        # Ensure state doesn't have signature attribute
        (delattr(request.state, "signature") if hasattr(request.state, "signature") else None)

        # Create decorated function
        @require_request_signature()
        async def test_endpoint(request: Request):
            return {"success": True}

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "required" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_require_admin_signature_valid(self):
        """Test require_admin_signature with valid admin key."""
        # Setup
        signature_key_store.add_key("admin_key1", "admin_secret")

        # Create mock request
        auth_header = format_authorization_header(
            sign_request(
                secret_key="admin_secret",
                method="POST",
                path="/admin/test",
                headers={"host": "example.com"},
                key_id="admin_key1",
            )
        )

        request = Mock(spec=Request)
        request.__class__ = Request
        request.headers = Headers(
            {
                "authorization": auth_header,
                "host": "example.com",
            }
        )
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/admin/test"
        request.query_params = {}
        request.body = AsyncMock(return_value=b"")
        request.state = Mock()

        # Create decorated function
        @require_admin_signature()
        async def admin_endpoint(request: Request):
            return {"admin": True}

        # Call endpoint
        result = await admin_endpoint(request)

        assert result["admin"] is True
        assert request.state.is_admin_request is True

    @pytest.mark.asyncio
    async def test_require_admin_signature_non_admin_key(self):
        """Test require_admin_signature rejects non-admin keys."""
        # Setup
        signature_key_store.add_key("user_key1", "user_secret")  # Not admin key

        # Create mock request
        auth_header = format_authorization_header(
            sign_request(
                secret_key="user_secret",
                method="POST",
                path="/admin/test",
                headers={"host": "example.com"},
                key_id="user_key1",
            )
        )

        request = Mock(spec=Request)
        request.__class__ = Request
        request.headers = Headers(
            {
                "authorization": auth_header,
                "host": "example.com",
            }
        )

        # Create decorated function
        @require_admin_signature()
        async def admin_endpoint(request: Request):
            return {"admin": True}

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await admin_endpoint(request)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin signature required" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_verify_webhook_signature_valid(self):
        """Test verify_webhook_signature with valid signature."""
        import hashlib
        import hmac

        webhook_secret = "webhook_secret_123"
        timestamp = str(int(time.time()))
        body = b'{"event": "payment.completed"}'

        # Create valid signature
        signature = hmac.new(
            webhook_secret.encode(),
            f"{timestamp}.{body.decode()}".encode(),
            hashlib.sha256,
        ).hexdigest()

        # Create mock request
        request = Mock(spec=Request)
        request.__class__ = Request
        request.headers = Headers(
            {
                "x-webhook-signature": signature,
                "x-webhook-timestamp": timestamp,
            }
        )
        request.body = AsyncMock(return_value=body)

        # Create decorated function
        @verify_webhook_signature(secret_key=webhook_secret)
        async def webhook_endpoint(request: Request):
            return {"received": True}

        # Call endpoint
        result = await webhook_endpoint(request)
        assert result["received"] is True

    @pytest.mark.asyncio
    async def test_verify_webhook_signature_invalid(self):
        """Test verify_webhook_signature with invalid signature."""
        webhook_secret = "webhook_secret_123"
        timestamp = str(int(time.time()))
        body = b'{"event": "payment.completed"}'

        # Create invalid signature
        signature = "invalid_signature_123"

        # Create mock request
        request = Mock(spec=Request)
        request.__class__ = Request
        request.headers = Headers(
            {
                "x-webhook-signature": signature,
                "x-webhook-timestamp": timestamp,
            }
        )
        request.body = AsyncMock(return_value=body)

        # Create decorated function
        @verify_webhook_signature(secret_key=webhook_secret)
        async def webhook_endpoint(request: Request):
            return {"received": True}

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await webhook_endpoint(request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "invalid webhook signature" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_verify_webhook_signature_expired(self):
        """Test verify_webhook_signature with expired timestamp."""
        webhook_secret = "webhook_secret_123"
        old_timestamp = str(int(time.time()) - 400)  # 400 seconds ago
        body = b'{"event": "payment.completed"}'

        # Create mock request
        request = Mock(spec=Request)
        request.__class__ = Request
        request.headers = Headers(
            {
                "x-webhook-signature": "dummy",
                "x-webhook-timestamp": old_timestamp,
            }
        )

        # Create decorated function with 5 minute max age
        @verify_webhook_signature(secret_key=webhook_secret, max_age_seconds=300)
        async def webhook_endpoint(request: Request):
            return {"received": True}

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await webhook_endpoint(request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "too old" in exc_info.value.detail.lower()

    def test_sync_endpoint_not_supported(self):
        """Test that sync endpoints are not supported."""

        # Try to decorate sync function
        @require_request_signature()
        def sync_endpoint(request: Request):
            return {"sync": True}

        # Create mock request
        request = Mock(spec=Request)

        # Should raise NotImplementedError
        with pytest.raises(NotImplementedError, match="only supports async"):
            sync_endpoint(request)
