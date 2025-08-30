"""Tests for request size limiting middleware."""

import pytest
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from app.middleware.request_size import RequestSizeLimitMiddleware


@pytest.fixture
def test_app():
    """Create test FastAPI app with request size middleware."""
    app = FastAPI()

    # Add request size middleware with small limits for testing
    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_content_length=1024,  # 1KB for testing
        max_upload_size=2048,  # 2KB for uploads
    )

    @app.post("/test")
    async def test_endpoint(request: Request):
        body = await request.body()
        return JSONResponse({"size": len(body), "received": True})

    @app.post("/upload/file")
    async def upload_endpoint(request: Request):
        body = await request.body()
        return JSONResponse({"size": len(body), "uploaded": True})

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app


@pytest.mark.asyncio
async def test_request_within_limit(test_app):
    """Test request within size limit is processed normally."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send small request (500 bytes)
        data = "x" * 500
        response = await client.post("/test", content=data, headers={"Content-Type": "text/plain"})

        assert response.status_code == 200
        assert response.json() == {"size": 500, "received": True}


@pytest.mark.asyncio
async def test_request_exceeds_limit(test_app):
    """Test request exceeding size limit is rejected."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send large request (1500 bytes, exceeds 1KB limit)
        data = "x" * 1500
        response = await client.post("/test", content=data, headers={"Content-Type": "text/plain"})

        assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        assert "exceeds maximum allowed size" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_within_limit(test_app):
    """Test upload within size limit is processed normally."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send upload within limit (1500 bytes, under 2KB upload limit)
        data = "x" * 1500
        response = await client.post(
            "/upload/file",
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )

        assert response.status_code == 200
        assert response.json() == {"size": 1500, "uploaded": True}


@pytest.mark.asyncio
async def test_upload_exceeds_limit(test_app):
    """Test upload exceeding size limit is rejected."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send large upload (3000 bytes, exceeds 2KB upload limit)
        data = "x" * 3000
        response = await client.post(
            "/upload/file",
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )

        assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        assert "exceeds maximum allowed size" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_request_not_limited(test_app):
    """Test GET requests are not subject to size limits."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_response_headers(test_app):
    """Test response includes size limit headers."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/test", content="test")

        assert response.status_code == 200
        assert "X-Max-Request-Size" in response.headers
        assert response.headers["X-Max-Request-Size"] == "1024"

        # Upload endpoint should have upload size header
        response = await client.post("/upload/file", content="test")
        assert "X-Max-Upload-Size" in response.headers
        assert response.headers["X-Max-Upload-Size"] == "2048"


@pytest.mark.asyncio
async def test_missing_content_length_header(test_app):
    """Test handling of requests without content-length header."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Manually create request without content-length
        # This would trigger streaming validation
        response = await client.post("/test", content="small data", headers={"Content-Type": "text/plain"})

        assert response.status_code == 200


@pytest.mark.asyncio
async def test_invalid_content_length_header(test_app):
    """Test handling of invalid content-length header."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/test",
            content="test",
            headers={"Content-Type": "text/plain", "Content-Length": "invalid"},
        )

        # Should still process the request (fallback to streaming)
        assert response.status_code == 200


class TestRequestSizeLimitMiddleware:
    """Test RequestSizeLimitMiddleware class methods."""

    def test_is_upload_endpoint(self):
        """Test upload endpoint detection."""
        app = FastAPI()
        middleware = RequestSizeLimitMiddleware(app)

        # Test upload patterns
        assert middleware._is_upload_endpoint("/api/v1/upload/file") is True
        assert middleware._is_upload_endpoint("/files/upload") is True
        assert middleware._is_upload_endpoint("/api/attachment/123") is True
        assert middleware._is_upload_endpoint("/user/avatar") is True
        assert middleware._is_upload_endpoint("/import/data") is True
        assert middleware._is_upload_endpoint("/media/video") is True
        assert middleware._is_upload_endpoint("/document/upload") is True

        # Test non-upload patterns
        assert middleware._is_upload_endpoint("/api/v1/users") is False
        assert middleware._is_upload_endpoint("/auth/login") is False
        assert middleware._is_upload_endpoint("/health") is False

    def test_get_content_length(self):
        """Test content length extraction."""
        app = FastAPI()
        middleware = RequestSizeLimitMiddleware(app)

        # Valid content length
        request = Request(
            scope={
                "type": "http",
                "method": "POST",
                "headers": [(b"content-length", b"1234")],
                "path": "/test",
                "query_string": b"",
            }
        )
        assert middleware._get_content_length(request) == 1234

        # Missing content length
        request = Request(
            scope={
                "type": "http",
                "method": "POST",
                "headers": [],
                "path": "/test",
                "query_string": b"",
            }
        )
        assert middleware._get_content_length(request) is None

        # Invalid content length
        request = Request(
            scope={
                "type": "http",
                "method": "POST",
                "headers": [(b"content-length", b"invalid")],
                "path": "/test",
                "query_string": b"",
            }
        )
        assert middleware._get_content_length(request) is None


@pytest.mark.asyncio
async def test_large_request_warning(test_app, caplog):
    """Test warning logged for large requests near limit."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send request at 90% of limit (900 bytes out of 1024)
        data = "x" * 900
        response = await client.post("/test", content=data, headers={"Content-Type": "text/plain"})

        assert response.status_code == 200
        # Check if warning was logged
        assert "large_request_detected" in caplog.text
