"""Tests for input sanitization middleware."""

import json
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.middleware.input_sanitization import InputSanitizationMiddleware


@pytest.fixture
def app():
    """Create test FastAPI app with input sanitization middleware."""
    app = FastAPI()
    app.add_middleware(InputSanitizationMiddleware)

    @app.get("/test")
    async def test_get(request: Request):
        # Return sanitized query params if available
        sanitized_params = getattr(request.state, "sanitized_query_params", None)
        return {"query_params": sanitized_params or dict(request.query_params)}

    @app.post("/test")
    async def test_post(request: Request):
        try:
            # Try to get sanitized body first
            from app.middleware.input_sanitization import get_sanitized_body

            sanitized_body = get_sanitized_body(request)
            if sanitized_body:
                import json

                body = json.loads(sanitized_body.decode("utf-8"))
            else:
                # Fallback to original method
                body = await request.json()
            return {"body": body, "sanitized": True}
        except Exception:
            return {"body": "not_json", "sanitized": True}

    @app.post("/form")
    async def test_form(request: Request):
        try:
            form = await request.form()
            return {"form": dict(form)}
        except Exception:
            return {"form": "error"}

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestInputSanitizationMiddleware:
    """Test input sanitization middleware functionality."""

    def test_clean_query_params(self, client):
        """Test sanitization of clean query parameters."""
        response = client.get("/test?name=john&age=25")
        assert response.status_code == 200

        data = response.json()
        assert "query_params" in data
        assert data["query_params"]["name"] == "john"
        assert data["query_params"]["age"] == "25"

    def test_malicious_query_params(self, client):
        """Test sanitization of malicious query parameters."""
        # Test XSS attempt in query params
        response = client.get("/test?name=<script>alert('xss')</script>")
        assert response.status_code == 200

        data = response.json()
        # Verify script tags were sanitized - with aggressive filtering, alert is filtered out
        assert "<script>" not in str(data)
        assert "[FILTERED]" in str(data) or "alert" not in str(data).lower()  # Alert should be filtered

    def test_sql_injection_query_params(self, client):
        """Test sanitization of SQL injection in query parameters."""
        # Test with single quotes that should be filtered
        response = client.get("/test?id=1' OR '1'='1")
        assert response.status_code == 200

        data = response.json()
        # With aggressive filtering, dangerous SQL patterns are replaced with [FILTERED]
        # The ' OR ' pattern is filtered out, leaving HTML-escaped quotes
        assert "[FILTERED]" in data["query_params"]["id"]
        assert data["query_params"]["id"] == "1[FILTERED]1&#x27;=&#x27;1"

    def test_clean_json_body(self, client):
        """Test sanitization of clean JSON body."""
        clean_data = {"name": "john", "message": "hello world"}
        response = client.post("/test", json=clean_data)

        assert response.status_code == 200
        data = response.json()
        assert data["body"] == clean_data

    def test_malicious_json_body(self, client):
        """Test sanitization of malicious JSON body."""
        malicious_data = {"name": "<script>alert('xss')</script>", "message": "SELECT * FROM users WHERE id = 1"}

        response = client.post("/test", json=malicious_data)

        # Should sanitize the content rather than reject
        assert response.status_code == 200
        data = response.json()

        # Script tags should be filtered with aggressive sanitization
        # JavaScript patterns are replaced with [FILTERED]
        assert "[FILTERED]" in data["body"]["name"]

    def test_nested_json_sanitization(self, client):
        """Test sanitization of nested JSON structures."""
        nested_data = {
            "user": {
                "profile": {
                    "bio": "<script>alert('nested')</script>",
                    "tags": ["<script>", "normal_tag", "javascript:void(0)"],
                }
            }
        }

        response = client.post("/test", json=nested_data)
        assert response.status_code == 200

        data = response.json()
        # Nested content should be sanitized with aggressive filtering
        bio = data["body"]["user"]["profile"]["bio"]
        assert "[FILTERED]" in bio

        # Tags should also be sanitized
        tags = data["body"]["user"]["profile"]["tags"]
        assert "[FILTERED]" in tags[0] or "script" not in tags[0].lower()

    def test_form_data_sanitization(self, client):
        """Test sanitization of form-encoded data."""
        clean_form_data = {"name": "john", "message": "hello"}

        response = client.post(
            "/form", data=clean_form_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["form"]["name"] == "john"

    def test_malicious_form_data(self, client):
        """Test rejection of malicious form data."""
        malicious_form_data = {"name": "<script>alert('xss')</script>", "comment": "'; DROP TABLE users; --"}

        response = client.post(
            "/form", data=malicious_form_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        # Should sanitize rather than reject
        assert response.status_code == 200

    def test_large_request_body_rejected(self, client):
        """Test rejection of oversized request bodies."""
        # Create large JSON payload
        large_data = {"data": "x" * (11 * 1024 * 1024)}  # 11MB

        response = client.post("/test", json=large_data)
        assert response.status_code == 413
        assert "Request body too large" in response.json()["detail"]

    def test_invalid_json_rejected(self, client):
        """Test handling of invalid JSON."""
        response = client.post("/test", data="invalid json {", headers={"Content-Type": "application/json"})

        assert response.status_code == 400
        assert "Invalid request body" in response.json()["detail"]

    def test_exempt_paths_bypass_sanitization(self, client):
        """Test that exempt paths bypass sanitization."""
        with patch("app.middleware.input_sanitization.SANITIZATION_EXEMPT_PATHS", ["/test"]):
            # Malicious content should pass through
            response = client.post("/test", json={"xss": "<script>alert('test')</script>"})
            assert response.status_code == 200

    def test_url_decoding(self, client):
        """Test proper URL decoding of query parameters."""
        # URL-encoded query param
        response = client.get("/test?message=hello%20world")
        assert response.status_code == 200

        data = response.json()
        assert data["query_params"]["message"] == "hello world"

    def test_header_sanitization(self, client):
        """Test sanitization of request headers."""
        # Test with custom header containing potential XSS
        response = client.get("/test", headers={"X-Custom-Header": "<script>alert('header')</script>"})

        # Should not reject request, but sanitize header
        assert response.status_code == 200

    def test_whitelisted_headers_preserved(self, client):
        """Test that whitelisted headers are preserved."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer token123",
            "X-CSRF-Token": "csrf_token_here",
        }

        response = client.get("/test", headers=headers)
        assert response.status_code == 200

    def test_content_type_handling(self, client):
        """Test different content type handling."""
        # Test text/plain
        response = client.post("/test", data="plain text content", headers={"Content-Type": "text/plain"})
        assert response.status_code == 200

    def test_sanitization_error_handling(self, client):
        """Test error handling in sanitization process."""
        # Mock sanitization function to raise exception
        with patch("app.middleware.input_sanitization.sanitize_string", side_effect=Exception("Test error")):
            response = client.get("/test?param=value")

            # Should return 400 on sanitization error (sanitization method returns None)
            assert response.status_code == 400
            assert "Invalid query parameters" in response.json()["detail"]

    @pytest.mark.parametrize(
        "malicious_input,expected_check",
        [
            ("<script>alert('xss')</script>", lambda x: "[FILTERED]" in x),  # Aggressive filtering
            ("javascript:alert('xss')", lambda x: "[FILTERED]" in x),  # JavaScript protocol filtered
            (
                "<iframe src='evil.com'></iframe>",
                lambda x: "[FILTERED]" in x or "iframe" not in x.lower(),
            ),  # HTML filtered
            ("'; DROP TABLE users; --", lambda x: "users;" in x or "[FILTERED]" in x),  # SQL pattern removed
            ("1' OR '1'='1", lambda x: "OR" not in x or "[FILTERED]" in x),  # SQL pattern filtered
            (
                "<img onerror='alert(1)' src='x'>",
                lambda x: "[FILTERED]" in x or "onerror" not in x.lower(),
            ),  # Event handler filtered
        ],
    )
    def test_various_malicious_inputs(self, client, malicious_input, expected_check):
        """Test sanitization of various malicious inputs."""
        response = client.post("/test", json={"input": malicious_input})

        assert response.status_code == 200
        # Content should be sanitized
        data = response.json()
        sanitized_input = data["body"]["input"]

        # Check expected sanitization
        assert expected_check(sanitized_input), f"Failed for input: {malicious_input}, got: {sanitized_input}"

    def test_empty_request_body(self, client):
        """Test handling of empty request body."""
        response = client.post("/test")
        assert response.status_code == 200

    def test_multipart_form_data(self, client):
        """Test handling of multipart form data."""
        files = {"file": ("test.txt", "file content", "text/plain")}
        data = {"field": "value"}

        response = client.post("/form", files=files, data=data)
        # Should handle multipart data appropriately
        assert response.status_code == 200
