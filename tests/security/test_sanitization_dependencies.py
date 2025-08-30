"""Tests for sanitization dependencies."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.dependencies.sanitization import (
    MessageInput,
    SanitizedModel,
    UserInput,
    get_sanitized_body,
)


class TestSanitizationDependencies:
    """Test the dependency-based sanitization approach."""

    def test_sanitized_body_dependency(self):
        """Test that the SanitizedBody dependency works correctly."""
        app = FastAPI()

        @app.post("/echo")
        async def echo(data: dict = Depends(get_sanitized_body)):
            return data

        client = TestClient(app)

        # Test with XSS attempt
        response = client.post(
            "/echo",
            json={"message": "<script>alert('xss')</script>", "safe": "normal text"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "[FILTERED]"  # JS stripped
        assert data["safe"] == "normal text"

    def test_sanitized_model(self):
        """Test that SanitizedModel automatically sanitizes fields."""
        # Test with malicious input
        user = UserInput(
            name="<script>Evil User</script>",
            email="test@example.com",
            bio="<b>Bold bio</b>",
        )

        # Strings should be sanitized
        assert user.name == "[FILTERED]"
        assert user.email == "test@example.com"
        assert user.bio == "&lt;b&gt;Bold bio&lt;/b&gt;"

    def test_nested_sanitization(self):
        """Test nested data sanitization."""
        message = MessageInput(
            content="<script>alert('xss')</script>",
            metadata={"user": "<b>John</b>", "action": "post"},
        )

        assert message.content == "[FILTERED]"
        assert "&lt;b&gt;" in message.metadata["user"]
        assert message.metadata["action"] == "post"

    @pytest.mark.asyncio
    async def test_dependency_in_fastapi(self):
        """Test the dependency in a real FastAPI app."""
        app = FastAPI()

        @app.post("/users")
        async def create_user(user: UserInput):
            return {"created": user.dict()}

        client = TestClient(app)

        response = client.post(
            "/users",
            json={
                "name": "<h1>Test User</h1>",
                "email": "test@test.com",
                "bio": "javascript:alert(1)",
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Check sanitization happened
        created = data["created"]
        assert "&lt;h1&gt;" in created["name"]
        assert created["email"] == "test@test.com"
        assert created["bio"] == "[FILTERED]"  # javascript: filtered
