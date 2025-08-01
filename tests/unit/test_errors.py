"""Test error handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from fastapi import FastAPI

# TestClient imported via TYPE_CHECKING for type hints only
from pydantic import BaseModel

from app.core.errors import (
    APIError,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    UnauthorizedError,
)
from app.core.errors import ValidationError as APIValidationError
from app.core.errors import (
    setup_error_handlers,
)
from tests.utils.testclient import SafeTestClient

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


class TestModel(BaseModel):
    """Test model for validation."""

    name: str
    age: int


def _setup_basic_error_endpoints(app: FastAPI) -> None:
    """Set up basic error test endpoints."""

    @app.get("/test/api-error")
    async def raise_api_error() -> None:
        raise APIError(status_code=418, error="teapot", message="I'm a teapot")

    @app.get("/test/bad-request")
    async def raise_bad_request() -> None:
        raise BadRequestError("Invalid request data")

    @app.get("/test/unauthorized")
    async def raise_unauthorized() -> None:
        raise UnauthorizedError("Invalid credentials")

    @app.get("/test/forbidden")
    async def raise_forbidden() -> None:
        raise ForbiddenError("Access denied")

    @app.get("/test/not-found")
    async def raise_not_found() -> None:
        raise NotFoundError("Item not found")


def _setup_advanced_error_endpoints(app: FastAPI) -> None:
    """Set up advanced error test endpoints."""

    @app.get("/test/conflict")
    async def raise_conflict() -> None:
        raise ConflictError("Resource already exists")

    @app.get("/test/validation-error")
    async def raise_validation_error() -> None:
        raise APIValidationError("Invalid data format")

    @app.get("/test/internal-error")
    async def raise_internal_error() -> None:
        raise InternalServerError("Something went wrong")

    @app.post("/test/pydantic-validation")
    async def test_validation(data: TestModel) -> TestModel:
        return data

    @app.get("/test/unhandled")
    async def raise_unhandled() -> None:
        raise RuntimeError("Unhandled exception")


@pytest.fixture
def error_app() -> FastAPI:
    """Create app with error handlers and test endpoints."""
    app = FastAPI()
    setup_error_handlers(app, development_mode=True)
    _setup_basic_error_endpoints(app)
    _setup_advanced_error_endpoints(app)
    return app


class TestErrorHandling:
    """Test error handling functionality."""

    def test_api_error(self, error_app: FastAPI) -> None:
        """Test custom API error handling."""
        client = SafeTestClient(error_app)
        response = client.get("/test/api-error")

        assert response.status_code == 418
        data = response.json()
        assert data["error"] == "teapot"
        assert data["message"] == "I'm a teapot"
        assert "timestamp" in data
        assert "path" in data

    def test_bad_request_error(self, error_app: FastAPI) -> None:
        """Test bad request error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/bad-request")

        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "bad_request"
        assert data["message"] == "Invalid request data"

    def test_unauthorized_error(self, error_app: FastAPI) -> None:
        """Test unauthorized error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/unauthorized")

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        data = response.json()
        assert data["error"] == "unauthorized"
        assert data["message"] == "Invalid credentials"

    def test_forbidden_error(self, error_app: FastAPI) -> None:
        """Test forbidden error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/forbidden")

        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "forbidden"
        assert data["message"] == "Access denied"

    def test_not_found_error(self, error_app: FastAPI) -> None:
        """Test not found error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/not-found")

        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "not_found"
        assert data["message"] == "Item not found"

    def test_conflict_error(self, error_app: FastAPI) -> None:
        """Test conflict error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/conflict")

        assert response.status_code == 409
        data = response.json()
        assert data["error"] == "conflict"
        assert data["message"] == "Resource already exists"

    def test_validation_error(self, error_app: FastAPI) -> None:
        """Test API validation error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/validation-error")

        assert response.status_code == 422
        data = response.json()
        assert data["error"] == "validation_error"
        assert data["message"] == "Invalid data format"

    def test_internal_server_error(self, error_app: FastAPI) -> None:
        """Test internal server error."""
        client = SafeTestClient(error_app)
        response = client.get("/test/internal-error")

        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "internal_error"
        assert data["message"] == "Something went wrong"

    def test_pydantic_validation_error(self, error_app: FastAPI) -> None:
        """Test Pydantic validation error handling."""
        client = SafeTestClient(error_app)
        response = client.post("/test/pydantic-validation", json={"name": "John", "age": "not-a-number"})

        assert response.status_code == 422
        data = response.json()
        assert data["error"] == "validation_error"
        assert data["message"] == "Request validation failed"
        assert "errors" in data
        assert len(data["errors"]) > 0

        # Check error structure
        error = data["errors"][0]
        assert "field" in error
        assert "message" in error
        assert "type" in error

    def test_unhandled_exception(self, error_app: FastAPI) -> None:
        """Test unhandled exception handling."""
        client = SafeTestClient(error_app, raise_server_exceptions=False)
        response = client.get("/test/unhandled")

        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "internal_error"
        # In development mode, should show actual error
        assert "Unhandled exception" in data["message"]

    def test_production_mode_error_masking(self) -> None:
        """Test that errors are masked in production mode."""
        app = FastAPI()
        setup_error_handlers(app, development_mode=False)

        @app.get("/test/error")
        async def raise_error() -> None:
            raise RuntimeError("Secret internal error")

        client = SafeTestClient(app, raise_server_exceptions=False)
        response = client.get("/test/error")

        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "internal_error"
        # Should not expose internal details
        assert "Secret internal error" not in data["message"]
        assert data["message"] == "An unexpected error occurred"
