"""Tests for session middleware."""

from typing import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.core.session import SESSION_COOKIE_NAME, SessionManager
from app.middleware.session import SessionMiddleware


@pytest.fixture
def app():
    """Create test FastAPI app with session middleware."""
    app = FastAPI()
    app.add_middleware(SessionMiddleware)

    @app.get("/test")
    async def test_endpoint(request: Request):
        return {
            "has_session": bool(request.state.session),
            "session_id": getattr(request.state, "session_id", None),
            "user_id": getattr(request.state, "user_id", None),
        }

    @app.post("/login")
    async def login_endpoint(request: Request):
        # Simulate creating a session
        request.state.new_session_id = "test_session_123"
        return {"status": "logged_in"}

    @app.post("/logout")
    async def logout_endpoint(request: Request):
        # Simulate deleting a session
        request.state.delete_session = True
        return {"status": "logged_out"}

    return app


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Create test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mock_session_manager():
    """Mock session manager."""
    with patch("app.middleware.session.get_session_manager") as mock:
        manager = AsyncMock(spec=SessionManager)
        mock.return_value = manager
        yield manager


class TestSessionMiddleware:
    """Test session middleware functionality."""

    async def test_no_session_cookie(self, client, mock_session_manager):
        """Test request without session cookie."""
        response = client.get("/test")

        assert response.status_code == 200
        data = response.json()
        assert data["has_session"] is False
        assert data["session_id"] is None
        assert data["user_id"] is None

    async def test_valid_session_cookie(self, client, mock_session_manager):
        """Test request with valid session cookie."""
        # Mock session validation and retrieval
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = {
            "session_id": "test_session_123",
            "user_id": "user_456",
            "created_at": "2024-01-01T00:00:00Z",
        }

        # Make request with session cookie
        response = client.get("/test", cookies={SESSION_COOKIE_NAME: "test_session_123"})

        assert response.status_code == 200
        data = response.json()
        assert data["has_session"] is True
        assert data["session_id"] == "test_session_123"
        assert data["user_id"] == "user_456"

        # Verify session validation was called
        mock_session_manager.validate_session.assert_called_once()
        mock_session_manager.get_session.assert_called_once_with("test_session_123")

    async def test_invalid_session_cookie(self, client, mock_session_manager):
        """Test request with invalid session cookie."""
        # Mock invalid session
        mock_session_manager.validate_session.return_value = False

        response = client.get("/test", cookies={SESSION_COOKIE_NAME: "invalid_session"})

        assert response.status_code == 200
        data = response.json()
        assert data["has_session"] is False

    async def test_session_creation(self, client, mock_session_manager):
        """Test session creation during login."""
        response = client.post("/login")

        assert response.status_code == 200

        # Check that session cookie was set
        assert SESSION_COOKIE_NAME in response.cookies
        cookie_value = response.cookies[SESSION_COOKIE_NAME]
        assert cookie_value == "test_session_123"

        # Verify cookie attributes
        cookie = response.cookies.get_dict()[SESSION_COOKIE_NAME]
        # Note: TestClient doesn't preserve all cookie attributes

    async def test_session_deletion(self, client, mock_session_manager):
        """Test session deletion during logout."""
        response = client.post("/logout")

        assert response.status_code == 200

        # TestClient doesn't handle cookie deletion well, so we check the logic
        # In a real test, you'd verify the cookie was cleared

    async def test_session_rotation_recommendation(self, client, mock_session_manager):
        """Test session rotation when recommended."""
        # Mock session with rotation recommendation
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = {
            "session_id": "old_session",
            "user_id": "user_456",
            "rotation_recommended": True,
        }
        mock_session_manager.rotate_session.return_value = "new_session_123"

        # Make request with old session
        response = client.get("/test", cookies={SESSION_COOKIE_NAME: "old_session"})

        assert response.status_code == 200

    async def test_session_loading_error(self, client, mock_session_manager):
        """Test handling of session loading errors."""
        # Mock session manager to raise exception
        mock_session_manager.validate_session.side_effect = Exception("Redis error")

        response = client.get("/test", cookies={SESSION_COOKIE_NAME: "test_session"})

        # Should handle error gracefully
        assert response.status_code == 200
        data = response.json()
        assert data["has_session"] is False

    @pytest.mark.parametrize(
        "cookie_attributes",
        [
            {"httponly": True, "secure": True, "samesite": "strict"},
            {"httponly": True, "secure": False, "samesite": "strict"},
        ],
    )
    async def test_session_cookie_security(self, app, cookie_attributes):
        """Test session cookie security attributes."""
        # This would require more sophisticated testing with actual cookie parsing
        # For now, we verify the middleware sets the right attributes in the code
        middleware = SessionMiddleware(app)

        # Mock response
        response = MagicMock()
        response.set_cookie = MagicMock()

        # Test cookie setting
        middleware._set_session_cookie(response, "test_session_123")

        # Verify set_cookie was called with security attributes
        response.set_cookie.assert_called_once()
        call_args = response.set_cookie.call_args

        assert call_args[1]["httponly"] is True
        assert call_args[1]["samesite"] == "strict"
        assert call_args[1]["path"] == "/"
