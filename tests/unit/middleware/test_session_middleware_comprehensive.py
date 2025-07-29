"""Comprehensive tests for session middleware to achieve 90%+ coverage."""

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import Request, Response
from starlette.datastructures import Headers, State
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.session import SESSION_COOKIE_NAME
from app.middleware.session import (
    SessionMiddleware,
    create_session_for_user,
    delete_current_session,
    rotate_current_session,
)


@pytest.fixture
def mock_request():
    """Create mock request."""
    request = MagicMock(spec=Request)
    request.state = State()
    request.cookies = {}
    request.headers = Headers({})
    request.client = MagicMock()
    request.client.host = "192.168.1.1"
    return request


@pytest.fixture
def mock_response():
    """Create mock response."""
    response = MagicMock(spec=Response)
    response.set_cookie = MagicMock()
    response.delete_cookie = MagicMock()
    return response


@pytest.fixture
def mock_session_manager():
    """Create mock session manager."""
    manager = AsyncMock()
    manager.validate_session = AsyncMock(return_value=True)
    manager.get_session = AsyncMock()
    manager.rotate_session = AsyncMock()
    return manager


@pytest.fixture
def mock_settings():
    """Mock settings."""
    with patch("app.middleware.session.settings") as mock:
        mock.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        mock.SECURE_COOKIES = True
        yield mock


@pytest.fixture
def session_middleware(mock_session_manager):
    """Create session middleware with mocked dependencies."""
    app = MagicMock(spec=BaseHTTPMiddleware)

    with patch("app.middleware.session.get_session_manager", return_value=mock_session_manager):
        middleware = SessionMiddleware(app)
        middleware.session_manager = mock_session_manager
        return middleware


class TestSessionMiddlewareInit:
    """Test SessionMiddleware initialization."""

    def test_init(self, mock_session_manager):
        """Test middleware initialization."""
        app = MagicMock(spec=BaseHTTPMiddleware)

        with patch("app.middleware.session.get_session_manager", return_value=mock_session_manager):
            middleware = SessionMiddleware(app)

            assert middleware.session_manager == mock_session_manager


class TestSessionMiddlewareDispatch:
    """Test SessionMiddleware dispatch method."""

    @pytest.mark.asyncio
    async def test_dispatch_no_session(self, session_middleware, mock_request, mock_response):
        """Test request without session cookie."""
        # No session cookie
        mock_request.cookies = {}

        # Mock call_next
        async def call_next(request):
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        assert result == mock_response
        assert mock_request.state.session is None
        assert mock_request.state.session_id is None

        # Should not try to load session
        session_middleware.session_manager.validate_session.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_with_valid_session(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test request with valid session cookie."""
        # Set session cookie
        session_id = "test_session_123"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}
        mock_request.headers = Headers({"User-Agent": "TestBrowser/1.0"})

        # Mock session data
        session_data = {"session_id": session_id, "user_id": "user_456", "role": "user", "permissions": ["read"]}
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = session_data

        # Mock call_next
        async def call_next(request):
            # Verify session was loaded
            assert request.state.session == session_data
            assert request.state.session_id == session_id
            assert request.state.user_id == "user_456"
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        assert result == mock_response

        # Verify session validation
        mock_session_manager.validate_session.assert_called_once_with(
            session_id, ip_address="192.168.1.1", user_agent="TestBrowser/1.0"
        )
        mock_session_manager.get_session.assert_called_once_with(session_id)

    @pytest.mark.asyncio
    async def test_dispatch_with_invalid_session(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test request with invalid session cookie."""
        # Set invalid session cookie
        session_id = "invalid_session"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}

        # Mock invalid session
        mock_session_manager.validate_session.return_value = False

        # Mock call_next
        async def call_next(request):
            # Session should be cleared
            assert request.state.session is None
            assert request.state.session_id is None
            return mock_response

        with patch("app.middleware.session.logger") as mock_logger:
            result = await session_middleware.dispatch(mock_request, call_next)

            assert result == mock_response
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_session_rotation_recommended(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test session with rotation recommendation."""
        session_id = "old_session"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}

        # Mock session with rotation recommendation
        session_data = {"session_id": session_id, "user_id": "user_123", "rotation_recommended": True}
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = session_data

        # Mock call_next
        async def call_next(request):
            assert request.state.session_rotation_needed is True
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        assert result == mock_response

    @pytest.mark.asyncio
    async def test_dispatch_session_loading_error(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test session loading with exception."""
        session_id = "error_session"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}

        # Mock session loading error
        mock_session_manager.validate_session.side_effect = Exception("Redis error")

        # Mock call_next
        async def call_next(request):
            # Session should be None due to error
            assert request.state.session is None
            return mock_response

        with patch("app.middleware.session.logger") as mock_logger:
            result = await session_middleware.dispatch(mock_request, call_next)

            assert result == mock_response
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_new_session_creation(self, session_middleware, mock_request, mock_response, mock_settings):
        """Test creating new session."""
        # No initial session
        mock_request.cookies = {}

        # Mock call_next that creates session
        async def call_next(request):
            request.state.new_session_id = "new_session_123"
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Verify cookie was set
        mock_response.set_cookie.assert_called_once_with(
            key=SESSION_COOKIE_NAME,
            value="new_session_123",
            max_age=1800,  # 30 * 60
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
            domain=None,
        )

    @pytest.mark.asyncio
    async def test_dispatch_session_deletion(self, session_middleware, mock_request, mock_response, mock_settings):
        """Test deleting session."""
        # Existing session
        mock_request.cookies = {SESSION_COOKIE_NAME: "delete_me"}

        # Mock call_next that requests deletion
        async def call_next(request):
            request.state.delete_session = True
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Verify cookie was deleted
        mock_response.delete_cookie.assert_called_once_with(
            key=SESSION_COOKIE_NAME, path="/", httponly=True, secure=True, samesite="strict"
        )

    @pytest.mark.asyncio
    async def test_dispatch_session_rotation(
        self, session_middleware, mock_request, mock_response, mock_session_manager, mock_settings
    ):
        """Test session rotation."""
        old_session_id = "old_session"
        new_session_id = "new_session_123"
        mock_request.cookies = {SESSION_COOKIE_NAME: old_session_id}
        mock_request.headers = Headers({"User-Agent": "RotateTest/1.0"})

        # Mock rotation
        mock_session_manager.rotate_session.return_value = new_session_id

        # Mock call_next that requests rotation
        async def call_next(request):
            request.state.rotate_session = True
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Verify rotation was called
        mock_session_manager.rotate_session.assert_called_once_with(
            old_session_id, ip_address="192.168.1.1", user_agent="RotateTest/1.0"
        )

        # Verify new cookie was set
        mock_response.set_cookie.assert_called_once()
        cookie_call = mock_response.set_cookie.call_args
        assert cookie_call[1]["value"] == new_session_id

    @pytest.mark.asyncio
    async def test_dispatch_rotation_without_session(self, session_middleware, mock_request, mock_response):
        """Test rotation request without existing session."""
        # No session cookie
        mock_request.cookies = {}

        # Mock call_next that requests rotation
        async def call_next(request):
            request.state.rotate_session = True
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Should not attempt rotation
        session_middleware.session_manager.rotate_session.assert_not_called()
        mock_response.set_cookie.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_rotation_failure(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test rotation when rotation fails."""
        old_session_id = "old_session"
        mock_request.cookies = {SESSION_COOKIE_NAME: old_session_id}

        # Mock failed rotation
        mock_session_manager.rotate_session.return_value = None

        # Mock call_next that requests rotation
        async def call_next(request):
            request.state.rotate_session = True
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Should not set cookie if rotation failed
        mock_response.set_cookie.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_no_client_info(self, session_middleware, mock_request, mock_response, mock_session_manager):
        """Test request without client info."""
        session_id = "test_session"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}
        mock_request.client = None  # No client info
        mock_request.headers = Headers({})  # No User-Agent

        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = {"session_id": session_id}

        # Mock call_next
        async def call_next(request):
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        # Should still work but with None values
        mock_session_manager.validate_session.assert_called_once_with(session_id, ip_address=None, user_agent=None)


class TestSessionMiddlewareCookieHandling:
    """Test cookie handling methods."""

    def test_set_session_cookie(self, session_middleware, mock_response, mock_settings):
        """Test setting session cookie."""
        session_id = "test_session_123"

        with patch("app.middleware.session.logger") as mock_logger:
            session_middleware._set_session_cookie(mock_response, session_id)

            mock_response.set_cookie.assert_called_once_with(
                key=SESSION_COOKIE_NAME,
                value=session_id,
                max_age=1800,  # 30 * 60
                httponly=True,
                secure=True,
                samesite="strict",
                path="/",
                domain=None,
            )

            mock_logger.debug.assert_called_once()

    def test_set_session_cookie_insecure(self, session_middleware, mock_response, mock_settings):
        """Test setting session cookie in insecure mode."""
        mock_settings.SECURE_COOKIES = False
        session_id = "test_session_456"

        session_middleware._set_session_cookie(mock_response, session_id)

        cookie_args = mock_response.set_cookie.call_args[1]
        assert cookie_args["secure"] is False

    def test_clear_session_cookie(self, session_middleware, mock_response, mock_settings):
        """Test clearing session cookie."""
        with patch("app.middleware.session.logger") as mock_logger:
            session_middleware._clear_session_cookie(mock_response)

            mock_response.delete_cookie.assert_called_once_with(
                key=SESSION_COOKIE_NAME, path="/", httponly=True, secure=True, samesite="strict"
            )

            mock_logger.debug.assert_called_once()


class TestSessionHelperFunctions:
    """Test helper functions."""

    def test_create_session_for_user(self, mock_request):
        """Test create_session_for_user helper."""
        user_id = "user_789"
        user_data = {"role": "admin", "permissions": ["all"]}

        create_session_for_user(mock_request, user_id, user_data)

        assert mock_request.state.create_session is True
        assert mock_request.state.session_user_id == user_id
        assert mock_request.state.session_user_data == user_data

    def test_create_session_for_user_no_data(self, mock_request):
        """Test create_session_for_user without user data."""
        user_id = "user_minimal"

        create_session_for_user(mock_request, user_id)

        assert mock_request.state.create_session is True
        assert mock_request.state.session_user_id == user_id
        assert mock_request.state.session_user_data == {}

    def test_delete_current_session(self, mock_request):
        """Test delete_current_session helper."""
        delete_current_session(mock_request)

        assert mock_request.state.delete_session is True

    def test_rotate_current_session(self, mock_request):
        """Test rotate_current_session helper."""
        rotate_current_session(mock_request)

        assert mock_request.state.rotate_session is True


class TestSessionMiddlewareIntegration:
    """Test integration scenarios."""

    @pytest.mark.asyncio
    async def test_full_session_lifecycle(
        self, session_middleware, mock_request, mock_response, mock_session_manager, mock_settings
    ):
        """Test complete session lifecycle."""
        # 1. Initial request without session
        mock_request.cookies = {}

        async def create_session_handler(request):
            # Simulate login - create session
            request.state.new_session_id = "session_123"
            return mock_response

        await session_middleware.dispatch(mock_request, create_session_handler)
        assert mock_response.set_cookie.called

        # 2. Subsequent request with session
        mock_request.cookies = {SESSION_COOKIE_NAME: "session_123"}
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = {"session_id": "session_123", "user_id": "user_123"}

        async def use_session_handler(request):
            assert request.state.session is not None
            return mock_response

        mock_response.set_cookie.reset_mock()
        # Clear state from previous request to avoid state contamination
        if hasattr(mock_request.state, "new_session_id"):
            delattr(mock_request.state, "new_session_id")
        await session_middleware.dispatch(mock_request, use_session_handler)
        assert not mock_response.set_cookie.called

        # 3. Rotation
        mock_session_manager.rotate_session.return_value = "new_session_456"

        async def rotate_handler(request):
            request.state.rotate_session = True
            return mock_response

        await session_middleware.dispatch(mock_request, rotate_handler)
        mock_session_manager.rotate_session.assert_called_once()
        assert mock_response.set_cookie.called

        # 4. Deletion
        mock_response.set_cookie.reset_mock()

        async def logout_handler(request):
            request.state.delete_session = True
            return mock_response

        await session_middleware.dispatch(mock_request, logout_handler)
        mock_response.delete_cookie.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_session_operations(self, session_middleware, mock_request, mock_response):
        """Test that only one session operation is performed."""
        # Request with multiple session operations
        mock_request.cookies = {SESSION_COOKIE_NAME: "test_session"}

        async def conflicting_handler(request):
            # Set multiple conflicting operations
            request.state.new_session_id = "new_session"
            request.state.delete_session = True
            request.state.rotate_session = True
            return mock_response

        await session_middleware.dispatch(mock_request, conflicting_handler)

        # Only the first operation should be performed (new session)
        assert mock_response.set_cookie.call_count == 1
        assert mock_response.delete_cookie.call_count == 0
        session_middleware.session_manager.rotate_session.assert_not_called()

    @pytest.mark.asyncio
    async def test_session_validation_with_missing_data(
        self, session_middleware, mock_request, mock_response, mock_session_manager
    ):
        """Test session validation when get_session returns None."""
        session_id = "valid_but_missing"
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}

        # Session validates but data is missing
        mock_session_manager.validate_session.return_value = True
        mock_session_manager.get_session.return_value = None

        async def call_next(request):
            # Session should not be set if data is None
            assert request.state.session is None
            assert request.state.session_id is None
            return mock_response

        result = await session_middleware.dispatch(mock_request, call_next)

        assert result == mock_response
