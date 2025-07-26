"""Session middleware for ViolentUTF API."""

from typing import Any, Awaitable, Callable, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.config import settings
from ..core.session import SESSION_COOKIE_NAME, get_session_manager

logger = get_logger(__name__)


class SessionMiddleware(BaseHTTPMiddleware):
    """Middleware for secure session management."""

    def __init__(self, app: BaseHTTPMiddleware) -> None:
        """Initialize session middleware."""
        super().__init__(app)
        self.session_manager = get_session_manager()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:  # noqa: C901
        """Process request with session handling.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response with session cookie if needed
        """
        # Extract session ID from cookie
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        request.state.session = None
        request.state.session_id = None

        # Load session if ID provided
        if session_id:
            try:
                # Get client info for validation
                client_ip = request.client.host if request.client else None
                user_agent = request.headers.get("User-Agent")

                # Validate and load session
                if await self.session_manager.validate_session(session_id, ip_address=client_ip, user_agent=user_agent):
                    session_data = await self.session_manager.get_session(session_id)
                    if session_data:
                        request.state.session = session_data
                        request.state.session_id = session_id
                        request.state.user_id = session_data.get("user_id")

                        # Check if rotation is recommended
                        if session_data.get("rotation_recommended"):
                            request.state.session_rotation_needed = True
                else:
                    # Invalid session, clear it
                    logger.warning("invalid_session_cleared", session_id=session_id[:8] + "...")
            except Exception as e:
                logger.error("session_loading_error", error=str(e))

        # Process request
        response = await call_next(request)

        # Handle session updates
        if hasattr(request.state, "new_session_id"):
            # New session created, set cookie
            self._set_session_cookie(response, request.state.new_session_id)
        elif hasattr(request.state, "delete_session") and request.state.delete_session:
            # Session deletion requested, clear cookie
            self._clear_session_cookie(response)
        elif hasattr(request.state, "rotate_session") and request.state.rotate_session:
            # Session rotation requested
            if session_id:
                client_ip = request.client.host if request.client else None
                user_agent = request.headers.get("User-Agent")
                new_session_id = await self.session_manager.rotate_session(
                    session_id, ip_address=client_ip, user_agent=user_agent
                )
                if new_session_id:
                    self._set_session_cookie(response, new_session_id)

        return response

    def _set_session_cookie(self, response: Response, session_id: str) -> None:
        """Set session cookie with security options.

        Args:
            response: Response to add cookie to
            session_id: Session ID to set
        """
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,  # Prevent JS access
            secure=settings.SECURE_COOKIES,  # HTTPS only in production
            samesite="strict",  # CSRF protection
            path="/",
            domain=None,  # Current domain only
        )
        logger.debug("session_cookie_set", session_id=session_id[:8] + "...")

    def _clear_session_cookie(self, response: Response) -> None:
        """Clear session cookie.

        Args:
            response: Response to clear cookie from
        """
        response.delete_cookie(
            key=SESSION_COOKIE_NAME,
            path="/",
            httponly=True,
            secure=settings.SECURE_COOKIES,
            samesite="strict",
        )
        logger.debug("session_cookie_cleared")


def create_session_for_user(request: Request, user_id: str, user_data: Optional[Dict[str, Any]] = None) -> None:
    """Create session for authenticated user.

    Args:
        request: Current request
        user_id: User ID to create session for
        user_data: Additional user data
    """
    # This will be picked up by the middleware
    request.state.create_session = True
    request.state.session_user_id = user_id
    request.state.session_user_data = user_data or {}


def delete_current_session(request: Request) -> None:
    """Delete current session.

    Args:
        request: Current request
    """
    request.state.delete_session = True


def rotate_current_session(request: Request) -> None:
    """Rotate current session.

    Args:
        request: Current request
    """
    request.state.rotate_session = True
