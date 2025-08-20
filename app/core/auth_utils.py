"""Authentication utilities to avoid circular dependencies."""

from typing import Optional

from fastapi import Request
from structlog.stdlib import get_logger

logger = get_logger(__name__)


def get_current_user_id_from_request(request: Request) -> Optional[int]:
    """Extract current user ID from request state.

    This function is used to avoid circular dependency between core and middleware.
    The actual authentication is done in middleware, this just reads the result.

    Args:
        request: FastAPI request object

    Returns:
        User ID if authenticated, None otherwise
    """
    # Check request state for user_id (set by authentication middleware)
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        try:
            return int(user_id)
        except (ValueError, TypeError):
            logger.warning("Invalid user_id in request state", user_id=user_id)

    # Check for user object in request state
    user = getattr(request.state, "user", None)
    if user and hasattr(user, "id"):
        return user.id

    return None


async def get_oauth_user_from_request(request: Request) -> Optional[object]:
    """Extract OAuth user from request state.

    This function is used to avoid circular dependency between core and middleware.
    The actual OAuth validation is done in middleware, this just reads the result.

    Args:
        request: FastAPI request object

    Returns:
        OAuth user if authenticated, None otherwise
    """
    # Check request state for oauth_user (set by OAuth middleware)
    oauth_user = getattr(request.state, "oauth_user", None)
    if oauth_user:
        return oauth_user

    # Check for regular user object that might have been set via OAuth
    user = getattr(request.state, "user", None)
    if user and hasattr(user, "oauth_application_id"):
        return user

    return None


# Aliases for backward compatibility and architectural compliance
def get_current_user_id(request: Request) -> Optional[str]:
    """Alias for get_current_user_id_from_request that returns string ID for compatibility."""
    user_id = get_current_user_id_from_request(request)
    return str(user_id) if user_id is not None else None


async def get_oauth_user(request: Request) -> Optional[object]:
    """Alias for get_oauth_user_from_request."""
    return await get_oauth_user_from_request(request)
