"""Authentication dependencies for FastAPI endpoints."""

from typing import TYPE_CHECKING, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.auth_utils import get_current_user_id_from_request, get_oauth_user_from_request
from app.dependencies.auth import get_auth_service

if TYPE_CHECKING:
    from app.models.user import User
    from app.services.auth_service import AuthService

logger = get_logger(__name__)


async def get_current_user(
    request: Request,
    auth_service: "AuthService" = Depends(get_auth_service),
) -> "User":
    """Get current authenticated user.

    This dependency tries multiple authentication methods:
    1. JWT authentication (from cookies or headers)
    2. OAuth2 bearer token
    3. API key authentication (if implemented)

    Args:
        request: FastAPI request
        auth_service: Authentication service

    Returns:
        Current user object

    Raises:
        HTTPException: If user is not authenticated
    """
    # Try JWT authentication first
    user_id = get_current_user_id_from_request(request)

    # Try OAuth2 authentication
    oauth_user = get_oauth_user_from_request(request)

    # Authenticate using service
    user = await auth_service.authenticate_user(user_id=user_id, oauth_user=oauth_user)

    if user:
        return user

    # No valid authentication found
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_active_user(
    current_user: "User" = Depends(get_current_user),
) -> "User":
    """Get current active user.

    Args:
        current_user: Current user from auth

    Returns:
        Current active user

    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Inactive user",
        )
    return current_user


async def get_current_superuser(
    current_user: "User" = Depends(get_current_user),
) -> "User":
    """Get current superuser.

    Args:
        current_user: Current user from auth

    Returns:
        Current superuser

    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges",
        )
    return current_user


async def get_optional_current_user(
    request: Request,
    auth_service: "AuthService" = Depends(get_auth_service),
) -> Optional["User"]:
    """Get current user if authenticated, None otherwise.

    Args:
        request: FastAPI request
        auth_service: Authentication service

    Returns:
        Current user or None
    """
    try:
        return await get_current_user(request, auth_service)
    except HTTPException:
        return None
