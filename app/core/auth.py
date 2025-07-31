"""Authentication dependencies for FastAPI endpoints."""

from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.db.session import get_db
from app.middleware.authentication import get_current_user_id
from app.middleware.oauth import get_oauth_user
from app.models.user import User
from app.repositories.user import UserRepository

logger = get_logger(__name__)


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> User:
    """Get current authenticated user.

    This dependency tries multiple authentication methods:
    1. JWT authentication (from cookies or headers)
    2. OAuth2 bearer token
    3. API key authentication (if implemented)

    Args:
        request: FastAPI request
        session: Database session

    Returns:
        Current user object

    Raises:
        HTTPException: If user is not authenticated
    """
    # Try JWT authentication first
    user_id = get_current_user_id(request)

    if user_id:
        # Load user from database
        user_repo = UserRepository(session)
        user = await user_repo.get(user_id)

        if user and user.is_active:
            return user

    # Try OAuth2 authentication
    oauth_user = await get_oauth_user(request)
    if oauth_user and oauth_user.is_active:
        return oauth_user

    # No valid authentication found
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
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
    current_user: User = Depends(get_current_user),
) -> User:
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
    session: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Get current user if authenticated, None otherwise.

    Args:
        request: FastAPI request
        session: Database session

    Returns:
        Current user or None
    """
    try:
        return await get_current_user(request, session)
    except HTTPException:
        return None
