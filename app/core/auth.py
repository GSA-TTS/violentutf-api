"""Core authentication logic with Clean Architecture compliance."""

from typing import TYPE_CHECKING, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from .container import get_auth_service, get_user_service
from .interfaces.user_interface import UserData

if TYPE_CHECKING:
    from ..models.user import User

logger = get_logger(__name__)


async def get_current_user_data(request: Request) -> UserData:
    """Get current authenticated user data using dependency injection.

    This function uses the authentication service to identify users
    and user service to load user data, maintaining core layer independence.

    Args:
        request: FastAPI request

    Returns:
        Current user data

    Raises:
        HTTPException: If user is not authenticated
    """
    auth_service = get_auth_service()
    user_service = get_user_service()

    if not auth_service or not user_service:
        raise HTTPException(status_code=500, detail="Authentication services not configured")

    # Try JWT authentication first

    user_id = await auth_service.get_user_id_from_request(request)

    if user_id:
        # Load user from service
        user_data = await user_service.get_user_by_id(user_id)

        if user_data and user_data.is_active:
            return user_data

    # Try OAuth2 authentication
    oauth_data = await auth_service.validate_oauth_token(request)
    if oauth_data and oauth_data.get("is_active"):
        # Convert OAuth data to UserData
        return UserData(
            id=oauth_data["id"],
            username=oauth_data.get("username", ""),
            email=oauth_data.get("email", ""),
            is_active=oauth_data.get("is_active", False),
            is_verified=oauth_data.get("is_verified", False),
            is_superuser=oauth_data.get("is_superuser", False),
            roles=oauth_data.get("roles", []),
            organization_id=oauth_data.get("organization_id"),
        )

    # No valid authentication found
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def validate_active_user(user_data: UserData) -> UserData:
    """Validate that user is active.

    Args:
        user_data: User data to validate

    Returns:
        User data if active

    Raises:
        HTTPException: If user is not active
    """
    if not user_data.is_active:
        raise HTTPException(
            status_code=403,
            detail="Inactive user",
        )
    return user_data

def validate_superuser(user_data: UserData) -> UserData:
    """Validate that user is a superuser.

    Args:
        user_data: User data to validate

    Returns:
        User data if superuser

    Raises:
        HTTPException: If user is not a superuser
    """
    if not user_data.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges",
        )
    return user_data


async def get_optional_current_user_data(
    request: Request,
) -> Optional[UserData]:
    """Get current user data if authenticated, None otherwise.

    Args:
        request: FastAPI request

    Returns:
        Current user data or None
    """
    try:
        return await get_current_user_data(request)
    except HTTPException:
        return None


async def get_current_user(request: Request) -> "User":
    """Get current authenticated user as User model object.

    This function provides backward compatibility for endpoints expecting User objects.

    Args:
        request: FastAPI request

    Returns:
        Current user as User model

    Raises:
        HTTPException: If user is not authenticated
    """
    from sqlalchemy import select

    from ..db.session import get_db
    from ..models.user import User

    # Get user data first
    user_data = await get_current_user_data(request)

    # Convert to User object by fetching from database
    async for db_session in get_db():
        result = await db_session.execute(select(User).where(User.id == user_data.id))
        user_obj = result.scalar_one_or_none()
        if user_obj:
            return user_obj
        break

    # If user not found in database, raise error
    raise HTTPException(
        status_code=404,
        detail="User not found in database",
    )


async def get_current_active_user(request: Request) -> "User":
    """Get current active user as User model object.

    Args:
        request: FastAPI request

    Returns:
        Current active user as User model

    Raises:
        HTTPException: If user is not authenticated or inactive
    """
    user = await get_current_user(request)
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


async def get_current_superuser(request: Request) -> "User":
    """Get current superuser as User model object.

    Args:
        request: FastAPI request

    Returns:
        Current superuser as User model

    Raises:
        HTTPException: If user is not authenticated or not a superuser
    """
    user = await get_current_active_user(request)
    if not user.is_superuser:
        raise HTTPException(status_code=400, detail="The user doesn't have enough privileges")
    return user
