"""
API Dependencies Module.

This module provides common dependency injection functions for FastAPI endpoints.
It consolidates authentication, database access, and other shared dependencies.
"""

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

# Import existing authentication functions
from app.core.auth import (
    get_current_active_user,
    get_current_superuser,
    get_current_user,
)
from app.db.session import get_db
from app.models.user import User


async def get_current_verified_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Get verified user dependency injection.

    Ensures the current user is verified (email verified).

    Args:
        current_user: Current active user

    Returns:
        User: Verified user object

    Raises:
        HTTPException: If user is not verified
    """
    if not getattr(current_user, "is_verified", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unverified user")
    return current_user


async def get_optional_user(request: Request, db: AsyncSession = Depends(get_db)) -> Optional[User]:
    """Get optional user dependency injection.

    Attempts to get current user but doesn't fail if not authenticated.
    Useful for endpoints that work with or without authentication.

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        Optional[User]: User object if authenticated, None otherwise
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None
    except Exception:
        return None


# Legacy aliases for backward compatibility
get_current_user_dep = get_current_user
get_db_dep = get_db
