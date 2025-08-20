"""
API Dependencies Module.

This module provides common dependency injection functions for FastAPI endpoints.
It consolidates authentication, database access, and other shared dependencies.
"""

from typing import TYPE_CHECKING, Optional

from fastapi import Depends, HTTPException, Request, status

# Import existing authentication functions
from app.core.auth import (
    get_current_active_user,
    get_current_superuser,
    get_current_user,
    get_optional_current_user_data,
)

# Import db session dependency for backward compatibility
from app.db.session import get_db

if TYPE_CHECKING:
    from app.models.user import User
else:
    # Import User for runtime to maintain backward compatibility
    from app.models.user import User


async def get_current_verified_user(current_user: "User" = Depends(get_current_active_user)) -> "User":
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


async def get_optional_user(request: Request) -> Optional["User"]:
    """Get optional user dependency injection.

    Attempts to get current user but doesn't fail if not authenticated.
    Useful for endpoints that work with or without authentication.

    Args:
        request: FastAPI request object

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
