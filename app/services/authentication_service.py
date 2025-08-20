"""
Authentication service implementation for dependency injection.

This service implements authentication interfaces to maintain Clean Architecture
compliance by acting as an adapter between the core layer and infrastructure.
"""

from typing import Optional

from fastapi import Request
from structlog.stdlib import get_logger

from app.core.interfaces.auth_interface import IAuthenticationService
from app.middleware.authentication import get_current_user_id
from app.middleware.oauth import get_oauth_user

logger = get_logger(__name__)


class AuthenticationService(IAuthenticationService):
    """Authentication service implementation."""

    async def get_user_id_from_request(self, request: Request) -> Optional[str]:
        """Extract user ID from request authentication.

        Args:
            request: FastAPI request object

        Returns:
            User ID if authenticated, None otherwise
        """
        try:
            return get_current_user_id(request)
        except Exception as e:
            logger.debug("Failed to get user ID from request", error=str(e))
            return None

    async def validate_oauth_token(self, request: Request) -> Optional[dict]:
        """Validate OAuth2 token from request.

        Args:
            request: FastAPI request object

        Returns:
            User data if valid token, None otherwise
        """
        try:
            oauth_user = await get_oauth_user(request)
            if oauth_user:
                # Convert User model to dict for core layer
                return {
                    "id": str(oauth_user.id),
                    "username": oauth_user.username,
                    "email": oauth_user.email,
                    "is_active": oauth_user.is_active,
                    "is_verified": getattr(oauth_user, "is_verified", False),
                    "is_superuser": getattr(oauth_user, "is_superuser", False),
                    "roles": getattr(oauth_user, "roles", []),
                    "organization_id": (
                        str(oauth_user.organization_id) if getattr(oauth_user, "organization_id", None) else None
                    ),
                }
            return None
        except Exception as e:
            logger.debug("Failed to validate OAuth token", error=str(e))
            return None

    async def is_user_active(self, user_id: str) -> bool:
        """Check if user is active.

        Args:
            user_id: User identifier

        Returns:
            True if user is active, False otherwise
        """
        # This would typically query the user repository
        # For now, we'll assume users are active if they have a valid ID
        try:
            # In a real implementation, this would check the database
            return bool(user_id)
        except Exception:
            return False
