"""Authentication service interface for dependency injection."""

from abc import ABC, abstractmethod
from typing import Optional

from fastapi import Request


class IAuthenticationService(ABC):
    """Abstract interface for authentication services."""

    @abstractmethod
    async def get_user_id_from_request(self, request: Request) -> Optional[str]:
        """Extract user ID from request authentication.

        Args:
            request: FastAPI request object

        Returns:
            User ID if authenticated, None otherwise
        """
        pass

    @abstractmethod
    async def validate_oauth_token(self, request: Request) -> Optional[dict]:
        """Validate OAuth2 token from request.

        Args:
            request: FastAPI request object

        Returns:
            User data if valid token, None otherwise
        """
        pass

    @abstractmethod
    async def is_user_active(self, user_id: str) -> bool:
        """Check if user is active.

        Args:
            user_id: User identifier

        Returns:
            True if user is active, False otherwise
        """
        pass
