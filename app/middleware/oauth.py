"""OAuth2 authentication middleware for third-party access."""

import json
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import AuthenticationError
from app.dependencies.middleware import get_middleware_service
from app.services.oauth_service import OAuth2Service

logger = get_logger(__name__)


class OAuth2Bearer(HTTPBearer):
    """OAuth2 Bearer token authentication."""

    def __init__(self, auto_error: bool = True):
        """Initialize OAuth2 bearer authentication.

        Args:
            auto_error: Whether to automatically raise HTTP 401 for invalid tokens
        """
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        """Extract and validate OAuth2 bearer token.

        Args:
            request: FastAPI request

        Returns:
            Access token if valid, None otherwise

        Raises:
            HTTPException: If token is invalid and auto_error is True
        """
        credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(request)

        if not credentials:
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail="Authorization header missing",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        if credentials.scheme != "Bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid authentication scheme",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        return credentials.credentials


oauth2_scheme = OAuth2Bearer(auto_error=False)


async def get_oauth_user(request: Request, token: Optional[str] = None):
    """Get user from OAuth2 token.

    Args:
        request: FastAPI request
        token: OAuth2 access token

    Returns:
        User object if authenticated, None otherwise
    """
    if not token:
        # Try to get token from request
        token = await oauth2_scheme(request)

    if not token:
        return None

    try:
        # Get middleware service
        async for middleware_service in get_middleware_service():
            oauth_service = OAuth2Service(middleware_service.session)

            # Validate token and get user
            access_token, user, application = await oauth_service.validate_access_token(token)

            # Store OAuth context in request state
            request.state.oauth_token = access_token
            request.state.oauth_application = application
            request.state.oauth_scopes = json.loads(access_token.scopes)

            # Log OAuth access
            logger.info(
                "OAuth access",
                user_id=str(user.id),
                application_id=str(application.id),
                application_name=application.name,
                scopes=request.state.oauth_scopes,
            )

            return user

    except AuthenticationError as e:
        logger.warning(
            "Invalid OAuth token",
            error=str(e),
        )
        return None
    except Exception as e:
        logger.error(
            "OAuth authentication error",
            error=str(e),
        )
        return None


def require_oauth_scope(required_scope: str):
    """Decorator to require specific OAuth scope.

    Args:
        required_scope: Required scope name

    Returns:
        Decorator function
    """

    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Check if OAuth authentication was used
            if not hasattr(request.state, "oauth_scopes"):
                raise HTTPException(
                    status_code=403,
                    detail="OAuth authentication required",
                )

            # Check if required scope is granted
            if required_scope not in request.state.oauth_scopes:
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient scope. Required: {required_scope}",
                )

            return await func(request, *args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


def require_any_oauth_scope(*required_scopes: str):
    """Decorator to require any of the specified OAuth scopes.

    Args:
        *required_scopes: List of acceptable scopes

    Returns:
        Decorator function
    """

    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Check if OAuth authentication was used
            if not hasattr(request.state, "oauth_scopes"):
                raise HTTPException(
                    status_code=403,
                    detail="OAuth authentication required",
                )

            # Check if any required scope is granted
            granted_scopes = set(request.state.oauth_scopes)
            required_set = set(required_scopes)

            if not granted_scopes.intersection(required_set):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient scope. Required one of: {', '.join(required_scopes)}",
                )

            return await func(request, *args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


def require_all_oauth_scopes(*required_scopes: str):
    """Decorator to require all specified OAuth scopes.

    Args:
        *required_scopes: List of required scopes

    Returns:
        Decorator function
    """

    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Check if OAuth authentication was used
            if not hasattr(request.state, "oauth_scopes"):
                raise HTTPException(
                    status_code=403,
                    detail="OAuth authentication required",
                )

            # Check if all required scopes are granted
            granted_scopes = set(request.state.oauth_scopes)
            required_set = set(required_scopes)

            if not required_set.issubset(granted_scopes):
                missing = required_set - granted_scopes
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient scope. Missing: {', '.join(missing)}",
                )

            return await func(request, *args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator
