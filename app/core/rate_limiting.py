"""Rate limiting configuration and utilities for ViolentUTF API.

This module implements comprehensive rate limiting using SlowAPI with Redis backend,
following ADR-005 specifications for multi-layered rate limiting.
"""

import os
from functools import wraps
from typing import Any, Callable, Dict, Optional

from fastapi import HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from structlog.stdlib import get_logger

from .config import settings

logger = get_logger(__name__)

# Rate limit configurations for different endpoint types
# Following ADR-005 multi-layered approach
RATE_LIMITS = {
    # Authentication endpoints - strict limits to prevent credential stuffing
    "auth_login": "5/minute",
    "auth_register": "3/minute",
    "auth_refresh": "10/minute",
    "auth_logout": "10/minute",
    "auth_password_reset": "3/hour",
    # User management - moderate limits
    "user_create": "10/minute",
    "user_read": "60/minute",
    "user_update": "30/minute",
    "user_delete": "10/minute",
    "user_list": "30/minute",
    # API key management - strict limits for security
    "api_key_create": "5/minute",
    "api_key_list": "20/minute",
    "api_key_delete": "10/minute",
    # Health/status endpoints - relaxed limits
    "health_check": "120/minute",
    "readiness": "60/minute",
    # Resource-intensive endpoints - very strict limits
    "scan_create": "10/minute",  # Large-scale security scans
    "report_generate": "20/minute",  # Complex report generation
    "admin_operation": "5/minute",  # Administrative operations
    # Default for unspecified endpoints
    "default": "30/minute",
}


def get_rate_limit_key(request: Request) -> str:
    """
    Get rate limit key for request based on authentication state.

    Uses organization_id from JWT if available, API key if present,
    otherwise falls back to IP address.

    Args:
        request: FastAPI request object

    Returns:
        Rate limit key string for the request
    """
    # Check if request has state attribute
    if not hasattr(request, "state"):
        return get_remote_address(request)  # type: ignore[no-any-return]

    # Check if user is authenticated with JWT
    user_id = getattr(request.state, "user_id", None)
    organization_id = getattr(request.state, "organization_id", None)

    if organization_id:
        # Use organization_id for rate limiting (multi-tenant)
        return f"org:{organization_id}"
    elif user_id:
        # Use user_id if no organization context
        return f"user:{user_id}"

    # Check for API key authentication
    api_key = getattr(request.state, "api_key", None)
    if api_key:
        # Use truncated API key for rate limiting
        return f"api_key:{api_key[:8]}"

    # Fall back to IP address for unauthenticated requests
    return get_remote_address(request)  # type: ignore[no-any-return]


def get_rate_limit(endpoint_type: str) -> str:
    """
    Get rate limit configuration for specific endpoint type.

    Args:
        endpoint_type: Type of endpoint from RATE_LIMITS keys

    Returns:
        Rate limit string (e.g., "5/minute")
    """
    return RATE_LIMITS.get(endpoint_type, RATE_LIMITS["default"])


# Create limiter with custom key function for user-aware rate limiting
limiter = Limiter(
    key_func=get_rate_limit_key,
    storage_uri=settings.REDIS_URL if settings.REDIS_URL else "memory://",
    enabled=settings.RATE_LIMIT_ENABLED,
)

# Also create a simple IP-based limiter for fallback scenarios
ip_limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL if settings.REDIS_URL else "memory://",
    enabled=settings.RATE_LIMIT_ENABLED,
)


def rate_limit(endpoint_type: str) -> Callable[..., Any]:
    """
    Create rate limit decorator for specific endpoint type.

    Args:
        endpoint_type: Type of endpoint from RATE_LIMITS keys

    Returns:
        Decorator function that applies rate limiting
    """
    if not settings.RATE_LIMIT_ENABLED:
        # Return pass-through decorator if rate limiting is disabled
        def disabled_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return func

        return disabled_decorator

    rate_limit_str = get_rate_limit(endpoint_type)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # For compatibility with existing endpoints, check if function has Request parameter
        import inspect

        from fastapi import Request

        sig = inspect.signature(func)
        has_request_param = any(
            param.annotation == Request or param.name.lower() in ["request", "http_request"]
            for param in sig.parameters.values()
        )

        if has_request_param:
            # Apply SlowAPI limiter decorator directly
            limited_func = limiter.limit(rate_limit_str)(func)

            @wraps(limited_func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return await limited_func(*args, **kwargs)
                except Exception as e:
                    # Log rate limiting events for monitoring
                    logger.warning(
                        "rate_limit_exceeded", endpoint_type=endpoint_type, rate_limit=rate_limit_str, error=str(e)
                    )
                    raise

            return wrapper
        else:
            # For endpoints without request parameter, return original function
            # Rate limiting will be handled at middleware level
            logger.info("rate_limit_skipped_no_request_param", endpoint_type=endpoint_type, function_name=func.__name__)
            return func

    return decorator


def ip_rate_limit(rate_limit_str: str) -> Callable[..., Any]:
    """
    Create IP-based rate limit decorator for specific rate.

    Useful for endpoints that need IP-based limiting regardless of authentication.

    Args:
        rate_limit_str: Rate limit string (e.g., "5/minute")

    Returns:
        Decorator function that applies IP-based rate limiting
    """
    if not settings.RATE_LIMIT_ENABLED:

        def disabled_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return func

        return disabled_decorator

    return ip_limiter.limit(rate_limit_str)  # type: ignore[no-any-return]


def add_rate_limit_headers(request: Request, response: Any) -> None:
    """
    Add rate limit headers to response.

    SlowAPI automatically adds these headers:
    - X-RateLimit-Limit: Maximum requests allowed
    - X-RateLimit-Remaining: Requests remaining in window
    - X-RateLimit-Reset: When the window resets
    - Retry-After: Seconds to wait (on 429 responses)

    Args:
        request: FastAPI request object
        response: FastAPI response object
    """
    # Headers are automatically added by SlowAPI
    # This function exists for potential custom header logic
    pass


def get_rate_limit_status(request: Request, endpoint_type: str) -> Dict[str, Any]:
    """
    Get current rate limit status for a request.

    Args:
        request: FastAPI request object
        endpoint_type: Type of endpoint to check

    Returns:
        Dictionary with rate limit status information
    """
    if not settings.RATE_LIMIT_ENABLED:
        return {"enabled": False, "limit": "unlimited", "remaining": "unlimited", "reset_time": None}

    # This would require integration with SlowAPI's internal state
    # For now, return basic information
    rate_limit_str = get_rate_limit(endpoint_type)
    key = get_rate_limit_key(request)

    return {"enabled": True, "limit": rate_limit_str, "key": key, "endpoint_type": endpoint_type}


class RateLimitExceeded(HTTPException):
    """Custom exception for rate limit exceeded scenarios."""

    def __init__(self, detail: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(retry_after)} if retry_after else None,
        )
