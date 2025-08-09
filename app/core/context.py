"""
Organization Context Management

This module provides utilities for extracting and managing organization context
from authenticated requests to ensure proper multi-tenant isolation.
"""

from typing import Optional

from fastapi import Request
from structlog.stdlib import get_logger

logger = get_logger(__name__)


def get_organization_id(request: Request) -> Optional[str]:
    """
    Extract organization ID from authenticated request.

    This function provides a centralized way to get the organization context
    from an authenticated request, ensuring consistent multi-tenant isolation.

    Args:
        request: FastAPI request object with authentication state

    Returns:
        Organization ID string if available, None otherwise
    """
    # Organization ID should be set by authentication middleware
    organization_id = getattr(request.state, "organization_id", None)

    if organization_id:
        return str(organization_id)

    # Log when organization_id is missing for authenticated requests
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        logger.warning(
            "Authenticated request missing organization_id",
            user_id=user_id,
            path=request.url.path,
            method=request.method,
        )

    return None


def get_user_id(request: Request) -> Optional[str]:
    """
    Extract user ID from authenticated request.

    Args:
        request: FastAPI request object with authentication state

    Returns:
        User ID string if available, None otherwise
    """
    user_id = getattr(request.state, "user_id", None)
    return str(user_id) if user_id else None


def ensure_organization_context(request: Request) -> str:
    """
    Ensure organization context is available and valid.

    This function should be used when organization context is required
    for security purposes.

    Args:
        request: FastAPI request object

    Returns:
        Organization ID string

    Raises:
        ValueError: If organization context is missing
    """
    org_id = get_organization_id(request)
    if not org_id:
        user_id = get_user_id(request)
        logger.error(
            "Missing organization context for secure operation",
            user_id=user_id,
            path=request.url.path,
            method=request.method,
        )
        raise ValueError("Organization context is required for this operation")

    return org_id


def get_security_context(request: Request) -> dict:
    """
    Get complete security context from request.

    Returns:
        Dictionary containing user_id, organization_id, and other security context
    """
    return {
        "user_id": get_user_id(request),
        "organization_id": get_organization_id(request),
        "authority_level": getattr(request.state, "authority_level", None),
        "full_user": getattr(request.state, "full_user", None),
        "token_payload": getattr(request.state, "token_payload", None),
    }
