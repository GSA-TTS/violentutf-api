"""Audit logging decorators and utilities for enhanced tracking."""

import time
from functools import wraps
from typing import Any, Callable, Dict, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.services.audit_service import AuditService

logger = get_logger(__name__)


def audit_action(
    action: str,
    resource_type: str,
    extract_resource_id: Optional[Callable] = None,
    include_changes: bool = False,
    sensitive: bool = False,
) -> Callable:
    """Decorator to audit specific actions.

    Args:
        action: Action being performed (e.g., "create", "update", "delete")
        resource_type: Type of resource being acted upon
        extract_resource_id: Function to extract resource ID from response
        include_changes: Whether to include before/after changes
        sensitive: Whether this is a sensitive operation requiring enhanced logging

    Returns:
        Decorator function

    Example:
        @audit_action("create", "api_key", extract_resource_id=lambda r: r.data["id"])
        async def create_api_key(...):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            request = None
            session = None

            # Extract request and session from arguments
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    session = arg

            # Check keyword arguments too
            if request is None:
                request = kwargs.get("request")
            if session is None:
                session = kwargs.get("session")

            # Get user information
            user_id = None
            user_email = None
            if request:
                user_id = getattr(request.state, "user_id", None)
                user = getattr(request.state, "user", None)
                if user and hasattr(user, "email"):
                    user_email = user.email

            # Initialize audit data
            audit_data = {
                "action": f"{resource_type}.{action}",
                "resource_type": resource_type,
                "user_id": str(user_id) if user_id else None,
                "user_email": user_email,
                "request": request,
                "metadata": {
                    "function": func.__name__,
                    "sensitive": sensitive,
                },
            }

            # Track changes if requested
            if include_changes and action in ["update", "delete"]:
                # Extract current state before modification
                # This would need to be customized per resource type
                pass

            try:
                # Execute the function
                result = await func(*args, **kwargs)

                # Extract resource ID if possible
                if extract_resource_id and result:
                    try:
                        resource_id = extract_resource_id(result)
                        audit_data["resource_id"] = str(resource_id)
                    except Exception as e:
                        logger.warning(
                            "Failed to extract resource ID",
                            error=str(e),
                            function=func.__name__,
                        )

                # Calculate duration
                duration_ms = int((time.time() - start_time) * 1000)
                audit_data["duration_ms"] = duration_ms
                audit_data["status"] = "success"

                # Log the audit event
                if session:
                    await _log_audit_event(session, audit_data)

                return result

            except Exception as e:
                # Log failed action
                audit_data["status"] = "failure"
                audit_data["error_message"] = str(e)
                audit_data["duration_ms"] = int((time.time() - start_time) * 1000)

                if session:
                    await _log_audit_event(session, audit_data)

                # Re-raise the exception
                raise

        return wrapper

    return decorator


def audit_auth_event(event_type: str) -> Callable:
    """Decorator specifically for authentication events.

    Args:
        event_type: Type of auth event (login_success, login_failed, etc.)

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            session = None

            # Extract request and session
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    session = arg

            if request is None:
                request = kwargs.get("request")
            if session is None:
                session = kwargs.get("session")

            # Get user information from request body (for login)
            user_email = None
            if request and event_type in ["login_success", "login_failed"]:
                try:
                    if hasattr(request, "_json"):
                        body = request._json
                    else:
                        body = kwargs.get("login_data", {})
                    user_email = body.get("email") or body.get("username")
                except Exception as e:
                    logger.debug("Failed to extract user email from request body", error=str(e))
                    user_email = None

            try:
                # Execute the function
                result = await func(*args, **kwargs)

                # Log successful auth event
                if session:
                    audit_service = AuditService(session)

                    # Extract user ID from result if available
                    user_id = None
                    if result and hasattr(result, "data"):
                        user_id = result.data.get("user_id")

                    await audit_service.log_auth_event(
                        event_type=event_type,
                        user_id=str(user_id) if user_id else None,
                        user_email=user_email,
                        request=request,
                        success=True,
                    )

                return result

            except Exception as e:
                # Log failed auth event
                if session and event_type.endswith("_failed"):
                    audit_service = AuditService(session)
                    await audit_service.log_auth_event(
                        event_type=event_type,
                        user_id=None,
                        user_email=user_email,
                        request=request,
                        success=False,
                        metadata={"error": str(e)},
                    )

                # Re-raise the exception
                raise

        return wrapper

    return decorator


def audit_security_event(
    event_type: str,
    risk_level: str = "medium",
) -> Callable:
    """Decorator for security-related events.

    Args:
        event_type: Type of security event
        risk_level: Risk level (low, medium, high, critical)

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            session = None

            # Extract request and session
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    session = arg

            if session:
                audit_service = AuditService(session)

                # Get user information
                user_id = None
                if request:
                    user_id = getattr(request.state, "user_id", None)

                # Log security event
                await audit_service.log_security_event(
                    event_type=event_type,
                    user_id=str(user_id) if user_id else None,
                    request=request,
                    risk_level=risk_level,
                    details={
                        "function": func.__name__,
                        "endpoint": request.url.path if request else None,
                    },
                )

            # Execute the function regardless
            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def _log_audit_event(session: AsyncSession, audit_data: Dict[str, Any]) -> None:
    """Helper to log audit event.

    Args:
        session: Database session
        audit_data: Audit event data
    """
    try:
        audit_service = AuditService(session)
        await audit_service.log_event(**audit_data)
    except Exception as e:
        logger.error(
            "Failed to log audit event",
            error=str(e),
            action=audit_data.get("action"),
        )


# Convenience decorators for common actions
def audit_create(resource_type: str) -> Callable:
    """Create decorator for resource creation."""
    return audit_action("create", resource_type)


def audit_update(resource_type: str) -> Callable:
    """Create decorator for resource updates."""
    return audit_action("update", resource_type, include_changes=True)


def audit_delete(resource_type: str) -> Callable:
    """Create decorator for resource deletion."""
    return audit_action("delete", resource_type)


def audit_read(resource_type: str) -> Callable:
    """Create decorator for resource reading."""
    return audit_action("read", resource_type)


def audit_export(resource_type: str) -> Callable:
    """Create decorator for resource export."""
    return audit_action("export", resource_type, sensitive=True)


class AuditContext:
    """Context manager for audit logging within a code block."""

    def __init__(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
        request: Optional[Request] = None,
    ):
        """Initialize audit context.

        Args:
            action: Action being performed
            resource_type: Type of resource
            resource_id: Resource identifier
            user_id: User performing action
            session: Database session
            request: Request object
        """
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.user_id = user_id
        self.session = session
        self.request = request
        self.start_time = None
        self.metadata: Dict[str, Any] = {}

    async def __aenter__(self):
        """Enter audit context."""
        self.start_time = time.time()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit audit context and log event."""
        if not self.session:
            return

        duration_ms = int((time.time() - self.start_time) * 1000)
        status = "success" if exc_type is None else "failure"
        error_message = str(exc_val) if exc_val else None

        try:
            audit_service = AuditService(self.session)
            await audit_service.log_event(
                action=f"{self.resource_type}.{self.action}",
                resource_type=self.resource_type,
                resource_id=self.resource_id,
                user_id=self.user_id,
                request=self.request,
                metadata=self.metadata,
                status=status,
                error_message=error_message,
                duration_ms=duration_ms,
            )
        except Exception as e:
            logger.error(
                "Failed to log audit event from context",
                error=str(e),
                action=self.action,
            )

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the audit event.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
