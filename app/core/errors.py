"""Comprehensive error handling framework with RFC 7807 compliance."""

from typing import Any, Dict, Optional, Union

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details for HTTP APIs compliant error model."""

    # RFC 7807 standard fields
    type: str  # URI reference that identifies the problem type
    title: str  # Short, human-readable summary of the problem type
    status: int  # HTTP status code
    detail: Optional[str] = None  # Human-readable explanation specific to this occurrence
    instance: Optional[str] = None  # URI reference that identifies the specific occurrence

    # ADR-009 custom extensions
    correlation_id: Optional[str] = None  # Unique ID linking to detailed logs
    error_code: Optional[str] = None  # Stable, human-readable code for programmatic handling

    # Additional context for validation errors and other details
    errors: Optional[list] = None  # Detailed validation errors
    timestamp: Optional[str] = None  # When the error occurred
    invalid_params: Optional[list] = None  # Invalid parameters for validation errors

    model_config = {"extra": "allow"}  # Allow additional problem-specific fields


class APIError(HTTPException):
    """Base API exception with RFC 7807 compliance."""

    def __init__(
        self: "APIError",
        status_code: int,
        error_code: str,
        title: str,
        detail: str,
        problem_type: Optional[str] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize API error with RFC 7807 compliant structure."""
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code
        self.title = title
        self.problem_type = problem_type or f"/errors/{error_code.lower().replace('_', '-')}"
        self.additional_fields = kwargs


class BadRequestError(APIError):
    """400 Bad Request using error dictionary."""

    def __init__(self: "BadRequestError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize bad request error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_400_BAD_REQUEST")
        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VUTF_400_BAD_REQUEST",
                title="Bad Request",
                detail=detail or "The request is invalid",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


class UnauthorizedError(APIError):
    """401 Unauthorized using error dictionary."""

    def __init__(self: "UnauthorizedError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize unauthorized error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_401_UNAUTHORIZED")
        headers = {"WWW-Authenticate": "Bearer"}
        headers.update(kwargs.pop("headers", {}))

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error_code="VUTF_401_UNAUTHORIZED",
                title="Unauthorized",
                detail=detail or "Authentication required",
                headers=headers,
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                headers=headers,
                **kwargs,
            )


class AuthenticationError(UnauthorizedError):
    """Authentication error - alias for UnauthorizedError."""

    pass


class ForbiddenError(APIError):
    """403 Forbidden using error dictionary."""

    def __init__(self: "ForbiddenError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize forbidden error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_403_FORBIDDEN")

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_403_FORBIDDEN,
                error_code="VUTF_403_FORBIDDEN",
                title="Forbidden",
                detail=detail or "Access denied",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


class NotFoundError(APIError):
    """404 Not Found using error dictionary."""

    def __init__(self: "NotFoundError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize not found error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_404_NOT_FOUND")

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_404_NOT_FOUND,
                error_code="VUTF_404_NOT_FOUND",
                title="Not Found",
                detail=detail or "The requested resource was not found",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


class ConflictError(APIError):
    """409 Conflict using error dictionary."""

    def __init__(self: "ConflictError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize conflict error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_409_CONFLICT")

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_409_CONFLICT,
                error_code="VUTF_409_CONFLICT",
                title="Conflict",
                detail=detail or "The request conflicts with the current state",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


class ValidationError(APIError):
    """422 Validation Error using error dictionary."""

    def __init__(
        self: "ValidationError", detail: Optional[str] = None, errors: Optional[list] = None, **kwargs: Any
    ) -> None:
        """Initialize validation error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_422_VALIDATION_ERROR")

        # Add errors to additional fields
        if errors:
            kwargs["invalid_params"] = errors

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                error_code="VUTF_422_VALIDATION_ERROR",
                title="Validation Error",
                detail=detail or "One or more fields failed validation",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


class InternalServerError(APIError):
    """500 Internal Server Error using error dictionary."""

    def __init__(self: "InternalServerError", detail: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize internal server error."""
        from .error_dictionary import ErrorDictionary

        error_def = ErrorDictionary.get_error("VUTF_500_INTERNAL_ERROR")

        if not error_def:
            # Fallback if dictionary is not available
            super().__init__(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="VUTF_500_INTERNAL_ERROR",
                title="Internal Server Error",
                detail=detail or "An internal server error occurred",
                **kwargs,
            )
        else:
            super().__init__(
                status_code=error_def.status,
                error_code=error_def.error_code,
                title=error_def.title,
                detail=detail or error_def.description,
                problem_type=error_def.type,
                **kwargs,
            )


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle API errors with RFC 7807 compliant format."""
    from datetime import datetime, timezone

    # Build RFC 7807 problem details
    problem_detail = ProblemDetail(
        type=exc.problem_type,
        title=exc.title,
        status=exc.status_code,
        detail=exc.detail,
        instance=str(request.url.path),
        correlation_id=getattr(request.state, "request_id", None),
        error_code=exc.error_code,
        timestamp=datetime.now(timezone.utc).isoformat(),
        **exc.additional_fields,
    )

    # Log the error with correlation_id for traceability
    logger.error(
        "api_error",
        error_code=exc.error_code,
        status_code=exc.status_code,
        path=str(request.url),
        method=request.method,
        correlation_id=problem_detail.correlation_id,
    )

    # Return RFC 7807 compliant response
    return JSONResponse(
        status_code=exc.status_code,
        content=problem_detail.model_dump(exclude_none=True),
        headers={
            "Content-Type": "application/problem+json",
            **(exc.headers or {}),
        },
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle validation errors with RFC 7807 compliant format."""
    from datetime import datetime, timezone

    # Extract validation errors in RFC 7807 format
    invalid_params = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"])
        invalid_params.append(
            {
                "field": field,
                "reason": error["msg"],
                "type": error["type"],
            }
        )

    # Build RFC 7807 problem details for validation errors
    problem_detail = ProblemDetail(
        type="/errors/validation-error",
        title="Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="One or more fields in the request failed validation.",
        instance=str(request.url.path),
        correlation_id=getattr(request.state, "request_id", None),
        error_code="VUTF_422_VALIDATION_ERROR",
        timestamp=datetime.now(timezone.utc).isoformat(),
        invalid_params=invalid_params,
    )

    # Log validation error with correlation_id
    logger.warning(
        "validation_error",
        error_code=problem_detail.error_code,
        invalid_params=invalid_params,
        path=str(request.url),
        method=request.method,
        correlation_id=problem_detail.correlation_id,
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem_detail.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected errors safely with RFC 7807 compliance."""
    from datetime import datetime, timezone

    correlation_id = getattr(request.state, "request_id", None)

    # Log the full exception with correlation_id for traceability
    logger.exception(
        "unhandled_exception",
        exc_type=type(exc).__name__,
        path=str(request.url),
        method=request.method,
        correlation_id=correlation_id,
    )

    # Don't expose internal details in production
    if hasattr(request.app.state, "development_mode") and request.app.state.development_mode:
        detail = str(exc)
    else:
        detail = "An internal server error occurred. Please try again later."

    # Build RFC 7807 problem details
    problem_detail = ProblemDetail(
        type="/errors/internal-server-error",
        title="Internal Server Error",
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=detail,
        instance=str(request.url.path),
        correlation_id=correlation_id,
        error_code="VUTF_500_INTERNAL_ERROR",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem_detail.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


def setup_error_handlers(app: FastAPI, development_mode: bool = False) -> None:
    """Set up all error handlers for the application."""
    app.state.development_mode = development_mode

    # Custom error handlers
    app.add_exception_handler(APIError, api_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)

    # Generic error handler for unexpected exceptions
    app.add_exception_handler(Exception, generic_error_handler)

    logger.info("Error handlers configured", development_mode=development_mode)
