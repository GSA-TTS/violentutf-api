"""Comprehensive error handling framework."""

from typing import Any, Dict, Optional, Union

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class ErrorDetail(BaseModel):
    """Standard error response model."""

    error: str
    message: str
    request_id: Optional[str] = None
    path: Optional[str] = None
    timestamp: Optional[str] = None


class APIError(HTTPException):
    """Base API exception with consistent error handling."""

    def __init__(
        self: "APIError",
        status_code: int,
        error: str,
        message: str,
        headers: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize API error with status code and message."""
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.error = error
        self.message = message


class BadRequestError(APIError):
    """400 Bad Request."""

    def __init__(self: "BadRequestError", message: str = "Bad request") -> None:
        """Initialize bad request error."""
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="bad_request",
            message=message,
        )


class UnauthorizedError(APIError):
    """401 Unauthorized."""

    def __init__(self: "UnauthorizedError", message: str = "Unauthorized") -> None:
        """Initialize unauthorized error."""
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="unauthorized",
            message=message,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthenticationError(UnauthorizedError):
    """Authentication error - alias for UnauthorizedError."""

    pass


class ForbiddenError(APIError):
    """403 Forbidden."""

    def __init__(self: "ForbiddenError", message: str = "Forbidden") -> None:
        """Initialize forbidden error."""
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error="forbidden",
            message=message,
        )


class NotFoundError(APIError):
    """404 Not Found."""

    def __init__(self: "NotFoundError", message: str = "Resource not found") -> None:
        """Initialize not found error."""
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            error="not_found",
            message=message,
        )


class ConflictError(APIError):
    """409 Conflict."""

    def __init__(self: "ConflictError", message: str = "Resource conflict") -> None:
        """Initialize conflict error."""
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            error="conflict",
            message=message,
        )


class ValidationError(APIError):
    """422 Validation Error."""

    def __init__(self: "ValidationError", message: str = "Validation failed") -> None:
        """Initialize validation error."""
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error="validation_error",
            message=message,
        )


class InternalServerError(APIError):
    """500 Internal Server Error."""

    def __init__(self: "InternalServerError", message: str = "Internal server error") -> None:
        """Initialize internal server error."""
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="internal_error",
            message=message,
        )


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle API errors with consistent format."""
    from datetime import datetime, timezone

    error_detail = ErrorDetail(
        error=exc.error,
        message=exc.message,
        request_id=getattr(request.state, "request_id", None),
        path=str(request.url),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Log the error
    logger.error(
        "api_error",
        error=exc.error,
        status_code=exc.status_code,
        path=str(request.url),
        method=request.method,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=error_detail.model_dump(exclude_none=True),
        headers=exc.headers,
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle validation errors with detailed messages."""
    from datetime import datetime, timezone

    # Extract validation errors
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"])
        errors.append(
            {
                "field": field,
                "message": error["msg"],
                "type": error["type"],
            }
        )

    error_detail = {
        "error": "validation_error",
        "message": "Request validation failed",
        "errors": errors,
        "request_id": getattr(request.state, "request_id", None),
        "path": str(request.url),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Log validation error
    logger.warning(
        "validation_error",
        errors=errors,
        path=str(request.url),
        method=request.method,
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_detail,
    )


async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected errors safely."""
    from datetime import datetime, timezone

    # Log the full exception
    logger.exception(
        "unhandled_exception",
        exc_type=type(exc).__name__,
        path=str(request.url),
        method=request.method,
    )

    # Don't expose internal details in production
    if hasattr(request.app.state, "development_mode") and request.app.state.development_mode:
        message = str(exc)
    else:
        message = "An unexpected error occurred"

    error_detail = ErrorDetail(
        error="internal_error",
        message=message,
        request_id=getattr(request.state, "request_id", None),
        path=str(request.url),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_detail.model_dump(exclude_none=True),
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
