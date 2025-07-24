"""Request/response logging middleware."""

import time
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """Log all requests and responses with timing."""

    async def dispatch(
        self: "LoggingMiddleware", request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Log request details and response timing."""
        # Skip logging for health checks to reduce noise
        if request.url.path in ["/health", "/ready"]:
            return await call_next(request)

        # Record start time
        start_time = time.time()

        # Log request
        logger.info(
            "request_started",
            method=request.method,
            path=str(request.url.path),
            query_params=dict(request.query_params),
            content_length=request.headers.get("content-length", 0),
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000

            # Log response
            logger.info(
                "request_completed",
                method=request.method,
                path=str(request.url.path),
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )

            # Add timing header
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

            return response

        except Exception as e:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000

            # Log error
            logger.error(
                "request_failed",
                method=request.method,
                path=str(request.url.path),
                duration_ms=round(duration_ms, 2),
                exc_type=type(e).__name__,
                exc_message=str(e),
            )
            raise
