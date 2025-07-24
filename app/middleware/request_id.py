"""Request ID tracking middleware."""

import uuid
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.logging import clear_request_context, log_request_context

logger = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """Add unique request ID to each request for tracing."""

    async def dispatch(
        self: "RequestIDMiddleware", request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process request with unique ID."""
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in request state
        request.state.request_id = request_id

        # Get client IP
        client_ip = None
        if "x-forwarded-for" in request.headers:
            client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
        elif request.client:
            client_ip = request.client.host

        # Set logging context
        log_request_context(
            request_id=request_id,
            method=request.method,
            path=str(request.url.path),
            client_ip=client_ip,
        )

        try:
            # Process request
            response = await call_next(request)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            # Log request completion
            logger.info(
                "request_completed",
                status_code=response.status_code,
                duration_ms=0,  # TODO: Add timing
            )

            return response

        except Exception as e:
            # Log exception
            logger.exception(
                "request_failed",
                exc_type=type(e).__name__,
            )
            raise
        finally:
            # Clear logging context
            clear_request_context()
