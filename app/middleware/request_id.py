"""Request ID tracking middleware."""

import time
import uuid
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.logging import clear_request_context, log_request_context

logger = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to each request for tracing."""

    async def dispatch(
        self: "RequestIDMiddleware",
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
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

        # Record start time for request duration
        start_time = time.time()

        try:
            # Process request
            response = await call_next(request)

            # Calculate request duration
            duration_ms = (time.time() - start_time) * 1000

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            # Log request completion with timing
            logger.info(
                "request_completed",
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )

            return response

        except Exception as e:
            # Calculate duration even for failed requests
            duration_ms = (time.time() - start_time) * 1000

            # Log exception with timing
            logger.exception(
                "request_failed",
                exc_type=type(e).__name__,
                duration_ms=round(duration_ms, 2),
            )
            raise
        finally:
            # Clear logging context
            clear_request_context()
