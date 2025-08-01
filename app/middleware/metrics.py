"""Metrics collection middleware."""

import time
from typing import Awaitable, Callable

from fastapi import Request, Response
from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)

ACTIVE_REQUESTS = Gauge(
    "http_requests_active",
    "Number of active HTTP requests",
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Collect metrics for all requests."""

    async def dispatch(
        self: "MetricsMiddleware", request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Collect request metrics."""
        if not settings.ENABLE_METRICS:
            return await call_next(request)

        # Skip metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)

        # Normalize endpoint for metrics (remove IDs)
        endpoint = self._normalize_endpoint(str(request.url.path))

        # Increment active requests
        ACTIVE_REQUESTS.inc()

        # Record start time
        start_time = time.time()

        try:
            # Process request
            response = await call_next(request)

            # Record metrics
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status=str(response.status_code),  # Convert to string for consistency
            ).inc()

            REQUEST_DURATION.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(time.time() - start_time)

            return response

        except Exception:
            # Record error metrics
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status="500",  # Convert to string for consistency
            ).inc()

            REQUEST_DURATION.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(time.time() - start_time)

            raise
        finally:
            # Decrement active requests
            ACTIVE_REQUESTS.dec()

    def _normalize_endpoint(self: "MetricsMiddleware", path: str) -> str:
        """Normalize endpoint path for metrics grouping."""
        import re

        # Split path into segments
        segments = path.split("/")

        # Process each segment
        for i, segment in enumerate(segments):
            if not segment:  # Skip empty segments
                continue

            # Check if segment looks like an ID
            # UUID pattern
            if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", segment, re.IGNORECASE):
                segments[i] = "{id}"
            # Numeric ID
            elif re.match(r"^\d+$", segment):
                segments[i] = "{id}"
            # Alphanumeric ID (at least one letter and one number, or contains dash/underscore)
            elif re.match(r"^[a-zA-Z0-9\-_]+$", segment) and (
                re.search(r"\d", segment) or "-" in segment or "_" in segment
            ):
                segments[i] = "{id}"

        return "/".join(segments)
