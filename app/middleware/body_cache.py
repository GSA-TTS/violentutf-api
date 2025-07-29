"""Body caching middleware to solve ASGI body consumption conflicts."""

from typing import Any, Awaitable, Callable, Dict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class BodyCachingMiddleware(BaseHTTPMiddleware):
    """Middleware that caches request body to avoid ASGI consumption conflicts."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize body caching middleware."""
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Cache request body and provide it to subsequent middlewares.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response from next handler
        """
        # Cache the request body if not already cached
        if not hasattr(request.state, "cached_body"):
            try:
                # Read and cache the full body
                body = await request.body()
                request.state.cached_body = body

                # Create a new receive callable that provides the cached body
                body_sent = False

                async def cached_receive() -> Dict[str, Any]:
                    nonlocal body_sent
                    if not body_sent:
                        body_sent = True
                        return {
                            "type": "http.request",
                            "body": body,
                            "more_body": False,
                        }
                    else:
                        # For any subsequent calls, return disconnect
                        return {"type": "http.disconnect"}

                # Replace the receive callable
                request._receive = cached_receive

                logger.debug("request_body_cached", body_size=len(body), has_body=len(body) > 0)
            except Exception as e:
                logger.error("body_caching_failed", error=str(e))
                # If caching fails, set empty body to prevent downstream issues
                request.state.cached_body = b""

        # Process request with cached body available
        return await call_next(request)


def get_cached_body(request: Request) -> bytes:
    """Get cached body from request state.

    Args:
        request: Request with cached body

    Returns:
        Cached request body bytes
    """
    return getattr(request.state, "cached_body", b"")


def has_cached_body(request: Request) -> bool:
    """Check if request has cached body.

    Args:
        request: Request to check

    Returns:
        True if body is cached
    """
    return hasattr(request.state, "cached_body")
