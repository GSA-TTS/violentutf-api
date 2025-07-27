"""Idempotency middleware for ensuring safe retries of non-idempotent operations."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Optional, Set, Union, cast

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from app.core.config import settings
from app.core.errors import ValidationError
from app.utils.cache import get_cache_client

logger = get_logger(__name__)


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle idempotency for non-idempotent HTTP operations.

    Uses the 'Idempotency-Key' header to ensure that retries of the same
    operation don't cause duplicate side effects. Responses are cached
    in Redis with a configurable TTL.

    Standards compliance:
    - Follows IETF draft-ietf-httpapi-idempotency-key-header
    - Compatible with Stripe, GitHub, and other major APIs
    """

    # HTTP methods that require idempotency protection
    PROTECTED_METHODS: Set[str] = {"POST", "PUT", "PATCH", "DELETE"}

    # Paths that should be excluded from idempotency checking
    EXCLUDED_PATHS: Set[str] = {"/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json"}

    def __init__(
        self,
        app: ASGIApp,
        header_name: str = "Idempotency-Key",
        cache_ttl: int = 86400,  # 24 hours
        max_key_length: int = 255,
        min_key_length: int = 1,
    ) -> None:
        """
        Initialize idempotency middleware.

        Args:
            app: ASGI application instance
            header_name: Name of the idempotency header
            cache_ttl: TTL for cached responses in seconds
            max_key_length: Maximum length of idempotency key
            min_key_length: Minimum length of idempotency key
        """
        super().__init__(app)
        self.header_name = header_name
        self.cache_ttl = cache_ttl
        self.max_key_length = max_key_length
        self.min_key_length = min_key_length

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Process request with idempotency protection."""
        # Skip processing for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        # Skip processing for non-protected methods
        if request.method not in self.PROTECTED_METHODS:
            return await call_next(request)

        # Get idempotency key from header
        idempotency_key = request.headers.get(self.header_name)

        # If no idempotency key provided, proceed normally
        if not idempotency_key:
            return await call_next(request)

        # Validate idempotency key
        validation_error = self._validate_idempotency_key(idempotency_key)
        if validation_error:
            return self._create_error_response(validation_error, request.url.path)

        # Check if we have a cached response
        cached_response = await self._get_cached_response(request, idempotency_key)
        if cached_response:
            logger.info(
                "idempotency_cache_hit",
                idempotency_key=idempotency_key,
                path=request.url.path,
                method=request.method,
            )
            return self._create_response_from_cache(cached_response)

        # Process the request
        response = await call_next(request)

        # Cache successful responses (2xx status codes)
        if 200 <= response.status_code < 300:
            await self._cache_response(request, idempotency_key, response)
            logger.info(
                "idempotency_response_cached",
                idempotency_key=idempotency_key,
                path=request.url.path,
                method=request.method,
                status_code=response.status_code,
            )

        return response

    def _validate_idempotency_key(self, key: str) -> Optional[str]:
        """
        Validate idempotency key format.

        Args:
            key: The idempotency key to validate

        Returns:
            Error message if invalid, None if valid
        """
        if not key:
            return "Idempotency key cannot be empty"

        if len(key) < self.min_key_length:
            return f"Idempotency key must be at least {self.min_key_length} characters"

        if len(key) > self.max_key_length:
            return f"Idempotency key cannot exceed {self.max_key_length} characters"

        # Check for valid characters (printable ASCII)
        if not all(32 <= ord(c) <= 126 for c in key):
            return "Idempotency key must contain only printable ASCII characters"

        # Validate UUID format (recommended but not required)
        try:
            uuid.UUID(key)
        except ValueError:
            # Not a UUID, but that's okay - log a warning
            logger.debug(
                "idempotency_key_not_uuid", key=key, message="Idempotency key is not a UUID (recommended format)"
            )

        return None

    async def _get_cached_response(self, request: Request, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached response for the idempotency key.

        Args:
            request: The HTTP request
            idempotency_key: The idempotency key

        Returns:
            Cached response data or None if not found
        """
        try:
            cache_client = get_cache_client()
            if not cache_client:
                logger.warning("cache_not_available_for_idempotency")
                return None

            # Create a unique cache key that includes method and path
            cache_key = self._create_cache_key(request, idempotency_key)

            cached_data = await cache_client.get(cache_key)
            if cached_data:
                parsed_data = json.loads(str(cached_data))
                # Ensure we return the correct type
                if isinstance(parsed_data, dict):
                    return parsed_data
                return None

            return None

        except Exception as e:
            logger.error(
                "idempotency_cache_get_error",
                error=str(e),
                idempotency_key=idempotency_key,
                exc_info=True,
            )
            return None

    async def _cache_response(self, request: Request, idempotency_key: str, response: Response) -> None:
        """
        Cache response for future idempotent requests.

        Args:
            request: The HTTP request
            idempotency_key: The idempotency key
            response: The HTTP response to cache
        """
        try:
            cache_client = get_cache_client()
            if not cache_client:
                logger.warning("cache_not_available_for_idempotency")
                return

            # Read response body - early return if cannot cache
            if not hasattr(response, "body"):
                # For streaming responses, we cannot cache them
                # This is a limitation of idempotency with streaming
                logger.warning("Cannot cache streaming response for idempotency")
                return

            # Process response body (guaranteed to have body attribute at this point)
            body = response.body
            # FastAPI Response.body is always bytes
            response_body = body if isinstance(body, bytes) else bytes(body)

            # Create cache data
            cache_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body.decode("utf-8", errors="replace"),
                "content_type": response.headers.get("content-type", "application/json"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "path": str(request.url.path),
            }

            # Create cache key
            cache_key = self._create_cache_key(request, idempotency_key)

            # Store in cache
            await cache_client.setex(cache_key, self.cache_ttl, json.dumps(cache_data))

            # Update response with cached content
            # response already has the body set correctly

        except Exception as e:
            logger.error(
                "idempotency_cache_set_error",
                error=str(e),
                idempotency_key=idempotency_key,
                exc_info=True,
            )

    def _create_cache_key(self, request: Request, idempotency_key: str) -> str:
        """
        Create a unique cache key for the request.

        Args:
            request: The HTTP request
            idempotency_key: The idempotency key

        Returns:
            Unique cache key string
        """
        # Include method and path to ensure different endpoints don't collide
        base_key = f"idempotency:{request.method}:{request.url.path}:{idempotency_key}"

        # Add user context if available (to prevent cross-user collisions)
        user_id = getattr(request.state, "user_id", "anonymous")
        return f"{base_key}:user:{user_id}"

    def _create_response_from_cache(self, cached_data: Dict[str, Any]) -> Response:
        """
        Create a Response object from cached data.

        Args:
            cached_data: The cached response data

        Returns:
            Response object reconstructed from cache
        """
        headers = dict(cached_data["headers"]) if isinstance(cached_data["headers"], dict) else {}

        # Add idempotency headers
        headers["X-Idempotency-Cached"] = "true"
        headers["X-Idempotency-Timestamp"] = str(cached_data["timestamp"])

        # Extract status code with type checking
        status_code = cached_data["status_code"]
        if not isinstance(status_code, int):
            status_code = 200  # Default fallback

        # Extract body content with type checking
        body = cached_data["body"]
        content_type = cached_data.get("content_type", "application/json")

        content: Union[str, Any]
        if content_type == "application/json" and isinstance(body, str):
            try:
                content = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                content = body
        else:
            content = body

        return JSONResponse(
            status_code=status_code,
            content=content,
            headers=headers,
        )

    def _create_error_response(self, error_message: str, instance: str) -> JSONResponse:
        """
        Create an error response for idempotency validation failures.

        Args:
            error_message: The validation error message
            instance: The request path

        Returns:
            Error response
        """
        return JSONResponse(
            status_code=422,
            content={"detail": error_message, "instance": instance},
        )

    @staticmethod
    def _create_body_iterator(body: bytes) -> AsyncIterator[bytes]:
        """Create an async iterator for response body."""

        async def body_iterator() -> AsyncIterator[bytes]:
            yield body

        return body_iterator()


def setup_idempotency_middleware(
    app: FastAPI,
    header_name: str = "Idempotency-Key",
    cache_ttl: int = 86400,
    max_key_length: int = 255,
    min_key_length: int = 1,
) -> None:
    """
    Set up idempotency middleware for the application.

    Args:
        app: FastAPI application instance
        header_name: Name of the idempotency header
        cache_ttl: TTL for cached responses in seconds
        max_key_length: Maximum length of idempotency key
        min_key_length: Minimum length of idempotency key
    """
    # Only add middleware if caching is enabled
    if settings.REDIS_URL:
        app.add_middleware(
            IdempotencyMiddleware,
            header_name=header_name,
            cache_ttl=cache_ttl,
            max_key_length=max_key_length,
            min_key_length=min_key_length,
        )
        logger.info("Idempotency middleware configured")
    else:
        logger.warning("Idempotency middleware skipped - caching disabled")
