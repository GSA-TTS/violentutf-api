"""Input sanitization middleware for ViolentUTF API."""

import json
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union
from urllib.parse import unquote

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..utils.sanitization import sanitize_dict, sanitize_string
from .body_cache import get_cached_body, has_cached_body

logger = get_logger(__name__)

# Paths to exclude from sanitization (e.g., file uploads)
SANITIZATION_EXEMPT_PATHS: List[str] = [
    "/api/v1/files/upload",
    "/api/v1/documents/upload",
]

# Content types to sanitize
SANITIZABLE_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
]

# Maximum size for request body (10MB)
MAX_BODY_SIZE = 10 * 1024 * 1024


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """Middleware for comprehensive input sanitization."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize input sanitization middleware."""
        super().__init__(app)

    def _should_sanitize_body(self, request: Request, content_type: str) -> bool:
        """Check if request body should be sanitized."""
        return request.method in ["POST", "PUT", "PATCH"] and content_type in SANITIZABLE_CONTENT_TYPES

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:  # noqa: C901
        """Process request with input sanitization.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response or 400 if input validation fails
        """
        # Skip sanitization for exempt paths
        if any(request.url.path.startswith(path) for path in SANITIZATION_EXEMPT_PATHS):
            return await call_next(request)

        try:
            # Sanitize query parameters
            if request.query_params:
                sanitized_params = await self._sanitize_query_params(request)
                if sanitized_params is None:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "Invalid query parameters"},
                    )
                # Store sanitized params for later use
                request.state.sanitized_query_params = sanitized_params

            # Sanitize headers
            sanitized_headers = await self._sanitize_headers(request)
            if sanitized_headers is None:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid headers"},
                )

            # Handle body sanitization
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            if self._should_sanitize_body(request, content_type):
                # Store original body - use cached body if available to avoid ASGI conflicts
                if has_cached_body(request):
                    body = get_cached_body(request)
                else:
                    body = await request.body()

                # Check body size
                if len(body) > MAX_BODY_SIZE:
                    logger.warning(
                        "request_body_too_large",
                        size=len(body),
                        max_size=MAX_BODY_SIZE,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request body too large"},
                    )

                # Sanitize body
                sanitized_body = await self._sanitize_body(body, content_type)
                if sanitized_body is None:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "Invalid request body"},
                    )

                # Store sanitized body in request state
                request.state.sanitized_body = sanitized_body

                # Monkey-patch the request's json method to use sanitized body
                original_json = request.json

                async def sanitized_json() -> Any:
                    """Return parsed JSON from sanitized body."""
                    try:
                        return json.loads(sanitized_body.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Fallback to original method if sanitized body is invalid
                        return await original_json()

                request.json = sanitized_json  # type: ignore[method-assign]

                # Also monkey-patch body method for consistency
                async def sanitized_body_method() -> bytes:
                    """Return sanitized body."""
                    return sanitized_body

                request.body = sanitized_body_method  # type: ignore[method-assign]

        except Exception as e:
            logger.error("input_sanitization_error", error=str(e))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Input validation error"},
            )

        # Process request
        response = await call_next(request)
        return response

    async def _sanitize_query_params(self, request: Request) -> Optional[Dict[str, str]]:
        """Sanitize query parameters.

        Args:
            request: Incoming request

        Returns:
            Sanitized parameters or None if invalid
        """
        try:
            sanitized = {}
            for key, value in request.query_params.items():
                # Decode URL encoding
                decoded_key = unquote(key)
                decoded_value = unquote(value)

                # Use aggressive JS filtering for enhanced security
                clean_key = sanitize_string(decoded_key, max_length=100, strip_js=True)
                clean_value = sanitize_string(decoded_value, max_length=1000, strip_js=True)

                sanitized[clean_key] = clean_value

            return sanitized
        except Exception as e:
            logger.error("query_param_sanitization_error", error=str(e))
            return None

    async def _sanitize_headers(self, request: Request) -> Optional[Dict[str, str]]:
        """Sanitize request headers.

        Args:
            request: Incoming request

        Returns:
            Sanitized headers or None if invalid
        """
        try:
            # Headers that should not be sanitized
            header_whitelist = {
                "content-type",
                "content-length",
                "authorization",
                "x-csrf-token",
                "x-request-id",
                "x-api-key",
            }

            sanitized = {}
            for key, value in request.headers.items():
                lower_key = key.lower()

                # Skip whitelisted headers
                if lower_key in header_whitelist:
                    sanitized[key] = value
                    continue

                # Sanitize other headers
                clean_value = sanitize_string(value, max_length=500, allow_html=False)
                sanitized[key] = clean_value

            return sanitized
        except Exception as e:
            logger.error("header_sanitization_error", error=str(e))
            return None

    async def _sanitize_body(self, body: bytes, content_type: str) -> Optional[bytes]:
        """Sanitize request body based on content type.

        Args:
            body: Raw request body
            content_type: Content type header

        Returns:
            Sanitized body or None if invalid
        """
        try:
            if content_type == "application/json":
                return await self._sanitize_json_body(body)
            elif content_type == "application/x-www-form-urlencoded":
                return await self._sanitize_form_body(body)
            elif content_type == "text/plain":
                return await self._sanitize_text_body(body)
            else:
                # For other types, pass through
                return body
        except Exception as e:
            logger.error("body_sanitization_error", error=str(e), content_type=content_type)
            return None

    async def _sanitize_json_body(self, body: bytes) -> Optional[bytes]:
        """Sanitize JSON request body.

        Args:
            body: Raw JSON body

        Returns:
            Sanitized JSON body or None if invalid
        """
        try:
            # Parse JSON
            data = json.loads(body.decode("utf-8"))

            # Recursively sanitize
            sanitized_data = self._sanitize_json_value(data)

            if sanitized_data is None:
                return None

            # Convert back to JSON
            return json.dumps(sanitized_data, ensure_ascii=False).encode("utf-8")
        except json.JSONDecodeError as e:
            logger.warning("invalid_json_body", error=str(e))
            return None
        except Exception as e:
            logger.error("json_sanitization_error", error=str(e))
            return None

    def _sanitize_json_value(
        self, value: Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
    ) -> Union[str, int, float, bool, None, Dict[str, Any], List[Any]]:
        """Recursively sanitize JSON values.

        Args:
            value: JSON value to sanitize

        Returns:
            Sanitized value
        """
        if isinstance(value, str):
            # Use aggressive JS filtering for enhanced security in advanced contexts
            return sanitize_string(value, max_length=10000, strip_js=True)
        elif isinstance(value, dict):
            # Sanitize dictionary
            return {str(k): self._sanitize_json_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            # Sanitize list
            return [self._sanitize_json_value(item) for item in value]
        else:
            # Pass through other types (numbers, booleans, null)
            return value

    async def _sanitize_form_body(self, body: bytes) -> Optional[bytes]:
        """Sanitize form-encoded body.

        Args:
            body: Raw form body

        Returns:
            Sanitized form body or None if invalid
        """
        try:
            # Parse form data
            form_string = body.decode("utf-8")
            params = {}

            for param in form_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    key = unquote(key)
                    value = unquote(value)

                    # Sanitize with basic escaping for form data
                    clean_key = sanitize_string(key, max_length=100, strip_js=False)
                    clean_value = sanitize_string(value, max_length=10000, strip_js=False)

                    if clean_key and clean_value is not None:
                        params[clean_key] = clean_value

            # Reconstruct form data
            sanitized_params = []
            for key, value in params.items():
                sanitized_params.append(f"{key}={value}")

            return "&".join(sanitized_params).encode("utf-8")
        except Exception as e:
            logger.error("form_sanitization_error", error=str(e))
            return None

    async def _sanitize_text_body(self, body: bytes) -> Optional[bytes]:
        """Sanitize plain text body.

        Args:
            body: Raw text body

        Returns:
            Sanitized text body or None if invalid
        """
        try:
            text = body.decode("utf-8")
            sanitized = sanitize_string(text, max_length=100000, allow_html=False)
            return sanitized.encode("utf-8")
        except Exception as e:
            logger.error("text_sanitization_error", error=str(e))
            return None


def get_sanitized_query_params(request: Request) -> Optional[Dict[str, str]]:
    """Get sanitized query parameters from request state.

    Args:
        request: Current request

    Returns:
        Sanitized parameters or None
    """
    return getattr(request.state, "sanitized_query_params", None)


def get_sanitized_body(request: Request) -> Optional[bytes]:
    """Get sanitized body from request state.

    Args:
        request: Current request

    Returns:
        Sanitized body or None
    """
    return getattr(request.state, "sanitized_body", None)
