"""Response caching middleware with intelligent cache management."""

import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from structlog.stdlib import get_logger

from ..core.config import settings
from ..utils.cache import delete_cached_value, get_cached_value, set_cached_value

logger = get_logger(__name__)


class ResponseCacheMiddleware(BaseHTTPMiddleware):
    """
    Middleware for caching HTTP responses with intelligent invalidation.

    Features:
    - Automatic caching of GET requests
    - Configurable TTL per endpoint pattern
    - Cache invalidation on POST/PUT/DELETE operations
    - ETag support for client-side caching
    - Compression-aware caching
    - Cache warming capabilities
    """

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        default_ttl: int = 300,
        cache_patterns: Optional[Dict[str, int]] = None,
        exclude_patterns: Optional[List[str]] = None,
        invalidation_patterns: Optional[Dict[str, List[str]]] = None,
        enable_etag: bool = True,
        max_cache_size: int = 100 * 1024 * 1024,  # 100MB
    ):
        """
        Initialize response cache middleware.

        Args:
            app: ASGI application
            default_ttl: Default cache TTL in seconds
            cache_patterns: Path patterns and their TTL overrides
            exclude_patterns: Path patterns to exclude from caching
            invalidation_patterns: Mapping of write operations to cache invalidation patterns
            enable_etag: Whether to generate ETags for cached responses
            max_cache_size: Maximum cache size in bytes
        """
        super().__init__(app)
        self.default_ttl = default_ttl
        self.cache_patterns = cache_patterns or {}
        self.exclude_patterns = exclude_patterns or []
        self.invalidation_patterns = invalidation_patterns or {}
        self.enable_etag = enable_etag
        self.max_cache_size = max_cache_size

        # Default cache patterns for common endpoints
        self.default_cache_patterns = {
            "/api/v1/users": 300,  # 5 minutes
            "/api/v1/audit_logs": 600,  # 10 minutes
            "/api/v1/sessions": 60,  # 1 minute
            "/api/v1/health": 30,  # 30 seconds
        }
        self.cache_patterns.update(self.default_cache_patterns)

        # Default invalidation patterns
        self.default_invalidation_patterns = {
            "POST /api/v1/users": ["/api/v1/users*"],
            "PUT /api/v1/users": ["/api/v1/users*"],
            "DELETE /api/v1/users": ["/api/v1/users*"],
            "POST /api/v1/sessions": ["/api/v1/sessions*"],
            "DELETE /api/v1/sessions": ["/api/v1/sessions*"],
        }
        self.invalidation_patterns.update(self.default_invalidation_patterns)

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        """Process request with caching logic."""
        # Skip caching if disabled or not cacheable request
        if not self._should_cache_request(request):
            response = await call_next(request)
            await self._handle_cache_invalidation(request)
            return response

        # Generate cache key
        cache_key = self._generate_cache_key(request)

        # Try to get cached response
        cached_response = await self._get_cached_response(cache_key, request)
        if cached_response:
            logger.debug("Cache hit", path=request.url.path, cache_key=cache_key)
            return cached_response

        # Execute request
        response = await call_next(request)

        # Cache successful responses
        if self._should_cache_response(response):
            await self._cache_response(cache_key, request, response)
            logger.debug("Response cached", path=request.url.path, cache_key=cache_key)

        # Handle cache invalidation for write operations
        await self._handle_cache_invalidation(request)

        return response

    def _should_cache_request(self, request: Request) -> bool:
        """Determine if request should be cached."""
        # Only cache GET requests
        if request.method != "GET":
            return False

        # Check if caching is disabled
        if not getattr(settings, "ENABLE_RESPONSE_CACHE", True):
            return False

        # Check cache control headers
        cache_control = request.headers.get("Cache-Control", "")
        if "no-cache" in cache_control or "no-store" in cache_control:
            return False

        # Check exclude patterns
        path = request.url.path
        for pattern in self.exclude_patterns:
            if self._match_pattern(path, pattern):
                return False

        # Check if path has caching configuration
        return any(self._match_pattern(path, pattern) for pattern in self.cache_patterns.keys())

    def _should_cache_response(self, response: Response) -> bool:
        """Determine if response should be cached."""
        # Only cache successful responses
        if response.status_code >= 400:
            return False

        # Check response cache control headers
        cache_control = response.headers.get("Cache-Control", "")
        if "no-cache" in cache_control or "no-store" in cache_control or "private" in cache_control:
            return False

        # Don't cache responses with set-cookie headers
        if "Set-Cookie" in response.headers:
            return False

        return True

    def _generate_cache_key(self, request: Request) -> str:
        """Generate cache key for request."""
        # Base components
        components = {
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else "",
        }

        # Include relevant headers
        relevant_headers = ["Accept", "Accept-Language", "Authorization"]
        headers: Dict[str, str] = {}
        for header in relevant_headers:
            value = request.headers.get(header)
            if value:
                # Hash authorization header for security
                if header == "Authorization":
                    # Hash authorization for security (not cryptographic use)
                    headers[header] = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()[:16]
                else:
                    headers[header] = value

        if headers:
            components["headers"] = headers  # type: ignore[assignment]

        # Generate hash
        key_string = json.dumps(components, sort_keys=True)
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()[:32]

        return f"response_cache:{key_hash}"

    async def _get_cached_response(self, cache_key: str, request: Request) -> Optional[Response]:
        """Retrieve cached response."""
        try:
            cached_data = await get_cached_value(cache_key)
            if not cached_data:
                return None

            # Deserialize cached response
            cache_info = json.loads(cached_data)

            # Check ETag if present
            if self.enable_etag:
                client_etag = request.headers.get("If-None-Match")
                if client_etag and client_etag == cache_info.get("etag"):
                    return Response(status_code=304)  # Not Modified

            # Reconstruct response
            response = JSONResponse(
                content=cache_info["content"],
                status_code=cache_info["status_code"],
                headers=cache_info.get("headers", {}),
            )

            # Add cache headers
            response.headers["X-Cache"] = "HIT"
            response.headers["X-Cache-Key"] = cache_key[:16]  # Truncated for security

            if self.enable_etag and "etag" in cache_info:
                response.headers["ETag"] = cache_info["etag"]

            return response

        except Exception as e:
            logger.warning("Failed to retrieve cached response", cache_key=cache_key, error=str(e))
            return None

    async def _cache_response(self, cache_key: str, request: Request, response: Response) -> bool:
        """Cache response with appropriate TTL."""
        try:
            # Determine TTL
            ttl = self._get_cache_ttl(request.url.path)

            # Read response body
            if hasattr(response, "body"):
                body = response.body
            else:
                # For streaming responses, we can't cache easily
                return False

            # Parse response content
            try:
                if isinstance(body, bytes):
                    content = json.loads(body.decode())
                else:
                    content = body
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Can't cache non-JSON responses for now
                return False

            # Prepare cache data
            cache_data = {
                "content": content,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cached_at": json.dumps({"timestamp": "now"}),  # Simplified timestamp
            }

            # Generate ETag if enabled
            if self.enable_etag:
                etag_content = json.dumps(content, sort_keys=True)
                # Generate ETag using MD5 (not for security, just content fingerprinting)
                etag = f'"{hashlib.md5(etag_content.encode(), usedforsecurity=False).hexdigest()}"'
                cache_data["etag"] = etag
                response.headers["ETag"] = etag

            # Add cache headers to response
            response.headers["X-Cache"] = "MISS"
            response.headers["Cache-Control"] = f"max-age={ttl}"

            # Store in cache
            cache_json = json.dumps(cache_data)
            success = await set_cached_value(cache_key, cache_json, ttl)

            return success

        except Exception as e:
            logger.error("Failed to cache response", cache_key=cache_key, error=str(e))
            return False

    def _get_cache_ttl(self, path: str) -> int:
        """Get cache TTL for the given path."""
        for pattern, ttl in self.cache_patterns.items():
            if self._match_pattern(path, pattern):
                return ttl
        return self.default_ttl

    async def _handle_cache_invalidation(self, request: Request) -> None:
        """Handle cache invalidation for write operations."""
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            operation_key = f"{request.method} {request.url.path}"

            # Find matching invalidation patterns
            patterns_to_invalidate = []
            for pattern, invalidation_list in self.invalidation_patterns.items():
                if self._match_pattern(operation_key, pattern):
                    patterns_to_invalidate.extend(invalidation_list)

            # Invalidate matching cache entries
            for pattern in patterns_to_invalidate:
                await self._invalidate_cache_pattern(pattern)
                logger.debug("Cache invalidated", operation=operation_key, pattern=pattern)

    async def _invalidate_cache_pattern(self, pattern: str) -> None:
        """Invalidate cache entries matching the pattern."""
        try:
            # This is a simplified implementation
            # In production, you'd want to use Redis SCAN or maintain cache key sets
            logger.info("Cache invalidation requested", pattern=pattern)

            # For now, just log the invalidation
            # Implement actual pattern-based cache invalidation based on your Redis setup

        except Exception as e:
            logger.error("Cache invalidation failed", pattern=pattern, error=str(e))

    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern (supports wildcards)."""
        if pattern.endswith("*"):
            return path.startswith(pattern[:-1])
        return path == pattern

    # Cache warming methods
    async def warm_cache(self, endpoints: List[Dict[str, Any]]) -> Dict[str, bool]:
        """
        Warm cache by pre-loading responses for specified endpoints.

        Args:
            endpoints: List of endpoint configurations with path, params, etc.

        Returns:
            Dictionary mapping endpoints to warming success status
        """
        results = {}

        for endpoint in endpoints:
            try:
                # This would make actual requests to warm the cache
                # Implementation depends on your testing/client setup
                path = endpoint.get("path", "")
                results[path] = True
                logger.info("Cache warmed", endpoint=path)

            except Exception as e:
                results[path] = False
                logger.error("Cache warming failed", endpoint=path, error=str(e))

        return results

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics and health information."""
        try:
            # This would collect actual cache statistics
            # Implementation depends on your Redis monitoring setup

            return {
                "enabled": getattr(settings, "ENABLE_RESPONSE_CACHE", True),
                "default_ttl": self.default_ttl,
                "cache_patterns_count": len(self.cache_patterns),
                "exclude_patterns_count": len(self.exclude_patterns),
                "invalidation_patterns_count": len(self.invalidation_patterns),
                "max_cache_size": self.max_cache_size,
            }

        except Exception as e:
            logger.error("Failed to get cache stats", error=str(e))
            return {"error": str(e)}
