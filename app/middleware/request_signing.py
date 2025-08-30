"""Request signing middleware for ViolentUTF API."""

import hashlib
import hmac
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from structlog.stdlib import get_logger

from ..core.config import settings
from ..utils.cache import get_cache_client
from .body_cache import get_cached_body, has_cached_body

logger = get_logger(__name__)

# Request signing configuration
SIGNATURE_HEADER = "X-Signature"
TIMESTAMP_HEADER = "X-Timestamp"
API_KEY_HEADER = "X-API-Key"  # pragma: allowlist secret
NONCE_HEADER = "X-Nonce"

# Signing algorithm
SIGNATURE_ALGORITHM = "SHA256"

# Maximum age for signed requests (5 minutes)
MAX_REQUEST_AGE = 300

# Paths that require request signing
SIGNED_PATHS: List[str] = [
    "/api/v1/admin/",
    "/api/v1/users/",
    "/api/v1/api-keys/",
]


class RequestSigningMiddleware(BaseHTTPMiddleware):
    """Middleware for request signing verification."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize request signing middleware."""
        super().__init__(app)
        self.cache = get_cache_client()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Process request with signature verification.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response or 401/403 if signature validation fails
        """
        # Check if path requires signing
        requires_signing = any(request.url.path.startswith(path) for path in SIGNED_PATHS)

        if not requires_signing:
            return await call_next(request)

        # Extract signing headers
        signature = request.headers.get(SIGNATURE_HEADER)
        timestamp = request.headers.get(TIMESTAMP_HEADER)
        api_key = request.headers.get(API_KEY_HEADER)
        nonce = request.headers.get(NONCE_HEADER)

        # Validate signature presence
        if not all([signature, timestamp, api_key, nonce]):
            logger.warning(
                "request_signing_headers_missing",
                path=request.url.path,
                has_signature=bool(signature),
                has_timestamp=bool(timestamp),
                has_api_key=bool(api_key),
                has_nonce=bool(nonce),
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Request signing required"},
            )

        # Type narrowing and validation
        if signature is None or timestamp is None or api_key is None or nonce is None:
            logger.warning("Missing required request signing parameters")
            raise HTTPException(status_code=400, detail="Missing required request signing parameters")

        # Validate timestamp
        try:
            request_time = int(timestamp)
            current_time = int(time.time())

            if abs(current_time - request_time) > MAX_REQUEST_AGE:
                logger.warning(
                    "request_timestamp_expired",
                    request_time=request_time,
                    current_time=current_time,
                    age=abs(current_time - request_time),
                )
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Request timestamp expired"},
                )
        except ValueError:
            logger.warning("invalid_timestamp", timestamp=timestamp)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Invalid timestamp"},
            )

        # Check nonce replay
        if await self._is_nonce_replayed(nonce, api_key):
            logger.warning(
                "nonce_replay_detected",
                nonce=nonce[:16] + "...",
                api_key=api_key[:8] + "...",
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Nonce replay detected"},
            )

        # Get API key secret (this would come from database in real implementation)
        api_secret = await self._get_api_secret(api_key)
        if not api_secret:
            logger.warning("invalid_api_key", api_key=api_key[:8] + "...")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid API key"},
            )

        # Read request body for signing - use cached body if available to avoid ASGI conflicts
        if has_cached_body(request):
            body = get_cached_body(request)
        else:
            body = await request.body()

        # Verify signature
        if not await self._verify_signature(
            request.method,
            request.url.path,
            dict(request.query_params),
            dict(request.headers),
            body,
            timestamp,
            nonce,
            signature,
            api_secret,
        ):
            logger.warning(
                "signature_verification_failed",
                method=request.method,
                path=request.url.path,
                api_key=api_key[:8] + "...",
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Invalid signature"},
            )

        # Store nonce to prevent replay
        await self._store_nonce(nonce, api_key)

        # Store API key in request state for later use
        request.state.api_key = api_key
        request.state.signature_verified = True

        # Note: No need to recreate request body stream when using body caching middleware

        # Process request
        response = await call_next(request)
        return response

    async def _get_api_secret(self, api_key: str) -> Optional[str]:
        """Get API secret for key validation.

        In production, this would query the database.

        Args:
            api_key: API key to lookup

        Returns:
            API secret or None if invalid
        """
        # Placeholder implementation
        # In real implementation, this would query the API keys table
        if api_key.startswith("test_"):
            return "test_secret"
        elif api_key.startswith("admin_"):
            return "admin_secret"
        else:
            return None

    async def _verify_signature(
        self,
        method: str,
        path: str,
        query_params: Dict[str, Any],
        headers: Dict[str, Any],
        body: bytes,
        timestamp: str,
        nonce: str,
        signature: str,
        api_secret: str,
    ) -> bool:
        """Verify request signature.

        Args:
            method: HTTP method
            path: Request path
            query_params: Query parameters
            headers: Request headers
            body: Request body
            timestamp: Request timestamp
            nonce: Request nonce
            signature: Provided signature
            api_secret: API secret for verification

        Returns:
            True if signature is valid
        """
        try:
            # Create canonical request string
            canonical_string = self._create_canonical_request(
                method, path, query_params, headers, body, timestamp, nonce
            )

            # Create expected signature
            # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signature verification, not sensitive data storage
            expected_signature = hmac.new(
                api_secret.encode(),
                canonical_string.encode(),
                hashlib.sha256,  # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signatures
            ).hexdigest()

            # Constant-time comparison
            return hmac.compare_digest(signature.lower(), expected_signature.lower())
        except Exception as e:
            logger.error("signature_verification_error", error=str(e))
            return False

    def _create_canonical_request(
        self,
        method: str,
        path: str,
        query_params: Dict[str, Any],
        headers: Dict[str, Any],
        body: bytes,
        timestamp: str,
        nonce: str,
    ) -> str:
        """Create canonical request string for signing.

        Args:
            method: HTTP method
            path: Request path
            query_params: Query parameters
            headers: Request headers
            body: Request body
            timestamp: Request timestamp
            nonce: Request nonce

        Returns:
            Canonical request string
        """
        # Canonical method
        canonical_method = method.upper()

        # Canonical path
        canonical_path = path

        # Canonical query string (sorted)
        query_items = sorted(query_params.items())
        canonical_query = "&".join([f"{k}={v}" for k, v in query_items])

        # Canonical headers (only signed headers, sorted)
        signed_headers = ["content-type", "host"]
        canonical_headers = []
        for header in sorted(signed_headers):
            value = headers.get(header, "")
            canonical_headers.append(f"{header}:{value.strip()}")
        canonical_headers_str = "\n".join(canonical_headers)

        # Body hash
        # CodeQL [py/weak-sensitive-data-hashing] SHA256 appropriate for request body integrity, not sensitive data storage
        body_hash = hashlib.sha256(body).hexdigest()

        # Combine all parts
        canonical_request = "\n".join(
            [
                canonical_method,
                canonical_path,
                canonical_query,
                canonical_headers_str,
                "",  # Empty line after headers
                ";".join(sorted(signed_headers)),  # Signed headers list
                timestamp,
                nonce,
                body_hash,
            ]
        )

        return canonical_request

    async def _is_nonce_replayed(self, nonce: str, api_key: str) -> bool:
        """Check if nonce has been used before.

        Args:
            nonce: Request nonce
            api_key: API key

        Returns:
            True if nonce was replayed
        """
        if not self.cache:
            # If no cache, allow (but log warning)
            logger.warning("nonce_check_unavailable_no_cache")
            return False

        try:
            nonce_key = f"nonce:{api_key}:{nonce}"
            exists = await self.cache.get(nonce_key)
            return exists is not None
        except Exception as e:
            logger.error("nonce_check_error", error=str(e))
            return False

    async def _store_nonce(self, nonce: str, api_key: str) -> None:
        """Store nonce to prevent replay.

        Args:
            nonce: Request nonce
            api_key: API key
        """
        if not self.cache:
            return

        try:
            nonce_key = f"nonce:{api_key}:{nonce}"
            # Store for maximum request age duration
            await self.cache.set(nonce_key, "used", ex=MAX_REQUEST_AGE)
        except Exception as e:
            logger.error("nonce_storage_error", error=str(e))


class RequestSigner:
    """Helper class for creating signed requests."""

    def __init__(self, api_key: str, api_secret: str) -> None:
        """Initialize request signer.

        Args:
            api_key: API key
            api_secret: API secret
        """
        self.api_key = api_key
        self.api_secret = api_secret

    def sign_request(
        self,
        method: str,
        path: str,
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ) -> Dict[str, str]:
        """Sign a request and return headers.

        Args:
            method: HTTP method
            path: Request path
            query_params: Query parameters
            headers: Request headers
            body: Request body

        Returns:
            Dictionary of headers to add to request
        """
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(16)

        # Prepare headers and params
        headers = headers or {}
        query_params = query_params or {}

        # Create canonical request
        canonical_string = self._create_canonical_request(method, path, query_params, headers, body, timestamp, nonce)

        # Create signature
        # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signature generation, not sensitive data storage
        signature = hmac.new(
            self.api_secret.encode(),
            canonical_string.encode(),
            hashlib.sha256,  # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signatures
        ).hexdigest()

        return {
            API_KEY_HEADER: self.api_key,
            SIGNATURE_HEADER: signature,
            TIMESTAMP_HEADER: timestamp,
            NONCE_HEADER: nonce,
        }

    def _create_canonical_request(
        self,
        method: str,
        path: str,
        query_params: Dict[str, str],
        headers: Dict[str, str],
        body: bytes,
        timestamp: str,
        nonce: str,
    ) -> str:
        """Create canonical request string - same as middleware."""
        # This duplicates the middleware logic
        # In production, this should be shared code
        canonical_method = method.upper()
        canonical_path = path

        query_items = sorted(query_params.items())
        canonical_query = "&".join([f"{k}={v}" for k, v in query_items])

        signed_headers = ["content-type", "host"]
        canonical_headers = []
        for header in sorted(signed_headers):
            value = headers.get(header, "")
            canonical_headers.append(f"{header}:{value.strip()}")
        canonical_headers_str = "\n".join(canonical_headers)

        # CodeQL [py/weak-sensitive-data-hashing] SHA256 appropriate for request body integrity, not sensitive data storage
        body_hash = hashlib.sha256(body).hexdigest()

        canonical_request = "\n".join(
            [
                canonical_method,
                canonical_path,
                canonical_query,
                canonical_headers_str,
                "",
                ";".join(sorted(signed_headers)),
                timestamp,
                nonce,
                body_hash,
            ]
        )

        return canonical_request


def get_request_signer(api_key: str, api_secret: str) -> RequestSigner:
    """Get request signer instance.

    Args:
        api_key: API key
        api_secret: API secret

    Returns:
        RequestSigner instance
    """
    return RequestSigner(api_key, api_secret)
