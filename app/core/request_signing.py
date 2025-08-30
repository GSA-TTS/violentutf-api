"""Request signing framework for ViolentUTF API.

This module provides HMAC-based request signing for sensitive operations,
protecting against tampering and replay attacks.
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""

    HMAC_SHA256 = "HMAC-SHA256"
    HMAC_SHA512 = "HMAC-SHA512"


class SignatureVersion(str, Enum):
    """Signature scheme versions."""

    V1 = "v1"  # Basic HMAC
    V2 = "v2"  # HMAC with timestamp and nonce


class RequestSignature(BaseModel):
    """Request signature information."""

    signature: str
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256
    version: SignatureVersion = SignatureVersion.V2
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    nonce: Optional[str] = None
    key_id: Optional[str] = None
    headers: List[str] = Field(default_factory=list)


class SignatureConfig(BaseModel):
    """Configuration for request signing."""

    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256
    version: SignatureVersion = SignatureVersion.V2
    max_age_seconds: int = 300  # 5 minutes
    require_nonce: bool = True
    require_timestamp: bool = True
    include_headers: List[str] = Field(default_factory=lambda: ["host", "content-type", "content-length"])
    include_query_params: bool = True
    include_body: bool = True
    body_hash_algorithm: str = "sha256"


class SignatureValidationResult(BaseModel):
    """Result of signature validation."""

    is_valid: bool
    error: Optional[str] = None
    signature_age: Optional[int] = None
    key_id: Optional[str] = None


def get_hash_function(algorithm: SignatureAlgorithm) -> Any:
    """Get hash function for algorithm.

    Args:
        algorithm: Signature algorithm

    Returns:
        Hash function

    Raises:
        ValueError: If algorithm not supported
    """
    if algorithm == SignatureAlgorithm.HMAC_SHA256:
        # CodeQL [py/weak-sensitive-data-hashing] SHA256 appropriate for HMAC signature algorithms, not sensitive data storage
        return hashlib.sha256
    elif algorithm == SignatureAlgorithm.HMAC_SHA512:
        return hashlib.sha512
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def compute_body_hash(body: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of request body.

    Args:
        body: Request body bytes
        algorithm: Hash algorithm

    Returns:
        Hex-encoded hash
    """
    if algorithm == "sha256":
        # CodeQL [py/weak-sensitive-data-hashing] SHA256 appropriate for request body integrity, not sensitive data storage
        return hashlib.sha256(body).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(body).hexdigest()
    else:
        raise ValueError(f"Unsupported body hash algorithm: {algorithm}")


def create_signing_string(
    method: str,
    path: str,
    headers: Dict[str, str],
    query_params: Optional[Dict[str, str]] = None,
    body_hash: Optional[str] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
    config: Optional[SignatureConfig] = None,
) -> str:
    """Create canonical string to sign.

    Args:
        method: HTTP method
        path: Request path
        headers: Request headers
        query_params: Query parameters
        body_hash: Hash of request body
        timestamp: Request timestamp
        nonce: Request nonce
        config: Signature configuration

    Returns:
        Canonical string for signing
    """
    if config is None:
        config = SignatureConfig()

    parts = []

    # Add method and path
    parts.append(method.upper())
    parts.append(path)

    # Add selected headers
    if config.include_headers:
        header_parts = []
        for header_name in sorted(config.include_headers):
            header_value = headers.get(header_name.lower(), "")
            header_parts.append(f"{header_name.lower()}:{header_value}")
        parts.append("\n".join(header_parts))

    # Add query parameters
    if config.include_query_params and query_params:
        sorted_params = sorted(query_params.items())
        query_string = "&".join([f"{k}={v}" for k, v in sorted_params])
        parts.append(query_string)

    # Add body hash
    if config.include_body and body_hash:
        parts.append(f"body-hash:{body_hash}")

    # Add timestamp
    if config.require_timestamp and timestamp:
        parts.append(f"timestamp:{timestamp}")

    # Add nonce
    if config.require_nonce and nonce:
        parts.append(f"nonce:{nonce}")

    return "\n".join(parts)


def sign_request(
    secret_key: str,
    method: str,
    path: str,
    headers: Dict[str, str],
    query_params: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    config: Optional[SignatureConfig] = None,
    key_id: Optional[str] = None,
) -> RequestSignature:
    """Sign a request.

    Args:
        secret_key: Secret key for signing
        method: HTTP method
        path: Request path
        headers: Request headers
        query_params: Query parameters
        body: Request body
        config: Signature configuration
        key_id: Optional key identifier

    Returns:
        Request signature
    """
    if config is None:
        config = SignatureConfig()

    # Generate timestamp and nonce
    timestamp = int(time.time())
    # CodeQL [py/weak-sensitive-data-hashing] SHA256 appropriate for nonce generation, not sensitive data storage
    nonce = hashlib.sha256(f"{timestamp}{path}".encode()).hexdigest()[:16]

    # Compute body hash if needed
    body_hash = None
    if config.include_body and body:
        body_hash = compute_body_hash(body, config.body_hash_algorithm)

    # Create signing string
    signing_string = create_signing_string(
        method=method,
        path=path,
        headers=headers,
        query_params=query_params,
        body_hash=body_hash,
        timestamp=timestamp,
        nonce=nonce,
        config=config,
    )

    # Compute signature
    hash_func = get_hash_function(config.algorithm)
    signature = hmac.new(
        secret_key.encode(),
        signing_string.encode(),
        hash_func,
    ).hexdigest()

    return RequestSignature(
        signature=signature,
        algorithm=config.algorithm,
        version=config.version,
        timestamp=timestamp,
        nonce=nonce,
        key_id=key_id,
        headers=config.include_headers,
    )


def verify_signature(
    secret_key: str,
    method: str,
    path: str,
    headers: Dict[str, str],
    provided_signature: RequestSignature,
    query_params: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    config: Optional[SignatureConfig] = None,
    nonce_cache: Optional[Set[str]] = None,
) -> SignatureValidationResult:
    """Verify a request signature.

    Args:
        secret_key: Secret key for verification
        method: HTTP method
        path: Request path
        headers: Request headers
        provided_signature: Provided signature to verify
        query_params: Query parameters
        body: Request body
        config: Signature configuration
        nonce_cache: Cache of used nonces (for replay prevention)

    Returns:
        Validation result
    """
    if config is None:
        config = SignatureConfig()

    try:
        # Check signature age
        if config.require_timestamp:
            current_time = int(time.time())
            signature_age = current_time - provided_signature.timestamp

            if signature_age > config.max_age_seconds:
                return SignatureValidationResult(
                    is_valid=False,
                    error=f"Signature expired (age: {signature_age}s)",
                    signature_age=signature_age,
                    key_id=provided_signature.key_id,
                )

            if signature_age < -30:  # Allow 30s clock skew
                return SignatureValidationResult(
                    is_valid=False,
                    error="Signature timestamp in future",
                    signature_age=signature_age,
                    key_id=provided_signature.key_id,
                )

        # Check nonce for replay attacks
        if config.require_nonce and provided_signature.nonce:
            if nonce_cache is not None and provided_signature.nonce in nonce_cache:
                return SignatureValidationResult(
                    is_valid=False,
                    error="Nonce already used (replay attack)",
                    key_id=provided_signature.key_id,
                )

        # Compute body hash if needed
        body_hash = None
        if config.include_body and body:
            body_hash = compute_body_hash(body, config.body_hash_algorithm)

        # Create signing string
        signing_string = create_signing_string(
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body_hash=body_hash,
            timestamp=provided_signature.timestamp,
            nonce=provided_signature.nonce,
            config=config,
        )

        # Compute expected signature
        hash_func = get_hash_function(provided_signature.algorithm)
        expected_signature = hmac.new(
            secret_key.encode(),
            signing_string.encode(),
            hash_func,
        ).hexdigest()

        # Compare signatures (constant time)
        is_valid = hmac.compare_digest(expected_signature, provided_signature.signature)

        if is_valid and nonce_cache is not None and provided_signature.nonce:
            # Add nonce to cache to prevent replay
            nonce_cache.add(provided_signature.nonce)

        return SignatureValidationResult(
            is_valid=is_valid,
            error=None if is_valid else "Invalid signature",
            signature_age=signature_age if config.require_timestamp else None,
            key_id=provided_signature.key_id,
        )

    except Exception as e:
        logger.error("signature_verification_error", error=str(e))
        return SignatureValidationResult(
            is_valid=False,
            error=f"Verification error: {str(e)}",
            key_id=provided_signature.key_id,
        )


def parse_authorization_header(auth_header: str) -> Optional[RequestSignature]:
    """Parse Authorization header for signature.

    Expected format:
    Authorization: Signature keyId="key123",algorithm="HMAC-SHA256",headers="host content-type",signature="abc123"

    Args:
        auth_header: Authorization header value

    Returns:
        Parsed signature or None
    """
    if not auth_header or not auth_header.startswith("Signature "):
        return None

    try:
        # Remove "Signature " prefix
        sig_string = auth_header[10:]

        # Parse key-value pairs
        params = {}
        for param in sig_string.split(","):
            key, value = param.strip().split("=", 1)
            # Remove quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            params[key] = value

        # Create signature object
        return RequestSignature(
            signature=params.get("signature", ""),
            key_id=params.get("keyId"),
            algorithm=SignatureAlgorithm(params.get("algorithm", "HMAC-SHA256")),
            headers=params.get("headers", "").split() if params.get("headers") else [],
            timestamp=(int(params.get("timestamp", 0)) if params.get("timestamp") else int(time.time())),
            nonce=params.get("nonce"),
        )

    except Exception as e:
        logger.error("authorization_header_parse_error", error=str(e))
        return None


def format_authorization_header(signature: RequestSignature) -> str:
    """Format signature as Authorization header.

    Args:
        signature: Request signature

    Returns:
        Formatted Authorization header value
    """
    parts = []

    if signature.key_id:
        parts.append(f'keyId="{signature.key_id}"')

    parts.append(f'algorithm="{signature.algorithm.value}"')

    if signature.headers:
        parts.append(f'headers="{" ".join(signature.headers)}"')

    if signature.timestamp:
        parts.append(f'timestamp="{signature.timestamp}"')

    if signature.nonce:
        parts.append(f'nonce="{signature.nonce}"')

    parts.append(f'signature="{signature.signature}"')

    return "Signature " + ",".join(parts)


class SignatureKeyStore:
    """Store for signature keys."""

    def __init__(self) -> None:
        """Initialize key store."""
        self._keys: Dict[str, str] = {}
        self._key_metadata: Dict[str, Dict[str, Any]] = {}

    def add_key(
        self,
        key_id: str,
        secret_key: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a key to the store.

        Args:
            key_id: Key identifier
            secret_key: Secret key value
            metadata: Optional key metadata
        """
        self._keys[key_id] = secret_key
        if metadata:
            self._key_metadata[key_id] = metadata

    def get_key(self, key_id: str) -> Optional[str]:
        """Get a key by ID.

        Args:
            key_id: Key identifier

        Returns:
            Secret key or None
        """
        return self._keys.get(key_id)

    def remove_key(self, key_id: str) -> None:
        """Remove a key.

        Args:
            key_id: Key identifier
        """
        self._keys.pop(key_id, None)
        self._key_metadata.pop(key_id, None)

    def list_keys(self) -> List[str]:
        """List all key IDs.

        Returns:
            List of key IDs
        """
        return list(self._keys.keys())


# Global key store
signature_key_store = SignatureKeyStore()


class NonceCache:
    """Cache for tracking used nonces."""

    def __init__(self, max_age_seconds: int = 300) -> None:
        """Initialize nonce cache.

        Args:
            max_age_seconds: Maximum age for nonces
        """
        self._nonces: Dict[str, float] = {}
        self._max_age_seconds = max_age_seconds

    def add(self, nonce: str) -> None:
        """Add a nonce to the cache.

        Args:
            nonce: Nonce value
        """
        self._nonces[nonce] = time.time()
        self._cleanup()

    def contains(self, nonce: str) -> bool:
        """Check if nonce exists in cache.

        Args:
            nonce: Nonce value

        Returns:
            True if nonce exists
        """
        self._cleanup()
        return nonce in self._nonces

    def _cleanup(self) -> None:
        """Remove expired nonces."""
        current_time = time.time()
        expired = [
            nonce for nonce, timestamp in self._nonces.items() if current_time - timestamp > self._max_age_seconds
        ]
        for nonce in expired:
            del self._nonces[nonce]

    def clear(self) -> None:
        """Clear all nonces."""
        self._nonces.clear()


# Global nonce cache
nonce_cache = NonceCache()

# Global signature key store
signature_key_store = SignatureKeyStore()


def get_request_info(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes] = None,
) -> Tuple[str, Dict[str, str], Optional[bytes]]:
    """Extract request information for signing.

    Args:
        method: HTTP method
        url: Full URL
        headers: Request headers
        body: Request body

    Returns:
        Tuple of (path, query_params, body)
    """
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(url)
    path = parsed.path

    # Parse query parameters
    query_params = {}
    if parsed.query:
        parsed_qs = parse_qs(parsed.query)
        # Flatten single-value lists
        query_params = {k: v[0] if len(v) == 1 else ",".join(v) for k, v in parsed_qs.items()}

    return path, query_params, body
