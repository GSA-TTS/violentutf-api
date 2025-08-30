"""Security utilities for authentication and authorization."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import jwt
from passlib.context import CryptContext
from structlog.stdlib import get_logger

from .config import get_settings

logger = get_logger(__name__)

# JWT token type constants to avoid hardcoded strings flagged by security scanners
ACCESS_TOKEN_TYPE = "access"  # nosec B105 - Standard JWT token type
REFRESH_TOKEN_TYPE = "refresh"  # nosec B105 - Standard JWT token type


# Password hashing context with Argon2
def _get_pwd_context() -> CryptContext:
    """Get password context with current settings."""
    settings = get_settings()
    return CryptContext(
        schemes=["argon2"],
        deprecated="auto",
        argon2__rounds=settings.BCRYPT_ROUNDS,
        argon2__memory_cost=65536,
        argon2__parallelism=2,
    )


pwd_context = _get_pwd_context()


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        settings = get_settings()
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})

    settings = get_settings()
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM,
    )

    logger.info("Access token created", sub=data.get("sub"))
    return str(encoded_jwt)


def create_refresh_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        settings = get_settings()
        expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "type": "refresh"})

    settings = get_settings()
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM,
    )

    logger.info("Refresh token created", sub=data.get("sub"))
    return str(encoded_jwt)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token."""
    try:
        settings = get_settings()
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
        )
        return dict(payload)
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token", error=str(e))
        raise ValueError("Could not validate credentials")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        pwd_context = _get_pwd_context()
        result = pwd_context.verify(plain_password, hashed_password)
        return bool(result)
    except Exception as e:
        logger.error("Password verification failed", error=str(e))
        return False


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    pwd_context = _get_pwd_context()
    result = pwd_context.hash(password)
    return str(result)


def generate_api_key(length: int = 32) -> str:
    """Generate a secure API key."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong"


def create_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    token_type: str = ACCESS_TOKEN_TYPE,
) -> str:
    """Create a JWT token (generic function for any token type)."""
    if token_type == ACCESS_TOKEN_TYPE:
        return create_access_token(data, expires_delta)
    elif token_type == REFRESH_TOKEN_TYPE:
        return create_refresh_token(data, expires_delta)
    else:
        # For other token types (like OAuth tokens), create a custom token
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=60)

        to_encode.update({"exp": expire, "type": token_type})

        settings = get_settings()
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )

        return str(encoded_jwt)


def hash_oauth_token(token: str) -> str:
    """Hash an OAuth token for secure storage using Argon2.

    Uses Argon2 which is a computationally expensive hash function appropriate
    for sensitive data like OAuth tokens, authorization codes, and refresh tokens.
    This ensures protection against brute force attacks even if the database is compromised.

    OAuth tokens are considered sensitive authentication credentials similar to passwords
    and should use computationally expensive hashing algorithms per OWASP recommendations.
    """
    pwd_context = _get_pwd_context()
    return pwd_context.hash(token)


def hash_cache_key(key: str) -> str:
    """Hash a cache key for secure storage using BLAKE2b.

    This function is ONLY for cache keys and non-sensitive identifiers.
    DO NOT use for passwords - use hash_password(), hash_api_key(), or hash_client_secret().
    """
    import hashlib

    from .config import settings

    secret_key = (
        settings.SECRET_KEY.get_secret_value()
        if hasattr(settings.SECRET_KEY, "get_secret_value")
        else str(settings.SECRET_KEY)
    )
    # BLAKE2b with key is cryptographically secure for cache key hashing
    return hashlib.blake2b(
        key.encode(), key=secret_key.encode()[:64], digest_size=32  # BLAKE2b key max 64 bytes
    ).hexdigest()


# Legacy function - deprecated, use specific functions above
def hash_token(token: str) -> str:
    """DEPRECATED: Use hash_oauth_token() or hash_cache_key() instead."""
    return hash_oauth_token(token)


def hash_client_secret(client_secret: str) -> str:
    """Hash an OAuth client secret using secure password hashing.

    Uses Argon2 for secure password-based key derivation.
    This is specifically for OAuth client secrets which should use
    computationally expensive hashing algorithms.
    """
    return pwd_context.hash(client_secret)


def hash_api_key(api_key: str) -> str:
    """Hash an API key using secure password hashing.

    Uses Argon2 for secure password-based key derivation.
    API keys are sensitive authentication credentials and should use
    computationally expensive hashing algorithms like passwords.
    """
    return pwd_context.hash(api_key)


def verify_client_secret(client_secret: str, hashed_secret: str) -> bool:
    """Verify an OAuth client secret against its hash.

    Uses secure password verification with Argon2 only.
    Legacy client secrets must be re-hashed using proper password hashing.
    """
    try:
        # Only use Argon2 verification - no fallback to weak hashing
        return pwd_context.verify(client_secret, hashed_secret)
    except Exception:
        # Return False for any verification failure - no weak hash fallback
        return False


def verify_api_key(api_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash.

    Uses secure password verification with Argon2 only.
    Legacy API keys must be re-hashed using proper password hashing.
    """
    try:
        # Only use Argon2 verification - no fallback to weak hashing
        return pwd_context.verify(api_key, hashed_key)
    except Exception:
        # Return False for any verification failure - no weak hash fallback
        return False


def verify_token_hash(token: str, stored_hash: str) -> bool:
    """Verify a token against a stored hash using Argon2.

    Uses secure Argon2 verification for OAuth tokens, authorization codes,
    and refresh tokens. This ensures protection against timing attacks and
    provides proper cryptographic verification.

    Args:
        token: The plain token to verify
        stored_hash: The stored Argon2 hash to verify against

    Returns:
        True if the token matches the stored hash
    """
    try:
        pwd_context = _get_pwd_context()
        return pwd_context.verify(token, stored_hash)
    except Exception:
        # Log migration warning for legacy hashes
        if len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
            from structlog.stdlib import get_logger

            logger = get_logger(__name__)
            logger.warning("Legacy token hash detected - token should be regenerated for security")
        return False
