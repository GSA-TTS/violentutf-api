"""Security utilities for authentication and authorization."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import jwt
from passlib.context import CryptContext
from structlog.stdlib import get_logger

from .config import get_settings

logger = get_logger(__name__)


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


def create_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None, token_type: str = "access") -> str:
    """Create a JWT token (generic function for any token type)."""
    if token_type == "access":
        return create_access_token(data, expires_delta)
    elif token_type == "refresh":
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


def hash_token(token: str) -> str:
    """Hash a token using SHA256."""
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()
