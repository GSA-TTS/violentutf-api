"""Authentication failover mechanisms and fallback providers."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from structlog.stdlib import get_logger

from app.core.cache import get_cache
from app.core.circuit_breaker import circuit_breaker
from app.core.errors import AuthenticationError
from app.models.user import User

logger = get_logger(__name__)


class FallbackAuthProvider:
    """Provides fallback authentication when primary services fail."""

    # Cache key prefixes
    USER_CACHE_PREFIX = "fallback_user"
    PERMISSION_CACHE_PREFIX = "fallback_permissions"
    API_KEY_CACHE_PREFIX = "fallback_api_key"  # pragma: allowlist secret

    # Cache TTLs
    USER_CACHE_TTL = 3600  # 1 hour
    PERMISSION_CACHE_TTL = 1800  # 30 minutes
    API_KEY_CACHE_TTL = 7200  # 2 hours

    def __init__(self):
        """Initialize fallback auth provider."""
        self._emergency_tokens: Dict[str, Dict[str, Any]] = {}
        self._last_sync: Optional[datetime] = None
        self._sync_interval = timedelta(minutes=5)

    async def cache_user_credentials(
        self,
        user: User,
        password_hash: Optional[str] = None,
        permissions: Optional[List[str]] = None,
    ) -> None:
        """
        Cache user credentials for fallback authentication.

        Args:
            user: User object
            password_hash: Hashed password (optional)
            permissions: User permissions (optional)
        """
        cache = await get_cache()

        # Cache user data
        user_data = {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "roles": user.roles or [],
            "organization_id": str(user.organization_id) if user.organization_id else None,
            "password_hash": password_hash,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }

        # Cache by username and email for multiple lookup paths
        username_key = f"{self.USER_CACHE_PREFIX}:username:{user.username}"
        email_key = f"{self.USER_CACHE_PREFIX}:email:{user.email}"
        id_key = f"{self.USER_CACHE_PREFIX}:id:{user.id}"

        await cache.set(username_key, user_data, ttl=self.USER_CACHE_TTL)
        await cache.set(email_key, user_data, ttl=self.USER_CACHE_TTL)
        await cache.set(id_key, user_data, ttl=self.USER_CACHE_TTL)

        # Cache permissions if provided
        if permissions:
            perm_key = f"{self.PERMISSION_CACHE_PREFIX}:{user.id}"
            await cache.set(perm_key, permissions, ttl=self.PERMISSION_CACHE_TTL)

    async def authenticate_fallback(
        self,
        username_or_email: str,
        password: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate user using cached credentials.

        Args:
            username_or_email: Username or email
            password: Plain password

        Returns:
            User data if authenticated, None otherwise
        """
        cache = await get_cache()

        # Try username lookup first
        username_key = f"{self.USER_CACHE_PREFIX}:username:{username_or_email}"
        user_data = await cache.get(username_key)

        # Try email lookup if username failed
        if not user_data:
            email_key = f"{self.USER_CACHE_PREFIX}:email:{username_or_email}"
            user_data = await cache.get(email_key)

        if not user_data:
            return None

        # Check if user is active
        if not user_data.get("is_active", False):
            return None

        # Verify password if hash is cached
        password_hash = user_data.get("password_hash")
        if password_hash:
            # Use bcrypt for secure password verification
            try:
                import bcrypt

                if not bcrypt.checkpw(password.encode(), password_hash.encode()):
                    return None
            except ImportError:
                # bcrypt is required for secure password verification
                logger.error("bcrypt library not available for secure password verification")
                raise AuthenticationError("Password verification not available - system misconfiguration")
        else:
            # No password hash cached, can't verify
            logger.warning("No password hash cached for fallback auth", username=username_or_email)
            return None

        # Remove password hash from returned data
        user_data.pop("password_hash", None)

        logger.info(
            "User authenticated via fallback",
            user_id=user_data["id"],
            username=user_data["username"],
        )

        return user_data

    async def cache_api_key(
        self,
        api_key: str,
        user_id: str,
        permissions: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Cache API key for fallback authentication.

        Args:
            api_key: API key (hashed)
            user_id: User ID
            permissions: API key permissions
            metadata: Additional metadata
        """
        cache = await get_cache()

        key_data = {
            "user_id": user_id,
            "permissions": permissions,
            "metadata": metadata or {},
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }

        cache_key = f"{self.API_KEY_CACHE_PREFIX}:{api_key}"
        await cache.set(cache_key, key_data, ttl=self.API_KEY_CACHE_TTL)

    async def validate_api_key_fallback(
        self,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate API key using cache.

        Args:
            api_key: API key to validate

        Returns:
            API key data if valid, None otherwise
        """
        cache = await get_cache()

        cache_key = f"{self.API_KEY_CACHE_PREFIX}:{api_key}"
        key_data = await cache.get(cache_key)

        if key_data:
            logger.info(
                "API key validated via fallback",
                user_id=key_data["user_id"],
            )

        return key_data

    async def get_user_permissions_fallback(
        self,
        user_id: str,
    ) -> List[str]:
        """
        Get user permissions from cache.

        Args:
            user_id: User ID

        Returns:
            List of permissions
        """
        cache = await get_cache()

        perm_key = f"{self.PERMISSION_CACHE_PREFIX}:{user_id}"
        permissions = await cache.get(perm_key, default=[])

        return permissions

    async def create_emergency_token(
        self,
        user_id: str,
        permissions: List[str],
        duration: timedelta = timedelta(hours=1),
        reason: str = "emergency_access",
    ) -> str:
        """
        Create emergency access token for critical operations.

        Args:
            user_id: User ID
            permissions: Granted permissions
            duration: Token validity duration
            reason: Reason for emergency access

        Returns:
            Emergency token
        """
        import secrets

        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + duration

        token_data = {
            "user_id": user_id,
            "permissions": permissions,
            "expires_at": expires_at,
            "reason": reason,
            "created_at": datetime.now(timezone.utc),
        }

        # Store in memory and cache
        self._emergency_tokens[token] = token_data

        cache = await get_cache()
        cache_key = f"emergency_token:{token}"
        await cache.set(
            cache_key,
            token_data,
            ttl=int(duration.total_seconds()),
        )

        logger.warning(
            "Emergency token created",
            user_id=user_id,
            reason=reason,
            expires_at=expires_at.isoformat(),
        )

        return token

    async def validate_emergency_token(
        self,
        token: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate emergency access token.

        Args:
            token: Emergency token

        Returns:
            Token data if valid, None otherwise
        """
        # Check memory first
        token_data = self._emergency_tokens.get(token)

        if not token_data:
            # Check cache
            cache = await get_cache()
            cache_key = f"emergency_token:{token}"
            token_data = await cache.get(cache_key)

        if not token_data:
            return None

        # Check expiration
        expires_at = token_data["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        if expires_at <= datetime.now(timezone.utc):
            # Token expired, clean up
            self._emergency_tokens.pop(token, None)
            cache = await get_cache()
            await cache.delete(f"emergency_token:{token}")
            return None

        logger.warning(
            "Emergency token validated",
            user_id=token_data["user_id"],
            reason=token_data["reason"],
        )

        return token_data

    async def sync_critical_users(
        self,
        users: List[Tuple[User, str]],
    ) -> None:
        """
        Sync critical users to fallback cache.

        Args:
            users: List of (User, password_hash) tuples
        """
        for user, password_hash in users:
            await self.cache_user_credentials(
                user=user,
                password_hash=password_hash,
            )

        self._last_sync = datetime.now(timezone.utc)

        logger.info(
            "Critical users synced to fallback cache",
            count=len(users),
        )

    async def is_service_degraded(self) -> bool:
        """
        Check if authentication service is degraded.

        Returns:
            True if service is degraded
        """
        # Check circuit breaker states
        from app.core.circuit_breaker import get_circuit_breaker

        auth_breaker = get_circuit_breaker("auth.login")
        db_breaker = get_circuit_breaker("database.query")

        return (auth_breaker and auth_breaker.is_open) or (db_breaker and db_breaker.is_open)

    async def get_degraded_mode_info(self) -> Dict[str, Any]:
        """
        Get information about degraded mode status.

        Returns:
            Degraded mode information
        """
        cache = await get_cache()
        cache_health = await cache.health_check()

        # Count cached items
        user_count = len(self._emergency_tokens)

        return {
            "is_degraded": await self.is_service_degraded(),
            "cache_available": cache_health.get("redis_available", False),
            "fallback_mode": not cache_health.get("redis_available", False),
            "emergency_tokens_active": user_count,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "cache_health": cache_health,
        }


# Global instance
_fallback_provider = FallbackAuthProvider()


def get_fallback_auth_provider() -> FallbackAuthProvider:
    """Get global fallback auth provider instance."""
    return _fallback_provider


@circuit_breaker(
    name="auth.login",
    failure_threshold=5,
    recovery_timeout=60,
)
async def authenticate_with_fallback(
    username_or_email: str,
    password: str,
    primary_auth_func: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Authenticate with automatic fallback.

    Args:
        username_or_email: Username or email
        password: Plain password
        primary_auth_func: Primary authentication function

    Returns:
        User data

    Raises:
        AuthenticationError: If authentication fails
    """
    # Try primary authentication if available
    if primary_auth_func:
        try:
            result = await primary_auth_func(username_or_email, password)
            if result:
                # Cache for fallback
                provider = get_fallback_auth_provider()
                await provider.cache_user_credentials(
                    user=result,
                    # Note: In real implementation, get password hash from auth service
                )
                return result
        except Exception as e:
            logger.warning(
                "Primary authentication failed",
                error=str(e),
                fallback_available=True,
            )

    # Try fallback authentication
    provider = get_fallback_auth_provider()
    user_data = await provider.authenticate_fallback(username_or_email, password)

    if not user_data:
        raise AuthenticationError("Authentication failed")

    return user_data
