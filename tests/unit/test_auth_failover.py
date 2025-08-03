"""Unit tests for authentication failover mechanisms."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.auth_failover import FallbackAuthProvider, authenticate_with_fallback
from app.core.cache import CacheManager
from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerError
from app.core.errors import AuthenticationError


# Create mock class for the model
class User:
    pass


@pytest.fixture
def mock_user():
    """Create mock user."""
    user = MagicMock(spec=User)
    user.id = "test-user-id"
    user.username = "testuser"
    user.email = "test@example.com"
    user.is_active = True
    user.is_superuser = False
    user.roles = ["user"]
    user.organization_id = None
    return user


@pytest.fixture
def fallback_provider():
    """Create fallback auth provider."""
    return FallbackAuthProvider()


class TestCacheManager:
    """Test cache manager functionality."""

    @pytest.mark.asyncio
    async def test_cache_fallback_when_redis_unavailable(self):
        """Test fallback to in-memory cache when Redis is unavailable."""
        cache = CacheManager(redis_url=None)

        # Should use in-memory cache
        await cache.set("test_key", "test_value", ttl=60)
        value = await cache.get("test_key")
        assert value == "test_value"

        # Test deletion
        await cache.set("expire_key", "expire_value", ttl=60)
        await cache.delete("expire_key")
        value = await cache.get("expire_key")
        assert value is None

    @pytest.mark.asyncio
    async def test_cache_pattern_matching(self):
        """Test cache pattern matching for clearing keys."""
        cache = CacheManager(redis_url=None)

        # Set multiple keys
        await cache.set("user:1:session", "session1", ttl=60)
        await cache.set("user:2:session", "session2", ttl=60)
        await cache.set("api:key:1", "key1", ttl=60)

        # Clear by pattern
        count = await cache.clear_pattern("user:*")
        assert count == 2

        # Verify keys were cleared
        assert await cache.get("user:1:session") is None
        assert await cache.get("user:2:session") is None
        assert await cache.get("api:key:1") == "key1"


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures."""
        breaker = CircuitBreaker(
            name="test_service",
            failure_threshold=3,
            recovery_timeout=60,
        )

        def failing_function():
            raise Exception("Service error")

        # Fail 3 times
        for _ in range(3):
            with pytest.raises(Exception):
                breaker.call(failing_function)

        # Circuit should be open
        assert breaker.is_open

        # Next call should fail immediately
        with pytest.raises(CircuitBreakerError):
            breaker.call(failing_function)

    def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker recovery through half-open state."""
        breaker = CircuitBreaker(
            name="test_service",
            failure_threshold=2,
            recovery_timeout=0,  # Immediate recovery for testing
            success_threshold=2,
        )

        call_count = 0

        def sometimes_failing_function():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Service error")
            return "success"

        # Fail twice to open circuit
        for _ in range(2):
            with pytest.raises(Exception):
                breaker.call(sometimes_failing_function)

        assert breaker.is_open

        # Wait a moment and try again (should go to half-open)
        import time

        time.sleep(0.1)

        # First success in half-open
        result = breaker.call(sometimes_failing_function)
        assert result == "success"
        assert breaker.is_half_open

        # Second success should close circuit
        result = breaker.call(sometimes_failing_function)
        assert result == "success"
        assert breaker.is_closed


class TestFallbackAuthProvider:
    """Test fallback authentication provider."""

    @pytest.mark.asyncio
    async def test_cache_user_credentials(self, fallback_provider, mock_user):
        """Test caching user credentials for fallback."""
        with patch("app.core.auth_failover.get_cache") as mock_get_cache:
            mock_cache = AsyncMock()
            mock_get_cache.return_value = mock_cache

            await fallback_provider.cache_user_credentials(
                user=mock_user,
                password_hash="hashed_password",
                permissions=["read", "write"],
            )

            # Should cache by username, email, and ID
            assert mock_cache.set.call_count == 4  # 3 user keys + 1 permission key

    @pytest.mark.asyncio
    async def test_authenticate_fallback_success(self, fallback_provider):
        """Test successful fallback authentication."""
        with patch("app.core.auth_failover.get_cache") as mock_get_cache:
            mock_cache = AsyncMock()

            # Mock bcrypt
            with patch("bcrypt.checkpw", return_value=True):
                user_data = {
                    "id": "user-id",
                    "username": "testuser",
                    "email": "test@example.com",
                    "is_active": True,
                    "password_hash": "hashed_password",
                    "roles": ["user"],
                }

                mock_cache.get.return_value = user_data
                mock_get_cache.return_value = mock_cache

                result = await fallback_provider.authenticate_fallback("testuser", "password123")

                assert result is not None
                assert result["username"] == "testuser"
                assert "password_hash" not in result

    @pytest.mark.asyncio
    async def test_authenticate_fallback_invalid_password(self, fallback_provider):
        """Test fallback authentication with invalid password."""
        with patch("app.core.auth_failover.get_cache") as mock_get_cache:
            mock_cache = AsyncMock()

            # Mock bcrypt
            with patch("bcrypt.checkpw", return_value=False):
                user_data = {
                    "id": "user-id",
                    "username": "testuser",
                    "is_active": True,
                    "password_hash": "hashed_password",
                }

                mock_cache.get.return_value = user_data
                mock_get_cache.return_value = mock_cache

                result = await fallback_provider.authenticate_fallback("testuser", "wrong_password")

                assert result is None

    @pytest.mark.asyncio
    async def test_create_emergency_token(self, fallback_provider):
        """Test emergency token creation."""
        with patch("app.core.auth_failover.get_cache") as mock_get_cache:
            mock_cache = AsyncMock()
            mock_get_cache.return_value = mock_cache

            token = await fallback_provider.create_emergency_token(
                user_id="emergency-user",
                permissions=["emergency.access"],
                duration=timedelta(hours=1),
                reason="system_recovery",
            )

            assert token is not None
            assert len(token) > 20

            # Verify token data
            token_data = await fallback_provider.validate_emergency_token(token)
            assert token_data is not None
            assert token_data["user_id"] == "emergency-user"
            assert token_data["reason"] == "system_recovery"

    @pytest.mark.asyncio
    async def test_emergency_token_expiration(self, fallback_provider):
        """Test emergency token expiration."""
        with patch("app.core.auth_failover.get_cache") as mock_get_cache:
            mock_cache = AsyncMock()
            mock_get_cache.return_value = mock_cache

            # Create token with past expiration
            token = "expired_token"
            fallback_provider._emergency_tokens[token] = {
                "user_id": "user",
                "permissions": [],
                "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
                "reason": "test",
            }

            # Should return None for expired token
            result = await fallback_provider.validate_emergency_token(token)
            assert result is None
            assert token not in fallback_provider._emergency_tokens

    @pytest.mark.asyncio
    async def test_authenticate_with_fallback_primary_fails(self):
        """Test authentication with fallback when primary fails."""

        async def failing_primary_auth(username, password):
            raise Exception("Database error")

        with patch("app.core.auth_failover.get_fallback_auth_provider") as mock_provider:
            provider = AsyncMock()
            provider.authenticate_fallback.return_value = {
                "id": "user-id",
                "username": "testuser",
                "email": "test@example.com",
            }
            mock_provider.return_value = provider

            # Should fall back to cached authentication
            result = await authenticate_with_fallback(
                "testuser",
                "password",
                primary_auth_func=failing_primary_auth,
            )

            assert result is not None
            assert result["username"] == "testuser"
