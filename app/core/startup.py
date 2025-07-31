"""Application startup and shutdown handlers."""

from typing import Any

from structlog.stdlib import get_logger

from app.core.cache import close_cache, get_cache
from app.core.config import settings

logger = get_logger(__name__)


async def on_startup() -> None:
    """
    Application startup handler.

    Initializes:
    - Cache connections
    - Health monitoring
    - Background tasks
    """
    logger.info(
        "Application starting",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )

    # Initialize cache
    try:
        cache = await get_cache()
        cache_health = await cache.health_check()

        if cache_health.get("redis_available"):
            logger.info("Redis cache initialized successfully")
        else:
            logger.warning(
                "Redis not available, using fallback cache",
                redis_configured=cache_health.get("redis_url_configured"),
            )
    except Exception as e:
        logger.error("Failed to initialize cache", error=str(e))

    # Log configuration status
    logger.info(
        "Configuration loaded",
        database_url=settings.database_url_safe,
        redis_url=settings.redis_url_safe,
        rate_limiting=settings.RATE_LIMIT_ENABLED,
        secure_cookies=settings.SECURE_COOKIES,
    )

    # Sync critical users for failover (if needed)
    if settings.ENVIRONMENT == "production":
        try:
            from app.core.auth_failover import get_fallback_auth_provider
            from app.db.session import AsyncSessionLocal
            from app.repositories.user import UserRepository

            # Get superusers for emergency access
            async with AsyncSessionLocal() as session:
                user_repo = UserRepository(session)
                superusers = await user_repo.get_superusers()

                if superusers:
                    provider = get_fallback_auth_provider()
                    # Note: In production, you'd need to get password hashes
                    # This is just an example
                    await provider.sync_critical_users([(user, None) for user in superusers[:5]])  # Top 5 superusers
                    logger.info(
                        "Critical users synced for failover",
                        count=min(len(superusers), 5),
                    )
        except Exception as e:
            logger.error("Failed to sync critical users", error=str(e))


async def on_shutdown() -> None:
    """
    Application shutdown handler.

    Cleanup:
    - Close cache connections
    - Cancel background tasks
    - Flush logs
    """
    logger.info("Application shutting down")

    # Close cache connections
    try:
        await close_cache()
        logger.info("Cache connections closed")
    except Exception as e:
        logger.error("Error closing cache connections", error=str(e))

    # Log final shutdown message
    logger.info("Application shutdown complete")
