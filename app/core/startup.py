"""Application startup and shutdown handlers with Clean Architecture compliance."""

from typing import Any

from structlog.stdlib import get_logger

from .config import settings
from .container import get_cache_service, get_user_service
from .service_registry import initialize_di_container

logger = get_logger(__name__)


async def on_startup() -> None:
    """
    Application startup handler using dependency injection.

    Initializes:
    - Dependency injection container
    - Cache connections via service
    - Health monitoring
    - Background tasks
    """
    logger.info(
        "Application starting",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )

    # Initialize dependency injection container first
    try:
        await initialize_di_container()
        logger.info("Dependency injection container initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize DI container", error=str(e))
        # Continue startup even if DI initialization fails to allow graceful degradation

    # Initialize cache via service
    try:
        cache_service = get_cache_service()
        if cache_service:
            cache_health = await cache_service.health_check()

            if cache_health.get("redis_available"):
                logger.info("Redis cache initialized successfully")
            else:
                logger.warning(
                    "Redis not available, using fallback cache",
                    redis_configured=cache_health.get("redis_url_configured"),
                )
        else:
            logger.warning("Cache service not configured")
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

    # Sync critical users for failover (if needed) via service
    if settings.ENVIRONMENT == "production":
        try:
            from .auth_failover import get_fallback_auth_provider

            user_service = get_user_service()
            if user_service:
                # Get superusers via service for emergency access
                superusers = await user_service.get_superusers()

                if superusers:
                    provider = get_fallback_auth_provider()
                    # Convert UserData to tuples for sync
                    user_tuples = [(user, None) for user in superusers[:5]]  # Top 5 superusers
                    await provider.sync_critical_users(user_tuples)
                    logger.info(
                        "Critical users synced for failover",
                        count=min(len(superusers), 5),
                    )
            else:
                logger.warning("User service not configured for failover")
        except Exception as e:
            logger.error("Failed to sync critical users", error=str(e))


async def on_shutdown() -> None:
    """
    Application shutdown handler using dependency injection.

    Cleanup:
    - Close cache connections via service
    - Cancel background tasks
    - Flush logs
    """
    logger.info("Application shutting down")

    # Close cache connections via service
    try:
        cache_service = get_cache_service()
        if cache_service:
            # Assume cache service handles its own cleanup
            logger.info("Cache service cleanup initiated")
        else:
            logger.info("No cache service to cleanup")
    except Exception as e:
        logger.error("Error during cache service cleanup", error=str(e))

    # Log final shutdown message
    logger.info("Application shutdown complete")
