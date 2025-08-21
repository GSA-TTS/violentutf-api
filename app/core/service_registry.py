"""
Service registry for dependency injection container initialization.

This module is responsible for registering concrete service implementations
with the dependency injection container, ensuring proper Clean Architecture
compliance by maintaining the separation between interfaces and implementations.
"""

from typing import Optional

from structlog.stdlib import get_logger

from app.core.interfaces import (
    IABACService,
    IAuthenticationService,
    ICacheService,
    IUserService,
)
from app.services.abac_service_impl import ABACServiceImpl
from app.services.authentication_service import AuthenticationService
from app.services.cache_service_impl import CacheServiceImpl
from app.services.user_service_impl import UserServiceImpl

from .container import DependencyContainer, get_container

logger = get_logger(__name__)


async def register_services(container: Optional[DependencyContainer] = None) -> None:
    """Register all service implementations in the DI container.

    This function creates instances of all concrete service implementations
    and registers them with their corresponding interfaces in the DI container.

    Args:
        container: Optional container instance. Uses global container if None.
    """
    if container is None:
        container = get_container()

    logger.info("Starting service registration for DI container")

    try:
        # Register Cache Service (no dependencies)
        cache_service = CacheServiceImpl()
        container.register_service(ICacheService, cache_service)  # type: ignore[type-abstract]
        logger.debug("Registered ICacheService with CacheServiceImpl")

        # Register Authentication Service (no DB dependencies)
        auth_service = AuthenticationService()
        container.register_service(IAuthenticationService, auth_service)  # type: ignore[type-abstract]
        logger.debug("Registered IAuthenticationService with AuthenticationService")

        # Register session-dependent services using async session creation
        try:
            from app.db.session import _create_database_session

            # Create database sessions for service registration
            user_session = await _create_database_session()
            user_service = UserServiceImpl(user_session)
            container.register_service(IUserService, user_service)  # type: ignore[type-abstract]
            logger.debug("Registered IUserService with UserServiceImpl")

            abac_session = await _create_database_session()
            abac_service = ABACServiceImpl(abac_session)
            container.register_service(IABACService, abac_service)  # type: ignore[type-abstract]
            logger.debug("Registered IABACService with ABACServiceImpl")

        except Exception as e:
            logger.warning(
                "Failed to register database-dependent services", error=str(e), fallback="Services will return None"
            )
            # Register None for these services so they don't crash when requested
            # This allows the app to start even if database is not available
            container.register_service(IUserService, None)
            container.register_service(IABACService, None)

        logger.info(
            "Service registration completed",
            registered=["ICacheService", "IAuthenticationService", "IUserService", "IABACService"],
        )

    except Exception as e:
        logger.error("Failed to register services", error=str(e))
        raise


def create_user_service_with_session(session) -> IUserService:
    """Create UserService instance with database session.

    Args:
        session: Database session (AsyncSession)

    Returns:
        UserService instance
    """
    return UserServiceImpl(session)


def create_abac_service_with_session(session) -> IABACService:
    """Create ABACService instance with database session.

    Args:
        session: Database session (AsyncSession)

    Returns:
        ABACService instance
    """
    return ABACServiceImpl(session)


async def initialize_di_container() -> None:
    """Initialize the dependency injection container with all services.

    This is the main entry point for setting up the DI container.
    Should be called during application startup.
    """
    logger.info("Initializing dependency injection container")

    try:
        await register_services()
        logger.info("Dependency injection container initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize DI container", error=str(e))
        raise


def clear_di_container() -> None:
    """Clear all services from the DI container.

    Useful for testing or cleanup scenarios.
    """
    container = get_container()
    container.clear()
    logger.info("Dependency injection container cleared")
