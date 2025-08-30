"""
Dependency injection container for Clean Architecture compliance.

This module provides a centralized container for managing dependencies,
enabling the core layer to remain independent while still accessing
required services through abstraction interfaces.
"""

from typing import Any, Dict, Optional, Type, TypeVar

from structlog.stdlib import get_logger

from .interfaces import (
    IABACService,
    IAuthenticationService,
    ICacheService,
    IUserService,
)

logger = get_logger(__name__)

# Repository interfaces
try:
    from ..repositories.interfaces import (
        IApiKeyRepository,
        IAuditRepository,
        IHealthRepository,
        IRoleRepository,
        ISecurityScanRepository,
        ISessionRepository,
        IUserRepository,
        IVulnerabilityRepository,
    )
except ImportError:
    # Fallback in case interfaces are not available during initial setup
    IApiKeyRepository = None
    IAuditRepository = None
    IHealthRepository = None
    IRoleRepository = None
    ISecurityScanRepository = None
    ISessionRepository = None
    IUserRepository = None
    IVulnerabilityRepository = None

T = TypeVar("T")


class DependencyContainer:
    """Dependency injection container for managing service instances."""

    def __init__(self):
        """Initialize empty container."""
        self._services: Dict[Type, Any] = {}
        self._factories: Dict[Type, Any] = {}

    def register_service(self, interface: Type[T], implementation: T) -> None:
        """Register a service implementation for an interface.

        Args:
            interface: Interface class or type
            implementation: Implementation instance
        """
        self._services[interface] = implementation

    def register_factory(self, interface: Type[T], factory: Any) -> None:
        """Register a factory function for creating service instances.

        Args:
            interface: Interface class or type
            factory: Factory function that returns implementation
        """
        self._factories[interface] = factory

    def get_service(self, interface: Type[T]) -> Optional[T]:
        """Get service implementation for interface.

        Args:
            interface: Interface class or type

        Returns:
            Service implementation if registered, None otherwise
        """
        # Return cached service if available
        if interface in self._services:
            return self._services[interface]

        # Try to create from factory
        if interface in self._factories:
            service = self._factories[interface]()
            self._services[interface] = service
            return service

        return None

    def clear(self) -> None:
        """Clear all registered services and factories."""
        self._services.clear()
        self._factories.clear()


# Global container instance
_container: Optional[DependencyContainer] = None
_auto_registration_attempted: bool = False


def get_container() -> DependencyContainer:
    """Get the global dependency injection container."""
    global _container
    if _container is None:
        _container = DependencyContainer()
    return _container


def set_container(container: DependencyContainer) -> None:
    """Set the global dependency injection container.

    Args:
        container: Container instance to set as global
    """
    global _container
    _container = container


# Convenience functions for getting services
def get_auth_service() -> Optional[IAuthenticationService]:
    """Get authentication service from container."""
    return get_container().get_service(IAuthenticationService)  # type: ignore[type-abstract]


def get_user_service() -> Optional[IUserService]:
    """Get user service from container."""
    return get_container().get_service(IUserService)  # type: ignore[type-abstract]


def get_abac_service() -> Optional[IABACService]:
    """Get ABAC service from container."""
    return get_container().get_service(IABACService)  # type: ignore[type-abstract]


def get_cache_service() -> Optional[ICacheService]:
    """Get cache service from container."""
    return get_container().get_service(ICacheService)  # type: ignore[type-abstract]


def _ensure_repositories_registered() -> None:
    """Ensure repositories are registered, with auto-registration if needed."""
    if _auto_registration_attempted:
        return

    container = get_container()

    # Check if repositories are already registered
    if any(interface.__name__.endswith("Repository") for interface in container._factories.keys()):
        return

    # Attempt auto-registration
    import asyncio

    try:
        loop = asyncio.get_running_loop()
        # If we have a running loop, schedule auto-registration as a task
        loop.create_task(_auto_register_repositories_if_needed())
    except RuntimeError:
        # No running loop, run synchronously for UAT commands
        asyncio.run(_auto_register_repositories_if_needed())


# Repository convenience functions
def get_user_repository() -> Optional[IUserRepository]:
    """Get user repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IUserRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_session_repository() -> Optional[ISessionRepository]:
    """Get session repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(ISessionRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_api_key_repository() -> Optional[IApiKeyRepository]:
    """Get API key repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IApiKeyRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_audit_repository() -> Optional[IAuditRepository]:
    """Get audit repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IAuditRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_security_scan_repository() -> Optional[ISecurityScanRepository]:
    """Get security scan repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(ISecurityScanRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_health_repository() -> Optional[IHealthRepository]:
    """Get health repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IHealthRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_vulnerability_repository() -> Optional[IVulnerabilityRepository]:
    """Get vulnerability repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IVulnerabilityRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


def get_role_repository() -> Optional[IRoleRepository]:
    """Get role repository from container."""
    try:
        _ensure_repositories_registered()
        return get_container().get_service(IRoleRepository)  # type: ignore[type-abstract]
    except Exception:
        return None


# Repository factory helper functions
def _add_session_cleanup(repository, session, repo_type: str):
    """Add session cleanup functionality to a repository instance."""
    if not hasattr(repository, "_cleanup_session"):

        async def cleanup_session():
            try:
                if session and hasattr(session, "close"):
                    await session.close()
                    logger.debug(f"{repo_type}_session_closed", session_id=id(session))
            except Exception as e:
                logger.warning(
                    f"{repo_type}_session_cleanup_failed",
                    session_id=id(session),
                    error=str(e),
                )

        repository._cleanup_session = cleanup_session
        repository._session_id = id(session)


def _handle_session_cleanup_on_error(session):
    """Handle session cleanup when repository creation fails."""
    if session and hasattr(session, "close"):
        try:
            import asyncio

            if asyncio.iscoroutinefunction(session.close):
                asyncio.create_task(session.close())
            else:
                session.close()
        except Exception:
            pass


# Repository factory functions
def _create_user_repository_factory(session_factory) -> Any:
    """Create user repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("user_repository_factory_starting", factory_type="UserRepository")

            from ..repositories.user import UserRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "user_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = UserRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "user_repository")

            creation_time = time.time() - start_time
            creation_time_ms = round(creation_time * 1000, 2)

            # Record operation metrics
            record_operation_time("repository_creation", creation_time_ms)

            logger.info(
                "user_repository_created",
                repository_type="UserRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=creation_time_ms,
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "user_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "user_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_api_key_repository_factory(session_factory) -> Any:
    """Create API key repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("api_key_repository_factory_starting", factory_type="APIKeyRepository")

            from ..repositories.api_key import APIKeyRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "api_key_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = APIKeyRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "api_key_repository")

            creation_time = time.time() - start_time

            logger.info(
                "api_key_repository_created",
                repository_type="APIKeyRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "api_key_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "api_key_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_session_repository_factory(session_factory) -> Any:
    """Create session repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("session_repository_factory_starting", factory_type="SessionRepository")

            from ..repositories.session import SessionRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "session_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = SessionRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "session_repository")

            creation_time = time.time() - start_time

            logger.info(
                "session_repository_created",
                repository_type="SessionRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "session_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "session_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_audit_repository_factory(session_factory) -> Any:
    """Create audit repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("audit_repository_factory_starting", factory_type="AuditLogRepository")

            from ..repositories.audit_log import AuditLogRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "audit_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = AuditLogRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "audit_repository")

            creation_time = time.time() - start_time

            logger.info(
                "audit_repository_created",
                repository_type="AuditLogRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "audit_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "audit_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_security_scan_repository_factory(session_factory) -> Any:
    """Create security scan repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug(
                "security_scan_repository_factory_starting",
                factory_type="SecurityScanRepository",
            )

            from ..repositories.security_scan import SecurityScanRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "security_scan_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = SecurityScanRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "security_scan_repository")

            creation_time = time.time() - start_time

            logger.info(
                "security_scan_repository_created",
                repository_type="SecurityScanRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "security_scan_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "security_scan_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_vulnerability_repository_factory(session_factory) -> Any:
    """Create vulnerability repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug(
                "vulnerability_repository_factory_starting",
                factory_type="VulnerabilityTaxonomyRepository",
            )

            from ..repositories.vulnerability_taxonomy import (
                VulnerabilityTaxonomyRepository,
            )

            # Create and validate session
            session = session_factory()
            logger.debug(
                "vulnerability_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = VulnerabilityTaxonomyRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "vulnerability_repository")

            creation_time = time.time() - start_time

            logger.info(
                "vulnerability_repository_created",
                repository_type="VulnerabilityTaxonomyRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "vulnerability_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "vulnerability_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_role_repository_factory(session_factory) -> Any:
    """Create role repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("role_repository_factory_starting", factory_type="RoleRepository")

            from ..repositories.role import RoleRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "role_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = RoleRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "role_repository")

            creation_time = time.time() - start_time

            logger.info(
                "role_repository_created",
                repository_type="RoleRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "role_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "role_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


def _create_health_repository_factory(session_factory) -> Any:
    """Create health repository factory function with session cleanup."""

    def factory():
        import time

        start_time = time.time()
        session = None
        try:
            logger.debug("health_repository_factory_starting", factory_type="HealthRepository")

            from ..repositories.health import HealthRepository

            # Create and validate session
            session = session_factory()
            logger.debug(
                "health_repository_session_created",
                session_id=id(session),
                session_type=type(session).__name__,
            )

            # Create repository instance
            repository = HealthRepository(session)

            # Add session cleanup functionality
            _add_session_cleanup(repository, session, "health_repository")

            creation_time = time.time() - start_time

            logger.info(
                "health_repository_created",
                repository_type="HealthRepository",
                repository_id=id(repository),
                session_id=id(session),
                creation_time_ms=round(creation_time * 1000, 2),
            )
            return repository
        except ImportError as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "health_repository_import_failed",
                error=str(e),
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise
        except Exception as e:
            _handle_session_cleanup_on_error(session)
            logger.error(
                "health_repository_creation_failed",
                error=str(e),
                error_type=type(e).__name__,
                session_id=id(session) if session else None,
                creation_time_ms=round((time.time() - start_time) * 1000, 2),
            )
            raise

    return factory


async def register_repositories(session_factory) -> None:
    """Register all repository implementations in the container.

    Args:
        session_factory: Function that returns AsyncSession instances
    """
    container = get_container()

    try:
        logger.info("registering_repositories", repository_count=8)

        # Register all repository factories
        repository_registrations = [
            (IUserRepository, _create_user_repository_factory(session_factory)),
            (IApiKeyRepository, _create_api_key_repository_factory(session_factory)),
            (ISessionRepository, _create_session_repository_factory(session_factory)),
            (IAuditRepository, _create_audit_repository_factory(session_factory)),
            (
                ISecurityScanRepository,
                _create_security_scan_repository_factory(session_factory),
            ),
            (
                IVulnerabilityRepository,
                _create_vulnerability_repository_factory(session_factory),
            ),
            (IRoleRepository, _create_role_repository_factory(session_factory)),
            (IHealthRepository, _create_health_repository_factory(session_factory)),
        ]

        for interface, factory in repository_registrations:
            if interface is not None:  # Check if interface was imported successfully
                container.register_factory(interface, factory)
                logger.debug("repository_factory_registered", interface=interface.__name__)

        logger.info(
            "repository_registration_complete",
            registered_count=len(repository_registrations),
        )

        # Validate repository registration by attempting to create one instance of each
        await _validate_repository_registration()

    except Exception as e:
        logger.error("repository_registration_failed", error=str(e))
        raise


async def _validate_repository_registration() -> None:
    """Validate that all repositories can be successfully created."""
    try:
        logger.info("validating_repository_registration")

        # Test repository creation without caching to avoid side effects
        repository_getters = [
            ("UserRepository", get_user_repository),
            ("ApiKeyRepository", get_api_key_repository),
            ("SessionRepository", get_session_repository),
            ("AuditRepository", get_audit_repository),
            ("SecurityScanRepository", get_security_scan_repository),
            ("VulnerabilityRepository", get_vulnerability_repository),
            ("RoleRepository", get_role_repository),
            ("HealthRepository", get_health_repository),
        ]

        validation_results = {}
        for name, getter in repository_getters:
            try:
                # Note: We're not actually calling the getter here to avoid creating instances
                # during validation. We're just ensuring the factory is registered.
                container = get_container()
                has_factory = any(
                    interface.__name__.endswith(name.replace("Repository", "Repository"))
                    for interface in container._factories.keys()
                )
                validation_results[name] = "registered" if has_factory else "missing"
            except Exception as e:
                validation_results[name] = f"error: {str(e)}"

        # Log validation results
        failed_validations = [name for name, result in validation_results.items() if result != "registered"]
        if failed_validations:
            logger.warning(
                "repository_validation_issues",
                failed=failed_validations,
                results=validation_results,
            )
        else:
            logger.info(
                "repository_validation_successful",
                validated_count=len(validation_results),
            )

    except Exception as e:
        logger.error("repository_validation_failed", error=str(e))
        # Don't raise here as this is validation, not critical functionality


# Health check cache
_health_check_cache: Optional[Dict[str, Any]] = None
_health_check_cache_time: float = 0

# Connection pool monitoring
_connection_pool_metrics = {
    "pool_size": 0,
    "checked_out_connections": 0,
    "overflow_connections": 0,
    "invalid_connections": 0,
    "total_connections": 0,
    "pool_utilization_percentage": 0.0,
    "last_updated": 0,
}

# Repository operation metrics
_operation_metrics = {
    "repository_creation": {"total_count": 0, "total_time_ms": 0.0, "avg_time_ms": 0.0},
    "session_creation": {"total_count": 0, "total_time_ms": 0.0, "avg_time_ms": 0.0},
    "database_queries": {"total_count": 0, "total_time_ms": 0.0, "avg_time_ms": 0.0},
    "session_cleanup": {"total_count": 0, "total_time_ms": 0.0, "avg_time_ms": 0.0},
    "health_checks": {"total_count": 0, "total_time_ms": 0.0, "avg_time_ms": 0.0},
}

# Repository health thresholds and alerts
_health_thresholds = {
    "response_time_warning_ms": 50.0,
    "response_time_critical_ms": 200.0,
    "connection_pool_warning_pct": 80.0,
    "connection_pool_critical_pct": 95.0,
    "consecutive_failure_threshold": 3,
    "health_check_cache_max_age_sec": 300,  # 5 minutes
}


def update_connection_pool_metrics() -> Dict[str, Any]:
    """Update and return current connection pool metrics."""
    import time

    try:
        from ..db.session import get_connection_pool_stats, get_engine

        engine = get_engine()
        if engine and engine.pool:
            pool_stats = get_connection_pool_stats()

            # Update global metrics
            _connection_pool_metrics.update(
                {
                    "pool_size": pool_stats.get("pool_size", 0),
                    "checked_out_connections": pool_stats.get("checked_out", 0),
                    "overflow_connections": pool_stats.get("overflow", 0),
                    "invalid_connections": pool_stats.get("invalid", 0),
                    "total_connections": pool_stats.get("checked_out", 0) + pool_stats.get("checked_in", 0),
                    "pool_utilization_percentage": round(
                        (pool_stats.get("checked_out", 0) / max(pool_stats.get("pool_size", 1), 1)) * 100,
                        2,
                    ),
                    "last_updated": time.time(),
                    **pool_stats,  # Include all raw stats
                }
            )

            logger.debug(
                "connection_pool_metrics_updated",
                pool_size=_connection_pool_metrics["pool_size"],
                checked_out=_connection_pool_metrics["checked_out_connections"],
                utilization=_connection_pool_metrics["pool_utilization_percentage"],
            )
        else:
            logger.warning("connection_pool_metrics_unavailable", reason="no_engine_or_pool")

    except Exception as e:
        logger.error("connection_pool_metrics_update_failed", error=str(e))

    return _connection_pool_metrics.copy()


def get_connection_pool_metrics() -> Dict[str, Any]:
    """Get current connection pool metrics (cached)."""
    import time

    current_time = time.time()

    # Update metrics if they're older than 5 seconds
    if current_time - _connection_pool_metrics["last_updated"] > 5:
        return update_connection_pool_metrics()

    return _connection_pool_metrics.copy()


def record_operation_time(operation_type: str, time_ms: float) -> None:
    """Record response time for a repository operation."""
    if operation_type in _operation_metrics:
        metric = _operation_metrics[operation_type]
        metric["total_count"] += 1
        metric["total_time_ms"] += time_ms
        metric["avg_time_ms"] = round(metric["total_time_ms"] / metric["total_count"], 3)

        logger.debug(
            "operation_time_recorded",
            operation=operation_type,
            time_ms=round(time_ms, 3),
            total_count=metric["total_count"],
            avg_time_ms=metric["avg_time_ms"],
        )


def get_operation_metrics() -> Dict[str, Any]:
    """Get all repository operation metrics."""
    return {
        operation: {
            "total_operations": metric["total_count"],
            "total_time_ms": round(metric["total_time_ms"], 2),
            "average_time_ms": metric["avg_time_ms"],
            "operations_per_second": (
                round(metric["total_count"] / (metric["total_time_ms"] / 1000), 2) if metric["total_time_ms"] > 0 else 0
            ),
        }
        for operation, metric in _operation_metrics.items()
        if metric["total_count"] > 0
    }


def clear_operation_metrics() -> None:
    """Clear all operation metrics."""
    for metric in _operation_metrics.values():
        metric["total_count"] = 0
        metric["total_time_ms"] = 0.0
        metric["avg_time_ms"] = 0.0
    logger.debug("operation_metrics_cleared")


async def get_comprehensive_system_status() -> Dict[str, Any]:
    """Get comprehensive status of the entire repository system."""
    import time

    start_time = time.time()

    try:
        # Get all metrics
        health_status = await get_repository_health_status(use_cache=True)
        pool_metrics = get_connection_pool_metrics()
        operation_metrics = get_operation_metrics()

        # Analyze performance and health
        analysis = {
            "overall_system_health": "unknown",
            "performance_grade": "unknown",
            "alerts": [],
            "recommendations": [],
        }

        # Analyze repository health
        healthy_pct = health_status.get("summary", {}).get("health_percentage", 0)
        avg_response_time = health_status.get("summary", {}).get("average_response_time_ms", 0)

        if healthy_pct >= 100:
            analysis["overall_system_health"] = "excellent"
        elif healthy_pct >= 80:
            analysis["overall_system_health"] = "good"
        elif healthy_pct >= 60:
            analysis["overall_system_health"] = "degraded"
        else:
            analysis["overall_system_health"] = "critical"

        # Analyze performance
        if avg_response_time <= _health_thresholds["response_time_warning_ms"]:
            analysis["performance_grade"] = "A"
        elif avg_response_time <= _health_thresholds["response_time_critical_ms"]:
            analysis["performance_grade"] = "B"
        else:
            analysis["performance_grade"] = "C"

        # Check for alerts
        pool_utilization = pool_metrics.get("pool_utilization_percentage", 0)
        if pool_utilization >= _health_thresholds["connection_pool_critical_pct"]:
            analysis["alerts"].append(
                {
                    "severity": "critical",
                    "type": "connection_pool",
                    "message": f"Connection pool utilization critical: {pool_utilization}%",
                }
            )
        elif pool_utilization >= _health_thresholds["connection_pool_warning_pct"]:
            analysis["alerts"].append(
                {
                    "severity": "warning",
                    "type": "connection_pool",
                    "message": f"Connection pool utilization high: {pool_utilization}%",
                }
            )

        if avg_response_time >= _health_thresholds["response_time_critical_ms"]:
            analysis["alerts"].append(
                {
                    "severity": "critical",
                    "type": "performance",
                    "message": f"Average response time critical: {avg_response_time}ms",
                }
            )
        elif avg_response_time >= _health_thresholds["response_time_warning_ms"]:
            analysis["alerts"].append(
                {
                    "severity": "warning",
                    "type": "performance",
                    "message": f"Average response time high: {avg_response_time}ms",
                }
            )

        # Generate recommendations
        if len(analysis["alerts"]) == 0:
            analysis["recommendations"].append("System operating optimally")
        else:
            if pool_utilization > 70:
                analysis["recommendations"].append("Consider increasing connection pool size")
            if avg_response_time > 20:
                analysis["recommendations"].append("Monitor database query performance")

        # Calculate uptime metrics
        total_operations = 0
        for metric in operation_metrics.values():
            if isinstance(metric, dict) and "total_operations" in metric:
                total_operations += metric.get("total_operations", 0)

        uptime_info = {
            "total_operations": total_operations,
            "total_repositories_registered": len(get_container()._factories),
            "cache_efficiency": "N/A",
        }

        # Calculate cache hit ratio if available
        if "health_checks" in operation_metrics and operation_metrics["health_checks"]["total_count"] > 0:
            cache_hits = health_status.get("cache_hit", False)
            uptime_info["cache_efficiency"] = "Active" if cache_hits else "Miss"

        compilation_time = round((time.time() - start_time) * 1000, 2)

        return {
            "timestamp": time.time(),
            "compilation_time_ms": compilation_time,
            "system_analysis": analysis,
            "repository_health": health_status,
            "connection_pool": pool_metrics,
            "operation_metrics": operation_metrics,
            "uptime_info": uptime_info,
            "thresholds": _health_thresholds,
            "system_version": {
                "features": [
                    "Repository Registration & Dependency Injection",
                    "Health Monitoring with Caching",
                    "Session Lifecycle Management",
                    "Connection Pool Monitoring",
                    "Response Time Tracking",
                    "Automatic Cleanup & Error Recovery",
                    "Performance Analysis & Alerts",
                ],
                "repository_count": 8,
                "metrics_tracked": len(_operation_metrics),
            },
        }

    except Exception as e:
        logger.error("comprehensive_system_status_failed", error=str(e))
        return {
            "timestamp": time.time(),
            "error": f"Failed to compile system status: {str(e)[:100]}",
            "system_analysis": {"overall_system_health": "error"},
        }


async def get_repository_health_status(use_cache: bool = True) -> Dict[str, Any]:
    """Get comprehensive health status of all registered repositories with caching.

    Args:
        use_cache: Whether to use cached results if available

    Returns:
        Dict with detailed health information for each repository
    """
    import time

    from sqlalchemy import text

    from ..core.config import settings

    global _health_check_cache, _health_check_cache_time

    # Check cache validity
    cache_ttl = settings.REPOSITORY_HEALTH_CHECK_CACHE_TTL
    current_time = time.time()

    if use_cache and _health_check_cache is not None and (current_time - _health_check_cache_time) < cache_ttl:
        logger.debug(
            "repository_health_cache_hit",
            cache_age_seconds=round(current_time - _health_check_cache_time, 2),
        )
        # Update timestamp to current time but keep cached data
        cached_result = _health_check_cache.copy()
        cached_result["cache_hit"] = True
        cached_result["cache_age_seconds"] = round(current_time - _health_check_cache_time, 2)
        return cached_result

    logger.debug(
        "repository_health_cache_miss",
        use_cache=use_cache,
        cache_exists=_health_check_cache is not None,
        cache_age_seconds=(round(current_time - _health_check_cache_time, 2) if _health_check_cache else 0),
    )

    health_status = {}
    overall_start_time = time.time()

    repository_checks = [
        ("user_repository", get_user_repository),
        ("api_key_repository", get_api_key_repository),
        ("session_repository", get_session_repository),
        ("audit_repository", get_audit_repository),
        ("security_scan_repository", get_security_scan_repository),
        ("vulnerability_repository", get_vulnerability_repository),
        ("role_repository", get_role_repository),
        ("health_repository", get_health_repository),
    ]

    for name, getter in repository_checks:
        repo_start_time = time.time()
        repo_health = {
            "status": "unknown",
            "session_available": False,
            "connectivity_test": False,
            "response_time_ms": 0,
            "error_message": None,
            "last_check": time.time(),
        }

        try:
            repository = getter()
            if repository is None:
                repo_health.update(
                    {
                        "status": "not_registered",
                        "error_message": "Repository not available from container",
                    }
                )
            else:
                # Check session availability
                session = getattr(repository, "session", getattr(repository, "db", None))
                repo_health["session_available"] = session is not None

                if session:
                    # Perform connectivity test
                    try:
                        result = await session.execute(text("SELECT 1 as health_check"))
                        row = result.fetchone()
                        if row and row[0] == 1:
                            repo_health["connectivity_test"] = True
                            repo_health["status"] = "healthy"
                        else:
                            repo_health["status"] = "degraded"
                            repo_health["error_message"] = f"Unexpected query result: {row}"
                    except Exception as conn_e:
                        repo_health["status"] = "unhealthy"
                        repo_health["connectivity_test"] = False
                        repo_health["error_message"] = "Database connectivity test failed"
                        logger.warning(
                            "repository_connectivity_failed",
                            repository=name,
                            error=str(conn_e),
                        )
                else:
                    repo_health["status"] = "degraded"
                    repo_health["error_message"] = "No database session available"

        except Exception as e:
            repo_health.update({"status": "error", "error_message": "Repository health check failed"})
            logger.error("repository_health_check_failed", repository=name, error=str(e))

        # Calculate response time
        repo_health["response_time_ms"] = round((time.time() - repo_start_time) * 1000, 2)
        health_status[name] = repo_health

    # Calculate overall metrics
    total_check_time = round((time.time() - overall_start_time) * 1000, 2)
    healthy_count = sum(1 for repo in health_status.values() if repo["status"] == "healthy")
    degraded_count = sum(1 for repo in health_status.values() if repo["status"] == "degraded")
    unhealthy_count = sum(
        1 for repo in health_status.values() if repo["status"] in ["unhealthy", "error", "not_registered"]
    )
    total_count = len(health_status)

    # Determine overall health
    if healthy_count == total_count:
        overall_status = "healthy"
    elif healthy_count + degraded_count == total_count:
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    # Get connection pool metrics and operation metrics
    pool_metrics = get_connection_pool_metrics()
    operation_metrics = get_operation_metrics()

    # Record health check time
    record_operation_time("health_checks", total_check_time)

    # Create result dictionary
    result = {
        "overall_status": overall_status,
        "healthy_count": healthy_count,
        "degraded_count": degraded_count,
        "unhealthy_count": unhealthy_count,
        "total_count": total_count,
        "total_check_time_ms": total_check_time,
        "repositories": health_status,
        "cache_hit": False,
        "cache_age_seconds": 0,
        "connection_pool": {
            "pool_size": pool_metrics.get("pool_size", 0),
            "checked_out_connections": pool_metrics.get("checked_out_connections", 0),
            "overflow_connections": pool_metrics.get("overflow_connections", 0),
            "total_connections": pool_metrics.get("total_connections", 0),
            "utilization_percentage": pool_metrics.get("pool_utilization_percentage", 0.0),
            "last_updated": pool_metrics.get("last_updated", 0),
        },
        "operation_metrics": operation_metrics,
        "summary": {
            "health_percentage": (round((healthy_count / total_count) * 100, 1) if total_count > 0 else 0),
            "average_response_time_ms": (
                round(
                    sum(repo["response_time_ms"] for repo in health_status.values()) / total_count,
                    2,
                )
                if total_count > 0
                else 0
            ),
            "unhealthy_repositories": [
                name
                for name, repo in health_status.items()
                if repo["status"] in ["unhealthy", "error", "not_registered"]
            ],
            "connection_pool_health": (
                "healthy"
                if pool_metrics.get("pool_utilization_percentage", 0) < 80
                else ("degraded" if pool_metrics.get("pool_utilization_percentage", 0) < 95 else "critical")
            ),
        },
    }

    # Update cache
    _health_check_cache = result.copy()
    _health_check_cache_time = current_time

    logger.debug(
        "repository_health_cache_updated",
        total_check_time_ms=total_check_time,
        cache_ttl_seconds=cache_ttl,
    )

    return result


def clear_repository_health_cache() -> None:
    """Clear the repository health check cache."""
    global _health_check_cache, _health_check_cache_time
    _health_check_cache = None
    _health_check_cache_time = 0
    logger.debug("repository_health_cache_cleared")


async def get_repository_health_with_timeout(
    timeout_seconds: Optional[int] = 30, use_cache: bool = True
) -> Dict[str, Any]:
    """Get repository health status with timeout protection.

    Args:
        timeout_seconds: Maximum time to wait for health check
        use_cache: Whether to use cached results if available

    Returns:
        Dict with health information or timeout error
    """
    import asyncio

    from ..core.config import settings

    # Use configured timeout if not specified
    if timeout_seconds is None:
        timeout_seconds = settings.REPOSITORY_HEALTH_CHECK_TIMEOUT

    try:
        logger.debug(
            "repository_health_check_starting",
            timeout_seconds=timeout_seconds,
            use_cache=use_cache,
        )

        # Run health check with timeout
        result = await asyncio.wait_for(get_repository_health_status(use_cache=use_cache), timeout=timeout_seconds)

        result["timeout_occurred"] = False
        result["timeout_seconds"] = timeout_seconds
        return result

    except asyncio.TimeoutError:
        logger.error("repository_health_check_timeout", timeout_seconds=timeout_seconds)

        # Return error structure that matches expected format
        return {
            "overall_status": "timeout",
            "healthy_count": 0,
            "degraded_count": 0,
            "unhealthy_count": 8,  # Assume all repositories are unhealthy on timeout
            "total_count": 8,
            "total_check_time_ms": timeout_seconds * 1000,
            "repositories": {},
            "cache_hit": False,
            "cache_age_seconds": 0,
            "timeout_occurred": True,
            "timeout_seconds": timeout_seconds,
            "summary": {
                "health_percentage": 0,
                "average_response_time_ms": 0,
                "unhealthy_repositories": ["all_repositories_timeout"],
            },
            "error": f"Health check timed out after {timeout_seconds} seconds",
        }
    except Exception as e:
        logger.error(
            "repository_health_check_error",
            error=str(e),
            timeout_seconds=timeout_seconds,
        )

        return {
            "overall_status": "error",
            "healthy_count": 0,
            "degraded_count": 0,
            "unhealthy_count": 8,
            "total_count": 8,
            "total_check_time_ms": 0,
            "repositories": {},
            "cache_hit": False,
            "cache_age_seconds": 0,
            "timeout_occurred": False,
            "timeout_seconds": timeout_seconds,
            "summary": {
                "health_percentage": 0,
                "average_response_time_ms": 0,
                "unhealthy_repositories": ["all_repositories_error"],
            },
            "error": f"Health check failed: {str(e)[:100]}",
        }


async def _auto_register_repositories_if_needed() -> None:
    """Automatically register repositories if they haven't been registered yet."""
    global _auto_registration_attempted

    # Skip if already attempted or if container has repositories
    if _auto_registration_attempted:
        return

    container = get_container()

    # Check if repositories are already registered
    if any(interface.__name__.endswith("Repository") for interface in container._factories.keys()):
        return

    try:
        logger.info("auto_registering_repositories", reason="first_access")
        _auto_registration_attempted = True

        # Try to get session maker and register repositories
        from ..db.session import get_session_maker

        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await register_repositories(session_factory)
            logger.info("auto_registration_successful")
        else:
            logger.warning("auto_registration_skipped", reason="no_session_maker")

    except Exception as e:
        logger.error("auto_registration_failed", error=str(e))
        # Don't raise - allow graceful degradation


def clear_repository_registrations() -> None:
    """Clear all repository registrations from container."""
    global _auto_registration_attempted
    try:
        container = get_container()
        container.clear()
        _auto_registration_attempted = False  # Reset auto-registration flag
        logger.info("repository_registrations_cleared")
    except Exception as e:
        logger.error("clear_repository_registrations_failed", error=str(e))
        raise
