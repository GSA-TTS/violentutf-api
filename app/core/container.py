"""
Dependency injection container for Clean Architecture compliance.

This module provides a centralized container for managing dependencies,
enabling the core layer to remain independent while still accessing
required services through abstraction interfaces.
"""

from typing import Any, Dict, Optional, Type, TypeVar

from .interfaces import (
    IABACService,
    IAuthenticationService,
    ICacheService,
    IUserService,
)

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
