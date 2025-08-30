"""Core interfaces for dependency injection and abstraction."""

from .abac_interface import IABACService
from .auth_interface import IAuthenticationService
from .cache_interface import ICacheService
from .user_interface import IUserService

__all__ = [
    "IAuthenticationService",
    "IUserService",
    "IABACService",
    "ICacheService",
]
