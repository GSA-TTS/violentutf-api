"""ABAC service interface for dependency injection."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple


class PermissionContext(dict):
    """Permission evaluation context.

    A specialized dictionary for holding permission evaluation context data.
    Provides convenient access to attributes used during ABAC policy evaluation.
    """

    def __init__(self, **kwargs: Any):
        """Initialize permission context with provided attributes.

        Args:
            **kwargs: Context attributes as key-value pairs
        """
        super().__init__(**kwargs)

    def get_subject_attribute(self, key: str, default: Any = None) -> Any:
        """Get subject-related attribute.

        Args:
            key: Attribute key
            default: Default value if key not found

        Returns:
            Attribute value or default
        """
        return self.get(f"subject.{key}", default)

    def get_resource_attribute(self, key: str, default: Any = None) -> Any:
        """Get resource-related attribute.

        Args:
            key: Attribute key
            default: Default value if key not found

        Returns:
            Attribute value or default
        """
        return self.get(f"resource.{key}", default)

    def get_action_attribute(self, key: str, default: Any = None) -> Any:
        """Get action-related attribute.

        Args:
            key: Attribute key
            default: Default value if key not found

        Returns:
            Attribute value or default
        """
        return self.get(f"action.{key}", default)

    def get_environment_attribute(self, key: str, default: Any = None) -> Any:
        """Get environment-related attribute.

        Args:
            key: Attribute key
            default: Default value if key not found

        Returns:
            Attribute value or default
        """
        return self.get(f"environment.{key}", default)


class IUserPermissionProvider(ABC):
    """Abstract interface for user permission providers."""

    @abstractmethod
    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get effective permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            Set of permission strings
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get roles for a user.

        Args:
            user_id: User identifier

        Returns:
            List of role names
        """
        raise NotImplementedError


class IABACService(ABC):
    """Abstract interface for ABAC services."""

    @abstractmethod
    async def check_permission(
        self,
        subject_id: str,
        resource_type: str,
        action: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Check if subject has permission for action on resource.

        Args:
            subject_id: ID of the user making the request
            resource_type: Type of resource being accessed
            action: Action being performed
            organization_id: Organization context
            resource_id: Specific resource ID
            resource_owner_id: Owner of the resource
            context: Additional context

        Returns:
            Tuple of (is_allowed, reason)
        """
        raise NotImplementedError

    @abstractmethod
    async def explain_decision(
        self,
        subject_id: str,
        resource_type: str,
        action: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get detailed explanation of access decision.

        Args:
            subject_id: ID of the user making the request
            resource_type: Type of resource being accessed
            action: Action being performed
            organization_id: Organization context
            resource_id: Specific resource ID
            resource_owner_id: Owner of the resource
            context: Additional context

        Returns:
            Detailed explanation dictionary
        """
        raise NotImplementedError
