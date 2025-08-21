"""MFA Policy repository interface."""

import uuid
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Union

from app.models.mfa import MFAPolicy
from app.models.user import User

from .base import IBaseRepository


class IMfaPolicyRepository(IBaseRepository[MFAPolicy]):
    """Interface for MFA policy repository operations."""

    @abstractmethod
    async def get_by_name(
        self, name: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[MFAPolicy]:
        """
        Get MFA policy by name with optional organization filtering.

        Args:
            name: Policy name
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            MFA policy if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_active_policies(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[MFAPolicy]:
        """
        Get all active MFA policies ordered by priority.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of active MFA policies ordered by priority (highest first)
        """
        raise NotImplementedError

    @abstractmethod
    async def get_applicable_policies(
        self, user: User, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[MFAPolicy]:
        """
        Get all MFA policies applicable to a user based on conditions.

        Args:
            user: User to check policies for
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of applicable MFA policies ordered by priority
        """
        raise NotImplementedError

    @abstractmethod
    async def check_policy_conditions(
        self, policy_id: Union[str, uuid.UUID], user: User, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Check if a policy's conditions apply to a user.

        Args:
            policy_id: MFA policy ID
            user: User to check conditions for
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if policy conditions apply to user, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_policies_by_enforcement_level(
        self, enforcement_level: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[MFAPolicy]:
        """
        Get MFA policies by enforcement level.

        Args:
            enforcement_level: Enforcement level (required, recommended, optional)
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of MFA policies with specified enforcement level
        """
        raise NotImplementedError

    @abstractmethod
    async def get_policies_by_priority_range(
        self, min_priority: int, max_priority: int, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[MFAPolicy]:
        """
        Get MFA policies within a priority range.

        Args:
            min_priority: Minimum priority
            max_priority: Maximum priority
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of MFA policies within priority range
        """
        raise NotImplementedError

    @abstractmethod
    async def activate_policy(
        self,
        policy_id: Union[str, uuid.UUID],
        activated_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Activate an MFA policy.

        Args:
            policy_id: MFA policy ID
            activated_by: User who activated the policy
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if activation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def deactivate_policy(
        self,
        policy_id: Union[str, uuid.UUID],
        deactivated_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Deactivate an MFA policy.

        Args:
            policy_id: MFA policy ID
            deactivated_by: User who deactivated the policy
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if deactivation successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def update_policy_conditions(
        self,
        policy_id: Union[str, uuid.UUID],
        conditions: Dict[str, Any],
        updated_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update MFA policy conditions.

        Args:
            policy_id: MFA policy ID
            conditions: New policy conditions
            updated_by: User who updated the policy
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def update_policy_priority(
        self,
        policy_id: Union[str, uuid.UUID],
        priority: int,
        updated_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update MFA policy priority.

        Args:
            policy_id: MFA policy ID
            priority: New priority value
            updated_by: User who updated the policy
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_policy_usage_stats(
        self, policy_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Dict[str, Any]:
        """
        Get usage statistics for an MFA policy.

        Args:
            policy_id: MFA policy ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Dictionary containing policy usage statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def search_policies(
        self, query: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[MFAPolicy]:
        """
        Search MFA policies by name or description.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching MFA policies
        """
        raise NotImplementedError
