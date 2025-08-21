"""MFA Policy repository implementation."""

import json
import uuid
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ..models.mfa import MFAPolicy
from ..models.user import User
from .base import BaseRepository
from .interfaces.mfa_policy import IMfaPolicyRepository

logger = get_logger(__name__)


class MfaPolicyRepository(BaseRepository[MFAPolicy], IMfaPolicyRepository):
    """
    MFA Policy repository implementation.

    Provides data access methods for MFA policies following the repository pattern.
    """

    def __init__(self, session: AsyncSession):
        """Initialize MFA policy repository."""
        super().__init__(session, MFAPolicy)

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
        try:
            # Build filters for name (MFAPolicy doesn't have soft delete)
            filters = [self.model.name == name]

            # Add organization filtering if provided and model supports it
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(self.model.organization_id == str(organization_id))

            query = select(self.model).where(and_(*filters))
            result = await self.session.execute(query)
            policy = result.scalar_one_or_none()

            if policy:
                self.logger.debug("MFA policy found by name", policy_name=name)
            else:
                self.logger.debug("MFA policy not found by name", policy_name=name)

            return policy

        except Exception as e:
            self.logger.error("Failed to get MFA policy by name", policy_name=name, error=str(e))
            raise

    async def get_active_policies(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> List[MFAPolicy]:
        """
        Get all active MFA policies ordered by priority.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of active MFA policies ordered by priority (highest first)
        """
        try:
            # Build filters for active (MFAPolicy doesn't have soft delete)
            filters = [self.model.is_active == True]  # noqa: E712

            # Add organization filtering if provided and model supports it
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(self.model.organization_id == str(organization_id))

            query = select(self.model).where(and_(*filters)).order_by(desc(self.model.priority))
            result = await self.session.execute(query)
            policies = list(result.scalars().all())

            self.logger.debug("Retrieved active MFA policies", count=len(policies))
            return policies

        except Exception as e:
            self.logger.error("Failed to get active MFA policies", error=str(e))
            raise

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
        try:
            # Get all active policies
            policies = await self.get_active_policies(organization_id)

            # Filter policies based on conditions
            applicable_policies = []
            for policy in policies:
                if await self._check_policy_conditions(policy, user):
                    applicable_policies.append(policy)

            self.logger.debug("Retrieved applicable MFA policies", user_id=str(user.id), count=len(applicable_policies))
            return applicable_policies

        except Exception as e:
            self.logger.error("Failed to get applicable MFA policies", user_id=str(user.id), error=str(e))
            raise

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
        try:
            policy = await self.get_by_id(policy_id, organization_id)
            if not policy:
                self.logger.warning("Policy not found for condition check", policy_id=str(policy_id))
                return False

            return await self._check_policy_conditions(policy, user)

        except Exception as e:
            self.logger.error(
                "Failed to check policy conditions", policy_id=str(policy_id), user_id=str(user.id), error=str(e)
            )
            raise

    async def _check_policy_conditions(self, policy: MFAPolicy, user: User) -> bool:
        """
        Internal method to check if a policy's conditions apply to a user.

        Args:
            policy: MFA policy to check
            user: User to check conditions for

        Returns:
            True if policy conditions apply to user, False otherwise
        """
        try:
            conditions = json.loads(policy.conditions)
        except json.JSONDecodeError:
            self.logger.error("Invalid policy conditions JSON", policy_id=str(policy.id))
            return False

        # Check role conditions
        if "roles" in conditions:
            required_roles = conditions["roles"]
            if isinstance(required_roles, list):
                # User must have at least one of the required roles
                user_roles = user.roles or []
                if not any(role in user_roles for role in required_roles):
                    return False

        # Check permission conditions
        if "permissions" in conditions:
            required_permissions = conditions["permissions"]
            if isinstance(required_permissions, list):
                # Check if user has required permissions through roles
                user_permissions = await self._get_user_permissions(user)
                if not any(perm in user_permissions for perm in required_permissions):
                    return False

        # Check organization conditions
        if "organization_ids" in conditions:
            org_ids = conditions["organization_ids"]
            if isinstance(org_ids, list) and hasattr(user, "organization_id") and user.organization_id:
                if str(user.organization_id) not in org_ids:
                    return False

        # Check user type conditions
        if "is_superuser" in conditions:
            if conditions["is_superuser"] != user.is_superuser:
                return False

        # Check account age conditions
        if "min_account_age_days" in conditions:
            from datetime import datetime, timezone

            min_age = conditions["min_account_age_days"]
            account_age = datetime.now(timezone.utc) - user.created_at
            if account_age.days < min_age:
                return False

        # All conditions passed
        return True

    async def _get_user_permissions(self, user: User) -> List[str]:
        """
        Get all permissions for a user through their roles.

        Args:
            user: User to get permissions for

        Returns:
            List of permission strings
        """
        # This would integrate with the RBAC system
        # For now, return empty list (matching the service implementation)
        return []

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
        try:
            # Build filters (MFAPolicy doesn't have soft delete)
            filters = [self.model.enforcement_level == enforcement_level]

            # Add organization filtering if provided and model supports it
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(self.model.organization_id == str(organization_id))

            query = select(self.model).where(and_(*filters)).order_by(desc(self.model.priority))
            result = await self.session.execute(query)
            policies = list(result.scalars().all())

            self.logger.debug(
                "Retrieved policies by enforcement level", enforcement_level=enforcement_level, count=len(policies)
            )
            return policies

        except Exception as e:
            self.logger.error(
                "Failed to get policies by enforcement level", enforcement_level=enforcement_level, error=str(e)
            )
            raise

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
        try:
            # Build filters (MFAPolicy doesn't have soft delete)
            filters = [self.model.priority >= min_priority, self.model.priority <= max_priority]

            # Add organization filtering if provided and model supports it
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(self.model.organization_id == str(organization_id))

            query = select(self.model).where(and_(*filters)).order_by(desc(self.model.priority))
            result = await self.session.execute(query)
            policies = list(result.scalars().all())

            self.logger.debug(
                "Retrieved policies by priority range",
                min_priority=min_priority,
                max_priority=max_priority,
                count=len(policies),
            )
            return policies

        except Exception as e:
            self.logger.error(
                "Failed to get policies by priority range",
                min_priority=min_priority,
                max_priority=max_priority,
                error=str(e),
            )
            raise

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
        try:
            from datetime import datetime, timezone

            updated_policy = await self.update(
                policy_id,
                organization_id=organization_id,
                is_active=True,
                updated_by=activated_by,
                updated_at=datetime.now(timezone.utc),
            )

            success = updated_policy is not None
            if success:
                self.logger.info("MFA policy activated", policy_id=str(policy_id), activated_by=activated_by)

            return success

        except Exception as e:
            self.logger.error("Failed to activate MFA policy", policy_id=str(policy_id), error=str(e))
            raise

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
        try:
            from datetime import datetime, timezone

            updated_policy = await self.update(
                policy_id,
                organization_id=organization_id,
                is_active=False,
                updated_by=deactivated_by,
                updated_at=datetime.now(timezone.utc),
            )

            success = updated_policy is not None
            if success:
                self.logger.info("MFA policy deactivated", policy_id=str(policy_id), deactivated_by=deactivated_by)

            return success

        except Exception as e:
            self.logger.error("Failed to deactivate MFA policy", policy_id=str(policy_id), error=str(e))
            raise

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
        try:
            from datetime import datetime, timezone

            # Serialize conditions to JSON
            conditions_json = json.dumps(conditions)

            updated_policy = await self.update(
                policy_id,
                organization_id=organization_id,
                conditions=conditions_json,
                updated_by=updated_by,
                updated_at=datetime.now(timezone.utc),
            )

            success = updated_policy is not None
            if success:
                self.logger.info("MFA policy conditions updated", policy_id=str(policy_id), updated_by=updated_by)

            return success

        except Exception as e:
            self.logger.error("Failed to update MFA policy conditions", policy_id=str(policy_id), error=str(e))
            raise

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
        try:
            from datetime import datetime, timezone

            updated_policy = await self.update(
                policy_id,
                organization_id=organization_id,
                priority=priority,
                updated_by=updated_by,
                updated_at=datetime.now(timezone.utc),
            )

            success = updated_policy is not None
            if success:
                self.logger.info(
                    "MFA policy priority updated", policy_id=str(policy_id), priority=priority, updated_by=updated_by
                )

            return success

        except Exception as e:
            self.logger.error("Failed to update MFA policy priority", policy_id=str(policy_id), error=str(e))
            raise

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
        try:
            # For now, return basic stats
            # In a full implementation, this would query usage tables
            policy = await self.get_by_id(policy_id, organization_id)
            if not policy:
                return {}

            stats = {
                "policy_id": str(policy_id),
                "policy_name": policy.name,
                "is_active": policy.is_active,
                "priority": policy.priority,
                "enforcement_level": policy.enforcement_level,
                # TODO: Add actual usage metrics from audit/login tables
                "total_applications": 0,
                "successful_authentications": 0,
                "failed_authentications": 0,
            }

            self.logger.debug("Retrieved MFA policy usage stats", policy_id=str(policy_id))
            return stats

        except Exception as e:
            self.logger.error("Failed to get MFA policy usage stats", policy_id=str(policy_id), error=str(e))
            raise

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
        try:
            from sqlalchemy import or_

            search_term = f"%{query}%"

            # Build search conditions
            search_conditions = [
                self.model.name.ilike(search_term),
                self.model.description.ilike(search_term),
            ]

            # Build base query (MFAPolicy doesn't have soft delete)
            filters = [or_(*search_conditions)]

            # Add organization filtering if provided and model supports it
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(self.model.organization_id == str(organization_id))

            search_query = select(self.model).where(and_(*filters)).order_by(desc(self.model.priority)).limit(limit)
            result = await self.session.execute(search_query)
            policies = list(result.scalars().all())

            self.logger.debug("MFA policy search completed", query=query, count=len(policies), limit=limit)
            return policies

        except Exception as e:
            self.logger.error("Failed to search MFA policies", query=query, error=str(e))
            raise
