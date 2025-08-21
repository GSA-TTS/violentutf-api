"""MFA Policy Service for enforcement of MFA requirements."""

import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import ValidationError
from app.models.mfa import MFAMethod, MFAPolicy
from app.models.user import User
from app.repositories.mfa_policy import MfaPolicyRepository

logger = get_logger(__name__)


class MFAPolicyService:
    """Service for managing and enforcing MFA policies."""

    def __init__(self, session: AsyncSession):
        """Initialize MFA policy service."""
        self.session = session
        self.mfa_policy_repo = MfaPolicyRepository(session)

    async def create_policy(
        self,
        name: str,
        description: str,
        conditions: Dict,
        required_methods: List[str],
        min_methods: int = 1,
        grace_period_days: int = 0,
        enforcement_level: str = "required",
        bypass_permissions: Optional[List[str]] = None,
        priority: int = 0,
        created_by: str = "system",
    ) -> MFAPolicy:
        """Create a new MFA policy."""
        # Validate enforcement level
        valid_levels = ["required", "recommended", "optional"]
        if enforcement_level not in valid_levels:
            raise ValidationError(f"Invalid enforcement level. Must be one of: {valid_levels}")

        # Validate required methods
        valid_methods = [m.value for m in MFAMethod]
        for method in required_methods:
            if method not in valid_methods:
                raise ValidationError(f"Invalid MFA method: {method}")

        # Check for duplicate policy name
        existing_policy = await self.mfa_policy_repo.get_by_name(name)
        if existing_policy:
            raise ValidationError(f"Policy with name '{name}' already exists")

        # Create policy data
        policy_data = {
            "name": name,
            "description": description,
            "conditions": json.dumps(conditions),
            "required_methods": json.dumps(required_methods),
            "min_methods": min_methods,
            "grace_period_days": grace_period_days,
            "enforcement_level": enforcement_level,
            "bypass_permissions": json.dumps(bypass_permissions) if bypass_permissions else None,
            "priority": priority,
            "created_by": created_by,
        }

        policy = await self.mfa_policy_repo.create(policy_data)

        logger.info(
            "mfa_policy_created",
            policy_id=str(policy.id),
            policy_name=name,
            enforcement_level=enforcement_level,
        )

        return policy

    async def get_applicable_policies(self, user: User) -> List[MFAPolicy]:
        """Get all MFA policies applicable to a user, ordered by priority."""
        # Use repository to get applicable policies
        return await self.mfa_policy_repo.get_applicable_policies(user)

    async def _check_policy_conditions(self, policy: MFAPolicy, user: User) -> bool:
        """Check if a policy's conditions apply to a user."""
        try:
            conditions = json.loads(policy.conditions)
        except json.JSONDecodeError:
            logger.error("Invalid policy conditions JSON", policy_id=str(policy.id))
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
            if isinstance(org_ids, list) and user.organization_id:
                if str(user.organization_id) not in org_ids:
                    return False

        # Check user type conditions
        if "is_superuser" in conditions:
            if conditions["is_superuser"] != user.is_superuser:
                return False

        # Check account age conditions
        if "min_account_age_days" in conditions:
            min_age = conditions["min_account_age_days"]
            account_age = datetime.now(timezone.utc) - user.created_at
            if account_age.days < min_age:
                return False

        # All conditions passed
        return True

    async def _get_user_permissions(self, user: User) -> List[str]:
        """Get all permissions for a user through their roles."""
        # This would integrate with the RBAC system
        # For now, return empty list
        return []

    async def check_mfa_requirement(self, user: User) -> Tuple[bool, Optional[MFAPolicy], Dict]:
        """
        Check if MFA is required for a user.

        Returns:
            Tuple of (is_required, policy, requirement_details)
        """
        # Get applicable policies
        policies = await self.get_applicable_policies(user)

        if not policies:
            # No policies apply, MFA is optional
            return (
                False,
                None,
                {"required": False, "enforcement_level": "optional", "reason": "No MFA policies apply to this user"},
            )

        # Use highest priority policy (first in list)
        policy = policies[0]

        # Check if user has bypass permissions
        if policy.bypass_permissions:
            try:
                bypass_perms = json.loads(policy.bypass_permissions)
                user_perms = await self._get_user_permissions(user)
                if any(perm in user_perms for perm in bypass_perms):
                    return (
                        False,
                        policy,
                        {
                            "required": False,
                            "enforcement_level": "bypassed",
                            "reason": "User has bypass permissions",
                            "policy": policy.name,
                        },
                    )
            except json.JSONDecodeError:
                logger.error("Invalid bypass permissions JSON", policy_id=str(policy.id))

        # Check grace period for new users
        if policy.grace_period_days > 0:
            account_age = datetime.now(timezone.utc) - user.created_at
            if account_age.days < policy.grace_period_days:
                remaining_days = policy.grace_period_days - account_age.days
                return (
                    False,
                    policy,
                    {
                        "required": False,
                        "enforcement_level": "grace_period",
                        "reason": f"User is in grace period",
                        "grace_period_remaining": remaining_days,
                        "policy": policy.name,
                    },
                )

        # Parse required methods
        try:
            required_methods = json.loads(policy.required_methods)
        except json.JSONDecodeError:
            required_methods = []

        # Determine if MFA is required
        is_required = policy.enforcement_level == "required"

        return (
            is_required,
            policy,
            {
                "required": is_required,
                "enforcement_level": policy.enforcement_level,
                "required_methods": required_methods,
                "min_methods": policy.min_methods,
                "policy": policy.name,
                "reason": f"Policy '{policy.name}' applies to user",
            },
        )

    async def update_policy(self, policy_id: str, **kwargs) -> MFAPolicy:
        """Update an existing MFA policy."""
        # Get policy to check if it exists
        policy = await self.mfa_policy_repo.get_by_id(policy_id)
        if not policy:
            raise ValidationError("MFA policy not found")

        # Prepare update data with allowed fields
        allowed_fields = [
            "name",
            "description",
            "is_active",
            "priority",
            "conditions",
            "required_methods",
            "min_methods",
            "grace_period_days",
            "enforcement_level",
            "bypass_permissions",
        ]

        update_data = {}
        for field, value in kwargs.items():
            if field in allowed_fields:
                # Validate and serialize JSON fields
                if field in ["conditions", "required_methods", "bypass_permissions"]:
                    if value is not None:
                        value = json.dumps(value)
                update_data[field] = value

        # Add metadata
        update_data["updated_at"] = datetime.now(timezone.utc)
        update_data["updated_by"] = kwargs.get("updated_by", "system")

        # Update using repository
        updated_policy = await self.mfa_policy_repo.update(policy_id, **update_data)
        if not updated_policy:
            raise ValidationError("Failed to update MFA policy")

        logger.info(
            "mfa_policy_updated",
            policy_id=str(updated_policy.id),
            policy_name=updated_policy.name,
            updates=list(kwargs.keys()),
        )

        return updated_policy

    async def delete_policy(self, policy_id: str, deleted_by: str = "system") -> bool:
        """Soft delete an MFA policy."""
        # Use repository for soft delete
        success = await self.mfa_policy_repo.deactivate_policy(policy_id, deleted_by)

        if success:
            # Get policy name for logging
            policy = await self.mfa_policy_repo.get_by_id(policy_id)
            logger.info(
                "mfa_policy_deleted",
                policy_id=str(policy_id),
                policy_name=policy.name if policy else "unknown",
            )

        return success

    async def list_policies(self, active_only: bool = True, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List MFA policies with details."""
        # Get policies using repository
        if active_only:
            policies = await self.mfa_policy_repo.get_active_policies()
        else:
            # Use pagination to get all policies
            page_result = await self.mfa_policy_repo.list_with_pagination(
                page=(offset // limit) + 1, size=limit, order_by="priority", order_desc=True
            )
            policies = page_result.items

        # Convert to dict with parsed JSON fields
        policy_list = []
        for policy in policies:
            policy_dict = {
                "id": str(policy.id),
                "name": policy.name,
                "description": policy.description,
                "is_active": policy.is_active,
                "priority": policy.priority,
                "enforcement_level": policy.enforcement_level,
                "grace_period_days": policy.grace_period_days,
                "min_methods": policy.min_methods,
                "created_at": policy.created_at.isoformat() if policy.created_at else None,
                "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
            }

            # Parse JSON fields
            try:
                policy_dict["conditions"] = json.loads(policy.conditions)
            except (json.JSONDecodeError, TypeError, ValueError):
                policy_dict["conditions"] = {}

            try:
                policy_dict["required_methods"] = json.loads(policy.required_methods)
            except (json.JSONDecodeError, TypeError, ValueError):
                policy_dict["required_methods"] = []

            try:
                policy_dict["bypass_permissions"] = (
                    json.loads(policy.bypass_permissions) if policy.bypass_permissions else []
                )
            except (json.JSONDecodeError, TypeError, ValueError):
                policy_dict["bypass_permissions"] = []

            policy_list.append(policy_dict)

        return policy_list
