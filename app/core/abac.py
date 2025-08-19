"""
Attribute-Based Access Control (ABAC) Policy Engine

This module implements a comprehensive ABAC system that evaluates access permissions
based on subject attributes (user), resource attributes, action attributes, and
environmental attributes (context).

Design Principles:
- Policy-driven authorization with rule engine
- Multi-tenant organization isolation
- Hierarchical role inheritance
- Resource ownership validation
- Contextual permission evaluation
- Extensible policy framework
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import ForbiddenError, ValidationError
from app.models.user import User

logger = get_logger(__name__)


class PolicyEffect(Enum):
    """Policy evaluation effects."""

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class AttributeType(Enum):
    """Types of attributes used in ABAC evaluation."""

    SUBJECT = "subject"
    RESOURCE = "resource"
    ACTION = "action"
    ENVIRONMENT = "environment"


class ABACRule(ABC):
    """Abstract base class for ABAC rules."""

    def __init__(self, rule_id: str, priority: int = 100):
        """Initialize ABAC rule.

        Args:
            rule_id: Unique identifier for the rule
            priority: Rule priority (lower number = higher priority)
        """
        self.rule_id = rule_id
        self.priority = priority

    @abstractmethod
    async def evaluate(self, context: "ABACContext") -> PolicyEffect:
        """Evaluate the rule against the given context.

        Args:
            context: ABAC evaluation context

        Returns:
            PolicyEffect indicating rule result
        """
        pass

    @abstractmethod
    def matches_request(self, resource: str, action: str) -> bool:
        """Check if this rule applies to the given resource and action.

        Args:
            resource: Resource type being accessed
            action: Action being performed

        Returns:
            True if rule applies to this request
        """
        pass


class ABACContext:
    """Context for ABAC policy evaluation containing all relevant attributes."""

    def __init__(
        self,
        subject_id: str,
        resource_type: str,
        action: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_owner_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
        environment: Optional[Dict[str, Any]] = None,
    ):
        """Initialize ABAC context.

        Args:
            subject_id: ID of the user/subject making the request
            resource_type: Type of resource being accessed (e.g., 'users', 'api_keys')
            action: Action being performed (e.g., 'read', 'write', 'delete')
            organization_id: Organization context from JWT token
            resource_id: Specific resource instance ID (if applicable)
            resource_owner_id: Owner of the specific resource (if applicable)
            session: Database session for attribute lookup
            environment: Additional environmental context
        """
        self.subject_id = subject_id
        self.resource_type = resource_type
        self.action = action
        self.organization_id = organization_id
        self.resource_id = resource_id
        self.resource_owner_id = resource_owner_id
        self.session = session
        self.environment = environment or {}

        # Cached attributes
        self._subject_attributes: Optional[Dict[str, Any]] = None
        self._resource_attributes: Optional[Dict[str, Any]] = None
        self._action_attributes: Optional[Dict[str, Any]] = None
        self._environment_attributes: Optional[Dict[str, Any]] = None

    async def get_subject_attributes(self) -> Dict[str, Any]:
        """Get subject (user) attributes for policy evaluation."""
        if self._subject_attributes is None:
            self._subject_attributes = await self._load_subject_attributes()
        return self._subject_attributes

    async def get_resource_attributes(self) -> Dict[str, Any]:
        """Get resource attributes for policy evaluation."""
        if self._resource_attributes is None:
            self._resource_attributes = await self._load_resource_attributes()
        return self._resource_attributes

    async def get_action_attributes(self) -> Dict[str, Any]:
        """Get action attributes for policy evaluation."""
        if self._action_attributes is None:
            self._action_attributes = self._load_action_attributes()
        return self._action_attributes

    async def get_environment_attributes(self) -> Dict[str, Any]:
        """Get environmental attributes for policy evaluation."""
        if self._environment_attributes is None:
            self._environment_attributes = self._load_environment_attributes()
        return self._environment_attributes

    async def _load_subject_attributes(self) -> Dict[str, Any]:
        """Load subject attributes from database."""
        attributes: Dict[str, Any] = {
            "subject_id": self.subject_id,
            "organization_id": self.organization_id,
        }

        if self.session:
            try:
                from app.repositories.user import UserRepository
                from app.services.rbac_service import RBACService

                user_repo = UserRepository(self.session)
                rbac_service = RBACService(self.session)

                # Get user information
                user = await user_repo.get_by_id(self.subject_id, self.organization_id)
                if user:
                    attributes.update(
                        {
                            "username": user.username,
                            "email": user.email,
                            "is_active": user.is_active,
                            "is_verified": user.is_verified,
                            "roles": user.roles,
                            "user_organization_id": str(user.organization_id) if user.organization_id else None,
                        }
                    )

                    # Get effective permissions
                    permissions = await rbac_service.get_user_permissions(self.subject_id)
                    attributes["permissions"] = list(permissions)

                    # Determine authority level
                    attributes["authority_level"] = self._calculate_authority_level(user, permissions)

            except Exception as e:
                logger.warning("Failed to load subject attributes", subject_id=self.subject_id, error=str(e))

        return attributes

    async def _load_resource_attributes(self) -> Dict[str, Any]:
        """Load resource attributes."""
        attributes: Dict[str, Any] = {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_owner_id": self.resource_owner_id,
        }

        # Add resource-specific attributes based on type
        if self.resource_type == "users" and self.resource_id and self.session:
            try:
                from app.repositories.user import UserRepository

                user_repo = UserRepository(self.session)
                resource_user = await user_repo.get_by_id(self.resource_id, self.organization_id)
                if resource_user:
                    attributes.update(
                        {
                            "resource_is_active": resource_user.is_active,
                            "resource_organization_id": (
                                str(resource_user.organization_id) if resource_user.organization_id else None
                            ),
                            "resource_roles": resource_user.roles,
                        }
                    )
            except Exception as e:
                logger.warning("Failed to load user resource attributes", resource_id=self.resource_id, error=str(e))

        elif self.resource_type == "api_keys" and self.resource_id and self.session:
            try:
                from app.repositories.api_key import APIKeyRepository

                api_key_repo = APIKeyRepository(self.session)
                api_key = await api_key_repo.get_by_id(self.resource_id, self.organization_id)
                if api_key:
                    attributes.update(
                        {
                            "resource_is_active": api_key.is_active(),
                            "resource_organization_id": (
                                str(api_key.organization_id) if api_key.organization_id else None
                            ),
                            "resource_permissions": api_key.permissions,
                            "resource_expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                        }
                    )
            except Exception as e:
                logger.warning("Failed to load API key resource attributes", resource_id=self.resource_id, error=str(e))

        return attributes

    def _load_action_attributes(self) -> Dict[str, Any]:
        """Load action attributes."""
        action_risk_levels = {"read": "low", "write": "medium", "delete": "high", "manage": "high", "*": "critical"}

        return {
            "action": self.action,
            "risk_level": action_risk_levels.get(self.action, "medium"),
            "is_destructive": self.action in ["delete", "revoke"],
            "is_privileged": self.action in ["manage", "*", "admin"],
        }

    def _load_environment_attributes(self) -> Dict[str, Any]:
        """Load environmental context attributes."""
        now = datetime.now(timezone.utc)

        attributes = {
            "current_time": now.isoformat(),
            "timestamp": now.timestamp(),
            "is_business_hours": 9 <= now.hour < 17,  # Simple business hours check
        }

        # Add any additional environmental context
        attributes.update(self.environment)

        return attributes

    def _calculate_authority_level(self, user: User, permissions: Set[str]) -> str:
        """Calculate user's authority level based on roles and permissions."""
        # Check for global admin permissions
        if "*" in permissions:
            return "global_admin"

        # Check for system-level roles (replaces is_superuser boolean)
        if "admin" in user.roles:
            return "admin"
        elif "tester" in user.roles:
            return "tester"
        elif "viewer" in user.roles:
            return "viewer"
        else:
            return "user"


class OrganizationIsolationRule(ABACRule):
    """Rule to enforce multi-tenant organization isolation."""

    def __init__(self):
        super().__init__("organization_isolation", priority=10)

    async def evaluate(self, context: ABACContext) -> PolicyEffect:
        """Enforce organization-based isolation."""
        subject_attrs = await context.get_subject_attributes()
        resource_attrs = await context.get_resource_attributes()

        # Global admins can access cross-organization resources
        if subject_attrs.get("authority_level") == "global_admin":
            return PolicyEffect.ALLOW

        # Must have organization context
        if not context.organization_id:
            logger.warning(
                "Missing organization context for isolation check",
                subject_id=context.subject_id,
                resource_type=context.resource_type,
            )
            return PolicyEffect.DENY

        # Subject must belong to the organization
        subject_org_id = subject_attrs.get("user_organization_id")
        if not subject_org_id or subject_org_id != context.organization_id:
            logger.warning(
                "Subject not in required organization",
                subject_id=context.subject_id,
                subject_org=subject_org_id,
                required_org=context.organization_id,
            )
            return PolicyEffect.DENY

        # If resource has organization context, it must match
        resource_org_id = resource_attrs.get("resource_organization_id")
        if resource_org_id and resource_org_id != context.organization_id:
            logger.warning(
                "Resource not in subject's organization",
                subject_id=context.subject_id,
                resource_id=context.resource_id,
                resource_org=resource_org_id,
                subject_org=context.organization_id,
            )
            return PolicyEffect.DENY

        return PolicyEffect.NOT_APPLICABLE

    def matches_request(self, resource: str, action: str) -> bool:
        """This rule applies to all requests for organization isolation."""
        return True


class RoleBasedAccessRule(ABACRule):
    """Rule for role-based access control with proper hierarchy (replaces superuser boolean)."""

    def __init__(self):
        super().__init__("role_based_access", priority=20)

    async def evaluate(self, context: ABACContext) -> PolicyEffect:
        """Evaluate role-based permissions with hierarchy."""
        subject_attrs = await context.get_subject_attributes()
        action_attrs = await context.get_action_attributes()

        authority_level = subject_attrs.get("authority_level", "user")
        permissions = set(subject_attrs.get("permissions", []))

        # Global admin has all permissions (replaces is_superuser=True)
        if authority_level == "global_admin" or "*" in permissions:
            return PolicyEffect.ALLOW

        # Check specific permission
        permission_string = f"{context.resource_type}:{context.action}"
        if permission_string in permissions:
            return PolicyEffect.ALLOW

        # Check wildcard permission for resource
        resource_wildcard = f"{context.resource_type}:*"
        if resource_wildcard in permissions:
            return PolicyEffect.ALLOW

        # Authority level based permissions
        if authority_level == "admin":
            # Admins can perform most operations
            if action_attrs.get("risk_level") != "critical":
                return PolicyEffect.ALLOW
        elif authority_level == "tester":
            # Testers can read and perform test operations
            if context.action in ["read", "test", "execute"]:
                return PolicyEffect.ALLOW
        elif authority_level == "viewer":
            # Viewers can only read
            if context.action == "read":
                return PolicyEffect.ALLOW

        return PolicyEffect.NOT_APPLICABLE

    def matches_request(self, resource: str, action: str) -> bool:
        """This rule applies to all requests for role-based access."""
        return True


class OwnershipBasedAccessRule(ABACRule):
    """Rule for ownership-based access control (:own scoped permissions)."""

    def __init__(self):
        super().__init__("ownership_based_access", priority=30)

    async def evaluate(self, context: ABACContext) -> PolicyEffect:
        """Evaluate ownership-based permissions."""
        # Only applies to requests with resource ownership context
        if not context.resource_owner_id:
            return PolicyEffect.NOT_APPLICABLE

        subject_attrs = await context.get_subject_attributes()
        permissions = set(subject_attrs.get("permissions", []))

        # Check for :own scoped permissions
        own_permission = f"{context.resource_type}:{context.action}:own"
        own_wildcard = f"{context.resource_type}:*:own"

        if own_permission in permissions or own_wildcard in permissions:
            # User must own the resource
            if str(context.subject_id) == str(context.resource_owner_id):
                return PolicyEffect.ALLOW
            else:
                # User has :own permission but doesn't own the resource
                return PolicyEffect.DENY

        return PolicyEffect.NOT_APPLICABLE

    def matches_request(self, resource: str, action: str) -> bool:
        """This rule applies to requests involving resource ownership."""
        return True


class EnvironmentalRule(ABACRule):
    """Rule for environmental constraints (time-based, context-based access)."""

    def __init__(self):
        super().__init__("environmental_constraints", priority=40)

    async def evaluate(self, context: ABACContext) -> PolicyEffect:
        """Evaluate environmental constraints."""
        env_attrs = await context.get_environment_attributes()
        action_attrs = await context.get_action_attributes()

        # High-risk actions during non-business hours require higher privileges
        if action_attrs.get("risk_level") == "high" and not env_attrs.get("is_business_hours", True):

            subject_attrs = await context.get_subject_attributes()
            if subject_attrs.get("authority_level") not in ["admin", "global_admin"]:
                logger.info(
                    "High-risk action denied outside business hours",
                    subject_id=context.subject_id,
                    action=context.action,
                    resource_type=context.resource_type,
                )
                return PolicyEffect.DENY

        return PolicyEffect.NOT_APPLICABLE

    def matches_request(self, resource: str, action: str) -> bool:
        """This rule applies to high-risk actions."""
        high_risk_actions = ["delete", "revoke", "manage"]
        return action in high_risk_actions


class ABACPolicyEngine:
    """ABAC Policy Engine for evaluating access control policies."""

    def __init__(self):
        """Initialize ABAC policy engine with default rules."""
        self.rules: List[ABACRule] = []
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        """Initialize default ABAC rules."""
        # Add rules in priority order (lower priority number = higher precedence)
        self.rules.extend(
            [
                OrganizationIsolationRule(),
                RoleBasedAccessRule(),
                OwnershipBasedAccessRule(),
                EnvironmentalRule(),
            ]
        )

        # Sort rules by priority
        self.rules.sort(key=lambda r: r.priority)

    def add_rule(self, rule: ABACRule) -> None:
        """Add a custom rule to the policy engine."""
        self.rules.append(rule)
        # Re-sort rules by priority
        self.rules.sort(key=lambda r: r.priority)

    async def evaluate_access(self, context: ABACContext) -> Tuple[bool, str]:
        """Evaluate access request against all applicable rules.

        Args:
            context: ABAC evaluation context

        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            applicable_rules = [
                rule for rule in self.rules if rule.matches_request(context.resource_type, context.action)
            ]

            logger.debug(
                "Evaluating ABAC rules",
                subject_id=context.subject_id,
                resource_type=context.resource_type,
                action=context.action,
                applicable_rules=len(applicable_rules),
            )

            deny_reasons = []
            allow_reasons = []

            # Evaluate all applicable rules
            for rule in applicable_rules:
                try:
                    effect = await rule.evaluate(context)

                    if effect == PolicyEffect.DENY:
                        deny_reasons.append(f"Rule {rule.rule_id} denied access")
                    elif effect == PolicyEffect.ALLOW:
                        allow_reasons.append(f"Rule {rule.rule_id} allowed access")

                    logger.debug(
                        "Rule evaluation result",
                        rule_id=rule.rule_id,
                        effect=effect.value,
                        subject_id=context.subject_id,
                    )

                except Exception as e:
                    logger.error(
                        "Rule evaluation error", rule_id=rule.rule_id, subject_id=context.subject_id, error=str(e)
                    )
                    # Fail-secure: treat evaluation errors as denials
                    deny_reasons.append(f"Rule {rule.rule_id} evaluation failed")

            # Decision logic: Any explicit DENY overrides ALLOWs
            if deny_reasons:
                reason = "; ".join(deny_reasons)
                logger.info(
                    "Access denied by ABAC policy",
                    subject_id=context.subject_id,
                    resource_type=context.resource_type,
                    action=context.action,
                    reason=reason,
                )
                return False, reason

            # If we have explicit allows, grant access
            if allow_reasons:
                reason = "; ".join(allow_reasons)
                logger.debug(
                    "Access allowed by ABAC policy",
                    subject_id=context.subject_id,
                    resource_type=context.resource_type,
                    action=context.action,
                    reason=reason,
                )
                return True, reason

            # No explicit allow or deny - default deny for security
            reason = "No applicable policy rules granted access (default deny)"
            logger.info(
                "Access denied by default policy",
                subject_id=context.subject_id,
                resource_type=context.resource_type,
                action=context.action,
            )
            return False, reason

        except Exception as e:
            logger.error(
                "ABAC evaluation error",
                subject_id=context.subject_id,
                resource_type=context.resource_type,
                action=context.action,
                error=str(e),
            )
            # Fail-secure: deny access on evaluation errors
            return False, f"Policy evaluation error: {str(e)}"

    async def explain_decision(self, context: ABACContext) -> Dict[str, Any]:
        """Provide detailed explanation of access decision for debugging/auditing."""
        try:
            # Get all attributes for context
            subject_attrs = await context.get_subject_attributes()
            resource_attrs = await context.get_resource_attributes()
            action_attrs = await context.get_action_attributes()
            env_attrs = await context.get_environment_attributes()

            # Evaluate decision
            is_allowed, reason = await self.evaluate_access(context)

            explanation = {
                "decision": "ALLOW" if is_allowed else "DENY",
                "reason": reason,
                "context": {
                    "subject_id": context.subject_id,
                    "resource_type": context.resource_type,
                    "action": context.action,
                    "organization_id": context.organization_id,
                    "resource_id": context.resource_id,
                    "resource_owner_id": context.resource_owner_id,
                },
                "attributes": {
                    "subject": subject_attrs,
                    "resource": resource_attrs,
                    "action": action_attrs,
                    "environment": env_attrs,
                },
                "applicable_rules": [
                    {
                        "rule_id": rule.rule_id,
                        "priority": rule.priority,
                        "matches": rule.matches_request(context.resource_type, context.action),
                    }
                    for rule in self.rules
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            return explanation

        except Exception as e:
            logger.error("Failed to generate decision explanation", subject_id=context.subject_id, error=str(e))
            return {
                "decision": "DENY",
                "reason": f"Explanation generation failed: {str(e)}",
                "error": True,
            }


# Global policy engine instance
_policy_engine: Optional[ABACPolicyEngine] = None


def get_abac_engine() -> ABACPolicyEngine:
    """Get the global ABAC policy engine instance."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = ABACPolicyEngine()
    return _policy_engine


async def check_abac_permission(
    subject_id: str,
    resource_type: str,
    action: str,
    session: AsyncSession,
    organization_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_owner_id: Optional[str] = None,
    environment: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Convenience function to check ABAC permission.

    Args:
        subject_id: ID of the user making the request
        resource_type: Type of resource being accessed
        action: Action being performed
        session: Database session
        organization_id: Organization context
        resource_id: Specific resource ID (if applicable)
        resource_owner_id: Owner of the resource (if applicable)
        environment: Additional environmental context

    Returns:
        Tuple of (is_allowed, reason)
    """
    context = ABACContext(
        subject_id=subject_id,
        resource_type=resource_type,
        action=action,
        organization_id=organization_id,
        resource_id=resource_id,
        resource_owner_id=resource_owner_id,
        session=session,
        environment=environment,
    )

    engine = get_abac_engine()
    return await engine.evaluate_access(context)


async def explain_abac_decision(
    subject_id: str,
    resource_type: str,
    action: str,
    session: AsyncSession,
    organization_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_owner_id: Optional[str] = None,
    environment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Get detailed explanation of ABAC decision for debugging/auditing.

    Args:
        subject_id: ID of the user making the request
        resource_type: Type of resource being accessed
        action: Action being performed
        session: Database session
        organization_id: Organization context
        resource_id: Specific resource ID (if applicable)
        resource_owner_id: Owner of the resource (if applicable)
        environment: Additional environmental context

    Returns:
        Detailed explanation dictionary
    """
    context = ABACContext(
        subject_id=subject_id,
        resource_type=resource_type,
        action=action,
        organization_id=organization_id,
        resource_id=resource_id,
        resource_owner_id=resource_owner_id,
        session=session,
        environment=environment,
    )

    engine = get_abac_engine()
    return await engine.explain_decision(context)
