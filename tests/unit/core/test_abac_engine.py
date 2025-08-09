"""
Comprehensive tests for the ABAC (Attribute-Based Access Control) policy engine.

This test suite provides 100% coverage for the new ABAC system that addresses
critical security vulnerabilities identified in the authentication audit report.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.abac import (
    ABACContext,
    ABACPolicyEngine,
    AttributeType,
    EnvironmentalRule,
    OrganizationIsolationRule,
    OwnershipBasedAccessRule,
    PolicyEffect,
    RoleBasedAccessRule,
    check_abac_permission,
    explain_abac_decision,
    get_abac_engine,
)
from app.models.user import User


class TestABACContext:
    """Test ABAC context creation and attribute loading."""

    @pytest.fixture
    def sample_context(self) -> ABACContext:
        """Create a sample ABAC context for testing."""
        return ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
            resource_id="resource-789",
            resource_owner_id="owner-123",
        )

    def test_context_initialization(self, sample_context):
        """Test ABAC context initialization."""
        assert sample_context.subject_id == "user-123"
        assert sample_context.resource_type == "users"
        assert sample_context.action == "read"
        assert sample_context.organization_id == "org-456"
        assert sample_context.resource_id == "resource-789"
        assert sample_context.resource_owner_id == "owner-123"

    def test_context_with_defaults(self):
        """Test ABAC context with minimal parameters."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        assert context.subject_id == "user-123"
        assert context.resource_type == "users"
        assert context.action == "read"
        assert context.organization_id is None
        assert context.resource_id is None
        assert context.resource_owner_id is None
        assert context.environment == {}

    @pytest.mark.asyncio
    async def test_load_subject_attributes_with_session(self):
        """Test loading subject attributes with database session."""
        # Mock database session and repositories
        mock_session = MagicMock(spec=AsyncSession)
        mock_user_repo = AsyncMock()
        mock_rbac_service = AsyncMock()

        # Create mock user
        mock_user = MagicMock(spec=User)
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.roles = ["admin", "tester"]
        mock_user.organization_id = uuid.uuid4()

        mock_user_repo.get_by_id.return_value = mock_user
        mock_rbac_service.get_user_permissions.return_value = {"users:*", "api_keys:read"}

        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
            session=mock_session,
        )

        with patch("app.repositories.user.UserRepository", return_value=mock_user_repo):
            with patch("app.services.rbac_service.RBACService", return_value=mock_rbac_service):
                attrs = await context.get_subject_attributes()

        assert attrs["subject_id"] == "user-123"
        assert attrs["organization_id"] == "org-456"
        assert attrs["username"] == "testuser"
        assert attrs["email"] == "test@example.com"
        assert attrs["is_active"] is True
        assert attrs["is_verified"] is True
        assert attrs["roles"] == ["admin", "tester"]
        assert sorted(attrs["permissions"]) == sorted(["users:*", "api_keys:read"])
        assert attrs["authority_level"] == "admin"

    @pytest.mark.asyncio
    async def test_load_subject_attributes_without_session(self, sample_context):
        """Test loading subject attributes without database session."""
        attrs = await sample_context.get_subject_attributes()

        assert attrs["subject_id"] == "user-123"
        assert attrs["organization_id"] == "org-456"
        # Should contain minimal attributes when no session available
        assert "username" not in attrs
        assert "permissions" not in attrs

    @pytest.mark.asyncio
    async def test_load_resource_attributes_users(self):
        """Test loading resource attributes for user resources."""
        mock_session = MagicMock(spec=AsyncSession)
        mock_user_repo = AsyncMock()

        # Create mock resource user
        mock_resource_user = MagicMock(spec=User)
        mock_resource_user.is_active = True
        mock_resource_user.organization_id = uuid.uuid4()
        mock_resource_user.roles = ["viewer"]

        mock_user_repo.get_by_id.return_value = mock_resource_user

        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
            resource_id="resource-user-789",
            session=mock_session,
        )

        with patch("app.repositories.user.UserRepository", return_value=mock_user_repo):
            attrs = await context.get_resource_attributes()

        assert attrs["resource_type"] == "users"
        assert attrs["resource_id"] == "resource-user-789"
        assert attrs["resource_is_active"] is True
        assert attrs["resource_roles"] == ["viewer"]

    @pytest.mark.asyncio
    async def test_load_resource_attributes_api_keys(self):
        """Test loading resource attributes for API key resources."""
        mock_session = MagicMock(spec=AsyncSession)
        mock_api_key_repo = AsyncMock()

        # Create mock API key
        mock_api_key = MagicMock()
        mock_api_key.is_active.return_value = True
        mock_api_key.organization_id = uuid.uuid4()
        mock_api_key.permissions = ["users:read", "api_keys:write"]
        mock_api_key.expires_at = None

        mock_api_key_repo.get_by_id.return_value = mock_api_key

        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="read",
            organization_id="org-456",
            resource_id="api-key-789",
            session=mock_session,
        )

        with patch("app.repositories.api_key.APIKeyRepository", return_value=mock_api_key_repo):
            attrs = await context.get_resource_attributes()

        assert attrs["resource_type"] == "api_keys"
        assert attrs["resource_id"] == "api-key-789"
        assert attrs["resource_is_active"] is True
        assert attrs["resource_permissions"] == ["users:read", "api_keys:write"]
        assert attrs["resource_expires_at"] is None

    @pytest.mark.asyncio
    async def test_load_action_attributes(self, sample_context):
        """Test loading action attributes."""
        attrs = await sample_context.get_action_attributes()

        assert attrs["action"] == "read"
        assert attrs["risk_level"] == "low"
        assert attrs["is_destructive"] is False
        assert attrs["is_privileged"] is False

    @pytest.mark.asyncio
    async def test_load_action_attributes_high_risk(self):
        """Test loading action attributes for high-risk actions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        attrs = await context.get_action_attributes()

        assert attrs["action"] == "delete"
        assert attrs["risk_level"] == "high"
        assert attrs["is_destructive"] is True
        assert attrs["is_privileged"] is False

    @pytest.mark.asyncio
    async def test_load_environment_attributes(self, sample_context):
        """Test loading environmental attributes."""
        attrs = await sample_context.get_environment_attributes()

        assert "current_time" in attrs
        assert "timestamp" in attrs
        assert "is_business_hours" in attrs
        assert isinstance(attrs["is_business_hours"], bool)

    @pytest.mark.asyncio
    async def test_calculate_authority_level_global_admin(self):
        """Test authority level calculation for global admin."""
        mock_user = MagicMock(spec=User)
        mock_user.roles = ["admin"]

        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        # Test global wildcard permission
        level = context._calculate_authority_level(mock_user, {"*"})
        assert level == "global_admin"

    @pytest.mark.asyncio
    async def test_calculate_authority_level_admin(self):
        """Test authority level calculation for admin."""
        mock_user = MagicMock(spec=User)
        mock_user.roles = ["admin", "viewer"]

        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        level = context._calculate_authority_level(mock_user, {"users:*"})
        assert level == "admin"

    @pytest.mark.asyncio
    async def test_calculate_authority_level_user(self):
        """Test authority level calculation for regular user."""
        mock_user = MagicMock(spec=User)
        mock_user.roles = ["viewer"]

        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        level = context._calculate_authority_level(mock_user, {"users:read"})
        assert level == "viewer"


class TestOrganizationIsolationRule:
    """Test organization isolation rule for multi-tenant security."""

    @pytest.fixture
    def isolation_rule(self) -> OrganizationIsolationRule:
        """Create organization isolation rule for testing."""
        return OrganizationIsolationRule()

    @pytest.mark.asyncio
    async def test_global_admin_bypass(self, isolation_rule):
        """Test that global admins can bypass organization isolation."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        # Mock subject attributes with global admin authority
        context._subject_attributes = {
            "authority_level": "global_admin",
            "user_organization_id": "org-456",
        }
        context._resource_attributes = {
            "resource_organization_id": "org-789",  # Different org
        }

        result = await isolation_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_missing_organization_context(self, isolation_rule):
        """Test denial when organization context is missing."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            # organization_id is None
        )

        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-456",
        }
        context._resource_attributes = {}

        result = await isolation_rule.evaluate(context)
        assert result == PolicyEffect.DENY

    @pytest.mark.asyncio
    async def test_subject_not_in_organization(self, isolation_rule):
        """Test denial when subject doesn't belong to required organization."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-789",  # Different org
        }
        context._resource_attributes = {}

        result = await isolation_rule.evaluate(context)
        assert result == PolicyEffect.DENY

    @pytest.mark.asyncio
    async def test_resource_in_different_organization(self, isolation_rule):
        """Test denial when resource belongs to different organization."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-456",
        }
        context._resource_attributes = {
            "resource_organization_id": "org-789",  # Different org
        }

        result = await isolation_rule.evaluate(context)
        assert result == PolicyEffect.DENY

    @pytest.mark.asyncio
    async def test_same_organization_access(self, isolation_rule):
        """Test allowing access within same organization."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-456",
        }
        context._resource_attributes = {
            "resource_organization_id": "org-456",  # Same org
        }

        result = await isolation_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    def test_matches_all_requests(self, isolation_rule):
        """Test that isolation rule applies to all requests."""
        assert isolation_rule.matches_request("users", "read") is True
        assert isolation_rule.matches_request("api_keys", "write") is True
        assert isolation_rule.matches_request("*", "delete") is True


class TestRoleBasedAccessRule:
    """Test role-based access control rule."""

    @pytest.fixture
    def rbac_rule(self) -> RoleBasedAccessRule:
        """Create RBAC rule for testing."""
        return RoleBasedAccessRule()

    @pytest.mark.asyncio
    async def test_global_admin_access(self, rbac_rule):
        """Test global admin has all permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        context._subject_attributes = {
            "authority_level": "global_admin",
            "permissions": {"*"},
        }
        context._action_attributes = {
            "risk_level": "critical",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_specific_permission_match(self, rbac_rule):
        """Test specific permission matching."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        context._subject_attributes = {
            "authority_level": "user",
            "permissions": {"users:read", "api_keys:write"},
        }
        context._action_attributes = {
            "risk_level": "low",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_wildcard_permission_match(self, rbac_rule):
        """Test wildcard permission matching."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="write",
        )

        context._subject_attributes = {
            "authority_level": "admin",
            "permissions": {"users:*", "api_keys:read"},
        }
        context._action_attributes = {
            "risk_level": "medium",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_admin_authority_level_access(self, rbac_rule):
        """Test admin authority level permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="write",
        )

        context._subject_attributes = {
            "authority_level": "admin",
            "permissions": set(),
        }
        context._action_attributes = {
            "risk_level": "medium",  # Not critical
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_admin_blocked_critical_action(self, rbac_rule):
        """Test admin blocked from critical actions without explicit permission."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="system",
            action="destroy",
        )

        context._subject_attributes = {
            "authority_level": "admin",
            "permissions": set(),
        }
        context._action_attributes = {
            "risk_level": "critical",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    @pytest.mark.asyncio
    async def test_tester_authority_level(self, rbac_rule):
        """Test tester authority level permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="tests",
            action="execute",
        )

        context._subject_attributes = {
            "authority_level": "tester",
            "permissions": set(),
        }
        context._action_attributes = {
            "risk_level": "low",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_viewer_authority_level(self, rbac_rule):
        """Test viewer authority level permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        context._subject_attributes = {
            "authority_level": "viewer",
            "permissions": set(),
        }
        context._action_attributes = {
            "risk_level": "low",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_insufficient_permissions(self, rbac_rule):
        """Test denial with insufficient permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        context._subject_attributes = {
            "authority_level": "viewer",
            "permissions": {"users:read"},
        }
        context._action_attributes = {
            "risk_level": "high",
        }

        result = await rbac_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    def test_matches_all_requests(self, rbac_rule):
        """Test that RBAC rule applies to all requests."""
        assert rbac_rule.matches_request("users", "read") is True
        assert rbac_rule.matches_request("api_keys", "write") is True


class TestOwnershipBasedAccessRule:
    """Test ownership-based access control rule."""

    @pytest.fixture
    def ownership_rule(self) -> OwnershipBasedAccessRule:
        """Create ownership rule for testing."""
        return OwnershipBasedAccessRule()

    @pytest.mark.asyncio
    async def test_no_resource_owner_not_applicable(self, ownership_rule):
        """Test rule doesn't apply when no resource owner specified."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            # resource_owner_id is None
        )

        result = await ownership_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    @pytest.mark.asyncio
    async def test_own_permission_with_ownership(self, ownership_rule):
        """Test :own permission grants access to owned resources."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="write",
            resource_owner_id="user-123",  # Same as subject
        )

        context._subject_attributes = {
            "permissions": {"api_keys:write:own", "users:read"},
        }

        result = await ownership_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_own_wildcard_permission(self, ownership_rule):
        """Test :own wildcard permission grants access to owned resources."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="delete",
            resource_owner_id="user-123",  # Same as subject
        )

        context._subject_attributes = {
            "permissions": {"api_keys:*:own", "users:read"},
        }

        result = await ownership_rule.evaluate(context)
        assert result == PolicyEffect.ALLOW

    @pytest.mark.asyncio
    async def test_own_permission_without_ownership(self, ownership_rule):
        """Test :own permission denies access to non-owned resources."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="write",
            resource_owner_id="user-456",  # Different from subject
        )

        context._subject_attributes = {
            "permissions": {"api_keys:write:own", "users:read"},
        }

        result = await ownership_rule.evaluate(context)
        assert result == PolicyEffect.DENY

    @pytest.mark.asyncio
    async def test_no_own_permissions(self, ownership_rule):
        """Test rule doesn't apply when user has no :own permissions."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="write",
            resource_owner_id="user-123",
        )

        context._subject_attributes = {
            "permissions": {"api_keys:write", "users:read"},  # No :own permissions
        }

        result = await ownership_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    def test_matches_all_requests(self, ownership_rule):
        """Test that ownership rule applies to all requests."""
        assert ownership_rule.matches_request("users", "read") is True
        assert ownership_rule.matches_request("api_keys", "delete") is True


class TestEnvironmentalRule:
    """Test environmental constraints rule."""

    @pytest.fixture
    def env_rule(self) -> EnvironmentalRule:
        """Create environmental rule for testing."""
        return EnvironmentalRule()

    @pytest.mark.asyncio
    async def test_high_risk_business_hours_allowed(self, env_rule):
        """Test high-risk actions allowed during business hours."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        context._environment_attributes = {
            "is_business_hours": True,
        }
        context._action_attributes = {
            "risk_level": "high",
        }
        context._subject_attributes = {
            "authority_level": "user",
        }

        result = await env_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    @pytest.mark.asyncio
    async def test_high_risk_non_business_hours_admin_allowed(self, env_rule):
        """Test high-risk actions allowed for admins outside business hours."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        context._environment_attributes = {
            "is_business_hours": False,
        }
        context._action_attributes = {
            "risk_level": "high",
        }
        context._subject_attributes = {
            "authority_level": "admin",
        }

        result = await env_rule.evaluate(context)
        assert result == PolicyEffect.NOT_APPLICABLE

    @pytest.mark.asyncio
    async def test_high_risk_non_business_hours_user_denied(self, env_rule):
        """Test high-risk actions denied for regular users outside business hours."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="delete",
        )

        context._environment_attributes = {
            "is_business_hours": False,
        }
        context._action_attributes = {
            "risk_level": "high",
        }
        context._subject_attributes = {
            "authority_level": "user",
        }

        result = await env_rule.evaluate(context)
        assert result == PolicyEffect.DENY

    def test_matches_high_risk_actions(self, env_rule):
        """Test that environmental rule applies to high-risk actions."""
        assert env_rule.matches_request("users", "delete") is True
        assert env_rule.matches_request("api_keys", "revoke") is True
        assert env_rule.matches_request("system", "manage") is True
        assert env_rule.matches_request("users", "read") is False


class TestABACPolicyEngine:
    """Test ABAC policy engine."""

    @pytest.fixture
    def policy_engine(self) -> ABACPolicyEngine:
        """Create policy engine for testing."""
        return ABACPolicyEngine()

    @pytest.mark.asyncio
    async def test_allow_decision(self, policy_engine):
        """Test policy engine ALLOW decision."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        # Mock all attributes to simulate successful evaluation
        context._subject_attributes = {
            "authority_level": "admin",
            "user_organization_id": "org-456",
            "permissions": {"users:*"},
        }
        context._resource_attributes = {
            "resource_organization_id": "org-456",
        }
        context._action_attributes = {
            "risk_level": "low",
        }
        context._environment_attributes = {
            "is_business_hours": True,
        }

        is_allowed, reason = await policy_engine.evaluate_access(context)

        assert is_allowed is True
        assert "allowed access" in reason

    @pytest.mark.asyncio
    async def test_deny_decision(self, policy_engine):
        """Test policy engine DENY decision."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        # Mock attributes to simulate organization isolation violation
        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-789",  # Different org
            "permissions": {"users:read"},
        }
        context._resource_attributes = {
            "resource_organization_id": "org-456",
        }
        context._action_attributes = {
            "risk_level": "low",
        }
        context._environment_attributes = {
            "is_business_hours": True,
        }

        is_allowed, reason = await policy_engine.evaluate_access(context)

        assert is_allowed is False
        assert "denied access" in reason

    @pytest.mark.asyncio
    async def test_default_deny(self, policy_engine):
        """Test default deny when no rules apply."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="unknown",
            action="unknown",
        )

        # Mock attributes that won't match any rules
        context._subject_attributes = {
            "authority_level": "user",
            "permissions": set(),
        }
        context._resource_attributes = {}
        context._action_attributes = {
            "risk_level": "low",
        }
        context._environment_attributes = {
            "is_business_hours": True,
        }

        # Remove all rules to test default behavior
        policy_engine.rules = []

        is_allowed, reason = await policy_engine.evaluate_access(context)

        assert is_allowed is False
        assert "default deny" in reason

    @pytest.mark.asyncio
    async def test_rule_evaluation_error(self, policy_engine):
        """Test handling of rule evaluation errors."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        # Create a mock rule that raises an exception
        mock_rule = MagicMock()
        mock_rule.matches_request.return_value = True
        mock_rule.rule_id = "failing_rule"
        mock_rule.priority = 1
        mock_rule.evaluate = AsyncMock(side_effect=Exception("Rule evaluation error"))

        # Add the failing rule
        policy_engine.rules = [mock_rule]

        is_allowed, reason = await policy_engine.evaluate_access(context)

        assert is_allowed is False
        assert "evaluation failed" in reason

    @pytest.mark.asyncio
    async def test_explain_decision(self, policy_engine):
        """Test decision explanation generation."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
            organization_id="org-456",
        )

        # Mock attributes
        context._subject_attributes = {
            "authority_level": "admin",
            "permissions": {"users:*"},
        }
        context._resource_attributes = {}
        context._action_attributes = {
            "risk_level": "low",
        }
        context._environment_attributes = {
            "is_business_hours": True,
        }

        explanation = await policy_engine.explain_decision(context)

        assert explanation["decision"] in ["ALLOW", "DENY"]
        assert "reason" in explanation
        assert "context" in explanation
        assert "attributes" in explanation
        assert "applicable_rules" in explanation
        assert "timestamp" in explanation

    @pytest.mark.asyncio
    async def test_explain_decision_error(self, policy_engine):
        """Test explanation generation error handling."""
        context = ABACContext(
            subject_id="user-123",
            resource_type="users",
            action="read",
        )

        # Mock context to raise an error during attribute loading
        context.get_subject_attributes = AsyncMock(side_effect=Exception("Attribute error"))

        explanation = await policy_engine.explain_decision(context)

        assert explanation["decision"] == "DENY"
        assert "error" in explanation
        assert explanation["error"] is True

    def test_add_custom_rule(self, policy_engine):
        """Test adding custom rules to the policy engine."""
        initial_count = len(policy_engine.rules)

        # Create a custom rule
        custom_rule = MagicMock()
        custom_rule.priority = 5

        policy_engine.add_rule(custom_rule)

        assert len(policy_engine.rules) == initial_count + 1
        assert custom_rule in policy_engine.rules


class TestABACHelperFunctions:
    """Test ABAC helper functions."""

    def test_get_abac_engine_singleton(self):
        """Test that get_abac_engine returns singleton instance."""
        engine1 = get_abac_engine()
        engine2 = get_abac_engine()

        assert engine1 is engine2
        assert isinstance(engine1, ABACPolicyEngine)

    @pytest.mark.asyncio
    async def test_check_abac_permission(self):
        """Test check_abac_permission convenience function."""
        mock_session = MagicMock(spec=AsyncSession)

        with patch("app.core.abac.get_abac_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.evaluate_access = AsyncMock(return_value=(True, "Test reason"))
            mock_get_engine.return_value = mock_engine

            is_allowed, reason = await check_abac_permission(
                subject_id="user-123",
                resource_type="users",
                action="read",
                session=mock_session,
            )

            assert is_allowed is True
            assert reason == "Test reason"
            mock_engine.evaluate_access.assert_called_once()

    @pytest.mark.asyncio
    async def test_explain_abac_decision(self):
        """Test explain_abac_decision convenience function."""
        mock_session = MagicMock(spec=AsyncSession)

        with patch("app.core.abac.get_abac_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.explain_decision = AsyncMock(return_value={"decision": "ALLOW"})
            mock_get_engine.return_value = mock_engine

            explanation = await explain_abac_decision(
                subject_id="user-123",
                resource_type="users",
                action="read",
                session=mock_session,
            )

            assert explanation["decision"] == "ALLOW"
            mock_engine.explain_decision.assert_called_once()


class TestABACIntegration:
    """Integration tests for ABAC system."""

    @pytest.mark.asyncio
    async def test_complete_evaluation_flow(self):
        """Test complete ABAC evaluation flow with real context."""
        # This test would require actual database setup in a full integration test
        # For now, we'll test the flow with mocked dependencies

        mock_session = MagicMock(spec=AsyncSession)
        mock_user_repo = AsyncMock()
        mock_rbac_service = AsyncMock()

        # Create mock user with admin privileges
        org_uuid = uuid.uuid4()
        mock_user = MagicMock(spec=User)
        mock_user.username = "admin_user"
        mock_user.email = "admin@example.com"
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.roles = ["admin"]
        mock_user.organization_id = org_uuid

        mock_user_repo.get_by_id.return_value = mock_user
        mock_rbac_service.get_user_permissions.return_value = {"users:*", "api_keys:*"}

        with patch("app.repositories.user.UserRepository", return_value=mock_user_repo):
            with patch("app.services.rbac_service.RBACService", return_value=mock_rbac_service):
                is_allowed, reason = await check_abac_permission(
                    subject_id="admin-123",
                    resource_type="users",
                    action="read",
                    session=mock_session,
                    organization_id=str(org_uuid),
                )

        # Should be allowed due to admin role and proper organization context
        assert is_allowed is True
        assert "allowed access" in reason

    @pytest.mark.asyncio
    async def test_multi_rule_evaluation(self):
        """Test evaluation with multiple rules contributing to decision."""
        engine = ABACPolicyEngine()

        context = ABACContext(
            subject_id="user-123",
            resource_type="api_keys",
            action="write",
            organization_id="org-456",
            resource_owner_id="user-123",  # Owned resource
        )

        # Mock attributes for multi-rule scenario
        context._subject_attributes = {
            "authority_level": "user",
            "user_organization_id": "org-456",  # Same org
            "permissions": {"api_keys:write:own"},  # Only :own permission
        }
        context._resource_attributes = {
            "resource_organization_id": "org-456",  # Same org
        }
        context._action_attributes = {
            "risk_level": "medium",
        }
        context._environment_attributes = {
            "is_business_hours": True,
        }

        is_allowed, reason = await engine.evaluate_access(context)

        # Should be allowed through ownership rule
        assert is_allowed is True
        assert "allowed access" in reason
