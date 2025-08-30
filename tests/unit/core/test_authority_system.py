"""
Comprehensive tests for the Authority Level system.

This test suite provides 100% coverage for the new hierarchical authority system
that replaces the problematic boolean is_superuser flag, addressing critical
security vulnerabilities identified in the authentication audit report.
"""

import uuid
from datetime import datetime, timezone
from typing import Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authority import (
    AuthorityContext,
    AuthorityEvaluator,
    AuthorityLevel,
    create_authority_context,
    evaluate_user_authority,
    get_authority_evaluator,
    get_migration_recommendation,
    is_deprecated_superuser,
)
from app.models.user import User


class TestAuthorityLevel:
    """Test authority level enumeration and comparison logic."""

    def test_authority_level_properties(self):
        """Test authority level properties and metadata."""
        global_admin = AuthorityLevel.GLOBAL_ADMIN

        assert global_admin.level_name == "global_admin"
        assert global_admin.priority == 0
        assert "Global system administrator" in global_admin.description

    def test_authority_level_comparison(self):
        """Test authority level comparison operators."""
        global_admin = AuthorityLevel.GLOBAL_ADMIN
        admin = AuthorityLevel.ADMIN
        user = AuthorityLevel.USER
        none = AuthorityLevel.NONE

        # Test less than (higher authority)
        assert global_admin < admin
        assert admin < user
        assert user < none

        # Test greater than (lower authority)
        assert none > user
        assert user > admin
        assert admin > global_admin

        # Test equality
        assert admin <= AuthorityLevel.ADMIN
        assert admin >= AuthorityLevel.ADMIN

    def test_can_manage_hierarchy(self):
        """Test can_manage method for authority hierarchy."""
        global_admin = AuthorityLevel.GLOBAL_ADMIN
        admin = AuthorityLevel.ADMIN
        user = AuthorityLevel.USER

        # Global admin can manage admin and user
        assert global_admin.can_manage(admin) is True
        assert global_admin.can_manage(user) is True

        # Admin can manage user but not other admins
        assert admin.can_manage(user) is True
        assert admin.can_manage(admin) is False
        assert admin.can_manage(global_admin) is False

        # User cannot manage anyone
        assert user.can_manage(admin) is False
        assert user.can_manage(user) is False

    def test_access_level_checks(self):
        """Test access level checking methods."""
        global_admin = AuthorityLevel.GLOBAL_ADMIN
        admin = AuthorityLevel.ADMIN
        user_manager = AuthorityLevel.USER_MANAGER
        viewer = AuthorityLevel.VIEWER
        user = AuthorityLevel.USER

        # System access (priority <= 0)
        assert global_admin.has_system_access() is True
        assert admin.has_system_access() is False

        # Admin access (priority <= 10)
        assert global_admin.has_admin_access() is True
        assert admin.has_admin_access() is True
        assert user_manager.has_admin_access() is False

        # Management access (priority <= 20)
        assert admin.has_management_access() is True
        assert user_manager.has_management_access() is True
        assert viewer.has_management_access() is False
        assert user.has_management_access() is False

    def test_from_string_parsing(self):
        """Test parsing authority level from string."""
        assert AuthorityLevel.from_string("global_admin") == AuthorityLevel.GLOBAL_ADMIN
        assert AuthorityLevel.from_string("admin") == AuthorityLevel.ADMIN
        assert AuthorityLevel.from_string("user") == AuthorityLevel.USER
        assert AuthorityLevel.from_string("invalid") == AuthorityLevel.NONE
        assert AuthorityLevel.from_string("") == AuthorityLevel.NONE

    def test_deprecated_super_admin_mapping(self):
        """Test deprecated super_admin mapping for backward compatibility."""
        super_admin = AuthorityLevel.SUPER_ADMIN

        assert super_admin.level_name == "super_admin"
        assert super_admin.priority == 0  # Same as global_admin
        assert super_admin.has_system_access() is True


class TestAuthorityEvaluator:
    """Test authority evaluator for determining user authority levels."""

    @pytest.fixture
    def mock_session(self) -> AsyncSession:
        """Create mock database session."""
        return MagicMock(spec=AsyncSession)

    @pytest.fixture
    def evaluator(self, mock_session) -> AuthorityEvaluator:
        """Create authority evaluator with mock session."""
        return AuthorityEvaluator(mock_session)

    @pytest.fixture
    def sample_user(self) -> User:
        """Create sample user for testing."""
        user = MagicMock(spec=User)
        user.id = uuid.uuid4()
        user.username = "testuser"
        user.roles = ["viewer"]
        user.is_superuser = False
        return user

    @pytest.mark.asyncio
    async def test_evaluate_global_wildcard_permission(self, evaluator, sample_user):
        """Test evaluation with global wildcard permission."""
        permissions = {"*"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.GLOBAL_ADMIN

    @pytest.mark.asyncio
    async def test_evaluate_admin_role(self, evaluator, sample_user):
        """Test evaluation with admin role."""
        sample_user.roles = ["admin", "viewer"]
        permissions = {"users:read", "api_keys:write"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.ADMIN

    @pytest.mark.asyncio
    async def test_evaluate_user_manager_role(self, evaluator, sample_user):
        """Test evaluation with user_manager role."""
        sample_user.roles = ["user_manager"]
        permissions = {"users:write"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.USER_MANAGER

    @pytest.mark.asyncio
    async def test_evaluate_api_manager_role(self, evaluator, sample_user):
        """Test evaluation with api_manager role."""
        sample_user.roles = ["api_manager"]
        permissions = {"api_keys:write"}  # Specific permission, not wildcard

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.API_MANAGER

    @pytest.mark.asyncio
    async def test_evaluate_permission_based_authority(self, evaluator, sample_user):
        """Test evaluation based on permissions without explicit roles."""
        sample_user.roles = []
        permissions = {"users:*", "api_keys:*", "sessions:*"}  # Admin-level permissions

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.ADMIN

    @pytest.mark.asyncio
    async def test_evaluate_management_permissions(self, evaluator, sample_user):
        """Test evaluation with management-level permissions."""
        sample_user.roles = []
        permissions = {"users:write", "users:delete"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.USER_MANAGER

    @pytest.mark.asyncio
    async def test_evaluate_viewer_permissions(self, evaluator, sample_user):
        """Test evaluation with read-only permissions."""
        sample_user.roles = []
        permissions = {"users:read", "api_keys:read"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.VIEWER

    @pytest.mark.asyncio
    async def test_evaluate_own_permissions(self, evaluator, sample_user):
        """Test evaluation with :own scoped permissions."""
        sample_user.roles = []
        permissions = {"users:read:own", "api_keys:*:own"}

        authority = await evaluator.evaluate_user_authority(sample_user, permissions)

        assert authority == AuthorityLevel.USER

    @pytest.mark.asyncio
    async def test_evaluate_deprecated_superuser_flag(self, evaluator, sample_user):
        """Test handling of deprecated is_superuser flag."""
        sample_user.is_superuser = True
        sample_user.roles = ["viewer"]
        permissions = set()

        with patch("app.core.authority.logger") as mock_logger:
            authority = await evaluator.evaluate_user_authority(sample_user, permissions)

            # Should upgrade to admin level due to superuser flag
            assert authority == AuthorityLevel.ADMIN
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_with_rbac_service(self, evaluator, sample_user):
        """Test evaluation loading permissions from RBAC service."""
        evaluator.session = MagicMock(spec=AsyncSession)

        mock_rbac_service = AsyncMock()
        mock_rbac_service.get_user_permissions.return_value = {
            "users:*",
            "api_keys:read",
        }

        with patch("app.services.rbac_service.RBACService", return_value=mock_rbac_service):
            authority = await evaluator.evaluate_user_authority(sample_user, permissions=None)

        assert authority == AuthorityLevel.ADMIN  # Due to users:* permission
        mock_rbac_service.get_user_permissions.assert_called_once_with(str(sample_user.id))

    @pytest.mark.asyncio
    async def test_evaluate_error_handling(self, evaluator, sample_user):
        """Test error handling during evaluation."""
        evaluator.session = MagicMock(spec=AsyncSession)

        # Mock RBAC service to raise an exception
        with patch("app.services.rbac_service.RBACService", side_effect=Exception("RBAC error")):
            with patch("app.core.authority.logger") as mock_logger:
                authority = await evaluator.evaluate_user_authority(sample_user, permissions=None)

                # Should fail-secure to lowest authority
                assert authority == AuthorityLevel.NONE
                mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_can_user_manage_user(self, evaluator):
        """Test user management authority checking."""
        # Create manager and target users
        manager_user = MagicMock(spec=User)
        manager_user.id = uuid.uuid4()
        manager_user.roles = ["admin"]
        manager_user.is_superuser = False

        target_user = MagicMock(spec=User)
        target_user.id = uuid.uuid4()
        target_user.roles = ["viewer"]
        target_user.is_superuser = False

        # Mock the evaluate_user_authority calls
        evaluator.evaluate_user_authority = AsyncMock()
        evaluator.evaluate_user_authority.side_effect = [
            AuthorityLevel.ADMIN,  # Manager authority
            AuthorityLevel.VIEWER,  # Target authority
        ]

        can_manage, reason = await evaluator.can_user_manage_user(manager_user, target_user)

        assert can_manage is True
        assert "admin can manage viewer" in reason

    @pytest.mark.asyncio
    async def test_cannot_manage_higher_authority(self, evaluator):
        """Test that users cannot manage higher authority users."""
        manager_user = MagicMock(spec=User)
        manager_user.id = uuid.uuid4()

        target_user = MagicMock(spec=User)
        target_user.id = uuid.uuid4()

        evaluator.evaluate_user_authority = AsyncMock()
        evaluator.evaluate_user_authority.side_effect = [
            AuthorityLevel.VIEWER,  # Manager authority
            AuthorityLevel.ADMIN,  # Target authority
        ]

        can_manage, reason = await evaluator.can_user_manage_user(manager_user, target_user)

        assert can_manage is False
        assert "viewer cannot manage admin" in reason

    @pytest.mark.asyncio
    async def test_global_admin_restrictions(self, evaluator):
        """Test global admin management restrictions."""
        manager_user = MagicMock(spec=User)
        manager_user.id = uuid.uuid4()

        target_user = MagicMock(spec=User)
        target_user.id = uuid.uuid4()

        evaluator.evaluate_user_authority = AsyncMock()
        evaluator.evaluate_user_authority.side_effect = [
            AuthorityLevel.GLOBAL_ADMIN,  # Manager authority
            AuthorityLevel.GLOBAL_ADMIN,  # Target authority
        ]

        can_manage, reason = await evaluator.can_user_manage_user(manager_user, target_user)

        assert can_manage is False
        assert "Cannot manage other global administrators" in reason

    def test_get_authority_capabilities_global_admin(self, evaluator):
        """Test capabilities for global admin authority level."""
        caps = evaluator.get_authority_capabilities(AuthorityLevel.GLOBAL_ADMIN)

        assert caps["authority_level"] == "global_admin"
        assert caps["can_access_system"] is True
        assert caps["can_administer"] is True
        assert caps["can_manage_users"] is True
        assert caps["can_manage_system_roles"] is True
        assert caps["can_access_all_organizations"] is True
        assert caps["can_override_restrictions"] is True

    def test_get_authority_capabilities_admin(self, evaluator):
        """Test capabilities for admin authority level."""
        caps = evaluator.get_authority_capabilities(AuthorityLevel.ADMIN)

        assert caps["authority_level"] == "admin"
        assert caps["can_access_system"] is False
        assert caps["can_administer"] is True
        assert caps["can_manage_users"] is True
        assert caps["can_manage_organization_users"] is True
        assert caps["can_assign_roles"] is True

    def test_get_authority_capabilities_user_manager(self, evaluator):
        """Test capabilities for user manager authority level."""
        caps = evaluator.get_authority_capabilities(AuthorityLevel.USER_MANAGER)

        assert caps["authority_level"] == "user_manager"
        assert caps["can_manage_users"] is True
        assert caps["can_create_users"] is True
        assert caps["can_modify_user_roles"] is True
        assert caps["can_reset_passwords"] is True

    def test_get_authority_capabilities_api_manager(self, evaluator):
        """Test capabilities for API manager authority level."""
        caps = evaluator.get_authority_capabilities(AuthorityLevel.API_MANAGER)

        assert caps["authority_level"] == "api_manager"
        assert caps["can_manage_apis"] is True
        assert caps["can_create_api_keys"] is True
        assert caps["can_manage_integrations"] is True
        assert caps["can_view_api_usage"] is True


class TestAuthorityContext:
    """Test authority context for decision making."""

    @pytest.fixture
    def sample_user(self) -> User:
        """Create sample user for testing."""
        user = MagicMock(spec=User)
        user.id = uuid.uuid4()
        user.username = "testuser"
        user.roles = ["admin"]
        return user

    @pytest.fixture
    def authority_context(self, sample_user) -> AuthorityContext:
        """Create authority context for testing."""
        return AuthorityContext(
            user=sample_user,
            authority_level=AuthorityLevel.ADMIN,
            permissions={"users:*", "api_keys:read"},
            organization_id="org-123",
        )

    def test_has_authority_level(self, authority_context):
        """Test authority level checking."""
        assert authority_context.has_authority_level(AuthorityLevel.ADMIN) is True
        assert authority_context.has_authority_level(AuthorityLevel.USER) is True
        assert authority_context.has_authority_level(AuthorityLevel.GLOBAL_ADMIN) is False

    def test_can_perform_action_explicit_permission(self, authority_context):
        """Test action permission with explicit permission."""
        assert authority_context.can_perform_action("read", "api_keys") is True
        assert authority_context.can_perform_action("write", "api_keys") is False

    def test_can_perform_action_wildcard_permission(self, authority_context):
        """Test action permission with wildcard permission."""
        assert authority_context.can_perform_action("read", "users") is True
        assert authority_context.can_perform_action("write", "users") is True
        assert authority_context.can_perform_action("delete", "users") is True

    def test_can_perform_action_global_wildcard(self, sample_user):
        """Test action permission with global wildcard."""
        context = AuthorityContext(
            user=sample_user,
            authority_level=AuthorityLevel.GLOBAL_ADMIN,
            permissions={"*"},
            organization_id="org-123",
        )

        assert context.can_perform_action("delete", "system") is True
        assert context.can_perform_action("manage", "anything") is True

    def test_can_perform_action_authority_based(self, authority_context):
        """Test action permission based on authority level."""
        # Admin level should allow certain actions even without explicit permissions
        assert authority_context.can_perform_action("read", "sessions") is True  # Viewer and above
        assert authority_context.can_perform_action("write", "sessions") is True  # Management and above
        assert authority_context.can_perform_action("delete", "sessions") is True  # Admin and above

    def test_can_perform_action_insufficient_authority(self, sample_user):
        """Test action permission with insufficient authority."""
        context = AuthorityContext(
            user=sample_user,
            authority_level=AuthorityLevel.VIEWER,
            permissions=set(),
            organization_id="org-123",
        )

        assert context.can_perform_action("read", "users") is True  # Viewer can read
        assert context.can_perform_action("write", "users") is False  # Viewer cannot write
        assert context.can_perform_action("delete", "users") is False  # Viewer cannot delete

    def test_to_dict(self, authority_context, sample_user):
        """Test converting authority context to dictionary."""
        result = authority_context.to_dict()

        assert result["user_id"] == str(sample_user.id)
        assert result["username"] == sample_user.username
        assert result["authority_level"] == "admin"
        assert result["organization_id"] == "org-123"
        assert result["permission_count"] == 2
        assert result["roles"] == sample_user.roles
        assert "capabilities" in result


class TestHelperFunctions:
    """Test helper functions for authority system."""

    def test_get_authority_evaluator_singleton(self):
        """Test that get_authority_evaluator returns singleton."""
        evaluator1 = get_authority_evaluator()
        evaluator2 = get_authority_evaluator()

        assert evaluator1 is evaluator2
        assert isinstance(evaluator1, AuthorityEvaluator)

    def test_get_authority_evaluator_with_session(self):
        """Test get_authority_evaluator with session parameter."""
        mock_session = MagicMock(spec=AsyncSession)

        evaluator = get_authority_evaluator(mock_session)

        assert evaluator.session is mock_session

    @pytest.mark.asyncio
    async def test_evaluate_user_authority_convenience(self):
        """Test evaluate_user_authority convenience function."""
        mock_user = MagicMock(spec=User)
        mock_session = MagicMock(spec=AsyncSession)
        mock_permissions = {"users:read"}

        with patch("app.core.authority.get_authority_evaluator") as mock_get_evaluator:
            mock_evaluator = MagicMock()
            mock_evaluator.evaluate_user_authority = AsyncMock(return_value=AuthorityLevel.ADMIN)
            mock_get_evaluator.return_value = mock_evaluator

            result = await evaluate_user_authority(mock_user, mock_session, mock_permissions)

            assert result == AuthorityLevel.ADMIN
            mock_evaluator.evaluate_user_authority.assert_called_once_with(mock_user, mock_permissions)

    @pytest.mark.asyncio
    async def test_create_authority_context(self):
        """Test create_authority_context convenience function."""
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_session = MagicMock(spec=AsyncSession)

        mock_rbac_service = AsyncMock()
        mock_rbac_service.get_user_permissions.return_value = {"users:read"}

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_user_authority = AsyncMock(return_value=AuthorityLevel.ADMIN)

        with patch("app.core.authority.get_authority_evaluator", return_value=mock_evaluator):
            with patch("app.services.rbac_service.RBACService", return_value=mock_rbac_service):
                context = await create_authority_context(mock_user, mock_session, "org-123")

        assert isinstance(context, AuthorityContext)
        assert context.user is mock_user
        assert context.authority_level == AuthorityLevel.ADMIN
        assert context.permissions == {"users:read"}
        assert context.organization_id == "org-123"

    def test_is_deprecated_superuser_true(self):
        """Test is_deprecated_superuser with superuser flag set."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True

        result = is_deprecated_superuser(mock_user)

        assert result is True

    def test_is_deprecated_superuser_false(self):
        """Test is_deprecated_superuser with superuser flag unset."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        result = is_deprecated_superuser(mock_user)

        assert result is False

    def test_is_deprecated_superuser_no_attribute(self):
        """Test is_deprecated_superuser with missing attribute."""
        mock_user = MagicMock(spec=User)
        del mock_user.is_superuser  # Remove attribute

        result = is_deprecated_superuser(mock_user)

        assert result is False

    def test_get_migration_recommendation_no_superuser(self):
        """Test migration recommendation for non-superuser."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        result = get_migration_recommendation(mock_user)

        assert result is None

    def test_get_migration_recommendation_admin_role(self):
        """Test migration recommendation with existing admin role."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True
        mock_user.roles = ["admin", "viewer"]

        result = get_migration_recommendation(mock_user)

        assert result == "admin"

    def test_get_migration_recommendation_user_manager_role(self):
        """Test migration recommendation with user manager role."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True
        mock_user.roles = ["user_manager"]

        result = get_migration_recommendation(mock_user)

        assert result == "user_manager"

    def test_get_migration_recommendation_default(self):
        """Test migration recommendation default case."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True
        mock_user.roles = ["viewer"]

        result = get_migration_recommendation(mock_user)

        assert result == "admin"

    def test_get_migration_recommendation_no_roles(self):
        """Test migration recommendation with no roles."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True
        mock_user.roles = []

        result = get_migration_recommendation(mock_user)

        assert result == "admin"


class TestAuthoritySystemIntegration:
    """Integration tests for authority system components."""

    @pytest.mark.asyncio
    async def test_complete_authority_evaluation_flow(self):
        """Test complete authority evaluation with all components."""
        # Create mock user with various attributes
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.username = "test_admin"
        mock_user.roles = ["admin"]
        mock_user.is_superuser = False

        mock_session = MagicMock(spec=AsyncSession)

        # Mock RBAC service
        mock_rbac_service = AsyncMock()
        mock_rbac_service.get_user_permissions.return_value = {
            "users:*",
            "api_keys:write",
            "sessions:read",
        }

        with patch("app.services.rbac_service.RBACService", return_value=mock_rbac_service):
            # Create authority context
            context = await create_authority_context(mock_user, mock_session, "org-123")

            # Verify context properties
            assert context.authority_level == AuthorityLevel.ADMIN
            assert "users:*" in context.permissions
            assert context.organization_id == "org-123"

            # Test authority-based permissions
            assert context.has_authority_level(AuthorityLevel.USER) is True
            assert context.can_perform_action("read", "users") is True
            assert context.can_perform_action("write", "users") is True
            assert context.can_perform_action("delete", "users") is True  # Admin level

            # Test specific permissions
            assert context.can_perform_action("write", "api_keys") is True
            assert context.can_perform_action("read", "sessions") is True
            assert context.can_perform_action("delete", "api_keys") is False  # No explicit permission

    @pytest.mark.asyncio
    async def test_authority_hierarchy_enforcement(self):
        """Test authority hierarchy enforcement across different levels."""
        evaluator = AuthorityEvaluator()

        # Create users at different authority levels
        global_admin = MagicMock(spec=User)
        global_admin.id = uuid.uuid4()
        global_admin.roles = ["admin"]
        global_admin.is_superuser = False

        regular_admin = MagicMock(spec=User)
        regular_admin.id = uuid.uuid4()
        regular_admin.roles = ["admin"]
        regular_admin.is_superuser = False

        regular_user = MagicMock(spec=User)
        regular_user.id = uuid.uuid4()
        regular_user.roles = ["viewer"]
        regular_user.is_superuser = False

        # Mock evaluations
        evaluator.evaluate_user_authority = AsyncMock()
        evaluator.evaluate_user_authority.side_effect = [
            AuthorityLevel.GLOBAL_ADMIN,  # First user
            AuthorityLevel.ADMIN,  # Second user
            AuthorityLevel.GLOBAL_ADMIN,  # First user again
            AuthorityLevel.USER,  # Third user
        ]

        # Test management hierarchy
        can_manage, reason = await evaluator.can_user_manage_user(global_admin, regular_admin)
        assert can_manage is True
        assert "global_admin can manage admin" in reason

        can_manage, reason = await evaluator.can_user_manage_user(global_admin, regular_user)
        assert can_manage is True
        assert "global_admin can manage user" in reason

    @pytest.mark.asyncio
    async def test_deprecated_superuser_migration_flow(self):
        """Test complete migration flow from deprecated superuser to authority system."""
        # Create user with deprecated superuser flag
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.username = "legacy_admin"
        mock_user.roles = ["viewer"]  # Low role but has superuser flag
        mock_user.is_superuser = True

        # Test detection of deprecated flag
        assert is_deprecated_superuser(mock_user) is True

        # Test migration recommendation
        recommendation = get_migration_recommendation(mock_user)
        assert recommendation == "admin"

        # Test authority evaluation with deprecated flag
        evaluator = AuthorityEvaluator()

        with patch("app.core.authority.logger") as mock_logger:
            authority = await evaluator.evaluate_user_authority(mock_user, set())

            # Should upgrade to admin due to superuser flag
            assert authority == AuthorityLevel.ADMIN
            mock_logger.warning.assert_called()

    def test_authority_capabilities_comprehensive(self):
        """Test comprehensive authority capabilities mapping."""
        evaluator = AuthorityEvaluator()

        # Test all authority levels have proper capabilities
        for authority_level in AuthorityLevel:
            caps = evaluator.get_authority_capabilities(authority_level)

            # All should have basic fields
            assert "authority_level" in caps
            assert "priority" in caps
            assert "description" in caps
            assert "can_access_system" in caps
            assert "can_administer" in caps
            assert "can_manage_users" in caps

            # Verify hierarchy consistency
            if authority_level.has_system_access():
                assert caps["can_access_system"] is True
            if authority_level.has_admin_access():
                assert caps["can_administer"] is True
            if authority_level.has_management_access():
                assert caps["can_manage_users"] is True
