"""Tests for organization-aware permission validation and ownership checking.

This module tests the critical security fix for :own scoped permissions
with proper multi-tenant isolation.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.rbac_service import RBACService


class TestOrganizationPermissionValidation:
    """Test organization-aware permission validation."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = Mock(spec=AsyncSession)
        session.execute = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        return session

    @pytest.fixture
    def rbac_service(self, mock_session):
        """Create RBAC service with mocked dependencies."""
        with patch("app.services.rbac_service.RoleRepository"), patch("app.services.rbac_service.UserRepository"):
            return RBACService(mock_session)

    @pytest.fixture
    def mock_user(self):
        """Create mock user object."""
        user = Mock(spec=User)
        user.id = "user-123"
        user.organization_id = "org-456"
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def user_permissions(self):
        """Standard user permissions set."""
        return {"users:read:own", "api_keys:*:own", "sessions:read:own"}

    async def test_check_organization_permission_with_own_scope_valid(self, rbac_service, mock_user, user_permissions):
        """Test organization permission check for valid :own scoped permission."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read:own"
        resource_owner_id = "user-123"  # Same as user_id

        # Mock get_user_permissions to return user permissions
        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)

        # Mock user repository to return user in correct organization
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify
        assert result is True
        rbac_service.get_user_permissions.assert_called_once_with(user_id)
        rbac_service.user_repository.get_by_id.assert_called_once_with(user_id, organization_id)

    async def test_check_organization_permission_with_own_scope_invalid_owner(
        self, rbac_service, mock_user, user_permissions
    ):
        """Test organization permission check fails when user doesn't own resource."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read:own"
        resource_owner_id = "different-user-789"  # Different from user_id

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify - should fail because user doesn't own the resource
        assert result is False

    async def test_check_organization_permission_missing_organization_context(self, rbac_service, user_permissions):
        """Test organization permission check fails without organization context."""
        # Setup
        user_id = "user-123"
        organization_id = None  # Missing organization context
        permission = "users:read:own"
        resource_owner_id = "user-123"

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify - should fail without organization context for :own permissions
        assert result is False

    async def test_check_organization_permission_user_not_in_organization(self, rbac_service, user_permissions):
        """Test organization permission check fails when user not in specified organization."""
        # Setup
        user_id = "user-123"
        organization_id = "org-different"  # Different organization
        permission = "users:read:own"
        resource_owner_id = "user-123"

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=None)  # User not found in org

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify - should fail when user not found in organization
        assert result is False

    async def test_check_organization_permission_non_own_scope(self, rbac_service, mock_user):
        """Test organization permission check for non-:own scoped permission."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read"  # No :own scope
        user_permissions = {"users:read"}

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id,
            permission=permission,
            organization_id=organization_id,
            resource_owner_id=None,  # Not needed for non-:own permissions
        )

        # Verify - should succeed for non-:own permissions
        assert result is True
        rbac_service.get_user_permissions.assert_called_once_with(user_id)

    async def test_check_organization_permission_admin_bypass(self, rbac_service):
        """Test that admin users bypass ownership validation."""
        # Setup
        user_id = "admin-user"
        organization_id = "org-456"
        permission = "users:read:own"
        resource_owner_id = "different-user-789"
        admin_permissions = {"*"}  # Global admin

        rbac_service.get_user_permissions = AsyncMock(return_value=admin_permissions)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify - admin should bypass ownership checks
        assert result is True

    async def test_check_organization_permission_wildcard_resource(self, rbac_service, mock_user):
        """Test organization permission with wildcard resource permissions."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read:own"
        resource_owner_id = "user-123"
        wildcard_permissions = {"users:*"}  # Wildcard for users resource

        rbac_service.get_user_permissions = AsyncMock(return_value=wildcard_permissions)
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify - wildcard should match with ownership validation
        assert result is True

    async def test_check_organization_permission_broader_permission_covers_own(self, rbac_service):
        """Test that broader permissions cover :own scoped permissions."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read:own"  # Requesting :own scope
        broader_permissions = {"users:read"}  # Has broader permission

        rbac_service.get_user_permissions = AsyncMock(return_value=broader_permissions)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id="user-123"
        )

        # Verify - broader permission should cover :own scope
        assert result is True

    async def test_validate_ownership_context_success(self, rbac_service, mock_user):
        """Test successful ownership context validation."""
        # Setup
        user_id = "user-123"
        resource_owner_id = "user-123"
        organization_id = "org-456"

        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service._validate_ownership_context(
            user_id=user_id, resource_owner_id=resource_owner_id, organization_id=organization_id
        )

        # Verify
        assert result is True
        rbac_service.user_repository.get_by_id.assert_called_once_with(user_id, organization_id)

    async def test_validate_ownership_context_missing_organization(self, rbac_service):
        """Test ownership context validation fails without organization."""
        # Setup
        user_id = "user-123"
        resource_owner_id = "user-123"
        organization_id = None  # Missing organization

        # Execute
        result = await rbac_service._validate_ownership_context(
            user_id=user_id, resource_owner_id=resource_owner_id, organization_id=organization_id
        )

        # Verify
        assert result is False

    async def test_validate_ownership_context_missing_resource_owner(self, rbac_service):
        """Test ownership context validation fails without resource owner."""
        # Setup
        user_id = "user-123"
        resource_owner_id = None  # Missing resource owner
        organization_id = "org-456"

        # Execute
        result = await rbac_service._validate_ownership_context(
            user_id=user_id, resource_owner_id=resource_owner_id, organization_id=organization_id
        )

        # Verify
        assert result is False

    async def test_validate_ownership_context_user_not_owner(self, rbac_service):
        """Test ownership context validation fails when user doesn't own resource."""
        # Setup
        user_id = "user-123"
        resource_owner_id = "different-user-789"
        organization_id = "org-456"

        # Execute
        result = await rbac_service._validate_ownership_context(
            user_id=user_id, resource_owner_id=resource_owner_id, organization_id=organization_id
        )

        # Verify
        assert result is False

    async def test_validate_ownership_context_user_not_in_organization(self, rbac_service):
        """Test ownership context validation fails when user not in organization."""
        # Setup
        user_id = "user-123"
        resource_owner_id = "user-123"
        organization_id = "org-456"

        rbac_service.user_repository.get_by_id = AsyncMock(return_value=None)  # User not found

        # Execute
        result = await rbac_service._validate_ownership_context(
            user_id=user_id, resource_owner_id=resource_owner_id, organization_id=organization_id
        )

        # Verify
        assert result is False

    @pytest.mark.parametrize(
        "permission,expected",
        [
            ("users:read:own", True),  # Exact match with ownership
            ("api_keys:write:own", True),  # Wildcard match with ownership
            ("sessions:write:own", False),  # No permission for write
            ("users:delete:own", False),  # No delete permission
            ("invalid:format", False),  # Invalid permission format
        ],
    )
    async def test_permission_validation_scenarios(
        self, rbac_service, mock_user, user_permissions, permission, expected
    ):
        """Test various permission validation scenarios."""
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        resource_owner_id = "user-123"

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # Verify
        assert result is expected

    async def test_critical_security_fix_validation(self, rbac_service, mock_user, user_permissions):
        """Test that verifies the critical security fix for :own permissions.

        This test specifically validates that :own scoped permissions now properly
        validate both ownership AND organization membership, fixing the critical
        multi-tenant isolation vulnerability.
        """
        # Setup
        user_id = "user-123"
        organization_id = "org-456"
        permission = "users:read:own"
        resource_owner_id = "user-123"

        rbac_service.get_user_permissions = AsyncMock(return_value=user_permissions)
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=mock_user)

        # Execute
        result = await rbac_service.check_organization_permission(
            user_id=user_id, permission=permission, organization_id=organization_id, resource_owner_id=resource_owner_id
        )

        # CRITICAL: Verify the security fix is implemented
        assert result is True, "CRITICAL SECURITY BUG: Valid :own permission check failed"

        # Verify organization validation was called
        rbac_service.user_repository.get_by_id.assert_called_with(user_id, organization_id)

        # Test cross-tenant access prevention
        rbac_service.user_repository.get_by_id = AsyncMock(return_value=None)  # User not in org

        result = await rbac_service.check_organization_permission(
            user_id=user_id,
            permission=permission,
            organization_id="different-org",  # Different organization
            resource_owner_id=resource_owner_id,
        )

        assert result is False, "CRITICAL SECURITY BUG: Cross-tenant access not prevented"
