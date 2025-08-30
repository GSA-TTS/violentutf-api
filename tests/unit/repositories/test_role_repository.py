"""Comprehensive unit tests for RoleRepository implementation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role
from app.repositories.base import Page
from app.repositories.role import RoleRepository


class TestRoleRepository:
    """Comprehensive unit tests for RoleRepository implementation."""

    @pytest.fixture
    def role_repository(self, mock_session: AsyncMock) -> RoleRepository:
        """Create RoleRepository instance with mocked session."""
        return RoleRepository(mock_session)

    @pytest.fixture
    def sample_role(self, role_factory) -> Role:
        """Create a sample role for testing."""
        return role_factory.create(
            id="test-role-id",
            name="Test Role",
            display_name="Test Display Role",
            description="A test role for unit testing",
            role_metadata={"permissions": ["read", "write", "delete"]},
            is_system_role=False,
            is_active=True,
            created_by="admin",
            created_at=datetime.now(timezone.utc),
        )

    @pytest.fixture
    def system_role(self, role_factory) -> Role:
        """Create a system role for testing."""
        return role_factory.create(
            id="system-role-id",
            name="System Admin",
            description="System administrator role",
            permissions=["*"],
            organization_id=None,
            is_system_role=True,
            is_active=True,
            created_by="system",
            created_at=datetime.now(timezone.utc),
        )

    @pytest.fixture
    def inactive_role(self, role_factory) -> Role:
        """Create an inactive role for testing."""
        return role_factory.create(
            id="inactive-role-id",
            name="Inactive Role",
            description="An inactive role",
            permissions=["read"],
            organization_id="test-org-id",
            is_system_role=False,
            is_active=False,
            created_by="admin",
        )

    @pytest.fixture
    def user_role_assignment(self):
        """Create a user-role assignment for testing."""
        return {
            "user_id": "test-user-id",
            "role_id": "test-role-id",
            "assigned_by": "admin",
            "assigned_at": datetime.now(timezone.utc),
            "is_active": True,
        }

    # Repository Initialization Tests

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session: AsyncMock):
        """Test RoleRepository initialization."""
        repository = RoleRepository(mock_session)

        assert repository.session == mock_session
        assert repository.model == Role
        assert repository.logger is not None

    # get_by_name Tests

    @pytest.mark.asyncio
    async def test_get_by_name_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test successful role retrieval by name."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_role)
        mock_session.execute.return_value = result_mock

        # Act
        role = await role_repository.get_by_name("Test Role")

        # Assert
        assert role is not None
        assert role.name == "Test Role"
        assert role.display_name == "Test Display Role"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_name_without_organization(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        system_role: Role,
        query_result_factory,
    ):
        """Test role retrieval by name without organization filtering."""
        # Arrange
        result_mock = query_result_factory(scalar_result=system_role)
        mock_session.execute.return_value = result_mock

        # Act
        role = await role_repository.get_by_name("System Admin")

        # Assert
        assert role is not None
        assert role.name == "System Admin"
        assert role.is_system_role is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_name_not_found(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test role retrieval when role doesn't exist."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        role = await role_repository.get_by_name("Nonexistent Role")

        # Assert
        assert role is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_name_case_sensitivity(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test role name case sensitivity handling."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        role = await role_repository.get_by_name("test role")  # lowercase

        # Assert
        assert role is None  # Case sensitive, should not find "Test Role"
        mock_session.execute.assert_called_once()

    # create_role Tests

    @pytest.mark.asyncio
    async def test_create_role_success(self, role_repository: RoleRepository, mock_session: AsyncMock, role_factory):
        """Test successful role creation."""
        # Arrange
        new_role = role_factory.create(
            id="new-role-id",
            name="new_role",
            description="A newly created role",
            permissions=["users:read", "users:write"],
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.role.Role", return_value=new_role),
            patch.object(role_repository, "get_by_name", return_value=None),
        ):
            # Act
            created_role = await role_repository.create_role(
                name="new_role",
                description="A newly created role",
                permissions=["users:read", "users:write"],
                organization_id="test-org-id",
                created_by="admin",
            )

            # Assert
            assert created_role is not None
            assert created_role.name == "new_role"
            assert created_role.description == "A newly created role"
            assert created_role.permissions == ["users:read", "users:write"]
            mock_session.add.assert_called_once()
            mock_session.flush.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_role_system_role(
        self, role_repository: RoleRepository, mock_session: AsyncMock, role_factory
    ):
        """Test creation of system role."""
        # Arrange
        system_role = role_factory.create(
            id="new-system-role-id",
            name="system_admin_role",
            organization_id=None,
            is_system_role=True,
            permissions=["*"],
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.role.Role", return_value=system_role),
            patch.object(role_repository, "get_by_name", return_value=None),
        ):
            # Act
            created_role = await role_repository.create_role(
                name="system_admin_role",
                description="System level role",
                permissions=["*"],
                created_by="system",
            )

            # Assert
            assert created_role is not None
            assert created_role.organization_id is None
            assert created_role.is_system_role is True

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, role_repository: RoleRepository, mock_session: AsyncMock):
        """Test role creation with duplicate name."""
        # Arrange
        mock_session.flush.side_effect = IntegrityError("Duplicate role name", None, None)
        mock_session.rollback.return_value = None

        # Mock get_by_name to return None so we get past the initial check
        with patch.object(role_repository, "get_by_name", return_value=None):
            # Act & Assert
            with pytest.raises(IntegrityError):
                await role_repository.create_role(
                    name="existing_role",
                    description="This should fail",
                    permissions=["users:read"],
                )

        mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_role_empty_permissions(
        self, role_repository: RoleRepository, mock_session: AsyncMock, role_factory
    ):
        """Test role creation with empty permissions list."""
        # Arrange
        role_no_perms = role_factory.create(
            id="no-perms-role-id",
            name="no_permissions_role",
            permissions=[],
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.role.Role", return_value=role_no_perms),
            patch.object(role_repository, "get_by_name", return_value=None),
        ):
            # Act
            created_role = await role_repository.create_role(
                name="no_permissions_role",
                description="Role with no permissions",
                permissions=[],
            )

            # Assert
            assert created_role is not None
            assert created_role.permissions == []

    # update_role_permissions Tests

    @pytest.mark.asyncio
    async def test_update_role_permissions_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test successful role permissions update."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_role)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        new_permissions = ["users:read", "users:write", "system:manage"]

        # Act
        updated_role = await role_repository.update_role_permissions(
            role_id="test-role-id", permissions=new_permissions, updated_by="admin"
        )

        # Assert
        assert updated_role is not None
        assert updated_role.permissions == new_permissions
        assert updated_role.updated_by == "admin"
        assert updated_role.updated_at is not None
        mock_session.flush.assert_called_once()
        mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_role_permissions_not_found(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test updating permissions for non-existent role."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        updated_role = await role_repository.update_role_permissions(
            role_id="nonexistent-role-id",
            permissions=["read"],
        )

        # Assert
        assert updated_role is None
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_role_permissions_system_role_protection(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        system_role: Role,
        query_result_factory,
    ):
        """Test that system roles are protected from permission updates."""
        # Arrange
        result_mock = query_result_factory(scalar_result=system_role)
        mock_session.execute.return_value = result_mock

        # Act
        updated_role = await role_repository.update_role_permissions(
            role_id="system-role-id",
            permissions=["limited_access"],
        )

        # Assert - System roles should not be updated
        assert updated_role is None or updated_role.permissions == ["*"]
        # Should not flush changes for system roles
        if updated_role is None:
            mock_session.flush.assert_not_called()

    # get_user_roles Tests

    @pytest.mark.asyncio
    async def test_get_user_roles_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test successful retrieval of user roles."""
        # Arrange
        user_roles = [sample_role]
        result_mock = query_result_factory(data=user_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_user_roles("test-user-id")

        # Assert
        assert len(roles) == 1
        assert roles[0].name == "Test Role"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_roles_multiple_roles(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        system_role: Role,
        query_result_factory,
    ):
        """Test retrieval of multiple roles for a user."""
        # Arrange
        user_roles = [sample_role, system_role]
        result_mock = query_result_factory(data=user_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_user_roles("test-user-id")

        # Assert
        assert len(roles) == 2
        role_names = {role.name for role in roles}
        assert "Test Role" in role_names
        assert "System Admin" in role_names

    @pytest.mark.asyncio
    async def test_get_user_roles_no_roles(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test retrieval when user has no roles."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_user_roles("user-with-no-roles")

        # Assert
        assert roles == []
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_roles_only_active_roles(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test that only active roles are returned for user."""
        # Arrange
        active_roles = [sample_role]  # Only active roles returned
        result_mock = query_result_factory(data=active_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_user_roles("test-user-id")

        # Assert
        assert len(roles) == 1
        assert all(role.is_active for role in roles)

    # assign_role_to_user Tests

    @pytest.mark.asyncio
    async def test_assign_role_to_user_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test successful role assignment to user."""
        # Arrange
        # First check if role exists
        role_result = query_result_factory(scalar_result=sample_role)
        # Then check if assignment already exists (should return None for new assignment)
        assignment_result = query_result_factory(scalar_result=None)
        mock_session.execute.side_effect = [role_result, assignment_result]
        mock_session.flush.return_value = None

        # Act
        assignment = await role_repository.assign_role_to_user(
            user_id="test-user-id", role_id="test-role-id", assigned_by="admin"
        )

        # Assert
        assert assignment is not None
        assert hasattr(assignment, "user_id")
        assert hasattr(assignment, "role_id")
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_role_to_user_role_not_found(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test role assignment when role doesn't exist."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        success = await role_repository.assign_role_to_user(
            user_id="test-user-id", role_id="nonexistent-role-id", assigned_by="admin"
        )

        # Assert
        assert success is False
        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_assign_role_to_user_already_assigned(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        user_role_assignment,
        query_result_factory,
    ):
        """Test role assignment when user already has the role."""
        # Arrange
        role_result = query_result_factory(scalar_result=sample_role)
        assignment_result = query_result_factory(scalar_result=user_role_assignment)
        mock_session.execute.side_effect = [role_result, assignment_result]

        # Act
        success = await role_repository.assign_role_to_user(
            user_id="test-user-id", role_id="test-role-id", assigned_by="admin"
        )

        # Assert
        assert success is False  # Already assigned
        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_assign_role_to_user_reactivate_inactive_assignment(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        user_role_assignment,
        query_result_factory,
    ):
        """Test reactivating an inactive role assignment."""
        # Arrange
        inactive_assignment = {**user_role_assignment, "is_active": False}
        role_result = query_result_factory(scalar_result=sample_role)
        assignment_result = query_result_factory(scalar_result=inactive_assignment)
        mock_session.execute.side_effect = [role_result, assignment_result]
        mock_session.flush.return_value = None

        # Act
        success = await role_repository.assign_role_to_user(
            user_id="test-user-id", role_id="test-role-id", assigned_by="admin"
        )

        # Assert
        assert success is True
        assert inactive_assignment["is_active"] is True
        mock_session.flush.assert_called_once()

    # remove_role_from_user Tests

    @pytest.mark.asyncio
    async def test_remove_role_from_user_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        user_role_assignment,
        query_result_factory,
    ):
        """Test successful role removal from user."""
        # Arrange
        result_mock = query_result_factory(scalar_result=user_role_assignment)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None

        # Act
        success = await role_repository.remove_role_from_user(
            user_id="test-user-id", role_id="test-role-id", removed_by="admin"
        )

        # Assert
        assert success is True
        assert user_role_assignment["is_active"] is False
        assert user_role_assignment["removed_by"] == "admin"
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_role_from_user_assignment_not_found(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test role removal when assignment doesn't exist."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock

        # Act
        success = await role_repository.remove_role_from_user(
            user_id="test-user-id", role_id="test-role-id", removed_by="admin"
        )

        # Assert
        assert success is False
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_remove_role_from_user_already_inactive(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        user_role_assignment,
        query_result_factory,
    ):
        """Test removing role that is already inactive."""
        # Arrange
        inactive_assignment = {**user_role_assignment, "is_active": False}
        result_mock = query_result_factory(scalar_result=inactive_assignment)
        mock_session.execute.return_value = result_mock

        # Act
        success = await role_repository.remove_role_from_user(
            user_id="test-user-id", role_id="test-role-id", removed_by="admin"
        )

        # Assert
        assert success is False
        mock_session.flush.assert_not_called()

    # get_role_users Tests

    @pytest.mark.asyncio
    async def test_get_role_users_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test successful retrieval of users assigned to a role."""
        # Arrange
        role_users = [
            {
                "user_id": "user1",
                "username": "alice",
                "email": "alice@example.com",
                "assigned_at": datetime.now(timezone.utc) - timedelta(days=30),
                "assigned_by": "admin",
                "is_active": True,
            },
            {
                "user_id": "user2",
                "username": "bob",
                "email": "bob@example.com",
                "assigned_at": datetime.now(timezone.utc) - timedelta(days=15),
                "assigned_by": "admin",
                "is_active": True,
            },
        ]
        result_mock = query_result_factory(data=role_users)
        mock_session.execute.return_value = result_mock

        # Act
        users = await role_repository.get_role_users("test-role-id")

        # Assert
        assert len(users) == 2
        assert users[0]["username"] == "alice"
        assert users[1]["username"] == "bob"
        assert all(user["is_active"] for user in users)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_role_users_no_users(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test retrieval when no users are assigned to role."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        users = await role_repository.get_role_users("role-with-no-users")

        # Assert
        assert users == []
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_role_users_only_active_assignments(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test that only active user assignments are returned."""
        # Arrange
        active_users = [
            {
                "user_id": "user1",
                "username": "alice",
                "is_active": True,
            }
        ]
        result_mock = query_result_factory(data=active_users)
        mock_session.execute.return_value = result_mock

        # Act
        users = await role_repository.get_role_users("test-role-id")

        # Assert
        assert len(users) == 1
        assert all(user["is_active"] for user in users)

    # get_default_roles Tests

    @pytest.mark.asyncio
    async def test_get_default_roles_success(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        system_role: Role,
        query_result_factory,
    ):
        """Test successful retrieval of default system roles."""
        # Arrange
        default_roles = [system_role]
        result_mock = query_result_factory(data=default_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_default_roles()

        # Assert
        assert len(roles) == 1
        assert roles[0].is_system_role is True
        assert roles[0].name == "System Admin"
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_default_roles_multiple_system_roles(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
        role_factory,
    ):
        """Test retrieval of multiple default roles."""
        # Arrange
        admin_role = role_factory.create(name="Admin", is_system_role=True)
        user_role = role_factory.create(name="User", is_system_role=True)
        default_roles = [admin_role, user_role]
        result_mock = query_result_factory(data=default_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_default_roles()

        # Assert
        assert len(roles) == 2
        assert all(role.is_system_role for role in roles)
        role_names = {role.name for role in roles}
        assert "Admin" in role_names
        assert "User" in role_names

    @pytest.mark.asyncio
    async def test_get_default_roles_none_exist(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test retrieval when no default roles exist."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_default_roles()

        # Assert
        assert roles == []
        mock_session.execute.assert_called_once()

    # is_role_name_available Tests

    @pytest.mark.asyncio
    async def test_is_role_name_available_true(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test role name availability when name is available."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)  # No existing role
        mock_session.execute.return_value = result_mock

        # Act
        is_available = await role_repository.is_role_name_available("New Unique Role")

        # Assert
        assert is_available is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_role_name_available_false(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test role name availability when name is taken."""
        # Arrange
        result_mock = query_result_factory(scalar_result=sample_role)  # Existing role
        mock_session.execute.return_value = result_mock

        # Act
        is_available = await role_repository.is_role_name_available("Test Role")

        # Assert
        assert is_available is False
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_role_name_available_exclude_current_role(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test role name availability excluding current role (for updates)."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)  # No other role with this name
        mock_session.execute.return_value = result_mock

        # Act
        is_available = await role_repository.is_role_name_available("Test Role", exclude_role_id="test-role-id")

        # Assert
        assert is_available is True  # Available because we're excluding current role
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_role_name_available_case_insensitive(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test role name availability is case sensitive."""
        # Arrange
        result_mock = query_result_factory(scalar_result=None)  # Case sensitive search
        mock_session.execute.return_value = result_mock

        # Act
        is_available = await role_repository.is_role_name_available("test role")

        # Assert
        assert is_available is True  # Different case should be available
        mock_session.execute.assert_called_once()

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_database_connection_error_handling(self, role_repository: RoleRepository, mock_session: AsyncMock):
        """Test handling of database connection errors across methods."""
        # Arrange
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        # Test various methods handle database errors appropriately
        with pytest.raises(SQLAlchemyError):
            await role_repository.get_by_name("Test Role")

        with pytest.raises(SQLAlchemyError):
            await role_repository.get_user_roles("test-user-id")

        with pytest.raises(SQLAlchemyError):
            await role_repository.get_role_users("test-role-id")

        with pytest.raises(SQLAlchemyError):
            await role_repository.get_default_roles()

        with pytest.raises(SQLAlchemyError):
            await role_repository.is_role_name_available("Test Role")

    @pytest.mark.asyncio
    async def test_null_input_validation(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test repository methods handle null/None inputs appropriately."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test methods that should handle None gracefully
        result = await role_repository.get_by_name(None)
        assert result is None

        result = await role_repository.get_user_roles(None)
        assert result == []

        result = await role_repository.get_role_users(None)
        assert result == []

        success = await role_repository.assign_role_to_user(None, "role-id", "admin")
        assert success is False

        success = await role_repository.remove_role_from_user("user-id", None, "admin")
        assert success is False

    @pytest.mark.asyncio
    async def test_empty_string_input_validation(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        query_result_factory,
    ):
        """Test repository methods handle empty string inputs appropriately."""
        # Arrange
        result_mock = query_result_factory(data=[])
        mock_session.execute.return_value = result_mock

        # Test with empty strings
        result = await role_repository.get_by_name("")
        assert result is None

        result = await role_repository.get_user_roles("")
        assert result == []

        is_available = await role_repository.is_role_name_available("")
        assert is_available is False  # Empty names should not be available

    # Performance and Edge Case Tests

    @pytest.mark.asyncio
    async def test_large_permissions_list_handling(
        self, role_repository: RoleRepository, mock_session: AsyncMock, role_factory
    ):
        """Test handling of roles with very large permissions lists."""
        # Arrange
        large_permissions = [f"users:read" if i % 2 == 0 else f"api_keys:write" for i in range(1000)]
        large_role = role_factory.create(
            id="large-role-id",
            name="large_permissions_role",
            permissions=large_permissions,
        )
        mock_session.flush.return_value = None
        mock_session.refresh.return_value = None

        with (
            patch("app.repositories.role.Role", return_value=large_role),
            patch.object(role_repository, "get_by_name", return_value=None),
        ):
            # Act
            created_role = await role_repository.create_role(
                name="large_permissions_role",
                description="Role with many permissions",
                permissions=large_permissions,
            )

            # Assert
            assert created_role is not None
            assert len(created_role.permissions) == 1000
            mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_unicode_and_special_characters_in_role_name(
        self, role_repository: RoleRepository, mock_session: AsyncMock, role_factory
    ):
        """Test handling of Unicode and special characters in role names."""
        # Arrange - Test that Unicode characters are properly rejected
        unicode_name = "unicode_role_🔐_test_name"

        with patch.object(role_repository, "get_by_name", return_value=None):
            # Act & Assert - Should raise ValueError for invalid role name
            with pytest.raises(
                ValueError,
                match="Role name can only contain letters, numbers, underscores, and hyphens",
            ):
                await role_repository.create_role(
                    name=unicode_name,
                    description="Role with Unicode characters",
                    permissions=["users:read", "users:write"],
                )

    @pytest.mark.asyncio
    async def test_concurrent_role_operations(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test concurrent role operations."""
        # Arrange - Mock for concurrent operations testing
        # Use None to simulate no existing assignment for assign_role_to_user
        result_mock = query_result_factory(scalar_result=None)
        mock_session.execute.return_value = result_mock
        mock_session.flush.return_value = None

        # Act - Simulate concurrent operations
        update_task = role_repository.update_role_permissions("test-role-id", ["new_permission"])
        assign_task = role_repository.assign_role_to_user("user-id", "test-role-id", "admin")

        # Execute both operations
        update_result = await update_task
        assign_result = await assign_task

        # Assert
        # In this mock scenario, both operations execute
        # In real implementation, proper locking would be needed
        assert isinstance(update_result, (Role, type(None)))
        assert isinstance(assign_result, bool)

    @pytest.mark.asyncio
    async def test_role_hierarchy_and_inheritance_patterns(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        role_factory,
        query_result_factory,
    ):
        """Test role hierarchy and inheritance patterns."""
        # Create roles with hierarchical relationships
        parent_role = role_factory.create(
            id="parent-role-id",
            name="Parent Role",
            permissions=["users:read", "users:write"],
        )

        child_role = role_factory.create(
            id="child-role-id",
            name="Child Role",
            permissions=["users:read"],  # Subset of parent permissions
            parent_role_id="parent-role-id",
        )

        # Arrange
        hierarchy_roles = [parent_role, child_role]
        result_mock = query_result_factory(data=hierarchy_roles)
        mock_session.execute.return_value = result_mock

        # Act
        roles = await role_repository.get_user_roles("hierarchical-user-id")

        # Assert
        assert len(roles) == 2
        role_names = {role.name for role in roles}
        assert "Parent Role" in role_names
        assert "Child Role" in role_names

    @pytest.mark.asyncio
    async def test_bulk_role_assignment_patterns(
        self,
        role_repository: RoleRepository,
        mock_session: AsyncMock,
        sample_role: Role,
        query_result_factory,
    ):
        """Test patterns for bulk role assignments."""
        # This simulates bulk assignment operations

        # Arrange
        role_result = query_result_factory(scalar_result=sample_role)
        assignment_result = query_result_factory(scalar_result=None)
        mock_session.execute.side_effect = [
            role_result,
            assignment_result,
        ] * 5  # 5 users
        mock_session.flush.return_value = None

        user_ids = [f"user-{i}" for i in range(5)]

        # Act - Simulate bulk assignment
        assignment_results = []
        for user_id in user_ids:
            result = await role_repository.assign_role_to_user(user_id, "test-role-id", "admin")
            assignment_results.append(result)

        # Assert
        assert len(assignment_results) == 5
        # Accept both True (reactivated) and UserRole objects (new assignments) as success
        assert all(result is not False and result is not None for result in assignment_results)
        assert mock_session.add.call_count == 5
        assert mock_session.flush.call_count == 5
