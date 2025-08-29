"""Unit tests for MFA policy service."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError
from app.models.mfa import MFAMethod, MFAPolicy
from app.models.user import User
from app.services.mfa_policy_service import MFAPolicyService


@pytest.fixture
def mock_session():
    """Create mock database session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_user():
    """Create mock user."""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "test@example.com"
    user.username = "testuser"
    user.is_active = True
    user.is_superuser = False
    user.roles = ["user"]
    user.organization_id = uuid.uuid4()
    user.created_at = datetime.now(timezone.utc) - timedelta(days=30)
    return user


@pytest.fixture
def mfa_policy_service(mock_session):
    """Create MFA policy service instance."""
    return MFAPolicyService(mock_session)


class TestMFAPolicyService:
    """Test MFA policy service methods."""

    @pytest.mark.asyncio
    async def test_create_policy_success(self, mfa_policy_service):
        """Test successful policy creation."""
        # Arrange
        conditions = {"roles": ["admin", "manager"], "min_account_age_days": 7}

        # Mock no existing policy
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mfa_policy_service.session.execute.return_value = mock_result

        # Act
        policy = await mfa_policy_service.create_policy(
            name="Admin MFA Policy",
            description="Require MFA for admin users",
            conditions=conditions,
            required_methods=["totp"],
            min_methods=1,
            grace_period_days=7,
            enforcement_level="required",
            priority=100,
        )

        # Assert
        assert policy.name == "Admin MFA Policy"
        assert policy.enforcement_level == "required"
        assert policy.priority == 100
        mfa_policy_service.session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_policy_invalid_enforcement_level(self, mfa_policy_service):
        """Test policy creation with invalid enforcement level."""
        # Arrange
        conditions = {"roles": ["user"]}

        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid enforcement level"):
            await mfa_policy_service.create_policy(
                name="Test Policy",
                description="Test",
                conditions=conditions,
                required_methods=["totp"],
                enforcement_level="invalid",
            )

    @pytest.mark.asyncio
    async def test_create_policy_invalid_method(self, mfa_policy_service):
        """Test policy creation with invalid MFA method."""
        # Arrange
        conditions = {"roles": ["user"]}

        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid MFA method"):
            await mfa_policy_service.create_policy(
                name="Test Policy",
                description="Test",
                conditions=conditions,
                required_methods=["invalid_method"],
                enforcement_level="required",
            )

    @pytest.mark.asyncio
    async def test_check_policy_conditions_roles(self, mfa_policy_service, mock_user):
        """Test policy condition checking for roles."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)

        # Test matching role
        policy.conditions = json.dumps({"roles": ["user", "admin"]})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is True

        # Test non-matching role
        policy.conditions = json.dumps({"roles": ["admin", "superuser"]})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_policy_conditions_superuser(self, mfa_policy_service, mock_user):
        """Test policy condition checking for superuser status."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)

        # Test matching superuser status
        policy.conditions = json.dumps({"is_superuser": False})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is True

        # Test non-matching superuser status
        policy.conditions = json.dumps({"is_superuser": True})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_policy_conditions_account_age(self, mfa_policy_service, mock_user):
        """Test policy condition checking for account age."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)

        # Test account old enough
        policy.conditions = json.dumps({"min_account_age_days": 7})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is True

        # Test account too new
        policy.conditions = json.dumps({"min_account_age_days": 60})
        result = await mfa_policy_service._check_policy_conditions(policy, mock_user)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_mfa_requirement_no_policies(self, mfa_policy_service, mock_user):
        """Test MFA requirement check with no applicable policies."""
        # Arrange
        mfa_policy_service.get_applicable_policies = AsyncMock(return_value=[])

        # Act
        is_required, policy, details = await mfa_policy_service.check_mfa_requirement(mock_user)

        # Assert
        assert is_required is False
        assert policy is None
        assert details["enforcement_level"] == "optional"

    @pytest.mark.asyncio
    async def test_check_mfa_requirement_required_policy(self, mfa_policy_service, mock_user):
        """Test MFA requirement check with required policy."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)
        policy.name = "Admin Policy"
        policy.enforcement_level = "required"
        policy.grace_period_days = 0
        policy.bypass_permissions = None
        policy.required_methods = json.dumps(["totp"])
        policy.min_methods = 1

        mfa_policy_service.get_applicable_policies = AsyncMock(return_value=[policy])

        # Act
        is_required, returned_policy, details = await mfa_policy_service.check_mfa_requirement(mock_user)

        # Assert
        assert is_required is True
        assert returned_policy == policy
        assert details["enforcement_level"] == "required"
        assert details["required_methods"] == ["totp"]

    @pytest.mark.asyncio
    async def test_check_mfa_requirement_grace_period(self, mfa_policy_service, mock_user):
        """Test MFA requirement check with grace period."""
        # Arrange
        mock_user.created_at = datetime.now(timezone.utc) - timedelta(days=5)  # 5 days old account

        policy = MagicMock(spec=MFAPolicy)
        policy.name = "New User Policy"
        policy.enforcement_level = "required"
        policy.grace_period_days = 14  # 14 day grace period
        policy.bypass_permissions = None
        policy.required_methods = json.dumps(["totp"])

        mfa_policy_service.get_applicable_policies = AsyncMock(return_value=[policy])

        # Act
        is_required, returned_policy, details = await mfa_policy_service.check_mfa_requirement(mock_user)

        # Assert
        assert is_required is False
        assert returned_policy == policy
        assert details["enforcement_level"] == "grace_period"
        assert details["grace_period_remaining"] == 9  # 14 - 5 days

    @pytest.mark.asyncio
    async def test_update_policy_success(self, mfa_policy_service):
        """Test successful policy update."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)
        policy.id = uuid.uuid4()
        policy.name = "Old Name"
        policy.priority = 50

        # Mock the repository's session.execute calls
        # Create a mock result that can handle both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
        mock_result = MagicMock()
        mock_result.rowcount = 1  # For UPDATE operations
        mock_result.scalar_one_or_none.return_value = policy  # For SELECT operations

        # Mock the repository's session to always return our mock result
        mfa_policy_service.mfa_policy_repo.session.execute.return_value = mock_result

        # Act
        updated_policy = await mfa_policy_service.update_policy(
            policy_id=str(policy.id), name="New Name", priority=100, updated_by="admin"
        )

        # Assert
        assert updated_policy is not None
        assert updated_policy == policy  # The service should return the updated policy

        # Verify the mock was called properly (the repository's session.execute was called)
        assert mfa_policy_service.mfa_policy_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_delete_policy_success(self, mfa_policy_service):
        """Test successful policy deletion."""
        # Arrange
        policy = MagicMock(spec=MFAPolicy)
        policy.id = uuid.uuid4()
        policy.is_active = True

        # Mock the repository's session.execute calls
        # Create a mock result that can handle both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
        mock_result = MagicMock()
        mock_result.rowcount = 1  # For UPDATE operations (soft delete)
        mock_result.scalar_one_or_none.return_value = policy  # For SELECT operations

        # Mock the repository's session to always return our mock result
        mfa_policy_service.mfa_policy_repo.session.execute.return_value = mock_result

        # Act
        result = await mfa_policy_service.delete_policy(str(policy.id))

        # Assert
        assert result is True

        # Verify the mock was called properly (the repository's session.execute was called)
        assert mfa_policy_service.mfa_policy_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_list_policies_success(self, mfa_policy_service):
        """Test listing policies."""
        # Arrange
        policy1 = MagicMock(spec=MFAPolicy)
        policy1.id = uuid.uuid4()
        policy1.name = "Policy 1"
        policy1.description = "Test policy 1"
        policy1.is_active = True
        policy1.priority = 100
        policy1.enforcement_level = "required"
        policy1.grace_period_days = 0
        policy1.min_methods = 1
        policy1.conditions = json.dumps({"roles": ["admin"]})
        policy1.required_methods = json.dumps(["totp"])
        policy1.bypass_permissions = None
        policy1.created_at = datetime.now(timezone.utc)
        policy1.updated_at = None

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [policy1]
        mfa_policy_service.session.execute.return_value = mock_result

        # Act
        policies = await mfa_policy_service.list_policies()

        # Assert
        assert len(policies) == 1
        assert policies[0]["name"] == "Policy 1"
        assert policies[0]["conditions"]["roles"] == ["admin"]
        assert policies[0]["required_methods"] == ["totp"]
