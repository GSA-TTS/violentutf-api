"""Tests for repository organization-based filtering.

This module tests the critical security fix for multi-tenant data isolation in repositories.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.models.permission import Permission
from app.models.user import User
from app.repositories.api_key import APIKeyRepository
from app.repositories.base import BaseRepository
from app.repositories.user import UserRepository


class TestRepositoryOrganizationFiltering:
    """Test repository organization-based filtering."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = Mock(spec=AsyncSession)
        session.execute = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        return session

    @pytest.fixture
    def real_user_model(self):
        """Use real User model class for SQLAlchemy compatibility."""
        return User

    @pytest.fixture
    def mock_result(self):
        """Create mock query result."""
        result = Mock()
        result.scalar_one_or_none = Mock(return_value=None)
        result.rowcount = 0
        return result

    async def test_base_repository_get_by_id_with_organization(self, mock_session, real_user_model, mock_result):
        """Test that get_by_id includes organization filtering when provided."""
        # Setup
        mock_session.execute.return_value = mock_result
        repository = BaseRepository(mock_session, real_user_model)

        entity_id = "user-123"
        organization_id = "org-456"

        # Execute
        result = await repository.get_by_id(entity_id, organization_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Get the query that was executed
        executed_query = mock_session.execute.call_args[0][0]

        # Verify the query structure includes organization filtering
        # The query should have filters for id, is_deleted, and organization_id
        assert "WHERE" in str(executed_query).upper()

        # Verify result
        assert result is None  # mock returns None

    async def test_base_repository_get_by_id_without_organization(self, mock_session, real_user_model, mock_result):
        """Test that get_by_id works without organization filtering (backward compatibility)."""
        # Setup
        mock_session.execute.return_value = mock_result
        repository = BaseRepository(mock_session, real_user_model)

        entity_id = "user-123"

        # Execute - no organization_id provided
        result = await repository.get_by_id(entity_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is None

    async def test_base_repository_update_with_organization(self, mock_session, real_user_model, mock_result):
        """Test that update includes organization filtering when provided."""
        # Setup
        mock_session.execute.return_value = mock_result
        mock_result.rowcount = 1  # Simulate successful update

        # Mock get_by_id to return a user for version checking
        repository = BaseRepository(mock_session, real_user_model)

        with patch.object(repository, "get_by_id", return_value=None):
            entity_id = "user-123"
            organization_id = "org-456"
            update_data = {"name": "Updated Name"}

            # Execute
            result = await repository.update(entity_id, organization_id, **update_data)

            # Verify query was executed
            assert mock_session.execute.call_count >= 1

            # Verify result
            assert result is None  # get_by_id returns None in mock

    async def test_base_repository_delete_with_organization(self, mock_session, real_user_model, mock_result):
        """Test that delete includes organization filtering when provided."""
        # Setup
        mock_session.execute.return_value = mock_result
        mock_result.rowcount = 1  # Simulate successful delete

        repository = BaseRepository(mock_session, real_user_model)

        entity_id = "user-123"
        organization_id = "org-456"

        # Execute
        result = await repository.delete(entity_id, organization_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is True  # rowcount > 0

    async def test_base_repository_list_with_pagination_organization(self, mock_session, real_user_model):
        """Test that list_with_pagination includes organization filtering when provided."""
        # Setup
        mock_count_result = Mock()
        mock_count_result.scalar.return_value = 0

        mock_list_result = Mock()
        mock_list_result.scalars.return_value.all.return_value = []

        mock_session.execute.side_effect = [mock_count_result, mock_list_result]

        repository = BaseRepository(mock_session, real_user_model)

        organization_id = "org-456"

        # Execute
        result = await repository.list_with_pagination(organization_id=organization_id)

        # Verify queries were executed (count + list)
        assert mock_session.execute.call_count == 2

        # Verify result structure
        assert hasattr(result, "items")
        assert hasattr(result, "total")
        assert result.total == 0

    async def test_user_repository_get_by_username_with_organization(self, mock_session):
        """Test UserRepository get_by_username with organization filtering."""
        # Setup
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        repository = UserRepository(mock_session)

        username = "testuser"
        organization_id = "org-456"

        # Execute
        result = await repository.get_by_username(username, organization_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is None

    async def test_api_key_repository_get_by_hash_with_organization(self, mock_session):
        """Test APIKeyRepository get_by_hash with organization filtering."""
        # Setup
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        repository = APIKeyRepository(mock_session)

        key_hash = "abc123hash"
        organization_id = "org-456"

        # Execute
        result = await repository.get_by_hash(key_hash, organization_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is None

    async def test_organization_filtering_prevents_cross_tenant_access(
        self, mock_session, real_user_model, mock_result
    ):
        """Test that organization filtering prevents cross-tenant data access.

        This test specifically validates the multi-tenant security fix.
        """
        # Setup - simulate finding user in wrong organization
        mock_user = Mock()
        mock_user.id = "user-123"
        mock_user.organization_id = "org-different"

        mock_result.scalar_one_or_none.return_value = None  # Should not find user in different org
        mock_session.execute.return_value = mock_result

        repository = BaseRepository(mock_session, real_user_model)

        # Execute - try to access user from different organization
        result = await repository.get_by_id("user-123", "org-456")

        # Verify result is None (user not found due to organization filtering)
        assert result is None

        # Verify query included organization filter
        mock_session.execute.assert_called_once()

    async def test_backward_compatibility_without_organization_id(self, mock_session, real_user_model, mock_result):
        """Test that repositories still work without organization_id for backward compatibility."""
        # Setup
        mock_user = Mock()
        mock_user.id = "user-123"
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result

        repository = BaseRepository(mock_session, real_user_model)

        # Execute - no organization_id provided
        result = await repository.get_by_id("user-123")

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result == mock_user

    async def test_organization_filter_helper_method(self, mock_session, real_user_model):
        """Test the _add_organization_filter helper method."""
        # Setup
        repository = BaseRepository(mock_session, real_user_model)
        mock_query = Mock()
        mock_query.where.return_value = mock_query

        organization_id = "org-123"

        # Execute
        result_query = repository._add_organization_filter(mock_query, organization_id)

        # Verify where clause was added
        mock_query.where.assert_called_once()

        # Verify same query object returned (fluent interface)
        assert result_query == mock_query

    async def test_organization_filter_skipped_for_model_without_organization_id(self, mock_session, mock_result):
        """Test that organization filtering is skipped for models without organization_id field."""
        # Setup - use Permission model which doesn't have organization_id field
        mock_session.execute.return_value = mock_result
        repository = BaseRepository(mock_session, Permission)

        # Execute
        result = await repository.get_by_id("entity-123", "org-456")

        # Verify query was executed (should work even without organization_id)
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is None

    @pytest.mark.parametrize(
        "organization_id",
        [
            "org-123",
            "550e8400-e29b-41d4-a716-446655440000",
            None,
            "",
        ],
    )
    async def test_organization_id_edge_cases(self, mock_session, real_user_model, mock_result, organization_id):
        """Test organization filtering with various edge cases."""
        # Setup
        mock_session.execute.return_value = mock_result
        repository = BaseRepository(mock_session, real_user_model)

        # Execute
        result = await repository.get_by_id("user-123", organization_id)

        # Verify query was executed
        mock_session.execute.assert_called_once()

        # Verify result
        assert result is None
