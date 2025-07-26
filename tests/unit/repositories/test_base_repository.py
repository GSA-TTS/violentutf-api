"""Tests for the base repository pattern implementation."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.base import BaseRepository, Page


class TestBaseRepository:
    """Test the BaseRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock(spec=AsyncSession)
        return session

    @pytest.fixture
    def user_repository(self, mock_session):
        """Create a user repository for testing."""
        return BaseRepository(mock_session, User)

    @pytest.mark.asyncio
    async def test_repository_initialization(self, mock_session):
        """Test repository initialization."""
        repo = BaseRepository(mock_session, User)

        assert repo.session == mock_session
        assert repo.model == User
        assert repo.logger is not None

    @pytest.mark.asyncio
    async def test_create_generates_uuid(self, user_repository, mock_session):
        """Test that create generates UUID if not provided."""
        # Mock session operations
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        # Create the entity directly
        result = await user_repository.create(username="test", email="test@example.com")

        # Verify UUID was generated
        assert result.id is not None
        assert isinstance(result.id, str)
        # Verify it's a valid UUID
        uuid.UUID(result.id)

        # Verify session operations
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_with_provided_id(self, user_repository, mock_session):
        """Test that create uses provided ID."""
        test_id = str(uuid.uuid4())

        # Mock session operations
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        # Create the entity with provided ID
        result = await user_repository.create(id=test_id, username="test", email="test@example.com")

        # Verify the provided ID was used
        assert result.id == test_id

        # Verify session operations
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_exists_method(self, user_repository, mock_session):
        """Test the exists method."""
        test_id = str(uuid.uuid4())

        # Mock the scalar result to return 1 (exists)
        mock_result = MagicMock()
        mock_result.scalar.return_value = 1
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await user_repository.exists(test_id)

        assert result is True
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_count_method(self, user_repository, mock_session):
        """Test the count method."""
        # Mock the scalar result to return 5
        mock_result = MagicMock()
        mock_result.scalar.return_value = 5
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await user_repository.count()

        assert result == 5
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_count_with_filters(self, user_repository, mock_session):
        """Test the count method with filters."""
        # Mock the scalar result
        mock_result = MagicMock()
        mock_result.scalar.return_value = 3
        mock_session.execute = AsyncMock(return_value=mock_result)

        filters = {"is_active": True}
        result = await user_repository.count(filters=filters)

        assert result == 3
        mock_session.execute.assert_called_once()


class TestPageModel:
    """Test the Page model for pagination."""

    def test_page_initialization(self):
        """Test Page model initialization."""
        items = [1, 2, 3]
        page = Page(
            items=items,
            total=10,
            page=1,
            size=3,
            has_next=True,
            has_prev=False,
        )

        assert page.items == items
        assert page.total == 10
        assert page.page == 1
        assert page.size == 3
        assert page.has_next is True
        assert page.has_prev is False
        assert page.pages == 4  # 10 items / 3 per page = 4 pages

    def test_page_calculation_edge_cases(self):
        """Test edge cases for page calculation."""
        # Test with empty results
        page = Page(
            items=[],
            total=0,
            page=1,
            size=10,
            has_next=False,
            has_prev=False,
        )
        assert page.pages == 0

        # Test with size 0 (should handle gracefully)
        page = Page(
            items=[],
            total=5,
            page=1,
            size=0,
            has_next=False,
            has_prev=False,
        )
        assert page.pages == 0
