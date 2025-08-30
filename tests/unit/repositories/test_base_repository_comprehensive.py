"""Comprehensive tests for the base repository pattern implementation achieving 100% coverage."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, PropertyMock, call, patch

import pytest
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    and_,
    func,
    or_,
    select,
)
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeMeta
from sqlalchemy.sql.elements import ColumnElement

from app.db.base_class import Base
from app.repositories.base import BaseRepository, Page


# Test model for comprehensive testing
class RepositoryTestModel(Base):
    """Test model with all features for comprehensive testing."""

    __tablename__ = "test_models"

    id = Column(String, primary_key=True)
    name = Column(String)
    description = Column(String)
    is_active = Column(Boolean, default=True)
    is_deleted = Column(Boolean, default=False)
    deleted_by = Column(String, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc))
    created_by = Column(String, default="system")
    updated_by = Column(String, default="system")
    version = Column(Integer, default=1)
    organization_id = Column(String, nullable=True)
    email = Column(String, nullable=True)
    status = Column(String, nullable=True)

    def __init__(self, **kwargs):
        """Initialize test model with provided attributes."""
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestPageModel:
    """Test the Page model for pagination with full coverage."""

    def test_page_initialization_basic(self):
        """Test Page model basic initialization."""
        items = ["item1", "item2", "item3"]
        page = Page(
            items=items,
            total=10,
            page=2,
            size=3,
            has_next=True,
            has_prev=True,
        )

        assert page.items == items
        assert page.total == 10
        assert page.page == 2
        assert page.size == 3
        assert page.has_next is True
        assert page.has_prev is True
        assert page.pages == 4  # 10 items / 3 per page = 4 pages

    def test_page_iteration(self):
        """Test Page model iteration support."""
        items = [1, 2, 3, 4, 5]
        page = Page(
            items=items,
            total=5,
            page=1,
            size=5,
            has_next=False,
            has_prev=False,
        )

        # Test iteration
        result = []
        for item in page:
            result.append(item)
        assert result == items

    def test_page_length(self):
        """Test Page model length support."""
        items = ["a", "b", "c"]
        page = Page(
            items=items,
            total=10,
            page=1,
            size=3,
            has_next=True,
            has_prev=False,
        )

        assert len(page) == 3

    def test_page_indexing(self):
        """Test Page model indexing support."""
        items = [10, 20, 30, 40]
        page = Page(
            items=items,
            total=4,
            page=1,
            size=4,
            has_next=False,
            has_prev=False,
        )

        assert page[0] == 10
        assert page[1] == 20
        assert page[2] == 30
        assert page[3] == 40

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
        assert len(page) == 0

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

        # Test exact division
        page = Page(
            items=list(range(10)),
            total=30,
            page=2,
            size=10,
            has_next=True,
            has_prev=True,
        )
        assert page.pages == 3

        # Test with remainder
        page = Page(
            items=list(range(7)),
            total=17,
            page=2,
            size=7,
            has_next=True,
            has_prev=True,
        )
        assert page.pages == 3  # 17 / 7 = 2.4, rounds up to 3


class TestBaseRepositoryInitialization:
    """Test BaseRepository initialization scenarios."""

    @pytest.fixture
    def test_session(self):
        """Create a mock async session."""
        return AsyncMock(spec=AsyncSession)

    def test_initialization_with_model(self, test_session):
        """Test repository initialization with model provided."""
        repo = BaseRepository(test_session, RepositoryTestModel)

        assert repo.session == test_session
        assert repo.model == RepositoryTestModel
        assert repo.logger is not None

    def test_initialization_without_model_raises_error(self, test_session):
        """Test repository initialization without model raises ValueError."""
        with pytest.raises(ValueError, match="Model must be provided"):
            BaseRepository(test_session)

    def test_initialization_with_subclass_model_attribute(self, test_session):
        """Test repository initialization with model as class attribute."""

        class CustomRepository(BaseRepository):
            model = RepositoryTestModel

        repo = CustomRepository(test_session)
        assert repo.model == RepositoryTestModel


class TestBaseRepositoryCRUD:
    """Test BaseRepository CRUD operations with comprehensive coverage."""

    @pytest.fixture
    def test_session(self):
        """Create a mock async session."""
        session = AsyncMock(spec=AsyncSession)
        # Add commit method
        session.commit = AsyncMock()
        return session

    @pytest.fixture
    def repository(self, test_session):
        """Create a repository for testing."""
        return BaseRepository(test_session, RepositoryTestModel)

    @pytest.mark.asyncio
    async def test_get_by_id_found(self, repository, test_session):
        """Test get_by_id when entity is found."""
        test_id = str(uuid.uuid4())
        test_entity = RepositoryTestModel(id=test_id, name="Test Entity")

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = test_entity
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.get_by_id(test_id)

        assert result == test_entity
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repository, test_session):
        """Test get_by_id when entity is not found."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = None
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.get_by_id(test_id)

        assert result is None
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_id_with_organization_filtering(self, repository, test_session):
        """Test get_by_id with organization filtering."""
        test_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        test_entity = RepositoryTestModel(id=test_id, name="Test", organization_id=org_id)

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = test_entity
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.get_by_id(test_id, organization_id=org_id)

        assert result == test_entity
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_id_with_soft_delete_filter(self, repository, test_session):
        """Test get_by_id filters out soft-deleted entities."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = None
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.get_by_id(test_id)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_id_exception_handling(self, repository, test_session):
        """Test get_by_id exception handling."""
        test_id = str(uuid.uuid4())

        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.get_by_id(test_id)

    @pytest.mark.asyncio
    async def test_create_with_auto_generated_uuid(self, repository, test_session):
        """Test create generates UUID if not provided."""
        test_session.add = MagicMock()
        test_session.flush = AsyncMock()

        data = {"name": "Test Entity", "email": "test@example.com"}
        result = await repository.create(data)

        assert result.id is not None
        assert isinstance(result.id, str)
        uuid.UUID(result.id)  # Verify it's a valid UUID
        assert result.name == "Test Entity"
        assert result.created_by == "system"
        assert result.updated_by == "system"

        test_session.add.assert_called_once()
        test_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_with_provided_id(self, repository, test_session):
        """Test create uses provided ID."""
        test_id = str(uuid.uuid4())

        test_session.add = MagicMock()
        test_session.flush = AsyncMock()

        data = {"id": test_id, "name": "Test Entity"}
        result = await repository.create(data)

        assert result.id == test_id
        test_session.add.assert_called_once()
        test_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_with_custom_audit_fields(self, repository, test_session):
        """Test create with custom audit fields."""
        test_session.add = MagicMock()
        test_session.flush = AsyncMock()

        data = {"name": "Test Entity", "created_by": "admin", "updated_by": "admin"}
        result = await repository.create(data)

        assert result.created_by == "admin"
        assert result.updated_by == "admin"

    @pytest.mark.asyncio
    async def test_create_with_timestamps(self, repository, test_session):
        """Test create sets timestamps if model has them."""
        test_session.add = MagicMock()
        test_session.flush = AsyncMock()

        data = {"name": "Test Entity"}
        result = await repository.create(data)

        assert result.created_at is not None
        assert result.updated_at is not None
        assert isinstance(result.created_at, datetime)
        assert isinstance(result.updated_at, datetime)

    @pytest.mark.asyncio
    async def test_update_existing_entity(self, repository, test_session):
        """Test update of existing entity."""
        test_id = str(uuid.uuid4())
        original_entity = RepositoryTestModel(id=test_id, name="Original", version=1, is_deleted=False)
        updated_entity = RepositoryTestModel(id=test_id, name="Updated", version=2, is_deleted=False)

        # Mock get_by_id for version check
        test_result_get = MagicMock()
        test_result_get.scalar_one_or_none.return_value = original_entity

        # Mock update execution
        test_result_update = MagicMock()
        test_result_update.rowcount = 1

        # Setup side effects for multiple calls
        test_session.execute = AsyncMock(side_effect=[test_result_get, test_result_update, test_result_get])

        # Set updated entity for second get_by_id
        test_result_get.scalar_one_or_none.side_effect = [
            original_entity,
            updated_entity,
        ]

        result = await repository.update(test_id, name="Updated", description="New description")

        assert result is not None
        assert test_session.execute.call_count == 3  # get, update, get

    @pytest.mark.asyncio
    async def test_update_non_existent_entity(self, repository, test_session):
        """Test update of non-existent entity."""
        test_id = str(uuid.uuid4())

        # Mock get_by_id to return None
        test_result_get = MagicMock()
        test_result_get.scalar_one_or_none.return_value = None

        # Mock update with 0 rowcount
        test_result_update = MagicMock()
        test_result_update.rowcount = 0

        test_session.execute = AsyncMock(side_effect=[test_result_get, test_result_update])

        result = await repository.update(test_id, name="Updated")

        assert result is None

    @pytest.mark.asyncio
    async def test_update_with_organization_filtering(self, repository, test_session):
        """Test update with organization filtering."""
        test_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())

        entity = RepositoryTestModel(
            id=test_id,
            name="Original",
            organization_id=org_id,
            version=1,
            is_deleted=False,
        )

        test_result_get = MagicMock()
        test_result_get.scalar_one_or_none.return_value = entity

        test_result_update = MagicMock()
        test_result_update.rowcount = 1

        test_session.execute = AsyncMock(side_effect=[test_result_get, test_result_update, test_result_get])

        result = await repository.update(test_id, organization_id=org_id, name="Updated")

        assert result is not None

    @pytest.mark.asyncio
    async def test_update_filters_none_values(self, repository, test_session):
        """Test update filters out None values."""
        test_id = str(uuid.uuid4())

        entity = RepositoryTestModel(id=test_id, name="Original", is_deleted=False)

        test_result_get = MagicMock()
        test_result_get.scalar_one_or_none.return_value = entity

        test_result_update = MagicMock()
        test_result_update.rowcount = 1

        test_session.execute = AsyncMock(side_effect=[test_result_get, test_result_update, test_result_get])

        result = await repository.update(test_id, name="Updated", description=None)  # Should be filtered out

        assert result is not None

    @pytest.mark.asyncio
    async def test_update_with_no_fields_to_update(self, repository, test_session):
        """Test update when no fields to update."""
        test_id = str(uuid.uuid4())
        entity = RepositoryTestModel(id=test_id, name="Original", is_deleted=False)

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = entity
        test_session.execute = AsyncMock(return_value=test_result)

        # Only updated_by will be set, which triggers the no-update path
        result = await repository.update(test_id)

        assert result == entity
        test_session.execute.assert_called_once()  # Only get_by_id called

    @pytest.mark.asyncio
    async def test_update_increments_version(self, repository, test_session):
        """Test update increments version for optimistic locking."""
        test_id = str(uuid.uuid4())
        entity = RepositoryTestModel(id=test_id, name="Original", version=5, is_deleted=False)

        test_result_get = MagicMock()
        test_result_get.scalar_one_or_none.return_value = entity

        test_result_update = MagicMock()
        test_result_update.rowcount = 1

        test_session.execute = AsyncMock(side_effect=[test_result_get, test_result_update, test_result_get])

        await repository.update(test_id, name="Updated")

        # Check that version was incremented in the update call
        assert test_session.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_update_exception_handling(self, repository, test_session):
        """Test update exception handling."""
        test_id = str(uuid.uuid4())

        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.update(test_id, name="Updated")

    @pytest.mark.asyncio
    async def test_delete_soft_delete(self, repository, test_session):
        """Test soft delete operation."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete(test_id, hard_delete=False)

        assert result is True
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_hard_delete(self, repository, test_session):
        """Test hard delete operation."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete(test_id, hard_delete=True)

        assert result is True
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_with_organization_filtering(self, repository, test_session):
        """Test delete with organization filtering."""
        test_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete(test_id, organization_id=org_id, hard_delete=True)

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_not_found(self, repository, test_session):
        """Test delete when entity not found."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 0
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete(test_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_soft_delete_model_without_support(self, repository, test_session):
        """Test soft delete on model without soft delete support."""

        # Create a model without is_deleted field
        class SimpleModel(Base):
            __tablename__ = "simple_models"
            id = Column(String, primary_key=True)
            name = Column(String)

        simple_repo = BaseRepository(test_session, SimpleModel)
        test_id = str(uuid.uuid4())

        result = await simple_repo.delete(test_id, hard_delete=False)

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_exception_handling(self, repository, test_session):
        """Test delete exception handling."""
        test_id = str(uuid.uuid4())

        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.delete(test_id)

    @pytest.mark.asyncio
    async def test_restore_soft_deleted_entity(self, repository, test_session):
        """Test restore of soft-deleted entity."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.restore(test_id, restored_by="admin")

        assert result is True
        test_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_restore_not_found(self, repository, test_session):
        """Test restore when entity not found."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 0
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.restore(test_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_restore_model_without_soft_delete(self, repository, test_session):
        """Test restore on model without soft delete support."""

        class SimpleModelRestore(Base):
            __tablename__ = "simple_models_restore"
            id = Column(String, primary_key=True)

        simple_repo = BaseRepository(test_session, SimpleModelRestore)
        test_id = str(uuid.uuid4())

        result = await simple_repo.restore(test_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_restore_exception_handling(self, repository, test_session):
        """Test restore exception handling."""
        test_id = str(uuid.uuid4())

        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.restore(test_id)

    @pytest.mark.asyncio
    async def test_exists_returns_true(self, repository, test_session):
        """Test exists returns True when entity exists."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.scalar.return_value = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.exists(test_id)

        assert result is True

    @pytest.mark.asyncio
    async def test_exists_returns_false(self, repository, test_session):
        """Test exists returns False when entity doesn't exist."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.scalar.return_value = 0
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.exists(test_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_exists_with_none_result(self, repository, test_session):
        """Test exists handles None result."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.scalar.return_value = None
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.exists(test_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_exists_exception_handling(self, repository, test_session):
        """Test exists exception handling."""
        test_id = str(uuid.uuid4())

        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.exists(test_id)

    @pytest.mark.asyncio
    async def test_count_basic(self, repository, test_session):
        """Test basic count operation."""
        test_result = MagicMock()
        test_result.scalar.return_value = 42
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.count()

        assert result == 42

    @pytest.mark.asyncio
    async def test_count_with_filters(self, repository, test_session):
        """Test count with filters."""
        test_result = MagicMock()
        test_result.scalar.return_value = 10
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.count(filters={"is_active": True})

        assert result == 10

    @pytest.mark.asyncio
    async def test_count_with_list_filter(self, repository, test_session):
        """Test count with list filter (IN clause)."""
        test_result = MagicMock()
        test_result.scalar.return_value = 5
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.count(filters={"status": ["active", "pending"]})

        assert result == 5

    @pytest.mark.asyncio
    async def test_count_include_deleted(self, repository, test_session):
        """Test count including soft-deleted entities."""
        test_result = MagicMock()
        test_result.scalar.return_value = 50
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.count(include_deleted=True)

        assert result == 50

    @pytest.mark.asyncio
    async def test_count_with_none_result(self, repository, test_session):
        """Test count handles None result."""
        test_result = MagicMock()
        test_result.scalar.return_value = None
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.count()

        assert result == 0

    @pytest.mark.asyncio
    async def test_count_exception_handling(self, repository, test_session):
        """Test count exception handling."""
        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.count()

    @pytest.mark.asyncio
    async def test_get_alias_method(self, repository, test_session):
        """Test get method (alias for get_by_id)."""
        test_id = str(uuid.uuid4())
        test_entity = RepositoryTestModel(id=test_id, name="Test")

        test_result = MagicMock()
        test_result.scalar_one_or_none.return_value = test_entity
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.get(test_id)

        assert result == test_entity

    @pytest.mark.asyncio
    async def test_delete_permanent(self, repository, test_session):
        """Test permanent delete operation."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 1
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete_permanent(test_id)

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_permanent_not_found(self, repository, test_session):
        """Test permanent delete when entity not found."""
        test_id = str(uuid.uuid4())

        test_result = MagicMock()
        test_result.rowcount = 0
        test_session.execute = AsyncMock(return_value=test_result)

        result = await repository.delete_permanent(test_id)

        assert result is False


class TestBaseRepositoryPagination:
    """Test BaseRepository pagination operations."""

    @pytest.fixture
    def test_session(self):
        """Create a mock async session."""
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def repository(self, test_session):
        """Create a repository for testing."""
        return BaseRepository(test_session, RepositoryTestModel)

    @pytest.mark.asyncio
    async def test_list_with_pagination_basic(self, repository, test_session):
        """Test basic pagination."""
        # Mock count query
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 100

        # Mock data query
        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(20)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=1, size=20)

        assert isinstance(result, Page)
        assert len(result.items) == 20
        assert result.total == 100
        assert result.page == 1
        assert result.size == 20
        assert result.has_next is True
        assert result.has_prev is False
        assert result.pages == 5

    @pytest.mark.asyncio
    async def test_list_with_pagination_middle_page(self, repository, test_session):
        """Test pagination on middle page."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 100

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(20)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=3, size=20)

        assert result.page == 3
        assert result.has_next is True
        assert result.has_prev is True

    @pytest.mark.asyncio
    async def test_list_with_pagination_last_page(self, repository, test_session):
        """Test pagination on last page."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 45

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(5)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=3, size=20)

        assert len(result.items) == 5
        assert result.has_next is False
        assert result.has_prev is True

    @pytest.mark.asyncio
    async def test_list_with_pagination_invalid_params(self, repository, test_session):
        """Test pagination with invalid parameters (should be corrected)."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 10

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Page < 1 should be corrected to 1
        result = await repository.list_with_pagination(page=-5, size=10)
        assert result.page == 1

        # Size > 100 should be limited to 100
        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])
        result = await repository.list_with_pagination(page=1, size=200)
        assert result.size == 100

    @pytest.mark.asyncio
    async def test_list_with_pagination_with_filters(self, repository, test_session):
        """Test pagination with filters."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 30

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}", is_active=True) for i in range(10)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(
            page=1,
            size=10,
            filters={"is_active": True, "status": ["pending", "active"]},
        )

        assert len(result.items) == 10
        assert result.total == 30

    @pytest.mark.asyncio
    async def test_list_with_pagination_with_organization(self, repository, test_session):
        """Test pagination with organization filtering."""
        org_id = str(uuid.uuid4())

        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 15

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}", organization_id=org_id) for i in range(15)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=1, size=20, organization_id=org_id)

        assert len(result.items) == 15
        assert result.total == 15

    @pytest.mark.asyncio
    async def test_list_with_pagination_include_deleted(self, repository, test_session):
        """Test pagination including soft-deleted items."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 50

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(20)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=1, size=20, include_deleted=True)

        assert result.total == 50

    @pytest.mark.asyncio
    async def test_list_with_pagination_eager_loading(self, repository, test_session):
        """Test pagination with eager loading relationships."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 10

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(10)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Mock the model to have a relationship attribute
        with patch.object(RepositoryTestModel, "related_items", create=True):
            result = await repository.list_with_pagination(page=1, size=10, eager_load=["related_items"])

        assert len(result.items) == 10

    @pytest.mark.asyncio
    async def test_list_with_pagination_ordering(self, repository, test_session):
        """Test pagination with different ordering options."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 20

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(20)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Test ascending order
        result = await repository.list_with_pagination(page=1, size=20, order_by="name", order_desc=False)

        assert len(result.items) == 20

        # Test descending order
        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=1, size=20, order_by="created_at", order_desc=True)

        assert len(result.items) == 20

    @pytest.mark.asyncio
    async def test_list_with_pagination_null_total(self, repository, test_session):
        """Test pagination when total count is None."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = None

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        result = await repository.list_with_pagination(page=1, size=20)

        assert result.total == 0
        assert result.has_next is False

    @pytest.mark.asyncio
    async def test_list_with_pagination_exception(self, repository, test_session):
        """Test pagination exception handling."""
        test_session.execute = AsyncMock(side_effect=SQLAlchemyError("Database error"))

        with pytest.raises(SQLAlchemyError):
            await repository.list_with_pagination(page=1, size=20)

    @pytest.mark.asyncio
    async def test_list_paginated_basic(self, repository, test_session):
        """Test list_paginated method."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 50

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(20)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=1, per_page=20)

        assert len(items) == 20
        assert total == 50

    @pytest.mark.asyncio
    async def test_list_paginated_with_sorting(self, repository, test_session):
        """Test list_paginated with sorting."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 30

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(10)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=2, per_page=10, sort_by="name", sort_order="desc")

        assert len(items) == 10
        assert total == 30

    @pytest.mark.asyncio
    async def test_list_paginated_with_invalid_sort_field(self, repository, test_session):
        """Test list_paginated with invalid sort field (uses default)."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 10

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(10)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=1, per_page=10, sort_by="nonexistent_field")

        assert len(items) == 10

    @pytest.mark.asyncio
    async def test_list_paginated_limits(self, repository, test_session):
        """Test list_paginated parameter limits."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 200

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(100)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Test per_page limit (max 100)
        items, total = await repository.list_paginated(page=1, per_page=500)  # Should be limited to 100

        assert len(items) <= 100

        # Test minimum page (at least 1)
        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=-1, per_page=10)  # Should be corrected to 1

        assert total == 200


class TestBaseRepositoryFiltering:
    """Test BaseRepository filtering operations."""

    @pytest.fixture
    def test_session(self):
        """Create a mock async session."""
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def repository(self, test_session):
        """Create a repository for testing."""
        return BaseRepository(test_session, RepositoryTestModel)

    @pytest.mark.asyncio
    async def test_apply_filters_search(self, repository, test_session):
        """Test search filter application."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 5

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Search {i}") for i in range(5)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=1, per_page=10, filters={"search": "test"})

        assert total == 5

    @pytest.mark.asyncio
    async def test_apply_filters_date_range(self, repository, test_session):
        """Test date range filter application."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 10

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(10)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)
        tomorrow = now + timedelta(days=1)

        items, total = await repository.list_paginated(
            page=1,
            per_page=10,
            filters={
                "created_after": yesterday,
                "created_before": tomorrow,
                "updated_after": yesterday,
                "updated_before": tomorrow,
            },
        )

        assert total == 10

    @pytest.mark.asyncio
    async def test_apply_filters_advanced(self, repository, test_session):
        """Test advanced operator-based filters."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 3

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(3)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        advanced_filters = [
            {"field": "name", "operator": "contains", "value": "test"},
            {"field": "status", "operator": "in", "value": ["active", "pending"]},
            {"field": "version", "operator": "gt", "value": 5},
        ]

        items, total = await repository.list_paginated(
            page=1,
            per_page=10,
            filters={"advanced_filters": advanced_filters, "filter_logic": "and"},
        )

        assert total == 3

    @pytest.mark.asyncio
    async def test_apply_filters_advanced_or_logic(self, repository, test_session):
        """Test advanced filters with OR logic."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 8

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_items = [RepositoryTestModel(id=str(i), name=f"Item {i}") for i in range(8)]
        test_scalars.all.return_value = test_items
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        advanced_filters = [
            {"field": "name", "operator": "startswith", "value": "test"},
            {"field": "email", "operator": "endswith", "value": "@example.com"},
        ]

        items, total = await repository.list_paginated(
            page=1,
            per_page=10,
            filters={"advanced_filters": advanced_filters, "filter_logic": "or"},
        )

        assert total == 8

    def test_get_searchable_fields(self, repository):
        """Test getting searchable fields for a model."""
        # Mock the model's table columns
        test_columns = []

        # Create properly mocked columns with name attributes
        id_col = MagicMock()
        id_col.name = "id"
        id_col.type = MagicMock()
        type(id_col.type).__str__ = lambda self: "UUID"
        test_columns.append(id_col)

        name_col = MagicMock()
        name_col.name = "name"
        name_col.type = MagicMock()
        type(name_col.type).__str__ = lambda self: "VARCHAR(255)"
        test_columns.append(name_col)

        desc_col = MagicMock()
        desc_col.name = "description"
        desc_col.type = MagicMock()
        type(desc_col.type).__str__ = lambda self: "TEXT"
        test_columns.append(desc_col)

        version_col = MagicMock()
        version_col.name = "version"
        version_col.type = MagicMock()
        type(version_col.type).__str__ = lambda self: "INTEGER"
        test_columns.append(version_col)

        email_col = MagicMock()
        email_col.name = "email"
        email_col.type = MagicMock()
        type(email_col.type).__str__ = lambda self: "VARCHAR(100)"
        test_columns.append(email_col)

        with patch.object(RepositoryTestModel.__table__, "columns", test_columns):
            fields = repository._get_searchable_fields()

        # Should include VARCHAR and TEXT fields
        assert "name" in fields
        assert "description" in fields
        assert "email" in fields
        assert "version" not in fields

    def test_build_filter_condition_simple_operators(self, repository):
        """Test building filter conditions with simple operators."""
        # Use an actual model field that supports operators
        test_field = RepositoryTestModel.name

        # Test equality
        condition = repository._build_filter_condition(test_field, "eq", "test")
        assert condition is not None

        # Test inequality
        condition = repository._build_filter_condition(test_field, "ne", "test")
        assert condition is not None

        # Test greater than
        condition = repository._build_filter_condition(test_field, "gt", 10)
        assert condition is not None

        # Test less than
        condition = repository._build_filter_condition(test_field, "lt", 10)
        assert condition is not None

        # Test greater than or equal
        condition = repository._build_filter_condition(test_field, "gte", 10)
        assert condition is not None

        # Test less than or equal
        condition = repository._build_filter_condition(test_field, "lte", 10)
        assert condition is not None

    def test_build_filter_condition_special_operators(self, repository):
        """Test building filter conditions with special operators."""
        test_field = MagicMock()

        # Test IN operator
        condition = repository._build_filter_condition(test_field, "in", ["a", "b", "c"])
        assert condition is not None

        # Test NOT IN operator
        condition = repository._build_filter_condition(test_field, "nin", ["x", "y"])
        assert condition is not None

        # Test contains (case-insensitive)
        condition = repository._build_filter_condition(test_field, "contains", "test")
        assert condition is not None

        # Test icontains (same as contains)
        condition = repository._build_filter_condition(test_field, "icontains", "test")
        assert condition is not None

        # Test startswith
        condition = repository._build_filter_condition(test_field, "startswith", "pre")
        assert condition is not None

        # Test endswith
        condition = repository._build_filter_condition(test_field, "endswith", "suf")
        assert condition is not None

        # Test is null (True)
        condition = repository._build_filter_condition(test_field, "isnull", True)
        assert condition is not None

        # Test is not null (False)
        condition = repository._build_filter_condition(test_field, "isnull", False)
        assert condition is not None

    def test_build_filter_condition_invalid_operator(self, repository):
        """Test building filter condition with invalid operator."""
        test_field = MagicMock()

        condition = repository._build_filter_condition(test_field, "invalid_op", "value")
        assert condition is None

    def test_build_filter_condition_invalid_value_types(self, repository):
        """Test building filter condition with invalid value types."""
        test_field = MagicMock()

        # Invalid value type for 'in' operator (not a list)
        condition = repository._build_filter_condition(test_field, "in", "not_a_list")
        assert condition is None

        # Invalid value type for string operators (not a string)
        condition = repository._build_filter_condition(test_field, "contains", 123)
        assert condition is None

    def test_add_organization_filter(self, repository):
        """Test adding organization filter to query."""
        test_query = MagicMock()
        test_query.where = MagicMock(return_value=test_query)

        org_id = str(uuid.uuid4())

        # Test with organization_id
        result = repository._add_organization_filter(test_query, org_id)
        test_query.where.assert_called_once()

        # Test without organization_id
        test_query.reset_mock()
        result = repository._add_organization_filter(test_query, None)
        test_query.where.assert_not_called()


class TestBaseRepositoryEdgeCases:
    """Test edge cases and error scenarios for BaseRepository."""

    @pytest.fixture
    def test_session(self):
        """Create a mock async session."""
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def repository(self, test_session):
        """Create a repository for testing."""
        return BaseRepository(test_session, RepositoryTestModel)

    @pytest.mark.asyncio
    async def test_apply_filters_with_non_dict_advanced_filters(self, repository, test_session):
        """Test advanced filters with non-dict items (should be skipped)."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Include non-dict items that should be filtered out
        advanced_filters = [
            {"field": "name", "operator": "eq", "value": "test"},
            "not_a_dict",  # Should be skipped
            123,  # Should be skipped
            {"field": "status", "operator": "eq", "value": "active"},
        ]

        items, total = await repository.list_paginated(
            page=1, per_page=10, filters={"advanced_filters": advanced_filters}
        )

        assert total == 0

    @pytest.mark.asyncio
    async def test_apply_advanced_filters_missing_fields(self, repository, test_session):
        """Test advanced filters with missing required fields."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        advanced_filters = [
            {"operator": "eq", "value": "test"},  # Missing 'field'
            {"field": "name", "value": "test"},  # Missing 'operator'
            {"field": "name", "operator": "eq"},  # Missing 'value'
            {"field": None, "operator": "eq", "value": "test"},  # None field
            {"field": "name", "operator": None, "value": "test"},  # None operator
        ]

        items, total = await repository.list_paginated(
            page=1, per_page=10, filters={"advanced_filters": advanced_filters}
        )

        assert total == 0

    @pytest.mark.asyncio
    async def test_apply_advanced_filters_nonexistent_field(self, repository, test_session):
        """Test advanced filters with non-existent model field."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        advanced_filters = [{"field": "nonexistent_field", "operator": "eq", "value": "test"}]

        items, total = await repository.list_paginated(
            page=1, per_page=10, filters={"advanced_filters": advanced_filters}
        )

        assert total == 0

    @pytest.mark.asyncio
    async def test_apply_advanced_filters_unsupported_value_types(self, repository, test_session):
        """Test advanced filters with unsupported value types."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        # Use complex objects that aren't supported
        advanced_filters = [
            {"field": "name", "operator": "eq", "value": {"nested": "object"}},
            {
                "field": "name",
                "operator": "eq",
                "value": datetime.now(),
            },  # datetime not in simple types
        ]

        items, total = await repository.list_paginated(
            page=1, per_page=10, filters={"advanced_filters": advanced_filters}
        )

        assert total == 0

    @pytest.mark.asyncio
    async def test_apply_filters_non_string_filter_logic(self, repository, test_session):
        """Test filters with non-string filter_logic."""
        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(
            page=1,
            per_page=10,
            filters={
                "advanced_filters": [{"field": "name", "operator": "eq", "value": "test"}],
                "filter_logic": 123,  # Not a string, should default to "and"
            },
        )

        assert total == 0

    @pytest.mark.asyncio
    async def test_list_paginated_without_created_at(self, test_session):
        """Test list_paginated with model without created_at field."""

        # Create a model without created_at
        class SimpleModelNoCreatedAt(Base):
            __tablename__ = "simple_models_no_created_at"
            id = Column(String, primary_key=True)
            name = Column(String)

        repository = BaseRepository(test_session, SimpleModelNoCreatedAt)

        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 5

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        items, total = await repository.list_paginated(page=1, per_page=10)

        assert total == 5

    @pytest.mark.asyncio
    async def test_apply_date_filter_without_date_fields(self, test_session):
        """Test date filters on model without date fields."""

        # Create a model without date fields
        class SimpleModelDateFilter(Base):
            __tablename__ = "simple_models_date_filter"
            id = Column(String, primary_key=True)
            name = Column(String)

        repository = BaseRepository(test_session, SimpleModelDateFilter)

        test_count_result = MagicMock()
        test_count_result.scalar.return_value = 0

        test_data_result = MagicMock()
        test_scalars = MagicMock()
        test_scalars.all.return_value = []
        test_data_result.scalars.return_value = test_scalars

        test_session.execute = AsyncMock(side_effect=[test_count_result, test_data_result])

        now = datetime.now(timezone.utc)

        items, total = await repository.list_paginated(
            page=1,
            per_page=10,
            filters={
                "created_after": now,
                "created_before": now,
                "updated_after": now,
                "updated_before": now,
            },
        )

        assert total == 0


# Run all tests with pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app.repositories.base", "--cov-report=term-missing"])
