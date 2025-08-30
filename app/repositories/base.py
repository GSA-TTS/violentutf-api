"""Base repository class providing common CRUD operations."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Generic, Iterator, List, Optional, Tuple, Type, TypeVar, Union

from sqlalchemy import and_, delete, desc, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement
from structlog.stdlib import get_logger

from ..db.base_class import Base
from ..models.mixins import BaseModelMixin

logger = get_logger(__name__)

# Type variable for model classes
T = TypeVar("T", bound="Base")


class Page(Generic[T]):
    """Pagination result container."""

    def __init__(  # noqa: D107
        self,
        items: List[T],
        total: int,
        page: int,
        size: int,
        has_next: bool,
        has_prev: bool,
    ):
        self.items = items
        self.total = total
        self.page = page
        self.size = size
        self.has_next = has_next
        self.has_prev = has_prev
        self.pages = (total + size - 1) // size if size > 0 else 0

    def __iter__(self) -> Iterator[T]:
        """Allow iteration over page items."""
        return iter(self.items)

    def __len__(self) -> int:
        """Return number of items on this page."""
        return len(self.items)

    def __getitem__(self, index: int) -> T:
        """Allow indexing into page items."""
        return self.items[index]


class BaseRepository(Generic[T]):
    """
    Base repository providing common CRUD operations.

    Following patterns from original ViolentUTF repository with enhancements:
    - Soft delete support
    - Audit trail integration
    - Connection resilience patterns
    - Query optimization
    - Advanced filtering and pagination
    """

    def __init__(self, session: AsyncSession, model: Optional[Type[T]] = None):
        """
        Initialize repository with database session and model.

        Args:
            session: Async SQLAlchemy session
            model: SQLAlchemy model class (optional if set in subclass)
        """
        self.session = session
        if model:
            self.model = model
        elif not hasattr(self, "model"):
            raise ValueError("Model must be provided either in constructor or as class attribute")
        self.logger = logger.bind(repository=self.__class__.__name__, model=self.model.__name__)

    async def get_by_id(
        self,
        entity_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> Optional[T]:
        """
        Get entity by ID with optional organization filtering for multi-tenant isolation.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Entity if found, None otherwise
        """
        try:
            entity_id_str = str(entity_id)

            # Start with base filters
            filters = [self.model.id == entity_id_str]

            # Add soft delete filter if model supports it
            if hasattr(self.model, "is_deleted"):
                filters.append(getattr(self.model, "is_deleted") == False)  # noqa: E712

            # CRITICAL: Add organization filtering if model supports multi-tenancy and organization_id is provided
            if organization_id and hasattr(self.model, "organization_id"):
                filters.append(getattr(self.model, "organization_id") == str(organization_id))

            # Build query with all filters
            query = select(self.model).where(and_(*filters))

            result = await self.session.execute(query)
            entity = result.scalar_one_or_none()

            if entity:
                self.logger.debug("Entity found", entity_id=entity_id_str)
            else:
                self.logger.debug("Entity not found", entity_id=entity_id_str)

            return entity

        except Exception as e:
            self.logger.error("Failed to get entity by ID", entity_id=str(entity_id), error=str(e))
            raise

    async def update(
        self,
        entity_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        **kwargs: object,
    ) -> Optional[T]:
        """
        Update entity by ID with optional organization filtering for multi-tenant isolation.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering
            **kwargs: Fields to update

        Returns:
            Updated entity if found, None otherwise
        """
        try:
            entity_id_str = str(entity_id)

            # Remove ID from update data to prevent accidental changes
            kwargs.pop("id", None)

            # Filter out None values to avoid overwriting with NULL
            kwargs = {k: v for k, v in kwargs.items() if v is not None}

            # Set audit fields
            if "updated_by" not in kwargs:
                kwargs["updated_by"] = "system"

            # Ensure we have something to update
            if not kwargs or (len(kwargs) == 1 and "updated_by" in kwargs):
                self.logger.warning("No fields to update", entity_id=entity_id_str)
                return await self.get_by_id(entity_id_str, organization_id)

            # Increment version for optimistic locking
            if hasattr(self.model, "version"):
                # Get current version first (with organization filtering)
                current_entity = await self.get_by_id(entity_id_str, organization_id)
                if current_entity and hasattr(current_entity, "version"):
                    current_version = getattr(current_entity, "version")
                    # Handle None version by starting at 1
                    kwargs["version"] = (current_version or 0) + 1

            # Build update filters
            update_filters = [self.model.id == entity_id_str]

            # Add soft delete filter if model supports it
            if hasattr(self.model, "is_deleted"):
                update_filters.append(getattr(self.model, "is_deleted") == False)  # noqa: E712

            # CRITICAL: Add organization filtering if model supports multi-tenancy and organization_id is provided
            if organization_id and hasattr(self.model, "organization_id"):
                update_filters.append(getattr(self.model, "organization_id") == str(organization_id))

            # Build update query
            query = update(self.model).where(and_(*update_filters)).values(**kwargs)

            result = await self.session.execute(query)

            if result.rowcount > 0:
                # Fetch updated entity (with organization filtering)
                updated_entity = await self.get_by_id(entity_id_str, organization_id)
                self.logger.info(
                    "Entity updated",
                    entity_id=entity_id_str,
                    updated_fields=list(kwargs.keys()),
                )
                return updated_entity
            else:
                self.logger.warning("Entity not found for update", entity_id=entity_id_str)
                return None

        except Exception as e:
            self.logger.error("Failed to update entity", entity_id=str(entity_id), error=str(e))
            raise

    async def delete(
        self,
        entity_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        hard_delete: bool = False,
    ) -> bool:
        """
        Delete entity by ID (soft delete by default) with optional organization filtering.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering
            hard_delete: If True, permanently delete; if False, soft delete

        Returns:
            True if entity was deleted, False if not found
        """
        try:
            entity_id_str = str(entity_id)

            # Build delete filters
            delete_filters = [self.model.id == entity_id_str]

            # CRITICAL: Add organization filtering if model supports multi-tenancy and organization_id is provided
            if organization_id and hasattr(self.model, "organization_id"):
                delete_filters.append(getattr(self.model, "organization_id") == str(organization_id))

            if hard_delete:
                # Hard delete - permanently remove from database
                delete_query = delete(self.model).where(and_(*delete_filters))
                result = await self.session.execute(delete_query)
                deleted = result.rowcount > 0

                if deleted:
                    self.logger.info("Entity hard deleted", entity_id=entity_id_str)
            else:
                # Soft delete - mark as deleted (only for models with soft delete support)
                if hasattr(self.model, "is_deleted"):
                    deleted_kwargs = {
                        "is_deleted": True,
                        "deleted_by": "system",
                        "deleted_at": func.now(),
                    }

                    # Add soft delete filter to delete_filters
                    soft_delete_filters = delete_filters + [getattr(self.model, "is_deleted") == False]  # noqa: E712

                    update_query = update(self.model).where(and_(*soft_delete_filters)).values(**deleted_kwargs)

                    result = await self.session.execute(update_query)
                    deleted = result.rowcount > 0

                    if deleted:
                        self.logger.info("Entity soft deleted", entity_id=entity_id_str)
                else:
                    # For models without soft delete, treat as not found
                    deleted = False
                    self.logger.warning("Model does not support soft delete", entity_id=entity_id_str)

            if not deleted:
                self.logger.warning("Entity not found for deletion", entity_id=entity_id_str)

            return deleted

        except Exception as e:
            self.logger.error("Failed to delete entity", entity_id=str(entity_id), error=str(e))
            raise

    async def list_with_pagination(  # noqa: C901
        self,
        page: int = 1,
        size: int = 20,
        filters: Optional[Dict[str, object]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_deleted: bool = False,
        eager_load: Optional[List[str]] = None,
        order_by: Optional[str] = "created_at",
        order_desc: bool = True,
    ) -> Page[T]:
        """
        List entities with pagination and filtering.

        Args:
            page: Page number (1-based)
            size: Page size
            filters: Optional filters to apply
            include_deleted: Whether to include soft-deleted entities
            eager_load: List of relationships to eager load
            order_by: Field to order by
            order_desc: Whether to order in descending order

        Returns:
            Page of entities with pagination metadata
        """
        try:
            # Validate pagination parameters
            page = max(1, page)  # Ensure page is at least 1
            size = max(1, min(size, 100))  # Limit page size to 100

            # Build base query
            query = select(self.model)

            # Apply soft delete filter if model has is_deleted field
            if not include_deleted and hasattr(self.model, "is_deleted"):
                query = query.where(getattr(self.model, "is_deleted") == False)  # noqa: E712

            # CRITICAL: Add organization filtering if model supports multi-tenancy and organization_id is provided
            if organization_id and hasattr(self.model, "organization_id"):
                query = query.where(getattr(self.model, "organization_id") == str(organization_id))

            # Apply custom filters
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model, field):
                        if isinstance(value, list):
                            # IN clause for lists
                            query = query.where(getattr(self.model, field).in_(value))
                        else:
                            # Equality for single values
                            query = query.where(getattr(self.model, field) == value)

            # Apply eager loading
            if eager_load:
                for relationship in eager_load:
                    if hasattr(self.model, relationship):
                        try:
                            query = query.options(selectinload(getattr(self.model, relationship)))
                        except Exception as e:
                            self.logger.warning(
                                "Failed to apply eager loading",
                                relationship=relationship,
                                error=str(e),
                            )

            # Count total items before pagination
            count_query = select(func.count()).select_from(query.subquery())
            total_result = await self.session.execute(count_query)
            total = total_result.scalar()

            # Apply ordering
            if order_by and hasattr(self.model, order_by):
                order_field = getattr(self.model, order_by)
                if order_desc:
                    query = query.order_by(order_field.desc())
                else:
                    query = query.order_by(order_field.asc())

            # Apply pagination
            offset = (page - 1) * size
            query = query.offset(offset).limit(size)

            # Execute query
            result = await self.session.execute(query)
            items = list(result.scalars().all())

            # Calculate pagination metadata
            has_next = offset + size < total if total is not None else False
            has_prev = page > 1

            self.logger.debug(
                "Listed entities with pagination",
                page=page,
                size=size,
                total=total,
                returned=len(items),
                filters=filters,
            )

            return Page(
                items=items,
                total=total or 0,
                page=page,
                size=size,
                has_next=has_next,
                has_prev=has_prev,
            )

        except Exception as e:
            self.logger.error("Failed to list entities", page=page, size=size, error=str(e))
            raise

    async def count(self, filters: Optional[Dict[str, object]] = None, include_deleted: bool = False) -> int:
        """
        Count entities with optional filtering.

        Args:
            filters: Optional filters to apply
            include_deleted: Whether to include soft-deleted entities

        Returns:
            Count of matching entities
        """
        try:
            # Build count query
            query = select(func.count(self.model.id))

            # Apply soft delete filter if model has is_deleted field
            if not include_deleted and hasattr(self.model, "is_deleted"):
                query = query.where(getattr(self.model, "is_deleted") == False)  # noqa: E712

            # Apply custom filters
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model, field):
                        if isinstance(value, list):
                            # IN clause for lists
                            query = query.where(getattr(self.model, field).in_(value))
                        else:
                            # Equality for single values
                            query = query.where(getattr(self.model, field) == value)

            result = await self.session.execute(query)
            count = result.scalar()

            self.logger.debug("Counted entities", count=count, filters=filters)
            return count or 0

        except Exception as e:
            self.logger.error("Failed to count entities", filters=filters, error=str(e))
            raise

    async def exists(self, entity_id: Union[str, uuid.UUID]) -> bool:
        """
        Check if entity exists.

        Args:
            entity_id: Entity identifier

        Returns:
            True if entity exists and is not soft-deleted
        """
        try:
            entity_id_str = str(entity_id)

            # Build query with soft delete filter if model has is_deleted field
            if hasattr(self.model, "is_deleted"):
                query = select(func.count(self.model.id)).where(
                    and_(
                        self.model.id == entity_id_str,
                        getattr(self.model, "is_deleted") == False,
                    )  # noqa: E712
                )
            else:
                query = select(func.count(self.model.id)).where(self.model.id == entity_id_str)

            result = await self.session.execute(query)
            count = result.scalar()

            exists = (count or 0) > 0
            self.logger.debug("Checked entity existence", entity_id=entity_id_str, exists=exists)
            return exists

        except Exception as e:
            self.logger.error(
                "Failed to check entity existence",
                entity_id=str(entity_id),
                error=str(e),
            )
            raise

    async def restore(self, entity_id: Union[str, uuid.UUID], restored_by: str = "system") -> bool:
        """
        Restore a soft-deleted entity.

        Args:
            entity_id: Entity identifier
            restored_by: User who restored the entity

        Returns:
            True if entity was restored, False if not found
        """
        try:
            entity_id_str = str(entity_id)

            restore_kwargs = {
                "is_deleted": False,
                "deleted_by": None,
                "deleted_at": None,
                "updated_by": restored_by,
            }

            # Only restore if model supports soft delete
            if hasattr(self.model, "is_deleted"):
                query = (
                    update(self.model)
                    .where(
                        and_(
                            self.model.id == entity_id_str,
                            getattr(self.model, "is_deleted") == True,
                        )
                    )  # noqa: E712
                    .values(**restore_kwargs)
                )

                result = await self.session.execute(query)
                restored = result.rowcount > 0

                if restored:
                    self.logger.info(
                        "Entity restored",
                        entity_id=entity_id_str,
                        restored_by=restored_by,
                    )
                else:
                    self.logger.warning("Entity not found for restoration", entity_id=entity_id_str)

                return restored
            else:
                self.logger.warning(
                    "Model does not support soft delete/restore",
                    entity_id=entity_id_str,
                )
                return False

        except Exception as e:
            self.logger.error("Failed to restore entity", entity_id=str(entity_id), error=str(e))
            raise

    # Enhanced methods for CRUD router compatibility

    async def get(
        self,
        entity_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> Optional[T]:
        """Alias for get_by_id for consistency with CRUD router."""
        return await self.get_by_id(entity_id, organization_id)

    def _add_organization_filter(
        self, query: Select[Tuple[T]], organization_id: Optional[Union[str, uuid.UUID]]
    ) -> Select[Tuple[T]]:
        """Add organization filtering to query if model supports multi-tenancy.

        Args:
            query: SQLAlchemy select query
            organization_id: Organization ID to filter by

        Returns:
            Query with organization filter applied if applicable
        """
        if organization_id and hasattr(self.model, "organization_id"):
            query = query.where(getattr(self.model, "organization_id") == str(organization_id))
        return query

    async def create(self, data: Dict[str, object]) -> T:
        """
        Create entity from dictionary data.

        Args:
            data: Dictionary of entity attributes

        Returns:
            Created entity
        """
        # Generate UUID if not provided
        if "id" not in data:
            data["id"] = str(uuid.uuid4())

        # Set audit fields
        if "created_by" not in data:
            data["created_by"] = "system"
        if "updated_by" not in data:
            data["updated_by"] = data.get("created_by", "system")

        # Set timestamps if model has them and they're not provided
        now = datetime.now(timezone.utc)
        if hasattr(self.model, "created_at") and "created_at" not in data:
            data["created_at"] = now
        if hasattr(self.model, "updated_at") and "updated_at" not in data:
            data["updated_at"] = now

        entity = self.model(**data)
        self.session.add(entity)
        await self.session.flush()  # Get the ID without committing

        self.logger.info("Entity created", entity_id=entity.id)
        return entity

    async def delete_permanent(self, entity_id: Union[str, uuid.UUID]) -> bool:
        """
        Permanently delete entity.

        Args:
            entity_id: Entity identifier

        Returns:
            True if entity was deleted, False if not found
        """
        entity_id_str = str(entity_id)

        delete_query = delete(self.model).where(self.model.id == entity_id_str)
        result = await self.session.execute(delete_query)
        deleted = result.rowcount > 0

        if deleted:
            self.logger.info("Entity permanently deleted", entity_id=entity_id_str)
        else:
            self.logger.warning("Entity not found for permanent deletion", entity_id=entity_id_str)

        return deleted

    async def list_paginated(
        self,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, object]] = None,
        sort_by: Optional[str] = None,
        sort_order: str = "asc",
        include_deleted: bool = False,
    ) -> Tuple[List[T], int]:
        """
        List entities with pagination and filtering.

        Args:
            page: Page number (1-based)
            per_page: Items per page
            filters: Optional filters to apply
            sort_by: Field to sort by
            sort_order: Sort order ("asc" or "desc")
            include_deleted: Whether to include soft-deleted entities

        Returns:
            Tuple of (items, total_count)
        """
        # Validate pagination parameters
        page = max(1, page)
        per_page = max(1, min(per_page, 100))

        # Build base query
        query = select(self.model)

        # Apply soft delete filter
        if not include_deleted and hasattr(self.model, "is_deleted"):
            query = query.where(getattr(self.model, "is_deleted") == False)

        # Apply filters
        if filters:
            query = self._apply_filters(query, filters)

        # Count total items
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply sorting
        if sort_by and hasattr(self.model, sort_by):
            sort_field = getattr(self.model, sort_by)
            if sort_order.lower() == "desc":
                query = query.order_by(desc(sort_field))
            else:
                query = query.order_by(sort_field)
        else:
            # Default sort by created_at desc if available
            # Use getattr to safely access the attribute
            created_at_col = getattr(self.model, "created_at", None)
            if created_at_col is not None:
                query = query.order_by(desc(created_at_col))

        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)

        # Execute query
        result = await self.session.execute(query)
        items = list(result.scalars().all())

        self.logger.debug(
            "Listed entities with pagination",
            page=page,
            per_page=per_page,
            total=total_count,
            returned=len(items),
            filters=filters,
        )

        return items, total_count

    def _apply_filters(self, query: Select[Tuple[T]], filters: Dict[str, object]) -> Select[Tuple[T]]:
        """Apply filters to query."""
        for key, value in filters.items():
            if key == "search" and value and isinstance(value, str):
                # Apply search across searchable fields
                query = self._apply_search_filter(query, value)
            elif key in [
                "created_after",
                "created_before",
                "updated_after",
                "updated_before",
            ] and isinstance(value, datetime):
                # Apply date range filters
                query = self._apply_date_filter(query, key, value)
            elif key == "advanced_filters" and value and isinstance(value, list):
                # Apply advanced operator-based filters
                filter_logic = filters.get("filter_logic", "and")
                logic = filter_logic if isinstance(filter_logic, str) else "and"
                # Type cast to satisfy mypy
                advanced_filters = [f for f in value if isinstance(f, dict)]
                query = self._apply_advanced_filters(query, advanced_filters, logic)
            elif hasattr(self.model, key):
                # Apply simple field filters
                if isinstance(value, list):
                    query = query.where(getattr(self.model, key).in_(value))
                else:
                    query = query.where(getattr(self.model, key) == value)

        return query

    def _apply_search_filter(self, query: Select[Tuple[T]], search_term: str) -> Select[Tuple[T]]:
        """Apply search filter across searchable fields."""
        # Define searchable fields for each model
        searchable_fields = self._get_searchable_fields()

        if not searchable_fields:
            return query

        search_conditions = []
        for field_name in searchable_fields:
            if hasattr(self.model, field_name):
                field = getattr(self.model, field_name)
                # Use ilike for case-insensitive search
                search_conditions.append(field.ilike(f"%{search_term}%"))

        if search_conditions:
            query = query.where(or_(*search_conditions))

        return query

    def _get_searchable_fields(self) -> List[str]:
        """Get list of searchable fields for the model."""
        # Override in subclasses to define searchable fields
        # Default to common string fields
        searchable = []
        for column in self.model.__table__.columns:
            if str(column.type).startswith("VARCHAR") or str(column.type).startswith("TEXT"):
                searchable.append(column.name)
        return searchable

    def _apply_date_filter(self, query: Select[Tuple[T]], filter_type: str, date_value: datetime) -> Select[Tuple[T]]:
        """Apply date range filters."""
        created_at_col = getattr(self.model, "created_at", None)
        updated_at_col = getattr(self.model, "updated_at", None)

        if filter_type == "created_after" and created_at_col is not None:
            query = query.where(created_at_col >= date_value)
        elif filter_type == "created_before" and created_at_col is not None:
            query = query.where(created_at_col <= date_value)
        elif filter_type == "updated_after" and updated_at_col is not None:
            query = query.where(updated_at_col >= date_value)
        elif filter_type == "updated_before" and updated_at_col is not None:
            query = query.where(updated_at_col <= date_value)

        return query

    def _apply_advanced_filters(
        self,
        query: Select[Tuple[T]],
        filters: List[Dict[str, object]],
        logic: str = "and",
    ) -> Select[Tuple[T]]:
        """Apply advanced operator-based filters."""
        conditions: List[ColumnElement[bool]] = []

        for filter_spec in filters:
            field_name = filter_spec.get("field")
            operator = filter_spec.get("operator")
            value = filter_spec.get("value")

            if (
                not field_name
                or not operator
                or not isinstance(field_name, str)
                or not isinstance(operator, str)
                or not hasattr(self.model, field_name)
            ):
                continue

            field = getattr(self.model, field_name)
            # Type cast for specific filter types
            if isinstance(value, (str, int, float, bool, type(None))) or (
                isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value)
            ):
                condition = self._build_filter_condition(field, operator, value)
            else:
                continue  # Skip unsupported value types

            if condition is not None:
                conditions.append(condition)

        if conditions:
            if logic.lower() == "or":
                query = query.where(or_(*conditions))
            else:
                query = query.where(and_(*conditions))

        return query

    def _build_filter_condition(
        self,
        field: ColumnElement[object],
        operator: str,
        value: Union[str, int, float, bool, List[object], None],
    ) -> Optional[ColumnElement[bool]]:
        """Build filter condition based on operator."""
        # Define operator mappings for better maintainability
        simple_operators = {
            "eq": lambda f, v: f == v,
            "ne": lambda f, v: f != v,
            "gt": lambda f, v: f > v,
            "lt": lambda f, v: f < v,
            "gte": lambda f, v: f >= v,
            "lte": lambda f, v: f <= v,
        }

        # Handle simple comparison operators
        if operator in simple_operators:
            return simple_operators[operator](field, value)  # type: ignore[no-untyped-call]

        # Handle special operators with type checking
        return self._build_special_filter_condition(field, operator, value)

    def _build_special_filter_condition(
        self,
        field: ColumnElement[object],
        operator: str,
        value: Union[str, int, float, bool, List[object], None],
    ) -> Optional[ColumnElement[bool]]:
        """Build special filter conditions (list, string, null operations)."""
        if operator == "in" and isinstance(value, list):
            return field.in_(value)
        elif operator == "nin" and isinstance(value, list):
            return ~field.in_(value)
        elif operator in ("contains", "icontains") and isinstance(value, str):
            return field.ilike(f"%{value}%")
        elif operator == "startswith" and isinstance(value, str):
            return field.ilike(f"{value}%")
        elif operator == "endswith" and isinstance(value, str):
            return field.ilike(f"%{value}")
        elif operator == "isnull":
            return field.is_(None) if value else field.is_not(None)

        return None
