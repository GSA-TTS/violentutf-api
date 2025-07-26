"""Base repository class providing common CRUD operations."""

import uuid
from typing import Any, Dict, Generic, Iterator, List, Optional, Type, TypeVar, Union

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
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
    """

    def __init__(self, session: AsyncSession, model: Type[T]):
        """
        Initialize repository with database session and model.

        Args:
            session: Async SQLAlchemy session
            model: SQLAlchemy model class
        """
        self.session = session
        self.model = model
        self.logger = logger.bind(repository=self.__class__.__name__, model=model.__name__)

    async def create(self, **kwargs: Any) -> T:  # noqa: ANN401
        """
        Create a new entity.

        Args:
            **kwargs: Entity attributes

        Returns:
            Created entity

        Raises:
            ValueError: If required fields are missing
            IntegrityError: If constraints are violated
        """
        try:
            # Generate UUID if not provided
            if "id" not in kwargs:
                kwargs["id"] = str(uuid.uuid4())

            # Set audit fields
            if "created_by" not in kwargs:
                kwargs["created_by"] = "system"
            if "updated_by" not in kwargs:
                kwargs["updated_by"] = kwargs.get("created_by", "system")

            entity = self.model(**kwargs)
            self.session.add(entity)
            await self.session.flush()  # Get the ID without committing

            self.logger.info("Entity created", entity_id=entity.id)
            return entity

        except Exception as e:
            self.logger.error("Failed to create entity", error=str(e), kwargs=kwargs)
            raise

    async def get_by_id(self, entity_id: Union[str, uuid.UUID]) -> Optional[T]:
        """
        Get entity by ID.

        Args:
            entity_id: Entity identifier

        Returns:
            Entity if found, None otherwise
        """
        try:
            entity_id_str = str(entity_id)

            # Build query with soft delete filter if model has is_deleted field
            if hasattr(self.model, "is_deleted"):
                query = select(self.model).where(
                    and_(self.model.id == entity_id_str, getattr(self.model, "is_deleted") == False)  # noqa: E712
                )
            else:
                query = select(self.model).where(self.model.id == entity_id_str)

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

    async def update(self, entity_id: Union[str, uuid.UUID], **kwargs: Any) -> Optional[T]:  # noqa: ANN401
        """
        Update entity by ID.

        Args:
            entity_id: Entity identifier
            **kwargs: Fields to update

        Returns:
            Updated entity if found, None otherwise
        """
        try:
            entity_id_str = str(entity_id)

            # Remove ID from update data to prevent accidental changes
            kwargs.pop("id", None)

            # Set audit fields
            if "updated_by" not in kwargs:
                kwargs["updated_by"] = "system"

            # Increment version for optimistic locking
            if hasattr(self.model, "version"):
                # Get current version first
                current_entity = await self.get_by_id(entity_id_str)
                if current_entity and hasattr(current_entity, "version"):
                    kwargs["version"] = getattr(current_entity, "version") + 1

            # Update entity with soft delete filter if model has is_deleted field
            if hasattr(self.model, "is_deleted"):
                query = (
                    update(self.model)
                    .where(
                        and_(self.model.id == entity_id_str, getattr(self.model, "is_deleted") == False)
                    )  # noqa: E712
                    .values(**kwargs)
                )
            else:
                query = update(self.model).where(self.model.id == entity_id_str).values(**kwargs)

            result = await self.session.execute(query)

            if result.rowcount > 0:
                # Fetch updated entity
                updated_entity = await self.get_by_id(entity_id_str)
                self.logger.info("Entity updated", entity_id=entity_id_str, updated_fields=list(kwargs.keys()))
                return updated_entity
            else:
                self.logger.warning("Entity not found for update", entity_id=entity_id_str)
                return None

        except Exception as e:
            self.logger.error("Failed to update entity", entity_id=str(entity_id), error=str(e))
            raise

    async def delete(self, entity_id: Union[str, uuid.UUID], hard_delete: bool = False) -> bool:
        """
        Delete entity by ID (soft delete by default).

        Args:
            entity_id: Entity identifier
            hard_delete: If True, permanently delete; if False, soft delete

        Returns:
            True if entity was deleted, False if not found
        """
        try:
            entity_id_str = str(entity_id)

            if hard_delete:
                # Hard delete - permanently remove from database
                delete_query = delete(self.model).where(self.model.id == entity_id_str)
                result = await self.session.execute(delete_query)
                deleted = result.rowcount > 0

                if deleted:
                    self.logger.info("Entity hard deleted", entity_id=entity_id_str)
            else:
                # Soft delete - mark as deleted (only for models with soft delete support)
                if hasattr(self.model, "is_deleted"):
                    deleted_kwargs = {"is_deleted": True, "deleted_by": "system", "deleted_at": func.now()}

                    update_query = (
                        update(self.model)
                        .where(
                            and_(self.model.id == entity_id_str, getattr(self.model, "is_deleted") == False)
                        )  # noqa: E712
                        .values(**deleted_kwargs)
                    )

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
        filters: Optional[Dict[str, Any]] = None,
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
                        query = query.options(selectinload(getattr(self.model, relationship)))

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

    async def count(self, filters: Optional[Dict[str, Any]] = None, include_deleted: bool = False) -> int:
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
                    and_(self.model.id == entity_id_str, getattr(self.model, "is_deleted") == False)  # noqa: E712
                )
            else:
                query = select(func.count(self.model.id)).where(self.model.id == entity_id_str)

            result = await self.session.execute(query)
            count = result.scalar()

            exists = (count or 0) > 0
            self.logger.debug("Checked entity existence", entity_id=entity_id_str, exists=exists)
            return exists

        except Exception as e:
            self.logger.error("Failed to check entity existence", entity_id=str(entity_id), error=str(e))
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
                        and_(self.model.id == entity_id_str, getattr(self.model, "is_deleted") == True)
                    )  # noqa: E712
                    .values(**restore_kwargs)
                )

                result = await self.session.execute(query)
                restored = result.rowcount > 0

                if restored:
                    self.logger.info("Entity restored", entity_id=entity_id_str, restored_by=restored_by)
                else:
                    self.logger.warning("Entity not found for restoration", entity_id=entity_id_str)

                return restored
            else:
                self.logger.warning("Model does not support soft delete/restore", entity_id=entity_id_str)
                return False

        except Exception as e:
            self.logger.error("Failed to restore entity", entity_id=str(entity_id), error=str(e))
            raise
