"""Base repository interface for common CRUD operations."""

import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Generic, List, Optional, Tuple, TypeVar, Union

if TYPE_CHECKING:
    from ...db.base_class import Base
    from ..base import Page

T = TypeVar("T", bound="Base")


class IBaseRepository(ABC, Generic[T]):
    """
    Base repository interface defining common CRUD operations.

    This interface establishes the contract that all repositories must implement,
    ensuring consistent data access patterns across the application.
    """

    @abstractmethod
    async def get_by_id(
        self, entity_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[T]:
        """
        Get entity by ID with optional organization filtering for multi-tenant isolation.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Entity if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def create(self, data: Dict[str, Any]) -> T:
        """
        Create new entity from dictionary data.

        Args:
            data: Dictionary of entity attributes

        Returns:
            Created entity
        """
        raise NotImplementedError

    @abstractmethod
    async def update(
        self,
        entity_id: Union[str, uuid.UUID],
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        **kwargs: Any,
    ) -> Optional[T]:
        """
        Update entity by ID with optional organization filtering.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering
            **kwargs: Fields to update

        Returns:
            Updated entity if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError

    @abstractmethod
    async def list_with_pagination(
        self,
        page: int = 1,
        size: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_deleted: bool = False,
        eager_load: Optional[List[str]] = None,
        order_by: Optional[str] = "created_at",
        order_desc: bool = True,
    ) -> "Page[T]":
        """
        List entities with pagination and filtering.

        Args:
            page: Page number (1-based)
            size: Page size
            filters: Optional filters to apply
            organization_id: Optional organization ID for multi-tenant filtering
            include_deleted: Whether to include soft-deleted entities
            eager_load: List of relationships to eager load
            order_by: Field to order by
            order_desc: Whether to order in descending order

        Returns:
            Page of entities with pagination metadata
        """
        raise NotImplementedError

    @abstractmethod
    async def count(
        self,
        filters: Optional[Dict[str, Any]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_deleted: bool = False,
    ) -> int:
        """
        Count entities with optional filtering and organization filtering.

        Args:
            filters: Optional filters to apply
            organization_id: Optional organization ID for multi-tenant filtering
            include_deleted: Whether to include soft-deleted entities

        Returns:
            Count of matching entities
        """
        raise NotImplementedError

    @abstractmethod
    async def exists(
        self, entity_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Check if entity exists with optional organization filtering.

        Args:
            entity_id: Entity identifier
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if entity exists and is not soft-deleted
        """
        raise NotImplementedError

    @abstractmethod
    async def restore(
        self,
        entity_id: Union[str, uuid.UUID],
        restored_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Restore a soft-deleted entity with optional organization filtering.

        Args:
            entity_id: Entity identifier
            restored_by: User who restored the entity
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if entity was restored, False if not found
        """
        raise NotImplementedError

    @abstractmethod
    async def list_paginated(
        self,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: Optional[str] = None,
        sort_order: str = "asc",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        include_deleted: bool = False,
    ) -> Tuple[List[T], int]:
        """
        List entities with pagination and filtering (alternative signature).

        Args:
            page: Page number (1-based)
            per_page: Items per page
            filters: Optional filters to apply
            sort_by: Field to sort by
            sort_order: Sort order ("asc" or "desc")
            organization_id: Optional organization ID for multi-tenant filtering
            include_deleted: Whether to include soft-deleted entities

        Returns:
            Tuple of (items, total_count)
        """
        raise NotImplementedError
