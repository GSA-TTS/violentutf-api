"""Base CRUD router with standardized patterns and comprehensive validation."""

import uuid
from typing import Any, Dict, Generic, List, Optional, Sequence, Type, TypeVar, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.db.base_class import Base
from app.db.session import get_db
from app.models.mixins import BaseModelMixin
from app.repositories.base import BaseRepository
from app.schemas.base import (
    AdvancedFilter,
    BaseFilter,
    BaseResponse,
    OperationResult,
    PaginatedResponse,
    PaginationInfo,
)

logger = get_logger(__name__)

# Type variables
ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)
ResponseSchemaType = TypeVar("ResponseSchemaType", bound=BaseModel)
FilterSchemaType = TypeVar("FilterSchemaType", bound=BaseFilter)


class BaseCRUDRouter(Generic[ModelType, CreateSchemaType, UpdateSchemaType, ResponseSchemaType, FilterSchemaType]):
    """
    Base CRUD router providing standardized endpoints for database models.

    This class provides a consistent pattern for CRUD operations with:
    - Comprehensive input validation
    - Standardized error responses
    - Pagination and filtering
    - Audit logging
    - Permission checking
    - Optimistic locking
    """

    def __init__(
        self,
        model: Type[ModelType],
        repository: Type[BaseRepository[ModelType]],
        create_schema: Type[CreateSchemaType],
        update_schema: Type[UpdateSchemaType],
        response_schema: Type[ResponseSchemaType],
        filter_schema: Type[FilterSchemaType] = BaseFilter,  # type: ignore[assignment]
        prefix: str = "",
        tags: Optional[Sequence[str]] = None,
        dependencies: Optional[List[Any]] = None,
        require_auth: bool = True,
        require_admin: bool = False,
    ):
        """
        Initialize CRUD router.

        Args:
            model: SQLAlchemy model class
            repository: Repository class for database operations
            create_schema: Pydantic schema for create operations
            update_schema: Pydantic schema for update operations
            response_schema: Pydantic schema for responses
            filter_schema: Pydantic schema for filtering
            prefix: URL prefix for endpoints
            tags: OpenAPI tags
            dependencies: Additional dependencies
            require_auth: Whether authentication is required
            require_admin: Whether admin privileges are required
        """
        self.model = model
        self.repository = repository
        self.create_schema = create_schema
        self.update_schema = update_schema
        self.response_schema = response_schema
        self.filter_schema = filter_schema
        self.require_auth = require_auth
        self.require_admin = require_admin

        # Create router
        self.router = APIRouter(
            prefix=prefix,
            tags=list(tags) if tags else [model.__name__.lower()],
            dependencies=dependencies or [],
        )

        # Register endpoints
        self._register_endpoints()

    def _register_endpoints(self) -> None:
        """Register all CRUD endpoints."""

        # List endpoint
        @self.router.get(
            "/",
            response_model=PaginatedResponse[ResponseSchemaType],
            summary=f"List {self.model.__name__}s",
            description=f"Retrieve a paginated list of {self.model.__name__} objects with optional filtering and sorting.",
        )
        async def list_items(
            request: Request,
            filters: FilterSchemaType = Depends(self.filter_schema),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> PaginatedResponse[ResponseSchemaType]:
            return await self._list_items(request, filters, session)

        # Get by ID endpoint
        @self.router.get(
            "/{item_id}",
            response_model=BaseResponse[ResponseSchemaType],
            summary=f"Get {self.model.__name__}",
            description=f"Retrieve a specific {self.model.__name__} by ID.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def get_item(
            request: Request, item_id: uuid.UUID, session: AsyncSession = Depends(get_db)  # noqa: B008
        ) -> BaseResponse[ResponseSchemaType]:
            return await self._get_item(request, item_id, session)

        # Create endpoint
        @self.router.post(
            "/",
            response_model=BaseResponse[ResponseSchemaType],
            status_code=status.HTTP_201_CREATED,
            summary=f"Create {self.model.__name__}",
            description=f"Create a new {self.model.__name__}.",
            responses={
                409: {"description": "Resource already exists"},
                422: {"description": "Validation error"},
            },
        )
        async def create_item(
            request: Request, item_data: CreateSchemaType, session: AsyncSession = Depends(get_db)  # noqa: B008
        ) -> BaseResponse[ResponseSchemaType]:
            return await self._create_item(request, item_data, session)

        # Update endpoint
        @self.router.put(
            "/{item_id}",
            response_model=BaseResponse[ResponseSchemaType],
            summary=f"Update {self.model.__name__}",
            description=f"Update an existing {self.model.__name__}.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
                409: {"description": "Version conflict (optimistic locking)"},
                422: {"description": "Validation error"},
            },
        )
        async def update_item(
            request: Request,
            item_id: uuid.UUID,
            item_data: UpdateSchemaType,
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[ResponseSchemaType]:
            return await self._update_item(request, item_id, item_data, session)

        # Patch endpoint
        @self.router.patch(
            "/{item_id}",
            response_model=BaseResponse[ResponseSchemaType],
            summary=f"Partially update {self.model.__name__}",
            description=f"Partially update an existing {self.model.__name__}.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
                409: {"description": "Version conflict (optimistic locking)"},
                422: {"description": "Validation error"},
            },
        )
        async def patch_item(
            request: Request,
            item_id: uuid.UUID,
            item_data: UpdateSchemaType,
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[ResponseSchemaType]:
            return await self._patch_item(request, item_id, item_data, session)

        # Delete endpoint
        @self.router.delete(
            "/{item_id}",
            response_model=BaseResponse[OperationResult],
            summary=f"Delete {self.model.__name__}",
            description=f"Soft delete a {self.model.__name__}.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def delete_item(
            request: Request,
            item_id: uuid.UUID,
            permanent: bool = Query(False, description="Whether to permanently delete the item"),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            return await self._delete_item(request, item_id, permanent, session)

    async def _list_items(
        self,
        request: Request,
        filters: FilterSchemaType,
        session: AsyncSession,
    ) -> PaginatedResponse[ResponseSchemaType]:
        """List items with pagination and filtering."""
        try:
            # Check permissions
            await self._check_permissions(request, "read")

            # Create repository instance
            repo = self.repository(session)

            # Apply filters and get paginated results
            items, total_count = await repo.list_paginated(
                page=filters.page,
                per_page=filters.per_page,
                filters=self._build_filters(filters),
                sort_by=filters.sort_by,
                sort_order=filters.sort_order,
                include_deleted=filters.include_deleted,
            )

            # Convert to response schemas
            response_items = [self.response_schema.model_validate(item) for item in items]

            # Calculate pagination info
            total_pages = (total_count + filters.per_page - 1) // filters.per_page

            pagination = PaginationInfo(
                page=filters.page,
                per_page=filters.per_page,
                total_pages=total_pages,
                has_next=filters.page < total_pages,
                has_prev=filters.page > 1,
                next_cursor=None,
                prev_cursor=None,
            )

            logger.info(
                "items_listed",
                model=self.model.__name__,
                count=len(response_items),
                total=total_count,
                page=filters.page,
                user_id=getattr(request.state, "user_id", None),
            )

            return PaginatedResponse(
                data=response_items,
                pagination=pagination,
                total_count=total_count,
                filters=self._get_applied_filters(filters),
                message="Success",
                trace_id=getattr(request.state, "trace_id", None),
            )

        except Exception as e:
            logger.error(
                "list_items_error",
                model=self.model.__name__,
                error=str(e),
                user_id=getattr(request.state, "user_id", None),
                exc_info=True,
            )
            raise

    async def _get_item(
        self,
        request: Request,
        item_id: uuid.UUID,
        session: AsyncSession,
    ) -> BaseResponse[ResponseSchemaType]:
        """Get a single item by ID."""
        try:
            # Check permissions
            await self._check_permissions(request, "read", item_id)

            # Create repository instance
            repo = self.repository(session)

            # Get item
            item = await repo.get(item_id)
            if not item:
                raise NotFoundError(message=f"{self.model.__name__} with ID {item_id} not found")

            # Convert to response schema
            response_item = self.response_schema.model_validate(item)

            logger.info(
                "item_retrieved",
                model=self.model.__name__,
                item_id=str(item_id),
                user_id=getattr(request.state, "user_id", None),
            )

            return BaseResponse(
                data=response_item, message="Success", trace_id=getattr(request.state, "trace_id", None)
            )

        except Exception as e:
            if not isinstance(e, (NotFoundError, ForbiddenError)):
                logger.error(
                    "get_item_error",
                    model=self.model.__name__,
                    item_id=str(item_id),
                    error=str(e),
                    user_id=getattr(request.state, "user_id", None),
                    exc_info=True,
                )
            raise

    async def _create_item(
        self,
        request: Request,
        item_data: CreateSchemaType,
        session: AsyncSession,
    ) -> BaseResponse[ResponseSchemaType]:
        """Create a new item."""
        try:
            # Check permissions
            await self._check_permissions(request, "create")

            # Create repository instance
            repo = self.repository(session)

            # Prepare data for creation
            create_data = item_data.model_dump(exclude_unset=True)

            # Add audit fields
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                create_data["created_by"] = str(user_id)
                create_data["updated_by"] = str(user_id)

            # Create item
            item = await repo.create(create_data)

            # Convert to response schema
            response_item = self.response_schema.model_validate(item)

            logger.info(
                "item_created",
                model=self.model.__name__,
                item_id=str(item.id),
                user_id=user_id,
            )

            return BaseResponse(
                data=response_item,
                message=f"{self.model.__name__} created successfully",
                trace_id=getattr(request.state, "trace_id", None),
            )

        except Exception as e:
            if not isinstance(e, (ValidationError, ConflictError, ForbiddenError)):
                logger.error(
                    "create_item_error",
                    model=self.model.__name__,
                    error=str(e),
                    user_id=getattr(request.state, "user_id", None),
                    exc_info=True,
                )
            raise

    async def _update_item(
        self,
        request: Request,
        item_id: uuid.UUID,
        item_data: UpdateSchemaType,
        session: AsyncSession,
    ) -> BaseResponse[ResponseSchemaType]:
        """Update an existing item (full update)."""
        return await self._update_item_internal(request, item_id, item_data, session, partial=False)

    async def _patch_item(
        self,
        request: Request,
        item_id: uuid.UUID,
        item_data: UpdateSchemaType,
        session: AsyncSession,
    ) -> BaseResponse[ResponseSchemaType]:
        """Update an existing item partially."""
        return await self._update_item_internal(request, item_id, item_data, session, partial=True)

    async def _update_item_internal(
        self,
        request: Request,
        item_id: uuid.UUID,
        item_data: UpdateSchemaType,
        session: AsyncSession,
        partial: bool = False,
    ) -> BaseResponse[ResponseSchemaType]:
        """Handle internal update operations."""
        try:
            # Check permissions
            await self._check_permissions(request, "update", item_id)

            # Create repository instance
            repo = self.repository(session)

            # Get existing item
            existing_item = await repo.get(item_id)
            if not existing_item:
                raise NotFoundError(message=f"{self.model.__name__} with ID {item_id} not found")

            # Prepare update data
            if partial:
                update_data = item_data.model_dump(exclude_unset=True)
            else:
                # For PUT, also exclude unset to avoid overwriting with None
                update_data = item_data.model_dump(exclude_unset=True)

            # Add audit fields
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                update_data["updated_by"] = str(user_id)

            # Update item
            item = await repo.update(item_id, **update_data)

            # Convert to response schema
            response_item = self.response_schema.model_validate(item)

            logger.info(
                "item_updated",
                model=self.model.__name__,
                item_id=str(item_id),
                partial=partial,
                user_id=user_id,
            )

            return BaseResponse(
                data=response_item,
                message=f"{self.model.__name__} updated successfully",
                trace_id=getattr(request.state, "trace_id", None),
            )

        except Exception as e:
            if not isinstance(e, (NotFoundError, ValidationError, ConflictError, ForbiddenError)):
                logger.error(
                    "update_item_error",
                    model=self.model.__name__,
                    item_id=str(item_id),
                    partial=partial,
                    error=str(e),
                    user_id=getattr(request.state, "user_id", None),
                    exc_info=True,
                )
            raise

    async def _delete_item(
        self,
        request: Request,
        item_id: uuid.UUID,
        permanent: bool,
        session: AsyncSession,
    ) -> BaseResponse[OperationResult]:
        """Delete an item (soft or hard delete)."""
        try:
            # Check permissions
            await self._check_permissions(request, "delete", item_id)

            # Create repository instance
            repo = self.repository(session)

            # Check if item exists
            existing_item = await repo.get(item_id)
            if not existing_item:
                raise NotFoundError(message=f"{self.model.__name__} with ID {item_id} not found")

            # Delete item
            if permanent:
                success = await repo.delete_permanent(item_id)
                operation_type = "permanently deleted"
            else:
                success = await repo.delete(item_id)
                operation_type = "soft deleted"

            logger.info(
                "item_deleted",
                model=self.model.__name__,
                item_id=str(item_id),
                permanent=permanent,
                user_id=getattr(request.state, "user_id", None),
            )

            result = OperationResult(
                success=success,
                message=f"{self.model.__name__} {operation_type} successfully",
                affected_rows=1 if success else 0,
                operation_id=str(uuid.uuid4()),
            )

            return BaseResponse(data=result, message="Success", trace_id=getattr(request.state, "trace_id", None))

        except Exception as e:
            if not isinstance(e, (NotFoundError, ForbiddenError)):
                logger.error(
                    "delete_item_error",
                    model=self.model.__name__,
                    item_id=str(item_id),
                    permanent=permanent,
                    error=str(e),
                    user_id=getattr(request.state, "user_id", None),
                    exc_info=True,
                )
            raise

    async def _check_permissions(
        self,
        request: Request,
        operation: str,
        item_id: Optional[uuid.UUID] = None,
    ) -> None:
        """Check if user has permission to perform operation."""
        if not self.require_auth:
            return

        # Get user from request state (set by auth middleware)
        user = getattr(request.state, "user", None)
        logger.debug(
            "check_permissions",
            has_user=user is not None,
            user_id=getattr(request.state, "user_id", None),
            request_state_attrs=list(vars(request.state).keys()) if hasattr(request, "state") else None,
        )
        if not user:
            raise ForbiddenError(message="Authentication required")

        # Check admin requirement
        if self.require_admin and not getattr(user, "is_superuser", False):
            raise ForbiddenError(message="Administrator privileges required")

        # Additional permission checks can be implemented here
        # This is where you'd check specific permissions based on:
        # - User roles
        # - Resource ownership
        # - Organization membership
        # - etc.

    def _build_filters(self, filters: FilterSchemaType) -> Dict[str, Any]:
        """Build filter dictionary from filter schema."""
        filter_dict: Dict[str, Any] = {}

        # Date range filters
        if hasattr(filters, "created_after") and filters.created_after:
            filter_dict["created_after"] = filters.created_after
        if hasattr(filters, "created_before") and filters.created_before:
            filter_dict["created_before"] = filters.created_before
        if hasattr(filters, "updated_after") and filters.updated_after:
            filter_dict["updated_after"] = filters.updated_after
        if hasattr(filters, "updated_before") and filters.updated_before:
            filter_dict["updated_before"] = filters.updated_before

        # Search filter
        if hasattr(filters, "search") and filters.search:
            filter_dict["search"] = filters.search

        # Advanced filters (if supported)
        if hasattr(filters, "filters") and filters.filters:
            filter_dict["advanced_filters"] = filters.filters
            filter_dict["filter_logic"] = getattr(filters, "filter_logic", "and")

        return filter_dict

    def _get_applied_filters(self, filters: FilterSchemaType) -> Dict[str, Any]:
        """Get dictionary of applied filters for response."""
        applied: Dict[str, Any] = {}

        if hasattr(filters, "search") and filters.search:
            applied["search"] = filters.search
        if hasattr(filters, "sort_by") and filters.sort_by:
            applied["sort_by"] = filters.sort_by
            applied["sort_order"] = getattr(filters, "sort_order", "asc")
        if hasattr(filters, "include_deleted") and filters.include_deleted:
            applied["include_deleted"] = str(filters.include_deleted)

        return applied if applied else {}
