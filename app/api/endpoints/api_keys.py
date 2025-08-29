"""API Key CRUD endpoints with comprehensive security and management."""

import hashlib
import secrets
import uuid
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Type, TypeVar, Union, cast

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.api.base import BaseCRUDRouter
from app.api.deps import get_api_key_service
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.api_key import APIKey

# Repository import removed - using service layer instead
from app.schemas.api_key import (
    APIKeyCreate,
    APIKeyCreateResponse,
    APIKeyFilter,
    APIKeyPermissionTemplate,
    APIKeyResponse,
    APIKeyUpdate,
    APIKeyUsageStats,
)
from app.schemas.base import AdvancedFilter, BaseResponse, OperationResult, PaginatedResponse
from app.services.api_key_service import APIKeyService

logger = get_logger(__name__)

T = TypeVar("T")


class APIKeyCRUDRouter(BaseCRUDRouter[APIKey, APIKeyCreate, APIKeyUpdate, APIKeyResponse, APIKeyFilter]):
    """Enhanced API Key CRUD router with key-specific operations."""

    def __init__(self) -> None:
        """Initialize API Key CRUD router."""
        super().__init__(
            model=APIKey,
            create_schema=APIKeyCreate,
            update_schema=APIKeyUpdate,
            response_schema=APIKeyResponse,
            filter_schema=APIKeyFilter,
            prefix="/api-keys",
            tags=["API Keys"],
            require_auth=True,
            require_admin=False,  # Users can manage their own API keys
            repository=None,  # Service layer handles data access
        )

        # Note: custom endpoints are now registered in _register_endpoints() to control routing order

    def _register_endpoints(self) -> None:
        """Override base endpoint registration to customize create endpoint."""
        # Register custom endpoints first to avoid routing conflicts
        self._add_custom_endpoints()

        # List endpoint
        @self.router.get(
            "/",
            response_model=PaginatedResponse[APIKeyResponse],
            summary=f"List {self.model.__name__}s",
            description=f"Retrieve a paginated list of {self.model.__name__} objects with optional filtering and sorting.",
        )
        async def list_items(
            request: Request,
            filters: APIKeyFilter = Depends(APIKeyFilter),  # noqa: B008
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> PaginatedResponse[APIKeyResponse]:
            return await self._list_items(request, filters, api_key_service)

        # Get by ID endpoint
        @self.router.get(
            "/{item_id}",
            response_model=BaseResponse[APIKeyResponse],
            summary=f"Get {self.model.__name__}",
            description=f"Retrieve a specific {self.model.__name__} by ID.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def get_item(
            request: Request,
            item_id: uuid.UUID,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[APIKeyResponse]:
            return await self._get_item(request, item_id, api_key_service)

        # Custom Create endpoint for API Keys
        @self.router.post(
            "/",
            response_model=BaseResponse[APIKeyCreateResponse],
            status_code=status.HTTP_201_CREATED,
            summary="Create API Key",
            description="Create a new API key with specified permissions.",
            responses={
                409: {"description": "API key name already exists for user"},
                422: {"description": "Validation error"},
            },
        )
        async def create_item(
            request: Request,
            item_data: APIKeyCreate,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[APIKeyCreateResponse]:
            return await self._create_item(request, item_data, api_key_service)

        # Update endpoint
        @self.router.put(
            "/{item_id}",
            response_model=BaseResponse[APIKeyResponse],
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
            item_data: APIKeyUpdate,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[APIKeyResponse]:
            return await self._update_item(request, item_id, item_data, api_key_service)

        # Patch endpoint
        @self.router.patch(
            "/{item_id}",
            response_model=BaseResponse[APIKeyResponse],
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
            item_data: APIKeyUpdate,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[APIKeyResponse]:
            return await self._patch_item(request, item_id, item_data, api_key_service)

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
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            return await self._delete_item(request, item_id, permanent, api_key_service)

    async def _create_item(
        self,
        request: Request,
        item_data: APIKeyCreate,
        session: AsyncSession,
    ) -> BaseResponse[Any]:  # Using Any to allow APIKeyCreateResponse override
        """Override base create to implement custom API key creation logic."""
        try:
            # Get current user
            current_user_id = self._get_current_user_id(request)

            # Create service with session
            api_key_service = APIKeyService(session)

            # Use service layer for transaction management
            api_key, full_key = await api_key_service.create_api_key(current_user_id, item_data)

            # Create response with full key (only time it's shown)
            response_key = APIKeyCreateResponse(
                id=api_key.id,
                name=api_key.name,
                description=api_key.description,
                key=full_key,  # Full key only shown once
                key_prefix=api_key.key_prefix,
                permissions=api_key.permissions,
                expires_at=api_key.expires_at,
                user_id=api_key.user_id,
                created_at=api_key.created_at,
                updated_at=api_key.updated_at,
                created_by=api_key.created_by,
                updated_by=api_key.updated_by,
                version=api_key.version,
            )

            return self._build_base_response(response_key, "API key created successfully", request)

        except Exception as e:
            if not isinstance(e, (ConflictError, ValidationError)):
                logger.error(
                    "api_key_creation_error",
                    error=str(e),
                    name=item_data.name,
                    user_id=self._get_current_user_id(request),
                    exc_info=True,
                )
            raise

    def _generate_api_key(self) -> tuple[str, str, str]:
        """
        Generate a new API key with prefix and hash.

        Returns:
            Tuple of (full_key, key_prefix, key_hash)
        """
        # Create key in format: vutf_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        key_base = secrets.token_urlsafe(32)
        full_key = f"vutf_{key_base}"

        # Create prefix (first 8 characters after prefix)
        key_prefix = full_key[:12]  # "vutf_" + 7 chars

        # Create SHA256 hash of the full key
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()

        return full_key, key_prefix, key_hash

    def _get_current_user_id(self, request: Request) -> str:
        """Get current user ID from request state."""
        current_user_id = getattr(request.state, "user_id", None)
        if not current_user_id:
            raise ValidationError(message="User authentication required")
        return str(current_user_id)

    def _check_admin_permission(self, request: Request) -> None:
        """Check if user has admin permissions."""
        current_user = getattr(request.state, "user", None)
        if not current_user or not getattr(current_user, "is_superuser", False):
            raise ForbiddenError(message="Administrator privileges required")

    def _check_key_ownership(self, api_key: APIKey, current_user_id: str, request: Request) -> None:
        """Check if user owns the API key or is admin."""
        current_user = getattr(request.state, "user", None)
        is_admin = current_user and getattr(current_user, "is_superuser", False)

        if not is_admin and api_key.user_id != current_user_id:
            raise ForbiddenError(message="You can only access your own API keys")

    def _build_api_key_response(self, api_key: APIKey) -> APIKeyResponse:
        """Build API key response object."""
        return APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            description=api_key.description,
            key_prefix=api_key.key_prefix,
            masked_key=api_key.mask_key(),
            permissions=api_key.permissions,
            last_used_at=api_key.last_used_at,
            last_used_ip=api_key.last_used_ip,
            usage_count=api_key.usage_count,
            expires_at=api_key.expires_at,
            is_active=api_key.is_active(),
            revoked_at=api_key.revoked_at,
            user_id=api_key.user_id,
            created_at=api_key.created_at,
            updated_at=api_key.updated_at,
            created_by=api_key.created_by,
            updated_by=api_key.updated_by,
            version=api_key.version,
        )

    def _build_base_response(self, data: T, message: str, request: Request) -> BaseResponse[T]:
        """Build base response object."""
        return BaseResponse(data=data, message=message, trace_id=getattr(request.state, "trace_id", None))

    def _build_operation_result(
        self, success: bool, message: str, request: Request, affected_rows: int = 1
    ) -> BaseResponse[OperationResult]:
        """Build operation result response object."""
        result = OperationResult(
            success=success,
            message=message,
            affected_rows=affected_rows,
            operation_id=str(uuid.uuid4()),
        )
        return BaseResponse(
            data=result,
            message="Success",
            trace_id=getattr(request.state, "trace_id", None),
        )

    async def _validate_key_name_availability(
        self, api_key_service: APIKeyService, key_name: str, user_id: str
    ) -> None:
        """Validate that API key name is available for the user."""
        existing_keys = await api_key_service.list_user_keys(user_id)
        if any(key.name == key_name for key in existing_keys):
            raise ConflictError(message=f"API key with name '{key_name}' already exists")

    def _add_custom_endpoints(self) -> None:
        """Add API key-specific endpoints."""
        self._register_my_keys_endpoint()
        self._register_revoke_endpoint()
        self._register_rotate_endpoint()
        self._register_validate_endpoint()
        self._register_analytics_endpoint()
        self._register_permission_templates_endpoint()
        self._register_usage_stats_endpoint()
        self._register_record_usage_endpoint()

    def _register_my_keys_endpoint(self) -> None:
        """Register the get my API keys endpoint."""

        @self.router.get(
            "/my-keys",
            response_model=BaseResponse[List[APIKeyResponse]],
            summary="Get My API Keys",
            description="Get all API keys for the current user.",
        )
        async def get_my_api_keys(
            request: Request,
            include_revoked: bool = Query(False, description="Include revoked keys"),  # noqa: B008
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[List[APIKeyResponse]]:
            """Get current user's API keys."""
            current_user_id = self._get_current_user_id(request)

            # Use service layer to get user keys
            api_keys = await api_key_service.get_user_keys(current_user_id, include_revoked=include_revoked)

            # Convert to response schemas
            response_keys = [self._build_api_key_response(key) for key in api_keys]

            return self._build_base_response(response_keys, "Success", request)

    def _register_revoke_endpoint(self) -> None:
        """Register the revoke API key endpoint."""

        @self.router.post(
            "/{key_id}/revoke",
            response_model=BaseResponse[OperationResult],
            summary="Revoke API Key",
            description="Revoke an API key, making it permanently unusable.",
        )
        async def revoke_api_key(
            request: Request,
            key_id: uuid.UUID,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Revoke an API key."""
            try:
                # Get current user
                current_user_id = self._get_current_user_id(request)

                # Use service layer for revocation (includes transaction management)
                success = await api_key_service.revoke_api_key(str(key_id), current_user_id)

                if success:
                    logger.info(
                        "api_key_revoked",
                        api_key_id=str(key_id),
                        user_id=current_user_id,
                    )
                    return self._build_operation_result(True, "API key revoked successfully", request)
                else:
                    raise NotFoundError(message=f"API key with ID {key_id} not found or already revoked")

            except (NotFoundError, ValidationError, ForbiddenError):
                # Re-raise known exceptions
                raise
            except Exception as e:
                logger.error(
                    "api_key_revocation_error",
                    api_key_id=str(key_id),
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_rotate_endpoint(self) -> None:
        """Register the rotate API key endpoint."""

        @self.router.post(
            "/{key_id}/rotate",
            response_model=BaseResponse[APIKeyCreateResponse],
            summary="Rotate API Key",
            description="Generate a new key value for an existing API key.",
        )
        async def rotate_api_key(
            request: Request,
            key_id: uuid.UUID,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[APIKeyCreateResponse]:
            """Rotate an API key to generate a new key value."""
            try:
                current_user_id = self._get_current_user_id(request)

                # Use service layer (includes transaction management)
                api_key, new_full_key = await api_key_service.rotate_api_key(str(key_id), current_user_id)

                # Create response with new full key (only time it's shown)
                response_key = APIKeyCreateResponse(
                    id=api_key.id,
                    name=api_key.name,
                    description=api_key.description,
                    key=new_full_key,  # New full key only shown once
                    key_prefix=api_key.key_prefix,
                    permissions=api_key.permissions,
                    expires_at=api_key.expires_at,
                    user_id=api_key.user_id,
                    created_at=api_key.created_at,
                    updated_at=api_key.updated_at,
                    created_by=api_key.created_by,
                    updated_by=api_key.updated_by,
                    version=api_key.version,
                )

                return self._build_base_response(response_key, "API key rotated successfully", request)

            except (NotFoundError, ValidationError, ForbiddenError):
                # Re-raise known exceptions
                raise
            except Exception as e:
                logger.error(
                    "api_key_rotation_error",
                    api_key_id=str(key_id),
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_validate_endpoint(self) -> None:
        """Register the validate API key endpoint."""

        @self.router.post(
            "/{key_id}/validate",
            response_model=BaseResponse[OperationResult],
            summary="Validate API Key",
            description="Validate an API key and return its status.",
        )
        async def validate_api_key(
            request: Request,
            key_id: uuid.UUID,
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Validate an API key."""
            try:
                # Get the API key through service layer
                api_key = await api_key_service.get_api_key(key_id)
                if not api_key:
                    raise NotFoundError(message=f"API key with ID {key_id} not found")

                # Check if key is valid
                is_valid = api_key.is_active()
                message = f"API key is {'valid' if is_valid else 'invalid'}"

                return self._build_operation_result(is_valid, message, request, affected_rows=0)
            except NotFoundError:
                raise
            except Exception as e:
                logger.error("api_key_validation_error", key_id=str(key_id), error=str(e))
                raise

    def _register_analytics_endpoint(self) -> None:
        """Register the analytics endpoint."""

        @self.router.get(
            "/my-analytics",
            response_model=BaseResponse[Dict[str, Any]],
            summary="Get My API Key Analytics",
            description="Get analytics and usage statistics for current user's API keys.",
        )
        async def get_my_analytics(
            request: Request, api_key_service: APIKeyService = Depends(get_api_key_service)  # noqa: B008
        ) -> BaseResponse[Dict[str, Any]]:
            """Get analytics for current user's API keys."""
            try:
                current_user_id = self._get_current_user_id(request)

                # Use service layer for analytics
                analytics = await api_key_service.get_key_analytics(current_user_id)

                return self._build_base_response(analytics, "Analytics retrieved successfully", request)

            except Exception as e:
                logger.error(
                    "api_key_analytics_error",
                    user_id=self._get_current_user_id(request),
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_permission_templates_endpoint(self) -> None:
        """Register the permission templates endpoint."""

        @self.router.get(
            "/permission-templates",
            response_model=BaseResponse[Dict[str, APIKeyPermissionTemplate]],
            summary="Get Permission Templates",
            description="Get predefined permission templates for API keys.",
        )
        async def get_permission_templates(
            request: Request,
        ) -> BaseResponse[Dict[str, APIKeyPermissionTemplate]]:
            """Get predefined permission templates."""
            templates = APIKeyPermissionTemplate.get_templates()
            return self._build_base_response(templates, "Success", request)

    def _register_usage_stats_endpoint(self) -> None:
        """Register the usage statistics endpoint."""

        @self.router.get(
            "/usage-stats",
            response_model=BaseResponse[APIKeyUsageStats],
            summary="Get API Key Usage Statistics",
            description="Get usage statistics for API keys (admin only).",
        )
        async def get_usage_stats(
            request: Request, api_key_service: APIKeyService = Depends(get_api_key_service)  # noqa: B008
        ) -> BaseResponse[APIKeyUsageStats]:
            """Get API key usage statistics (admin only)."""
            # Check admin permissions
            self._check_admin_permission(request)

            try:
                # Get statistics using repository method through service
                stats = await api_key_service.repository.get_statistics()

                # Convert to response schema
                usage_stats = APIKeyUsageStats(
                    total_keys=stats.get("total_keys", 0),
                    active_keys=stats.get("active_keys", 0),
                    expired_keys=stats.get("expired_keys", 0),
                    revoked_keys=stats.get("revoked_keys", 0),
                    keys_used_today=stats.get("keys_used_today", 0),
                    total_requests=stats.get("total_requests", 0),
                )

                return self._build_base_response(usage_stats, "Success", request)

            except Exception as e:
                logger.error(
                    "api_key_stats_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_record_usage_endpoint(self) -> None:
        """Register the record usage endpoint."""

        @self.router.post(
            "/{key_id}/record-usage",
            response_model=BaseResponse[OperationResult],
            summary="Record API Key Usage",
            description="Record usage of an API key (internal endpoint).",
            include_in_schema=False,  # Hide from public docs
        )
        async def record_api_key_usage(
            request: Request,
            key_id: uuid.UUID,
            ip_address: Optional[str] = Query(None, description="IP address of the request"),  # noqa: B008
            api_key_service: APIKeyService = Depends(get_api_key_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Record API key usage (internal endpoint)."""
            try:
                # Get the API key through service
                api_key = await api_key_service.repository.get(key_id)
                if not api_key:
                    raise NotFoundError(message=f"API key with ID {key_id} not found")

                # Record usage through service (includes transaction management)
                await api_key_service.record_key_usage(api_key, ip_address)

                return self._build_operation_result(True, "API key usage recorded", request)

            except NotFoundError:
                raise
            except Exception as e:
                logger.error(
                    "api_key_usage_recording_error",
                    api_key_id=str(key_id),
                    error=str(e),
                    exc_info=True,
                )
                raise


# Create router instance
api_key_crud_router = APIKeyCRUDRouter()
router = api_key_crud_router.router
