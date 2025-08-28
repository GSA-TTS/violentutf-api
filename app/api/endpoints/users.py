"""User CRUD endpoints with comprehensive validation and security."""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from structlog.stdlib import get_logger

from app.api.base import BaseCRUDRouter
from app.api.deps import get_user_service
from app.core.config import settings
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.core.rate_limiting import rate_limit
from app.core.security import hash_password
from app.models.user import User

# Removed UserRepository import to comply with Clean Architecture
# Repository access moved to service layer
from app.schemas.base import AdvancedFilter, BaseResponse, OperationResult
from app.schemas.user import UserCreate, UserResponse, UserUpdate, UserUpdatePassword
from app.services.user_service_impl import UserServiceImpl

logger = get_logger(__name__)


# User filter schema
class UserFilter(AdvancedFilter):
    """Extended filtering for users."""

    username: Optional[str] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    is_verified: Optional[bool] = None


class UserCRUDRouter(BaseCRUDRouter[User, UserCreate, UserUpdate, UserResponse, UserFilter]):
    """Enhanced User CRUD router with user-specific operations."""

    def __init__(self) -> None:
        """Initialize user CRUD router."""
        super().__init__(
            model=User,
            create_schema=UserCreate,
            update_schema=UserUpdate,
            response_schema=UserResponse,
            filter_schema=UserFilter,
            prefix="/users",
            tags=["Users"],
            require_auth=True,
            require_admin=False,  # Users can view their own profile
            repository=None,  # Service layer handles data access
        )

    def _check_admin_permission(self, request: Request) -> None:
        """Check if user has admin permissions."""
        current_user = getattr(request.state, "user", None)
        if not current_user or not getattr(current_user, "is_superuser", False):
            raise ForbiddenError(message="Administrator privileges required")

    def _get_current_user_id(self, request: Request) -> str:
        """Get current user ID from request state."""
        current_user_id = getattr(request.state, "user_id", None)
        if not current_user_id:
            raise NotFoundError(message="Current user not found")
        return str(current_user_id)

    def _get_created_by(self, request: Request) -> str:
        """Get created_by value for audit trail."""
        current_user_id = getattr(request.state, "user_id", None)
        return str(current_user_id) if current_user_id else "system"

    def _build_user_response(self, user: User, message: str, request: Request) -> BaseResponse[UserResponse]:
        """Build user response object."""
        response_user = UserResponse.model_validate(user)
        return BaseResponse(
            data=response_user,
            message=message,
            trace_id=getattr(request.state, "trace_id", None),
        )

    def _build_operation_result(
        self, message: str, request: Request, affected_rows: int = 1
    ) -> BaseResponse[OperationResult]:
        """Build operation result response object."""
        result = OperationResult(
            success=True,
            message=message,
            affected_rows=affected_rows,
            operation_id=str(uuid.uuid4()),
        )
        return BaseResponse(
            data=result,
            message="Success",
            trace_id=getattr(request.state, "trace_id", None),
        )

    async def _validate_user_availability(self, user_service: UserServiceImpl, user_data: UserCreate) -> None:
        """Validate username and email availability."""
        if not await user_service.is_username_available(user_data.username):
            raise ConflictError(message=f"Username '{user_data.username}' is already taken")
        if not await user_service.is_email_available(user_data.email):
            raise ConflictError(message=f"Email '{user_data.email}' is already registered")

    def _prepare_update_data(self, user_data: UserUpdate, request: Request) -> Dict[str, Any]:
        """Prepare update data with admin field restrictions."""
        update_data = user_data.model_dump(exclude_unset=True)

        # Non-admin users cannot change these fields
        current_user = getattr(request.state, "user", None)
        if not current_user or not getattr(current_user, "is_superuser", False):
            update_data.pop("is_superuser", None)
            update_data.pop("is_active", None)

        return update_data

    async def _check_permissions(
        self,
        request: Request,
        operation: str,
        item_id: Optional[uuid.UUID] = None,
    ) -> None:
        """Override permission check to implement user ownership validation."""
        # First, call the parent permission check for basic auth
        await super()._check_permissions(request, operation, item_id)

        # For user endpoints, implement additional ownership checks
        if item_id and operation in ["read", "update", "delete"]:
            current_user = getattr(request.state, "user", None)
            current_user_id = getattr(request.state, "user_id", None)

            # Admins can access any user
            if current_user and getattr(current_user, "is_superuser", False):
                return

            # Regular users can only access their own data
            if current_user_id and str(item_id) != str(current_user_id):
                # Return 404 instead of 403 to not reveal that the user exists
                raise NotFoundError(message=f"User with ID {item_id} not found")

    def _register_endpoints(self) -> None:
        """Register CRUD endpoints, excluding create endpoint (custom implementation)."""
        # Register custom endpoints first to avoid routing conflicts
        self._add_custom_endpoints()

        import uuid

        from fastapi import Depends

        from app.schemas.base import PaginatedResponse

        # List endpoint (from base router)
        @self.router.get(
            "/",
            response_model=PaginatedResponse[UserResponse],
            summary=f"List {self.model.__name__}s",
            description=f"Retrieve a paginated list of {self.model.__name__} objects with optional filtering and sorting.",
        )
        async def list_items(
            request: Request,
            filters: UserFilter = Depends(UserFilter),
            user_service: UserServiceImpl = Depends(get_user_service),
        ) -> PaginatedResponse[UserResponse]:
            return await self._list_items(request, filters, user_service)

        # Get by ID endpoint (from base router)
        @self.router.get(
            "/{item_id}",
            response_model=BaseResponse[UserResponse],
            summary=f"Get {self.model.__name__}",
            description=f"Retrieve a specific {self.model.__name__} by ID.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def get_item(
            request: Request, item_id: uuid.UUID, user_service: UserServiceImpl = Depends(get_user_service)
        ) -> BaseResponse[UserResponse]:
            return await self._get_item(request, item_id, user_service)

        # Skip create endpoint - using custom implementation

        # Update endpoint (from base router)
        @self.router.put(
            "/{item_id}",
            response_model=BaseResponse[UserResponse],
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
            item_data: UserUpdate,
            user_service: UserServiceImpl = Depends(get_user_service),
        ) -> BaseResponse[UserResponse]:
            return await self._update_item(request, item_id, item_data, user_service)

        # Patch endpoint (from base router)
        @self.router.patch(
            "/{item_id}",
            response_model=BaseResponse[UserResponse],
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
            item_data: UserUpdate,
            user_service: UserServiceImpl = Depends(get_user_service),
        ) -> BaseResponse[UserResponse]:
            return await self._patch_item(request, item_id, item_data, user_service)

        # Delete endpoint (custom implementation with admin requirement)
        @self.router.delete(
            "/{item_id}",
            response_model=BaseResponse[OperationResult],
            summary=f"Delete {self.model.__name__}",
            description=f"Delete a specific {self.model.__name__} (admin only).",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
                403: {"description": "Administrator privileges required"},
            },
        )
        async def delete_item(
            request: Request, item_id: uuid.UUID, user_service: UserServiceImpl = Depends(get_user_service)
        ) -> BaseResponse[OperationResult]:
            # Check admin permission before proceeding
            self._check_admin_permission(request)
            return await self._delete_item(request, item_id, False, user_service)

    def _add_custom_endpoints(self) -> None:
        """Add user-specific endpoints."""
        self._register_create_endpoint()
        self._register_profile_endpoint()
        self._register_profile_update_endpoint()
        self._register_change_password_endpoint()
        self._register_username_lookup_endpoint()
        self._register_verify_endpoint()
        self._register_deactivate_endpoint()
        self._register_activate_endpoint()

    def _register_create_endpoint(self) -> None:
        """Register the create user endpoint."""

        @self.router.post(
            "/",
            response_model=BaseResponse[UserResponse],
            status_code=status.HTTP_201_CREATED,
            summary="Create User",
            description="Create a new user with password hashing and validation.",
            responses={
                409: {"description": "Username or email already exists"},
                422: {"description": "Validation error"},
            },
        )
        async def create_user_endpoint(
            request: Request,
            user_data: UserCreate,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[UserResponse]:
            """Create a new user with enhanced validation."""
            try:
                # Get current user for audit trail
                created_by = self._get_created_by(request)

                # Create user using service layer (handles validation and transactions)
                user = await user_service.create_user(user_data, created_by)

                return self._build_user_response(user, "User created successfully", request)

            except (ConflictError, ValidationError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise

    def _register_profile_endpoint(self) -> None:
        """Register the get current user profile endpoint."""

        @self.router.get(
            "/me",
            response_model=BaseResponse[UserResponse],
            summary="Get Current User",
            description="Get the current authenticated user's profile.",
        )
        async def get_current_user(
            request: Request, user_service: UserServiceImpl = Depends(get_user_service)  # noqa: B008
        ) -> BaseResponse[UserResponse]:
            """Get current user profile."""
            current_user_id = self._get_current_user_id(request)

            user_data = await user_service.get_user_by_id(current_user_id)

            if not user_data:
                raise NotFoundError(message="User not found")

            # Convert UserData to User model for response
            user = User(
                id=uuid.UUID(user_data.id),
                username=user_data.username,
                email=user_data.email,
                is_active=user_data.is_active,
                is_superuser=user_data.is_superuser,
                created_at=user_data.created_at,
                updated_at=user_data.updated_at,
            )

            return self._build_user_response(user, "Success", request)

    def _register_profile_update_endpoint(self) -> None:
        """Register the update current user profile endpoint."""

        @self.router.put(
            "/me",
            response_model=BaseResponse[UserResponse],
            summary="Update Current User",
            description="Update the current authenticated user's profile.",
        )
        async def update_current_user(
            request: Request,
            user_data: UserUpdate,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[UserResponse]:
            """Update current user profile."""
            current_user_id = self._get_current_user_id(request)

            try:
                # Prepare update data with admin field restrictions
                update_data_dict = self._prepare_update_data(user_data, request)

                # Convert dict back to UserUpdate schema for service layer
                filtered_user_data = UserUpdate.model_validate(update_data_dict)

                # Update user using service layer (handles validation and transactions)
                updated_user = await user_service.update_user_profile(
                    current_user_id, filtered_user_data, current_user_id
                )

                return self._build_user_response(updated_user, "Profile updated successfully", request)

            except (ConflictError, NotFoundError, ValidationError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise

    def _register_change_password_endpoint(self) -> None:
        """Register the change password endpoint."""

        @self.router.post(
            "/me/change-password",
            response_model=BaseResponse[OperationResult],
            summary="Change Password",
            description="Change the current user's password.",
        )
        async def change_password(
            request: Request,
            password_data: UserUpdatePassword,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Change current user's password."""
            current_user_id = self._get_current_user_id(request)

            try:
                # Change password using service layer (handles validation and transactions)
                await user_service.change_user_password(current_user_id, password_data, current_user_id)

                return self._build_operation_result("Password changed successfully", request)

            except (ValidationError, NotFoundError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise

    def _register_username_lookup_endpoint(self) -> None:
        """Register the get user by username endpoint."""

        @self.router.get(
            "/username/{username}",
            response_model=BaseResponse[UserResponse],
            summary="Get User by Username",
            description="Get a user by their username.",
            responses={
                404: {"description": "User not found"},
            },
        )
        async def get_user_by_username(
            request: Request, username: str, user_service: UserServiceImpl = Depends(get_user_service)  # noqa: B008
        ) -> BaseResponse[UserResponse]:
            """Get user by username."""
            user = await user_service.get_user_by_username(username)

            if not user:
                raise NotFoundError(message=f"User with username '{username}' not found")

            return self._build_user_response(user, "Success", request)

    def _register_verify_endpoint(self) -> None:
        """Register the verify user email endpoint."""

        @self.router.post(
            "/{user_id}/verify",
            response_model=BaseResponse[OperationResult],
            summary="Verify User Email",
            description="Verify a user's email address (admin only).",
        )
        async def verify_user_email(
            request: Request,
            user_id: uuid.UUID,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Verify user email (admin only)."""
            self._check_admin_permission(request)

            try:
                current_user_id = self._get_current_user_id(request)

                # Verify user email using service layer (handles validation and transactions)
                await user_service.verify_user_email(str(user_id), current_user_id)

                return self._build_operation_result("User email verified successfully", request)

            except (NotFoundError, ValidationError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise

    def _register_deactivate_endpoint(self) -> None:
        """Register the deactivate user endpoint."""

        @self.router.post(
            "/{user_id}/deactivate",
            response_model=BaseResponse[OperationResult],
            summary="Deactivate User",
            description="Deactivate a user account (admin only).",
        )
        async def deactivate_user(
            request: Request,
            user_id: uuid.UUID,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Deactivate user account (admin only)."""
            self._check_admin_permission(request)

            try:
                current_user_id = self._get_current_user_id(request)

                # Deactivate user using service layer (handles validation and transactions)
                await user_service.deactivate_user(str(user_id), current_user_id)

                return self._build_operation_result("User deactivated successfully", request)

            except (NotFoundError, ValidationError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise

    def _register_activate_endpoint(self) -> None:
        """Register the activate user endpoint."""

        @self.router.post(
            "/{user_id}/activate",
            response_model=BaseResponse[OperationResult],
            summary="Activate User",
            description="Activate a user account (admin only).",
        )
        async def activate_user(
            request: Request,
            user_id: uuid.UUID,
            user_service: UserServiceImpl = Depends(get_user_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Activate user account (admin only)."""
            self._check_admin_permission(request)

            try:
                current_user_id = self._get_current_user_id(request)

                # Activate user using service layer (handles validation and transactions)
                await user_service.activate_user(str(user_id), current_user_id)

                return self._build_operation_result("User activated successfully", request)

            except (NotFoundError, ValidationError):
                # Service layer handles rollback automatically
                raise
            except Exception:
                # Service layer handles rollback automatically
                raise


# Create router instance
user_crud_router = UserCRUDRouter()
router = user_crud_router.router
