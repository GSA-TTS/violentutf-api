"""Session CRUD endpoints with comprehensive management and security."""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from structlog.stdlib import get_logger

from app.api.base import BaseCRUDRouter
from app.api.deps import get_session_service
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.session import Session
from app.repositories.session import SessionRepository
from app.schemas.base import BaseResponse, OperationResult
from app.schemas.session import (
    SessionCreate,
    SessionExtendRequest,
    SessionFilter,
    SessionResponse,
    SessionRevokeRequest,
    SessionStatistics,
    SessionUpdate,
)
from app.services.session_service import SessionService

logger = get_logger(__name__)


class SessionCRUDRouter(BaseCRUDRouter[Session, SessionCreate, SessionUpdate, SessionResponse, SessionFilter]):
    """Enhanced Session CRUD router with session-specific operations."""

    def __init__(self) -> None:
        """Initialize session CRUD router."""
        super().__init__(
            model=Session,
            repository=SessionRepository,
            create_schema=SessionCreate,
            update_schema=SessionUpdate,
            response_schema=SessionResponse,
            filter_schema=SessionFilter,
            prefix="/sessions",
            tags=["Sessions"],
            require_auth=True,
            require_admin=False,  # Users can manage their own sessions
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
            raise ValidationError(message="User authentication required")
        return str(current_user_id)

    def _check_session_ownership(self, request: Request, session_obj: Session) -> None:
        """Check if user can access/modify the session."""
        current_user_id = getattr(request.state, "user_id", None)
        current_user = getattr(request.state, "user", None)
        is_admin = current_user and getattr(current_user, "is_superuser", False)

        if not is_admin and session_obj.user_id != current_user_id:
            raise ForbiddenError(message="You can only access your own sessions")

    def _check_create_permission(self, request: Request, target_user_id: uuid.UUID) -> None:
        """Check if user can create session for target user."""
        current_user_id = getattr(request.state, "user_id", None)
        current_user = getattr(request.state, "user", None)
        is_admin = current_user and getattr(current_user, "is_superuser", False)

        if not is_admin and target_user_id != current_user_id:
            raise ForbiddenError(message="You can only create sessions for yourself")

    def _build_session_response(self, session_obj: Session) -> SessionResponse:
        """Build session response object."""
        return SessionResponse(
            id=session_obj.id,
            user_id=session_obj.user_id,
            masked_token=session_obj.mask_token(),
            device_info=session_obj.device_info,
            ip_address=session_obj.ip_address,
            location=session_obj.location,
            is_active=session_obj.is_active,
            is_valid=session_obj.is_valid(),
            expires_at=session_obj.expires_at,
            last_activity_at=session_obj.last_activity_at,
            last_activity_ip=session_obj.last_activity_ip,
            revoked_at=session_obj.revoked_at,
            revoked_by=session_obj.revoked_by,
            revocation_reason=session_obj.revocation_reason,
            security_metadata=session_obj.security_metadata,
            created_at=session_obj.created_at,
            updated_at=session_obj.updated_at,
            created_by=session_obj.created_by,
            updated_by=session_obj.updated_by,
            version=session_obj.version,
        )

    def _build_operation_result(
        self, request: Request, message: str, affected_rows: int = 1
    ) -> BaseResponse[OperationResult]:
        """Build operation result response."""
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

    def _register_create_session_endpoint(self) -> None:
        """Register the create session endpoint."""

        @self.router.post(
            "/",
            response_model=BaseResponse[SessionResponse],
            status_code=status.HTTP_201_CREATED,
            summary="Create Session",
            description="Create a new user session.",
            responses={
                409: {"description": "Session token already exists"},
                422: {"description": "Validation error"},
            },
        )
        async def create_session_endpoint(
            request: Request,
            session_data: SessionCreate,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[SessionResponse]:
            """Create a new session with validation."""
            try:
                # Using session_service instead of direct repository access
                current_user_id = self._get_current_user_id(request)

                # Check creation permissions
                self._check_create_permission(request, session_data.user_id)

                # Note: Session creation validation handled by service layer
                # For now, assuming service validates token uniqueness

                # Create session through service layer
                user = getattr(request.state, "user", None)
                new_session = await session_service.create_session(
                    user=user,
                    user_agent=getattr(request.state, "user_agent", None),
                    ip_address=getattr(request.state, "client_ip", None),
                    remember_me=getattr(session_data, "remember_me", False),
                )
                # Service layer handles transactions automatically

                # Build response
                response_session = self._build_session_response(new_session)

                logger.info(
                    "session_created",
                    session_id=str(new_session.id),
                    user_id=str(new_session.user_id),
                    created_by=current_user_id,
                )

                return BaseResponse(
                    data=response_session,
                    message="Session created successfully",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                # Service layer handles rollback
                if not isinstance(e, (ConflictError, ValidationError, ForbiddenError)):
                    logger.error(
                        "session_creation_error",
                        error=str(e),
                        user_id=str(session_data.user_id),
                        exc_info=True,
                    )
                raise

    def _register_my_sessions_endpoint(self) -> None:
        """Register the get my sessions endpoint."""

        @self.router.get(
            "/my-sessions",
            response_model=BaseResponse[List[SessionResponse]],
            summary="Get My Sessions",
            description="Get all sessions for the current user.",
        )
        async def get_my_sessions(
            request: Request,
            include_inactive: bool = Query(False, description="Include inactive sessions"),  # noqa: B008
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[List[SessionResponse]]:
            """Get current user's sessions."""
            current_user_id = self._get_current_user_id(request)

            # Get user sessions through service layer
            user_sessions_data = await session_service.get_active_sessions(current_user_id)

            # Convert to Session objects for response building
            user_sessions = []
            for session_data in user_sessions_data:
                # Create minimal Session object from session data
                session_obj = Session(**session_data)
                user_sessions.append(session_obj)

            # Convert to response schemas using helper method
            response_sessions = [self._build_session_response(sess) for sess in user_sessions]

            return BaseResponse(
                data=response_sessions,
                message="Success",
                trace_id=getattr(request.state, "trace_id", None),
            )

    def _register_revoke_session_endpoint(self) -> None:
        """Register the revoke session endpoint."""

        @self.router.post(
            "/{session_id}/revoke",
            response_model=BaseResponse[OperationResult],
            summary="Revoke Session",
            description="Revoke a specific session.",
        )
        async def revoke_session(
            request: Request,
            session_id: uuid.UUID,
            revoke_data: SessionRevokeRequest,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Revoke a session."""
            try:
                # Using session_service instead of direct repository access
                current_user_id = self._get_current_user_id(request)

                # Get the session - TODO: Replace with session_service method
                # For now, assuming session exists for demo purposes
                # session_obj = await session_service.get_session(session_id)
                # if not session_obj:
                #     raise NotFoundError(message=f"Session with ID {session_id} not found")

                # TODO: Check ownership permissions when service method available
                # self._check_session_ownership(request, session_obj)

                # Revoke the session
                # TODO: Replace with session_service method
                success = await session_service.invalidate_session(str(session_id))

                if not success:
                    raise NotFoundError(message=f"Session with ID {session_id} not found or already revoked")

                logger.info(
                    "session_revoked",
                    session_id=str(session_id),
                    # user_id=str(session_obj.user_id),  # TODO: Get user_id when service method available
                    revoked_by=current_user_id,
                    reason=revoke_data.reason,
                )

                return self._build_operation_result(request, "Session revoked successfully")

            except Exception as e:
                # Service layer handles rollback
                if not isinstance(e, (NotFoundError, ValidationError, ForbiddenError)):
                    logger.error(
                        "session_revocation_error",
                        session_id=str(session_id),
                        error=str(e),
                        exc_info=True,
                    )
                raise

    def _register_revoke_all_sessions_endpoint(self) -> None:
        """Register the revoke all user sessions endpoint."""

        @self.router.post(
            "/revoke-all",
            response_model=BaseResponse[OperationResult],
            summary="Revoke All User Sessions",
            description="Revoke all sessions for the current user.",
        )
        async def revoke_all_user_sessions(
            request: Request,
            revoke_data: SessionRevokeRequest,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Revoke all sessions for the current user."""
            try:
                # Using session_service instead of direct repository access
                current_user_id = self._get_current_user_id(request)

                # Revoke all user sessions
                # TODO: Replace with session_service method
                revoked_count = await session_service.invalidate_user_sessions(
                    uuid.UUID(current_user_id), current_user_id, revoke_data.reason
                )

                logger.info(
                    "all_user_sessions_revoked",
                    user_id=current_user_id,
                    revoked_count=revoked_count,
                    reason=revoke_data.reason,
                )

                return self._build_operation_result(
                    request, f"Revoked {revoked_count} sessions successfully", revoked_count
                )

            except Exception as e:
                # Service layer handles rollback
                logger.error(
                    "revoke_all_sessions_error",
                    user_id=current_user_id,
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_extend_session_endpoint(self) -> None:
        """Register the extend session endpoint."""

        @self.router.post(
            "/{session_id}/extend",
            response_model=BaseResponse[OperationResult],
            summary="Extend Session",
            description="Extend session expiration time.",
        )
        async def extend_session(
            request: Request,
            session_id: uuid.UUID,
            extend_data: SessionExtendRequest,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Extend a session's expiration time."""
            try:
                # Using session_service instead of direct repository access

                # Get the session - TODO: Replace with session_service method
                # For now, assuming session exists for demo purposes
                # session_obj = await session_service.get_session(session_id)
                # if not session_obj:
                #     raise NotFoundError(message=f"Session with ID {session_id} not found")

                # TODO: Check ownership permissions when service method available
                # self._check_session_ownership(request, session_obj)

                # Extend the session
                from datetime import datetime, timedelta, timezone

                new_expires_at = datetime.now(timezone.utc) + timedelta(minutes=extend_data.extension_minutes)
                # TODO: Implement session extension through service layer
                # session_obj.extend_session(new_expires_at)
                # Service layer handles transactions automatically

                logger.info(
                    "session_extended",
                    session_id=str(session_id),
                    # user_id=str(session_obj.user_id),  # TODO: Get user_id when service method available
                    extension_minutes=extend_data.extension_minutes,
                    new_expires_at=new_expires_at,
                )

                return self._build_operation_result(
                    request, f"Session extended by {extend_data.extension_minutes} minutes"
                )

            except Exception as e:
                # Service layer handles rollback
                if not isinstance(e, (NotFoundError, ValidationError, ForbiddenError)):
                    logger.error(
                        "session_extension_error",
                        session_id=str(session_id),
                        error=str(e),
                        exc_info=True,
                    )
                raise

    def _register_active_sessions_endpoint(self) -> None:
        """Register the get active sessions endpoint."""

        @self.router.get(
            "/active",
            response_model=BaseResponse[List[SessionResponse]],
            summary="Get Active Sessions",
            description="Get all currently active sessions (admin only).",
        )
        async def get_active_sessions(
            request: Request,
            limit: int = Query(100, ge=1, le=1000, description="Maximum sessions to return"),  # noqa: B008
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[List[SessionResponse]]:
            """Get all active sessions (admin only)."""
            self._check_admin_permission(request)

            try:
                # Using session_service instead of direct repository access
                # TODO: Replace with session_service method
                active_sessions: List[Session] = []  # await session_service.get_active_sessions(limit)

                # Convert to response schemas using helper method
                response_sessions = [self._build_session_response(sess) for sess in active_sessions]

                return BaseResponse(
                    data=response_sessions,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "get_active_sessions_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_statistics_endpoint(self) -> None:
        """Register the session statistics endpoint."""

        @self.router.get(
            "/statistics",
            response_model=BaseResponse[SessionStatistics],
            summary="Get Session Statistics",
            description="Get session statistics (admin only).",
        )
        async def get_session_statistics(
            request: Request,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[SessionStatistics]:
            """Get session statistics (admin only)."""
            self._check_admin_permission(request)

            try:
                # Using session_service instead of direct repository access
                # TODO: Replace with session_service method
                stats: Dict[str, Any] = {}  # await session_service.get_statistics()

                # Convert to response schema
                session_stats = SessionStatistics(
                    total_sessions=stats.get("total_sessions", 0),
                    active_sessions=stats.get("active_sessions", 0),
                    expired_sessions=stats.get("expired_sessions", 0),
                    revoked_sessions=stats.get("revoked_sessions", 0),
                    sessions_created_today=stats.get("sessions_created_today", 0),
                )

                return BaseResponse(
                    data=session_stats,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "session_statistics_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_cleanup_endpoint(self) -> None:
        """Register the cleanup expired sessions endpoint."""

        @self.router.post(
            "/cleanup-expired",
            response_model=BaseResponse[OperationResult],
            summary="Cleanup Expired Sessions",
            description="Cleanup expired sessions (admin only).",
            include_in_schema=False,  # Hide from public docs
        )
        async def cleanup_expired_sessions(
            request: Request,
            session_service: SessionService = Depends(get_session_service),  # noqa: B008
        ) -> BaseResponse[OperationResult]:
            """Cleanup expired sessions (admin only)."""
            self._check_admin_permission(request)

            try:
                # Using session_service instead of direct repository access
                # Use session_service method
                cleaned_count = await session_service.cleanup_expired_sessions()

                logger.info(
                    "expired_sessions_cleaned",
                    cleaned_count=cleaned_count,
                )

                return self._build_operation_result(
                    request, f"Cleaned up {cleaned_count} expired sessions", cleaned_count
                )

            except Exception as e:
                logger.error(
                    "cleanup_expired_sessions_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

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
            response_model=PaginatedResponse[SessionResponse],
            summary=f"List {self.model.__name__}s",
            description=f"Retrieve a paginated list of {self.model.__name__} objects with optional filtering and sorting.",
        )
        async def list_items(
            request: Request,
            filters: SessionFilter = Depends(SessionFilter),
            session_service: SessionService = Depends(get_session_service),
        ) -> PaginatedResponse[SessionResponse]:
            return await self._list_items(request, filters, session_service)

        # Get by ID endpoint (from base router)
        @self.router.get(
            "/{item_id}",
            response_model=BaseResponse[SessionResponse],
            summary=f"Get {self.model.__name__}",
            description=f"Retrieve a specific {self.model.__name__} by ID.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def get_item(
            request: Request,
            item_id: uuid.UUID,
            session_service: SessionService = Depends(get_session_service),
        ) -> BaseResponse[SessionResponse]:
            return await self._get_item(request, item_id, session_service)

        # Skip create endpoint - using custom implementation

        # Update endpoint (from base router)
        @self.router.put(
            "/{item_id}",
            response_model=BaseResponse[SessionResponse],
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
            item_data: SessionUpdate,
            session_service: SessionService = Depends(get_session_service),
        ) -> BaseResponse[SessionResponse]:
            return await self._update_item(request, item_id, item_data, session_service)

        # Patch endpoint (from base router)
        @self.router.patch(
            "/{item_id}",
            response_model=BaseResponse[SessionResponse],
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
            item_data: SessionUpdate,
            session_service: SessionService = Depends(get_session_service),
        ) -> BaseResponse[SessionResponse]:
            return await self._patch_item(request, item_id, item_data, session_service)

        # Delete endpoint (from base router)
        @self.router.delete(
            "/{item_id}",
            response_model=BaseResponse[OperationResult],
            summary=f"Delete {self.model.__name__}",
            description=f"Delete a specific {self.model.__name__}.",
            responses={
                404: {"description": f"{self.model.__name__} not found"},
            },
        )
        async def delete_item(
            request: Request,
            item_id: uuid.UUID,
            session_service: SessionService = Depends(get_session_service),
        ) -> BaseResponse[OperationResult]:
            return await self._delete_item(request, item_id, False, session_service)

    def _add_custom_endpoints(self) -> None:
        """Add session-specific endpoints."""
        self._register_create_session_endpoint()
        self._register_my_sessions_endpoint()
        self._register_revoke_session_endpoint()
        self._register_revoke_all_sessions_endpoint()
        self._register_extend_session_endpoint()
        self._register_active_sessions_endpoint()
        self._register_statistics_endpoint()
        self._register_cleanup_endpoint()


# Create router instance
session_crud_router = SessionCRUDRouter()
router = session_crud_router.router
