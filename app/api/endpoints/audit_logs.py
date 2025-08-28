"""Audit Log read-only endpoints for compliance and monitoring."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.api.deps import get_audit_service, get_db
from app.core.errors import ForbiddenError, NotFoundError, ValidationError
from app.models.audit_log import AuditLog
from app.repositories.audit_log_extensions import ExtendedAuditLogRepository as AuditLogRepository

# TECHNICAL DEBT: Direct repository usage violates Clean Architecture
# TODO: Replace with complete service layer methods
from app.schemas.audit_log import (
    AuditLogExportRequest,
    AuditLogFilter,
    AuditLogResponse,
    AuditLogStatistics,
    AuditLogSummary,
)
from app.schemas.base import BaseResponse, PaginatedResponse, PaginationInfo
from app.services.audit_service import AuditService

logger = get_logger(__name__)


class AuditLogRouter:
    """Audit Log read-only router for compliance and monitoring."""

    def __init__(self) -> None:
        """Initialize audit log router."""
        self.router = APIRouter(
            prefix="/audit-logs",
            tags=["Audit Logs"],
        )

        # Add audit log endpoints
        self._add_endpoints()

    def _check_admin_permission(self, request: Request) -> None:
        """Check if user has admin permissions."""
        current_user = getattr(request.state, "user", None)
        if not current_user or not getattr(current_user, "is_superuser", False):
            raise ForbiddenError(message="Administrator privileges required")

    def _check_user_access_permission(self, request: Request, user_id: uuid.UUID) -> None:
        """Check if user can access audit logs for the given user_id."""
        current_user_id = getattr(request.state, "user_id", None)
        current_user = getattr(request.state, "user", None)
        is_admin = current_user and getattr(current_user, "is_superuser", False)

        if not is_admin and current_user_id != user_id:
            raise ForbiddenError(message="You can only view your own audit logs")

    def _build_audit_log_response(self, log: AuditLog) -> AuditLogResponse:
        """Build audit log response object."""
        return AuditLogResponse(
            id=log.id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            user_id=log.user_id,
            user_email=log.user_email,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            changes=log.changes,
            action_metadata=log.action_metadata,
            status=log.status,
            error_message=log.error_message,
            duration_ms=log.duration_ms,
            created_at=log.created_at,
            created_by=log.created_by,
            updated_at=getattr(log, "updated_at", log.created_at),
            updated_by=getattr(log, "updated_by", log.created_by),
            version=getattr(log, "version", 1),
        )

    def _build_pagination_info(self, page: int, per_page: int, total_count: int) -> PaginationInfo:
        """Build pagination info object."""
        total_pages = ((total_count - 1) // per_page) + 1 if total_count > 0 else 0
        return PaginationInfo(
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
            next_cursor=None,
            prev_cursor=None,
        )

    def _build_filters_from_params(self, **kwargs: object) -> Dict[str, object]:
        """Build filters dictionary from parameters."""
        filters: Dict[str, object] = {}
        for key, value in kwargs.items():
            if value is not None:
                if key == "user_id" and isinstance(value, uuid.UUID):
                    filters[key] = str(value)
                else:
                    filters[key] = value
        return filters

    def _safe_get_int(self, data: Dict[str, Any], key: str, default: int = 0) -> int:
        """Safely extract integer value from dictionary."""
        value = data.get(key, default)
        return int(value) if isinstance(value, (int, float, str)) and str(value).isdigit() else default

    def _safe_get_float(self, data: Dict[str, Any], key: str, default: float = 0.0) -> float:
        """Safely extract float value from dictionary."""
        value = data.get(key, default)
        if value is None:
            return default
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                return float(value)
            else:
                return default
        except (ValueError, TypeError):
            return default

    def _safe_get_optional_float(self, data: Dict[str, Any], key: str) -> Optional[float]:
        """Safely extract optional float value from dictionary."""
        value = data.get(key)
        if value is None:
            return None
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                return float(value)
            else:
                return None
        except (ValueError, TypeError):
            return None

    def _safe_get_dict(
        self, data: Dict[str, Any], key: str, default: Optional[Dict[str, int]] = None
    ) -> Dict[str, int]:
        """Safely extract dictionary value from dictionary."""
        if default is None:
            default = {}
        value = data.get(key, default)
        return value if isinstance(value, dict) else default

    def _safe_get_str(self, data: Dict[str, Any], key: str, default: str) -> str:
        """Safely extract string value from dictionary."""
        value = data.get(key, default)
        return str(value) if value is not None else default

    def _safe_get_datetime(self, data: Dict[str, Any], key: str) -> Optional[datetime]:
        """Safely extract datetime value from dictionary."""
        value = data.get(key)
        if isinstance(value, datetime):
            return value
        return None

    def _build_audit_statistics(self, stats: Dict[str, Any]) -> AuditLogStatistics:
        """Build AuditLogStatistics from raw statistics data."""
        return AuditLogStatistics(
            total_logs=self._safe_get_int(stats, "total_logs"),
            logs_today=self._safe_get_int(stats, "logs_today"),
            success_rate=self._safe_get_float(stats, "success_rate"),
            failure_rate=self._safe_get_float(stats, "failure_rate"),
            error_rate=self._safe_get_float(stats, "error_rate"),
            avg_duration_ms=self._safe_get_optional_float(stats, "avg_duration_ms"),
            top_actions=self._safe_get_dict(stats, "top_actions"),
            top_users=self._safe_get_dict(stats, "top_users"),
            top_resource_types=self._safe_get_dict(stats, "top_resource_types"),
        )

    def _build_audit_summary(self, summary: Dict[str, Any], resource_type: str, resource_id: str) -> AuditLogSummary:
        """Build AuditLogSummary from raw summary data."""
        return AuditLogSummary(
            resource_type=self._safe_get_str(summary, "resource_type", resource_type),
            resource_id=self._safe_get_str(summary, "resource_id", resource_id),
            total_actions=self._safe_get_int(summary, "total_actions"),
            first_action_at=self._safe_get_datetime(summary, "first_action_at"),
            last_action_at=self._safe_get_datetime(summary, "last_action_at"),
            unique_users=self._safe_get_int(summary, "unique_users"),
            action_breakdown=self._safe_get_dict(summary, "action_breakdown"),
            status_breakdown=self._safe_get_dict(summary, "status_breakdown"),
        )

    def _add_endpoints(self) -> None:
        """Add audit log endpoints."""
        # Register specific endpoints first to avoid routing conflicts
        self._register_list_endpoint()
        self._register_user_endpoint()
        self._register_resource_endpoint()
        self._register_search_endpoint()
        self._register_statistics_endpoint()
        self._register_summary_endpoint()
        self._register_export_endpoint()
        # Register generic endpoints last to prevent conflicts
        self._register_get_endpoint()

    def _register_list_endpoint(self) -> None:
        """Register the list audit logs endpoint."""

        @self.router.get(
            "/",
            response_model=PaginatedResponse[AuditLogResponse],
            summary="List Audit Logs",
            description="Get audit logs with filtering and pagination (admin only).",
        )
        async def list_audit_logs(
            request: Request,
            page: int = Query(1, ge=1, description="Page number"),  # noqa: B008
            per_page: int = Query(20, ge=1, le=100, description="Items per page"),  # noqa: B008
            action: Optional[str] = Query(None, description="Filter by action"),  # noqa: B008
            resource_type: Optional[str] = Query(None, description="Filter by resource type"),  # noqa: B008
            resource_id: Optional[str] = Query(None, description="Filter by resource ID"),  # noqa: B008
            user_id: Optional[uuid.UUID] = Query(None, description="Filter by user ID"),  # noqa: B008
            status: Optional[str] = Query(None, description="Filter by status"),  # noqa: B008
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> PaginatedResponse[AuditLogResponse]:
            """List audit logs with filtering and pagination."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)

                # Build filters using helper method
                filters = self._build_filters_from_params(
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    user_id=user_id,
                    status=status,
                )

                # Get paginated results
                audit_logs, total_count = await repo.list_paginated(
                    page=page,
                    per_page=per_page,
                    filters=filters,
                    sort_by="created_at",
                    sort_order="desc",
                )

                # Convert to response schemas using helper method
                response_logs = [self._build_audit_log_response(log) for log in audit_logs]

                return PaginatedResponse(
                    data=response_logs,
                    pagination=self._build_pagination_info(page, per_page, total_count),
                    total_count=total_count,
                    filters=filters,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "list_audit_logs_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_get_endpoint(self) -> None:
        """Register the get audit log endpoint."""

        @self.router.get(
            "/{log_id}",
            response_model=BaseResponse[AuditLogResponse],
            summary="Get Audit Log",
            description="Get a specific audit log by ID (admin only).",
        )
        async def get_audit_log(
            request: Request,
            log_id: uuid.UUID,
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[AuditLogResponse]:
            """Get a specific audit log."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)
                audit_log = await repo.get(log_id)

                if not audit_log:
                    raise NotFoundError(message=f"Audit log with ID {log_id} not found")

                response_log = self._build_audit_log_response(audit_log)

                return BaseResponse(
                    data=response_log, message="Success", trace_id=getattr(request.state, "trace_id", None)
                )

            except Exception as e:
                if not isinstance(e, NotFoundError):
                    logger.error(
                        "get_audit_log_error",
                        log_id=str(log_id),
                        error=str(e),
                        exc_info=True,
                    )
                raise

    def _register_user_endpoint(self) -> None:
        """Register the get user audit logs endpoint."""

        @self.router.get(
            "/user/{user_id}",
            response_model=PaginatedResponse[AuditLogResponse],
            summary="Get User Audit Logs",
            description="Get audit logs for a specific user (admin only).",
        )
        async def get_user_audit_logs(
            request: Request,
            user_id: uuid.UUID,
            page: int = Query(1, ge=1, description="Page number"),  # noqa: B008
            per_page: int = Query(20, ge=1, le=100, description="Items per page"),  # noqa: B008
            action: Optional[str] = Query(None, description="Filter by action"),  # noqa: B008
            resource_type: Optional[str] = Query(None, description="Filter by resource type"),  # noqa: B008
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> PaginatedResponse[AuditLogResponse]:
            """Get audit logs for a specific user."""
            self._check_user_access_permission(request, user_id)

            try:
                repo = AuditLogRepository(session)

                # Build filters using helper method
                filters = self._build_filters_from_params(
                    user_id=user_id,
                    action=action,
                    resource_type=resource_type,
                )

                # Get paginated results
                audit_logs, total_count = await repo.list_paginated(
                    page=page,
                    per_page=per_page,
                    filters=filters,
                    sort_by="created_at",
                    sort_order="desc",
                )

                # Convert to response schemas using helper method
                response_logs = [self._build_audit_log_response(log) for log in audit_logs]

                return PaginatedResponse(
                    data=response_logs,
                    pagination=self._build_pagination_info(page, per_page, total_count),
                    total_count=total_count,
                    filters=filters,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "get_user_audit_logs_error",
                    user_id=str(user_id),
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_resource_endpoint(self) -> None:
        """Register the get resource audit logs endpoint."""

        @self.router.get(
            "/resource/{resource_type}/{resource_id}",
            response_model=PaginatedResponse[AuditLogResponse],
            summary="Get Resource Audit Logs",
            description="Get audit logs for a specific resource (admin only).",
        )
        async def get_resource_audit_logs(
            request: Request,
            resource_type: str,
            resource_id: str,
            page: int = Query(1, ge=1, description="Page number"),  # noqa: B008
            per_page: int = Query(20, ge=1, le=100, description="Items per page"),  # noqa: B008
            action: Optional[str] = Query(None, description="Filter by action"),  # noqa: B008
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> PaginatedResponse[AuditLogResponse]:
            """Get audit logs for a specific resource."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)

                # Build filters using helper method
                filters = self._build_filters_from_params(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=action,
                )

                # Get paginated results
                audit_logs, total_count = await repo.list_paginated(
                    page=page,
                    per_page=per_page,
                    filters=filters,
                    sort_by="created_at",
                    sort_order="desc",
                )

                # Convert to response schemas using helper method
                response_logs = [self._build_audit_log_response(log) for log in audit_logs]

                return PaginatedResponse(
                    data=response_logs,
                    pagination=self._build_pagination_info(page, per_page, total_count),
                    total_count=total_count,
                    filters=filters,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "get_resource_audit_logs_error",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_search_endpoint(self) -> None:
        """Register the search audit logs endpoint."""

        @self.router.get(
            "/search",
            response_model=PaginatedResponse[AuditLogResponse],
            summary="Search Audit Logs",
            description="Search audit logs with advanced filtering (admin only).",
        )
        async def search_audit_logs(
            request: Request,
            q: Optional[str] = Query(None, description="Search query"),  # noqa: B008
            page: int = Query(1, ge=1, description="Page number"),  # noqa: B008
            per_page: int = Query(20, ge=1, le=100, description="Items per page"),  # noqa: B008
            action: Optional[str] = Query(None, description="Filter by action"),  # noqa: B008
            resource_type: Optional[str] = Query(None, description="Filter by resource type"),  # noqa: B008
            user_id: Optional[uuid.UUID] = Query(None, description="Filter by user ID"),  # noqa: B008
            status: Optional[str] = Query(None, description="Filter by status"),  # noqa: B008
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> PaginatedResponse[AuditLogResponse]:
            """Search audit logs with advanced filtering."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)

                # Build filters using helper method
                filters = self._build_filters_from_params(
                    action=action,
                    resource_type=resource_type,
                    user_id=user_id,
                    status=status,
                )

                # Add search query if provided
                if q:
                    filters["search_query"] = q

                # Get paginated results
                if q:
                    page_result = await repo.search_logs(
                        search_term=q,
                        page=page,
                        size=per_page,
                    )
                    audit_logs = page_result.items
                    total_count = page_result.total
                else:
                    audit_logs, total_count = await repo.list_paginated(
                        page=page,
                        per_page=per_page,
                        filters=filters,
                        sort_by="created_at",
                        sort_order="desc",
                    )

                # Convert to response schemas using helper method
                response_logs = [self._build_audit_log_response(log) for log in audit_logs]

                return PaginatedResponse(
                    data=response_logs,
                    pagination=self._build_pagination_info(page, per_page, total_count),
                    total_count=total_count,
                    filters=filters,
                    message="Success",
                    trace_id=getattr(request.state, "trace_id", None),
                )

            except Exception as e:
                logger.error(
                    "search_audit_logs_error",
                    search_query=q,
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_statistics_endpoint(self) -> None:
        """Register the get audit log statistics endpoint."""

        @self.router.get(
            "/statistics",
            response_model=BaseResponse[AuditLogStatistics],
            summary="Get Audit Log Statistics",
            description="Get audit log statistics (admin only).",
        )
        async def get_audit_log_statistics(
            request: Request,
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[AuditLogStatistics]:
            """Get audit log statistics."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)
                stats = await repo.get_statistics()

                # Build audit statistics using helper method
                audit_stats = self._build_audit_statistics(stats)

                return BaseResponse(
                    data=audit_stats, message="Success", trace_id=getattr(request.state, "trace_id", None)
                )

            except Exception as e:
                logger.error(
                    "audit_log_statistics_error",
                    error=str(e),
                    exc_info=True,
                )
                raise

    def _register_summary_endpoint(self) -> None:
        """Register the get resource audit summary endpoint."""

        @self.router.get(
            "/summary/{resource_type}/{resource_id}",
            response_model=BaseResponse[AuditLogSummary],
            summary="Get Resource Audit Summary",
            description="Get audit summary for a specific resource (admin only).",
        )
        async def get_resource_audit_summary(
            request: Request,
            resource_type: str,
            resource_id: str,
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> BaseResponse[AuditLogSummary]:
            """Get audit summary for a specific resource."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)
                summary = await repo.get_resource_summary(resource_type, resource_id)

                if not summary:
                    raise NotFoundError(message=f"No audit logs found for {resource_type}:{resource_id}")

                # Build audit summary using helper method
                audit_summary = self._build_audit_summary(summary, resource_type, resource_id)

                return BaseResponse(
                    data=audit_summary, message="Success", trace_id=getattr(request.state, "trace_id", None)
                )

            except Exception as e:
                if not isinstance(e, NotFoundError):
                    logger.error(
                        "resource_audit_summary_error",
                        resource_type=resource_type,
                        resource_id=resource_id,
                        error=str(e),
                        exc_info=True,
                    )
                raise

    def _register_export_endpoint(self) -> None:
        """Register the export audit logs endpoint."""

        @self.router.post(
            "/export",
            summary="Export Audit Logs",
            description="Export audit logs in CSV or JSON format (admin only).",
            response_class=Response,
        )
        async def export_audit_logs(
            request: Request,
            export_request: AuditLogExportRequest,
            audit_service: AuditService = Depends(get_audit_service),  # noqa: B008
            session: AsyncSession = Depends(get_db),  # noqa: B008
        ) -> Response:
            """Export audit logs in specified format."""
            self._check_admin_permission(request)

            try:
                repo = AuditLogRepository(session)

                # Build filters from export request using helper method
                filters = self._build_filters_from_params(
                    user_id=export_request.user_id,
                    resource_type=export_request.resource_type,
                )

                # Add export-specific filters
                if export_request.actions:
                    filters["action__in"] = export_request.actions
                if export_request.date_from:
                    filters["created_at__gte"] = export_request.date_from.isoformat()
                if export_request.date_to:
                    filters["created_at__lte"] = export_request.date_to.isoformat()

                # Get audit logs for export
                audit_logs = await repo.list_for_export(
                    filters=filters,
                    include_metadata=export_request.include_metadata,
                )

                # Generate export content
                if export_request.format == "csv":
                    content = await repo.export_to_csv(audit_logs, include_metadata=export_request.include_metadata)
                    media_type = "text/csv"
                    filename = f"audit_logs_{export_request.date_from or 'all'}_{export_request.date_to or 'all'}.csv"
                else:  # json
                    content = await repo.export_to_json(audit_logs, include_metadata=export_request.include_metadata)
                    media_type = "application/json"
                    filename = f"audit_logs_{export_request.date_from or 'all'}_{export_request.date_to or 'all'}.json"

                logger.info(
                    "audit_logs_exported",
                    format=export_request.format,
                    record_count=len(audit_logs),
                    exported_by=str(getattr(request.state, "user_id", None)),
                )

                # Return file response
                headers = {
                    "Content-Disposition": f"attachment; filename={filename}",
                }

                return Response(
                    content=content,
                    media_type=media_type,
                    headers=headers,
                )

            except Exception as e:
                logger.error(
                    "export_audit_logs_error",
                    format=export_request.format,
                    error=str(e),
                    exc_info=True,
                )
                raise


# Create router instance
audit_log_router = AuditLogRouter()
router = audit_log_router.router
