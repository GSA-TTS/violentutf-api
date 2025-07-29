"""Comprehensive tests for Audit Log read-only endpoints."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.repositories.audit_log import AuditLogRepository
from app.schemas.audit_log import (
    AuditLogExportRequest,
    AuditLogFilter,
    AuditLogResponse,
    AuditLogStatistics,
    AuditLogSummary,
)


class TestAuditLogEndpoints:
    """Test suite for Audit Log read-only endpoints."""

    def create_test_jwt_token(
        self,
        user_id: str = "12345678-1234-5678-9abc-123456789abc",
        roles: list = None,
        organization_id: str = None,
        token_type: str = "access",
        exp_delta: timedelta = None,
    ) -> str:
        """Create test JWT token with proper structure."""
        if roles is None:
            roles = ["viewer"]
        if exp_delta is None:
            exp_delta = timedelta(hours=1)

        payload = {
            "sub": user_id,
            "roles": roles,
            "organization_id": organization_id,
            "type": token_type,
            "exp": datetime.now(timezone.utc) + exp_delta,
        }

        encoded_jwt = jwt.encode(
            payload,
            settings.SECRET_KEY.get_secret_value(),
            algorithm=settings.ALGORITHM,
        )
        return str(encoded_jwt)

    def create_admin_jwt_token(self, user_id: str = "87654321-4321-8765-cba9-987654321cba") -> str:
        """Create test JWT token with admin privileges."""
        return self.create_test_jwt_token(user_id=user_id, roles=["admin"])

    @pytest.fixture
    def mock_audit_log(self) -> AuditLog:
        """Create a mock audit log for testing."""
        audit_log = MagicMock(spec=AuditLog)
        audit_log.id = uuid.uuid4()
        audit_log.action = "user.create"
        audit_log.resource_type = "user"
        audit_log.resource_id = str(uuid.uuid4())
        audit_log.user_id = uuid.uuid4()
        audit_log.user_email = "admin@example.com"
        audit_log.ip_address = "192.168.1.50"
        audit_log.user_agent = "Mozilla/5.0 Chrome/91.0"
        audit_log.changes = {"before": {"status": "inactive"}, "after": {"status": "active"}}
        audit_log.action_metadata = {"reason": "User registration"}
        audit_log.status = "success"
        audit_log.error_message = None
        audit_log.duration_ms = 125
        audit_log.created_at = datetime.now(timezone.utc)
        audit_log.updated_at = datetime.now(timezone.utc)
        audit_log.created_by = str(audit_log.user_id)
        audit_log.updated_by = str(audit_log.user_id)
        audit_log.version = 1
        return audit_log

    @pytest.fixture
    def mock_audit_log_repo(self, mock_audit_log: AuditLog) -> AsyncMock:
        """Create a mock audit log repository."""
        repo = AsyncMock(spec=AuditLogRepository)
        repo.get.return_value = mock_audit_log
        repo.list_paginated.return_value = ([mock_audit_log], 1)
        repo.get_statistics.return_value = {
            "total_logs": 1000,
            "logs_today": 50,
            "success_rate": 95.5,
            "failure_rate": 3.5,
            "error_rate": 1.0,
            "avg_duration_ms": 150.5,
            "top_actions": {"user.create": 100, "user.update": 80, "api_key.create": 60},
            "top_users": {str(uuid.uuid4()): 50, str(uuid.uuid4()): 40},
            "top_resource_types": {"user": 300, "api_key": 200, "session": 150},
        }
        repo.get_resource_summary.return_value = {
            "resource_type": "user",
            "resource_id": str(uuid.uuid4()),
            "total_actions": 25,
            "first_action_at": datetime.now(timezone.utc) - timedelta(days=30),
            "last_action_at": datetime.now(timezone.utc),
            "unique_users": 5,
            "action_breakdown": {"user.create": 1, "user.update": 20, "user.delete": 4},
            "status_breakdown": {"success": 23, "failure": 2},
        }
        repo.list_for_export.return_value = [mock_audit_log]
        repo.export_to_csv.return_value = "id,action,resource_type\n123,user.create,user\n"
        repo.export_to_json.return_value = json.dumps([{"id": "123", "action": "user.create"}])
        return repo

    @pytest.fixture
    def auth_headers(self) -> Dict[str, str]:
        """Create authentication headers."""
        token = self.create_test_jwt_token()
        return {"Authorization": f"Bearer {token}"}

    @pytest.fixture
    def admin_headers(self) -> Dict[str, str]:
        """Create admin authentication headers."""
        token = self.create_admin_jwt_token()
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.asyncio
    async def test_list_audit_logs_admin_only(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test listing audit logs with pagination (admin only)."""
        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                "/api/v1/audit-logs/",
                headers=admin_headers,
                params={"page": 1, "per_page": 20},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "data" in data
        assert "total_count" in data
        assert "pagination" in data
        assert len(data["data"]) == 1
        assert data["data"][0]["action"] == "user.create"
        mock_audit_log_repo.list_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_audit_logs_with_filters(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test listing audit logs with filters."""
        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                "/api/v1/audit-logs/",
                headers=admin_headers,
                params={
                    "page": 1,
                    "per_page": 20,
                    "action": "user.create",
                    "resource_type": "user",
                    "status": "success",
                },
            )

        assert response.status_code == status.HTTP_200_OK
        _, kwargs = mock_audit_log_repo.list_paginated.call_args
        assert kwargs["filters"]["action"] == "user.create"
        assert kwargs["filters"]["resource_type"] == "user"
        assert kwargs["filters"]["status"] == "success"

    @pytest.mark.asyncio
    async def test_get_audit_log_by_id(
        self,
        async_client: AsyncClient,
        mock_audit_log: AuditLog,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting a specific audit log by ID."""
        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                f"/api/v1/audit-logs/{mock_audit_log.id}",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["id"] == str(mock_audit_log.id)
        assert data["data"]["action"] == mock_audit_log.action
        assert data["data"]["resource_type"] == mock_audit_log.resource_type
        mock_audit_log_repo.get.assert_called_once_with(mock_audit_log.id)

    @pytest.mark.asyncio
    async def test_get_user_audit_logs(
        self,
        async_client: AsyncClient,
        mock_audit_log: AuditLog,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting audit logs for a specific user."""
        user_id = mock_audit_log.user_id

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                f"/api/v1/audit-logs/user/{user_id}",
                headers=admin_headers,
                params={"page": 1, "per_page": 20},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["data"]) == 1
        _, kwargs = mock_audit_log_repo.list_paginated.call_args
        assert kwargs["filters"]["user_id"] == str(user_id)

    @pytest.mark.asyncio
    async def test_get_resource_audit_logs(
        self,
        async_client: AsyncClient,
        mock_audit_log: AuditLog,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting audit logs for a specific resource."""
        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                f"/api/v1/audit-logs/resource/{mock_audit_log.resource_type}/{mock_audit_log.resource_id}",
                headers=admin_headers,
                params={"page": 1, "per_page": 20},
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["data"]) == 1
        _, kwargs = mock_audit_log_repo.list_paginated.call_args
        assert kwargs["filters"]["resource_type"] == mock_audit_log.resource_type
        assert kwargs["filters"]["resource_id"] == mock_audit_log.resource_id

    @pytest.mark.asyncio
    async def test_get_audit_log_statistics(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting audit log statistics."""
        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                "/api/v1/audit-logs/statistics",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        stats = data["data"]
        assert stats["total_logs"] == 1000
        assert stats["logs_today"] == 50
        assert stats["success_rate"] == 95.5
        assert stats["failure_rate"] == 3.5
        assert stats["error_rate"] == 1.0
        assert stats["avg_duration_ms"] == 150.5
        assert "top_actions" in stats
        assert "top_users" in stats
        assert "top_resource_types" in stats
        mock_audit_log_repo.get_statistics.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_resource_audit_summary(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting audit summary for a specific resource."""
        resource_type = "user"
        resource_id = str(uuid.uuid4())

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                f"/api/v1/audit-logs/summary/{resource_type}/{resource_id}",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        summary = data["data"]
        assert summary["resource_type"] == resource_type
        assert summary["total_actions"] == 25
        assert summary["unique_users"] == 5
        assert "action_breakdown" in summary
        assert "status_breakdown" in summary
        mock_audit_log_repo.get_resource_summary.assert_called_once_with(resource_type, resource_id)

    @pytest.mark.asyncio
    async def test_export_audit_logs_csv(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test exporting audit logs in CSV format."""
        export_data = {
            "format": "csv",
            "date_from": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            "date_to": datetime.now(timezone.utc).isoformat(),
            "include_metadata": False,
        }

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.post(
                "/api/v1/audit-logs/export",
                json=export_data,
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "attachment" in response.headers["content-disposition"]
        mock_audit_log_repo.list_for_export.assert_called_once()
        mock_audit_log_repo.export_to_csv.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_audit_logs_json(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test exporting audit logs in JSON format."""
        export_data = {
            "format": "json",
            "user_id": str(uuid.uuid4()),
            "resource_type": "user",
            "include_metadata": True,
        }

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.post(
                "/api/v1/audit-logs/export",
                json=export_data,
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/json"
        assert "attachment" in response.headers["content-disposition"]
        mock_audit_log_repo.list_for_export.assert_called_once()
        mock_audit_log_repo.export_to_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_logs_require_admin(
        self,
        async_client: AsyncClient,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that most audit log endpoints require admin privileges."""
        endpoints = [
            ("GET", "/api/v1/audit-logs/"),
            ("GET", f"/api/v1/audit-logs/{uuid.uuid4()}"),
            ("GET", "/api/v1/audit-logs/resource/user/123"),
            ("GET", "/api/v1/audit-logs/statistics"),
            ("GET", "/api/v1/audit-logs/summary/user/123"),
            ("POST", "/api/v1/audit-logs/export"),
        ]

        for method, endpoint in endpoints:
            if method == "GET":
                response = await async_client.get(endpoint, headers=auth_headers)
            else:
                response = await async_client.post(
                    endpoint,
                    json={"format": "csv"},
                    headers=auth_headers,
                )

            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "Administrator privileges required" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_user_can_view_own_audit_logs(
        self,
        async_client: AsyncClient,
        mock_audit_log: AuditLog,
        mock_audit_log_repo: AsyncMock,
        auth_headers: Dict[str, str],
    ) -> None:
        """Test that users can view their own audit logs."""
        # Simulate current user viewing their own logs
        user_id = mock_audit_log.user_id

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            # Mock the permission check to allow access to own logs
            from app.api.endpoints.audit_logs import audit_log_router

            with patch.object(audit_log_router, "_check_user_access_permission", return_value=None):
                response = await async_client.get(
                    f"/api/v1/audit-logs/user/{user_id}",
                    headers=auth_headers,
                )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_export_validation(
        self,
        async_client: AsyncClient,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test export request validation."""
        invalid_exports = [
            # Invalid format
            {"format": "xml"},
            # Too many actions filter
            {"format": "csv", "actions": [f"action_{i}" for i in range(100)]},
        ]

        for export_data in invalid_exports:
            response = await async_client.post(
                "/api/v1/audit-logs/export",
                json=export_data,
                headers=admin_headers,
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_audit_log_not_found(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting non-existent audit log."""
        mock_audit_log_repo.get.return_value = None
        log_id = uuid.uuid4()

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                f"/api/v1/audit-logs/{log_id}",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_resource_summary_not_found(
        self,
        async_client: AsyncClient,
        mock_audit_log_repo: AsyncMock,
        admin_headers: Dict[str, str],
    ) -> None:
        """Test getting summary for non-existent resource."""
        mock_audit_log_repo.get_resource_summary.return_value = None

        with patch("app.api.endpoints.audit_logs.AuditLogRepository", return_value=mock_audit_log_repo):
            response = await async_client.get(
                "/api/v1/audit-logs/summary/user/nonexistent",
                headers=admin_headers,
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "No audit logs found" in response.json()["message"]
