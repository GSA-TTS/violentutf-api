"""Integration tests for CRUD endpoints flow."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.session import Session
from app.models.user import User


class TestCRUDEndpointsIntegration:
    """Integration tests for complete CRUD endpoints flow."""

    def test_complete_user_crud_flow(
        self,
        client: TestClient,
        admin_token: str,
        db_session: AsyncSession,
    ) -> None:
        """Test complete user CRUD flow."""
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Create a new user
        import uuid

        unique_suffix = str(uuid.uuid4())[:8]
        user_data = {
            "username": f"newuser_{unique_suffix}",
            "email": f"new_{unique_suffix}@example.com",
            "password": "NewPass123!",
            "full_name": "New User",
            "is_superuser": False,
        }

        create_response = client.post(
            "/api/v1/users/",
            json=user_data,
            headers=headers,
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        created_user = create_response.json()["data"]
        user_id = created_user["id"]
        print(f"Created user: {created_user}")
        print(f"Created user id: {user_id}, is_deleted: {created_user.get('is_deleted', 'NOT PRESENT')}")

        # 2. List users with pagination
        list_response = client.get(
            "/api/v1/users/",
            params={"page": 1, "per_page": 10},
            headers=headers,
        )
        assert list_response.status_code == status.HTTP_200_OK
        list_data = list_response.json()
        # Debug print
        print(f"List response structure: {list_data.keys()}")
        print(f"List data: {list_data}")
        # Check if data is in right structure
        if "items" in list_data:
            users = list_data["items"]
        else:
            users = list_data.get("data", [])
        assert any(u["id"] == user_id for u in users)

        # 3. Get user by ID
        get_response = client.get(
            f"/api/v1/users/{user_id}",
            headers=headers,
        )
        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["data"]["username"] == user_data["username"]

        # 4. Update user
        update_data = {"full_name": "Updated User Name"}
        update_response = client.put(
            f"/api/v1/users/{user_id}",
            json=update_data,
            headers=headers,
        )
        assert update_response.status_code == status.HTTP_200_OK

        # 5. Verify update
        verify_response = client.get(
            f"/api/v1/users/{user_id}",
            headers=headers,
        )
        assert verify_response.json()["data"]["full_name"] == "Updated User Name"

        # 6. Delete user
        delete_response = client.delete(
            f"/api/v1/users/{user_id}",
            headers=headers,
        )
        assert delete_response.status_code == status.HTTP_200_OK
        assert delete_response.json()["data"]["success"] is True

        # 7. Verify deletion (soft delete)
        final_response = client.get(
            f"/api/v1/users/{user_id}",
            headers=headers,
        )
        assert final_response.status_code == status.HTTP_404_NOT_FOUND

    def test_api_key_lifecycle(
        self,
        client: TestClient,
        test_user: User,
        auth_token: str,
        db_session: AsyncSession,
    ) -> None:
        """Test complete API key lifecycle."""
        headers = {"Authorization": f"Bearer {auth_token}"}

        # 1. Create API key
        key_data = {
            "name": "Test API Key",
            "description": "Integration test key",
            "permissions": {"read": True, "write": False},
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }

        create_response = client.post(
            "/api/v1/api-keys/",
            json=key_data,
            headers=headers,
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        created_key = create_response.json()["data"]
        key_id = created_key["id"]
        full_key = created_key["key"]  # Save for later validation

        # 2. List my API keys
        list_response = client.get(
            "/api/v1/api-keys/my-keys",
            headers=headers,
        )
        assert list_response.status_code == status.HTTP_200_OK
        assert any(k["id"] == key_id for k in list_response.json()["data"])

        # 3. Validate API key
        validate_response = client.post(
            f"/api/v1/api-keys/{key_id}/validate",
            headers=headers,
        )
        assert validate_response.status_code == status.HTTP_200_OK
        assert validate_response.json()["data"]["success"] is True

        # 4. Update API key
        update_data = {
            "name": "Updated API Key",
            "permissions": {"read": True, "write": True},
        }
        update_response = client.put(
            f"/api/v1/api-keys/{key_id}",
            json=update_data,
            headers=headers,
        )
        assert update_response.status_code == status.HTTP_200_OK

        # 5. Revoke API key
        revoke_response = client.post(
            f"/api/v1/api-keys/{key_id}/revoke",
            headers=headers,
        )
        assert revoke_response.status_code == status.HTTP_200_OK

        # 6. Validate revoked key
        validate_revoked = client.post(
            f"/api/v1/api-keys/{key_id}/validate",
            headers=headers,
        )
        assert validate_revoked.status_code == status.HTTP_200_OK
        assert validate_revoked.json()["data"]["success"] is False

    def test_session_management_flow(
        self,
        client: TestClient,
        test_user: User,
        auth_token: str,
        db_session: AsyncSession,
    ) -> None:
        """Test session management flow."""
        headers = {"Authorization": f"Bearer {auth_token}"}

        # 1. Create a session
        session_data = {
            "user_id": str(test_user.id),
            "session_token": f"test_session_{uuid.uuid4()}",
            "device_info": "Test Device",
            "ip_address": "127.0.0.1",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        }

        create_response = client.post(
            "/api/v1/sessions/",
            json=session_data,
            headers=headers,
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        session_id = create_response.json()["data"]["id"]

        # 2. Get my sessions
        my_sessions = client.get(
            "/api/v1/sessions/my-sessions",
            headers=headers,
        )
        assert my_sessions.status_code == status.HTTP_200_OK
        assert any(s["id"] == session_id for s in my_sessions.json()["data"])

        # 3. Extend session
        extend_response = client.post(
            f"/api/v1/sessions/{session_id}/extend",
            json={"extension_minutes": 60},
            headers=headers,
        )
        assert extend_response.status_code == status.HTTP_200_OK

        # 4. Revoke specific session
        revoke_response = client.post(
            f"/api/v1/sessions/{session_id}/revoke",
            json={"reason": "Test revocation"},
            headers=headers,
        )
        assert revoke_response.status_code == status.HTTP_200_OK

        # 5. Verify session is revoked
        get_response = client.get(
            f"/api/v1/sessions/{session_id}",
            headers=headers,
        )
        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["data"]["is_active"] is False

    def test_audit_log_tracking(
        self,
        client: TestClient,
        admin_user: User,
        admin_token: str,
        db_session: AsyncSession,
    ) -> None:
        """Test that actions are properly tracked in audit logs."""
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Perform some actions
        # Create a user
        user_data = {
            "username": "audittest",
            "email": "audit@example.com",
            "password": "AuditPass123!",
        }
        user_response = client.post(
            "/api/v1/users/",
            json=user_data,
            headers=headers,
        )
        assert user_response.status_code == status.HTTP_201_CREATED
        user_id = user_response.json()["data"]["id"]

        # Update the user
        client.put(
            f"/api/v1/users/{user_id}",
            json={"full_name": "Audit Test User"},
            headers=headers,
        )

        # 2. Check audit logs
        # Wait a moment for audit logs to be written
        import time

        time.sleep(0.5)

        # Get audit logs for the user
        logs_response = client.get(
            f"/api/v1/audit-logs/resource/user/{user_id}",
            headers=headers,
        )
        assert logs_response.status_code == status.HTTP_200_OK
        logs = logs_response.json()["data"]

        # Should have at least create and update actions
        actions = [log["action"] for log in logs]
        assert "user.create" in actions
        assert "user.update" in actions

        # 3. Get audit statistics
        stats_response = client.get(
            "/api/v1/audit-logs/statistics",
            headers=headers,
        )
        assert stats_response.status_code == status.HTTP_200_OK
        stats = stats_response.json()["data"]
        assert stats["total_logs"] > 0

        # 4. Test export functionality
        export_response = client.post(
            "/api/v1/audit-logs/export",
            json={
                "format": "json",
                "resource_type": "user",
                "include_metadata": True,
            },
            headers=headers,
        )
        assert export_response.status_code == status.HTTP_200_OK
        assert export_response.headers["content-type"] == "application/json"

    def test_idempotency_middleware(
        self,
        client: TestClient,
        auth_token: str,
    ) -> None:
        """Test idempotency middleware with repeated requests."""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Idempotency-Key": f"test-key-{uuid.uuid4()}",
        }

        # First request - create API key
        key_data = {
            "name": "Idempotent Key",
            "permissions": {"read": True},
        }

        first_response = client.post(
            "/api/v1/api-keys/",
            json=key_data,
            headers=headers,
        )
        assert first_response.status_code == status.HTTP_201_CREATED
        first_data = first_response.json()

        # Second request with same idempotency key
        second_response = client.post(
            "/api/v1/api-keys/",
            json=key_data,
            headers=headers,
        )
        assert second_response.status_code == status.HTTP_201_CREATED
        second_data = second_response.json()

        # Should return the same response
        assert first_data["data"]["id"] == second_data["data"]["id"]

        # Different idempotency key should create new resource
        headers["Idempotency-Key"] = f"test-key-{uuid.uuid4()}"
        third_response = client.post(
            "/api/v1/api-keys/",
            json={**key_data, "name": "Another Key"},
            headers=headers,
        )
        assert third_response.status_code == status.HTTP_201_CREATED
        assert third_response.json()["data"]["id"] != first_data["data"]["id"]

    def test_permission_boundaries(
        self,
        client: TestClient,
        test_user: User,
        auth_token: str,
        admin_user: User,
        admin_token: str,
    ) -> None:
        """Test permission boundaries between users and admins."""
        user_headers = {"Authorization": f"Bearer {auth_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Regular user cannot access admin endpoints
        admin_only_endpoints = [
            ("GET", "/api/v1/sessions/statistics"),
            ("GET", "/api/v1/api-keys/usage-stats"),
            ("GET", "/api/v1/audit-logs/"),
            ("POST", f"/api/v1/users/{admin_user.id}/verify"),
        ]

        for method, endpoint in admin_only_endpoints:
            if method == "GET":
                response = client.get(endpoint, headers=user_headers)
            else:
                response = client.post(endpoint, headers=user_headers)
            assert response.status_code == status.HTTP_403_FORBIDDEN

        # 2. Users can only modify their own resources
        # Try to delete another user's data
        delete_response = client.delete(
            f"/api/v1/users/{admin_user.id}",
            headers=user_headers,
        )
        assert delete_response.status_code == status.HTTP_403_FORBIDDEN

        # 3. Admin can access everything
        admin_list = client.get(
            "/api/v1/users/",
            headers=admin_headers,
        )
        assert admin_list.status_code == status.HTTP_200_OK

        stats = client.get(
            "/api/v1/sessions/statistics",
            headers=admin_headers,
        )
        assert stats.status_code == status.HTTP_200_OK
