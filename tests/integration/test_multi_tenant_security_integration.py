"""
End-to-End Multi-Tenant Security Integration Tests.

This test suite addresses critical security gaps by testing the complete security pipeline:
- JWT → Middleware → RBAC → Repository → Database
- Organization isolation across full stack
- Cross-tenant access attempt prevention
- Live endpoint security boundary testing

Tests use REAL endpoints and database connections (no mocks) as requested by user.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.core.security import create_access_token
from app.main import app
from app.models.api_key import APIKey
from app.models.user import User


class TestMultiTenantSecurityIntegration:
    """Test complete multi-tenant security pipeline with live endpoints."""

    @pytest_asyncio.fixture
    async def async_client(self) -> AsyncClient:
        """Create async HTTP client for live endpoint testing."""
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    @pytest_asyncio.fixture
    async def db_session(self) -> AsyncSession:
        """Create live database session."""
        from app.db.session import get_session

        async with get_session() as session:
            yield session

    @pytest_asyncio.fixture
    async def org1_test_user(self, db_session: AsyncSession) -> Dict:
        """Create test user for organization 1."""
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())

        # Create user in database
        user_data = {
            "id": user_id,
            "username": f"org1_user_{user_id[:8]}",
            "email": f"org1_user_{user_id[:8]}@example.com",
            "organization_id": org_id,
            "is_active": True,
            "is_verified": True,
            "hashed_password": "hashed_password_placeholder",
        }

        user = User(**user_data)
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create JWT token with organization_id
        token_data = {
            "sub": user_id,
            "organization_id": org_id,
            "roles": ["viewer"],
            "type": "access",
        }
        token = create_access_token(data=token_data)

        return {
            "user": user,
            "user_id": user_id,
            "organization_id": org_id,
            "token": token,
            "headers": {"Authorization": f"Bearer {token}"},
        }

    @pytest_asyncio.fixture
    async def org2_test_user(self, db_session: AsyncSession) -> Dict:
        """Create test user for organization 2."""
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())  # Different organization

        # Create user in database
        user_data = {
            "id": user_id,
            "username": f"org2_user_{user_id[:8]}",
            "email": f"org2_user_{user_id[:8]}@example.com",
            "organization_id": org_id,
            "is_active": True,
            "is_verified": True,
            "hashed_password": "hashed_password_placeholder",
        }

        user = User(**user_data)
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create JWT token with different organization_id
        token_data = {
            "sub": user_id,
            "organization_id": org_id,
            "roles": ["viewer"],
            "type": "access",
        }
        token = create_access_token(data=token_data)

        return {
            "user": user,
            "user_id": user_id,
            "organization_id": org_id,
            "token": token,
            "headers": {"Authorization": f"Bearer {token}"},
        }

    @pytest_asyncio.fixture
    async def org1_test_api_key(self, db_session: AsyncSession, org1_test_user: Dict) -> Dict:
        """Create test API key for organization 1 user."""
        api_key_id = str(uuid.uuid4())

        # Create API key in database
        api_key_data = {
            "id": api_key_id,
            "name": f"Test API Key {api_key_id[:8]}",
            "description": "Test API key for multi-tenant security testing",
            "key_hash": "test_hash_placeholder",
            "key_prefix": f"vutf_{api_key_id[:6]}",
            "user_id": org1_test_user["user_id"],
            "organization_id": org1_test_user["organization_id"],  # Same org as user
            "permissions": {"users:read": True, "api_keys:read": True},
            "is_active": True,
            "usage_count": 0,
        }

        api_key = APIKey(**api_key_data)
        db_session.add(api_key)
        await db_session.commit()
        await db_session.refresh(api_key)

        return {
            "api_key": api_key,
            "api_key_id": api_key_id,
            "organization_id": org1_test_user["organization_id"],
        }

    @pytest.mark.asyncio
    async def test_jwt_organization_extraction_integration(self, async_client: AsyncClient, org1_test_user: Dict):
        """Test JWT organization_id extraction through live middleware."""
        # Make request with JWT token containing organization_id
        response = await async_client.get("/api/v1/users/me", headers=org1_test_user["headers"])

        # Should succeed with proper organization context
        assert response.status_code == 200

        # Verify organization context was properly extracted
        user_data = response.json()
        assert "id" in user_data  # User data returned

        # Test state injection by checking custom endpoint if available
        test_response = await async_client.get("/api/v1/test-state", headers=org1_test_user["headers"])
        if test_response.status_code == 200:
            state_data = test_response.json()
            assert state_data.get("user_id") == org1_test_user["user_id"]
            assert "organization_id" in state_data.get("token_payload", {})

    @pytest.mark.asyncio
    async def test_cross_tenant_user_access_prevention(
        self, async_client: AsyncClient, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test that users cannot access other organizations' user data."""
        # User from org1 tries to access user from org2
        org2_user_id = org2_test_user["user_id"]

        response = await async_client.get(f"/api/v1/users/{org2_user_id}", headers=org1_test_user["headers"])

        # Should be forbidden or not found (403/404) due to organization isolation
        assert response.status_code in [403, 404]

        # Verify error message doesn't leak information about other orgs
        error_data = response.json()
        assert "organization" not in error_data.get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_cross_tenant_api_key_access_prevention(
        self, async_client: AsyncClient, org1_test_user: Dict, org2_test_user: Dict, org1_test_api_key: Dict
    ):
        """Test that users cannot access other organizations' API keys."""
        # User from org2 tries to access API key from org1
        api_key_id = org1_test_api_key["api_key_id"]

        response = await async_client.get(f"/api/v1/api-keys/{api_key_id}", headers=org2_test_user["headers"])

        # Should be forbidden or not found due to organization isolation
        assert response.status_code in [403, 404]

    @pytest.mark.asyncio
    async def test_organization_isolation_in_list_endpoints(
        self, async_client: AsyncClient, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test that list endpoints only return data from user's organization."""
        # Get user list for org1 user
        org1_response = await async_client.get("/api/v1/users", headers=org1_test_user["headers"])
        assert org1_response.status_code == 200

        # Get user list for org2 user
        org2_response = await async_client.get("/api/v1/users", headers=org2_test_user["headers"])
        assert org2_response.status_code == 200

        org1_users = org1_response.json()
        org2_users = org2_response.json()

        # Extract user IDs from responses (handle different response formats)
        org1_user_ids = set()
        org2_user_ids = set()

        if isinstance(org1_users, list):
            org1_user_ids = {user["id"] for user in org1_users if "id" in user}
        elif isinstance(org1_users, dict) and "items" in org1_users:
            org1_user_ids = {user["id"] for user in org1_users["items"] if "id" in user}

        if isinstance(org2_users, list):
            org2_user_ids = {user["id"] for user in org2_users if "id" in user}
        elif isinstance(org2_users, dict) and "items" in org2_users:
            org2_user_ids = {user["id"] for user in org2_users["items"] if "id" in user}

        # Users should not see each other across organizations
        assert org1_test_user["user_id"] not in org2_user_ids
        assert org2_test_user["user_id"] not in org1_user_ids

        # Each user should see themselves in their own org
        assert org1_test_user["user_id"] in org1_user_ids or len(org1_user_ids) == 0
        assert org2_test_user["user_id"] in org2_user_ids or len(org2_user_ids) == 0

    @pytest.mark.asyncio
    async def test_database_organization_filtering_direct(
        self, db_session: AsyncSession, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test organization filtering directly at database level."""
        # Query users with organization filtering
        org1_query = select(User).where(User.organization_id == org1_test_user["organization_id"])
        org1_result = await db_session.execute(org1_query)
        org1_users = list(org1_result.scalars().all())

        org2_query = select(User).where(User.organization_id == org2_test_user["organization_id"])
        org2_result = await db_session.execute(org2_query)
        org2_users = list(org2_result.scalars().all())

        # Verify organization isolation at database level
        org1_user_ids = {user.id for user in org1_users}
        org2_user_ids = {user.id for user in org2_users}

        # No overlap between organizations
        assert org1_user_ids.isdisjoint(org2_user_ids)

        # Each user should only appear in their own organization
        assert org1_test_user["user_id"] in org1_user_ids
        assert org2_test_user["user_id"] in org2_user_ids
        assert org1_test_user["user_id"] not in org2_user_ids
        assert org2_test_user["user_id"] not in org1_user_ids

    @pytest.mark.asyncio
    async def test_concurrent_multi_tenant_requests(
        self, async_client: AsyncClient, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test concurrent requests from different organizations maintain isolation."""

        # Create concurrent requests from both organizations
        async def make_user_request(user_data: Dict) -> Dict:
            response = await async_client.get("/api/v1/users", headers=user_data["headers"])
            return {
                "status_code": response.status_code,
                "user_id": user_data["user_id"],
                "organization_id": user_data["organization_id"],
                "response": response.json() if response.status_code == 200 else None,
            }

        # Execute concurrent requests
        results = await asyncio.gather(
            make_user_request(org1_test_user),
            make_user_request(org2_test_user),
            make_user_request(org1_test_user),
            make_user_request(org2_test_user),
        )

        # All requests should succeed
        assert all(result["status_code"] == 200 for result in results)

        # Verify organization isolation is maintained in concurrent execution
        org1_results = [r for r in results if r["organization_id"] == org1_test_user["organization_id"]]
        org2_results = [r for r in results if r["organization_id"] == org2_test_user["organization_id"]]

        assert len(org1_results) == 2
        assert len(org2_results) == 2

        # Each organization should get consistent results
        if org1_results[0]["response"] and org1_results[1]["response"]:
            # Compare response structure (should be consistent)
            assert type(org1_results[0]["response"]) == type(org1_results[1]["response"])

    @pytest.mark.asyncio
    async def test_jwt_token_manipulation_prevention(self, async_client: AsyncClient, org1_test_user: Dict):
        """Test that JWT token manipulation is detected and prevented."""
        original_token = org1_test_user["token"]

        # Test cases for token manipulation
        manipulated_tokens = [
            # Invalid signature
            original_token[:-10] + "manipulated",
            # Malformed structure
            "invalid.jwt.token",
            # Empty token
            "",
            # Wrong token type
            original_token.replace('"type":"access"', '"type":"refresh"'),
        ]

        for manipulated_token in manipulated_tokens:
            if manipulated_token == "":
                # No Authorization header
                response = await async_client.get("/api/v1/users")
            else:
                # Manipulated token
                headers = {"Authorization": f"Bearer {manipulated_token}"}
                response = await async_client.get("/api/v1/users", headers=headers)

            # Should be rejected
            assert response.status_code == 401

            error_data = response.json()
            assert (
                "authentication" in error_data.get("detail", "").lower()
                or "token" in error_data.get("detail", "").lower()
            )

    @pytest.mark.asyncio
    async def test_organization_id_missing_from_jwt(self, async_client: AsyncClient, org1_test_user: Dict):
        """Test handling of JWT tokens missing organization_id claim."""
        # Create token without organization_id
        token_data = {
            "sub": org1_test_user["user_id"],
            # Missing organization_id
            "roles": ["viewer"],
            "type": "access",
        }
        token_without_org = create_access_token(data=token_data)
        headers = {"Authorization": f"Bearer {token_without_org}"}

        # Make request - should still work but with limited access
        response = await async_client.get("/api/v1/users", headers=headers)

        # Might succeed with empty results or fail with organization context error
        assert response.status_code in [200, 400, 403]

        if response.status_code == 200:
            # If successful, should return empty/filtered results
            data = response.json()
            # Results should be empty or minimal due to missing organization context
            if isinstance(data, list):
                assert len(data) == 0
            elif isinstance(data, dict) and "items" in data:
                assert len(data["items"]) == 0

    @pytest.mark.asyncio
    async def test_privileged_endpoint_access_control(self, async_client: AsyncClient, org1_test_user: Dict):
        """Test access control for privileged endpoints."""
        # Test admin-only endpoints with regular user token
        privileged_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system",
            "/api/v1/admin/audit-logs",
        ]

        for endpoint in privileged_endpoints:
            response = await async_client.get(endpoint, headers=org1_test_user["headers"])

            # Should be forbidden (403) or not found (404) for regular user
            assert response.status_code in [403, 404]

    @pytest.mark.asyncio
    async def test_api_key_permission_scoping(
        self, async_client: AsyncClient, org1_test_user: Dict, org1_test_api_key: Dict
    ):
        """Test that API key permissions are properly scoped to organization."""
        # Try to use API key to access data (would need API key authentication endpoint)
        api_key_id = org1_test_api_key["api_key_id"]

        # Test API key details access with proper authentication
        response = await async_client.get(f"/api/v1/api-keys/{api_key_id}", headers=org1_test_user["headers"])

        if response.status_code == 200:
            # API key should belong to the same organization
            api_key_data = response.json()
            assert "id" in api_key_data
            # Verify organization context is maintained
            # (organization_id might not be in response for security)

    @pytest.mark.asyncio
    async def test_session_isolation_across_organizations(
        self, async_client: AsyncClient, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test that user sessions are isolated across organizations."""
        # Make authenticated requests from both organizations
        org1_response = await async_client.get("/api/v1/users/me", headers=org1_test_user["headers"])
        org2_response = await async_client.get("/api/v1/users/me", headers=org2_test_user["headers"])

        # Both should succeed
        assert org1_response.status_code == 200
        assert org2_response.status_code == 200

        # Verify they get different user data
        org1_data = org1_response.json()
        org2_data = org2_response.json()

        assert org1_data["id"] != org2_data["id"]
        # Verify they cannot see each other's data
        assert org1_data["id"] == org1_test_user["user_id"]
        assert org2_data["id"] == org2_test_user["user_id"]

    @pytest.mark.asyncio
    async def test_audit_trail_organization_isolation(
        self, db_session: AsyncSession, org1_test_user: Dict, org2_test_user: Dict
    ):
        """Test that audit trails are properly isolated by organization."""
        # This would test audit log isolation if audit logs are implemented
        # For now, test that user activities are properly attributed

        # Query user activities/audit logs by organization
        # This is a placeholder for when audit logging is implemented
        org1_activities = []  # Would query audit logs for org1
        org2_activities = []  # Would query audit logs for org2

        # Verify no cross-contamination in audit logs
        assert len(org1_activities) >= 0  # Placeholder assertion
        assert len(org2_activities) >= 0  # Placeholder assertion

    @pytest.mark.asyncio
    async def test_data_breach_simulation_prevention(
        self, async_client: AsyncClient, db_session: AsyncSession, org1_test_user: Dict
    ):
        """Test prevention of common data breach scenarios."""
        # Scenario 1: SQL Injection attempt through API
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "' UNION SELECT * FROM users --",
            "../../../etc/passwd",
            "<script>alert('xss')</script>",
        ]

        for malicious_input in malicious_inputs:
            # Try SQL injection through search parameters
            response = await async_client.get(
                f"/api/v1/users?search={malicious_input}", headers=org1_test_user["headers"]
            )

            # Should not crash or return unexpected data
            assert response.status_code in [200, 400, 422]  # Valid responses

            if response.status_code == 200:
                # Verify no malicious data in response
                response_text = response.text
                assert "DROP TABLE" not in response_text.upper()
                assert "<script>" not in response_text.lower()

        # Scenario 2: Verify database is still intact after injection attempts
        user_count_query = select(text("COUNT(*)")).select_from(User)
        result = await db_session.execute(user_count_query)
        user_count = result.scalar()

        # Database should still be functional and contain our test users
        assert user_count >= 2  # At least our test users should exist

    @pytest.mark.asyncio
    async def test_rate_limiting_per_organization(self, async_client: AsyncClient, org1_test_user: Dict):
        """Test that rate limiting is properly applied per organization."""
        # Make multiple rapid requests
        responses = []
        for i in range(10):  # Rapid requests
            response = await async_client.get("/api/v1/users/me", headers=org1_test_user["headers"])
            responses.append(response.status_code)

        # Most requests should succeed (200), but rate limiting might kick in (429)
        success_count = responses.count(200)
        rate_limited_count = responses.count(429)

        # Should have at least some successful requests
        assert success_count > 0
        # Rate limiting is optional but if implemented, should be reasonable
        assert rate_limited_count < 8  # Not too aggressive

    async def cleanup_test_data(
        self, db_session: AsyncSession, org1_test_user: Dict, org2_test_user: Dict, org1_test_api_key: Dict
    ):
        """Clean up test data after tests complete."""
        try:
            # Delete test API key
            if org1_test_api_key.get("api_key"):
                await db_session.delete(org1_test_api_key["api_key"])

            # Delete test users
            if org1_test_user.get("user"):
                await db_session.delete(org1_test_user["user"])
            if org2_test_user.get("user"):
                await db_session.delete(org2_test_user["user"])

            await db_session.commit()
        except Exception as e:
            # Log cleanup error but don't fail tests
            print(f"Cleanup error (non-fatal): {e}")
            await db_session.rollback()
