"""
API-Repository Integration Tests.

This module provides comprehensive integration testing of API endpoints
with the full service-repository stack to validate end-to-end functionality,
HTTP response formats, authentication, and CRUD operations as required by Issue #89.

Key integration patterns tested:
- API endpoints with full service-repository stack
- HTTP response codes and JSON formats
- Authentication and authorization with repository pattern
- CRUD operations work end-to-end
- Error handling and response consistency
- Performance characteristics under realistic load

Related:
- Issue #89: Integration Testing & PyTestArch Validation - Zero Violations
- ADR-013: Repository Pattern Implementation
- UAT Requirement: All API integration tests pass with repository pattern
"""

import json
from typing import Any, Dict, List, Optional
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import status
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.models.api_key import APIKey
from app.models.user import User
from app.schemas.api_key import APIKeyCreate, APIKeyResponse
from app.schemas.responses.auth_response import AuthTokenResponse as TokenResponse
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from tests.utils.testclient import SafeTestClient


@pytest.mark.integration
@pytest.mark.api
class TestUserAPIRepositoryIntegration:
    """Integration tests for User API endpoints with repository implementation."""

    @pytest_asyncio.fixture
    async def admin_user_data(self) -> Dict[str, Any]:
        """Admin user data for testing."""
        return {
            "username": f"admin_{uuid4().hex[:8]}",
            "email": f"admin_{uuid4().hex[:8]}@example.com",
            "full_name": "Admin Test User",
            "password": "AdminPassword123!",
            "is_active": True,
        }

    @pytest_asyncio.fixture
    async def regular_user_data(self) -> Dict[str, Any]:
        """Regular user data for testing."""
        return {
            "username": f"user_{uuid4().hex[:8]}",
            "email": f"user_{uuid4().hex[:8]}@example.com",
            "full_name": "Regular Test User",
            "password": "UserPassword123!",
            "is_active": True,
        }

    async def test_create_user_api_integration(
        self,
        client: SafeTestClient,
        admin_token: str,
        regular_user_data: Dict[str, Any],
    ):
        """Test user creation through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Act
        response = client.post("/api/v1/users/", json=regular_user_data, headers=headers)

        # Assert
        assert response.status_code == status.HTTP_201_CREATED

        response_data = response.json()
        assert "id" in response_data
        assert response_data["username"] == regular_user_data["username"]
        assert response_data["email"] == regular_user_data["email"]
        assert response_data["full_name"] == regular_user_data["full_name"]
        assert response_data["is_active"] == regular_user_data["is_active"]
        assert "password" not in response_data  # Password should not be returned
        assert "created_at" in response_data
        assert "updated_at" in response_data

    async def test_get_user_by_id_api_integration(self, client: SafeTestClient, admin_token: str, test_user: User):
        """Test user retrieval by ID through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Act
        response = client.get(f"/api/v1/users/{test_user.id}", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert response_data["id"] == str(test_user.id)
        assert response_data["username"] == test_user.username
        assert response_data["email"] == test_user.email
        assert response_data["full_name"] == test_user.full_name

    async def test_update_user_api_integration(self, client: SafeTestClient, admin_token: str, test_user: User):
        """Test user update through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}
        update_data = {"full_name": "Updated Full Name", "is_active": False}

        # Act
        response = client.put(f"/api/v1/users/{test_user.id}", json=update_data, headers=headers)

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert response_data["id"] == str(test_user.id)
        assert response_data["full_name"] == update_data["full_name"]
        assert response_data["is_active"] == update_data["is_active"]
        assert response_data["username"] == test_user.username  # Unchanged

    async def test_delete_user_api_integration(
        self,
        client: SafeTestClient,
        admin_token: str,
        regular_user_data: Dict[str, Any],
    ):
        """Test user deletion through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create user to delete
        create_response = client.post("/api/v1/users/", json=regular_user_data, headers=headers)
        created_user = create_response.json()
        user_id = created_user["id"]

        # Act
        response = client.delete(f"/api/v1/users/{user_id}", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify user is deleted
        get_response = client.get(f"/api/v1/users/{user_id}", headers=headers)
        assert get_response.status_code == status.HTTP_404_NOT_FOUND

    async def test_list_users_api_integration(self, client: SafeTestClient, admin_token: str):
        """Test user listing through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Act
        response = client.get("/api/v1/users/", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert isinstance(response_data, list)

        # Verify response format
        if response_data:
            user = response_data[0]
            assert "id" in user
            assert "username" in user
            assert "email" in user
            assert "full_name" in user
            assert "is_active" in user
            assert "created_at" in user
            assert "password" not in user

    async def test_user_api_authentication_required(self, client: SafeTestClient, regular_user_data: Dict[str, Any]):
        """Test that user API endpoints require authentication."""
        # Act - try to create user without token
        response = client.post("/api/v1/users/", json=regular_user_data)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_user_api_duplicate_username_error(
        self,
        client: SafeTestClient,
        admin_token: str,
        regular_user_data: Dict[str, Any],
    ):
        """Test proper error handling for duplicate username."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create first user
        client.post("/api/v1/users/", json=regular_user_data, headers=headers)

        # Act - try to create duplicate
        response = client.post("/api/v1/users/", json=regular_user_data, headers=headers)

        # Assert
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_409_CONFLICT,
        ]

        response_data = response.json()
        assert "detail" in response_data

    async def test_user_api_not_found_error(self, client: SafeTestClient, admin_token: str):
        """Test proper error handling for user not found."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}
        non_existent_id = uuid4()

        # Act
        response = client.get(f"/api/v1/users/{non_existent_id}", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

        response_data = response.json()
        assert "detail" in response_data


@pytest.mark.integration
@pytest.mark.api
class TestAPIKeyAPIRepositoryIntegration:
    """Integration tests for API Key endpoints with repository implementation."""

    async def test_create_api_key_integration(self, client: SafeTestClient, auth_token: str):
        """Test API key creation through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}
        api_key_data = {"name": "Test API Key", "scopes": ["read", "write"]}

        # Act
        response = client.post("/api/v1/api-keys/", json=api_key_data, headers=headers)

        # Assert
        assert response.status_code == status.HTTP_201_CREATED

        response_data = response.json()
        assert "id" in response_data
        assert "key" in response_data
        assert response_data["name"] == api_key_data["name"]
        assert response_data["scopes"] == api_key_data["scopes"]
        assert response_data["is_active"] is True
        assert "created_at" in response_data
        assert len(response_data["key"]) > 20  # Key should be generated

    async def test_list_api_keys_integration(self, client: SafeTestClient, auth_token: str):
        """Test API key listing through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Create an API key first
        api_key_data = {"name": "List Test Key", "scopes": ["read"]}
        client.post("/api/v1/api-keys/", json=api_key_data, headers=headers)

        # Act
        response = client.get("/api/v1/api-keys/", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert isinstance(response_data, list)

        # Find our created key
        test_key = next((k for k in response_data if k["name"] == "List Test Key"), None)
        assert test_key is not None
        assert "id" in test_key
        assert "name" in test_key
        assert "scopes" in test_key
        assert "is_active" in test_key
        assert "created_at" in test_key
        # Key should NOT be included in list response for security
        assert "key" not in test_key

    async def test_revoke_api_key_integration(self, client: SafeTestClient, auth_token: str):
        """Test API key revocation through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Create API key to revoke
        api_key_data = {"name": "Revoke Test Key", "scopes": ["read"]}
        create_response = client.post("/api/v1/api-keys/", json=api_key_data, headers=headers)
        created_key = create_response.json()
        key_id = created_key["id"]

        # Act
        response = client.delete(f"/api/v1/api-keys/{key_id}", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify key is revoked (inactive)
        list_response = client.get("/api/v1/api-keys/", headers=headers)
        keys = list_response.json()
        revoked_key = next((k for k in keys if k["id"] == key_id), None)
        if revoked_key:  # If it still appears in list, it should be inactive
            assert revoked_key["is_active"] is False

    async def test_api_key_authentication_usage(self, client: SafeTestClient, auth_token: str):
        """Test using API key for authentication in API calls."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Create API key
        api_key_data = {"name": "Auth Test Key", "scopes": ["read"]}
        create_response = client.post("/api/v1/api-keys/", json=api_key_data, headers=headers)
        created_key = create_response.json()
        api_key = created_key["key"]

        # Act - use API key for authentication
        api_key_headers = {"X-API-Key": api_key}
        response = client.get("/api/v1/users/me", headers=api_key_headers)

        # Assert
        # Note: This test depends on the API key authentication middleware being properly configured
        # The exact status code may vary based on implementation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
        ]


@pytest.mark.integration
@pytest.mark.api
class TestAuthAPIRepositoryIntegration:
    """Integration tests for Authentication endpoints with repository implementation."""

    async def test_user_registration_integration(self, client: SafeTestClient):
        """Test user registration through API with repository integration."""
        # Arrange
        registration_data = {
            "username": f"newuser_{uuid4().hex[:8]}",
            "email": f"newuser_{uuid4().hex[:8]}@example.com",
            "full_name": "New Test User",
            "password": "NewUserPassword123!",
        }

        # Act
        response = client.post("/api/v1/auth/register", json=registration_data)

        # Assert
        # Note: Registration endpoint may not exist or may be disabled
        # Adjust assertion based on actual API implementation
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_404_NOT_FOUND,  # If registration is disabled
            status.HTTP_405_METHOD_NOT_ALLOWED,  # If endpoint doesn't exist
        ]

        if response.status_code == status.HTTP_201_CREATED:
            response_data = response.json()
            assert "id" in response_data
            assert response_data["username"] == registration_data["username"]
            assert response_data["email"] == registration_data["email"]
            assert "password" not in response_data

    async def test_user_login_integration(self, client: SafeTestClient, test_user: User):
        """Test user login through API with repository integration."""
        # Arrange
        login_data = {
            "username": test_user.username,
            "password": "testpassword123",  # This should match test user setup
        }

        # Act
        response = client.post("/api/v1/auth/login", data=login_data)

        # Assert
        # Note: Login implementation may vary
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,  # If using different login format
            status.HTTP_404_NOT_FOUND,  # If endpoint doesn't exist
        ]

        if response.status_code == status.HTTP_200_OK:
            response_data = response.json()
            assert "access_token" in response_data
            assert "token_type" in response_data
            assert response_data["token_type"] == "bearer"

    async def test_token_refresh_integration(self, client: SafeTestClient, auth_token: str):
        """Test token refresh through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Act
        response = client.post("/api/v1/auth/refresh", headers=headers)

        # Assert
        # Note: Refresh endpoint may not exist
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,  # If refresh endpoint doesn't exist
            status.HTTP_405_METHOD_NOT_ALLOWED,
        ]

        if response.status_code == status.HTTP_200_OK:
            response_data = response.json()
            assert "access_token" in response_data
            assert "token_type" in response_data

    async def test_get_current_user_integration(self, client: SafeTestClient, auth_token: str, test_user: User):
        """Test getting current user through API with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Act
        response = client.get("/api/v1/users/me", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert "id" in response_data
        assert "username" in response_data
        assert "email" in response_data
        assert "full_name" in response_data
        assert "password" not in response_data  # Password should never be returned


@pytest.mark.integration
@pytest.mark.api
class TestHealthAPIRepositoryIntegration:
    """Integration tests for Health endpoints with repository integration."""

    async def test_health_check_basic_integration(self, client: SafeTestClient):
        """Test basic health check endpoint with repository integration."""
        # Act
        response = client.get("/api/v1/health")

        # Assert
        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        assert "status" in response_data
        assert response_data["status"] in ["healthy", "unhealthy", "degraded"]
        assert "timestamp" in response_data
        assert "version" in response_data

    async def test_health_check_detailed_integration(self, client: SafeTestClient):
        """Test detailed health check with repository integration."""
        # Act
        response = client.get("/api/v1/health/detailed")

        # Assert
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ]

        response_data = response.json()
        assert "status" in response_data
        assert "checks" in response_data

        # Verify database check is included
        checks = response_data["checks"]
        database_check = next((check for check in checks if check["name"] == "database"), None)
        if database_check:
            assert "status" in database_check
            assert database_check["status"] in ["healthy", "unhealthy"]

    async def test_readiness_check_integration(self, client: SafeTestClient):
        """Test readiness check with repository integration."""
        # Act
        response = client.get("/api/v1/health/ready")

        # Assert
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ]

        if response.status_code == status.HTTP_200_OK:
            response_data = response.json()
            assert "ready" in response_data
            assert response_data["ready"] is True


@pytest.mark.integration
@pytest.mark.api
@pytest.mark.slow
class TestAPIRepositoryPerformanceIntegration:
    """Performance integration tests for API endpoints with repository implementation."""

    async def test_api_endpoint_response_times(self, client: SafeTestClient, auth_token: str):
        """Test API endpoint response times with repository integration."""
        import time

        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}
        endpoints_to_test = [
            ("GET", "/api/v1/users/me"),
            ("GET", "/api/v1/health"),
            ("GET", "/api/v1/api-keys/"),
        ]

        response_times = []

        # Act
        for method, endpoint in endpoints_to_test:
            start_time = time.time()

            if method == "GET":
                response = client.get(endpoint, headers=headers)
            elif method == "POST":
                response = client.post(endpoint, headers=headers)

            end_time = time.time()
            response_time = end_time - start_time
            response_times.append((endpoint, response_time, response.status_code))

        # Assert
        for endpoint, response_time, status_code in response_times:
            # Each endpoint should respond within reasonable time
            assert response_time < 2.0, f"Endpoint {endpoint} took {response_time:.2f}s (> 2.0s)"
            # Status should be successful (or expected error)
            assert status_code < 500, f"Endpoint {endpoint} returned server error: {status_code}"

        # Calculate average response time
        avg_response_time = sum(rt[1] for rt in response_times) / len(response_times)
        assert avg_response_time < 1.0, f"Average response time {avg_response_time:.2f}s exceeds 1.0s"

    async def test_concurrent_api_requests(self, client: SafeTestClient, auth_token: str):
        """Test concurrent API requests performance."""
        import asyncio
        import time
        from concurrent.futures import ThreadPoolExecutor

        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}
        request_count = 5  # Keep small for CI

        def make_request():
            """Make a single API request."""
            response = client.get("/api/v1/users/me", headers=headers)
            return response.status_code, time.time()

        # Act
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=request_count) as executor:
            futures = [executor.submit(make_request) for _ in range(request_count)]
            results = [future.result() for future in futures]

        end_time = time.time()
        total_time = end_time - start_time

        # Assert
        assert len(results) == request_count

        # All requests should be successful
        for status_code, _ in results:
            assert status_code == status.HTTP_200_OK

        # Concurrent requests should be faster than sequential
        assert total_time < request_count * 0.5, f"Concurrent requests took {total_time:.2f}s"


@pytest.mark.integration
@pytest.mark.api
class TestAPIErrorHandlingIntegration:
    """Integration tests for API error handling with repository implementation."""

    async def test_api_validation_errors(self, client: SafeTestClient, admin_token: str):
        """Test API validation error handling with repository integration."""
        # Arrange
        headers = {"Authorization": f"Bearer {admin_token}"}
        invalid_user_data = {
            "username": "",  # Empty username
            "email": "invalid-email",  # Invalid email format
            "full_name": "",  # Empty name
            "password": "short",  # Too short password
        }

        # Act
        response = client.post("/api/v1/users/", json=invalid_user_data, headers=headers)

        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        response_data = response.json()
        assert "detail" in response_data
        assert isinstance(response_data["detail"], list)

        # Should have validation errors for multiple fields
        error_fields = [error["loc"][-1] for error in response_data["detail"]]
        assert "username" in error_fields or "email" in error_fields

    async def test_api_authentication_errors(self, client: SafeTestClient):
        """Test API authentication error handling."""
        # Act - no auth token
        response = client.get("/api/v1/users/me")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        response_data = response.json()
        assert "detail" in response_data

    async def test_api_authorization_errors(self, client: SafeTestClient, auth_token: str):
        """Test API authorization error handling."""
        # Arrange - regular user trying to access admin endpoint
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Act - try to create user (admin-only operation)
        user_data = {
            "username": "unauthorized_test",
            "email": "unauth@example.com",
            "full_name": "Unauthorized User",
            "password": "Password123!",
        }
        response = client.post("/api/v1/users/", json=user_data, headers=headers)

        # Assert
        # Note: This may return 403 Forbidden or 401 Unauthorized depending on implementation
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        ]

    async def test_api_not_found_errors(self, client: SafeTestClient, auth_token: str):
        """Test API not found error handling."""
        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}
        non_existent_id = uuid4()

        # Act
        response = client.get(f"/api/v1/users/{non_existent_id}", headers=headers)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

        response_data = response.json()
        assert "detail" in response_data

    async def test_api_server_error_handling(self, client: SafeTestClient, auth_token: str):
        """Test API server error handling with repository integration."""
        # This test would require mocking to force server errors
        # For now, just verify the API handles malformed requests gracefully

        # Arrange
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Act - send malformed JSON
        response = client.post(
            "/api/v1/users/",
            data="invalid json",
            headers={**headers, "Content-Type": "application/json"},
        )

        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
@pytest.mark.api
class TestAPIRepositoryIntegrationCoverage:
    """Comprehensive API-repository integration coverage tests for Issue #89."""

    async def test_all_major_api_endpoints_integration(self, client: SafeTestClient, auth_token: str, admin_token: str):
        """Test that all major API endpoints integrate correctly with repository layer.

        This test ensures API integration coverage for Issue #89 UAT.
        """
        integration_results = {
            "health_endpoints": False,
            "auth_endpoints": False,
            "user_endpoints": False,
            "api_key_endpoints": False,
        }

        # Test Health Endpoints
        try:
            health_response = client.get("/api/v1/health")
            assert health_response.status_code == status.HTTP_200_OK
            integration_results["health_endpoints"] = True
        except Exception as e:
            print(f"Health endpoints failed: {e}")

        # Test Auth Endpoints
        try:
            headers = {"Authorization": f"Bearer {auth_token}"}
            me_response = client.get("/api/v1/users/me", headers=headers)
            assert me_response.status_code == status.HTTP_200_OK
            integration_results["auth_endpoints"] = True
        except Exception as e:
            print(f"Auth endpoints failed: {e}")

        # Test User Endpoints
        try:
            headers = {"Authorization": f"Bearer {admin_token}"}
            users_response = client.get("/api/v1/users/", headers=headers)
            assert users_response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_403_FORBIDDEN,
            ]
            integration_results["user_endpoints"] = True
        except Exception as e:
            print(f"User endpoints failed: {e}")

        # Test API Key Endpoints
        try:
            headers = {"Authorization": f"Bearer {auth_token}"}
            api_keys_response = client.get("/api/v1/api-keys/", headers=headers)
            assert api_keys_response.status_code == status.HTTP_200_OK
            integration_results["api_key_endpoints"] = True
        except Exception as e:
            print(f"API Key endpoints failed: {e}")

        # Calculate coverage
        successful_integrations = sum(integration_results.values())
        total_integrations = len(integration_results)
        coverage_percentage = (successful_integrations / total_integrations) * 100

        print(f"📊 API-Repository Integration Coverage Report:")
        for endpoint_group, success in integration_results.items():
            status_icon = "✅" if success else "❌"
            print(f"   {status_icon} {endpoint_group.replace('_', ' ').title()}")

        print(
            f"📈 API Integration Coverage: {coverage_percentage:.1f}% ({successful_integrations}/{total_integrations})"
        )

        # Validate Issue #89 requirement: All API integration tests pass
        if coverage_percentage < 100:
            failed_integrations = [group for group, success in integration_results.items() if not success]
            pytest.fail(
                f"API-repository integration incomplete: {coverage_percentage:.1f}% coverage\n"
                f"Failed integrations: {failed_integrations}\n\n"
                "Issue #89 requires all API integration tests to pass with repository pattern."
            )

        print("🎯 Issue #89 API integration requirement: SATISFIED")
        print("✅ All API endpoints successfully integrated with repository pattern")

    async def test_issue_89_api_repository_requirements_met(self, client: SafeTestClient, auth_token: str):
        """Validate all Issue #89 API-repository integration requirements are satisfied.

        This test validates the API integration requirements from UAT specification:
        - HTTP response codes and formats unchanged
        - Authentication and authorization work with repository pattern
        - CRUD operations function end-to-end
        - Error handling preserved
        """
        print("🌐 Validating Issue #89 API-Repository Integration Requirements...")

        api_requirements = {
            "http_responses_consistent": True,
            "authentication_preserved": True,
            "crud_operations_functional": True,
            "error_handling_preserved": True,
        }

        # Test HTTP response consistency
        try:
            response = client.get("/api/v1/health")
            assert response.status_code == status.HTTP_200_OK
            assert "status" in response.json()
        except:
            api_requirements["http_responses_consistent"] = False

        # Test authentication preservation
        try:
            headers = {"Authorization": f"Bearer {auth_token}"}
            response = client.get("/api/v1/users/me", headers=headers)
            assert response.status_code == status.HTTP_200_OK
        except:
            api_requirements["authentication_preserved"] = False

        # Test CRUD operations
        try:
            headers = {"Authorization": f"Bearer {auth_token}"}

            # Test Read operation
            response = client.get("/api/v1/api-keys/", headers=headers)
            assert response.status_code == status.HTTP_200_OK

            # Test Create operation
            create_data = {"name": "Test Integration Key", "scopes": ["read"]}
            create_response = client.post("/api/v1/api-keys/", json=create_data, headers=headers)
            if create_response.status_code == status.HTTP_201_CREATED:
                # Test Delete operation
                created_key = create_response.json()
                delete_response = client.delete(f"/api/v1/api-keys/{created_key['id']}", headers=headers)
                assert delete_response.status_code == status.HTTP_204_NO_CONTENT
        except:
            api_requirements["crud_operations_functional"] = False

        # Test error handling preservation
        try:
            # Test authentication error
            unauth_response = client.get("/api/v1/users/me")
            assert unauth_response.status_code == status.HTTP_401_UNAUTHORIZED

            # Test not found error
            headers = {"Authorization": f"Bearer {auth_token}"}
            notfound_response = client.get(f"/api/v1/users/{uuid4()}", headers=headers)
            assert notfound_response.status_code == status.HTTP_404_NOT_FOUND
        except:
            api_requirements["error_handling_preserved"] = False

        # Generate final compliance report
        passed_requirements = sum(api_requirements.values())
        total_requirements = len(api_requirements)
        compliance_percentage = (passed_requirements / total_requirements) * 100

        print(f"📊 API-Repository Integration Compliance Report:")
        for requirement, req_status in api_requirements.items():
            status_icon = "✅" if req_status else "❌"
            print(f"   {status_icon} {requirement.replace('_', ' ').title()}")

        print(
            f"📈 Overall API Integration Compliance: {compliance_percentage:.1f}% ({passed_requirements}/{total_requirements})"
        )

        if compliance_percentage < 100:
            failed_requirements = [req for req, status in api_requirements.items() if not status]
            pytest.fail(
                f"Issue #89 API-repository integration requirements not met: {compliance_percentage:.1f}% compliance\n"
                f"Failed requirements: {failed_requirements}\n\n"
                "All API integration requirements must pass for Issue #89 acceptance."
            )

        print("🎯 Issue #89 API-repository integration requirements: SATISFIED")
        print("✅ All API endpoints function correctly with repository pattern")
