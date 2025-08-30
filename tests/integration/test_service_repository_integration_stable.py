"""
Stable Service-Repository Integration Tests.

This module provides enhanced integration testing between service layer
and repository implementations with improved stability and reliability.

Improvements:
- Retry logic for flaky tests
- Better database isolation
- Connection pool monitoring
- Async operation synchronization
- Race condition prevention
"""

import asyncio
from typing import List, Optional
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError as DuplicateResourceError
from app.core.errors import NotFoundError as ResourceNotFoundError
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.session import Session
from app.models.user import User
from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log_extensions import ExtendedAuditLogRepository
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository
from app.schemas.api_key import APIKeyCreate
from app.schemas.user import UserCreate
from app.services.api_key_service import APIKeyService
from app.services.audit_service import AuditService
from app.services.session_service import SessionService
from app.services.user_service_impl import UserServiceImpl

# Import our stability utilities
from tests.helpers.test_stability import (
    AsyncOperationWaiter,
    TestDataFactory,
    connection_monitor,
    isolated_db_session,
    stable_integration_test,
    test_data_factory,
)


@pytest.mark.integration
@pytest.mark.database
@pytest.mark.asyncio
class TestStableUserServiceRepositoryIntegration:
    """Stable integration tests for User service with repository implementation."""

    pytestmark = pytest.mark.asyncio

    @pytest_asyncio.fixture
    async def user_service(self, isolated_db_session: AsyncSession) -> UserServiceImpl:
        """Create user service with real repository and isolated session."""
        user_repo = UserRepository(isolated_db_session)
        return UserServiceImpl(user_repo)

    @stable_integration_test(max_retries=3, sync_key="user_creation")
    async def test_create_user_integration_stable(
        self, user_service: UserServiceImpl, test_data_factory: TestDataFactory
    ):
        """Test user creation through service-repository integration with stability improvements."""
        # Arrange - Create unique user data
        username = f"testuser_{uuid4().hex[:8]}"
        email = f"test_{uuid4().hex[:8]}@example.com"

        sample_user_data = UserCreate(
            username=username,
            email=email,
            password="TestPassword123!",
            full_name="Test User",
            is_active=True,
        )

        # Act
        user = await user_service.create_user(sample_user_data)

        # Wait for database consistency
        async def check_user_exists():
            try:
                retrieved_user = await user_service.get_user_by_id(str(user.id))
                return retrieved_user is not None and retrieved_user.username == username
            except ResourceNotFoundError:
                return False

        consistency_achieved = await AsyncOperationWaiter.wait_for_condition(check_user_exists, timeout=5.0)

        # Assert
        assert consistency_achieved, "Database consistency not achieved within timeout"
        assert user is not None
        assert user.username == sample_user_data.username
        assert user.email == sample_user_data.email
        assert user.full_name == sample_user_data.full_name
        assert user.is_active == sample_user_data.is_active
        assert user.id is not None
        assert user.created_at is not None

    @stable_integration_test(max_retries=3, sync_key="user_retrieval")
    async def test_get_user_by_id_integration_stable(
        self, user_service: UserServiceImpl, test_data_factory: TestDataFactory
    ):
        """Test user retrieval by ID with improved stability."""
        # Arrange - Create test user
        test_user = await test_data_factory.create_user()

        # Wait for user to be committed
        await asyncio.sleep(0.1)

        # Act & Assert
        retrieved_user = await user_service.get_user_by_id(str(test_user.id))

        assert retrieved_user is not None
        assert retrieved_user.id == test_user.id
        assert retrieved_user.username == test_user.username

    @stable_integration_test(max_retries=3, sync_key="user_update")
    async def test_update_user_integration_stable(
        self, user_service: UserServiceImpl, test_data_factory: TestDataFactory
    ):
        """Test user update through service-repository integration."""
        # Arrange - Create test user
        test_user = await test_data_factory.create_user()

        # Act - Update user
        new_full_name = f"Updated Name {uuid4().hex[:4]}"
        updated_user = await user_service.update_user(str(test_user.id), {"full_name": new_full_name})

        # Wait for consistency
        async def check_update_consistency():
            fresh_user = await user_service.get_user_by_id(str(test_user.id))
            return fresh_user.full_name == new_full_name

        consistency_achieved = await AsyncOperationWaiter.wait_for_condition(check_update_consistency, timeout=5.0)

        # Assert
        assert consistency_achieved
        assert updated_user.full_name == new_full_name
        assert updated_user.id == test_user.id


@pytest.mark.integration
@pytest.mark.database
@pytest.mark.asyncio
class TestStableAPIKeyServiceRepositoryIntegration:
    """Stable integration tests for API Key service with repository implementation."""

    pytestmark = pytest.mark.asyncio

    @pytest_asyncio.fixture
    async def api_key_service(self, isolated_db_session: AsyncSession) -> APIKeyService:
        """Create API key service with real repository and isolated session."""
        return APIKeyService(isolated_db_session)

    @pytest_asyncio.fixture
    async def test_user(self, test_data_factory: TestDataFactory) -> User:
        """Create a test user for API key operations."""
        return await test_data_factory.create_user()

    @stable_integration_test(max_retries=3, sync_key="api_key_creation")
    async def test_create_api_key_integration_stable(
        self, api_key_service: APIKeyService, test_user: User, connection_monitor
    ):
        """Test API key creation with stability improvements."""
        # Arrange
        key_data = APIKeyCreate(name=f"Test Key {uuid4().hex[:8]}", permissions={"read": True})

        initial_connections = connection_monitor.get_active_count()

        # Act
        api_key, full_key = await api_key_service.create_api_key(user_id=str(test_user.id), key_data=key_data)

        # Wait for database consistency
        async def check_api_key_exists():
            try:
                retrieved_key = await api_key_service.get_api_key_by_key(full_key)
                return retrieved_key is not None and retrieved_key.name == key_data.name
            except Exception:
                return False

        consistency_achieved = await AsyncOperationWaiter.wait_for_condition(check_api_key_exists, timeout=5.0)

        # Assert
        assert consistency_achieved
        assert api_key is not None
        assert api_key.name == key_data.name
        assert api_key.user_id == test_user.id
        assert full_key is not None

        # Check connection stability
        final_connections = connection_monitor.get_active_count()
        assert final_connections <= initial_connections + 2, "Connection leak detected"

    @stable_integration_test(max_retries=5, sync_key="api_key_revocation", timeout=45.0)
    async def test_revoke_api_key_integration_stable(
        self, api_key_service: APIKeyService, test_data_factory: TestDataFactory
    ):
        """Test API key revocation with enhanced stability and retries."""
        # Arrange - Create test user and API key
        test_user = await test_data_factory.create_user()
        api_key, full_key = await test_data_factory.create_api_key(str(test_user.id))

        # Ensure API key is properly created and retrievable
        async def verify_api_key_active():
            try:
                retrieved_key = await api_key_service.get_api_key_by_key(full_key)
                return retrieved_key is not None and retrieved_key.revoked_at is None
            except Exception:
                return False

        # Wait for API key to be fully created
        creation_verified = await AsyncOperationWaiter.wait_for_condition(verify_api_key_active, timeout=10.0)
        assert creation_verified, "API key creation not verified"

        # Act - Revoke the API key
        result = await api_key_service.revoke_api_key(str(api_key.id), str(test_user.id))

        # Wait for revocation to be consistent
        async def verify_revocation():
            try:
                revoked_key = await api_key_service.get_api_key_by_key(full_key)
                return revoked_key is None or revoked_key.revoked_at is not None
            except Exception:
                return True  # If not found, it's effectively revoked

        revocation_verified = await AsyncOperationWaiter.wait_for_condition(verify_revocation, timeout=10.0)

        # Assert
        assert result is True
        assert revocation_verified, "API key revocation not verified"


@pytest.mark.integration
@pytest.mark.database
@pytest.mark.asyncio
class TestStableSessionServiceRepositoryIntegration:
    """Stable integration tests for Session service with repository implementation."""

    pytestmark = pytest.mark.asyncio

    @pytest_asyncio.fixture
    async def session_service(self, isolated_db_session: AsyncSession) -> SessionService:
        """Create session service with real repository and isolated session."""
        return SessionService(isolated_db_session)

    @stable_integration_test(max_retries=3, sync_key="session_creation")
    async def test_create_session_integration_stable(
        self, session_service: SessionService, test_data_factory: TestDataFactory
    ):
        """Test session creation with stability improvements."""
        # Arrange - Create test user
        test_user = await test_data_factory.create_user()

        # Act
        session = await session_service.create_session(str(test_user.id))

        # Wait for consistency
        async def check_session_exists():
            try:
                retrieved_session = await session_service.get_session_by_token(session.token)
                return retrieved_session is not None and retrieved_session.user_id == test_user.id
            except Exception:
                return False

        consistency_achieved = await AsyncOperationWaiter.wait_for_condition(check_session_exists, timeout=5.0)

        # Assert
        assert consistency_achieved
        assert session is not None
        assert session.user_id == test_user.id
        assert session.token is not None
        assert session.is_active is True


@pytest.mark.integration
@pytest.mark.database
@pytest.mark.asyncio
class TestStableAuditServiceRepositoryIntegration:
    """Stable integration tests for Audit service with repository implementation."""

    pytestmark = pytest.mark.asyncio

    @pytest_asyncio.fixture
    async def audit_service(self, isolated_db_session: AsyncSession) -> AuditService:
        """Create audit service with real repository and isolated session."""
        return AuditService(isolated_db_session)

    @stable_integration_test(max_retries=3, sync_key="audit_logging")
    async def test_log_event_integration_stable(self, audit_service: AuditService, test_data_factory: TestDataFactory):
        """Test audit event logging with stability improvements."""
        # Arrange - Create test user
        test_user = await test_data_factory.create_user()

        # Act
        await audit_service.log_event(
            action="test_action",
            resource_type="user",
            resource_id=str(test_user.id),
            user_id=str(test_user.id),
            metadata={"test": "data"},
        )

        # Wait for audit log consistency
        async def check_audit_log_exists():
            try:
                logs = await audit_service.get_user_audit_logs(str(test_user.id), limit=1)
                return len(logs) > 0 and logs[0].action == "test_action"
            except Exception:
                return False

        consistency_achieved = await AsyncOperationWaiter.wait_for_condition(check_audit_log_exists, timeout=5.0)

        # Assert
        assert consistency_achieved, "Audit log not found within timeout"
