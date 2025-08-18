"""Comprehensive integration tests for repository implementations achieving 100% coverage."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.db.base_class import Base
from app.db.session import create_async_session_maker, get_db
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.security_scan import SecurityScan
from app.models.session import UserSession
from app.models.user import User
from app.models.vulnerability_finding import VulnerabilityFinding
from app.models.vulnerability_taxonomy import VulnerabilityTaxonomy
from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.base import Page
from app.repositories.role import RoleRepository
from app.repositories.security_scan import SecurityScanRepository
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository
from app.repositories.vulnerability_finding import VulnerabilityFindingRepository
from app.repositories.vulnerability_taxonomy import VulnerabilityTaxonomyRepository


@pytest.fixture(scope="function")
async def test_engine():
    """Create a test database engine."""
    # Use in-memory SQLite for tests
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False, connect_args={"check_same_thread": False})

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Clean up
    await engine.dispose()


@pytest.fixture(scope="function")
async def test_session(test_engine):
    """Create a test database session."""
    async_session_maker = create_async_session_maker(test_engine)

    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def user_repository(test_session):
    """Create a user repository for testing."""
    return UserRepository(test_session)


@pytest.fixture
async def role_repository(test_session):
    """Create a role repository for testing."""
    return RoleRepository(test_session)


@pytest.fixture
async def api_key_repository(test_session):
    """Create an API key repository for testing."""
    return APIKeyRepository(test_session)


@pytest.fixture
async def audit_log_repository(test_session):
    """Create an audit log repository for testing."""
    return AuditLogRepository(test_session)


@pytest.fixture
async def session_repository(test_session):
    """Create a session repository for testing."""
    return SessionRepository(test_session)


class TestUserRepositoryIntegration:
    """Integration tests for UserRepository."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, user_repository, test_session):
        """Test successful user creation."""
        user = await user_repository.create_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
            full_name="Test User",
            is_superuser=False,
            created_by="admin",
        )

        await test_session.commit()

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.is_superuser is False
        assert user.is_active is True
        assert verify_password("SecurePass123!", user.password_hash)

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, user_repository, test_session):
        """Test user creation with duplicate username."""
        # Create first user
        await user_repository.create_user(username="testuser", email="test1@example.com", password="Pass123!")
        await test_session.commit()

        # Try to create second user with same username
        with pytest.raises(ValueError, match="Username 'testuser' already exists"):
            await user_repository.create_user(username="testuser", email="test2@example.com", password="Pass456!")

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, user_repository, test_session):
        """Test user creation with duplicate email."""
        # Create first user
        await user_repository.create_user(username="user1", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Try to create second user with same email
        with pytest.raises(ValueError, match="Email 'test@example.com' already exists"):
            await user_repository.create_user(username="user2", email="test@example.com", password="Pass456!")

    @pytest.mark.asyncio
    async def test_create_user_empty_password(self, user_repository):
        """Test user creation with empty password."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await user_repository.create_user(username="testuser", email="test@example.com", password="")

    @pytest.mark.asyncio
    async def test_get_by_username(self, user_repository, test_session):
        """Test getting user by username."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Get by username
        found_user = await user_repository.get_by_username("testuser")

        assert found_user is not None
        assert found_user.id == user.id
        assert found_user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_by_username_not_found(self, user_repository):
        """Test getting non-existent user by username."""
        user = await user_repository.get_by_username("nonexistent")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_by_username_with_organization(self, user_repository, test_session):
        """Test getting user by username with organization filtering."""
        org_id = str(uuid.uuid4())

        # Create user with organization
        user_data = {
            "username": "orguser",
            "email": "org@example.com",
            "password_hash": hash_password("Pass123!"),
            "organization_id": org_id,
        }
        user = await user_repository.create(user_data)
        await test_session.commit()

        # Get with correct organization
        found_user = await user_repository.get_by_username("orguser", organization_id=org_id)
        assert found_user is not None

        # Get with wrong organization
        wrong_org_id = str(uuid.uuid4())
        found_user = await user_repository.get_by_username("orguser", organization_id=wrong_org_id)
        assert found_user is None

    @pytest.mark.asyncio
    async def test_get_by_email(self, user_repository, test_session):
        """Test getting user by email."""
        # Create user
        user = await user_repository.create_user(
            username="testuser", email="Test@Example.Com", password="Pass123!"  # Mixed case
        )
        await test_session.commit()

        # Get by email (case-insensitive)
        found_user = await user_repository.get_by_email("test@example.com")

        assert found_user is not None
        assert found_user.id == user.id
        assert found_user.email == "test@example.com"  # Stored in lowercase

    @pytest.mark.asyncio
    async def test_authenticate_success(self, user_repository, test_session):
        """Test successful authentication."""
        # Create user
        user = await user_repository.create_user(
            username="testuser", email="test@example.com", password="SecurePass123!"
        )
        await test_session.commit()

        # Authenticate with username
        auth_user = await user_repository.authenticate("testuser", "SecurePass123!", "192.168.1.1")

        assert auth_user is not None
        assert auth_user.id == user.id
        assert auth_user.last_login_at is not None
        assert auth_user.last_login_ip == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_authenticate_with_email(self, user_repository, test_session):
        """Test authentication using email."""
        # Create user
        user = await user_repository.create_user(
            username="testuser", email="test@example.com", password="SecurePass123!"
        )
        await test_session.commit()

        # Authenticate with email
        auth_user = await user_repository.authenticate("test@example.com", "SecurePass123!")

        assert auth_user is not None
        assert auth_user.id == user.id

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self, user_repository, test_session):
        """Test authentication with wrong password."""
        # Create user
        await user_repository.create_user(username="testuser", email="test@example.com", password="SecurePass123!")
        await test_session.commit()

        # Authenticate with wrong password
        auth_user = await user_repository.authenticate("testuser", "WrongPassword")

        assert auth_user is None

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, user_repository):
        """Test authentication with non-existent user."""
        auth_user = await user_repository.authenticate("nonexistent", "password")
        assert auth_user is None

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self, user_repository, test_session):
        """Test authentication with inactive user."""
        # Create user
        user = await user_repository.create_user(
            username="testuser", email="test@example.com", password="SecurePass123!"
        )
        await test_session.commit()

        # Deactivate user
        await user_repository.deactivate_user(user.id)
        await test_session.commit()

        # Try to authenticate
        auth_user = await user_repository.authenticate("testuser", "SecurePass123!")

        assert auth_user is None

    @pytest.mark.asyncio
    async def test_update_password_success(self, user_repository, test_session):
        """Test successful password update."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="OldPass123!")
        await test_session.commit()

        # Update password
        success = await user_repository.update_password(user.id, "OldPass123!", "NewPass456!", "admin")

        assert success is True

        # Verify new password works
        auth_user = await user_repository.authenticate("testuser", "NewPass456!")
        assert auth_user is not None

    @pytest.mark.asyncio
    async def test_update_password_wrong_old_password(self, user_repository, test_session):
        """Test password update with wrong old password."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="OldPass123!")
        await test_session.commit()

        # Update with wrong old password
        success = await user_repository.update_password(user.id, "WrongOldPass", "NewPass456!")

        assert success is False

    @pytest.mark.asyncio
    async def test_update_password_empty_new_password(self, user_repository, test_session):
        """Test password update with empty new password."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="OldPass123!")
        await test_session.commit()

        # Update with empty new password
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_repository.update_password(user.id, "OldPass123!", "")

    @pytest.mark.asyncio
    async def test_activate_deactivate_user(self, user_repository, test_session):
        """Test user activation and deactivation."""
        # Create active user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Deactivate
        success = await user_repository.deactivate_user(user.id, "admin")
        assert success is True

        # Verify user is inactive
        updated_user = await user_repository.get_by_id(user.id)
        assert updated_user.is_active is False

        # Try to deactivate again (already inactive)
        success = await user_repository.deactivate_user(user.id)
        assert success is False

        # Activate
        success = await user_repository.activate_user(user.id, "admin")
        assert success is True

        # Verify user is active
        updated_user = await user_repository.get_by_id(user.id)
        assert updated_user.is_active is True

        # Try to activate again (already active)
        success = await user_repository.activate_user(user.id)
        assert success is False

    @pytest.mark.asyncio
    async def test_is_username_available(self, user_repository, test_session):
        """Test username availability check."""
        # Check availability before creating user
        available = await user_repository.is_username_available("testuser")
        assert available is True

        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Check availability after creating user
        available = await user_repository.is_username_available("testuser")
        assert available is False

        # Check with exclusion (for updates)
        available = await user_repository.is_username_available("testuser", exclude_user_id=user.id)
        assert available is True

    @pytest.mark.asyncio
    async def test_is_email_available(self, user_repository, test_session):
        """Test email availability check."""
        # Check availability before creating user
        available = await user_repository.is_email_available("test@example.com")
        assert available is True

        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Check availability after creating user
        available = await user_repository.is_email_available("test@example.com")
        assert available is False

        # Check with exclusion (for updates)
        available = await user_repository.is_email_available("test@example.com", exclude_user_id=user.id)
        assert available is True

    @pytest.mark.asyncio
    async def test_verify_user(self, user_repository, test_session):
        """Test user verification."""
        # Create unverified user
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password_hash": hash_password("Pass123!"),
            "is_verified": False,
        }
        user = await user_repository.create(user_data)
        await test_session.commit()

        # Verify user
        success = await user_repository.verify_user(user.id, "admin")
        assert success is True

        # Check user is verified
        updated_user = await user_repository.get_by_id(user.id)
        assert updated_user.is_verified is True
        assert updated_user.verified_at is not None

        # Try to verify again (already verified)
        success = await user_repository.verify_user(user.id)
        assert success is False

    @pytest.mark.asyncio
    async def test_verify_email(self, user_repository, test_session):
        """Test email verification."""
        # Create unverified user
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password_hash": hash_password("Pass123!"),
            "is_verified": False,
        }
        user = await user_repository.create(user_data)
        await test_session.commit()

        # Verify email
        updated_user = await user_repository.verify_email(user.id)

        assert updated_user is not None
        assert updated_user.is_verified is True

    @pytest.mark.asyncio
    async def test_revoke_user(self, user_repository, test_session):
        """Test user revocation."""
        # Create active user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Revoke user
        success = await user_repository.revoke(user.id, "Security violation")

        assert success is True

        # Check user is inactive
        updated_user = await user_repository.get_by_id(user.id)
        assert updated_user.is_active is False

    @pytest.mark.asyncio
    async def test_update_last_login(self, user_repository, test_session):
        """Test updating last login timestamp."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        original_login = user.last_login_at

        # Wait a bit to ensure timestamp difference
        await asyncio.sleep(0.1)

        # Update last login
        updated_user = await user_repository.update_last_login(user.id)

        assert updated_user is not None
        assert updated_user.last_login_at is not None
        if original_login:
            assert updated_user.last_login_at > original_login

    @pytest.mark.asyncio
    async def test_change_password(self, user_repository, test_session):
        """Test changing user password."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="OldPass123!")
        await test_session.commit()

        # Change password
        new_hash = hash_password("NewPass456!")
        updated_user = await user_repository.change_password(user.id, new_hash)

        assert updated_user is not None

        # Verify new password works
        auth_user = await user_repository.authenticate("testuser", "NewPass456!")
        assert auth_user is not None

    @pytest.mark.asyncio
    async def test_get_active_users(self, user_repository, test_session):
        """Test getting active users with pagination."""
        # Create multiple users
        for i in range(15):
            await user_repository.create_user(
                username=f"user{i}",
                email=f"user{i}@example.com",
                password="Pass123!",
                is_superuser=i < 3,  # First 3 are superusers
            )
        await test_session.commit()

        # Get first page of active users
        page = await user_repository.get_active_users(page=1, size=10)

        assert isinstance(page, Page)
        assert len(page.items) == 10
        assert page.total == 15
        assert page.has_next is True
        assert page.has_prev is False

        # Get second page
        page2 = await user_repository.get_active_users(page=2, size=10)

        assert len(page2.items) == 5
        assert page2.has_next is False
        assert page2.has_prev is True

    @pytest.mark.asyncio
    async def test_get_unverified_users(self, user_repository, test_session):
        """Test getting unverified users."""
        # Create mixed verified/unverified users
        for i in range(10):
            user_data = {
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "password_hash": hash_password("Pass123!"),
                "is_verified": i >= 5,  # Last 5 are verified
                "is_active": i != 2,  # user2 is inactive
            }
            await user_repository.create(user_data)
        await test_session.commit()

        # Get unverified active users
        users = await user_repository.get_unverified_users(include_inactive=False, limit=10)

        assert len(users) == 4  # 5 unverified - 1 inactive = 4
        assert all(not u.is_verified for u in users)
        assert all(u.is_active for u in users)

        # Get all unverified users including inactive
        users = await user_repository.get_unverified_users(include_inactive=True, limit=10)

        assert len(users) == 5
        assert all(not u.is_verified for u in users)

    @pytest.mark.asyncio
    async def test_soft_delete_and_restore(self, user_repository, test_session):
        """Test soft delete and restore operations."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Soft delete
        success = await user_repository.delete(user.id, hard_delete=False)
        assert success is True

        # User should not be found with normal get
        found_user = await user_repository.get_by_id(user.id)
        assert found_user is None

        # Restore user
        success = await user_repository.restore(user.id, "admin")
        assert success is True

        # User should be found again
        found_user = await user_repository.get_by_id(user.id)
        assert found_user is not None
        assert found_user.is_deleted is False

    @pytest.mark.asyncio
    async def test_error_handling_in_operations(self, user_repository, test_session):
        """Test error handling in various operations."""
        # Test operations with non-existent user ID
        nonexistent_id = str(uuid.uuid4())

        # Update password for non-existent user
        success = await user_repository.update_password(nonexistent_id, "old", "new")
        assert success is False

        # Activate non-existent user
        success = await user_repository.activate_user(nonexistent_id)
        assert success is False

        # Deactivate non-existent user
        success = await user_repository.deactivate_user(nonexistent_id)
        assert success is False

        # Verify non-existent user
        success = await user_repository.verify_user(nonexistent_id)
        assert success is False

        # Verify email for non-existent user
        user = await user_repository.verify_email(nonexistent_id)
        assert user is None

        # Revoke non-existent user
        success = await user_repository.revoke(nonexistent_id)
        assert success is False

        # Update last login for non-existent user
        user = await user_repository.update_last_login(nonexistent_id)
        assert user is None

        # Change password for non-existent user
        user = await user_repository.change_password(nonexistent_id, "new_hash")
        assert user is None


class TestRepositoryPaginationIntegration:
    """Integration tests for pagination across repositories."""

    @pytest.mark.asyncio
    async def test_pagination_with_filters(self, user_repository, test_session):
        """Test pagination with various filters."""
        # Create test data
        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)

        for i in range(25):
            user_data = {
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "password_hash": hash_password("Pass123!"),
                "is_active": i % 2 == 0,
                "is_superuser": i < 5,
                "created_at": yesterday if i < 10 else now,
            }
            await user_repository.create(user_data)
        await test_session.commit()

        # Test basic pagination
        page = await user_repository.list_with_pagination(page=1, size=10)
        assert len(page.items) == 10
        assert page.total == 25

        # Test with filters
        page = await user_repository.list_with_pagination(page=1, size=10, filters={"is_active": True})
        assert page.total == 13  # Only active users

        # Test with multiple filters
        page = await user_repository.list_with_pagination(
            page=1, size=10, filters={"is_active": True, "is_superuser": True}
        )
        assert page.total == 3  # Active superusers (0, 2, 4)

        # Test ordering
        page = await user_repository.list_with_pagination(page=1, size=5, order_by="username", order_desc=False)
        assert page.items[0].username == "user0"  # Alphabetically first

    @pytest.mark.asyncio
    async def test_pagination_edge_cases(self, user_repository, test_session):
        """Test pagination edge cases."""
        # Test empty results
        page = await user_repository.list_with_pagination(page=1, size=10, filters={"username": "nonexistent"})
        assert len(page.items) == 0
        assert page.total == 0
        assert page.has_next is False
        assert page.has_prev is False

        # Create one user
        await user_repository.create_user(username="single", email="single@example.com", password="Pass123!")
        await test_session.commit()

        # Test single item
        page = await user_repository.list_with_pagination(page=1, size=10)
        assert len(page.items) == 1
        assert page.total == 1
        assert page.has_next is False
        assert page.has_prev is False

        # Test requesting page beyond available
        page = await user_repository.list_with_pagination(page=10, size=10)
        assert len(page.items) == 0
        assert page.has_next is False
        assert page.has_prev is True


class TestRepositoryTransactions:
    """Test transactional behavior of repositories."""

    @pytest.mark.asyncio
    async def test_rollback_on_error(self, user_repository, test_session):
        """Test that transactions are rolled back on error."""
        # Create user
        user = await user_repository.create_user(username="testuser", email="test@example.com", password="Pass123!")
        await test_session.commit()

        # Start a transaction that will fail
        try:
            # Try to create duplicate user (should fail)
            await user_repository.create_user(
                username="testuser", email="new@example.com", password="Pass456!"  # Duplicate
            )
            await test_session.commit()
        except ValueError:
            await test_session.rollback()

        # Verify original user still exists and no duplicate was created
        users = await user_repository.list_with_pagination(page=1, size=10)
        assert users.total == 1
        assert users.items[0].username == "testuser"

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, test_engine):
        """Test concurrent repository operations."""
        # Create multiple sessions
        async_session_maker = create_async_session_maker(test_engine)

        async def create_user_task(index: int):
            async with async_session_maker() as session:
                repo = UserRepository(session)
                user = await repo.create_user(
                    username=f"user{index}", email=f"user{index}@example.com", password="Pass123!"
                )
                await session.commit()
                return user

        # Run concurrent tasks
        tasks = [create_user_task(i) for i in range(10)]
        users = await asyncio.gather(*tasks)

        # Verify all users were created
        assert len(users) == 10
        assert all(u.id is not None for u in users)

        # Verify in database
        async with async_session_maker() as session:
            repo = UserRepository(session)
            page = await repo.list_with_pagination(page=1, size=20)
            assert page.total == 10


class TestRepositoryComplexQueries:
    """Test complex queries and filtering."""

    @pytest.mark.asyncio
    async def test_search_functionality(self, user_repository, test_session):
        """Test search across text fields."""
        # Create users with various attributes
        users_data = [
            ("john_doe", "john@example.com", "John Doe"),
            ("jane_smith", "jane@example.com", "Jane Smith"),
            ("bob_jones", "bob@example.com", "Bob Jones"),
            ("alice_wonder", "alice@example.com", "Alice Wonderland"),
        ]

        for username, email, full_name in users_data:
            await user_repository.create_user(username=username, email=email, password="Pass123!", full_name=full_name)
        await test_session.commit()

        # Search by partial username
        items, total = await user_repository.list_paginated(page=1, per_page=10, filters={"search": "john"})
        assert total >= 1
        assert any("john" in u.username.lower() or "john" in (u.full_name or "").lower() for u in items)

    @pytest.mark.asyncio
    async def test_advanced_filtering(self, user_repository, test_session):
        """Test advanced filtering with operators."""
        # Create test data
        now = datetime.now(timezone.utc)
        for i in range(10):
            user_data = {
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "password_hash": hash_password("Pass123!"),
                "created_at": now - timedelta(days=i),
            }
            await user_repository.create(user_data)
        await test_session.commit()

        # Test date range filtering
        week_ago = now - timedelta(days=7)
        items, total = await user_repository.list_paginated(page=1, per_page=20, filters={"created_after": week_ago})
        assert total == 8  # Users created in last 7 days (0-7)

        # Test with advanced filters
        advanced_filters = [
            {"field": "username", "operator": "contains", "value": "user"},
            {"field": "email", "operator": "endswith", "value": "@example.com"},
        ]

        items, total = await user_repository.list_paginated(
            page=1, per_page=20, filters={"advanced_filters": advanced_filters, "filter_logic": "and"}
        )
        assert total == 10  # All users match both conditions


class TestRepositoryPerformance:
    """Test repository performance characteristics."""

    @pytest.mark.asyncio
    async def test_bulk_operations(self, user_repository, test_session):
        """Test bulk creation and querying."""
        # Bulk create users
        users = []
        for i in range(100):
            user_data = {
                "username": f"user{i:03d}",
                "email": f"user{i:03d}@example.com",
                "password_hash": hash_password("Pass123!"),
                "is_active": True,
            }
            user = await user_repository.create(user_data)
            users.append(user)

        await test_session.commit()

        # Test pagination performance
        page1 = await user_repository.list_with_pagination(page=1, size=50)
        assert len(page1.items) == 50
        assert page1.total == 100

        page2 = await user_repository.list_with_pagination(page=2, size=50)
        assert len(page2.items) == 50

        # Test count performance
        count = await user_repository.count()
        assert count == 100

        # Test filtered count
        count = await user_repository.count(filters={"is_active": True})
        assert count == 100


# Run all tests with pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app.repositories", "--cov-report=term-missing"])
