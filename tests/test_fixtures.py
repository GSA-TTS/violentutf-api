"""Test fixtures for user management and authentication."""

from typing import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.user import User
from tests.test_database import TestDatabaseManager


class UserFactory:
    """Factory for creating test users with proper validation."""

    @staticmethod
    async def create_user(
        session: AsyncSession,
        username: str,
        email: str,
        password: str = "TestPass123!",
        full_name: str | None = None,
        is_superuser: bool = False,
        is_active: bool = True,
        is_verified: bool = True,
        roles: list[str] | None = None,
    ) -> User:
        """Create a user with proper validation and hashing."""
        if roles is None:
            roles = ["admin"] if is_superuser else ["viewer"]

        # Create user instance
        user = User(
            username=username.lower(),  # Model validates and converts to lowercase
            email=email.lower(),
            password_hash=hash_password(password),
            full_name=full_name,
            is_superuser=is_superuser,
            is_active=is_active,
            is_verified=is_verified,
            roles=roles,
            created_by="test_system",
            updated_by="test_system",
        )

        # Add to session and commit
        session.add(user)
        await session.commit()
        await session.refresh(user)

        return user

    @staticmethod
    async def create_admin_user(session: AsyncSession) -> User:
        """Create an admin user for testing."""
        return await UserFactory.create_user(
            session=session,
            username="testadmin",
            email="admin@testexample.com",
            password="AdminPass123!",
            full_name="Test Admin User",
            is_superuser=True,
            is_verified=True,
            roles=["admin"],
        )

    @staticmethod
    async def create_regular_user(session: AsyncSession) -> User:
        """Create a regular user for testing."""
        return await UserFactory.create_user(
            session=session,
            username="testuser",
            email="user@testexample.com",
            password="UserPass123!",
            full_name="Test Regular User",
            is_superuser=False,
            is_verified=True,
            roles=["viewer"],
        )


# Global user cache for session-scoped fixtures
_cached_admin_user: User | None = None
_cached_test_user: User | None = None


@pytest_asyncio.fixture(scope="session")
async def admin_user(test_db_manager: TestDatabaseManager) -> User:
    """Create admin user for the entire test session."""
    global _cached_admin_user

    if _cached_admin_user is None:
        # Use clean session that commits changes
        session = await test_db_manager.get_session()

        try:
            _cached_admin_user = await UserFactory.create_admin_user(session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    return _cached_admin_user


@pytest_asyncio.fixture(scope="session")
async def test_user(test_db_manager: TestDatabaseManager) -> User:
    """Create regular test user for the entire test session."""
    global _cached_test_user

    if _cached_test_user is None:
        # Use clean session that commits changes
        session = await test_db_manager.get_session()

        try:
            _cached_test_user = await UserFactory.create_regular_user(session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    return _cached_test_user


@pytest_asyncio.fixture(scope="session")
async def admin_token(admin_user: User, async_client: AsyncClient) -> str:
    """Generate authentication token for admin user."""
    # Login with admin credentials
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "username": admin_user.username,
            "password": "AdminPass123!",  # Password used in factory
        },
    )

    if login_response.status_code != 200:
        raise RuntimeError(f"Admin login failed: {login_response.status_code} - {login_response.text}")

    response_data = login_response.json()
    access_token = response_data.get("access_token")

    if not access_token:
        raise RuntimeError(f"No access token in response: {response_data}")

    return access_token


@pytest_asyncio.fixture(scope="session")
async def auth_token(test_user: User, async_client: AsyncClient) -> str:
    """Generate authentication token for regular test user."""
    # Login with regular user credentials
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "username": test_user.username,
            "password": "UserPass123!",  # Password used in factory
        },
    )

    if login_response.status_code != 200:
        raise RuntimeError(f"User login failed: {login_response.status_code} - {login_response.text}")

    response_data = login_response.json()
    access_token = response_data.get("access_token")

    if not access_token:
        raise RuntimeError(f"No access token in response: {response_data}")

    return access_token


@pytest_asyncio.fixture
async def fresh_user(db_session: AsyncSession) -> User:
    """Create a fresh user for tests that need unique users."""
    import uuid

    # Generate unique username and email
    unique_id = str(uuid.uuid4())[:8]
    username = f"user_{unique_id}"
    email = f"user_{unique_id}@testexample.com"

    return await UserFactory.create_user(
        session=db_session,
        username=username,
        email=email,
        password="FreshPass123!",
        full_name=f"Fresh User {unique_id}",
    )


@pytest_asyncio.fixture
async def fresh_admin_user(db_session: AsyncSession) -> User:
    """Create a fresh admin user for tests that need unique admin users."""
    import uuid

    # Generate unique username and email
    unique_id = str(uuid.uuid4())[:8]
    username = f"admin_{unique_id}"
    email = f"admin_{unique_id}@testexample.com"

    return await UserFactory.create_user(
        session=db_session,
        username=username,
        email=email,
        password="FreshAdminPass123!",
        full_name=f"Fresh Admin {unique_id}",
        is_superuser=True,
        roles=["admin"],
    )


# Utility functions for token generation
async def generate_token_for_user(user: User, client: AsyncClient, password: str) -> str:
    """Generate authentication token for any user."""
    login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "username": user.username,
            "password": password,
        },
    )

    if login_response.status_code != 200:
        raise RuntimeError(f"Login failed for {user.username}: {login_response.status_code} - {login_response.text}")

    response_data = login_response.json()
    access_token = response_data.get("access_token")

    if not access_token:
        raise RuntimeError(f"No access token in response: {response_data}")

    return access_token


@pytest_asyncio.fixture
async def fresh_user_token(fresh_user: User, async_client: AsyncClient) -> str:
    """Generate token for fresh user."""
    return await generate_token_for_user(fresh_user, async_client, "FreshPass123!")


@pytest_asyncio.fixture
async def fresh_admin_token(fresh_admin_user: User, async_client: AsyncClient) -> str:
    """Generate token for fresh admin user."""
    return await generate_token_for_user(fresh_admin_user, async_client, "FreshAdminPass123!")
