"""Test fixtures for user management and authentication."""

from typing import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.user import User
from tests.test_database import DatabaseTestManager


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
        """Create an admin user for testing, or return existing one."""
        # Check if admin user already exists
        result = await session.execute(select(User).where(User.email == "admin@testexample.com"))
        existing_user = result.scalars().first()

        if existing_user:
            return existing_user

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
        """Create a regular user for testing, or return existing one."""
        # Check if regular user already exists
        result = await session.execute(select(User).where(User.email == "user@testexample.com"))
        existing_user = result.scalars().first()

        if existing_user:
            return existing_user

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


@pytest_asyncio.fixture(scope="module")
async def admin_user(test_db_manager: DatabaseTestManager) -> User:
    """Create admin user for each test module."""
    # Use clean session that commits changes
    session = await test_db_manager.get_session()

    try:
        user = await UserFactory.create_admin_user(session)
        await session.commit()
        return user
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


@pytest_asyncio.fixture(scope="module")
async def test_user(test_db_manager: DatabaseTestManager) -> User:
    """Create regular test user for each test module."""
    # Use clean session that commits changes
    session = await test_db_manager.get_session()

    try:
        user = await UserFactory.create_regular_user(session)
        await session.commit()
        return user
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


@pytest_asyncio.fixture(scope="module")
async def admin_token(admin_user: User, async_client: AsyncClient) -> str:
    """Generate authentication token for admin user."""
    # Create JWT token directly instead of using HTTP login to avoid authentication issues
    from datetime import timedelta

    from app.core.security import create_access_token

    # Create access token with admin user data
    access_token = create_access_token(
        data={
            "sub": str(admin_user.id),
            "username": admin_user.username,
            "email": admin_user.email,
            "is_superuser": admin_user.is_superuser,
            "is_active": admin_user.is_active,
            "is_verified": admin_user.is_verified,
        },
        expires_delta=timedelta(hours=1),
    )
    return access_token


@pytest_asyncio.fixture(scope="module")
async def auth_token(test_user: User, async_client: AsyncClient) -> str:
    """Generate authentication token for regular test user."""
    # Create JWT token directly instead of using HTTP login to avoid authentication issues
    from datetime import timedelta

    from app.core.security import create_access_token

    # Create access token with regular user data
    access_token = create_access_token(
        data={
            "sub": str(test_user.id),
            "username": test_user.username,
            "email": test_user.email,
            "is_superuser": test_user.is_superuser,
            "is_active": test_user.is_active,
            "is_verified": test_user.is_verified,
        },
        expires_delta=timedelta(hours=1),
    )
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
    # Create JWT token directly instead of using HTTP login to avoid authentication issues
    from datetime import timedelta

    from app.core.security import create_access_token

    # Create access token with user data
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
        },
        expires_delta=timedelta(hours=1),
    )
    return access_token


@pytest_asyncio.fixture
async def fresh_user_token(fresh_user: User, async_client: AsyncClient) -> str:
    """Generate token for fresh user."""
    return await generate_token_for_user(fresh_user, async_client, "FreshPass123!")


@pytest_asyncio.fixture
async def fresh_admin_token(fresh_admin_user: User, async_client: AsyncClient) -> str:
    """Generate token for fresh admin user."""
    return await generate_token_for_user(fresh_admin_user, async_client, "FreshAdminPass123!")
