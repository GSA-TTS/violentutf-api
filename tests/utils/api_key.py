"""Test utilities for API key testing."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from passlib.hash import argon2
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.models.user import User


async def create_test_user(
    session: AsyncSession,
    email: str = "test@example.com",
    username: str = "testuser",
    is_active: bool = True,
) -> Dict[str, Any]:
    """Create a test user for API key testing.

    Args:
        session: Database session
        email: User email
        username: Username
        is_active: Whether user is active

    Returns:
        Dictionary with user data
    """
    user_data = {
        "id": uuid.uuid4(),
        "email": email,
        "username": username,
        "password_hash": "hashed_password_test",  # Fixed: changed from hashed_password to password_hash
        "is_active": is_active,
        "is_superuser": False,
        "email_verified": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    user = User(**user_data)
    session.add(user)
    await session.commit()
    await session.refresh(user)

    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "is_active": user.is_active,
        "is_superuser": user.is_superuser,
    }


async def create_test_api_key(
    session: AsyncSession,
    user_id: uuid.UUID,
    name: str = "Test API Key",
    description: Optional[str] = None,
    permissions: Optional[Dict[str, Any]] = None,
    expires_at: Optional[datetime] = None,
) -> APIKey:
    """Create a test API key.

    Args:
        session: Database session
        user_id: User ID who owns the key
        name: API key name
        description: Optional description
        permissions: Optional permissions dict
        expires_at: Optional expiration date

    Returns:
        Created APIKey instance
    """
    # Generate a test API key
    key_base = secrets.token_urlsafe(32)
    full_key = f"vutf_{key_base}"
    key_prefix = full_key[:12]
    # Use Argon2 for secure hashing (same as production service)
    key_hash = argon2.hash(full_key)

    api_key_data = {
        "id": uuid.uuid4(),
        "user_id": user_id,
        "name": name,
        "description": description,
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "permissions": permissions or {"users:read": True},
        "expires_at": expires_at,
        "usage_count": 0,
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "created_by": str(user_id),
        "updated_by": str(user_id),
        "version": 1,
    }

    api_key = APIKey(**api_key_data)
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return api_key


def generate_test_api_key_string() -> str:
    """Generate a test API key string.

    Returns:
        Test API key string
    """
    key_base = secrets.token_urlsafe(32)
    return f"vutf_{key_base}"


def get_api_key_hash(key_string: str) -> str:
    """Get hash for an API key string using secure Argon2 hashing.

    Args:
        key_string: API key string

    Returns:
        Argon2 hash of the key
    """
    return argon2.hash(key_string)
