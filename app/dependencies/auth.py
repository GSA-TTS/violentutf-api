"""Authentication dependencies."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.auth_service import AuthService


def get_auth_service(session: AsyncSession = Depends(get_db)) -> AuthService:
    """Get authentication service.

    Args:
        session: Database session from dependency injection

    Returns:
        AuthService instance
    """
    return AuthService(session)
