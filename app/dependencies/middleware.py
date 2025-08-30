"""Dependencies for middleware layer."""

from typing import AsyncGenerator

from app.db.session import get_db
from app.services.middleware_service import MiddlewareService


async def get_middleware_service() -> AsyncGenerator[MiddlewareService, None]:
    """Get middleware service with database session.

    Yields:
        MiddlewareService instance
    """
    async with get_db() as session:
        yield MiddlewareService(session)
