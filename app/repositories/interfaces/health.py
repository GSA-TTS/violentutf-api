"""Health repository interface contract."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class IHealthRepository(ABC):
    """Interface contract for health repository operations."""

    @abstractmethod
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database connection and health statistics."""
        pass

    @abstractmethod
    async def check_database_connectivity(self) -> bool:
        """Check if database connection is healthy."""
        pass

    @abstractmethod
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics."""
        pass

    @abstractmethod
    async def get_connection_pool_stats(self) -> Dict[str, Any]:
        """Get database connection pool statistics."""
        pass

    @abstractmethod
    async def run_health_checks(self) -> Dict[str, Any]:
        """Run comprehensive health checks."""
        pass
