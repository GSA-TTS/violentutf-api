"""Health service for system health checks."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict

from structlog.stdlib import get_logger

from ..db.session import check_database_health
from ..utils.cache import check_cache_health
from ..utils.monitoring import check_dependency_health

logger = get_logger(__name__)


class HealthService:
    """Service for performing system health checks."""

    def __init__(self) -> None:
        """Initialize health service."""
        pass

    async def check_database_health(self) -> Dict[str, Any]:
        """Check database health through proper service layer."""
        try:
            return await check_database_health()
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return {"status": "unhealthy", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}

    async def check_cache_health(self) -> Dict[str, Any]:
        """Check cache health through proper service layer."""
        try:
            return await check_cache_health()
        except Exception as e:
            logger.error("Cache health check failed", error=str(e))
            return {"status": "unhealthy", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}

    async def check_dependency_health(self, cache_ttl: int = None) -> Dict[str, Any]:
        """Check dependency health through proper service layer."""
        try:
            if cache_ttl:
                return await check_dependency_health(cache_ttl=cache_ttl)
            else:
                return await check_dependency_health()
        except Exception as e:
            logger.error("Dependency health check failed", error=str(e))
            return {
                "overall_healthy": False,
                "checks": {
                    "database": False,
                    "cache": False,
                },
                "error": str(e),
                "check_duration_seconds": 0,
            }

    async def check_repository_health(self) -> Dict[str, Any]:
        """Check health of all registered repositories through service layer."""
        try:
            from ..core.container import get_repository_health_with_timeout

            # Get comprehensive health status with caching and timeout protection
            repository_status = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=True)

            logger.debug(
                "repository_health_check_complete",
                overall_status=repository_status["overall_status"],
                healthy_count=repository_status["healthy_count"],
                total_count=repository_status["total_count"],
            )

            return repository_status

        except Exception as e:
            logger.error("repository_health_check_failed", error=str(e))
            return {
                "overall_status": "error",
                "healthy_count": 0,
                "degraded_count": 0,
                "unhealthy_count": 8,
                "total_count": 8,
                "total_check_time_ms": 0,
                "repositories": {},
                "summary": {
                    "health_percentage": 0,
                    "average_response_time_ms": 0,
                    "unhealthy_repositories": ["health_endpoint_error"],
                },
                "error": str(e),
            }

    async def get_comprehensive_health(self) -> Dict[str, Any]:
        """Get comprehensive health status for all components."""
        try:
            # Run health checks in parallel
            results = await asyncio.gather(
                self.check_database_health(),
                self.check_cache_health(),
                self.check_dependency_health(),
                return_exceptions=True,
            )
            db_health, cache_health, dep_health = results

            # Process results
            health_status = {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "components": {
                    "database": (
                        db_health
                        if not isinstance(db_health, Exception)
                        else {"status": "error", "error": str(db_health)}
                    ),
                    "cache": (
                        cache_health
                        if not isinstance(cache_health, Exception)
                        else {"status": "error", "error": str(cache_health)}
                    ),
                    "dependencies": (
                        dep_health
                        if not isinstance(dep_health, Exception)
                        else {"status": "error", "error": str(dep_health)}
                    ),
                },
            }

            # Determine overall status
            component_statuses = [comp.get("status", "unknown") for comp in health_status["components"].values()]
            if "error" in component_statuses or "unhealthy" in component_statuses:
                health_status["status"] = "unhealthy"

            return health_status

        except Exception as e:
            logger.error("Comprehensive health check failed", error=str(e))
            return {"status": "unhealthy", "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}
