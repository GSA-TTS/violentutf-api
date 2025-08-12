"""Health check service for monitoring authentication components."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from structlog.stdlib import get_logger

from app.core.cache import get_cache
from app.core.circuit_breaker import get_all_circuit_stats
from app.core.config import settings
from app.db.session import get_db
from app.repositories.health import HealthRepository

logger = get_logger(__name__)


class HealthStatus:
    """Health status constants."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheckService:
    """Service for checking health of authentication components."""

    def __init__(self):
        """Initialize health check service."""
        self._last_check_time: Optional[datetime] = None
        self._last_check_results: Dict[str, Any] = {}
        self._check_interval = timedelta(seconds=30)

    async def check_all(self, force: bool = False) -> Dict[str, Any]:
        """
        Check health of all authentication components.

        Args:
            force: Force check even if recently checked

        Returns:
            Health check results
        """
        # Return cached results if recent
        if not force and self._last_check_time:
            time_since_check = datetime.now(timezone.utc) - self._last_check_time
            if time_since_check < self._check_interval:
                return self._last_check_results

        # Run all health checks concurrently
        results = await asyncio.gather(
            self.check_database(),
            self.check_cache(),
            self.check_auth_services(),
            self.check_circuit_breakers(),
            return_exceptions=True,
        )

        # Process results
        health_results = {
            "status": HealthStatus.HEALTHY,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": (
                    results[0] if not isinstance(results[0], Exception) else self._error_result("database", results[0])
                ),
                "cache": (
                    results[1] if not isinstance(results[1], Exception) else self._error_result("cache", results[1])
                ),
                "auth_services": (
                    results[2]
                    if not isinstance(results[2], Exception)
                    else self._error_result("auth_services", results[2])
                ),
                "circuit_breakers": (
                    results[3]
                    if not isinstance(results[3], Exception)
                    else self._error_result("circuit_breakers", results[3])
                ),
            },
        }

        # Determine overall status
        statuses = [comp["status"] for comp in health_results["components"].values()]
        if HealthStatus.UNHEALTHY in statuses:
            health_results["status"] = HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            health_results["status"] = HealthStatus.DEGRADED

        # Cache results
        self._last_check_time = datetime.now(timezone.utc)
        self._last_check_results = health_results

        return health_results

    async def check_database(self) -> Dict[str, Any]:
        """
        Check database health using repository pattern.

        Returns:
            Database health status
        """
        try:
            start_time = datetime.now(timezone.utc)

            async with get_db() as session:
                health_repo = HealthRepository(session)
                connectivity_result = await health_repo.check_database_connectivity()
                db_stats = await health_repo.get_database_stats()

            response_time = (datetime.now(timezone.utc) - start_time).total_seconds()

            return {
                "status": connectivity_result.get("status", HealthStatus.HEALTHY),
                "response_time_ms": response_time * 1000,
                "pool_size": settings.DATABASE_POOL_SIZE,
                **db_stats,  # Include database statistics from repository
            }

        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def check_cache(self) -> Dict[str, Any]:
        """
        Check cache (Redis) health.

        Returns:
            Cache health status
        """
        try:
            cache = await get_cache()
            health = await cache.health_check()

            if health.get("redis_available"):
                status = HealthStatus.HEALTHY
            elif health.get("fallback_cache_size", 0) > 0:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY

            return {
                "status": status,
                "redis_connected": health.get("redis_connected", False),
                "redis_available": health.get("redis_available", False),
                "response_time_ms": health.get("redis_response_time_ms"),
                "fallback_cache_size": health.get("fallback_cache_size", 0),
                "connection_failures": health.get("connection_failures", 0),
            }

        except Exception as e:
            logger.error("Cache health check failed", error=str(e))
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def check_auth_services(self) -> Dict[str, Any]:
        """
        Check authentication services health.

        Returns:
            Auth services health status
        """
        try:
            service_checks = {}

            # Check session service
            session_check = await self._check_session_service()
            service_checks["session_service"] = session_check

            # Check MFA service
            mfa_check = await self._check_mfa_service()
            service_checks["mfa_service"] = mfa_check

            # Check RBAC service
            rbac_check = await self._check_rbac_service()
            service_checks["rbac_service"] = rbac_check

            # Determine overall status
            all_healthy = all(check.get("status") == HealthStatus.HEALTHY for check in service_checks.values())
            any_unhealthy = any(check.get("status") == HealthStatus.UNHEALTHY for check in service_checks.values())

            if all_healthy:
                status = HealthStatus.HEALTHY
            elif any_unhealthy:
                status = HealthStatus.UNHEALTHY
            else:
                status = HealthStatus.DEGRADED

            return {
                "status": status,
                "services": service_checks,
            }

        except Exception as e:
            logger.error("Auth services health check failed", error=str(e))
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def check_circuit_breakers(self) -> Dict[str, Any]:
        """
        Check circuit breaker states.

        Returns:
            Circuit breaker health status
        """
        try:
            stats = get_all_circuit_stats()

            open_circuits = []
            half_open_circuits = []

            for name, breaker_stats in stats.items():
                if breaker_stats["state"] == "open":
                    open_circuits.append(name)
                elif breaker_stats["state"] == "half_open":
                    half_open_circuits.append(name)

            if open_circuits:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY

            return {
                "status": status,
                "total_breakers": len(stats),
                "open_circuits": open_circuits,
                "half_open_circuits": half_open_circuits,
                "stats": stats,
            }

        except Exception as e:
            logger.error("Circuit breaker health check failed", error=str(e))
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def _check_session_service(self) -> Dict[str, Any]:
        """Check session service health."""
        try:
            start_time = datetime.now(timezone.utc)

            # Test session operations
            from app.services.session_service import SessionService

            async with get_db() as session:
                service = SessionService(session)
                # Try to clean up expired sessions (lightweight operation)
                await service.cleanup_expired_sessions()

            response_time = (datetime.now(timezone.utc) - start_time).total_seconds()

            return {
                "status": HealthStatus.HEALTHY,
                "response_time_ms": response_time * 1000,
            }
        except Exception as e:
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
            }

    async def _check_mfa_service(self) -> Dict[str, Any]:
        """Check MFA service health."""
        try:
            # Check if MFA tables are accessible
            async with get_db() as session:
                from app.models.mfa import MFADevice

                query = select(MFADevice).limit(1)
                await session.execute(query)

            return {
                "status": HealthStatus.HEALTHY,
            }
        except Exception as e:
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
            }

    async def _check_rbac_service(self) -> Dict[str, Any]:
        """Check RBAC service health."""
        try:
            # Check if RBAC tables are accessible
            async with get_db() as session:
                from app.models.rbac import Role

                query = select(Role).limit(1)
                await session.execute(query)

            return {
                "status": HealthStatus.HEALTHY,
            }
        except Exception as e:
            return {
                "status": HealthStatus.UNHEALTHY,
                "error": str(e),
            }

    def _error_result(self, component: str, error: Exception) -> Dict[str, Any]:
        """Create error result for failed health check."""
        return {
            "status": HealthStatus.UNHEALTHY,
            "error": str(error),
            "error_type": type(error).__name__,
            "component": component,
        }

    async def get_auth_metrics(self) -> Dict[str, Any]:
        """
        Get authentication metrics.

        Returns:
            Authentication metrics
        """
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": {},
        }

        try:
            async with get_db() as session:
                # Active sessions count
                from app.models.session import Session

                active_sessions_query = select(Session).where(
                    Session.is_active == True,
                    Session.expires_at > datetime.now(timezone.utc),
                )
                result = await session.execute(active_sessions_query)
                active_sessions = len(result.scalars().all())
                metrics["metrics"]["active_sessions"] = active_sessions

                # Active users (logged in within last hour)
                from app.models.user import User

                one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
                active_users_query = select(User).where(
                    User.last_login_at > one_hour_ago,
                )
                result = await session.execute(active_users_query)
                active_users = len(result.scalars().all())
                metrics["metrics"]["active_users_1h"] = active_users

                # Failed login attempts (if tracked)
                # This would require an audit log query

        except Exception as e:
            logger.error("Failed to get auth metrics", error=str(e))
            metrics["error"] = str(e)

        return metrics


# Global instance
_health_service = HealthCheckService()


def get_health_service() -> HealthCheckService:
    """Get global health check service instance."""
    return _health_service
