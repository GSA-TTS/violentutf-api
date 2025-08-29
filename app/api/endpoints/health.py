"""Enhanced health check endpoints with real database and cache connectivity."""

import asyncio
import shutil
from datetime import datetime, timezone
from typing import Any, Dict

import psutil
from fastapi import APIRouter, Depends, Response, status
from structlog.stdlib import get_logger

from ...core.config import settings
from ...core.rate_limiting import rate_limit
from ...services.health_service import HealthService
from ...utils.monitoring import track_health_check
from ..deps import get_health_service

logger = get_logger(__name__)
router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
@track_health_check
async def health_check(health_service: HealthService = Depends(get_health_service)) -> Dict[str, Any]:
    """Return basic health check - always returns 200 if service is running."""
    # Get repository health for UAT compliance using health service
    db_health = await health_service.check_database_health()

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_health,
    }


@router.get("/ready")
@track_health_check
async def readiness_check(
    response: Response, health_service: HealthService = Depends(get_health_service)
) -> Dict[str, Any]:
    """Return comprehensive readiness check - verifies all dependencies.

    Returns 503 if any critical dependency is down.
    """
    # Use enhanced dependency health check with caching (10 second TTL)
    health_result = await health_service.check_dependency_health()

    # Check repository health
    repository_health = await health_service.check_repository_health()

    # Run additional system checks in parallel
    system_checks = await asyncio.gather(check_disk_space(), check_memory(), return_exceptions=True)

    # Process system check results safely without exposing exception details
    disk_healthy = not isinstance(system_checks[0], Exception) and system_checks[0]
    memory_healthy = not isinstance(system_checks[1], Exception) and system_checks[1]

    # Log exceptions securely without exposing to client
    if isinstance(system_checks[0], Exception):
        logger.error("disk_space_check_exception", error_type=type(system_checks[0]).__name__)
    if isinstance(system_checks[1], Exception):
        logger.error("memory_check_exception", error_type=type(system_checks[1]).__name__)

    # Combine all checks
    all_checks = {
        "database": health_result["checks"]["database"],
        "cache": health_result["checks"]["cache"],
        "repositories": repository_health["overall_status"] == "healthy",
        "disk_space": disk_healthy,
        "memory": memory_healthy,
    }

    all_healthy = all(all_checks.values())

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning("readiness_check_failed", failed_checks=[k for k, v in all_checks.items() if not v])

    # Sanitize repository health data to prevent information disclosure
    safe_repository_health = {
        "overall_status": str(repository_health.get("overall_status", "unknown"))[:20],
        "healthy_count": (
            int(repository_health.get("healthy_count", 0))
            if isinstance(repository_health.get("healthy_count"), (int, float))
            else 0
        ),
        "total_count": (
            int(repository_health.get("total_count", 0))
            if isinstance(repository_health.get("total_count"), (int, float))
            else 0
        ),
        "health_percentage": (
            float(repository_health.get("summary", {}).get("health_percentage", 0))
            if isinstance(repository_health.get("summary", {}).get("health_percentage"), (int, float))
            else 0
        ),
        "cache_hit": bool(repository_health.get("cache_hit", False)),
    }

    # Remove any potential error details or stack traces - be more aggressive
    safe_metrics = {}
    for k, v in health_result.get("metrics", {}).items():
        if (
            isinstance(v, (str, int, float, bool))
            and not str(k).lower().startswith("error")
            and not str(k).lower().startswith("exception")
        ):
            # Limit string values to prevent information disclosure
            if isinstance(v, str):
                safe_metrics[str(k)[:20]] = str(v)[:50]
            else:
                safe_metrics[str(k)[:20]] = v

    # Sanitize all_checks to ensure no exception objects leak through
    safe_all_checks = {}
    for check_name, check_result in all_checks.items():
        # Only include boolean results, convert everything to boolean
        safe_all_checks[str(check_name)[:20]] = bool(check_result) if not isinstance(check_result, Exception) else False

    return {
        "status": "ready" if all_healthy else "not ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": safe_all_checks,
        "details": {
            "failed_checks": [k for k, v in safe_all_checks.items() if not v],
            "service": str(settings.PROJECT_NAME)[:50] if settings.PROJECT_NAME else "unknown",
            "version": str(settings.VERSION)[:20] if settings.VERSION else "unknown",
            "repositories": safe_repository_health,
            "metrics": safe_metrics,
            "check_duration": (
                float(health_result.get("check_duration_seconds", 0))
                if isinstance(health_result.get("check_duration_seconds"), (int, float))
                else 0
            ),
        },
    }


@router.get("/live")
async def liveness_check() -> Dict[str, Any]:
    """Return liveness probe - checks if the application is running.

    Used by orchestrators to determine if the container should be restarted.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Database and cache checks are now handled by the imported functions:
# - check_database_health from ...db.session
# - check_cache_health from ...utils.cache


async def check_disk_space(threshold: float = 0.9) -> bool:
    """Check if disk space is below threshold."""
    try:
        # Use asyncio to run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        usage = await loop.run_in_executor(None, shutil.disk_usage, "/")

        usage_percent = usage.used / usage.total

        if usage_percent >= threshold:
            logger.warning(
                "disk_space_high",
                used_percent=round(usage_percent * 100, 2),
                threshold_percent=round(threshold * 100, 2),
            )
            return False

        return True
    except Exception as e:
        logger.error("disk_space_check_failed", error_type=type(e).__name__)
        return False


async def check_memory(threshold: float = 0.9) -> bool:
    """Check if memory usage is below threshold."""
    try:
        # Use asyncio to run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        memory = await loop.run_in_executor(None, psutil.virtual_memory)

        usage_percent = memory.percent / 100

        if usage_percent >= threshold:
            logger.warning(
                "memory_usage_high",
                used_percent=round(usage_percent * 100, 2),
                threshold_percent=round(threshold * 100, 2),
            )
            return False

        return True
    except Exception as e:
        logger.error("memory_check_failed", error_type=type(e).__name__)
        return False


async def check_repository_health() -> Dict[str, Any]:
    """Check health of all registered repositories with caching and timeout protection."""
    try:
        from ...core.container import get_repository_health_with_timeout

        # Get comprehensive health status with caching and timeout protection
        repository_status = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=True)

        logger.debug(
            "repository_health_check_complete",
            overall_status=repository_status["overall_status"],
            healthy_count=repository_status["healthy_count"],
            total_count=repository_status["total_count"],
            total_check_time_ms=repository_status["total_check_time_ms"],
            health_percentage=repository_status["summary"]["health_percentage"],
            cache_hit=repository_status.get("cache_hit", False),
            timeout_occurred=repository_status.get("timeout_occurred", False),
        )

        return repository_status

    except Exception as e:
        logger.error("repository_health_check_failed", error_type=type(e).__name__)
        return {
            "overall_status": "error",
            "healthy_count": 0,
            "degraded_count": 0,
            "unhealthy_count": 8,
            "total_count": 8,
            "total_check_time_ms": 0,
            "repositories": {},
            "cache_hit": False,
            "cache_age_seconds": 0,
            "timeout_occurred": False,
            "timeout_seconds": 30,
            "summary": {
                "health_percentage": 0,
                "average_response_time_ms": 0,
                "unhealthy_repositories": ["health_endpoint_error"],
            },
            "error": "Repository health check failed",
        }
