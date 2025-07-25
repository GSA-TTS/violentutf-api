"""Enhanced health check endpoints with real database and cache connectivity."""

import asyncio
import shutil
from datetime import datetime, timezone
from typing import Any, Dict

import psutil
from fastapi import APIRouter, Response, status
from structlog.stdlib import get_logger

from ...core.config import settings
from ...db.session import check_database_health
from ...utils.cache import check_cache_health
from ...utils.monitoring import check_dependency_health, track_health_check

logger = get_logger(__name__)
router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
@track_health_check
async def health_check() -> Dict[str, Any]:
    """Return basic health check - always returns 200 if service is running."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready")
@track_health_check
async def readiness_check(response: Response) -> Dict[str, Any]:
    """Return comprehensive readiness check - verifies all dependencies.

    Returns 503 if any critical dependency is down.
    """
    # Use enhanced dependency health check with caching (10 second TTL)
    health_result = await check_dependency_health(cache_ttl=10)

    # Run additional system checks in parallel
    system_checks = await asyncio.gather(check_disk_space(), check_memory(), return_exceptions=True)

    # Process system check results
    disk_healthy = not isinstance(system_checks[0], Exception) and system_checks[0]
    memory_healthy = not isinstance(system_checks[1], Exception) and system_checks[1]

    # Combine all checks
    all_checks = {
        "database": health_result["checks"]["database"],
        "cache": health_result["checks"]["cache"],
        "disk_space": disk_healthy,
        "memory": memory_healthy,
    }

    all_healthy = all(all_checks.values())

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning("readiness_check_failed", failed_checks=[k for k, v in all_checks.items() if not v])

    return {
        "status": "ready" if all_healthy else "not ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": all_checks,
        "details": {
            "failed_checks": [k for k, v in all_checks.items() if not v],
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "metrics": health_result.get("metrics", {}),
            "check_duration": health_result.get("check_duration_seconds", 0),
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
        logger.error("disk_space_check_failed", error=str(e))
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
        logger.error("memory_check_failed", error=str(e))
        return False
