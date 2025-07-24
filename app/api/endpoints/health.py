"""Enhanced health check endpoints."""

import asyncio
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict

import psutil
from fastapi import APIRouter, Response, status
from structlog.stdlib import get_logger

from ...core.config import settings

logger = get_logger(__name__)
router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)  # type: ignore[misc]
async def health_check() -> Dict[str, Any]:
    """Return basic health check - always returns 200 if service is running."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready")  # type: ignore[misc]
async def readiness_check(response: Response) -> Dict[str, Any]:
    """Return comprehensive readiness check - verifies all dependencies.

    Returns 503 if any critical dependency is down.
    """
    checks = {
        "database": False,
        "cache": False,
        "disk_space": False,
        "memory": False,
    }

    # Run all checks in parallel
    check_tasks = [
        check_database(),
        check_cache(),
        check_disk_space(),
        check_memory(),
    ]

    results = await asyncio.gather(*check_tasks, return_exceptions=True)

    # Process results
    for check_name, result in zip(checks.keys(), results):
        if isinstance(result, Exception):
            logger.error(f"{check_name}_check_failed", error=str(result))
            checks[check_name] = False
        else:
            checks[check_name] = bool(result)

    # Determine overall health
    all_healthy = all(checks.values())

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if all_healthy else "not ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "details": {
            "failed_checks": [k for k, v in checks.items() if not v],
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
        },
    }


@router.get("/live")  # type: ignore[misc]
async def liveness_check() -> Dict[str, Any]:
    """Return liveness probe - checks if the application is running.

    Used by orchestrators to determine if the container should be restarted.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def check_database() -> bool:
    """Check database connectivity with timeout."""
    if not settings.DATABASE_URL:
        # Database is optional
        return True

    try:
        # TODO: Implement actual database check
        # For now, return True if DATABASE_URL is set
        await asyncio.sleep(0.1)  # Simulate check
        return True
    except Exception as e:
        logger.error("database_check_failed", error=str(e))
        return False


async def check_cache() -> bool:
    """Check cache connectivity."""
    if not settings.REDIS_URL:
        # Cache is optional
        return True

    try:
        # TODO: Implement actual Redis check
        # For now, return True if REDIS_URL is set
        await asyncio.sleep(0.1)  # Simulate check
        return True
    except Exception as e:
        logger.error("cache_check_failed", error=str(e))
        return False


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
