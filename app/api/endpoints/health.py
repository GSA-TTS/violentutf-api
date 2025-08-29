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
from ...core.safe_logging import safe_error_message
from ...services.health_service import HealthService
from ...utils.monitoring import track_health_check
from ..deps import get_health_service

logger = get_logger(__name__)
router = APIRouter()


def _safe_extract_value(data: dict, key: str, default_value: Any, value_type: type) -> Any:
    """Safely extract and validate a value from potentially unsafe data."""
    try:
        value = data.get(key, default_value)
        # Reject any non-primitive types that could contain stack traces
        if isinstance(value, Exception) or hasattr(value, "__traceback__"):
            return default_value
        # Convert to expected type with bounds checking
        if value_type == str:
            return str(value)[:50] if value is not None else str(default_value)[:50]
        elif value_type in (int, float):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value_type(max(0, min(value, 1000000)))  # Reasonable bounds
            return value_type(default_value)
        elif value_type == bool:
            return bool(value) if not isinstance(value, Exception) else bool(default_value)
    except (ValueError, TypeError, AttributeError):
        return default_value
    return default_value


def _sanitize_repository_health(repository_health: dict) -> dict:
    """Sanitize repository health data to prevent information disclosure."""
    return {
        "overall_status": _safe_extract_value(repository_health, "overall_status", "unknown", str),
        "healthy_count": _safe_extract_value(repository_health, "healthy_count", 0, int),
        "total_count": _safe_extract_value(repository_health, "total_count", 0, int),
        "health_percentage": _safe_extract_value(repository_health.get("summary", {}), "health_percentage", 0, float),
        "cache_hit": _safe_extract_value(repository_health, "cache_hit", False, bool),
    }


def _sanitize_metrics(metrics: dict) -> dict:
    """Remove any potential error details or stack traces from metrics."""
    safe_metrics = {}
    for k, v in metrics.items():
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
    return safe_metrics


def _sanitize_checks(all_checks: dict) -> dict:
    """Sanitize all_checks to ensure no exception objects leak through."""
    safe_all_checks = {}
    for check_name, check_result in all_checks.items():
        # Only include boolean results, convert everything to boolean
        safe_all_checks[str(check_name)[:20]] = bool(check_result) if not isinstance(check_result, Exception) else False
    return safe_all_checks


def _sanitize_health_result(health_result: Any) -> dict:
    """Sanitize entire health_result to prevent stack trace exposure."""
    if not isinstance(health_result, dict):
        return {"status": "error", "checks": {}, "metrics": {}}

    return {
        "status": _safe_extract_value(health_result, "status", "unknown", str),
        "checks": _sanitize_checks(health_result.get("checks", {})),
        "metrics": _sanitize_metrics(health_result.get("metrics", {})),
        "check_duration_seconds": _safe_extract_value(health_result, "check_duration_seconds", 0, float),
    }


@router.get("/health", status_code=status.HTTP_200_OK)
@track_health_check
async def health_check(health_service: HealthService = Depends(get_health_service)) -> Dict[str, Any]:
    """Return basic health check - always returns 200 if service is running."""
    # Get repository health for UAT compliance using health service
    try:
        db_health = await health_service.check_database_health()
        # Ensure db_health is sanitized - convert to safe boolean
        safe_db_status = bool(db_health) if not isinstance(db_health, Exception) else False
    except Exception:
        safe_db_status = False

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": str(settings.PROJECT_NAME)[:50] if settings.PROJECT_NAME else "unknown",
        "version": str(settings.VERSION)[:20] if settings.VERSION else "unknown",
        "environment": str(settings.ENVIRONMENT)[:20] if settings.ENVIRONMENT else "unknown",
        "database": safe_db_status,
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
    raw_health_result = await health_service.check_dependency_health()

    # Sanitize health result immediately to prevent stack trace exposure
    health_result = _sanitize_health_result(raw_health_result)

    # Check repository health with exception protection
    try:
        repository_health = await health_service.check_repository_health()
        # Ensure repository_health is a dictionary to prevent stack trace exposure
        if not isinstance(repository_health, dict) or not repository_health:
            repository_health = {
                "overall_status": "error",
                "healthy_count": 0,
                "total_count": 0,
                "summary": {"health_percentage": 0},
                "cache_hit": False,
            }
    except Exception as e:
        # Log safely without exposing stack trace
        logger.error("repository_health_check_failed", error=safe_error_message(e))
        repository_health = {
            "overall_status": "error",
            "healthy_count": 0,
            "total_count": 0,
            "summary": {"health_percentage": 0},
            "cache_hit": False,
        }

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

    # Sanitize repository health data using helper function first
    safe_repository_health = _sanitize_repository_health(repository_health)

    # Combine all checks using sanitized data only
    all_checks = {
        "database": bool(health_result.get("checks", {}).get("database", False)),
        "cache": bool(health_result.get("checks", {}).get("cache", False)),
        "repositories": safe_repository_health.get("overall_status") == "healthy",
        "disk_space": disk_healthy,
        "memory": memory_healthy,
    }

    # Apply additional sanitization to ensure no unsafe data
    safe_all_checks = _sanitize_checks(all_checks)
    all_healthy = all(safe_all_checks.values())

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        # Use sanitized data for logging
        failed_checks = [k for k, v in safe_all_checks.items() if not v]
        logger.warning("readiness_check_failed", failed_check_count=len(failed_checks))

    # Final sanitization pass to ensure no unsafe data is returned
    # CodeQL [py/stack-trace-exposure] All data sanitized to prevent information exposure
    return {
        "status": "ready" if all_healthy else "not ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": safe_all_checks,
        "details": {
            "failed_checks": [k for k, v in safe_all_checks.items() if not v],
            "service": str(settings.PROJECT_NAME)[:50] if settings.PROJECT_NAME else "unknown",
            "version": str(settings.VERSION)[:20] if settings.VERSION else "unknown",
            "repositories": safe_repository_health,
            "metrics": _sanitize_metrics(health_result.get("metrics", {})),  # Double sanitization
            "check_duration": _safe_extract_value(
                health_result, "check_duration_seconds", 0, float
            ),  # Double sanitization
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
