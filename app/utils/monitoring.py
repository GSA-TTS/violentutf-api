"""Monitoring and tracking utilities for health checks and performance."""

import asyncio
import time
from functools import wraps
from typing import Any, Callable, Dict

from prometheus_client import Counter, Histogram
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)

# Prometheus metrics for health checks
health_check_total = Counter("health_check_total", "Total number of health checks performed", ["endpoint", "status"])

health_check_duration = Histogram("health_check_duration_seconds", "Time spent on health checks", ["endpoint"])

# Application performance metrics
request_duration = Histogram(
    "request_duration_seconds", "Time spent processing requests", ["method", "endpoint", "status"]
)

# Resource usage tracking
resource_usage = {
    "database_connections": 0,
    "cache_connections": 0,
    "active_requests": 0,
}


def track_health_check(func: Callable[..., object]) -> Callable[..., object]:
    """
    Track health check performance and outcomes.

    Usage:
        @track_health_check
        async def health_check():
            return {"status": "healthy"}
    """

    @wraps(func)
    async def wrapper(*args: object, **kwargs: object) -> object:
        endpoint_name = func.__name__
        start_time = time.time()
        status = "success"

        try:
            # Execute the health check
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Determine status from result
            if isinstance(result, dict):
                if result.get("status") == "healthy" or result.get("status") == "ready":
                    status = "success"
                else:
                    status = "failure"

            logger.info(
                "health_check_completed", endpoint=endpoint_name, status=status, duration=time.time() - start_time
            )

            return result

        except Exception as e:
            status = "error"
            logger.error("health_check_failed", endpoint=endpoint_name, error=str(e), duration=time.time() - start_time)
            raise
        finally:
            # Record metrics
            health_check_total.labels(endpoint=endpoint_name, status=status).inc()
            health_check_duration.labels(endpoint=endpoint_name).observe(time.time() - start_time)

    return wrapper


def track_request_performance(func: Callable[..., object]) -> Callable[..., object]:
    """
    Track request performance metrics.

    Usage:
        @track_request_performance
        async def api_endpoint():
            return {"data": "response"}
    """

    @wraps(func)
    async def wrapper(*args: object, **kwargs: object) -> object:
        start_time = time.time()
        method = getattr(args[0], "method", "UNKNOWN") if args else "UNKNOWN"
        endpoint = func.__name__
        status = "success"

        # Track active requests
        resource_usage["active_requests"] += 1

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            return result
        except Exception as e:
            status = "error"
            logger.error("request_performance_error", method=method, endpoint=endpoint, error=str(e))
            raise
        finally:
            # Record request duration
            duration = time.time() - start_time
            request_duration.labels(method=method, endpoint=endpoint, status=status).observe(duration)

            # Update active requests
            resource_usage["active_requests"] -= 1

            logger.debug("request_performance", method=method, endpoint=endpoint, status=status, duration=duration)

    return wrapper


async def get_system_metrics() -> Dict[str, Any]:
    """
    Get current system performance metrics.

    Returns:
        Dictionary with system metrics
    """
    try:
        import psutil

        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Get application metrics
        app_metrics = {
            "active_requests": resource_usage["active_requests"],
            "database_connections": resource_usage["database_connections"],
            "cache_connections": resource_usage["cache_connections"],
        }

        return {
            "timestamp": time.time(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": (disk.used / disk.total) * 100,
                "disk_free_gb": round(disk.free / (1024**3), 2),
            },
            "application": app_metrics,
        }

    except Exception as e:
        logger.error("Failed to get system metrics", error=str(e))
        return {
            "timestamp": time.time(),
            "error": str(e),
            "application": resource_usage.copy(),
        }


def increment_connection_count(connection_type: str) -> None:
    """
    Increment connection counter for monitoring.

    Args:
        connection_type: Type of connection ('database', 'cache')
    """
    key = f"{connection_type}_connections"
    if key in resource_usage:
        resource_usage[key] += 1
        logger.debug("Connection count incremented", type=connection_type, count=resource_usage[key])


def decrement_connection_count(connection_type: str) -> None:
    """
    Decrement connection counter for monitoring.

    Args:
        connection_type: Type of connection ('database', 'cache')
    """
    key = f"{connection_type}_connections"
    if key in resource_usage and resource_usage[key] > 0:
        resource_usage[key] -= 1
        logger.debug("Connection count decremented", type=connection_type, count=resource_usage[key])


async def check_dependency_health() -> Dict[str, Any]:
    """
    Check health of all dependencies with detailed metrics.

    Returns:
        Dictionary with dependency health status
    """
    from ..db.session import check_database_health
    from .cache import check_cache_health

    start_time = time.time()

    # Run all health checks in parallel
    try:
        db_healthy, cache_healthy, metrics = await asyncio.gather(
            check_database_health(), check_cache_health(), get_system_metrics(), return_exceptions=True
        )

        # Handle exceptions
        if isinstance(db_healthy, Exception):
            logger.error("Database health check exception", error=str(db_healthy))
            db_healthy = False

        if isinstance(cache_healthy, Exception):
            logger.error("Cache health check exception", error=str(cache_healthy))
            cache_healthy = False

        if isinstance(metrics, Exception):
            logger.error("System metrics exception", error=str(metrics))
            metrics = {"error": str(metrics)}

        total_duration = time.time() - start_time

        result = {
            "overall_healthy": db_healthy and cache_healthy,
            "checks": {
                "database": db_healthy,
                "cache": cache_healthy,
            },
            "metrics": metrics,
            "check_duration_seconds": round(total_duration, 3),
        }

        logger.info(
            "dependency_health_check_complete", overall_healthy=result["overall_healthy"], duration=total_duration
        )

        return result

    except Exception as e:
        logger.error("Dependency health check failed", error=str(e))
        return {
            "overall_healthy": False,
            "error": str(e),
            "check_duration_seconds": time.time() - start_time,
        }
