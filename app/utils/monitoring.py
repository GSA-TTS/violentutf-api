"""Monitoring and tracking utilities for health checks and performance."""

import asyncio
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

from prometheus_client import Counter, Histogram
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)

# Prometheus metrics for health checks
health_check_total = Counter(
    "health_check_total",
    "Total number of health checks performed",
    ["endpoint", "status"],
)

health_check_duration = Histogram("health_check_duration_seconds", "Time spent on health checks", ["endpoint"])

# Application performance metrics
request_duration = Histogram(
    "request_duration_seconds",
    "Time spent processing requests",
    ["method", "endpoint", "status"],
)

# Enhanced database query tracking metrics
database_query_total = Counter(
    "database_query_total",
    "Total number of database queries executed",
    ["query_type", "repository", "model", "status"],
)

database_query_duration_histogram = Histogram(
    "database_query_duration_histogram",
    "Distribution of database query execution times",
    ["query_type", "repository", "model"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

database_slow_query_total = Counter(
    "database_slow_query_total",
    "Total number of slow database queries (>500ms)",
    ["repository", "model", "operation"],
)

database_connection_pool_current = Histogram(
    "database_connection_pool_current",
    "Current database connection pool usage",
    ["pool_name"],
)

database_transaction_duration = Histogram(
    "database_transaction_duration_seconds",
    "Time spent in database transactions",
    ["repository", "operation_type"],
)

database_deadlock_total = Counter(
    "database_deadlock_total",
    "Total number of database deadlocks detected",
    ["repository", "model"],
)

database_cache_hit_rate = Histogram(
    "database_cache_hit_rate",
    "Database query cache hit rate",
    ["cache_type", "repository"],
)

# Resource usage tracking
resource_usage = {
    "database_connections": 0,
    "cache_connections": 0,
    "active_requests": 0,
    "database_pool_size": 0,
    "database_pool_checkedout": 0,
    "database_pool_overflow": 0,
}

# Health check cache: key -> (timestamp, result)
health_check_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


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
                "health_check_completed",
                endpoint=endpoint_name,
                status=status,
                duration=time.time() - start_time,
            )

            return result

        except Exception as e:
            status = "error"
            logger.error(
                "health_check_failed",
                endpoint=endpoint_name,
                error=str(e),
                duration=time.time() - start_time,
            )
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
            logger.error(
                "request_performance_error",
                method=method,
                endpoint=endpoint,
                error=str(e),
            )
            raise
        finally:
            # Record request duration
            duration = time.time() - start_time
            request_duration.labels(method=method, endpoint=endpoint, status=status).observe(duration)

            # Update active requests
            resource_usage["active_requests"] -= 1

            logger.debug(
                "request_performance",
                method=method,
                endpoint=endpoint,
                status=status,
                duration=duration,
            )

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
        logger.error("Failed to get system metrics", error=str(e), exception_type=type(e).__name__)
        return {
            "timestamp": time.time(),
            "metrics_error": True,
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
        logger.debug(
            "Connection count incremented",
            type=connection_type,
            count=resource_usage[key],
        )


def decrement_connection_count(connection_type: str) -> None:
    """
    Decrement connection counter for monitoring.

    Args:
        connection_type: Type of connection ('database', 'cache')
    """
    key = f"{connection_type}_connections"
    if key in resource_usage and resource_usage[key] > 0:
        resource_usage[key] -= 1
        logger.debug(
            "Connection count decremented",
            type=connection_type,
            count=resource_usage[key],
        )


async def check_dependency_health(cache_ttl: int = 10) -> Dict[str, Any]:
    """
    Check health of all dependencies with detailed metrics.

    Args:
        cache_ttl: Cache time-to-live in seconds (default: 10)

    Returns:
        Dictionary with dependency health status
    """
    from ..db.session import check_database_health
    from .cache import check_cache_health

    # Check cache first
    cache_key = "dependency_health"
    cached_result = get_cached_health_check(cache_key, cache_ttl)
    if cached_result is not None:
        logger.debug("Using cached health check result", cache_key=cache_key)
        return cached_result

    start_time = time.time()

    # Run all health checks in parallel
    try:
        db_healthy, cache_healthy, metrics = await asyncio.gather(
            check_database_health(),
            check_cache_health(),
            get_system_metrics(),
            return_exceptions=True,
        )

        # Handle exceptions
        if isinstance(db_healthy, Exception):
            logger.error("Database health check exception", error=str(db_healthy))
            db_healthy = False

        if isinstance(cache_healthy, Exception):
            logger.error("Cache health check exception", error=str(cache_healthy))
            cache_healthy = False

        if isinstance(metrics, Exception):
            logger.error("System metrics exception", error=str(metrics), exception_type=type(metrics).__name__)
            metrics = {"metrics_error": True}

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
            "dependency_health_check_complete",
            overall_healthy=result["overall_healthy"],
            duration=total_duration,
        )

        # Cache the result
        cache_health_check_result(cache_key, result)

        return result

    except Exception as e:
        logger.error("Dependency health check failed", error=str(e), exception_type=type(e).__name__, stack_info=True)
        return {
            "overall_healthy": False,
            "metrics_error": True,
            "check_duration_seconds": time.time() - start_time,
        }


def get_cached_health_check(cache_key: str, ttl: int) -> Optional[Dict[str, Any]]:
    """
    Get cached health check result if still valid.

    Args:
        cache_key: Cache key
        ttl: Time-to-live in seconds

    Returns:
        Cached result or None if expired/not found
    """
    if cache_key in health_check_cache:
        timestamp, result = health_check_cache[cache_key]
        if time.time() - timestamp < ttl:
            return result
        else:
            # Remove expired entry
            del health_check_cache[cache_key]
    return None


def cache_health_check_result(cache_key: str, result: Dict[str, Any]) -> None:
    """
    Cache health check result.

    Args:
        cache_key: Cache key
        result: Result to cache
    """
    health_check_cache[cache_key] = (time.time(), result)
    logger.debug("Cached health check result", cache_key=cache_key)


def clear_health_check_cache() -> None:
    """Clear all cached health check results."""
    health_check_cache.clear()
    logger.info("Health check cache cleared")


def track_database_query(
    query_type: str,
    repository: str,
    model: str,
    duration: float,
    success: bool = True,
    operation: str = "unknown",
) -> None:
    """
    Track database query performance metrics.

    Args:
        query_type: Type of query (read, write, delete)
        repository: Repository name
        model: Model name
        duration: Query execution duration in seconds
        success: Whether the query was successful
        operation: Specific operation name
    """
    status = "success" if success else "error"

    # Record query execution
    database_query_total.labels(
        query_type=query_type,
        repository=repository,
        model=model,
        status=status,
    ).inc()

    # Record query duration
    database_query_duration_histogram.labels(
        query_type=query_type,
        repository=repository,
        model=model,
    ).observe(duration)

    # Track slow queries (>500ms)
    if duration > 0.5:
        database_slow_query_total.labels(
            repository=repository,
            model=model,
            operation=operation,
        ).inc()

        logger.warning(
            "Slow database query detected",
            query_type=query_type,
            repository=repository,
            model=model,
            duration=duration,
            operation=operation,
        )


def update_database_connection_pool_metrics(
    pool_name: str,
    pool_size: int,
    checked_out: int,
    overflow: int,
) -> None:
    """
    Update database connection pool metrics.

    Args:
        pool_name: Name of the connection pool
        pool_size: Current pool size
        checked_out: Number of checked out connections
        overflow: Number of overflow connections
    """
    database_connection_pool_current.labels(pool_name=pool_name).observe(checked_out)

    # Update resource usage tracking
    resource_usage["database_pool_size"] = pool_size
    resource_usage["database_pool_checkedout"] = checked_out
    resource_usage["database_pool_overflow"] = overflow


def track_database_transaction(
    repository: str,
    operation_type: str,
    duration: float,
) -> None:
    """
    Track database transaction performance.

    Args:
        repository: Repository name
        operation_type: Type of transaction operation
        duration: Transaction duration in seconds
    """
    database_transaction_duration.labels(
        repository=repository,
        operation_type=operation_type,
    ).observe(duration)


def track_database_deadlock(repository: str, model: str) -> None:
    """
    Track database deadlock occurrences.

    Args:
        repository: Repository name where deadlock occurred
        model: Model involved in deadlock
    """
    database_deadlock_total.labels(
        repository=repository,
        model=model,
    ).inc()

    logger.error(
        "Database deadlock detected",
        repository=repository,
        model=model,
    )


def track_database_cache_performance(
    cache_type: str,
    repository: str,
    hit_rate: float,
) -> None:
    """
    Track database cache performance metrics.

    Args:
        cache_type: Type of cache (query, entity, etc.)
        repository: Repository name
        hit_rate: Cache hit rate (0.0 to 1.0)
    """
    database_cache_hit_rate.labels(
        cache_type=cache_type,
        repository=repository,
    ).observe(hit_rate)


async def get_enhanced_system_metrics() -> Dict[str, Any]:
    """
    Get enhanced system performance metrics including database-specific metrics.

    Returns:
        Dictionary with comprehensive system and database metrics
    """
    try:
        import psutil

        # Get basic system metrics
        base_metrics = await get_system_metrics()

        # Add database-specific metrics
        database_metrics = {
            "database_pool_size": resource_usage.get("database_pool_size", 0),
            "database_pool_checkedout": resource_usage.get("database_pool_checkedout", 0),
            "database_pool_overflow": resource_usage.get("database_pool_overflow", 0),
            "database_pool_utilization": (
                resource_usage.get("database_pool_checkedout", 0) / max(resource_usage.get("database_pool_size", 1), 1)
            ),
        }

        # Combine metrics
        enhanced_metrics = {
            **base_metrics,
            "database": database_metrics,
        }

        return enhanced_metrics

    except Exception as e:
        logger.error("Failed to get enhanced system metrics", error=str(e), exception_type=type(e).__name__)
        return await get_system_metrics()  # Fallback to basic metrics


def get_database_performance_summary() -> Dict[str, Any]:
    """
    Get summary of database performance metrics.

    Returns:
        Dictionary with database performance summary
    """
    return {
        "connection_pool": {
            "size": resource_usage.get("database_pool_size", 0),
            "checked_out": resource_usage.get("database_pool_checkedout", 0),
            "overflow": resource_usage.get("database_pool_overflow", 0),
            "utilization": (
                resource_usage.get("database_pool_checkedout", 0) / max(resource_usage.get("database_pool_size", 1), 1)
            ),
        },
        "active_connections": resource_usage.get("database_connections", 0),
        "cache_connections": resource_usage.get("cache_connections", 0),
    }
