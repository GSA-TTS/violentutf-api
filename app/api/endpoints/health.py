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


def _sanitize_checks(all_checks: Any) -> dict:
    """Sanitize all_checks to ensure no exception objects leak through."""
    # First, ensure the input itself is a safe dictionary
    if not isinstance(all_checks, dict):
        return {}

    # Complete isolation: Don't process any dict that could contain exceptions
    # Use try-catch to prevent any exception data from flowing through
    try:
        # Pre-screen for dangerous objects without directly accessing them
        for key, value in all_checks.items():
            # Only allow primitive types and basic containers
            if not isinstance(value, (bool, int, float, str, type(None))):
                return {}  # Reject any complex objects including exceptions
    except Exception:
        # If any error occurs during screening, reject entirely
        return {}

    safe_all_checks = {}

    # Iterate over items safely with complete exception isolation
    for check_name, check_result in all_checks.items():
        # Convert check name to safe string without any exception exposure
        if isinstance(check_name, str):
            safe_name = check_name[:20]
        elif isinstance(check_name, (int, float, bool)):
            safe_name = str(check_name)[:20]
        else:
            # For any complex objects (including exceptions), use generic name
            safe_name = "check"

        # Determine safe boolean value with complete isolation from exceptions
        if check_result is True:
            safe_value = True
        elif check_result is False:
            safe_value = False
        elif isinstance(check_result, int) and not isinstance(check_result, bool):
            safe_value = check_result != 0
        elif isinstance(check_result, float):
            safe_value = check_result != 0.0
        elif isinstance(check_result, str):
            safe_value = len(check_result) > 0
        else:
            # For any complex objects (including exceptions), default to False
            # This completely isolates exception objects from any data flow
            safe_value = False

        safe_all_checks[safe_name] = safe_value

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
async def health_check(
    health_service: HealthService = Depends(get_health_service),
) -> Dict[str, Any]:
    """Return basic health check - always returns 200 if service is running."""
    # Get repository health for UAT compliance using health service
    try:
        db_health = await health_service.check_database_health()
        # Ensure db_health is sanitized - convert to safe boolean
        safe_db_status = db_health.get("status") == "healthy" if db_health else False
    except Exception:
        safe_db_status = False

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": (str(settings.PROJECT_NAME)[:50] if settings.PROJECT_NAME else "unknown"),
        "version": str(settings.VERSION)[:20] if settings.VERSION else "unknown",
        "environment": (str(settings.ENVIRONMENT)[:20] if settings.ENVIRONMENT else "unknown"),
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
    # CodeQL [py/stack-trace-exposure] Raw health data sanitized here - all subsequent usage is safe
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

    # Process system check results with complete isolation from exceptions
    def extract_safe_boolean_result(check_result: Any) -> bool:
        """Extract safe boolean from check result, completely isolated from exceptions."""
        if check_result is True:
            return True
        elif check_result is False:
            return False
        else:
            return False  # Any non-boolean (including exceptions) becomes False

    disk_healthy = extract_safe_boolean_result(system_checks[0])
    memory_healthy = extract_safe_boolean_result(system_checks[1])

    # Log exceptions securely without exposing to client
    if isinstance(system_checks[0], Exception):
        logger.error("disk_space_check_exception", error_type=type(system_checks[0]).__name__)
    if isinstance(system_checks[1], Exception):
        logger.error("memory_check_exception", error_type=type(system_checks[1]).__name__)

    # Build safe response data using only primitive values - no data flow from exceptions
    safe_db_status = bool(health_result.get("checks", {}).get("database", False))
    safe_cache_status = bool(health_result.get("checks", {}).get("cache", False))
    safe_repo_status = bool(_sanitize_repository_health(repository_health).get("overall_status") == "healthy")

    # Construct final response with only safe primitive values
    safe_all_checks = {
        "database": safe_db_status,
        "cache": safe_cache_status,
        "repositories": safe_repo_status,
        "disk_space": disk_healthy,
        "memory": memory_healthy,
    }
    all_healthy = all(safe_all_checks.values())

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        # Count failed checks without exposing their names
        failed_count = len([k for k, v in safe_all_checks.items() if not v])
        logger.warning("readiness_check_failed", failed_check_count=failed_count)

    # Build safe response with completely isolated data - no potential for exception exposure
    safe_failed_checks = []
    for check_name, check_result in safe_all_checks.items():
        if not check_result:
            # Only include safe string check names
            safe_failed_checks.append(str(check_name)[:20])

    # Extract safe repository data
    safe_repository_data = _sanitize_repository_health(repository_health)

    # Extract safe metrics with additional isolation
    safe_metrics = {}
    raw_metrics = health_result.get("metrics", {}) if isinstance(health_result, dict) else {}
    for key, value in raw_metrics.items():
        if isinstance(value, (int, float, bool, str)) and not isinstance(key, Exception):
            safe_key = str(key)[:20]
            if isinstance(value, str):
                safe_metrics[safe_key] = str(value)[:50]
            else:
                safe_metrics[safe_key] = value

    # Build final response with only safe primitive data
    return {
        "status": "ready" if all_healthy else "not ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": safe_all_checks,
        "details": {
            "failed_checks": safe_failed_checks,
            "service": (str(settings.PROJECT_NAME)[:50] if settings.PROJECT_NAME else "unknown"),
            "version": str(settings.VERSION)[:20] if settings.VERSION else "unknown",
            "repositories": safe_repository_data,
            "metrics": safe_metrics,
            "check_duration": _safe_extract_value(health_result, "check_duration_seconds", 0, float),
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


@router.get("/performance/metrics")
@rate_limit("health_check")  # 120 requests per minute
async def get_performance_metrics(
    time_window: int = 3600,  # 1 hour default
    include_history: bool = False,
    health_service: HealthService = Depends(get_health_service),
) -> Dict[str, Any]:
    """
    Get real-time performance metrics for database operations.

    Args:
        time_window: Time window in seconds for metrics aggregation
        include_history: Whether to include detailed operation history
        health_service: Health service dependency

    Returns:
        Real-time performance metrics
    """
    try:
        from ...utils.monitoring import get_database_performance_summary, get_enhanced_system_metrics
        from ...utils.performance_tracker import get_global_performance_tracker

        logger.info("Fetching performance metrics", time_window=time_window)

        # Get performance tracker data
        performance_tracker = get_global_performance_tracker()
        performance_report = performance_tracker.get_performance_report(include_history=include_history)

        # Get enhanced system metrics
        system_metrics = await get_enhanced_system_metrics()

        # Get database performance summary
        db_summary = get_database_performance_summary()

        # Get recent performance data within time window
        recent_operations = {}
        for operation_name in performance_tracker._history.keys():
            recent_history = performance_tracker.get_operation_history(operation_name, limit=100)
            if recent_history:
                # Filter by time window
                import time

                cutoff_time = time.time() - time_window
                recent_ops = [op for op in recent_history if op.start_time > cutoff_time]

                if recent_ops:
                    durations = [op.duration for op in recent_ops]
                    recent_operations[operation_name] = {
                        "operation_count": len(recent_ops),
                        "average_duration": sum(durations) / len(durations),
                        "max_duration": max(durations),
                        "min_duration": min(durations),
                        "success_rate": len([op for op in recent_ops if "error" not in op.metadata.get("status", "")])
                        / len(recent_ops),
                    }

        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "time_window_seconds": time_window,
            "system_metrics": system_metrics,
            "database_summary": db_summary,
            "recent_operations": recent_operations,
            "performance_summary": {
                "total_operations_tracked": len(performance_tracker._history),
                "total_executions": sum(len(history) for history in performance_tracker._history.values()),
                "active_operations": len([op for ops in performance_tracker._history.values() for op in ops]),
            },
            "overall_performance": performance_report if include_history else None,
        }

        logger.info("Performance metrics retrieved successfully", operations_count=len(recent_operations))
        return metrics

    except Exception as e:
        logger.error("Failed to get performance metrics", error=safe_error_message(str(e)))
        return {
            "error": "Failed to retrieve performance metrics",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "time_window_seconds": time_window,
        }


@router.get("/performance/dashboard")
@rate_limit("health_check")  # 120 requests per minute
async def get_performance_dashboard_data(health_service: HealthService = Depends(get_health_service)) -> Dict[str, Any]:
    """
    Get performance dashboard data optimized for real-time visualization.

    Args:
        health_service: Health service dependency

    Returns:
        Performance dashboard data
    """
    try:
        from ...utils.monitoring import get_enhanced_system_metrics
        from ...utils.performance_tracker import get_global_performance_tracker

        logger.info("Fetching performance dashboard data")

        performance_tracker = get_global_performance_tracker()
        system_metrics = await get_enhanced_system_metrics()

        # Get aggregated metrics for each operation type
        operation_summaries = {}
        for operation_name in performance_tracker._history.keys():
            aggregated = performance_tracker.get_aggregated_metrics(operation_name)
            if aggregated:
                operation_summaries[operation_name] = {
                    "total_executions": aggregated.total_executions,
                    "average_duration": round(aggregated.average_duration, 3),
                    "p95_duration": round(aggregated.p95_duration, 3),
                    "success_rate": round(aggregated.success_rate, 3),
                    "error_count": aggregated.error_count,
                }

        # Get performance regressions
        regressions = []
        for operation_name in performance_tracker._history.keys():
            regression = performance_tracker.detect_performance_regression(operation_name)
            if regression:
                regressions.append(regression)

        # Calculate overall health score
        overall_health_score = 1.0
        if operation_summaries:
            avg_success_rate = sum(op["success_rate"] for op in operation_summaries.values()) / len(operation_summaries)
            overall_health_score = avg_success_rate

        dashboard_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "health_score": round(overall_health_score, 3),
            "system_overview": {
                "cpu_usage": system_metrics.get("system", {}).get("cpu_percent", 0),
                "memory_usage": system_metrics.get("system", {}).get("memory_percent", 0),
                "database_connections": system_metrics.get("database", {}).get("database_pool_checkedout", 0),
                "database_pool_utilization": system_metrics.get("database", {}).get("database_pool_utilization", 0),
            },
            "operation_summaries": operation_summaries,
            "performance_alerts": {
                "regressions_count": len(regressions),
                "regressions": regressions[:5],  # Top 5 regressions
                "slow_operations": [
                    name
                    for name, summary in operation_summaries.items()
                    if summary["average_duration"] > 1.0  # > 1 second
                ],
            },
            "trends": {
                "total_operations": len(operation_summaries),
                "total_executions": sum(op["total_executions"] for op in operation_summaries.values()),
                "avg_response_time": (
                    round(
                        sum(op["average_duration"] for op in operation_summaries.values()) / len(operation_summaries), 3
                    )
                    if operation_summaries
                    else 0
                ),
            },
        }

        logger.info("Performance dashboard data retrieved successfully")
        return dashboard_data

    except Exception as e:
        logger.error("Failed to get performance dashboard data", error=safe_error_message(str(e)))
        return {
            "error": "Failed to retrieve performance dashboard data",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@router.get("/performance/alerts")
@rate_limit("health_check")  # 120 requests per minute
async def get_performance_alerts(
    severity: str = "all",  # all, high, medium, low
    limit: int = 50,
    health_service: HealthService = Depends(get_health_service),
) -> Dict[str, Any]:
    """
    Get performance alerts and threshold violations.

    Args:
        severity: Alert severity filter
        limit: Maximum number of alerts to return
        health_service: Health service dependency

    Returns:
        Performance alerts
    """
    try:
        from ...utils.performance_tracker import get_global_performance_tracker

        logger.info("Fetching performance alerts", severity=severity, limit=limit)

        performance_tracker = get_global_performance_tracker()
        alerts = []

        # Check for performance regressions
        for operation_name in performance_tracker._history.keys():
            regression = performance_tracker.detect_performance_regression(operation_name)
            if regression:
                alert_severity = "high" if regression["regression_factor"] > 0.5 else "medium"

                if severity == "all" or severity == alert_severity:
                    alerts.append(
                        {
                            "type": "performance_regression",
                            "severity": alert_severity,
                            "operation": operation_name,
                            "message": f"Performance regression detected: {regression['regression_percentage']:.1f}% slower than baseline",
                            "details": regression,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )

        # Check for slow operations
        for operation_name in performance_tracker._history.keys():
            aggregated = performance_tracker.get_aggregated_metrics(operation_name)
            if aggregated and aggregated.average_duration > 1.0:  # > 1 second
                alert_severity = "high" if aggregated.average_duration > 5.0 else "medium"

                if severity == "all" or severity == alert_severity:
                    alerts.append(
                        {
                            "type": "slow_operation",
                            "severity": alert_severity,
                            "operation": operation_name,
                            "message": f"Slow operation detected: {aggregated.average_duration:.3f}s average duration",
                            "details": {
                                "average_duration": aggregated.average_duration,
                                "p95_duration": aggregated.p95_duration,
                                "total_executions": aggregated.total_executions,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )

        # Check for high error rates
        for operation_name in performance_tracker._history.keys():
            aggregated = performance_tracker.get_aggregated_metrics(operation_name)
            if aggregated and aggregated.success_rate < 0.95:  # < 95% success rate
                alert_severity = "high" if aggregated.success_rate < 0.9 else "medium"

                if severity == "all" or severity == alert_severity:
                    alerts.append(
                        {
                            "type": "high_error_rate",
                            "severity": alert_severity,
                            "operation": operation_name,
                            "message": f"High error rate detected: {(1 - aggregated.success_rate) * 100:.1f}% failure rate",
                            "details": {
                                "success_rate": aggregated.success_rate,
                                "error_count": aggregated.error_count,
                                "total_executions": aggregated.total_executions,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )

        # Sort by severity and timestamp
        severity_order = {"high": 0, "medium": 1, "low": 2}
        alerts.sort(key=lambda x: (severity_order.get(str(x["severity"]), 3), x["timestamp"]), reverse=True)

        # Limit results
        alerts = alerts[:limit]

        alert_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(alerts),
            "severity_breakdown": {
                "high": len([a for a in alerts if a["severity"] == "high"]),
                "medium": len([a for a in alerts if a["severity"] == "medium"]),
                "low": len([a for a in alerts if a["severity"] == "low"]),
            },
            "alerts": alerts,
            "filter": {
                "severity": severity,
                "limit": limit,
            },
        }

        logger.info("Performance alerts retrieved successfully", total_alerts=len(alerts))
        return alert_summary

    except Exception as e:
        logger.error("Failed to get performance alerts", error=safe_error_message(str(e)))
        return {
            "error": "Failed to retrieve performance alerts",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
