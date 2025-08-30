"""Health check endpoints for authentication services."""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from structlog.stdlib import get_logger

from app.api.deps import get_health_service
from app.core.auth import get_current_user_data
from app.core.auth_failover import get_fallback_auth_provider
from app.core.permissions import require_permission
from app.models.user import User
from app.schemas.base import BaseResponse

logger = get_logger(__name__)

router = APIRouter(prefix="/auth/health", tags=["auth-health"])


def _sanitize_health_data(health_data: Any) -> Dict[str, Any]:
    """Sanitize health data to prevent information exposure."""
    if not isinstance(health_data, dict):
        return {"status": "error", "message": "Invalid health data format"}

    # Safe extraction with bounds checking
    def safe_extract(data: dict, key: str, default: Any, value_type: type) -> Any:
        try:
            value = data.get(key, default)
            if isinstance(value, Exception) or hasattr(value, "__traceback__"):
                return default
            if value_type == str:
                return str(value)[:100] if value is not None else str(default)[:100]
            elif value_type in (int, float):
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return value_type(max(0, min(value, 1000000)))
                return value_type(default)
            elif value_type == bool:
                return bool(value) if not isinstance(value, Exception) else bool(default)
            return default
        except (ValueError, TypeError, AttributeError):
            return default

    return {
        "status": safe_extract(health_data, "status", "unknown", str),
        "message": safe_extract(health_data, "message", "Health check completed", str),
        "healthy": safe_extract(health_data, "healthy", False, bool),
        "timestamp": safe_extract(health_data, "timestamp", "", str),
        # Filter out any other potentially unsafe keys
    }


@router.get("/", response_model=BaseResponse[Dict])
async def get_auth_health(
    current_user: User = Depends(require_permission("system.health.read")),
) -> BaseResponse[Dict]:
    """
    Get comprehensive health status of authentication services.

    Requires permission: system.health.read
    """
    try:
        health_service = get_health_service()
        raw_health_data = await health_service.check_all()

        # CodeQL [py/stack-trace-exposure] Health data sanitized to prevent information exposure
        health_data = _sanitize_health_data(raw_health_data)
        return BaseResponse(
            status="success",
            message=f"Auth health status: {health_data['status']}",
            data=health_data,
        )
    except Exception as e:
        logger.error("Failed to get auth health", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve health status",
        )


@router.get("/components/{component}", response_model=BaseResponse[Dict])
async def get_component_health(
    component: str,
    current_user: User = Depends(require_permission("system.health.read")),
) -> BaseResponse[Dict]:
    """
    Get health status of specific authentication component.

    Components: database, cache, auth_services, circuit_breakers

    Requires permission: system.health.read
    """
    try:
        health_service = get_health_service()

        if component == "database":
            raw_health_data = await health_service.check_database()
        elif component == "cache":
            raw_health_data = await health_service.check_cache()
        elif component == "auth_services":
            raw_health_data = await health_service.check_auth_services()
        elif component == "circuit_breakers":
            raw_health_data = await health_service.check_circuit_breakers()
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown component: {component}",
            )

        # CodeQL [py/stack-trace-exposure] Component health data sanitized to prevent information exposure
        health_data = _sanitize_health_data(raw_health_data)
        return BaseResponse(
            status="success",
            message=f"{component} health status: {health_data.get('status', 'unknown')}",
            data=health_data,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get {component} health", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve {component} health status",
        )


@router.get("/metrics", response_model=BaseResponse[Dict])
async def get_auth_metrics(
    current_user: User = Depends(require_permission("system.metrics.read")),
) -> BaseResponse[Dict]:
    """
    Get authentication metrics.

    Requires permission: system.metrics.read
    """
    try:
        health_service = get_health_service()
        raw_metrics = await health_service.get_auth_metrics()

        # CodeQL [py/stack-trace-exposure] Metrics data sanitized to prevent information exposure
        metrics = _sanitize_health_data(raw_metrics)
        return BaseResponse(status="success", message="Authentication metrics retrieved", data=metrics)
    except Exception as e:
        logger.error("Failed to get auth metrics", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics",
        )


@router.get("/degraded-mode", response_model=BaseResponse[Dict])
async def get_degraded_mode_status(
    current_user: User = Depends(require_permission("system.health.read")),
) -> BaseResponse[Dict]:
    """
    Get degraded mode status and fallback authentication info.

    Requires permission: system.health.read
    """
    try:
        fallback_provider = get_fallback_auth_provider()
        raw_degraded_info = await fallback_provider.get_degraded_mode_info()

        # CodeQL [py/stack-trace-exposure] Degraded mode data sanitized to prevent information exposure
        degraded_info = _sanitize_health_data(raw_degraded_info)
        return BaseResponse(
            status="success",
            message="Degraded mode status retrieved",
            data=degraded_info,
        )
    except Exception as e:
        logger.error("Failed to get degraded mode status", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve degraded mode status",
        )
