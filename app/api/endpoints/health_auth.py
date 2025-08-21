"""Health check endpoints for authentication services."""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from structlog.stdlib import get_logger

from app.core.auth import get_current_user_data
from app.core.auth_failover import get_fallback_auth_provider
from app.core.permissions import require_permission
from app.models.user import User
from app.schemas.base import BaseResponse
from app.services.health_service import get_health_service

logger = get_logger(__name__)

router = APIRouter(prefix="/auth/health", tags=["auth-health"])


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
        health_data = await health_service.check_all()

        return BaseResponse(status="success", message=f"Auth health status: {health_data['status']}", data=health_data)
    except Exception as e:
        logger.error("Failed to get auth health", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve health status"
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
            health_data = await health_service.check_database()
        elif component == "cache":
            health_data = await health_service.check_cache()
        elif component == "auth_services":
            health_data = await health_service.check_auth_services()
        elif component == "circuit_breakers":
            health_data = await health_service.check_circuit_breakers()
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown component: {component}")

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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve {component} health status"
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
        metrics = await health_service.get_auth_metrics()

        return BaseResponse(status="success", message="Authentication metrics retrieved", data=metrics)
    except Exception as e:
        logger.error("Failed to get auth metrics", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve metrics")


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
        degraded_info = await fallback_provider.get_degraded_mode_info()

        return BaseResponse(status="success", message="Degraded mode status retrieved", data=degraded_info)
    except Exception as e:
        logger.error("Failed to get degraded mode status", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve degraded mode status"
        )
