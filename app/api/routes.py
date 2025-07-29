"""API route configuration."""

from typing import Any, Dict

from fastapi import APIRouter

from .endpoints import (
    api_keys,
    audit_logs,
    auth,
    health,
    sessions,
    upload,
    users,
)

api_router = APIRouter()

# Include health endpoints
api_router.include_router(
    health.router,
    tags=["health"],
    responses={
        503: {"description": "Service unavailable"},
    },
)

# Include auth endpoints
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["authentication"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)

# Include CRUD endpoints with comprehensive error responses
crud_error_responses: Dict[int | str, Dict[str, Any]] = {
    400: {"description": "Bad request"},
    401: {"description": "Unauthorized"},
    403: {"description": "Forbidden"},
    404: {"description": "Not found"},
    409: {"description": "Conflict"},
    422: {"description": "Validation error"},
    500: {"description": "Internal server error"},
}

# Include Users CRUD endpoints
api_router.include_router(
    users.router,
    tags=["Users"],
    responses=crud_error_responses,
)

# Include API Keys CRUD endpoints
api_router.include_router(
    api_keys.router,
    tags=["API Keys"],
    responses=crud_error_responses,
)

# Include Sessions CRUD endpoints
api_router.include_router(
    sessions.router,
    tags=["Sessions"],
    responses=crud_error_responses,
)

# Include Audit Logs read-only endpoints
api_router.include_router(
    audit_logs.router,
    tags=["Audit Logs"],
    responses=crud_error_responses,
)

# Include Upload endpoints
api_router.include_router(
    upload.router,
    tags=["Upload"],
    responses={
        400: {"description": "Bad request"},
        413: {"description": "Request entity too large"},
        422: {"description": "Validation error"},
    },
)
