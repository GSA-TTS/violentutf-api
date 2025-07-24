"""API route configuration."""

from fastapi import APIRouter

from .endpoints import auth, health

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
