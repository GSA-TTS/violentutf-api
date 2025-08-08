"""API route configuration."""

from typing import Any, Dict

from fastapi import APIRouter

from .endpoints import (
    api_keys,
    audit_logs,
    auth,
    health,
    health_auth,
    mfa,
    mfa_policies,
    oauth,
    owasp_llm_classification,
    plugins,
    reports,
    scans,
    security_scans,
    sessions,
    tasks,
    templates,
    upload,
    users,
    vulnerability_findings,
    vulnerability_taxonomies,
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

# Include OAuth2 endpoints
api_router.include_router(
    oauth.router,
    tags=["OAuth2"],
    responses=crud_error_responses,
)

# Include MFA endpoints
api_router.include_router(
    mfa.router,
    tags=["MFA"],
    responses=crud_error_responses,
)

# Include MFA Policy endpoints
api_router.include_router(
    mfa_policies.router,
    tags=["MFA Policies"],
    responses=crud_error_responses,
)

# Include Auth Health endpoints
api_router.include_router(
    health_auth.router,
    tags=["Auth Health"],
    responses=crud_error_responses,
)

# Include Vulnerability Management endpoints
api_router.include_router(
    vulnerability_taxonomies.router,
    tags=["Vulnerability Taxonomies"],
    responses=crud_error_responses,
)

api_router.include_router(
    vulnerability_findings.router,
    tags=["Vulnerability Findings"],
    responses=crud_error_responses,
)

api_router.include_router(
    security_scans.router,
    tags=["Security Scans"],
    responses=crud_error_responses,
)

api_router.include_router(
    owasp_llm_classification.router,
    tags=["OWASP LLM Classification"],
    responses=crud_error_responses,
)

# Include Task Management endpoints
api_router.include_router(
    tasks.router,
    prefix="/tasks",
    tags=["Tasks"],
    responses=crud_error_responses,
)

# Include Scan Management endpoints
api_router.include_router(
    scans.router,
    prefix="/scans",
    tags=["Scans"],
    responses=crud_error_responses,
)

# Include Report Management endpoints
api_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["Reports"],
    responses=crud_error_responses,
)

# Include Template Management endpoints
api_router.include_router(
    templates.router,
    prefix="/templates",
    tags=["Templates"],
    responses=crud_error_responses,
)

# Include Plugin Management endpoints
api_router.include_router(
    plugins.router,
    prefix="/plugins",
    tags=["Plugins"],
    responses=crud_error_responses,
)
