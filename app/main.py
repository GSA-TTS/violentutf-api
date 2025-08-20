"""Enhanced FastAPI application with security and monitoring."""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional, Union

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
from slowapi.errors import RateLimitExceeded
from structlog.stdlib import get_logger

from .api.routes import api_router
from .core.config import Settings, settings
from .core.errors import setup_error_handlers
from .core.logging import setup_logging
from .core.rate_limiting import limiter
from .core.startup import on_shutdown, on_startup
from .middleware.audit import audit_middleware
from .middleware.authentication import JWTAuthenticationMiddleware
from .middleware.csrf import CSRFProtectionMiddleware
from .middleware.idempotency import IdempotencyMiddleware
from .middleware.input_sanitization import InputSanitizationMiddleware
from .middleware.logging import LoggingMiddleware
from .middleware.metrics import MetricsMiddleware
from .middleware.permissions import permission_checker
from .middleware.rate_limiting import RateLimitingMiddleware
from .middleware.request_id import RequestIDMiddleware
from .middleware.request_signing import RequestSigningMiddleware
from .middleware.request_size import RequestSizeLimitMiddleware
from .middleware.security import setup_security_middleware
from .middleware.session import SessionMiddleware

# Setup logging first
setup_logging()
logger = get_logger(__name__)


async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Handle rate limit exceptions with enhanced logging."""
    logger.warning(
        "rate_limit_exceeded",
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        rate_limit_detail=exc.detail,
    )

    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}", "type": "rate_limit_exceeded"},
        headers={"Retry-After": "60"},  # Default retry after 60 seconds
    )


async def _initialize_database() -> None:
    """Initialize database connection."""
    try:
        from .db.session import get_session_maker

        session_maker = get_session_maker()
        if session_maker:
            logger.info("database_initialized")
        else:
            logger.info("database_not_configured")
    except Exception as e:
        logger.error("database_initialization_failed", error=str(e))


async def _initialize_cache() -> None:
    """Initialize cache connection."""
    try:
        from .utils.cache import get_cache_client

        cache_client = get_cache_client()
        if cache_client:
            logger.info("cache_initialized")
        else:
            logger.info("cache_not_configured")
    except Exception as e:
        logger.error("cache_initialization_failed", error=str(e))


async def _shutdown_database() -> None:
    """Close database connections."""
    try:
        from .db.session import close_database_connections

        await close_database_connections()
        logger.info("database_connections_closed")
    except Exception as e:
        logger.error("database_shutdown_error", error=str(e))


async def _shutdown_cache() -> None:
    """Close cache connections."""
    try:
        from .utils.cache import close_cache_connections

        await close_cache_connections()
        logger.info("cache_connections_closed")
    except Exception as e:
        logger.error("cache_shutdown_error", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info(
        "starting_application",
        project=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
    )

    # Startup tasks
    logger.info("initializing_application_dependencies")
    await _initialize_database()
    await _initialize_cache()

    # Run startup handler for auth services
    await on_startup()

    logger.info("application_startup_complete")

    yield

    # Shutdown tasks
    logger.info("shutting_down_application")

    # Run shutdown handler for auth services
    await on_shutdown()

    await _shutdown_database()
    await _shutdown_cache()


def create_application(custom_settings: Optional[Settings] = None) -> FastAPI:
    """Create and configure FastAPI application."""
    # Use custom settings if provided (for testing), otherwise use default
    app_settings = custom_settings or settings
    app = FastAPI(
        title=app_settings.PROJECT_NAME,
        description=app_settings.DESCRIPTION,
        version=app_settings.VERSION,
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json" if not app_settings.is_production else None,
        docs_url=f"{app_settings.API_V1_STR}/docs" if not app_settings.is_production else None,
        redoc_url=f"{app_settings.API_V1_STR}/redoc" if not app_settings.is_production else None,
        lifespan=lifespan,
    )

    # Add state for rate limiting
    app.state.limiter = limiter

    # Setup error handlers
    setup_error_handlers(app, development_mode=app_settings.is_development)

    # Add exception handler for rate limiting
    # Type ignore needed for mypy strict mode in CI environment
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)  # type: ignore[arg-type,unused-ignore]

    # Setup middleware (order matters!)
    # 1. Request ID (needs to be first)
    app.add_middleware(RequestIDMiddleware)

    # 2. Logging
    app.add_middleware(LoggingMiddleware)

    # 3. Metrics
    if app_settings.ENABLE_METRICS:
        app.add_middleware(MetricsMiddleware)

    # 4. Rate limiting (early in the chain to prevent resource usage)
    app.add_middleware(RateLimitingMiddleware)

    # 5. Request size limits (prevent resource exhaustion)
    app.add_middleware(RequestSizeLimitMiddleware)

    # 6. Session management (before CSRF)
    app.add_middleware(SessionMiddleware)
    # 7. CSRF Protection (after sessions) - configurable
    if app_settings.CSRF_PROTECTION:
        app.add_middleware(CSRFProtectionMiddleware)

    # 8. Audit logging (log all requests for security)
    app.middleware("http")(audit_middleware)

    # 9. Permission checking (needs authenticated user)
    app.middleware("http")(permission_checker)

    # 10. JWT Authentication (must run AFTER permission/audit due to middleware ordering)
    # Note: app.add_middleware() runs in reverse order, so this runs BEFORE permission checker
    app.add_middleware(JWTAuthenticationMiddleware)
    # 11. Idempotency support (before input sanitization)
    app.add_middleware(IdempotencyMiddleware)
    # 12. Input sanitization (before request processing)
    app.add_middleware(InputSanitizationMiddleware)
    # 13. Request signing (for high-security endpoints) - configurable
    if app_settings.REQUEST_SIGNING_ENABLED:
        app.add_middleware(RequestSigningMiddleware)
    # 14. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.ALLOWED_ORIGINS,
        allow_credentials=app_settings.ALLOW_CREDENTIALS,
        allow_methods=app_settings.ALLOWED_METHODS,
        allow_headers=app_settings.ALLOWED_HEADERS,
    )

    # 15. GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 16. Security headers (should be near the end)
    setup_security_middleware(app)

    # Include API routes
    app.include_router(api_router, prefix=app_settings.API_V1_STR)

    # Mount metrics endpoint
    if app_settings.ENABLE_METRICS:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)

    # Root endpoint
    @app.get("/")
    async def root() -> dict[str, Any]:
        """Root endpoint."""
        return {
            "service": app_settings.PROJECT_NAME,
            "version": app_settings.VERSION,
            "status": "operational",
            "docs": f"{app_settings.API_V1_STR}/docs" if not app_settings.is_production else None,
        }

    return app


# Create application instance
app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.is_development,
        log_config=None,  # Use our custom logging
        limit_max_requests=1000,  # Restart workers after 1000 requests
        limit_concurrency=1000,  # Max concurrent connections
        h11_max_incomplete_event_size=settings.MAX_REQUEST_LINE_SIZE,
    )
