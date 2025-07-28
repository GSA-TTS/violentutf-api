"""Enhanced FastAPI application with security and monitoring."""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional, Union

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from structlog.stdlib import get_logger

from .api.routes import api_router
from .core.config import Settings, settings
from .core.errors import setup_error_handlers
from .core.logging import setup_logging
from .middleware.authentication import JWTAuthenticationMiddleware
from .middleware.csrf import CSRFProtectionMiddleware
from .middleware.idempotency import IdempotencyMiddleware
from .middleware.input_sanitization import InputSanitizationMiddleware
from .middleware.logging import LoggingMiddleware
from .middleware.metrics import MetricsMiddleware
from .middleware.request_id import RequestIDMiddleware
from .middleware.request_signing import RequestSigningMiddleware
from .middleware.security import setup_security_middleware
from .middleware.session import SessionMiddleware

# Setup logging first
setup_logging()
logger = get_logger(__name__)

# Create rate limiter
limiter = Limiter(key_func=get_remote_address)


async def rate_limit_handler(request: Request, exc: Exception) -> Response:
    """Handle rate limit exceptions with FastAPI signature."""
    if isinstance(exc, RateLimitExceeded):
        response = _rate_limit_exceeded_handler(request, exc)
        # Convert starlette Response to FastAPI JSONResponse
        return JSONResponse(
            status_code=response.status_code,
            content={"detail": f"Rate limit exceeded: {exc.detail}"},
            headers=dict(response.headers),
        )
    # Fallback for other exceptions (shouldn't happen with this handler)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


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
    logger.info("application_startup_complete")

    yield

    # Shutdown tasks
    logger.info("shutting_down_application")
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
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

    # Setup middleware (order matters!)
    # 1. Request ID (needs to be first)
    app.add_middleware(RequestIDMiddleware)

    # 2. Logging
    app.add_middleware(LoggingMiddleware)

    # 3. Metrics
    if app_settings.ENABLE_METRICS:
        app.add_middleware(MetricsMiddleware)

    # 4. Session management (before CSRF)
    app.add_middleware(SessionMiddleware)
    # 5. CSRF Protection (after sessions) - configurable
    if app_settings.CSRF_PROTECTION:
        app.add_middleware(CSRFProtectionMiddleware)
    # 6. JWT Authentication (after CSRF, before other processing)
    app.add_middleware(JWTAuthenticationMiddleware)
    # 7. Idempotency support (before input sanitization)
    app.add_middleware(IdempotencyMiddleware)
    # 8. Input sanitization (before request processing)
    app.add_middleware(InputSanitizationMiddleware)
    # 9. Request signing (for high-security endpoints) - configurable
    if app_settings.REQUEST_SIGNING_ENABLED:
        app.add_middleware(RequestSigningMiddleware)
    # 10. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.ALLOWED_ORIGINS,
        allow_credentials=app_settings.ALLOW_CREDENTIALS,
        allow_methods=app_settings.ALLOWED_METHODS,
        allow_headers=app_settings.ALLOWED_HEADERS,
    )

    # 11. GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 12. Security headers (should be near the end)
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
    )
