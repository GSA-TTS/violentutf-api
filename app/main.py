"""Enhanced FastAPI application with security and monitoring."""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_client import make_asgi_app
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from structlog.stdlib import get_logger

from .api.routes import api_router
from .core.config import settings
from .core.errors import setup_error_handlers
from .core.logging import setup_logging
from .middleware.logging import LoggingMiddleware
from .middleware.metrics import MetricsMiddleware
from .middleware.request_id import RequestIDMiddleware
from .middleware.security import setup_security_middleware

# Setup logging first
setup_logging()
logger = get_logger(__name__)

# Create rate limiter
limiter = Limiter(key_func=get_remote_address)


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
    # TODO: Initialize database
    # TODO: Initialize cache
    # TODO: Run migrations

    yield

    # Shutdown tasks
    logger.info("shutting_down_application")
    # TODO: Close database connections
    # TODO: Close cache connections


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description=settings.DESCRIPTION,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json" if not settings.is_production else None,
        docs_url=f"{settings.API_V1_STR}/docs" if not settings.is_production else None,
        redoc_url=f"{settings.API_V1_STR}/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Add state for rate limiting
    app.state.limiter = limiter

    # Setup error handlers
    setup_error_handlers(app, development_mode=settings.is_development)

    # Add exception handler for rate limiting
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Setup middleware (order matters!)
    # 1. Request ID (needs to be first)
    app.add_middleware(RequestIDMiddleware)

    # 2. Logging
    app.add_middleware(LoggingMiddleware)

    # 3. Metrics
    if settings.ENABLE_METRICS:
        app.add_middleware(MetricsMiddleware)

    # 4. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=settings.ALLOW_CREDENTIALS,
        allow_methods=settings.ALLOWED_METHODS,
        allow_headers=settings.ALLOWED_HEADERS,
    )

    # 5. GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 6. Security headers (should be near the end)
    setup_security_middleware(app)

    # Include API routes
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Mount metrics endpoint
    if settings.ENABLE_METRICS:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)

    # Root endpoint
    @app.get("/")  # type: ignore[misc]
    async def root() -> dict[str, Any]:
        """Root endpoint."""
        return {
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "operational",
            "docs": f"{settings.API_V1_STR}/docs" if not settings.is_production else None,
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
