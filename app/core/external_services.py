"""External services integration with circuit breakers.

This module provides a framework for making resilient external API calls
with circuit breaker protection, retries, and monitoring.
"""

import asyncio
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import httpx
from pydantic import BaseModel, Field, field_validator
from structlog.stdlib import get_logger

from ..utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerException,
    get_circuit_breaker,
)
from ..utils.retry import RetryConfig, with_retry
from .config import settings

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


class ServiceType(str, Enum):
    """Types of external services."""

    PAYMENT = "payment"
    EMAIL = "email"
    SMS = "sms"
    GEOCODING = "geocoding"
    WEATHER = "weather"
    AUTHENTICATION = "authentication"
    ANALYTICS = "analytics"
    STORAGE = "storage"
    NOTIFICATION = "notification"
    SEARCH = "search"
    AI_MODEL = "ai_model"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    CUSTOM = "custom"


class ServiceHealth(str, Enum):
    """Service health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ExternalServiceConfig(BaseModel):
    """Configuration for an external service."""

    name: str = Field(..., description="Service name")
    service_type: ServiceType = ServiceType.CUSTOM
    base_url: str = Field(..., description="Base URL for the service")
    timeout: float = Field(default=30.0, ge=0.1, le=300.0)
    headers: Dict[str, str] = Field(default_factory=dict)

    # Circuit breaker configuration
    failure_threshold: int = Field(default=5, ge=1, le=100)
    recovery_timeout: float = Field(default=60.0, ge=1.0, le=3600.0)
    success_threshold: int = Field(default=3, ge=1, le=50)

    # Retry configuration
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay: float = Field(default=1.0, ge=0.1, le=60.0)
    retry_backoff: float = Field(default=2.0, ge=1.0, le=5.0)

    # Monitoring
    enable_metrics: bool = True
    enable_logging: bool = True
    health_check_endpoint: Optional[str] = None
    health_check_interval: float = Field(default=300.0, ge=60.0, le=3600.0)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Ensure base URL is valid."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("Base URL must start with http:// or https://")
        return v.rstrip("/")  # Remove trailing slash


class ServiceRequest(BaseModel):
    """Base model for service requests."""

    method: str = Field(default="GET", pattern="^(GET|POST|PUT|DELETE|PATCH)$")
    path: str = Field(..., description="Request path")
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    json_data: Optional[Dict[str, Any]] = None
    data: Optional[Union[str, bytes]] = None
    timeout: Optional[float] = None


class ServiceResponse(BaseModel):
    """Base model for service responses."""

    status_code: int
    headers: Dict[str, str]
    data: Any
    elapsed_time: float
    service_name: str
    request_id: Optional[str] = None


class ServiceError(Exception):
    """Base exception for service errors."""

    def __init__(
        self,
        message: str,
        service_name: str,
        status_code: Optional[int] = None,
        response_data: Optional[Any] = None,
    ) -> None:
        """Initialize service error."""
        super().__init__(message)
        self.service_name = service_name
        self.status_code = status_code
        self.response_data = response_data


class ExternalServiceClient:
    """Base client for external services with circuit breaker protection."""

    def __init__(self, config: ExternalServiceConfig) -> None:
        """Initialize external service client.

        Args:
            config: Service configuration
        """
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._last_health_check = 0.0
        self._health_status = ServiceHealth.UNKNOWN

        # Initialize circuit breaker
        self.circuit_breaker = get_circuit_breaker(
            name=f"external_service_{config.name}",
            config=CircuitBreakerConfig(
                failure_threshold=config.failure_threshold,
                recovery_timeout=config.recovery_timeout,
                success_threshold=config.success_threshold,
                timeout=config.timeout,
                expected_exception=(
                    httpx.HTTPError,
                    ServiceError,
                    asyncio.TimeoutError,
                ),
            ),
        )

        # Initialize retry configuration
        self.retry_config = RetryConfig(
            max_attempts=config.max_retries + 1,  # +1 for initial attempt
            base_delay=config.retry_delay,
            exponential_base=config.retry_backoff,
            max_delay=config.retry_delay * (config.retry_backoff**config.max_retries),
            jitter=True,
        )

        logger.info(
            "external_service_client_initialized",
            service_name=config.name,
            service_type=config.service_type.value,
            base_url=config.base_url,
        )

    async def __aenter__(self) -> "ExternalServiceClient":
        """Enter async context manager."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context manager."""
        await self.close()

    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=httpx.Timeout(self.config.timeout),
                headers=self.config.headers,
                follow_redirects=True,
            )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        request: ServiceRequest,
        response_model: Optional[Type[T]] = None,
    ) -> Union[ServiceResponse, T]:
        """Make a request to the external service.

        Args:
            request: Service request details
            response_model: Optional Pydantic model to parse response

        Returns:
            ServiceResponse or parsed response model

        Raises:
            ServiceError: If request fails
            CircuitBreakerException: If circuit is open
        """
        await self._ensure_client()

        # Use retry decorator with circuit breaker
        @with_retry(config=self.retry_config)
        async def _make_request() -> ServiceResponse:
            return await self.circuit_breaker.call(self._execute_request, request)

        try:
            response = await _make_request()

            if response_model:
                # Parse response data with the model
                try:
                    parsed = response_model(**response.data)
                    return parsed
                except Exception as e:
                    logger.error(
                        "response_parsing_failed",
                        service_name=self.config.name,
                        error=str(e),
                        response_data=response.data,
                    )
                    raise ServiceError(
                        f"Failed to parse response: {str(e)}",
                        self.config.name,
                        response.status_code,
                        response.data,
                    )

            return response

        except CircuitBreakerException as e:
            logger.warning(
                "circuit_breaker_open",
                service_name=self.config.name,
                error=str(e),
            )
            raise
        except Exception as e:
            logger.error(
                "service_request_failed",
                service_name=self.config.name,
                error=str(e),
                request_path=request.path,
            )
            raise

    async def _execute_request(self, request: ServiceRequest) -> ServiceResponse:
        """Execute the actual HTTP request.

        Args:
            request: Service request details

        Returns:
            ServiceResponse

        Raises:
            ServiceError: If request fails
        """
        if not self._client:
            raise ServiceError("Client not initialized", self.config.name)

        start_time = time.time()

        try:
            # Build request parameters
            kwargs: Dict[str, Any] = {
                "method": request.method,
                "url": request.path,
            }

            if request.headers:
                kwargs["headers"] = request.headers
            if request.params:
                kwargs["params"] = request.params
            if request.json_data:
                kwargs["json"] = request.json_data
            elif request.data:
                kwargs["content"] = request.data
            if request.timeout:
                kwargs["timeout"] = request.timeout

            # Make request
            response = await self._client.request(**kwargs)
            elapsed_time = time.time() - start_time

            # Check status
            response.raise_for_status()

            # Parse response
            try:
                data = response.json()
            except Exception:
                # If not JSON, return text
                data = response.text

            service_response = ServiceResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                data=data,
                elapsed_time=elapsed_time,
                service_name=self.config.name,
                request_id=response.headers.get("x-request-id"),
            )

            if self.config.enable_logging:
                logger.info(
                    "external_service_request_success",
                    service_name=self.config.name,
                    method=request.method,
                    path=request.path,
                    status_code=response.status_code,
                    elapsed_time=elapsed_time,
                )

            return service_response

        except httpx.HTTPStatusError as e:
            elapsed_time = time.time() - start_time
            logger.warning(
                "external_service_http_error",
                service_name=self.config.name,
                status_code=e.response.status_code,
                elapsed_time=elapsed_time,
            )
            raise ServiceError(
                f"HTTP {e.response.status_code}: {e.response.text}",
                self.config.name,
                e.response.status_code,
                e.response.text,
            )
        except httpx.RequestError as e:
            elapsed_time = time.time() - start_time
            logger.error(
                "external_service_request_error",
                service_name=self.config.name,
                error=str(e),
                elapsed_time=elapsed_time,
            )
            raise ServiceError(
                f"Request failed: {str(e)}",
                self.config.name,
            )

    async def health_check(self) -> ServiceHealth:
        """Check service health.

        Returns:
            ServiceHealth status
        """
        # Check if we need to run health check
        current_time = time.time()
        if current_time - self._last_health_check < self.config.health_check_interval:
            return self._health_status

        self._last_health_check = current_time

        # If no health check endpoint, use circuit breaker state
        if not self.config.health_check_endpoint:
            if self.circuit_breaker.is_open():
                self._health_status = ServiceHealth.UNHEALTHY
            elif self.circuit_breaker.is_half_open():
                self._health_status = ServiceHealth.DEGRADED
            else:
                self._health_status = ServiceHealth.HEALTHY
            return self._health_status

        # Perform actual health check
        try:
            response = await self.request(
                ServiceRequest(
                    method="GET",
                    path=self.config.health_check_endpoint,
                    timeout=5.0,  # Quick timeout for health checks
                )
            )

            if response.status_code == 200:
                self._health_status = ServiceHealth.HEALTHY
            else:
                self._health_status = ServiceHealth.DEGRADED

        except CircuitBreakerException:
            self._health_status = ServiceHealth.UNHEALTHY
        except Exception as e:
            logger.warning(
                "health_check_failed",
                service_name=self.config.name,
                error=str(e),
            )
            self._health_status = ServiceHealth.DEGRADED

        return self._health_status

    def get_circuit_breaker_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics.

        Returns:
            Circuit breaker stats
        """
        return self.circuit_breaker.get_stats()


# Service registry
_service_clients: Dict[str, ExternalServiceClient] = {}


def register_service(config: ExternalServiceConfig) -> ExternalServiceClient:
    """Register an external service.

    Args:
        config: Service configuration

    Returns:
        Service client
    """
    if config.name in _service_clients:
        logger.warning(
            "service_already_registered",
            service_name=config.name,
        )
        return _service_clients[config.name]

    client = ExternalServiceClient(config)
    _service_clients[config.name] = client

    logger.info(
        "service_registered",
        service_name=config.name,
        service_type=config.service_type.value,
    )

    return client


def get_service(name: str) -> Optional[ExternalServiceClient]:
    """Get a registered service client.

    Args:
        name: Service name

    Returns:
        Service client or None
    """
    return _service_clients.get(name)


async def get_all_services_health() -> Dict[str, ServiceHealth]:
    """Get health status of all registered services.

    Returns:
        Dictionary of service name to health status
    """
    health_status = {}

    for name, client in _service_clients.items():
        try:
            health = await client.health_check()
            health_status[name] = health
        except Exception as e:
            logger.error(
                "failed_to_get_service_health",
                service_name=name,
                error=str(e),
            )
            health_status[name] = ServiceHealth.UNKNOWN

    return health_status


async def close_all_services() -> None:
    """Close all service clients."""
    for client in _service_clients.values():
        try:
            await client.close()
        except Exception as e:
            logger.error(
                "failed_to_close_service",
                service_name=client.config.name,
                error=str(e),
            )

    _service_clients.clear()
    logger.info("all_services_closed")
