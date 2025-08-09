"""Tests for external services with circuit breakers."""

import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest
from pydantic import BaseModel

from app.core.external_services import (
    ExternalServiceClient,
    ExternalServiceConfig,
    ServiceError,
    ServiceHealth,
    ServiceRequest,
    ServiceResponse,
    ServiceType,
    close_all_services,
    get_all_services_health,
    get_service,
    register_service,
)
from app.utils.circuit_breaker import CircuitBreakerException, CircuitState


# Using function to avoid pytest collection warning
def create_test_service_response() -> type[BaseModel]:
    """Create test response model."""

    class ServiceResponseModel(BaseModel):
        id: int
        name: str
        value: float

    return ServiceResponseModel


ServiceResponseModel = create_test_service_response()


class TestExternalServiceConfig:
    """Test external service configuration."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ExternalServiceConfig(
            name="test_service",
            base_url="https://api.example.com",
        )

        assert config.name == "test_service"
        assert config.service_type == ServiceType.CUSTOM
        assert config.base_url == "https://api.example.com"
        assert config.timeout == 30.0
        assert config.failure_threshold == 5
        assert config.recovery_timeout == 60.0
        assert config.max_retries == 3

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = ExternalServiceConfig(
            name="payment_api",
            service_type=ServiceType.PAYMENT,
            base_url="https://payments.example.com/",  # Trailing slash should be removed
            timeout=10.0,
            failure_threshold=3,
            headers={"X-API-Key": "secret"},  # pragma: allowlist secret
        )

        assert config.name == "payment_api"
        assert config.service_type == ServiceType.PAYMENT
        assert config.base_url == "https://payments.example.com"  # No trailing slash
        assert config.timeout == 10.0
        assert config.failure_threshold == 3
        assert config.headers == {"X-API-Key": "secret"}  # pragma: allowlist secret

    def test_invalid_base_url(self) -> None:
        """Test invalid base URL validation."""
        with pytest.raises(ValueError, match="Base URL must start with http"):
            ExternalServiceConfig(
                name="test",
                base_url="invalid-url",
            )


class TestServiceError:
    """Test service error."""

    def test_error_creation(self) -> None:
        """Test service error creation."""
        error = ServiceError(
            "Connection failed",
            "payment_service",
            status_code=503,
            response_data={"error": "Service unavailable"},
        )

        assert str(error) == "Connection failed"
        assert error.service_name == "payment_service"
        assert error.status_code == 503
        assert error.response_data == {"error": "Service unavailable"}


class TestExternalServiceClient:
    """Test external service client."""

    def teardown_method(self) -> None:
        """Clean up circuit breakers after each test."""
        from app.utils.circuit_breaker import _circuit_breakers

        _circuit_breakers.clear()

    @pytest.fixture
    def config(self) -> ExternalServiceConfig:
        """Create test service configuration."""
        return ExternalServiceConfig(
            name="test_api",
            base_url="https://api.test.com",
            timeout=5.0,
            failure_threshold=2,
            recovery_timeout=10.0,
            max_retries=0,  # Disable retries for most tests
        )

    @pytest.fixture
    def client(self, config: ExternalServiceConfig) -> ExternalServiceClient:
        """Create test service client."""
        return ExternalServiceClient(config)

    @pytest.mark.asyncio
    async def test_client_initialization(self, client: ExternalServiceClient) -> None:
        """Test client initialization."""
        assert client.config.name == "test_api"
        assert client._client is None
        assert client._health_status == ServiceHealth.UNKNOWN
        assert client.circuit_breaker is not None
        assert client.circuit_breaker.name == "external_service_test_api"

    @pytest.mark.asyncio
    async def test_context_manager(self, client: ExternalServiceClient) -> None:
        """Test client as context manager."""
        async with client as c:
            assert c._client is not None
            assert isinstance(c._client, httpx.AsyncClient)

        # Client should be closed after context
        assert client._client is None

    @pytest.mark.asyncio
    async def test_successful_request(self, client: ExternalServiceClient) -> None:
        """Test successful request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"result": "success"}
        mock_response.text = '{"result": "success"}'
        mock_response.raise_for_status = Mock()

        with patch.object(httpx.AsyncClient, "request", return_value=mock_response):
            request = ServiceRequest(
                method="GET",
                path="/test",
            )

            response = await client.request(request)

            assert isinstance(response, ServiceResponse)
            assert response.status_code == 200
            assert response.data == {"result": "success"}
            assert response.service_name == "test_api"

    @pytest.mark.asyncio
    async def test_request_with_response_model(self, client: ExternalServiceClient) -> None:
        """Test request with response model parsing."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {
            "id": 123,
            "name": "test",
            "value": 45.6,
        }
        mock_response.raise_for_status = Mock()

        with patch.object(httpx.AsyncClient, "request", return_value=mock_response):
            request = ServiceRequest(method="GET", path="/item/123")

            result = await client.request(request, response_model=ServiceResponseModel)

            assert isinstance(result, ServiceResponseModel)
            assert result.id == 123
            assert result.name == "test"
            assert result.value == 45.6

    @pytest.mark.asyncio
    async def test_http_error(self, client: ExternalServiceClient) -> None:
        """Test HTTP error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.headers = {}
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server error",
            request=Mock(),
            response=mock_response,
        )

        with patch.object(httpx.AsyncClient, "request", return_value=mock_response):
            request = ServiceRequest(method="GET", path="/error")

            with pytest.raises(ServiceError) as exc_info:
                await client.request(request)

            assert exc_info.value.service_name == "test_api"
            assert exc_info.value.status_code == 500
            assert "HTTP 500" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_error(self, client: ExternalServiceClient) -> None:
        """Test connection error handling."""
        with patch.object(
            httpx.AsyncClient,
            "request",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            request = ServiceRequest(method="GET", path="/test")

            with pytest.raises(ServiceError) as exc_info:
                await client.request(request)

            assert exc_info.value.service_name == "test_api"
            assert "Request failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self, client: ExternalServiceClient) -> None:
        """Test circuit breaker integration."""
        # Reset circuit breaker state
        await client.circuit_breaker.reset()

        # Force failures to open circuit
        with patch.object(
            httpx.AsyncClient,
            "request",
            side_effect=httpx.ConnectError("Connection failed"),
        ):
            request = ServiceRequest(method="GET", path="/test")

            # First failure
            with pytest.raises(ServiceError):
                await client.request(request)

            assert client.circuit_breaker.stats.failure_count == 1

            # Second failure should open circuit
            with pytest.raises(ServiceError):
                await client.request(request)

            assert client.circuit_breaker.state == CircuitState.OPEN

            # Next request should fail fast
            with pytest.raises(CircuitBreakerException):
                await client.request(request)

    @pytest.mark.asyncio
    async def test_retry_behavior(self) -> None:
        """Test retry behavior."""
        # Create a client with retries enabled
        config = ExternalServiceConfig(
            name="retry_test_api",
            base_url="https://api.test.com",
            timeout=5.0,
            failure_threshold=10,  # High threshold to avoid opening circuit
            recovery_timeout=10.0,
            max_retries=2,
        )
        client = ExternalServiceClient(config)

        call_count = 0

        async def mock_request(*args: Any, **kwargs: Any) -> Mock:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Temporary failure")

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {"success": True}
            mock_response.raise_for_status = Mock()
            return mock_response

        with patch.object(httpx.AsyncClient, "request", side_effect=mock_request):
            request = ServiceRequest(method="GET", path="/retry-test")

            response = await client.request(request)

            assert response.status_code == 200
            assert call_count == 3  # Initial + 2 retries

    @pytest.mark.asyncio
    async def test_health_check_no_endpoint(self, client: ExternalServiceClient) -> None:
        """Test health check without specific endpoint."""
        # Circuit is closed
        assert client.circuit_breaker.state == CircuitState.CLOSED
        health = await client.health_check()
        assert health == ServiceHealth.HEALTHY

        # Manually set circuit state to test health status mapping
        client.circuit_breaker.state = CircuitState.OPEN
        # Force health check to run again by resetting last check time
        client._last_health_check = 0
        health = await client.health_check()
        assert health == ServiceHealth.UNHEALTHY

        # Test half-open state
        client.circuit_breaker.state = CircuitState.HALF_OPEN
        client._last_health_check = 0  # Force re-check
        health = await client.health_check()
        assert health == ServiceHealth.DEGRADED

        # Reset state
        client.circuit_breaker.state = CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_health_check_with_endpoint(self, config: ExternalServiceConfig) -> None:
        """Test health check with specific endpoint."""
        config.health_check_endpoint = "/health"
        config.max_retries = 0  # Disable retries
        client = ExternalServiceClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = Mock()

        with patch.object(httpx.AsyncClient, "request", return_value=mock_response):
            health = await client.health_check()
            assert health == ServiceHealth.HEALTHY

    @pytest.mark.asyncio
    async def test_get_circuit_breaker_stats(self, client: ExternalServiceClient) -> None:
        """Test getting circuit breaker statistics."""
        # Reset to ensure clean state
        await client.circuit_breaker.reset()

        stats = client.get_circuit_breaker_stats()

        assert stats["name"] == "external_service_test_api"
        assert stats["state"] == "closed"
        assert "failure_count" in stats
        assert "success_count" in stats
        assert "config" in stats

        # Verify config structure
        config = stats["config"]
        assert "failure_threshold" in config
        assert "recovery_timeout" in config
        assert "success_threshold" in config
        assert "timeout" in config


class TestServiceRegistry:
    """Test service registry functions."""

    def teardown_method(self) -> None:
        """Clean up registry after each test."""
        from app.core.external_services import _service_clients

        _service_clients.clear()

    def test_register_service(self) -> None:
        """Test service registration."""
        config = ExternalServiceConfig(
            name="test_service",
            base_url="https://api.test.com",
        )

        client = register_service(config)

        assert isinstance(client, ExternalServiceClient)
        assert client.config.name == "test_service"
        assert get_service("test_service") is client

    def test_register_duplicate_service(self) -> None:
        """Test registering duplicate service."""
        config1 = ExternalServiceConfig(
            name="duplicate",
            base_url="https://api1.test.com",
        )
        config2 = ExternalServiceConfig(
            name="duplicate",
            base_url="https://api2.test.com",
        )

        client1 = register_service(config1)
        client2 = register_service(config2)

        # Should return the same client
        assert client1 is client2
        assert client1.config.base_url == "https://api1.test.com"

    def test_get_nonexistent_service(self) -> None:
        """Test getting non-existent service."""
        assert get_service("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_all_services_health(self) -> None:
        """Test getting health of all services."""
        # Register services
        service1 = register_service(
            ExternalServiceConfig(
                name="service1",
                base_url="https://api1.test.com",
            )
        )
        service2 = register_service(
            ExternalServiceConfig(
                name="service2",
                base_url="https://api2.test.com",
            )
        )

        # Mock health checks
        service1._health_status = ServiceHealth.HEALTHY
        service2._health_status = ServiceHealth.DEGRADED

        # Mock health check method
        async def mock_health_check(self: Any) -> ServiceHealth:
            return self._health_status

        # Patch the health_check method on the instances
        service1.health_check = lambda: mock_health_check(service1)  # type: ignore
        service2.health_check = lambda: mock_health_check(service2)  # type: ignore

        health_status = await get_all_services_health()

        assert health_status["service1"] == ServiceHealth.HEALTHY
        assert health_status["service2"] == ServiceHealth.DEGRADED

    @pytest.mark.asyncio
    async def test_close_all_services(self) -> None:
        """Test closing all services."""
        # Register services
        config1 = ExternalServiceConfig(
            name="service1",
            base_url="https://api1.test.com",
        )
        config2 = ExternalServiceConfig(
            name="service2",
            base_url="https://api2.test.com",
        )

        client1 = register_service(config1)
        client2 = register_service(config2)

        # Mock close method
        client1.close = AsyncMock()
        client2.close = AsyncMock()

        await close_all_services()

        client1.close.assert_called_once()
        client2.close.assert_called_once()

        # Registry should be empty
        assert get_service("service1") is None
        assert get_service("service2") is None


class TestIntegration:
    """Integration tests for external services."""

    def teardown_method(self) -> None:
        """Clean up after each test."""
        from app.core.external_services import _service_clients
        from app.utils.circuit_breaker import _circuit_breakers

        _service_clients.clear()
        _circuit_breakers.clear()

    @pytest.mark.asyncio
    async def test_full_request_flow(self) -> None:
        """Test full request flow with all features."""
        config = ExternalServiceConfig(
            name="integration_test",
            base_url="https://api.integration.test",
            timeout=5.0,
            failure_threshold=2,
            recovery_timeout=5.0,
            max_retries=1,
        )

        client = ExternalServiceClient(config)

        # Successful request
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"x-request-id": "test-123"}
        mock_response.json.return_value = {
            "id": 1,
            "name": "Integration Test",
            "value": 99.9,
        }
        mock_response.raise_for_status = Mock()

        with patch.object(httpx.AsyncClient, "request", return_value=mock_response):
            request = ServiceRequest(
                method="POST",
                path="/api/test",
                json_data={"test": True},
                headers={"X-Custom": "header"},
            )

            result = await client.request(request, response_model=ServiceResponseModel)

            assert isinstance(result, ServiceResponseModel)
            assert result.id == 1
            assert result.name == "Integration Test"
            assert result.value == 99.9

        # Check circuit breaker stats
        stats = client.get_circuit_breaker_stats()
        assert stats["success_count"] == 1
        assert stats["failure_count"] == 0
        assert stats["state"] == "closed"

        await client.close()
