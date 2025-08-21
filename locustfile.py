"""
Locust configuration for ViolentUTF API performance testing.
Provides basic load testing capabilities as per ADR-012 requirements.
"""

from typing import TYPE_CHECKING

from locust import FastHttpUser, between, task

if TYPE_CHECKING:
    from locust.clients import HttpSession
    from locust.env import Environment


class ViolentUTFAPIUser(FastHttpUser):  # type: ignore[misc]
    """Basic API user for load testing."""

    # Wait between 1-3 seconds between requests
    wait_time = between(1, 3)

    # Set the base host for the API
    host = "http://localhost:8000"

    @task(3)  # type: ignore[misc]
    def test_health_endpoint(self) -> None:
        """Test the health check endpoint (high priority)."""
        self.client.get("/api/v1/health")

    @task(1)  # type: ignore[misc]
    def test_openapi_docs(self) -> None:
        """Test API documentation endpoint (lower priority)."""
        self.client.get("/docs")

    @task(1)  # type: ignore[misc]
    def test_ready_endpoint(self) -> None:
        """Test the readiness endpoint."""
        self.client.get("/api/v1/ready")

    def on_start(self) -> None:
        """Initialize user session."""
        pass

    def on_stop(self) -> None:
        """Clean up user session."""
        pass
