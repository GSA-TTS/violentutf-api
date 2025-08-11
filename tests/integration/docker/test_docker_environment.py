"""
Integration tests for Docker test environment setup.
Tests compliance with ADR-012 requirements for containerized testing.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

import pytest
import requests
import yaml


class TestDockerTestEnvironment:
    """Test suite for Docker test environment validation (US-101)."""

    @pytest.fixture(scope="class")
    def docker_compose_file(self) -> Path:
        """Get path to docker-compose.test.yml file."""
        project_root = Path(__file__).parent.parent.parent.parent
        return project_root / "docker-compose.test.yml"

    @pytest.fixture(scope="class")
    def docker_compose_config(self, docker_compose_file) -> Dict[str, Any]:
        """Load and validate docker-compose.test.yml configuration."""
        if not docker_compose_file.exists():
            pytest.skip(f"Docker compose test file not found: {docker_compose_file}")

        with open(docker_compose_file, "r") as f:
            return yaml.safe_load(f)

    def test_docker_compose_file_exists(self, docker_compose_file):
        """
        Test that docker-compose.test.yml exists.
        Addresses ADR-012 requirement for Docker-based testing infrastructure.
        """
        assert docker_compose_file.exists(), f"docker-compose.test.yml must exist at {docker_compose_file}"

    def test_required_services_defined(self, docker_compose_config):
        """
        Test that all required services are defined in docker-compose.test.yml.
        Validates ASR-1: Containerized testing infrastructure.
        """
        required_services = ["api", "db", "redis", "celery_worker"]
        services = docker_compose_config.get("services", {})

        for service in required_services:
            assert service in services, f"Required service '{service}' not found in docker-compose.test.yml"

    def test_test_database_configuration(self, docker_compose_config):
        """
        Test that PostgreSQL is configured with test database.
        Validates ASR-6: Complete test isolation.
        """
        db_service = docker_compose_config["services"]["db"]
        db_env = db_service.get("environment", {})

        # Check for test database name
        assert "POSTGRES_DB" in db_env, "POSTGRES_DB must be configured"
        assert db_env["POSTGRES_DB"] == "testdb", "Test database must be named 'testdb' for isolation"

        # Check for ephemeral storage (no volumes for test data)
        assert "volumes" not in db_service or not any(
            "postgres_data" in str(v) for v in db_service.get("volumes", [])
        ), "Test database should use ephemeral storage, not persistent volumes"

    def test_redis_test_configuration(self, docker_compose_config):
        """
        Test that Redis is configured for testing.
        Validates test environment isolation.
        """
        redis_service = docker_compose_config["services"]["redis"]

        # Check Redis configuration
        assert redis_service.get("image", "").startswith("redis:"), "Redis service must use official Redis image"

        # Ensure no persistent volumes for test Redis
        assert "volumes" not in redis_service or not any(
            "redis_data" in str(v) for v in redis_service.get("volumes", [])
        ), "Test Redis should use ephemeral storage"

    def test_api_test_environment_variables(self, docker_compose_config):
        """
        Test that API service has proper test environment variables.
        Validates ADR-012 test-specific configuration.
        """
        api_service = docker_compose_config["services"]["api"]
        api_env = api_service.get("environment", {})

        # Check for test mode flag
        assert "TESTING" in api_env, "TESTING environment variable must be set"
        assert api_env["TESTING"] in [
            "true",
            "True",
            "1",
        ], "TESTING must be set to true for test environment"

        # Check database URL points to test database
        assert "DATABASE_URL" in api_env, "DATABASE_URL must be configured"
        assert "testdb" in api_env["DATABASE_URL"], "DATABASE_URL must point to test database"

        # Check Redis URL configuration
        assert "REDIS_URL" in api_env, "REDIS_URL must be configured"
        assert "redis://" in api_env["REDIS_URL"], "REDIS_URL must be properly formatted"

    def test_network_isolation(self, docker_compose_config):
        """
        Test that services use isolated test network.
        Validates ASR-1: Complete isolation from production.
        """
        # Check for networks definition
        networks = docker_compose_config.get("networks", {})
        assert "test_network" in networks or "test-network" in networks, "Test network must be defined for isolation"

        # Verify all services use the test network
        for service_name, service_config in docker_compose_config["services"].items():
            service_networks = service_config.get("networks", [])
            if service_networks:
                assert any(
                    "test" in str(net).lower() for net in service_networks
                ), f"Service {service_name} must use test network"

    def test_health_check_configurations(self, docker_compose_config):
        """
        Test that health checks are configured for all services.
        Validates ASR-5: Service health checking and startup orchestration.
        """
        critical_services = ["db", "redis", "api"]

        for service in critical_services:
            service_config = docker_compose_config["services"][service]
            assert "healthcheck" in service_config, f"Service {service} must have health check configured"

            healthcheck = service_config["healthcheck"]
            assert "test" in healthcheck, f"Health check for {service} must define test command"
            assert "interval" in healthcheck, f"Health check for {service} must define interval"
            assert "timeout" in healthcheck, f"Health check for {service} must define timeout"
            assert "retries" in healthcheck, f"Health check for {service} must define retries"

    def test_service_dependencies(self, docker_compose_config):
        """
        Test that service dependencies are properly configured.
        Validates proper startup orchestration.
        """
        api_service = docker_compose_config["services"]["api"]

        # API should depend on database and Redis
        assert "depends_on" in api_service, "API service must define dependencies"

        depends_on = api_service["depends_on"]
        if isinstance(depends_on, list):
            assert "db" in depends_on and "redis" in depends_on, "API must depend on db and redis services"
        else:  # dict format with conditions
            assert "db" in depends_on and "redis" in depends_on, "API must depend on db and redis services"

            # Check for health conditions if using dict format
            if isinstance(depends_on["db"], dict):
                assert depends_on["db"].get("condition") == "service_healthy", "API should wait for db to be healthy"
            if isinstance(depends_on["redis"], dict):
                assert (
                    depends_on["redis"].get("condition") == "service_healthy"
                ), "API should wait for redis to be healthy"

    def test_celery_worker_configuration(self, docker_compose_config):
        """
        Test Celery worker configuration for async task processing.
        Validates ADR-007 compliance for async task processing.
        """
        celery_service = docker_compose_config["services"]["celery_worker"]

        # Check Celery command
        assert "command" in celery_service, "Celery worker must have command defined"
        assert "celery" in celery_service["command"], "Celery worker command must start celery"

        # Check dependencies
        assert "depends_on" in celery_service, "Celery worker must define dependencies"
        depends_on = celery_service["depends_on"]
        if isinstance(depends_on, list):
            assert "redis" in depends_on, "Celery must depend on Redis"
        else:
            assert "redis" in depends_on, "Celery must depend on Redis"

    @pytest.mark.integration
    def test_docker_environment_startup(self, docker_compose_file):
        """
        Integration test for Docker environment startup within time limits.
        Validates ASR-5: All services start within 30 seconds, healthy within 60 seconds.
        """
        if not docker_compose_file.exists():
            pytest.skip("Docker compose file not found")

        # Start Docker environment
        start_time = time.time()
        result = subprocess.run(
            ["docker-compose", "-f", str(docker_compose_file), "up", "-d"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to start Docker environment: {result.stderr}")

        startup_time = time.time() - start_time
        assert startup_time < 30, f"Docker environment must start within 30 seconds, took {startup_time:.1f}s"

        # Wait for services to be healthy
        max_wait = 60
        health_check_start = time.time()

        while (time.time() - health_check_start) < max_wait:
            # Check if API is responding
            try:
                response = requests.get("http://localhost:8000/health", timeout=2)
                if response.status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(2)
        else:
            pytest.fail("Services did not become healthy within 60 seconds")

        # Cleanup
        subprocess.run(["docker-compose", "-f", str(docker_compose_file), "down", "-v"], capture_output=True)

    def test_env_test_file_exists(self):
        """
        Test that .env.test template exists for test configuration.
        """
        project_root = Path(__file__).parent.parent.parent.parent
        env_test_file = project_root / ".env.test"

        assert env_test_file.exists(), ".env.test template must exist for test configuration"

    def test_no_production_data_access(self, docker_compose_config):
        """
        Test that test environment cannot access production data.
        Validates complete isolation from production.
        """
        # Check that no production database names are used
        for service_name, service_config in docker_compose_config["services"].items():
            env_vars = service_config.get("environment", {})

            # Check database URLs don't contain production database names
            if "DATABASE_URL" in env_vars:
                assert (
                    "violentutf" not in env_vars["DATABASE_URL"].lower()
                ), f"Service {service_name} must not reference production database"
                assert (
                    "production" not in env_vars["DATABASE_URL"].lower()
                ), f"Service {service_name} must not reference production database"

            # Check no production Redis databases
            if "REDIS_URL" in env_vars:
                assert (
                    "/0" not in env_vars["REDIS_URL"]
                ), f"Service {service_name} should not use Redis DB 0 (typically production)"
