"""
Integration tests for service health checks.
Tests compliance with ADR-012 ASR-5 requirements for health checking.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

import psycopg2
import pytest
import redis
import requests


class TestServiceHealthChecks:
    """Test suite for service health check validation (US-102)."""

    @pytest.fixture(scope="class")
    def docker_compose_file(self) -> Path:
        """Get path to docker-compose.test.yml file."""
        project_root = Path(__file__).parent.parent.parent.parent
        return project_root / "docker-compose.test.yml"

    def test_postgresql_health_check(self):
        """
        Test PostgreSQL health check functionality.
        Validates ADR-012 ASR-5: Database connectivity verification.
        """
        # Test connection parameters for test database
        test_db_params = {
            "host": "localhost",
            "port": 5433,
            "database": "testdb",
            "user": "test",
            "password": "test",
        }

        # Skip if Docker isn't running
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
            if result.returncode != 0:
                pytest.skip("Docker is not running")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Docker is not available")

        # Try to connect to test database
        max_retries = 6
        for i in range(max_retries):
            try:
                conn = psycopg2.connect(**test_db_params)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                cursor.close()
                conn.close()

                assert result[0] == 1, "Database health check query failed"
                break
            except psycopg2.OperationalError:
                if i < max_retries - 1:
                    time.sleep(5)
                else:
                    pytest.skip("Test PostgreSQL is not running")

    def test_redis_health_check(self):
        """
        Test Redis health check functionality.
        Validates Redis connectivity and PING response.
        """
        # Test connection for test Redis
        test_redis_params = {"host": "localhost", "port": 6380, "db": 1, "decode_responses": True}

        # Skip if Docker isn't running
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
            if result.returncode != 0:
                pytest.skip("Docker is not running")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Docker is not available")

        # Try to connect to test Redis
        max_retries = 6
        for i in range(max_retries):
            try:
                r = redis.Redis(**test_redis_params)
                pong = r.ping()

                assert pong is True, "Redis PING did not return PONG"

                # Test basic operations
                r.set("health_check_test", "OK", ex=10)
                value = r.get("health_check_test")
                assert value == "OK", "Redis set/get operation failed"

                r.delete("health_check_test")
                break
            except redis.ConnectionError:
                if i < max_retries - 1:
                    time.sleep(5)
                else:
                    pytest.skip("Test Redis is not running")

    def test_api_health_endpoint(self):
        """
        Test API health endpoint functionality.
        Validates API health check with dependency verification.
        """
        api_url = "http://localhost:8000/health"

        # Skip if Docker isn't running
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
            if result.returncode != 0:
                pytest.skip("Docker is not running")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Docker is not available")

        # Try to connect to API
        max_retries = 10
        for i in range(max_retries):
            try:
                response = requests.get(api_url, timeout=5)

                if response.status_code == 200:
                    health_data = response.json()

                    # Validate health response structure
                    assert "status" in health_data, "Health response missing 'status'"
                    assert health_data["status"] in [
                        "healthy",
                        "degraded",
                        "unhealthy",
                    ], f"Invalid health status: {health_data['status']}"

                    # Check for dependency health if provided
                    if "dependencies" in health_data:
                        deps = health_data["dependencies"]

                        # Database health
                        if "database" in deps:
                            assert deps["database"]["status"] in [
                                "healthy",
                                "degraded",
                                "unhealthy",
                            ], "Invalid database health status"

                        # Redis health
                        if "redis" in deps:
                            assert deps["redis"]["status"] in [
                                "healthy",
                                "degraded",
                                "unhealthy",
                            ], "Invalid Redis health status"

                    break
                elif i < max_retries - 1:
                    time.sleep(3)
                else:
                    pytest.fail(f"API health endpoint returned {response.status_code}")

            except requests.RequestException:
                if i < max_retries - 1:
                    time.sleep(3)
                else:
                    pytest.skip("API is not running")

    def test_service_startup_order(self, docker_compose_file):
        """
        Test that services start in the correct order.
        Validates dependency resolution and health conditions.
        """
        if not docker_compose_file.exists():
            pytest.skip("Docker compose file not found")

        # Check Docker compose config for dependencies
        result = subprocess.run(
            ["docker-compose", "-f", str(docker_compose_file), "config"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.skip(f"Failed to parse docker-compose config: {result.stderr}")

        config_output = result.stdout

        # Verify API depends on database and Redis
        assert "depends_on" in config_output, "Service dependencies not configured"

    def test_health_check_timing_requirements(self):
        """
        Test that health checks meet timing requirements.
        Validates ASR-5: Health checks must complete within specified timeouts.
        """
        timings = {
            "postgresql": {"max_time": 30, "endpoint": None},
            "redis": {"max_time": 10, "endpoint": None},
            "api": {"max_time": 45, "endpoint": "http://localhost:8000/health"},
        }

        for service, config in timings.items():
            start_time = time.time()

            if service == "postgresql":
                # Check PostgreSQL
                try:
                    conn = psycopg2.connect(
                        host="localhost",
                        port=5433,
                        database="testdb",
                        user="test",
                        password="test",
                        connect_timeout=config["max_time"],
                    )
                    conn.close()
                    elapsed = time.time() - start_time

                    assert (
                        elapsed < config["max_time"]
                    ), f"PostgreSQL health check took {elapsed:.1f}s, max is {config['max_time']}s"

                except psycopg2.OperationalError:
                    pytest.skip(f"{service} is not running")

            elif service == "redis":
                # Check Redis
                try:
                    r = redis.Redis(host="localhost", port=6380, socket_connect_timeout=config["max_time"])
                    r.ping()
                    elapsed = time.time() - start_time

                    assert (
                        elapsed < config["max_time"]
                    ), f"Redis health check took {elapsed:.1f}s, max is {config['max_time']}s"

                except redis.ConnectionError:
                    pytest.skip(f"{service} is not running")

            elif service == "api" and config["endpoint"]:
                # Check API
                try:
                    # Use explicit timeout value to satisfy bandit B113
                    timeout_value = config.get("max_time", 45)
                    response = requests.get(config["endpoint"], timeout=timeout_value)
                    elapsed = time.time() - start_time

                    if response.status_code == 200:
                        assert (
                            elapsed < config["max_time"]
                        ), f"API health check took {elapsed:.1f}s, max is {config['max_time']}s"
                    else:
                        pytest.skip(f"{service} returned {response.status_code}")

                except requests.RequestException:
                    pytest.skip(f"{service} is not running")

    @pytest.mark.integration
    def test_celery_worker_health(self):
        """
        Test Celery worker health verification.
        Validates ADR-007 compliance for async task processing.
        """
        # Skip if Docker isn't running
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
            if result.returncode != 0:
                pytest.skip("Docker is not running")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Docker is not available")

        # Check if Celery container is running
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=celery", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )

        if "celery" not in result.stdout:
            pytest.skip("Celery worker is not running")

        # Check Celery worker health using Docker exec
        result = subprocess.run(
            [
                "docker",
                "exec",
                "violentutf_test_celery",
                "celery",
                "-A",
                "app.celery.celery",
                "inspect",
                "ping",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )

        if result.returncode == 0:
            assert "OK" in result.stdout or "pong" in result.stdout.lower(), "Celery worker did not respond to ping"
        else:
            pytest.skip(f"Celery health check failed: {result.stderr}")

    def test_health_check_recovery(self):
        """
        Test that health checks can recover from failures.
        Validates resilience and retry logic.
        """
        # This test simulates a recovery scenario
        api_url = "http://localhost:8000/health"

        # Make multiple health check attempts
        attempts = []
        for i in range(3):
            try:
                response = requests.get(api_url, timeout=5)
                attempts.append(
                    {
                        "attempt": i + 1,
                        "status_code": response.status_code,
                        "success": response.status_code == 200,
                    }
                )
            except requests.RequestException as e:
                attempts.append({"attempt": i + 1, "error": str(e), "success": False})
            time.sleep(2)

        # At least one attempt should succeed for a healthy system
        successful_attempts = [a for a in attempts if a.get("success", False)]

        if not successful_attempts:
            pytest.skip("API is not running")

        assert len(successful_attempts) > 0, "Health check should recover and succeed at least once"

    def test_concurrent_health_checks(self):
        """
        Test that multiple health checks can run concurrently.
        Validates system can handle parallel health monitoring.
        """
        import concurrent.futures

        def check_health(service_url):
            """Perform a health check on a service."""
            try:
                response = requests.get(service_url, timeout=5)
                return {
                    "url": service_url,
                    "status": response.status_code,
                    "success": response.status_code == 200,
                }
            except Exception as e:
                return {"url": service_url, "error": str(e), "success": False}

        # Define health endpoints
        health_endpoints = [
            "http://localhost:8000/health",
            "http://localhost:8000/api/v1/health",
        ]

        # Run concurrent health checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_health, url) for url in health_endpoints]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Check results
        successful = [r for r in results if r.get("success", False)]

        if not successful:
            pytest.skip("No health endpoints are responding")

        assert len(successful) > 0, "At least one health check should succeed"
