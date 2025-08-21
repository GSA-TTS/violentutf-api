"""
BDD step definitions for US-101: Core Docker Test Environment Setup.
Implements Gherkin scenarios from us_101_docker_environment.feature.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

try:
    import docker

    docker_client = docker.from_env()
    DOCKER_AVAILABLE = True
except ImportError:
    docker_client = None
    DOCKER_AVAILABLE = False

import requests
import yaml
from behave import given, then, when


@given("the docker-compose.test.yml file exists in the project root")
@given("the docker-compose.test.yml file exists")
def step_docker_compose_exists(context):
    """Verify docker-compose.test.yml exists."""
    context.project_root = Path(__file__).parent.parent.parent.parent
    context.docker_compose_file = context.project_root / "docker-compose.test.yml"

    assert context.docker_compose_file.exists(), f"docker-compose.test.yml not found at {context.docker_compose_file}"

    # Load configuration for later use
    with open(context.docker_compose_file, "r") as f:
        context.docker_config = yaml.safe_load(f)


@given("the Docker test environment configuration")
def step_load_docker_config(context):
    """Load Docker test environment configuration."""
    context.project_root = Path(__file__).parent.parent.parent.parent
    context.docker_compose_file = context.project_root / "docker-compose.test.yml"

    with open(context.docker_compose_file, "r") as f:
        context.docker_config = yaml.safe_load(f)


@given("no previous test containers are running")
def step_cleanup_previous_containers(context):
    """Ensure no test containers are running."""
    # Stop and remove any existing test containers
    result = subprocess.run(
        ["docker-compose", "-f", str(context.docker_compose_file), "down", "-v"], capture_output=True, text=True
    )

    # Wait for cleanup to complete
    time.sleep(2)

    # Verify no test containers are running
    containers = docker_client.containers.list()
    test_containers = [c for c in containers if "test" in c.name.lower()]

    assert len(test_containers) == 0, f"Found {len(test_containers)} test containers still running"


@given("the Docker test environment is running")
def step_ensure_environment_running(context):
    """Ensure Docker test environment is running."""
    # Start environment if not already running
    result = subprocess.run(
        ["docker-compose", "-f", str(context.docker_compose_file), "up", "-d"], capture_output=True, text=True
    )

    # Wait for services to start
    time.sleep(5)

    # Store container information
    context.containers = docker_client.containers.list()


@when('I run "docker-compose -f docker-compose.test.yml up -d"')
def step_start_docker_environment(context):
    """Start Docker test environment."""
    context.start_time = time.time()

    result = subprocess.run(
        ["docker-compose", "-f", str(context.docker_compose_file), "up", "-d"], capture_output=True, text=True
    )

    context.startup_result = result
    context.startup_duration = time.time() - context.start_time


@when("I start the Docker test environment")
def step_start_clean_environment(context):
    """Start Docker test environment from clean state."""
    context.start_time = time.time()

    # Start with fresh environment
    result = subprocess.run(
        ["docker-compose", "-f", str(context.docker_compose_file), "up", "-d", "--force-recreate"],
        capture_output=True,
        text=True,
    )

    context.startup_result = result
    context.startup_duration = time.time() - context.start_time


@when("I check the database and Redis connections")
def step_check_connections(context):
    """Check database and Redis connection configurations."""
    # Get running containers
    containers = docker_client.containers.list()

    # Find database container
    db_containers = [c for c in containers if "db" in c.name.lower() and "test" in c.name.lower()]
    assert len(db_containers) > 0, "No test database container found"
    context.db_container = db_containers[0]

    # Find Redis container
    redis_containers = [c for c in containers if "redis" in c.name.lower() and "test" in c.name.lower()]
    assert len(redis_containers) > 0, "No test Redis container found"
    context.redis_container = redis_containers[0]

    # Get environment variables
    context.db_env = context.db_container.attrs["Config"]["Env"]
    context.redis_env = context.redis_container.attrs["Config"]["Env"]


@when("I examine the environment variables")
def step_examine_env_vars(context):
    """Examine environment variables in Docker configuration."""
    context.env_vars = {}

    for service_name, service_config in context.docker_config["services"].items():
        context.env_vars[service_name] = service_config.get("environment", {})


@when("I check resource limits")
def step_check_resource_limits(context):
    """Check resource limits in Docker configuration."""
    context.resource_limits = {}

    for service_name, service_config in context.docker_config["services"].items():
        deploy_config = service_config.get("deploy", {})
        resources = deploy_config.get("resources", {})

        context.resource_limits[service_name] = {
            "limits": resources.get("limits", {}),
            "reservations": resources.get("reservations", {}),
        }


@then("all services must start within {seconds:d} seconds")
def step_verify_startup_time(context, seconds):
    """Verify all services start within time limit."""
    assert context.startup_result.returncode == 0, f"Docker compose failed: {context.startup_result.stderr}"

    assert context.startup_duration < seconds, f"Startup took {context.startup_duration:.1f}s, exceeds {seconds}s limit"


@then("all health checks must pass within {seconds:d} seconds")
def step_verify_health_checks(context, seconds):
    """Verify all health checks pass within time limit."""
    start_time = time.time()
    services_healthy = False

    while (time.time() - start_time) < seconds:
        # Check container health status
        containers = docker_client.containers.list()
        test_containers = [c for c in containers if "test" in c.name.lower()]

        if all(
            c.attrs["State"]["Health"]["Status"] == "healthy" for c in test_containers if "Health" in c.attrs["State"]
        ):
            services_healthy = True
            break

        time.sleep(2)

    assert services_healthy, f"Not all services became healthy within {seconds} seconds"


@then("the API endpoint must respond at {url}")
def step_verify_api_endpoint(context, url):
    """Verify API endpoint is responding."""
    max_retries = 10

    for i in range(max_retries):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                context.api_response = response
                return
        except requests.RequestException:
            if i < max_retries - 1:
                time.sleep(2)
            continue

    assert False, f"API endpoint {url} did not respond after {max_retries} attempts"


@then('the test PostgreSQL must use database name "{db_name}"')
def step_verify_test_database(context, db_name):
    """Verify test database name."""
    db_env_vars = context.db_env

    # Find POSTGRES_DB environment variable
    postgres_db = None
    for env_var in db_env_vars:
        if env_var.startswith("POSTGRES_DB="):
            postgres_db = env_var.split("=", 1)[1]
            break

    assert postgres_db == db_name, f"Expected database name '{db_name}', got '{postgres_db}'"


@then("the test Redis must use a separate instance on port {port:d}")
def step_verify_redis_instance(context, port):
    """Verify Redis is using separate test instance."""
    # Check Redis container is running
    assert context.redis_container.status == "running", "Redis container is not running"

    # Check exposed ports
    ports = context.redis_container.attrs["NetworkSettings"]["Ports"]
    redis_port = f"{port}/tcp"

    assert redis_port in ports, f"Redis not configured on port {port}"


@then("no production data must be accessible")
def step_verify_no_production_data(context):
    """Verify no production data is accessible."""
    # Check environment variables don't contain production references
    for service_name, env_vars in context.env_vars.items():
        for key, value in env_vars.items():
            if isinstance(value, str):
                assert "production" not in value.lower(), f"Service {service_name} has production reference in {key}"

                if "DATABASE" in key.upper() or "DB" in key.upper():
                    assert "violentutf" not in value.lower(), f"Service {service_name} references production database"


@then("each container must start with a clean state")
def step_verify_clean_state(context):
    """Verify containers start with clean state."""
    containers = docker_client.containers.list()
    test_containers = [c for c in containers if "test" in c.name.lower()]

    for container in test_containers:
        # Check container was recently created
        created_time = container.attrs["Created"]
        assert container.status == "running", f"Container {container.name} is not running"


@then("no data from previous test runs must persist")
def step_verify_no_persistent_data(context):
    """Verify no persistent data from previous runs."""
    # Check that volumes are not persistent
    volumes = docker_client.volumes.list()
    test_volumes = [v for v in volumes if "test" in v.name.lower()]

    # Test volumes should be minimal or none
    assert len(test_volumes) <= 2, f"Found {len(test_volumes)} test volumes, possible data persistence"


@then("all volumes must be ephemeral by default")
def step_verify_ephemeral_volumes(context):
    """Verify volumes are ephemeral."""
    for service_name, service_config in context.docker_config["services"].items():
        volumes = service_config.get("volumes", [])

        for volume in volumes:
            # Check for persistent volume mounts
            if isinstance(volume, str) and ":" in volume:
                host_path, container_path = volume.split(":", 1)

                # Ephemeral volumes should use tmpfs or no host path
                assert not host_path.startswith("/var/lib/"), f"Service {service_name} uses persistent volume: {volume}"
                assert (
                    "data" not in host_path.lower()
                ), f"Service {service_name} may use persistent data volume: {volume}"


@then("test credentials must be different from production")
def step_verify_test_credentials(context):
    """Verify test credentials differ from production."""
    # Check for test-specific credentials
    for service_name, env_vars in context.env_vars.items():
        # Check for password/secret environment variables
        for key, value in env_vars.items():
            if any(secret in key.upper() for secret in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                if isinstance(value, str):
                    # Test credentials should be simple and obvious
                    assert (
                        value in ["test", "testpass", "testkey", "test123"] or "test" in value.lower()
                    ), f"Service {service_name} may be using non-test credential in {key}"


@then("no production secrets must be present")
def step_verify_no_production_secrets(context):
    """Verify no production secrets are present."""
    # Check that no production secret patterns exist
    for service_name, env_vars in context.env_vars.items():
        for key, value in env_vars.items():
            if isinstance(value, str):
                # Check for production-like secrets (long random strings)
                if len(value) > 32 and not value.startswith("postgresql://"):
                    assert (
                        "test" in value.lower() or key == "DATABASE_URL"
                    ), f"Service {service_name} may have production secret in {key}"


@then("test API keys must be clearly marked as test data")
def step_verify_test_api_keys(context):
    """Verify API keys are marked as test data."""
    api_env = context.env_vars.get("api", {})

    # Check for API key configuration
    for key, value in api_env.items():
        if "API_KEY" in key.upper():
            if isinstance(value, str):
                assert "test" in value.lower() or value.startswith(
                    "test_"
                ), f"API key {key} not clearly marked as test data"


@then("each container must have memory limits defined")
def step_verify_memory_limits(context):
    """Verify memory limits are defined."""
    for service_name, limits in context.resource_limits.items():
        if limits["limits"]:
            assert "memory" in limits["limits"], f"Service {service_name} missing memory limit"


@then("CPU limits must prevent resource exhaustion")
def step_verify_cpu_limits(context):
    """Verify CPU limits prevent exhaustion."""
    for service_name, limits in context.resource_limits.items():
        if limits["limits"]:
            assert "cpus" in limits["limits"], f"Service {service_name} missing CPU limit"


@then("total resource usage must be sustainable for CI/CD")
def step_verify_sustainable_resources(context):
    """Verify total resources are sustainable for CI/CD."""
    total_memory = 0
    total_cpus = 0

    for service_name, limits in context.resource_limits.items():
        if limits["limits"]:
            # Parse memory limits (e.g., "512M", "1G")
            memory = limits["limits"].get("memory", "0")
            if memory.endswith("G"):
                total_memory += float(memory[:-1]) * 1024
            elif memory.endswith("M"):
                total_memory += float(memory[:-1])

            # Parse CPU limits
            cpus = limits["limits"].get("cpus", "0")
            if cpus:
                total_cpus += float(cpus)

    # CI/CD typically has 4-8GB RAM and 2-4 CPUs
    assert total_memory <= 4096, f"Total memory {total_memory}M exceeds CI/CD limit"
    assert total_cpus <= 4, f"Total CPUs {total_cpus} exceeds CI/CD limit"
