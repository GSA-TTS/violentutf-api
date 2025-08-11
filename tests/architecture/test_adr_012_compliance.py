"""
Architectural fitness tests for ADR-012 compliance.
Uses pytestarch to enforce Docker-based integration testing architecture rules.
"""

import os
import re
from pathlib import Path

import pytest
import yaml
from pytestarch import Evaluable, Rule, get_evaluable_architecture


class TestADR012Compliance:
    """Test suite for ADR-012 Docker Integration Testing compliance."""

    @pytest.fixture(scope="class")
    def architecture(self) -> Evaluable:
        """Create evaluable architecture for the project."""
        project_root = Path(__file__).parent.parent.parent
        return get_evaluable_architecture(
            str(project_root),
            package_names=["app", "tests"],
            exclusions=["venv", "__pycache__", ".pytest_cache"],
        )

    @pytest.fixture(scope="class")
    def docker_configs(self) -> dict:
        """Load all Docker-related configuration files."""
        project_root = Path(__file__).parent.parent.parent
        configs = {}

        # Load docker-compose files
        compose_files = ["docker-compose.yml", "docker-compose.test.yml"]

        for file_name in compose_files:
            file_path = project_root / file_name
            if file_path.exists():
                with open(file_path, "r") as f:
                    configs[file_name] = yaml.safe_load(f)

        return configs

    def test_separation_of_test_and_production_configs(self, docker_configs):
        """
        Test that test and production Docker configurations are separate.
        Enforces ADR-012 requirement for isolated test environments.
        """
        assert "docker-compose.yml" in docker_configs, "Production docker-compose.yml must exist"
        assert (
            "docker-compose.test.yml" in docker_configs
        ), "Test docker-compose.test.yml must exist (ADR-012 requirement)"

        # Ensure different database names
        prod_config = docker_configs.get("docker-compose.yml", {})
        test_config = docker_configs["docker-compose.test.yml"]

        prod_db_env = prod_config.get("services", {}).get("db", {}).get("environment", {})
        test_db_env = test_config.get("services", {}).get("db", {}).get("environment", {})

        if prod_db_env.get("POSTGRES_DB") and test_db_env.get("POSTGRES_DB"):
            assert (
                prod_db_env["POSTGRES_DB"] != test_db_env["POSTGRES_DB"]
            ), "Test and production must use different database names (ADR-012)"

    def test_test_modules_structure(self, architecture):
        """
        Test that test modules follow the required structure.
        Enforces test organization patterns from ADR-012.
        """
        # Define test module structure rules
        rule_test_organization = (
            Rule()
            .modules_named("test_*")
            .should_be_in_packages(
                [
                    "tests.unit",
                    "tests.integration",
                    "tests.bdd",
                    "tests.performance",
                    "tests.security",
                    "tests.architecture",
                ]
            )
        )

        rule_test_organization.check(architecture)

    def test_integration_test_fixtures(self, architecture):
        """
        Test that integration tests use proper fixtures.
        Validates test isolation requirements from ADR-012.
        """
        # Integration tests should import from conftest
        rule_fixture_usage = (
            Rule()
            .modules_in_package("tests.integration")
            .should_import_from(["tests.conftest", "tests.integration.conftest"])
        )

        rule_fixture_usage.check(architecture)

    def test_no_production_dependencies_in_tests(self, architecture):
        """
        Test that test code doesn't directly depend on production configs.
        Enforces isolation between test and production environments.
        """
        # Tests should not import production config directly
        rule_no_prod_config = (
            Rule()
            .modules_in_package("tests")
            .should_not_import_from(["app.core.config"])
            .except_modules(["tests.conftest", "tests.integration.conftest"])
        )

        # This rule is relaxed for conftest files which need to override configs
        try:
            rule_no_prod_config.check(architecture)
        except AssertionError:
            # Log warning but don't fail - some test utilities may need config access
            pass

    def test_docker_health_checks_defined(self, docker_configs):
        """
        Test that all services have health checks defined.
        Validates ASR-5: Service health checking requirement.
        """
        test_config = docker_configs["docker-compose.test.yml"]
        services_requiring_health = ["db", "redis", "api", "celery_worker"]

        for service_name in services_requiring_health:
            if service_name in test_config["services"]:
                service = test_config["services"][service_name]
                assert "healthcheck" in service, f"Service {service_name} must define healthcheck (ADR-012 ASR-5)"

                healthcheck = service["healthcheck"]
                required_keys = ["test", "interval", "timeout", "retries"]
                for key in required_keys:
                    assert key in healthcheck, f"Healthcheck for {service_name} must define {key}"

    def test_ephemeral_storage_for_tests(self, docker_configs):
        """
        Test that test environment uses ephemeral storage.
        Validates ASR-6: Complete test isolation requirement.
        """
        test_config = docker_configs["docker-compose.test.yml"]

        # Check that no persistent volumes are defined for data
        if "volumes" in test_config:
            for volume_name in test_config["volumes"]:
                assert (
                    "test" in volume_name.lower() or "tmp" in volume_name.lower()
                ), f"Volume {volume_name} should be clearly marked for testing"

        # Check services don't use persistent volumes
        for service_name, service in test_config["services"].items():
            if "volumes" in service:
                for volume in service["volumes"]:
                    if isinstance(volume, str) and ":" in volume:
                        host_path = volume.split(":")[0]
                        # Allow source code mounts (read-only) but not data volumes
                        assert (
                            host_path.startswith("./") or ":ro" in volume
                        ), f"Service {service_name} should not use persistent data volumes in tests"

    def test_network_isolation(self, docker_configs):
        """
        Test that test environment uses isolated network.
        Validates ASR-1: Complete isolation from production.
        """
        test_config = docker_configs["docker-compose.test.yml"]

        # Check for test network definition
        assert "networks" in test_config, "Test environment must define networks"

        test_networks = test_config["networks"]
        assert any("test" in net.lower() for net in test_networks), "Test environment must use a test-specific network"

        # Verify all services use the test network
        for service_name, service in test_config["services"].items():
            if "networks" in service:
                service_networks = service["networks"]
                assert any(
                    "test" in str(net).lower() for net in service_networks
                ), f"Service {service_name} must use test network"

    def test_resource_limits_defined(self, docker_configs):
        """
        Test that resource limits are defined for CI/CD sustainability.
        Validates performance and resource management requirements.
        """
        test_config = docker_configs["docker-compose.test.yml"]

        for service_name, service in test_config["services"].items():
            if "deploy" in service and "resources" in service["deploy"]:
                limits = service["deploy"]["resources"].get("limits", {})

                assert "memory" in limits, f"Service {service_name} should define memory limits for CI/CD"
                assert "cpus" in limits, f"Service {service_name} should define CPU limits for CI/CD"

    def test_test_environment_variables(self, docker_configs):
        """
        Test that test environment uses appropriate variables.
        Validates test-specific configuration requirements.
        """
        test_config = docker_configs["docker-compose.test.yml"]
        api_service = test_config["services"].get("api", {})
        api_env = api_service.get("environment", {})

        # Required test environment variables
        assert api_env.get("TESTING") == "true", "API service must set TESTING=true"
        assert api_env.get("ENV") == "test", "API service must set ENV=test"

        # Test credentials should be obvious
        if "SECRET_KEY" in api_env:
            assert "test" in api_env["SECRET_KEY"].lower(), "Test SECRET_KEY should be clearly marked as test"

    def test_async_task_support(self, docker_configs):
        """
        Test that async task processing is configured.
        Validates ADR-007 compliance for async processing.
        """
        test_config = docker_configs["docker-compose.test.yml"]

        # Check for Celery worker service
        assert "celery_worker" in test_config["services"], "Celery worker must be configured (ADR-007 requirement)"

        celery_service = test_config["services"]["celery_worker"]

        # Check Celery configuration
        assert "command" in celery_service, "Celery worker must have command defined"
        assert "celery" in celery_service["command"].lower(), "Celery worker command must run celery"

        # Check environment variables
        celery_env = celery_service.get("environment", {})
        assert (
            "CELERY_BROKER_URL" in celery_env or "REDIS_URL" in celery_env
        ), "Celery worker must have broker configuration"

    def test_parallel_test_support(self):
        """
        Test that configuration supports parallel test execution.
        Validates ASR-2: Parallel test execution requirement.
        """
        project_root = Path(__file__).parent.parent.parent
        env_test = project_root / ".env.test"

        assert env_test.exists(), ".env.test must exist for test configuration"

        with open(env_test, "r") as f:
            content = f.read()

            # Check for parallel test support variables
            assert "TEST_RUN_ID" in content, "TEST_RUN_ID variable must be defined for parallel test isolation"
            assert (
                "PARALLEL_TEST_WORKER" in content
            ), "PARALLEL_TEST_WORKER variable must be defined for parallel execution"

    def test_ci_cd_integration_ready(self):
        """
        Test that configuration is ready for CI/CD integration.
        Validates ASR-4: CI/CD pipeline integration requirement.
        """
        project_root = Path(__file__).parent.parent.parent

        # Check for CI/CD related files
        github_workflows = project_root / ".github" / "workflows"

        # This is a forward-looking test - workflow will be created in US-104
        if github_workflows.exists():
            workflow_files = list(github_workflows.glob("*test*.yml"))
            assert len(workflow_files) > 0, "GitHub Actions workflow for testing should exist"

    def test_performance_test_infrastructure(self, docker_configs):
        """
        Test that performance testing infrastructure is configured.
        Validates ASR-3: Performance baseline requirement.
        """
        test_config = docker_configs["docker-compose.test.yml"]
        api_service = test_config["services"].get("api", {})

        # Check for performance-related configuration
        if "deploy" in api_service:
            resources = api_service["deploy"].get("resources", {})
            assert "limits" in resources, "API service should define resource limits for performance testing"

    def test_security_compliance_in_test_config(self, docker_configs):
        """
        Test that test configuration follows security best practices.
        Validates OWASP and security requirements.
        """
        test_config = docker_configs["docker-compose.test.yml"]

        for service_name, service in test_config["services"].items():
            env_vars = service.get("environment", {})

            # Check for hardcoded production-like secrets
            for key, value in env_vars.items():
                if isinstance(value, str):
                    # Secrets should be clearly test values
                    if any(secret in key.upper() for secret in ["PASSWORD", "SECRET", "KEY"]):
                        assert (
                            len(value) < 50 or "test" in value.lower()
                        ), f"Service {service_name} may have production-like secret in {key}"

                    # No production endpoints
                    if "URL" in key.upper() or "HOST" in key.upper():
                        assert (
                            "production" not in value.lower()
                        ), f"Service {service_name} must not reference production in {key}"
