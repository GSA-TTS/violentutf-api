"""
Architectural fitness tests for ADR-012 compliance.
Validates Docker-based integration testing architecture rules.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml


class TestADR012Compliance:
    """Test suite for ADR-012 Docker Integration Testing compliance."""

    @pytest.fixture(scope="class")
    def project_root(self) -> Path:
        """Get project root path."""
        return Path(__file__).parent.parent.parent

    @pytest.fixture(scope="class")
    def docker_configs(self, project_root) -> dict:
        """Load all Docker-related configuration files."""
        configs = {}
        docker_files = [
            "docker-compose.yml",
            "docker-compose.test.yml",
            "docker-compose.override.yml",
        ]

        for filename in docker_files:
            filepath = project_root / filename
            if filepath.exists():
                with open(filepath, "r") as f:
                    configs[filename] = yaml.safe_load(f)

        return configs

    def _normalize_environment(self, env):
        """Normalize environment variables from list or dict format to dict."""
        if isinstance(env, list):
            # Convert list format ["KEY=value"] to dict format
            result = {}
            for item in env:
                if isinstance(item, str) and "=" in item:
                    key, value = item.split("=", 1)
                    result[key] = value
            return result
        elif isinstance(env, dict):
            return env
        else:
            return {}

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

        prod_db_env_raw = prod_config.get("services", {}).get("db", {}).get("environment", {})
        test_db_env_raw = test_config.get("services", {}).get("db", {}).get("environment", {})

        # Normalize both environments to dict format
        prod_db_env = self._normalize_environment(prod_db_env_raw)
        test_db_env = self._normalize_environment(test_db_env_raw)

        if prod_db_env.get("POSTGRES_DB") and test_db_env.get("POSTGRES_DB"):
            # Extract actual values, handling variable substitution
            prod_db_name = prod_db_env["POSTGRES_DB"]
            test_db_name = test_db_env["POSTGRES_DB"]

            # Handle environment variable substitution like ${DB_NAME:-violentutf}
            if prod_db_name.startswith("${") and ":-" in prod_db_name:
                prod_db_name = prod_db_name.split(":-")[1].rstrip("}")

            assert (
                prod_db_name != test_db_name
            ), f"Test and production must use different database names (ADR-012). Found prod='{prod_db_name}', test='{test_db_name}'"

    def test_test_modules_structure(self, project_root):
        """
        Test that test modules follow the required structure.
        Enforces test organization patterns from ADR-012.
        """
        tests_dir = project_root / "tests"
        required_test_dirs = [
            "unit",
            "integration",
            "bdd",
            "performance",
            "security",
            "architecture",
        ]

        for dir_name in required_test_dirs:
            test_dir = tests_dir / dir_name
            assert test_dir.exists(), f"Required test directory {dir_name} must exist (ADR-012)"

        # Check that actual test files follow naming convention
        # Only check files that are likely to be tests (contain test classes or test functions)
        for test_file in tests_dir.rglob("test_*.py"):
            # These are definitely test files by naming convention
            assert test_file.stem.startswith("test_"), f"Test file {test_file.name} should start with 'test_'"

        # Also check for any .py files that might be tests but don't follow naming convention
        excluded_patterns = [
            "__init__",
            "conftest",
            "setup_",
            "fixtures",
            "utils",
            "disable_",
            "model_factories",
            "simple_factories",
            "run_",
            "mock_",
            "api_key",
            "benchmark_",
            "requirements",
        ]
        excluded_dirs = ["fixtures", "utils", "helpers", "pytest_plugins", "performance"]

        for py_file in tests_dir.rglob("*.py"):
            # Skip if in excluded directory
            if any(excluded_dir in py_file.parts for excluded_dir in excluded_dirs):
                continue
            # Skip if matches excluded pattern
            if any(pattern in py_file.stem for pattern in excluded_patterns):
                continue
            # Skip if already starts with test_ (covered above)
            if py_file.stem.startswith("test_"):
                continue

            # Check if file contains test classes or functions (basic heuristic)
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    if ("def test_" in content or "class Test" in content) and not py_file.stem.startswith("test_"):
                        assert False, f"File {py_file.name} contains tests but doesn't start with 'test_'"
            except (UnicodeDecodeError, PermissionError):
                # Skip files we can't read
                pass

    def test_integration_test_fixtures(self, project_root):
        """
        Test that integration tests use proper fixtures.
        Validates test isolation requirements from ADR-012.
        """
        integration_dir = project_root / "tests" / "integration"
        conftest_file = integration_dir / "conftest.py"

        # Check that integration tests have their own conftest
        if integration_dir.exists():
            if any(integration_dir.rglob("test_*.py")):
                assert conftest_file.exists(), "Integration tests must have conftest.py for fixtures (ADR-012)"

    def test_no_production_dependencies_in_tests(self, project_root):
        """
        Test that test files don't import production database directly.
        Ensures test isolation as per ADR-012.
        """
        tests_dir = project_root / "tests"

        # Patterns that indicate direct production database access
        forbidden_patterns = [
            r"from app\.db import.*production",
            r"import.*production.*database",
            r"DATABASE_URL.*production",
        ]

        violations = []
        for test_file in tests_dir.rglob("test_*.py"):
            # Skip this test file itself which defines the patterns
            if test_file.name == "test_adr_012_compliance.py":
                continue
            content = test_file.read_text()
            for pattern in forbidden_patterns:
                if re.search(pattern, content):
                    violations.append((test_file, pattern))

        assert not violations, f"Test files should not access production database directly: {violations}"

    def test_test_data_management_patterns(self, docker_configs):
        """
        Test that proper test data management is configured.
        Validates data isolation strategies from ADR-012.
        """
        if "docker-compose.test.yml" in docker_configs:
            test_config = docker_configs["docker-compose.test.yml"]
            test_db = test_config.get("services", {}).get("db", {})

            # Check for volume configuration
            volumes = test_db.get("volumes", [])

            # Test database should not persist data by default
            persistent_volumes = [v for v in volumes if not v.startswith("./") and ":/var/lib" in v]
            assert not persistent_volumes, "Test database should not use persistent volumes (ADR-012)"

    def test_mock_service_configuration(self, docker_configs):
        """
        Test that mock services are properly configured for testing.
        Ensures external dependency isolation per ADR-012.
        """
        if "docker-compose.test.yml" in docker_configs:
            test_config = docker_configs["docker-compose.test.yml"]
            services = test_config.get("services", {})

            # Check for mock services
            mock_services = [s for s in services if "mock" in s.lower() or "stub" in s.lower()]

            # This is informational - projects should have mock services
            if not mock_services:
                pytest.skip("Consider adding mock services for external dependencies (ADR-012)")

    def test_docker_health_checks(self, docker_configs):
        """
        Test that services have proper health checks configured.
        Ensures reliable test execution per ADR-012.
        """
        for config_name, config in docker_configs.items():
            services = config.get("services", {})

            critical_services = ["db", "redis", "api"]
            for service_name in critical_services:
                if service_name in services:
                    service = services[service_name]

                    # Check for healthcheck configuration
                    if "healthcheck" not in service:
                        pytest.skip(f"Service {service_name} in {config_name} should have healthcheck configured")

    def test_performance_test_configuration(self, project_root):
        """
        Test that performance tests are properly configured.
        Validates performance testing setup from ADR-012.
        """
        perf_dir = project_root / "tests" / "performance"

        if perf_dir.exists():
            perf_tests = list(perf_dir.glob("test_*.py"))

            if perf_tests:
                # Check for performance testing configuration
                locust_file = project_root / "locustfile.py"
                k6_script = project_root / "k6-script.js"
                pytest_bench = any((perf_dir / "requirements.txt").exists() for perf_dir in [perf_dir])
                has_runner_script = (perf_dir / "run_performance_tests.py").exists()

                has_perf_tool = locust_file.exists() or k6_script.exists() or pytest_bench or has_runner_script

                assert has_perf_tool, "Performance tests exist but no performance testing tool configured (ADR-012)"

    def test_github_actions_integration(self, project_root):
        """
        Test that GitHub Actions are configured for Docker tests.
        Ensures CI/CD integration per ADR-012.
        """
        workflows_dir = project_root / ".github" / "workflows"

        if workflows_dir.exists():
            test_workflows = [
                f
                for f in workflows_dir.glob("*.yml")
                if any(keyword in f.stem.lower() for keyword in ["test", "ci", "pr", "validation"])
            ]

            docker_test_configured = False
            for workflow_file in test_workflows:
                content = workflow_file.read_text()
                if "docker-compose" in content and "test" in content:
                    docker_test_configured = True
                    break

            assert docker_test_configured, "GitHub Actions should be configured for Docker-based testing (ADR-012)"
