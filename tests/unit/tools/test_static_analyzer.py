"""Tests for static dependency analyzer."""

import json
import tempfile
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml

from tools.dependency.static_analyzer import (
    ConfigurationDependency,
    DependencyAnalysisResult,
    ServiceDependency,
    StaticDependencyAnalyzer,
)


class TestStaticDependencyAnalyzer:
    """Test cases for StaticDependencyAnalyzer."""

    @pytest.fixture
    def sample_docker_compose(self):
        """Sample docker-compose.yml content."""
        return {
            "version": "3.8",
            "services": {
                "api": {
                    "build": {"context": "."},
                    "ports": ["8000:8000"],
                    "depends_on": {"db": {"condition": "service_healthy"}, "redis": {"condition": "service_healthy"}},
                    "healthcheck": {"test": ["CMD", "curl", "-f", "http://localhost:8000/health"]},
                    "environment": ["DATABASE_URL=postgresql://...", "REDIS_URL=redis://..."],
                    "volumes": ["./app:/app/app:ro", "./logs:/app/logs"],
                    "networks": ["violentutf-network"],
                },
                "db": {
                    "image": "postgres:15-alpine",
                    "environment": ["POSTGRES_USER=test", "POSTGRES_DB=test"],
                    "volumes": ["postgres_data:/var/lib/postgresql/data"],
                    "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U test"]},
                    "networks": ["violentutf-network"],
                },
                "redis": {
                    "image": "redis:7-alpine",
                    "volumes": ["redis_data:/data"],
                    "healthcheck": {"test": ["CMD", "redis-cli", "ping"]},
                    "networks": ["violentutf-network"],
                },
            },
            "volumes": {"postgres_data": {"driver": "local"}, "redis_data": {"driver": "local"}},
            "networks": {"violentutf-network": {"driver": "bridge"}},
        }

    @pytest.fixture
    def sample_config_py(self):
        """Sample config.py content with Settings class."""
        return """
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = Field(..., description="Database connection URL")
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    SECRET_KEY: str = Field(..., min_length=32)
    DEBUG: bool = Field(default=False)
    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=10, le=1000)
"""

    @pytest.fixture
    def temp_project(self, sample_docker_compose, sample_config_py):
        """Create a temporary project structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create docker-compose.yml
            docker_compose_path = project_path / "docker-compose.yml"
            with open(docker_compose_path, "w") as f:
                yaml.dump(sample_docker_compose, f)

            # Create config.py
            config_dir = project_path / "app" / "core"
            config_dir.mkdir(parents=True)
            config_path = config_dir / "config.py"
            with open(config_path, "w") as f:
                f.write(sample_config_py)

            yield project_path

    def test_analyzer_initialization(self, temp_project):
        """Test analyzer initialization."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))

        assert analyzer.project_root == temp_project
        assert analyzer.docker_compose_path == temp_project / "docker-compose.yml"
        assert analyzer.config_path == temp_project / "app" / "core" / "config.py"

    def test_docker_service_dependencies_analysis(self, temp_project):
        """Test Docker service dependency mapping from docker-compose.yml."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        service_deps = analyzer.analyze_docker_dependencies()

        # Should find 3 services
        assert len(service_deps) == 3

        # Check service names
        service_names = [dep.name for dep in service_deps]
        assert "api" in service_names
        assert "db" in service_names
        assert "redis" in service_names

        # Check API service dependencies
        api_service = next(dep for dep in service_deps if dep.name == "api")
        assert "db" in api_service.depends_on
        assert "redis" in api_service.depends_on
        assert api_service.service_type == "application"
        assert api_service.criticality == "critical"
        assert api_service.health_check is not None

        # Check database service
        db_service = next(dep for dep in service_deps if dep.name == "db")
        assert db_service.service_type == "database"
        assert db_service.criticality == "critical"
        assert "api" in db_service.dependents

        # Check Redis service
        redis_service = next(dep for dep in service_deps if dep.name == "redis")
        assert redis_service.service_type == "cache"
        assert redis_service.criticality == "important"
        assert "api" in redis_service.dependents

    def test_service_health_check_dependencies(self, temp_project):
        """Test health check dependency validation."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        service_deps = analyzer.analyze_docker_dependencies()

        # All services should have health checks
        for service in service_deps:
            assert service.health_check is not None

        # Check specific health check commands
        api_service = next(dep for dep in service_deps if dep.name == "api")
        assert "curl" in api_service.health_check

        db_service = next(dep for dep in service_deps if dep.name == "db")
        assert "pg_isready" in db_service.health_check

        redis_service = next(dep for dep in service_deps if dep.name == "redis")
        assert "redis-cli" in redis_service.health_check

    def test_network_dependency_mapping(self, temp_project):
        """Test inter-service network communication dependencies."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        network_deps = analyzer.analyze_network_dependencies()

        # All services should be on violentutf-network
        assert len(network_deps) == 3
        for service_name in ["api", "db", "redis"]:
            assert service_name in network_deps
            assert "violentutf-network" in network_deps[service_name]

    def test_volume_dependency_analysis(self, temp_project):
        """Test volume and data persistence dependencies."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        volume_deps = analyzer.analyze_volume_dependencies()

        # Check that services with volumes are identified
        assert "api" in volume_deps
        assert "db" in volume_deps
        assert "redis" in volume_deps

        # Check specific volume mappings
        assert "postgres_data" in volume_deps["db"]
        assert "redis_data" in volume_deps["redis"]
        assert any("bind_mount:" in vol for vol in volume_deps["api"])

    def test_configuration_dependencies_analysis(self, temp_project):
        """Test environment variable dependency mapping."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        config_deps = analyzer.analyze_configuration_dependencies()

        # Should find configuration fields
        assert len(config_deps) > 0

        # Check for specific configurations
        config_names = [dep.name for dep in config_deps]
        assert "DATABASE_URL" in config_names
        assert "REDIS_URL" in config_names
        assert "SECRET_KEY" in config_names
        assert "DEBUG" in config_names

        # Check required fields
        database_url_config = next(dep for dep in config_deps if dep.name == "DATABASE_URL")
        assert database_url_config.required == True

        # Check default values
        redis_url_config = next(dep for dep in config_deps if dep.name == "REDIS_URL")
        assert redis_url_config.default_value is not None

        # Check validation rules
        rate_limit_config = next(dep for dep in config_deps if dep.name == "RATE_LIMIT_PER_MINUTE")
        assert len(rate_limit_config.validation_rules) > 0

    def test_service_criticality_determination(self, temp_project):
        """Test service criticality level assessment."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        service_deps = analyzer.analyze_docker_dependencies()

        # Database and API should be critical
        db_service = next(dep for dep in service_deps if dep.name == "db")
        api_service = next(dep for dep in service_deps if dep.name == "api")
        assert db_service.criticality == "critical"
        assert api_service.criticality == "critical"

        # Redis should be important
        redis_service = next(dep for dep in service_deps if dep.name == "redis")
        assert redis_service.criticality == "important"

    def test_cascading_failure_scenarios(self, temp_project):
        """Test cascading failure scenario mapping."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        service_deps = analyzer.analyze_docker_dependencies()

        # Database failure should affect API
        db_service = next(dep for dep in service_deps if dep.name == "db")
        assert "api" in db_service.dependents

        # Redis failure should affect API
        redis_service = next(dep for dep in service_deps if dep.name == "redis")
        assert "api" in redis_service.dependents

        # API has no dependents (it's the top of the dependency chain)
        api_service = next(dep for dep in service_deps if dep.name == "api")
        assert len(api_service.dependents) == 0

    def test_comprehensive_analysis(self, temp_project):
        """Test complete end-to-end dependency discovery."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        result = analyzer.analyze_all_dependencies()

        # Check result structure
        assert isinstance(result, DependencyAnalysisResult)
        assert result.metadata is not None
        assert len(result.service_dependencies) > 0
        assert len(result.configuration_dependencies) > 0
        assert result.network_dependencies is not None
        assert result.volume_dependencies is not None
        assert result.analysis_summary is not None

        # Check metadata
        assert "analysis_date" in result.metadata
        assert "total_services" in result.metadata
        assert result.metadata["total_services"] == 3

        # Check analysis summary
        assert "service_analysis" in result.analysis_summary
        assert "configuration_analysis" in result.analysis_summary
        assert "infrastructure_analysis" in result.analysis_summary

    def test_results_export(self, temp_project):
        """Test dependency analysis results export."""
        analyzer = StaticDependencyAnalyzer(str(temp_project))
        result = analyzer.analyze_all_dependencies()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            output_path = temp_file.name

        try:
            analyzer.export_results(result, output_path)

            # Verify file was created and contains valid JSON
            assert Path(output_path).exists()

            with open(output_path, "r") as f:
                exported_data = json.load(f)

            # Check exported data structure
            assert "metadata" in exported_data
            assert "service_dependencies" in exported_data
            assert "configuration_dependencies" in exported_data
            assert "analysis_summary" in exported_data

        finally:
            # Clean up
            Path(output_path).unlink(missing_ok=True)

    def test_missing_docker_compose_file(self):
        """Test behavior when docker-compose.yml is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            analyzer = StaticDependencyAnalyzer(temp_dir)
            service_deps = analyzer.analyze_docker_dependencies()

            # Should return empty list when file is missing
            assert len(service_deps) == 0

    def test_missing_config_file(self):
        """Test behavior when config.py is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            analyzer = StaticDependencyAnalyzer(temp_dir)
            config_deps = analyzer.analyze_configuration_dependencies()

            # Should return empty list when file is missing
            assert len(config_deps) == 0

    def test_malformed_docker_compose(self):
        """Test behavior with malformed docker-compose.yml."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create malformed docker-compose.yml
            docker_compose_path = project_path / "docker-compose.yml"
            with open(docker_compose_path, "w") as f:
                f.write("invalid: yaml: content: [unclosed")

            analyzer = StaticDependencyAnalyzer(str(project_path))
            service_deps = analyzer.analyze_docker_dependencies()

            # Should handle error gracefully
            assert len(service_deps) == 0

    def test_malformed_config_file(self):
        """Test behavior with malformed config.py."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create config directory and malformed config.py
            config_dir = project_path / "app" / "core"
            config_dir.mkdir(parents=True)
            config_path = config_dir / "config.py"
            with open(config_path, "w") as f:
                f.write("def invalid python syntax:")

            analyzer = StaticDependencyAnalyzer(str(project_path))
            config_deps = analyzer.analyze_configuration_dependencies()

            # Should handle error gracefully
            assert len(config_deps) == 0
