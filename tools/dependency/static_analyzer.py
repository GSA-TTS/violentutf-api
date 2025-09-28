"""Static dependency analysis tool for ViolentUTF API."""

import ast
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class ServiceDependency:
    """Represents a service dependency."""

    name: str
    service_type: str
    depends_on: List[str]
    dependents: List[str]
    health_check: Optional[str]
    condition: Optional[str]
    criticality: str
    volumes: List[str]
    networks: List[str]
    ports: List[str]
    environment_variables: List[str]


@dataclass
class ConfigurationDependency:
    """Represents a configuration dependency."""

    name: str
    config_type: str
    depends_on: List[str]
    validation_rules: List[str]
    default_value: Optional[str]
    required: bool
    environment_variable: Optional[str]
    description: str


@dataclass
class DependencyAnalysisResult:
    """Results of dependency analysis."""

    metadata: Dict[str, Any]
    service_dependencies: List[ServiceDependency]
    configuration_dependencies: List[ConfigurationDependency]
    network_dependencies: Dict[str, List[str]]
    volume_dependencies: Dict[str, List[str]]
    analysis_summary: Dict[str, Any]


class StaticDependencyAnalyzer:
    """Static code analysis for dependency discovery."""

    def __init__(self, project_root: str):
        """Initialize the analyzer with project root path."""
        self.project_root = Path(project_root)
        self.docker_compose_path = self.project_root / "docker-compose.yml"
        self.config_path = self.project_root / "app" / "core" / "config.py"

        logger.info("StaticDependencyAnalyzer initialized", project_root=str(self.project_root))

    def analyze_all_dependencies(self) -> DependencyAnalysisResult:
        """Perform comprehensive static dependency analysis."""
        logger.info("Starting comprehensive dependency analysis")

        # Analyze different dependency types
        service_deps = self.analyze_docker_dependencies()
        config_deps = self.analyze_configuration_dependencies()
        network_deps = self.analyze_network_dependencies()
        volume_deps = self.analyze_volume_dependencies()

        # Generate analysis summary
        analysis_summary = self._generate_analysis_summary(service_deps, config_deps, network_deps, volume_deps)

        result = DependencyAnalysisResult(
            metadata={
                "analysis_date": datetime.now().isoformat(),
                "project_root": str(self.project_root),
                "analyzer_version": "1.0.0",
                "total_services": len(service_deps),
                "total_configurations": len(config_deps),
            },
            service_dependencies=service_deps,
            configuration_dependencies=config_deps,
            network_dependencies=network_deps,
            volume_dependencies=volume_deps,
            analysis_summary=analysis_summary,
        )

        logger.info("Dependency analysis completed", services=len(service_deps), configurations=len(config_deps))

        return result

    def analyze_docker_dependencies(self) -> List[ServiceDependency]:
        """Analyze Docker Compose service dependencies."""
        if not self.docker_compose_path.exists():
            logger.warning("Docker compose file not found", path=str(self.docker_compose_path))
            return []

        logger.info("Analyzing Docker service dependencies")

        try:
            with open(self.docker_compose_path, "r") as file:
                compose_data = yaml.safe_load(file)
        except Exception as e:
            logger.error("Failed to parse docker-compose.yml", error=str(e))
            return []

        services = compose_data.get("services", {})
        service_dependencies = []

        # First pass: collect all service names
        # all_services = set(services.keys())  # TODO: Use for validation if needed

        for service_name, service_config in services.items():
            # Extract depends_on relationships
            depends_on = []
            depends_on_config = service_config.get("depends_on", [])

            if isinstance(depends_on_config, list):
                depends_on = depends_on_config
            elif isinstance(depends_on_config, dict):
                depends_on = list(depends_on_config.keys())

            # Extract health check information
            health_check = None
            health_config = service_config.get("healthcheck", {})
            if health_config:
                test_command = health_config.get("test", [])
                if test_command and isinstance(test_command, list):
                    # Join all parts of the test command
                    health_check = " ".join(test_command)
                elif isinstance(test_command, str):
                    health_check = test_command

            # Extract condition information
            condition = None
            if isinstance(depends_on_config, dict):
                for dep, dep_config in depends_on_config.items():
                    if isinstance(dep_config, dict) and "condition" in dep_config:
                        condition = dep_config["condition"]
                        break

            # Determine service type and criticality
            service_type = self._determine_service_type(service_name, service_config)
            criticality = self._determine_service_criticality(service_name, service_type, depends_on)

            # Extract volumes, networks, ports, and environment variables
            volumes = self._extract_volumes(service_config)
            networks = self._extract_networks(service_config)
            ports = self._extract_ports(service_config)
            env_vars = self._extract_environment_variables(service_config)

            service_dep = ServiceDependency(
                name=service_name,
                service_type=service_type,
                depends_on=depends_on,
                dependents=[],  # Will be populated in second pass
                health_check=health_check,
                condition=condition,
                criticality=criticality,
                volumes=volumes,
                networks=networks,
                ports=ports,
                environment_variables=env_vars,
            )

            service_dependencies.append(service_dep)

        # Second pass: populate dependents
        self._populate_dependents(service_dependencies)

        logger.info("Docker service dependencies analyzed", count=len(service_dependencies))

        return service_dependencies

    def analyze_configuration_dependencies(self) -> List[ConfigurationDependency]:
        """Analyze configuration dependencies from config.py."""
        if not self.config_path.exists():
            logger.warning("Configuration file not found", path=str(self.config_path))
            return []

        logger.info("Analyzing configuration dependencies")

        try:
            with open(self.config_path, "r") as file:
                tree = ast.parse(file.read())
        except Exception as e:
            logger.error("Failed to parse config.py", error=str(e))
            return []

        config_dependencies = []

        # Find the Settings class
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "Settings":
                config_dependencies = self._extract_settings_dependencies(node)
                break

        logger.info("Configuration dependencies analyzed", count=len(config_dependencies))

        return config_dependencies

    def analyze_network_dependencies(self) -> Dict[str, List[str]]:
        """Analyze network dependencies between services."""
        if not self.docker_compose_path.exists():
            return {}

        logger.info("Analyzing network dependencies")

        try:
            with open(self.docker_compose_path, "r") as file:
                compose_data = yaml.safe_load(file)
        except Exception as e:
            logger.error("Failed to parse docker-compose.yml for networks", error=str(e))
            return {}

        services = compose_data.get("services", {})
        # networks = compose_data.get("networks", {})  # Reserved for future network analysis

        network_dependencies = {}

        # Map services to networks
        for service_name, service_config in services.items():
            service_networks = service_config.get("networks", [])
            if isinstance(service_networks, list):
                network_dependencies[service_name] = service_networks
            elif isinstance(service_networks, dict):
                network_dependencies[service_name] = list(service_networks.keys())
            else:
                # If no networks specified, service uses default network
                network_dependencies[service_name] = ["default"]

        logger.info("Network dependencies analyzed", services_count=len(network_dependencies))

        return network_dependencies

    def analyze_volume_dependencies(self) -> Dict[str, List[str]]:
        """Analyze volume dependencies between services."""
        if not self.docker_compose_path.exists():
            return {}

        logger.info("Analyzing volume dependencies")

        try:
            with open(self.docker_compose_path, "r") as file:
                compose_data = yaml.safe_load(file)
        except Exception as e:
            logger.error("Failed to parse docker-compose.yml for volumes", error=str(e))
            return {}

        services = compose_data.get("services", {})
        # volumes = compose_data.get("volumes", {})  # Reserved for future volume analysis

        volume_dependencies = {}

        # Map services to volumes
        for service_name, service_config in services.items():
            service_volumes = service_config.get("volumes", [])
            mapped_volumes = []

            for volume in service_volumes:
                if isinstance(volume, str):
                    # Extract volume name from volume mapping
                    volume_parts = volume.split(":")
                    if len(volume_parts) >= 2:
                        source = volume_parts[0]
                        # Check if it's a named volume or bind mount
                        if not source.startswith("./") and not source.startswith("/"):
                            mapped_volumes.append(source)
                        else:
                            mapped_volumes.append(f"bind_mount:{source}")

            if mapped_volumes:
                volume_dependencies[service_name] = mapped_volumes

        logger.info("Volume dependencies analyzed", services_count=len(volume_dependencies))

        return volume_dependencies

    def _determine_service_type(self, service_name: str, service_config: Dict[str, Any]) -> str:
        """Determine the type of service based on configuration."""
        image = service_config.get("image", "")
        command = service_config.get("command", "")

        if "postgres" in image:
            return "database"
        elif "redis" in image:
            return "cache"
        elif "nginx" in image:
            return "reverse_proxy"
        elif "celery" in command or "celery" in service_name:
            if "worker" in command or "worker" in service_name:
                return "worker"
            elif "flower" in command or "flower" in service_name:
                return "monitoring"
        elif "api" in service_name:
            return "application"
        else:
            return "unknown"

    def _determine_service_criticality(self, service_name: str, service_type: str, depends_on: List[str]) -> str:
        """Determine the criticality level of a service."""
        # Critical services
        if service_type in ["database", "application"]:
            return "critical"

        # Important services
        if service_type in ["cache", "worker"]:
            return "important"

        # Medium services
        if service_type in ["reverse_proxy", "monitoring"]:
            return "medium"

        # Services with many dependents are more critical
        if len(depends_on) >= 2:
            return "important"
        elif len(depends_on) == 1:
            return "medium"
        else:
            return "low"

    def _extract_volumes(self, service_config: Dict[str, Any]) -> List[str]:
        """Extract volume mappings from service configuration."""
        volumes = service_config.get("volumes", [])
        return [str(vol) for vol in volumes]

    def _extract_networks(self, service_config: Dict[str, Any]) -> List[str]:
        """Extract network mappings from service configuration."""
        networks = service_config.get("networks", [])
        if isinstance(networks, list):
            return networks
        elif isinstance(networks, dict):
            return list(networks.keys())
        else:
            return ["default"]

    def _extract_ports(self, service_config: Dict[str, Any]) -> List[str]:
        """Extract port mappings from service configuration."""
        ports = service_config.get("ports", [])
        return [str(port) for port in ports]

    def _extract_environment_variables(self, service_config: Dict[str, Any]) -> List[str]:
        """Extract environment variables from service configuration."""
        environment = service_config.get("environment", [])
        if isinstance(environment, list):
            return environment
        elif isinstance(environment, dict):
            return [f"{k}={v}" for k, v in environment.items()]
        else:
            return []

    def _populate_dependents(self, service_dependencies: List[ServiceDependency]) -> None:
        """Populate the dependents field for each service."""
        # Create a mapping of service name to dependency object
        service_map = {dep.name: dep for dep in service_dependencies}

        # For each service, add it as a dependent to its dependencies
        for service_dep in service_dependencies:
            for dependency_name in service_dep.depends_on:
                if dependency_name in service_map:
                    service_map[dependency_name].dependents.append(service_dep.name)

    def _extract_settings_dependencies(self, settings_class: ast.ClassDef) -> List[ConfigurationDependency]:
        """Extract configuration dependencies from Settings class."""
        config_dependencies = []

        for node in settings_class.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                field_name = node.target.id

                # Skip private fields and non-configuration fields
                if field_name.startswith("_") or field_name in ["model_config"]:
                    continue

                # Extract field information
                field_info = self._analyze_field_annotation(node)

                config_dep = ConfigurationDependency(
                    name=field_name,
                    config_type=field_info["type"],
                    depends_on=field_info["depends_on"],
                    validation_rules=field_info["validation_rules"],
                    default_value=field_info["default_value"],
                    required=field_info["required"],
                    environment_variable=field_name,  # Pydantic uses field name as env var
                    description=field_info["description"],
                )

                config_dependencies.append(config_dep)

        return config_dependencies

    def _analyze_field_annotation(self, node: ast.AnnAssign) -> Dict[str, Any]:
        """Analyze a field annotation to extract dependency information."""
        field_info = {
            "type": "unknown",
            "depends_on": [],
            "validation_rules": [],
            "default_value": None,
            "required": False,
            "description": "",
        }

        # Analyze type annotation
        if node.annotation:
            field_info["type"] = self._extract_type_name(node.annotation)

        # Analyze default value and Field() configuration
        if node.value:
            field_info.update(self._analyze_field_value(node.value))

        return field_info

    def _extract_type_name(self, annotation: ast.AST) -> str:
        """Extract type name from annotation."""
        if isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Name):
                return annotation.value.id
        elif isinstance(annotation, ast.Attribute):
            return f"{self._extract_type_name(annotation.value)}.{annotation.attr}"

        return "unknown"

    def _analyze_field_value(self, value: ast.AST) -> Dict[str, Any]:
        """Analyze field value to extract configuration information."""
        info = {"default_value": None, "required": False, "validation_rules": [], "description": ""}

        if isinstance(value, ast.Call):
            # Field() call
            if isinstance(value.func, ast.Name) and value.func.id == "Field":
                info.update(self._analyze_field_call(value))
        elif isinstance(value, ast.Constant):
            info["default_value"] = str(value.value)
        elif isinstance(value, ast.List):
            info["default_value"] = f"list[{len(value.elts)}]"
        elif isinstance(value, ast.Ellipsis):
            info["required"] = True
            info["default_value"] = "..."
        elif isinstance(value, ast.Name) and value.id == "Ellipsis":
            info["required"] = True
            info["default_value"] = "..."

        return info

    def _analyze_field_call(self, call: ast.Call) -> Dict[str, Any]:
        """Analyze Field() call to extract validation rules and constraints."""
        info = {"validation_rules": [], "description": ""}

        # Analyze positional arguments
        if call.args:
            arg = call.args[0]
            if isinstance(arg, ast.Constant):
                if arg.value is ...:  # Ellipsis constant
                    info["required"] = True
                    info["default_value"] = "..."
                else:
                    info["default_value"] = str(arg.value)
            elif isinstance(arg, ast.Ellipsis):
                info["required"] = True
                info["default_value"] = "..."
            elif isinstance(arg, ast.Name) and arg.id == "Ellipsis":
                info["required"] = True
                info["default_value"] = "..."
            else:
                # Check the representation to see if it's an ellipsis
                arg_repr = str(arg)
                if "..." in arg_repr or "Ellipsis" in arg_repr or "Ellipsis" in str(type(arg)):
                    info["required"] = True
                    info["default_value"] = "..."
                else:
                    info["default_value"] = arg_repr

        # Analyze keyword arguments
        for keyword in call.keywords:
            if keyword.arg == "default":
                if isinstance(keyword.value, ast.Constant):
                    info["default_value"] = str(keyword.value.value)
            elif keyword.arg == "description":
                if isinstance(keyword.value, ast.Constant):
                    info["description"] = str(keyword.value.value)
            elif keyword.arg in ["ge", "le", "gt", "lt", "min_length", "max_length", "pattern"]:
                rule = f"{keyword.arg}:"
                if isinstance(keyword.value, ast.Constant):
                    rule += str(keyword.value.value)
                info["validation_rules"].append(rule)

        return info

    def _generate_analysis_summary(
        self,
        service_deps: List[ServiceDependency],
        config_deps: List[ConfigurationDependency],
        network_deps: Dict[str, List[str]],
        volume_deps: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Generate analysis summary."""
        # Count services by type and criticality
        service_types = {}
        criticality_counts = {}

        for service in service_deps:
            service_types[service.service_type] = service_types.get(service.service_type, 0) + 1
            criticality_counts[service.criticality] = criticality_counts.get(service.criticality, 0) + 1

        # Count configuration types
        config_types = {}
        for config in config_deps:
            config_types[config.config_type] = config_types.get(config.config_type, 0) + 1

        # Calculate dependency complexity
        total_dependencies = sum(len(service.depends_on) for service in service_deps)
        avg_dependencies = total_dependencies / len(service_deps) if service_deps else 0

        return {
            "service_analysis": {
                "total_services": len(service_deps),
                "service_types": service_types,
                "criticality_distribution": criticality_counts,
                "average_dependencies_per_service": round(avg_dependencies, 2),
            },
            "configuration_analysis": {
                "total_configurations": len(config_deps),
                "configuration_types": config_types,
                "required_configurations": len([c for c in config_deps if c.required]),
            },
            "infrastructure_analysis": {
                "total_networks": len(set().union(*network_deps.values())) if network_deps else 0,
                "total_volumes": len(set().union(*volume_deps.values())) if volume_deps else 0,
                "services_with_volumes": len(volume_deps),
                "services_with_networks": len(network_deps),
            },
        }

    def export_results(self, result: DependencyAnalysisResult, output_path: str) -> None:
        """Export analysis results to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary for JSON serialization
        result_dict = {
            "metadata": result.metadata,
            "service_dependencies": [asdict(dep) for dep in result.service_dependencies],
            "configuration_dependencies": [asdict(dep) for dep in result.configuration_dependencies],
            "network_dependencies": result.network_dependencies,
            "volume_dependencies": result.volume_dependencies,
            "analysis_summary": result.analysis_summary,
        }

        with open(output_file, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info("Analysis results exported", output_path=str(output_file))


def main():
    """Main entry point for standalone execution."""
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = sys.argv[2] if len(sys.argv) > 2 else "dependency_analysis.json"

    analyzer = StaticDependencyAnalyzer(project_root)
    result = analyzer.analyze_all_dependencies()
    analyzer.export_results(result, output_path)

    print(f"Analysis completed. Results saved to {output_path}")


if __name__ == "__main__":
    main()
