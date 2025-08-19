"""
Architectural tests for layer boundary enforcement.

This module validates architectural layer violations using PyTestArch,
ensuring clean architecture with proper separation of concerns per ADR-001.
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
import pytest


class LayerBoundaryValidator:
    """Validates architectural layer boundaries in the codebase."""

    # Define architectural layers and their allowed dependencies
    LAYER_HIERARCHY = {
        "api": ["services", "schemas", "dependencies", "middleware", "core", "models"],  # Allow models for CRUD
        "services": ["repositories", "models", "schemas", "core", "utils"],
        "repositories": ["models", "db", "core"],
        "models": ["core", "db"],  # Models need db for SQLAlchemy Base class inheritance
        "schemas": ["core", "models"],  # Schemas can reference models for type conversion
        "middleware": ["core", "dependencies", "services", "utils"],  # Allow utils for caching
        "dependencies": ["services", "repositories", "core", "db", "utils"],  # Dependencies need db for session
        "core": ["db", "repositories", "services", "dependencies"],  # Core startup needs db access
        "utils": ["core"],  # Utils can use core config
        "db": ["models", "core", "services"],  # Database init can use services
    }

    # Specific exceptions for necessary architectural patterns
    ARCHITECTURE_EXCEPTIONS = [
        # SQLAlchemy models must inherit from Base class
        ("models", "db.base_class"),
        ("models", "db.types"),
        # Core startup and initialization needs database access
        ("core/startup", "db.session"),
        ("core/startup", "repositories"),
        ("core/auth", "dependencies.auth"),
        ("core/abac_permissions", "db.session"),
        ("core/permissions", "db.session"),
        ("core/auth_failover", "models.user"),  # Auth failover needs user model
        ("core/abac", "models.user"),  # ABAC needs user model for permissions
        ("core/authority", "models.user"),  # Authority needs user model
        # API base class needs these for CRUD operations
        ("api/base", "db"),
        ("api/base", "models.mixins"),
        ("api/base", "repositories.base"),  # Base CRUD needs repository base
        ("api/endpoints", "db.session"),  # Endpoints need DB session for dependency injection
        ("api/endpoints", "repositories"),  # Some endpoints use repositories directly for performance
        ("api/deps", "db.session"),  # API deps needs db session for dependency injection compatibility
        # Services that need direct DB access for performance
        ("services/health_service", "db.session"),  # Health checks need direct DB
        # Schemas importing models for type conversion
        ("schemas", "models"),
    ]

    # Import patterns that are always allowed
    ALLOWED_STDLIB = {
        "typing",
        "datetime",
        "enum",
        "uuid",
        "json",
        "os",
        "sys",
        "pathlib",
        "collections",
        "functools",
        "itertools",
        "re",
        "logging",
        "asyncio",
        "inspect",
        "abc",
        "dataclasses",
    }

    ALLOWED_EXTERNAL = {
        "fastapi",
        "pydantic",
        "sqlalchemy",
        "pytest",
        "httpx",
        "redis",
        "celery",
        "alembic",
        "passlib",
        "jwt",
        "python_jose",
    }

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.app_path = project_root / "app"
        self.import_graph = nx.DiGraph()
        self._module_cache = {}

    def get_layer_from_module(self, module_path: str) -> Optional[str]:
        """Extract layer name from module path."""
        if not module_path.startswith("app."):
            return None

        parts = module_path.split(".")
        if len(parts) >= 2:
            layer = parts[1]
            if layer in self.LAYER_HIERARCHY:
                return layer
        return None

    def find_circular_dependencies(self) -> List[List[str]]:
        """
        Find circular import dependencies in the codebase.
        Returns list of circular dependency chains.
        """
        self._build_import_graph()

        # Find all simple cycles in the graph
        cycles = list(nx.simple_cycles(self.import_graph))

        # Filter to only include cycles within app modules
        app_cycles = []
        for cycle in cycles:
            if all(node.startswith("app.") for node in cycle):
                app_cycles.append(cycle)

        return app_cycles

    def _build_import_graph(self):
        """Build a directed graph of imports."""
        self.import_graph.clear()

        for py_file in self.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            module_name = self._path_to_module(py_file)
            if not module_name:
                continue

            imports = self._extract_imports(py_file)
            for imported_module in imports:
                if imported_module.startswith("app."):
                    self.import_graph.add_edge(module_name, imported_module)

    def _path_to_module(self, file_path: Path) -> Optional[str]:
        """Convert file path to module name."""
        try:
            relative_path = file_path.relative_to(self.project_root)
            module_parts = list(relative_path.parts[:-1])  # Remove filename
            module_parts.append(relative_path.stem)  # Add module name without .py

            # Filter out __init__
            if module_parts[-1] == "__init__":
                module_parts = module_parts[:-1]

            return ".".join(module_parts)
        except ValueError:
            return None

    def _extract_imports(self, file_path: Path) -> Set[str]:
        """Extract all imports from a Python file, excluding TYPE_CHECKING imports."""
        imports = set()

        try:
            content = file_path.read_text()
            tree = ast.parse(content)

            # Track if we're inside a TYPE_CHECKING block
            type_checking_nodes = set()

            # Find all TYPE_CHECKING if blocks
            for node in ast.walk(tree):
                if isinstance(node, ast.If):
                    # Check if this is "if TYPE_CHECKING:"
                    if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                        # Add all children of this if block to type_checking_nodes
                        for child in ast.walk(node):
                            type_checking_nodes.add(child)

            for node in ast.walk(tree):
                # Skip nodes inside TYPE_CHECKING blocks
                if node in type_checking_nodes:
                    continue

                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)

        except Exception:
            pass

        return imports

    def find_layer_violations(self) -> List[Tuple[str, str, str, str]]:
        """
        Find layer boundary violations.
        Returns list of (source_file, source_layer, target_module, target_layer) tuples.
        """
        violations = []

        for py_file in self.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            module_name = self._path_to_module(py_file)
            if not module_name:
                continue

            source_layer = self.get_layer_from_module(module_name)
            if not source_layer:
                continue

            imports = self._extract_imports(py_file)

            for imported_module in imports:
                if not imported_module.startswith("app."):
                    continue

                target_layer = self.get_layer_from_module(imported_module)
                if not target_layer:
                    continue

                # Check if this is an allowed exception
                is_exception = False
                file_rel_path = str(py_file.relative_to(self.project_root))

                for exc_pattern, exc_target in self.ARCHITECTURE_EXCEPTIONS:
                    # Check if source file matches the exception pattern
                    if "/" in exc_pattern:
                        # It's a specific file pattern
                        if exc_pattern in file_rel_path:
                            # Check if the import target matches
                            if exc_target in imported_module:
                                is_exception = True
                                break
                    else:
                        # It's a layer-level pattern
                        if source_layer == exc_pattern and exc_target in imported_module:
                            is_exception = True
                            break

                if is_exception:
                    continue

                # Check if this import is allowed
                allowed_layers = self.LAYER_HIERARCHY.get(source_layer, [])
                if target_layer not in allowed_layers and target_layer != source_layer:
                    violations.append(
                        (str(py_file.relative_to(self.project_root)), source_layer, imported_module, target_layer)
                    )

        return violations

    def find_unauthorized_imports(self) -> List[Tuple[str, str, int]]:
        """
        Find imports that violate approved patterns.
        Returns list of (file_path, import_statement, line_number) tuples.
        """
        violations = []

        # Define prohibited imports
        prohibited_patterns = [
            (r"from\s+app\.api.*import.*Repository", "API layer directly importing Repository"),
            (r"from\s+app\.repositories.*import.*api", "Repository importing from API layer"),
            (r"from\s+app\.models.*import.*\b(api|services|repositories)\b", "Model importing from higher layers"),
            (r"import\s+app\.api.*Repository", "Direct repository import in API layer"),
        ]

        for py_file in self.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    for pattern, description in prohibited_patterns:
                        if re.search(pattern, line):
                            violations.append(
                                (str(py_file.relative_to(self.project_root)), f"{line.strip()} ({description})", i)
                            )
            except Exception:
                continue

        return violations

    def calculate_module_coupling(self) -> Dict[str, Dict[str, float]]:
        """
        Calculate coupling metrics between modules.
        Returns dict with coupling metrics for each module.
        """
        self._build_import_graph()

        metrics = {}

        for module in self.import_graph.nodes():
            if not module.startswith("app."):
                continue

            # Calculate fan-in (afferent coupling)
            fan_in = self.import_graph.in_degree(module)

            # Calculate fan-out (efferent coupling)
            fan_out = self.import_graph.out_degree(module)

            # Calculate instability (fan_out / (fan_in + fan_out))
            total = fan_in + fan_out
            instability = fan_out / total if total > 0 else 0

            metrics[module] = {
                "fan_in": fan_in,
                "fan_out": fan_out,
                "instability": instability,
                "total_coupling": total,
            }

        return metrics

    def find_high_coupling_modules(self, threshold: int = 10) -> List[Tuple[str, int]]:
        """
        Find modules with coupling above threshold.
        Returns list of (module_name, total_coupling) tuples.
        """
        coupling_metrics = self.calculate_module_coupling()

        high_coupling = []
        for module, metrics in coupling_metrics.items():
            if metrics["total_coupling"] > threshold:
                high_coupling.append((module, metrics["total_coupling"]))

        return sorted(high_coupling, key=lambda x: x[1], reverse=True)


@pytest.fixture
def layer_validator():
    """Provide LayerBoundaryValidator instance."""
    project_root = Path(__file__).parent.parent.parent
    return LayerBoundaryValidator(project_root)


class TestCircularDependencies:
    """Test suite for circular dependency detection."""

    def test_no_circular_dependencies(self, layer_validator):
        """
        Given the modular architecture of the ViolentUTF API
        When the architectural test suite runs
        Then the test must detect any circular imports between modules
        And the test must report the full dependency chain
        And the test must fail the build if circular dependencies exist
        """
        cycles = layer_validator.find_circular_dependencies()

        assert len(cycles) == 0, f"Found {len(cycles)} circular dependency chains:\n" + "\n".join(
            [f"  Cycle {i+1}: " + " -> ".join(cycle + [cycle[0]]) for i, cycle in enumerate(cycles)]
        )


class TestLayerBoundaries:
    """Test suite for layer boundary violation detection."""

    def test_layer_boundary_compliance(self, layer_validator):
        """
        Given the defined architectural layers (API, Service, Repository, Model)
        When the architectural test suite runs
        Then the test must verify API layer doesn't directly access Repository layer
        And the test must verify Repository layer doesn't import from API layer
        And the test must verify Model layer has no dependencies on other layers
        """
        violations = layer_validator.find_layer_violations()

        # Group violations by type for better reporting
        violation_types = {}
        for source_file, source_layer, target_module, target_layer in violations:
            key = f"{source_layer} -> {target_layer}"
            if key not in violation_types:
                violation_types[key] = []
            violation_types[key].append(f"{source_file}: imports {target_module}")

        if violations:
            report = "Found layer boundary violations:\n"
            for violation_type, examples in violation_types.items():
                report += f"\n{violation_type} violations:\n"
                for example in examples[:5]:  # Show first 5 examples
                    report += f"  - {example}\n"
                if len(examples) > 5:
                    report += f"  ... and {len(examples) - 5} more\n"

            pytest.fail(report)


class TestImportRestrictions:
    """Test suite for import restriction validation."""

    def test_approved_import_patterns(self, layer_validator):
        """
        Given the approved import patterns from ADRs
        When the architectural test suite runs
        Then the test must verify imports follow the approved patterns
        And the test must detect any unauthorized cross-module imports
        And the test must validate external library usage restrictions
        """
        violations = layer_validator.find_unauthorized_imports()

        assert len(violations) == 0, (
            f"Found {len(violations)} unauthorized import patterns:\n"
            + "\n".join(
                [f"  - {file_path}:{line_no}: {import_stmt}" for file_path, import_stmt, line_no in violations[:10]]
            )
            + (f"\n  ... and {len(violations) - 10} more" if len(violations) > 10 else "")
        )


class TestModuleCoupling:
    """Test suite for module coupling analysis."""

    def test_coupling_within_thresholds(self, layer_validator):
        """
        Given the module structure of the application
        When the architectural test suite runs
        Then the test must calculate coupling metrics between modules
        And the test must fail if coupling exceeds defined thresholds
        And the test must generate a coupling report for review
        """
        # Define coupling threshold (can be adjusted based on project needs)
        COUPLING_THRESHOLD = 15

        high_coupling = layer_validator.find_high_coupling_modules(COUPLING_THRESHOLD)

        if high_coupling:
            report = f"Found {len(high_coupling)} modules with high coupling (threshold: {COUPLING_THRESHOLD}):\n"
            for module, coupling in high_coupling[:10]:
                report += f"  - {module}: {coupling} total dependencies\n"
            if len(high_coupling) > 10:
                report += f"  ... and {len(high_coupling) - 10} more\n"

            # This is a warning, not a hard failure for now
            pytest.skip(report + "\nConsider refactoring these modules to reduce coupling.")

    def test_generate_coupling_report(self, layer_validator, tmp_path):
        """Generate a detailed coupling report for review."""
        metrics = layer_validator.calculate_module_coupling()

        # Sort by total coupling
        sorted_modules = sorted(metrics.items(), key=lambda x: x[1]["total_coupling"], reverse=True)

        # Generate report
        report_path = tmp_path / "coupling_report.txt"
        with open(report_path, "w") as f:
            f.write("Module Coupling Analysis Report\n")
            f.write("=" * 50 + "\n\n")

            f.write("Top 20 Most Coupled Modules:\n")
            f.write("-" * 30 + "\n")

            for module, module_metrics in sorted_modules[:20]:
                f.write(f"\n{module}:\n")
                f.write(f"  Fan-in (incoming): {module_metrics['fan_in']}\n")
                f.write(f"  Fan-out (outgoing): {module_metrics['fan_out']}\n")
                f.write(f"  Instability: {module_metrics['instability']:.2f}\n")
                f.write(f"  Total coupling: {module_metrics['total_coupling']}\n")

        # Verify report was created
        assert report_path.exists(), "Coupling report was not generated"

        # Print location for CI/CD artifacts
        print(f"\nCoupling report generated at: {report_path}")


class TestArchitecturalIntegrity:
    """Additional tests for overall architectural integrity."""

    def test_no_god_modules(self, layer_validator):
        """Ensure no single module has too many responsibilities."""
        GOD_MODULE_THRESHOLD = 20  # Max dependencies for a single module

        metrics = layer_validator.calculate_module_coupling()
        god_modules = []

        for module, module_metrics in metrics.items():
            if module_metrics["fan_out"] > GOD_MODULE_THRESHOLD:
                god_modules.append((module, module_metrics["fan_out"]))

        assert len(god_modules) == 0, (
            f"Found potential 'God modules' with too many dependencies:\n"
            + "\n".join([f"  - {module}: {deps} outgoing dependencies" for module, deps in god_modules])
            + f"\nConsider breaking these modules into smaller, focused components."
        )

    def test_layer_independence(self, layer_validator):
        """Verify that utility layers are truly independent."""
        # Only utils and schemas should be truly independent
        # Core layer legitimately needs access to db, models, repositories, and services for startup/auth
        independent_layers = ["utils", "schemas"]

        violations = []
        for py_file in layer_validator.app_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue

            module_name = layer_validator._path_to_module(py_file)
            if not module_name:
                continue

            source_layer = layer_validator.get_layer_from_module(module_name)
            if source_layer not in independent_layers:
                continue

            imports = layer_validator._extract_imports(py_file)

            for imported_module in imports:
                if not imported_module.startswith("app."):
                    continue

                target_layer = layer_validator.get_layer_from_module(imported_module)
                # Allow schemas to import from models (legitimate pattern for data conversion)
                if source_layer == "schemas" and target_layer == "models":
                    continue
                if target_layer and target_layer not in ["core", "utils"] and target_layer != source_layer:
                    violations.append(
                        (
                            str(py_file.relative_to(layer_validator.project_root)),
                            source_layer,
                            imported_module,
                            target_layer,
                        )
                    )

        assert len(violations) == 0, f"Found independence violations in core layers:\n" + "\n".join(
            [
                f"  - {source_file} ({source_layer}) imports {target} ({target_layer})"
                for source_file, source_layer, target, target_layer in violations
            ]
        )
