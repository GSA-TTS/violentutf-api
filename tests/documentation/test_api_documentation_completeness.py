"""Test API documentation completeness for all audit automation scripts.

This module contains tests that verify all 11 audit automation scripts have
complete API documentation following the TDD approach for documentation.
"""

import ast
import inspect
from pathlib import Path
from typing import Dict, List, Set

import pytest


class TestAPIDocumentationCompleteness:
    """Test suite for API documentation completeness validation."""

    # Define the 11 audit scripts that require documentation
    AUDIT_SCRIPTS = [
        "tools/inventory/data_asset_inventory.py",
        "tools/inventory/repository_analyzer.py",
        "tools/inventory/schema_discovery.py",
        "tools/inventory/security_classification.py",
        "tools/dependency/comprehensive_analyzer.py",
        "tools/dependency/repository_analyzer.py",
        "scripts/config_baseline_manager.py",
        "scripts/config_drift_detector.py",
        "scripts/backup_coverage_audit.py",
        "scripts/postgres_backup.py",
        "scripts/redis_backup.py",
    ]

    DOCUMENTATION_FILES = [
        "docs/audit-tools/api-reference/inventory-tools.md",
        "docs/audit-tools/api-reference/dependency-analysis.md",
        "docs/audit-tools/api-reference/backup-tools.md",
        "docs/audit-tools/api-reference/configuration-tools.md",
    ]

    @pytest.fixture
    def project_root(self):
        """Get project root directory."""
        return Path(__file__).parent.parent.parent

    def test_all_audit_scripts_exist(self, project_root):
        """Test that all required audit scripts exist."""
        for script_path in self.AUDIT_SCRIPTS:
            full_path = project_root / script_path
            assert full_path.exists(), f"Audit script {script_path} does not exist"
            assert full_path.is_file(), f"Audit script {script_path} is not a file"

    def test_inventory_tools_api_documentation_exists(self, project_root):
        """Test that inventory tools API documentation exists."""
        doc_path = project_root / "docs/audit-tools/api-reference/inventory-tools.md"
        assert doc_path.exists(), "Inventory tools API documentation does not exist"
        assert doc_path.stat().st_size > 0, "Inventory tools API documentation is empty"

    def test_dependency_analysis_api_documentation_exists(self, project_root):
        """Test that dependency analysis API documentation exists."""
        doc_path = project_root / "docs/audit-tools/api-reference/dependency-analysis.md"
        assert doc_path.exists(), "Dependency analysis API documentation does not exist"
        assert doc_path.stat().st_size > 0, "Dependency analysis API documentation is empty"

    def test_backup_tools_api_documentation_exists(self, project_root):
        """Test that backup tools API documentation exists."""
        doc_path = project_root / "docs/audit-tools/api-reference/backup-tools.md"
        assert doc_path.exists(), "Backup tools API documentation does not exist"
        assert doc_path.stat().st_size > 0, "Backup tools API documentation is empty"

    def test_configuration_tools_api_documentation_exists(self, project_root):
        """Test that configuration tools API documentation exists."""
        doc_path = project_root / "docs/audit-tools/api-reference/configuration-tools.md"
        assert doc_path.exists(), "Configuration tools API documentation does not exist"
        assert doc_path.stat().st_size > 0, "Configuration tools API documentation is empty"

    def test_data_asset_inventory_has_complete_documentation(self, project_root):
        """Test that DataAssetInventoryTool has complete API documentation."""
        script_path = project_root / "tools/inventory/data_asset_inventory.py"
        doc_path = project_root / "docs/audit-tools/api-reference/inventory-tools.md"

        # Get public methods from the script
        public_methods = self._get_public_methods_from_script(script_path)

        # Check that documentation exists
        if doc_path.exists():
            doc_content = doc_path.read_text()
            # Verify key methods are documented
            assert "perform_full_inventory" in doc_content, "perform_full_inventory method not documented"
            assert "DataAssetInventoryTool" in doc_content, "DataAssetInventoryTool class not documented"
        else:
            pytest.fail("API documentation file does not exist - must be created")

    def test_repository_analyzer_has_complete_documentation(self, project_root):
        """Test that RepositoryAnalyzer has complete API documentation."""
        script_path = project_root / "tools/inventory/repository_analyzer.py"
        doc_path = project_root / "docs/audit-tools/api-reference/inventory-tools.md"

        # Check that script exists and has public methods
        assert script_path.exists(), "RepositoryAnalyzer script does not exist"

        public_methods = self._get_public_methods_from_script(script_path)
        assert len(public_methods) > 0, "No public methods found in RepositoryAnalyzer"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "RepositoryAnalyzer" in doc_content, "RepositoryAnalyzer class not documented"
        else:
            pytest.fail("API documentation file does not exist - must be created")

    def test_schema_discovery_has_complete_documentation(self, project_root):
        """Test that SchemaDiscoveryTool has complete API documentation."""
        script_path = project_root / "tools/inventory/schema_discovery.py"
        doc_path = project_root / "docs/audit-tools/api-reference/inventory-tools.md"

        assert script_path.exists(), "SchemaDiscoveryTool script does not exist"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "SchemaDiscoveryTool" in doc_content, "SchemaDiscoveryTool class not documented"
        else:
            pytest.fail("API documentation file does not exist - must be created")

    def test_security_classification_has_complete_documentation(self, project_root):
        """Test that security classification tools have complete API documentation."""
        script_path = project_root / "tools/inventory/security_classification.py"
        doc_path = project_root / "docs/audit-tools/api-reference/inventory-tools.md"

        assert script_path.exists(), "Security classification script does not exist"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "classify_data_assets" in doc_content, "classify_data_assets function not documented"
        else:
            pytest.fail("API documentation file does not exist - must be created")

    def test_comprehensive_analyzer_has_complete_documentation(self, project_root):
        """Test that ComprehensiveAnalyzer has complete API documentation."""
        script_path = project_root / "tools/dependency/comprehensive_analyzer.py"
        doc_path = project_root / "docs/audit-tools/api-reference/dependency-analysis.md"

        assert script_path.exists(), "ComprehensiveAnalyzer script does not exist"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "ComprehensiveAnalyzer" in doc_content, "ComprehensiveAnalyzer class not documented"
        else:
            pytest.fail("Dependency analysis API documentation file does not exist - must be created")

    def test_backup_tools_have_complete_documentation(self, project_root):
        """Test that all backup tools have complete API documentation."""
        backup_scripts = ["scripts/backup_coverage_audit.py", "scripts/postgres_backup.py", "scripts/redis_backup.py"]

        doc_path = project_root / "docs/audit-tools/api-reference/backup-tools.md"

        for script_path in backup_scripts:
            full_script_path = project_root / script_path
            assert full_script_path.exists(), f"Backup script {script_path} does not exist"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "backup_coverage_audit" in doc_content, "backup_coverage_audit not documented"
            assert "postgres_backup" in doc_content, "postgres_backup not documented"
            assert "redis_backup" in doc_content, "redis_backup not documented"
        else:
            pytest.fail("Backup tools API documentation file does not exist - must be created")

    def test_configuration_tools_have_complete_documentation(self, project_root):
        """Test that configuration management tools have complete API documentation."""
        config_scripts = ["scripts/config_baseline_manager.py", "scripts/config_drift_detector.py"]

        doc_path = project_root / "docs/audit-tools/api-reference/configuration-tools.md"

        for script_path in config_scripts:
            full_script_path = project_root / script_path
            assert full_script_path.exists(), f"Configuration script {script_path} does not exist"

        if doc_path.exists():
            doc_content = doc_path.read_text()
            assert "config_baseline_manager" in doc_content, "config_baseline_manager not documented"
            assert "config_drift_detector" in doc_content, "config_drift_detector not documented"
        else:
            pytest.fail("Configuration tools API documentation file does not exist - must be created")

    def test_all_public_methods_have_docstrings(self, project_root):
        """Test that all public methods in audit scripts have proper docstrings."""
        for script_path in self.AUDIT_SCRIPTS:
            full_path = project_root / script_path
            if not full_path.exists():
                continue  # Skip missing scripts

            public_methods = self._get_public_methods_from_script(full_path)
            methods_without_docstrings = []

            for method_name, method_obj in public_methods.items():
                if not self._has_proper_docstring(method_obj):
                    methods_without_docstrings.append(method_name)

            if methods_without_docstrings:
                pytest.fail(
                    f"Script {script_path} has methods without proper docstrings: " f"{methods_without_docstrings}"
                )

    def test_documentation_contains_usage_examples(self, project_root):
        """Test that API documentation contains practical usage examples."""
        for doc_file in self.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                # Check for code blocks (markdown ```python markers)
                assert "```python" in content, f"Documentation {doc_file} lacks Python code examples"
                assert "```bash" in content, f"Documentation {doc_file} lacks bash command examples"
            else:
                pytest.fail(f"Documentation file {doc_file} does not exist")

    def test_documentation_contains_parameter_descriptions(self, project_root):
        """Test that API documentation contains parameter descriptions."""
        for doc_file in self.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                # Check for parameter documentation patterns
                assert any(
                    keyword in content.lower() for keyword in ["parameters", "args", "arguments"]
                ), f"Documentation {doc_file} lacks parameter descriptions"
            else:
                pytest.fail(f"Documentation file {doc_file} does not exist")

    def test_documentation_contains_return_value_descriptions(self, project_root):
        """Test that API documentation contains return value descriptions."""
        for doc_file in self.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                # Check for return value documentation patterns
                assert any(
                    keyword in content.lower() for keyword in ["returns", "return value", "output"]
                ), f"Documentation {doc_file} lacks return value descriptions"
            else:
                pytest.fail(f"Documentation file {doc_file} does not exist")

    def test_documentation_contains_exception_handling(self, project_root):
        """Test that API documentation contains exception handling information."""
        for doc_file in self.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                # Check for exception documentation patterns
                assert any(
                    keyword in content.lower() for keyword in ["raises", "exceptions", "errors"]
                ), f"Documentation {doc_file} lacks exception handling information"
            else:
                pytest.fail(f"Documentation file {doc_file} does not exist")

    def _get_public_methods_from_script(self, script_path: Path) -> Dict:
        """Extract public methods from a Python script."""
        try:
            with open(script_path, "r") as f:
                content = f.read()

            tree = ast.parse(content)
            public_methods = {}

            # Look for top-level functions and classes
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    if not node.name.startswith("_"):  # Public function
                        public_methods[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    # Look for public methods in the class
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if not item.name.startswith("_"):  # Public method
                                public_methods[f"{node.name}.{item.name}"] = item

            return public_methods
        except Exception as e:
            pytest.fail(f"Failed to parse script {script_path}: {e}")

    def _has_proper_docstring(self, method_node) -> bool:
        """Check if a method has a proper docstring."""
        if not method_node.body:
            return False

        first_stmt = method_node.body[0]
        if isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant):
            docstring = first_stmt.value.value
            if isinstance(docstring, str) and len(docstring.strip()) > 20:
                return True
        return False


class TestDocumentationQualityMetrics:
    """Test suite for documentation quality metrics."""

    def test_documentation_completeness_score_100_percent(self, project_root=None):
        """Test that overall documentation completeness score is 100%."""
        if project_root is None:
            project_root = Path(__file__).parent.parent.parent

        # Calculate completeness score
        total_scripts = len(TestAPIDocumentationCompleteness.AUDIT_SCRIPTS)
        documented_scripts = 0

        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists() and doc_path.stat().st_size > 0:
                documented_scripts += 1

        # For now, expect all documentation files to exist and be non-empty
        # This is a failing test that will drive documentation creation
        expected_docs = len(TestAPIDocumentationCompleteness.DOCUMENTATION_FILES)

        if documented_scripts < expected_docs:
            pytest.fail(
                f"Documentation completeness: {documented_scripts}/{expected_docs} files exist. "
                f"Need to create: {set(TestAPIDocumentationCompleteness.DOCUMENTATION_FILES) - set([df for df in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES if (project_root / df).exists()])}"
            )

    def test_documentation_meets_success_metrics(self):
        """Test that documentation meets the defined success metrics from issue #141."""
        # This test validates the key success metrics:
        # - 100% documentation completeness
        # - 70% developer onboarding time reduction potential
        # - 50% support ticket reduction potential

        project_root = Path(__file__).parent.parent.parent

        # Metric 1: 100% Documentation Completeness
        documentation_completeness = self._validate_documentation_completeness(project_root)
        assert (
            documentation_completeness >= 100.0
        ), f"Documentation completeness is {documentation_completeness}%, expected 100%"

        # Metric 2: Developer Onboarding Time Reduction Potential (70%)
        onboarding_potential = self._calculate_onboarding_time_reduction_potential(project_root)
        assert (
            onboarding_potential >= 70.0
        ), f"Developer onboarding time reduction potential is {onboarding_potential}%, expected >= 70%"

        # Metric 3: Support Ticket Reduction Potential (50%)
        support_ticket_potential = self._calculate_support_ticket_reduction_potential(project_root)
        assert (
            support_ticket_potential >= 50.0
        ), f"Support ticket reduction potential is {support_ticket_potential}%, expected >= 50%"

    def _validate_documentation_completeness(self, project_root: Path) -> float:
        """Calculate documentation completeness percentage."""
        total_required_elements = 0
        completed_elements = 0

        # Check documentation files exist and are non-empty
        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            total_required_elements += 4  # API docs, examples, parameters, returns

            if doc_path.exists():
                content = doc_path.read_text()
                if len(content) > 100:  # Non-trivial content
                    completed_elements += 1
                if "```python" in content:  # Python examples
                    completed_elements += 1
                if "```bash" in content:  # Bash examples
                    completed_elements += 1
                if any(keyword in content.lower() for keyword in ["parameters", "args", "returns", "output"]):
                    completed_elements += 1

        # Check script documentation
        for script_path in TestAPIDocumentationCompleteness.AUDIT_SCRIPTS:
            full_path = project_root / script_path
            total_required_elements += 2  # Script exists + has proper docstrings

            if full_path.exists():
                completed_elements += 1
                public_methods = self._get_public_methods_from_script(full_path)
                if all(self._has_proper_docstring(method) for method in public_methods.values()):
                    completed_elements += 1

        return (completed_elements / total_required_elements * 100) if total_required_elements > 0 else 0.0

    def _calculate_onboarding_time_reduction_potential(self, project_root: Path) -> float:
        """Calculate developer onboarding time reduction potential."""
        # Score based on presence of key documentation elements
        score = 0
        max_score = 10

        # Setup guides exist
        setup_guide = project_root / "docs/audit-tools/integration-guides/setup-and-installation.md"
        if setup_guide.exists() and len(setup_guide.read_text()) > 500:
            score += 2

        # Configuration guide exists
        config_guide = project_root / "docs/audit-tools/integration-guides/configuration-guide.md"
        if config_guide.exists() and len(config_guide.read_text()) > 300:
            score += 2

        # Practical examples exist
        examples_dir = project_root / "docs/audit-tools/examples"
        if examples_dir.exists() and len(list(examples_dir.glob("*.md"))) >= 3:
            score += 2

        # Troubleshooting guides exist
        troubleshooting_dir = project_root / "docs/audit-tools/troubleshooting"
        if troubleshooting_dir.exists() and len(list(troubleshooting_dir.glob("*.md"))) >= 2:
            score += 2

        # API documentation completeness
        if self._validate_documentation_completeness(project_root) >= 100:
            score += 2

        return (score / max_score) * 100

    def _calculate_support_ticket_reduction_potential(self, project_root: Path) -> float:
        """Calculate support ticket reduction potential."""
        # Score based on coverage of common support areas
        score = 0
        max_score = 10

        # Error handling documentation
        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                if any(keyword in content.lower() for keyword in ["error", "exception", "troubleshooting"]):
                    score += 1
                    break

        # Configuration examples and guides (reduces config-related tickets)
        config_examples = 0
        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists() and "config" in doc_path.read_text().lower():
                config_examples += 1
        if config_examples >= 2:
            score += 2

        # Usage examples (reduces how-to tickets)
        usage_examples = 0
        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                if "```python" in content and "```bash" in content:
                    usage_examples += 1
        if usage_examples >= 3:
            score += 2

        # Troubleshooting documentation
        troubleshooting_coverage = 0
        troubleshooting_dir = project_root / "docs/audit-tools/troubleshooting"
        if troubleshooting_dir.exists():
            for doc in troubleshooting_dir.glob("*.md"):
                if doc.stat().st_size > 200:  # Non-trivial content
                    troubleshooting_coverage += 1
        if troubleshooting_coverage >= 2:
            score += 3

        # Parameter and return documentation (reduces API usage tickets)
        param_docs = 0
        for doc_file in TestAPIDocumentationCompleteness.DOCUMENTATION_FILES:
            doc_path = project_root / doc_file
            if doc_path.exists():
                content = doc_path.read_text()
                if "parameters" in content.lower() and "returns" in content.lower():
                    param_docs += 1
        if param_docs >= 3:
            score += 2

        return min((score / max_score) * 100, 100.0)  # Cap at 100%

    def _get_public_methods_from_script(self, script_path: Path) -> Dict:
        """Extract public methods from a Python script."""
        try:
            with open(script_path, "r") as f:
                content = f.read()

            tree = ast.parse(content)
            public_methods = {}

            # Look for top-level functions and classes
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    if not node.name.startswith("_"):  # Public function
                        public_methods[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    # Look for public methods in the class
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if not item.name.startswith("_"):  # Public method
                                public_methods[f"{node.name}.{item.name}"] = item

            return public_methods
        except Exception:
            return {}

    def _has_proper_docstring(self, method_node) -> bool:
        """Check if a method has a proper docstring."""
        if not method_node.body:
            return False

        first_stmt = method_node.body[0]
        if isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant):
            docstring = first_stmt.value.value
            if isinstance(docstring, str) and len(docstring.strip()) > 20:
                return True
        return False
