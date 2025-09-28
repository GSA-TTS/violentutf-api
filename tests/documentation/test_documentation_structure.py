"""Test documentation structure validation for audit tools.

This module contains tests that verify the proper documentation file structure
exists and follows the defined organization patterns.
"""

from pathlib import Path
from typing import List

import pytest


class TestDocumentationStructure:
    """Test suite for documentation structure validation."""

    # Required documentation structure as defined in issue #141
    REQUIRED_API_REFERENCE_FILES = [
        "docs/audit-tools/api-reference/inventory-tools.md",
        "docs/audit-tools/api-reference/dependency-analysis.md",
        "docs/audit-tools/api-reference/backup-tools.md",
        "docs/audit-tools/api-reference/configuration-tools.md",
    ]

    REQUIRED_INTEGRATION_GUIDE_FILES = [
        "docs/audit-tools/integration-guides/setup-and-installation.md",
        "docs/audit-tools/integration-guides/configuration-guide.md",
        "docs/audit-tools/integration-guides/execution-workflows.md",
        "docs/audit-tools/integration-guides/docker-integration.md",
    ]

    REQUIRED_TROUBLESHOOTING_FILES = [
        "docs/audit-tools/troubleshooting/common-issues.md",
        "docs/audit-tools/troubleshooting/error-reference.md",
        "docs/audit-tools/troubleshooting/performance-tuning.md",
    ]

    REQUIRED_EXAMPLE_FILES = [
        "docs/audit-tools/examples/complete-audit-scenario.md",
        "docs/audit-tools/examples/security-classification.md",
        "docs/audit-tools/examples/automated-monitoring.md",
    ]

    REQUIRED_NOTEBOOK_FILES = [
        "docs/audit-tools/notebooks/interactive-audit-tutorial.ipynb",
        "docs/audit-tools/notebooks/advanced-configuration.ipynb",
    ]

    REQUIRED_CONFIG_SAMPLE_FILES = [
        "docs/audit-tools/examples/configuration-samples/audit-config.yaml",
        "docs/audit-tools/examples/configuration-samples/production.yaml",
        "docs/audit-tools/examples/configuration-samples/development.yaml",
        "docs/audit-tools/examples/configuration-samples/docker-compose.audit.yml",
    ]

    @pytest.fixture
    def project_root(self):
        """Get project root directory."""
        return Path(__file__).parent.parent.parent

    def test_audit_tools_documentation_root_exists(self, project_root):
        """Test that the audit-tools documentation root directory exists."""
        audit_tools_dir = project_root / "docs/audit-tools"
        assert audit_tools_dir.exists(), "docs/audit-tools directory does not exist"
        assert audit_tools_dir.is_dir(), "docs/audit-tools is not a directory"

    def test_api_reference_directory_structure(self, project_root):
        """Test that API reference directory structure is correct."""
        api_ref_dir = project_root / "docs/audit-tools/api-reference"
        assert api_ref_dir.exists(), "API reference directory does not exist"
        assert api_ref_dir.is_dir(), "API reference path is not a directory"

    def test_integration_guides_directory_structure(self, project_root):
        """Test that integration guides directory structure is correct."""
        guides_dir = project_root / "docs/audit-tools/integration-guides"
        assert guides_dir.exists(), "Integration guides directory does not exist"
        assert guides_dir.is_dir(), "Integration guides path is not a directory"

    def test_troubleshooting_directory_structure(self, project_root):
        """Test that troubleshooting directory structure is correct."""
        troubleshoot_dir = project_root / "docs/audit-tools/troubleshooting"
        assert troubleshoot_dir.exists(), "Troubleshooting directory does not exist"
        assert troubleshoot_dir.is_dir(), "Troubleshooting path is not a directory"

    def test_examples_directory_structure(self, project_root):
        """Test that examples directory structure is correct."""
        examples_dir = project_root / "docs/audit-tools/examples"
        assert examples_dir.exists(), "Examples directory does not exist"
        assert examples_dir.is_dir(), "Examples path is not a directory"

    def test_notebooks_directory_structure(self, project_root):
        """Test that notebooks directory structure is correct."""
        notebooks_dir = project_root / "docs/audit-tools/notebooks"
        assert notebooks_dir.exists(), "Notebooks directory does not exist"
        assert notebooks_dir.is_dir(), "Notebooks path is not a directory"

    def test_configuration_samples_directory_structure(self, project_root):
        """Test that configuration samples directory structure is correct."""
        config_samples_dir = project_root / "docs/audit-tools/examples/configuration-samples"
        assert config_samples_dir.exists(), "Configuration samples directory does not exist"
        assert config_samples_dir.is_dir(), "Configuration samples path is not a directory"

    def test_api_reference_files_exist(self, project_root):
        """Test that all required API reference files exist."""
        for file_path in self.REQUIRED_API_REFERENCE_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required API reference file {file_path} does not exist"
            assert full_path.is_file(), f"API reference path {file_path} is not a file"

    def test_integration_guide_files_exist(self, project_root):
        """Test that all required integration guide files exist."""
        for file_path in self.REQUIRED_INTEGRATION_GUIDE_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required integration guide file {file_path} does not exist"
            assert full_path.is_file(), f"Integration guide path {file_path} is not a file"

    def test_troubleshooting_files_exist(self, project_root):
        """Test that all required troubleshooting files exist."""
        for file_path in self.REQUIRED_TROUBLESHOOTING_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required troubleshooting file {file_path} does not exist"
            assert full_path.is_file(), f"Troubleshooting path {file_path} is not a file"

    def test_example_files_exist(self, project_root):
        """Test that all required example files exist."""
        for file_path in self.REQUIRED_EXAMPLE_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required example file {file_path} does not exist"
            assert full_path.is_file(), f"Example path {file_path} is not a file"

    def test_notebook_files_exist(self, project_root):
        """Test that all required notebook files exist."""
        for file_path in self.REQUIRED_NOTEBOOK_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required notebook file {file_path} does not exist"
            assert full_path.is_file(), f"Notebook path {file_path} is not a file"

    def test_configuration_sample_files_exist(self, project_root):
        """Test that all required configuration sample files exist."""
        for file_path in self.REQUIRED_CONFIG_SAMPLE_FILES:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required config sample file {file_path} does not exist"
            assert full_path.is_file(), f"Config sample path {file_path} is not a file"

    def test_api_reference_files_not_empty(self, project_root):
        """Test that all API reference files contain content."""
        for file_path in self.REQUIRED_API_REFERENCE_FILES:
            full_path = project_root / file_path
            if full_path.exists():
                assert full_path.stat().st_size > 0, f"API reference file {file_path} is empty"

    def test_integration_guide_files_not_empty(self, project_root):
        """Test that all integration guide files contain content."""
        for file_path in self.REQUIRED_INTEGRATION_GUIDE_FILES:
            full_path = project_root / file_path
            if full_path.exists():
                assert full_path.stat().st_size > 0, f"Integration guide file {file_path} is empty"

    def test_troubleshooting_files_not_empty(self, project_root):
        """Test that all troubleshooting files contain content."""
        for file_path in self.REQUIRED_TROUBLESHOOTING_FILES:
            full_path = project_root / file_path
            if full_path.exists():
                assert full_path.stat().st_size > 0, f"Troubleshooting file {file_path} is empty"

    def test_example_files_not_empty(self, project_root):
        """Test that all example files contain content."""
        for file_path in self.REQUIRED_EXAMPLE_FILES:
            full_path = project_root / file_path
            if full_path.exists():
                assert full_path.stat().st_size > 0, f"Example file {file_path} is empty"

    def test_markdown_files_have_proper_structure(self, project_root):
        """Test that markdown files have proper structure with headers."""
        all_md_files = []
        all_md_files.extend(self.REQUIRED_API_REFERENCE_FILES)
        all_md_files.extend(self.REQUIRED_INTEGRATION_GUIDE_FILES)
        all_md_files.extend(self.REQUIRED_TROUBLESHOOTING_FILES)
        all_md_files.extend(self.REQUIRED_EXAMPLE_FILES)

        for file_path in all_md_files:
            full_path = project_root / file_path
            if full_path.exists() and full_path.stat().st_size > 0:
                content = full_path.read_text()

                # Check for at least one header
                assert any(
                    line.startswith("#") for line in content.split("\\n")
                ), f"Markdown file {file_path} lacks proper header structure"

    def test_yaml_files_are_valid(self, project_root):
        """Test that YAML configuration files are valid."""
        yaml_files = [f for f in self.REQUIRED_CONFIG_SAMPLE_FILES if f.endswith(".yaml") or f.endswith(".yml")]

        for file_path in yaml_files:
            full_path = project_root / file_path
            if full_path.exists():
                try:
                    import yaml

                    with open(full_path, "r") as f:
                        yaml.safe_load(f)
                except yaml.YAMLError as e:
                    pytest.fail(f"YAML file {file_path} is not valid: {e}")
                except ImportError:
                    # If PyYAML is not available, just check that file is not empty
                    assert full_path.stat().st_size > 0, f"YAML file {file_path} is empty"

    def test_jupyter_notebooks_are_valid(self, project_root):
        """Test that Jupyter notebook files are valid JSON."""
        for file_path in self.REQUIRED_NOTEBOOK_FILES:
            full_path = project_root / file_path
            if full_path.exists():
                try:
                    import json

                    with open(full_path, "r") as f:
                        notebook_data = json.load(f)

                    # Basic notebook structure validation
                    assert "cells" in notebook_data, f"Notebook {file_path} missing cells"
                    assert "metadata" in notebook_data, f"Notebook {file_path} missing metadata"
                    assert "nbformat" in notebook_data, f"Notebook {file_path} missing nbformat"

                except (json.JSONDecodeError, KeyError) as e:
                    pytest.fail(f"Notebook file {file_path} is not valid: {e}")

    def test_complete_documentation_structure_integrity(self, project_root):
        """Test that the complete documentation structure is coherent and complete."""
        all_required_files = []
        all_required_files.extend(self.REQUIRED_API_REFERENCE_FILES)
        all_required_files.extend(self.REQUIRED_INTEGRATION_GUIDE_FILES)
        all_required_files.extend(self.REQUIRED_TROUBLESHOOTING_FILES)
        all_required_files.extend(self.REQUIRED_EXAMPLE_FILES)
        all_required_files.extend(self.REQUIRED_NOTEBOOK_FILES)
        all_required_files.extend(self.REQUIRED_CONFIG_SAMPLE_FILES)

        missing_files = []
        for file_path in all_required_files:
            full_path = project_root / file_path
            if not full_path.exists():
                missing_files.append(file_path)

        if missing_files:
            pytest.fail(
                f"Documentation structure incomplete. Missing files: {missing_files}. "
                f"Total missing: {len(missing_files)}/{len(all_required_files)}"
            )

    def test_documentation_follows_naming_conventions(self, project_root):
        """Test that documentation files follow consistent naming conventions."""
        # Check that all markdown files use kebab-case naming
        all_md_files = []
        all_md_files.extend(self.REQUIRED_API_REFERENCE_FILES)
        all_md_files.extend(self.REQUIRED_INTEGRATION_GUIDE_FILES)
        all_md_files.extend(self.REQUIRED_TROUBLESHOOTING_FILES)
        all_md_files.extend(self.REQUIRED_EXAMPLE_FILES)

        for file_path in all_md_files:
            filename = Path(file_path).name
            # Remove .md extension for checking
            name_without_ext = filename.replace(".md", "")

            # Check kebab-case pattern (lowercase with hyphens)
            assert name_without_ext.islower(), f"File {filename} should use lowercase naming"
            assert " " not in name_without_ext, f"File {filename} should not contain spaces"
            # Allow hyphens and alphanumeric characters
            allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789-")
            assert all(
                c in allowed_chars for c in name_without_ext
            ), f"File {filename} contains invalid characters for kebab-case naming"


class TestDocumentationContentStructure:
    """Test suite for documentation content structure requirements."""

    @pytest.fixture
    def project_root(self):
        """Get project root directory."""
        return Path(__file__).parent.parent.parent

    def test_api_reference_contains_required_sections(self, project_root):
        """Test that API reference files contain required sections."""
        required_sections = ["API Reference", "Classes", "Methods", "Examples", "Parameters", "Returns"]

        for file_path in TestDocumentationStructure.REQUIRED_API_REFERENCE_FILES:
            full_path = project_root / file_path
            if full_path.exists() and full_path.stat().st_size > 0:
                content = full_path.read_text()

                # Check for at least some required sections
                sections_found = sum(1 for section in required_sections if section.lower() in content.lower())

                assert (
                    sections_found >= 3
                ), f"API reference {file_path} should contain at least 3 of these sections: {required_sections}"

    def test_integration_guides_contain_required_sections(self, project_root):
        """Test that integration guides contain required sections."""
        required_sections = ["Prerequisites", "Installation", "Configuration", "Usage", "Examples"]

        for file_path in TestDocumentationStructure.REQUIRED_INTEGRATION_GUIDE_FILES:
            full_path = project_root / file_path
            if full_path.exists() and full_path.stat().st_size > 0:
                content = full_path.read_text()

                sections_found = sum(1 for section in required_sections if section.lower() in content.lower())

                assert (
                    sections_found >= 2
                ), f"Integration guide {file_path} should contain at least 2 of these sections: {required_sections}"

    def test_troubleshooting_guides_contain_required_sections(self, project_root):
        """Test that troubleshooting guides contain required sections."""
        required_sections = ["Common Issues", "Solutions", "Error Codes", "Diagnosis", "Prevention"]

        for file_path in TestDocumentationStructure.REQUIRED_TROUBLESHOOTING_FILES:
            full_path = project_root / file_path
            if full_path.exists() and full_path.stat().st_size > 0:
                content = full_path.read_text()

                sections_found = sum(1 for section in required_sections if section.lower() in content.lower())

                assert (
                    sections_found >= 2
                ), f"Troubleshooting guide {file_path} should contain at least 2 of these sections: {required_sections}"
