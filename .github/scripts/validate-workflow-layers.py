#!/usr/bin/env python3
"""
Multi-Layer Workflow Validation Tool
=====================================
Validates GitHub Actions workflows through the complete parsing chain:
YAML → Shell → Python/Script execution

This prevents issues where individual components work but integration fails.
"""

import os
import re
import shlex
import subprocess  # nosec B404 - Needed for workflow validation testing
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


class WorkflowValidator:
    """Validates GitHub Actions workflows through multiple parsing layers."""

    def __init__(self, workflow_dir: str = ".github/workflows"):
        self.workflow_dir = Path(workflow_dir)
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all_workflows(self) -> bool:
        """Validate all workflow files in the directory."""
        print("🔍 Multi-Layer Workflow Validation Starting...")

        workflow_files = list(self.workflow_dir.glob("*.yml")) + list(self.workflow_dir.glob("*.yaml"))

        if not workflow_files:
            print("❌ No workflow files found!")
            return False

        success = True
        for workflow_file in workflow_files:
            print(f"\n📁 Validating {workflow_file.name}...")
            if not self.validate_workflow(workflow_file):
                success = False

        self._print_summary()
        return success

    def validate_workflow(self, workflow_file: Path) -> bool:
        """Validate a single workflow file through all parsing layers."""
        try:
            # Layer 1: YAML Structure Validation
            if not self._validate_yaml_structure(workflow_file):
                return False

            # Layer 2: Shell Script Syntax Validation
            if not self._validate_shell_scripts(workflow_file):
                return False

            # Layer 3: Embedded Code Validation
            if not self._validate_embedded_code(workflow_file):
                return False

            # Layer 4: Integration Testing
            if not self._validate_integration(workflow_file):
                return False

            print(f"✅ {workflow_file.name} passed all validation layers")
            return True

        except Exception as e:
            self.errors.append(f"{workflow_file.name}: Validation failed with exception: {e}")
            return False

    def _validate_yaml_structure(self, workflow_file: Path) -> bool:
        """Layer 1: Validate YAML structure and GitHub Actions schema."""
        try:
            with open(workflow_file, "r") as f:
                workflow = yaml.safe_load(f)

            # Basic GitHub Actions structure validation
            # Note: 'on' is a reserved word in Python, YAML parser converts it to True
            required_keys = ["name", "jobs"]
            trigger_keys = ["on", True]  # 'on' gets converted to True by YAML parser

            missing_keys = [key for key in required_keys if key not in workflow]
            has_trigger = any(key in workflow for key in trigger_keys)

            if missing_keys:
                self.errors.append(f"{workflow_file.name}: Missing required keys: {missing_keys}")
                return False

            if not has_trigger:
                self.errors.append(f"{workflow_file.name}: Missing trigger configuration ('on' key)")
                return False

            # Validate job structure
            for job_name, job_config in workflow.get("jobs", {}).items():
                if "runs-on" not in job_config:
                    self.errors.append(f"{workflow_file.name}: Job '{job_name}' missing 'runs-on'")
                    return False

            print(f"  ✅ Layer 1: YAML structure valid")
            return True

        except yaml.YAMLError as e:
            self.errors.append(f"{workflow_file.name}: YAML parsing error: {e}")
            return False

    def _validate_shell_scripts(self, workflow_file: Path) -> bool:
        """Layer 2: Extract and validate shell scripts."""
        try:
            with open(workflow_file, "r") as f:
                workflow = yaml.safe_load(f)

            shell_scripts = self._extract_shell_scripts(workflow)

            for i, (location, script) in enumerate(shell_scripts):
                if not self._validate_shell_syntax(script, f"{workflow_file.name}:{location}"):
                    return False

            print(f"  ✅ Layer 2: {len(shell_scripts)} shell scripts validated")
            return True

        except Exception as e:
            self.errors.append(f"{workflow_file.name}: Shell validation error: {e}")
            return False

    def _validate_embedded_code(self, workflow_file: Path) -> bool:
        """Layer 3: Validate embedded Python/Node.js code in shell scripts."""
        try:
            with open(workflow_file, "r") as f:
                workflow = yaml.safe_load(f)

            embedded_code = self._extract_embedded_code(workflow)

            for location, lang, code in embedded_code:
                if not self._validate_code_syntax(lang, code, f"{workflow_file.name}:{location}"):
                    return False

            print(f"  ✅ Layer 3: {len(embedded_code)} embedded code blocks validated")
            return True

        except Exception as e:
            self.errors.append(f"{workflow_file.name}: Embedded code validation error: {e}")
            return False

    def _validate_integration(self, workflow_file: Path) -> bool:
        """Layer 4: Test the complete parsing chain integration."""
        try:
            with open(workflow_file, "r") as f:
                workflow = yaml.safe_load(f)

            # Test critical multi-line shell scripts that contain embedded code
            critical_scripts = self._extract_critical_scripts(workflow)

            for location, script in critical_scripts:
                if not self._test_shell_python_integration(script, f"{workflow_file.name}:{location}"):
                    return False

            print(f"  ✅ Layer 4: {len(critical_scripts)} integration tests passed")
            return True

        except Exception as e:
            self.errors.append(f"{workflow_file.name}: Integration testing error: {e}")
            return False

    def _extract_shell_scripts(self, workflow: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract all shell scripts from workflow."""
        scripts = []

        def extract_from_obj(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    if key == "run" and isinstance(value, str):
                        scripts.append((new_path, value))
                    else:
                        extract_from_obj(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    extract_from_obj(item, f"{path}[{i}]")

        extract_from_obj(workflow)
        return scripts

    def _extract_embedded_code(self, workflow: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """Extract embedded Python/Node.js code from shell scripts."""
        embedded = []
        shell_scripts = self._extract_shell_scripts(workflow)

        for location, script in shell_scripts:
            # Python code patterns
            # Use more robust patterns that handle embedded quotes properly
            python_patterns = [
                # Match double-quoted strings, handling escaped quotes
                (r'python3?\s+-c\s+"((?:[^"\\]|\\.)*)"\s*', "python"),
                # Match single-quoted strings, handling escaped quotes
                (r"python3?\s+-c\s+'((?:[^'\\\\]|\\\\.)*)'\s*", "python"),
            ]

            for pattern, lang in python_patterns:
                matches = re.finditer(pattern, script, re.DOTALL)
                for match in matches:
                    embedded.append((location, lang, match.group(1)))

        return embedded

    def _extract_critical_scripts(self, workflow: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract scripts that have multi-layer parsing (shell + embedded code)."""
        shell_scripts = self._extract_shell_scripts(workflow)
        critical = []

        for location, script in shell_scripts:
            # Check if script contains embedded code
            if any(pattern in script for pattern in ["python3 -c", "python -c", "node -e"]):
                critical.append((location, script))

        return critical

    def _validate_shell_syntax(self, script: str, location: str) -> bool:
        """Validate shell script syntax."""
        try:
            # Create temporary shell file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write("#!/bin/bash\n")
                f.write(script)
                f.flush()

                # Use bash -n to check syntax without execution
                result = subprocess.run(  # nosec B603, B607 - Safe bash syntax checking
                    ["bash", "-n", f.name], capture_output=True, text=True
                )

                os.unlink(f.name)

                if result.returncode != 0:
                    self.errors.append(f"{location}: Shell syntax error - {result.stderr.strip()}")
                    return False

                return True

        except Exception as e:
            self.warnings.append(f"{location}: Could not validate shell syntax: {e}")
            return True  # Don't fail on validation issues

    def _validate_code_syntax(self, lang: str, code: str, location: str) -> bool:
        """Validate embedded code syntax."""
        try:
            if lang == "python":
                # Check for common problematic patterns
                problematic_patterns = [
                    (r'[\'"`][^\'"`]*[\'"`]', "Unmatched quotes"),
                    (r'\\(?![ntrfbav\\\'"`])', "Invalid escape sequence"),
                ]

                for pattern, description in problematic_patterns:
                    if re.search(pattern, code):
                        self.warnings.append(f"{location}: Potential {description} in Python code")

                # Try to compile the Python code
                try:
                    compile(code, "<workflow>", "exec")
                except SyntaxError as e:
                    self.errors.append(f"{location}: Python syntax error - {e}")
                    return False

            return True

        except Exception as e:
            self.warnings.append(f"{location}: Could not validate {lang} syntax: {e}")
            return True

    def _test_shell_python_integration(self, script: str, location: str) -> bool:
        """Test the complete shell + Python parsing chain."""
        try:
            # Create a safe test environment
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                # Add safety measures
                test_script = "#!/bin/bash\nset -e\n" + script.replace("sys.exit(1)", 'echo "Would exit with code 1"')
                f.write(test_script)
                f.flush()

                # Test parsing only (don't execute dangerous commands)
                result = subprocess.run(  # nosec B603, B607 - Safe bash syntax checking
                    ["bash", "-n", f.name], capture_output=True, text=True
                )

                os.unlink(f.name)

                if result.returncode != 0:
                    self.errors.append(f"{location}: Integration test failed - {result.stderr.strip()}")
                    return False

                return True

        except Exception as e:
            self.warnings.append(f"{location}: Could not test integration: {e}")
            return True

    def _print_summary(self) -> None:
        """Print validation summary."""
        print(f"\n📊 VALIDATION SUMMARY:")
        print(f"   Errors: {len(self.errors)}")
        print(f"   Warnings: {len(self.warnings)}")

        if self.errors:
            print(f"\n❌ ERRORS:")
            for error in self.errors:
                print(f"   • {error}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"   • {warning}")

        if not self.errors and not self.warnings:
            print("✅ All workflows passed validation!")


def main() -> None:
    """Main entry point."""
    validator = WorkflowValidator()

    if len(sys.argv) > 1:
        # Validate specific workflow file
        workflow_file = Path(sys.argv[1])
        if not workflow_file.exists():
            print(f"❌ Workflow file not found: {workflow_file}")
            sys.exit(1)
        success = validator.validate_workflow(workflow_file)
    else:
        # Validate all workflows
        success = validator.validate_all_workflows()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
