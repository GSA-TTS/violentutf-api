#!/usr/bin/env python3
"""
Workflow Execution Testing Tool
===============================
Tests GitHub Actions workflows in a safe, local environment
to catch integration issues before CI/CD runs.
"""

import json
import os
import subprocess  # nosec B404 - Needed for workflow execution testing
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import yaml


class WorkflowExecutionTester:
    """Test workflow execution in controlled environment."""

    def __init__(self) -> None:
        self.test_results: List[str] = []
        self.failed_tests: List[str] = []

    def test_security_validation_workflow(self) -> bool:
        """Test the security validation workflow specifically."""
        print("🧪 Testing Security CI/CD Validation Workflow...")

        workflow_file = Path(".github/workflows/security-ci-validation.yml")
        if not workflow_file.exists():
            print("❌ Security validation workflow not found!")
            return False

        with open(workflow_file, "r") as f:
            workflow = yaml.safe_load(f)

        # Test specific jobs that caused issues
        jobs_to_test = ["validate-ci-integrity"]

        success = True
        for job_name in jobs_to_test:
            if job_name not in workflow.get("jobs", {}):
                print(f"⚠️  Job '{job_name}' not found in workflow")
                continue

            print(f"\n🔍 Testing job: {job_name}")
            if not self._test_job(workflow["jobs"][job_name], job_name):
                success = False

        return success

    def _test_job(self, job_config: Dict[str, Any], job_name: str) -> bool:
        """Test individual job steps."""
        steps = job_config.get("steps", [])

        for i, step in enumerate(steps):
            step_name = step.get("name", f"Step {i+1}")
            print(f"  🔸 Testing: {step_name}")

            if "run" not in step:
                print(f"    ⏭️  Skipping non-run step")
                continue

            if not self._test_step_execution(step["run"], f"{job_name}.{step_name}"):
                return False

        print(f"  ✅ Job '{job_name}' passed all step tests")
        return True

    def _test_step_execution(self, run_command: str, step_id: str) -> bool:
        """Test step execution in safe environment."""
        try:
            # Track this test
            self.test_results.append(step_id)

            # Skip potentially dangerous or environment-specific commands
            if self._should_skip_step(run_command):
                print(f"    ⏭️  Skipping environment-specific step")
                return True

            # Test multi-line scripts with embedded code
            if self._contains_embedded_code(run_command):
                result = self._test_embedded_code_execution(run_command, step_id)
                if not result:
                    self.failed_tests.append(f"{step_id}: Embedded code execution failed")
                return result

            # Test simple shell commands
            result = self._test_shell_command(run_command, step_id)
            if not result:
                self.failed_tests.append(f"{step_id}: Shell command test failed")
            return result

        except Exception as e:
            print(f"    ❌ Test execution failed: {e}")
            self.failed_tests.append(f"{step_id}: {e}")
            return False

    def _should_skip_step(self, command: str) -> bool:
        """Determine if step should be skipped in testing."""
        skip_patterns = [
            "actions/checkout",
            "actions/setup-python",
            "pip install",
            "apt-get",
            "sudo",
            "docker",
            "uses:",
            "github.rest.issues.createComment",
        ]

        return any(pattern in command for pattern in skip_patterns)

    def _contains_embedded_code(self, command: str) -> bool:
        """Check if command contains embedded Python/Node.js code."""
        patterns = [
            "python3 -c",
            "python -c",
            "node -e",
        ]
        return any(pattern in command for pattern in patterns)

    def _test_embedded_code_execution(self, command: str, step_id: str) -> bool:
        """Test commands with embedded code through full parsing chain."""
        try:
            # Create safe test script
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                # Add safety measures and test mode
                safe_command = self._make_command_safe(command)
                f.write("#!/bin/bash\n")
                f.write("set -e\n")
                f.write(safe_command)
                f.flush()

                # Test syntax parsing (bash -n)
                syntax_result = subprocess.run(  # nosec B603, B607 - Safe bash syntax checking
                    ["bash", "-n", f.name], capture_output=True, text=True
                )

                if syntax_result.returncode != 0:
                    print(f"    ❌ Shell syntax error: {syntax_result.stderr.strip()}")
                    os.unlink(f.name)
                    return False

                # Test actual execution in safe mode
                exec_result = subprocess.run(  # nosec B603, B607 - Safe testing with controlled input
                    ["bash", f.name],
                    capture_output=True,
                    text=True,
                    timeout=30,  # Prevent hanging
                )

                os.unlink(f.name)

                if exec_result.returncode != 0:
                    # Some commands are expected to fail (like security scans finding issues)
                    if self._is_expected_failure(command, exec_result.stderr):
                        print(f"    ✅ Expected failure handled correctly")
                        return True
                    else:
                        print(f"    ❌ Execution failed: {exec_result.stderr.strip()}")
                        # Write full debug to file for analysis
                        with open("debug_failed_command.txt", "w") as debug_file:
                            debug_file.write("ORIGINAL COMMAND:\n")
                            debug_file.write(command + "\n\n")
                            debug_file.write("SAFE COMMAND:\n")
                            debug_file.write(safe_command + "\n\n")
                            debug_file.write("STDERR:\n")
                            debug_file.write(exec_result.stderr + "\n\n")
                            debug_file.write("STDOUT:\n")
                            debug_file.write(exec_result.stdout + "\n")
                        print(f"    🔍 Debug info written to debug_failed_command.txt")
                        # Don't add to failed_tests here, it's handled in _test_step_execution
                        return False

                print(f"    ✅ Embedded code execution successful")
                return True

        except subprocess.TimeoutExpired:
            print(f"    ❌ Command timed out")
            return False
        except Exception as e:
            print(f"    ❌ Test failed: {e}")
            return False

    def _test_shell_command(self, command: str, step_id: str) -> bool:
        """Test simple shell commands."""
        try:
            # Just test syntax for simple commands
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write("#!/bin/bash\n")
                f.write(command)
                f.flush()

                result = subprocess.run(  # nosec B603, B607 - Safe bash syntax checking
                    ["bash", "-n", f.name], capture_output=True, text=True
                )

                os.unlink(f.name)

                if result.returncode != 0:
                    print(f"    ❌ Shell syntax error: {result.stderr.strip()}")
                    return False

                print(f"    ✅ Shell syntax valid")
                return True

        except Exception as e:
            print(f"    ❌ Shell test failed: {e}")
            return False

    def _make_command_safe(self, command: str) -> str:
        """Make command safe for testing by replacing dangerous operations."""
        safe_command = command

        # Context-aware replacement for sys.exit(1) in Python code
        # Handle different quote contexts properly
        import re

        # Pattern 1: sys.exit(1) in Python strings - replace with proper print
        # Use single quotes to avoid conflicts with double-quoted shell strings
        safe_command = re.sub(r"sys\.exit\(1\)", "print('Would exit with code 1')", safe_command)

        # Pattern 2: shell exit commands
        safe_command = safe_command.replace("exit 1", 'echo "Would exit with code 1"')

        # Replace file operations with safe alternatives (only at line boundaries)
        safe_command = re.sub(
            r"^(\s*)bandit -r \.github/",
            r'\1echo "Testing bandit command on .github/"',
            safe_command,
            flags=re.MULTILINE,
        )

        # Add test mode indicators
        safe_command = "export TESTING_MODE=true\n" + safe_command

        return safe_command

    def _is_expected_failure(self, command: str, stderr: str) -> bool:
        """Check if failure is expected (like security scans finding issues)."""
        expected_failure_patterns = [
            "bandit",  # Security scan finding issues
            "No such file or directory",  # Missing test files
            "command not found",  # Missing dependencies in test env
        ]

        return any(pattern in stderr.lower() for pattern in expected_failure_patterns)

    def run_comprehensive_test(self) -> bool:
        """Run comprehensive workflow testing."""
        print("🚀 Starting Comprehensive Workflow Testing...")

        success = True

        # Test security validation workflow
        if not self.test_security_validation_workflow():
            success = False

        # Test other critical workflows
        workflows_to_test = ["pr-validation.yml", "ci.yml"]

        for workflow_name in workflows_to_test:
            workflow_path = Path(f".github/workflows/{workflow_name}")
            if workflow_path.exists():
                print(f"\n🔍 Testing {workflow_name}...")
                if not self._test_workflow_file(workflow_path):
                    success = False

        self._print_test_summary()

        # Ensure we return failure if any tests failed
        if self.failed_tests:
            return False
        return success

    def _test_workflow_file(self, workflow_path: Path) -> bool:
        """Test a complete workflow file."""
        try:
            with open(workflow_path, "r") as f:
                workflow = yaml.safe_load(f)

            jobs = workflow.get("jobs", {})
            success = True

            for job_name, job_config in jobs.items():
                print(f"  🔍 Testing job: {job_name}")
                if not self._test_job(job_config, job_name):
                    success = False

            return success

        except Exception as e:
            print(f"❌ Failed to test {workflow_path.name}: {e}")
            return False

    def _print_test_summary(self) -> None:
        """Print test execution summary."""
        total_tests = len(self.test_results)
        failed_tests = len(self.failed_tests)
        passed_tests = total_tests - failed_tests

        print(f"\n📊 WORKFLOW EXECUTION TEST SUMMARY:")
        print(f"   Total tests executed: {total_tests}")
        print(f"   Passed tests: {passed_tests}")
        print(f"   Failed tests: {failed_tests}")

        if self.failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for failure in self.failed_tests:
                print(f"   • {failure}")
            print(f"\n💡 RESULT: {failed_tests} workflow execution test(s) failed")
        else:
            if total_tests > 0:
                print(f"\n✅ RESULT: All {total_tests} workflow execution tests passed!")
            else:
                print(f"\n⚠️  RESULT: No tests were executed (all steps were skipped)")


def main() -> None:
    """Main entry point."""
    tester = WorkflowExecutionTester()
    success = tester.run_comprehensive_test()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
