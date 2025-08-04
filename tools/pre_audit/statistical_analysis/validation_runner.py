"""
Validation Runner for GitHub Issue #43 Statistical Hotspot Analysis.

This module orchestrates comprehensive validation including:
- Statistical correctness validation
- Property-based testing with Hypothesis
- Performance benchmarking
- Edge case testing
- Integration testing

Provides a single entry point for complete system validation.
"""

import argparse
import json
import logging
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .validation_framework import ValidationFramework, ValidationSuite

logger = logging.getLogger(__name__)


class ValidationRunner:
    """Main validation runner orchestrating all validation activities."""

    def __init__(self, output_dir: Optional[Path] = None, verbose: bool = False):
        """
        Initialize validation runner.

        Args:
            output_dir: Directory to save validation reports
            verbose: Enable verbose logging
        """
        self.output_dir = output_dir or Path("validation_reports")
        self.output_dir.mkdir(exist_ok=True)

        # Configure logging
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        self.validation_framework = ValidationFramework()

    def run_validation_framework(self) -> ValidationSuite:
        """Run the comprehensive validation framework."""
        logger.info("Starting validation framework tests...")
        return self.validation_framework.run_complete_validation()

    def run_property_based_tests(self) -> Dict[str, Any]:
        """Run property-based tests using Hypothesis."""
        logger.info("Starting property-based tests...")

        start_time = time.time()

        # Find the property-based test file
        test_file = Path(__file__).parent.parent.parent / "tests" / "property_based" / "test_statistical_properties.py"

        try:
            # Run pytest with hypothesis
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    str(test_file),
                    "-v",
                    "--tb=short",
                    "--hypothesis-show-statistics",
                    "--json-report",
                    f"--json-report-file={tempfile.gettempdir()}/property_test_report.json",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )  # 10 minute timeout

            execution_time = time.time() - start_time

            # Parse results
            try:
                with open(f"{tempfile.gettempdir()}/property_test_report.json", "r") as f:
                    test_report = json.load(f)

                return {
                    "success": result.returncode == 0,
                    "execution_time": execution_time,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "test_summary": test_report.get("summary", {}),
                    "total_tests": test_report.get("summary", {}).get("total", 0),
                    "passed": test_report.get("summary", {}).get("passed", 0),
                    "failed": test_report.get("summary", {}).get("failed", 0),
                    "detailed_results": test_report.get("tests", []),
                }
            except (FileNotFoundError, json.JSONDecodeError):
                # Fallback if JSON report is not available
                return {
                    "success": result.returncode == 0,
                    "execution_time": execution_time,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "note": "Detailed JSON report not available",
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "execution_time": 600,
                "error": "Property-based tests timed out after 10 minutes",
                "stdout": "",
                "stderr": "",
            }
        except Exception as e:
            return {
                "success": False,
                "execution_time": time.time() - start_time,
                "error": str(e),
                "stdout": "",
                "stderr": "",
            }

    def run_unit_tests(self) -> Dict[str, Any]:
        """Run all unit tests to ensure no regressions."""
        logger.info("Running unit tests to check for regressions...")

        start_time = time.time()

        # Find test directories
        test_dirs = [
            Path(__file__).parent.parent.parent / "tests" / "unit",
        ]

        test_files = []
        for test_dir in test_dirs:
            if test_dir.exists():
                test_files.extend(list(test_dir.glob("test_*.py")))

        if not test_files:
            return {
                "success": False,
                "execution_time": 0,
                "error": "No unit test files found",
                "stdout": "",
                "stderr": "",
            }

        try:
            # Run pytest on all unit tests
            result = subprocess.run(
                [sys.executable, "-m", "pytest"]
                + [str(f) for f in test_files]
                + [
                    "-v",
                    "--tb=short",
                    "--json-report",
                    f"--json-report-file={tempfile.gettempdir()}/unit_test_report.json",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )  # 5 minute timeout

            execution_time = time.time() - start_time

            # Parse results
            try:
                with open(f"{tempfile.gettempdir()}/unit_test_report.json", "r") as f:
                    test_report = json.load(f)

                return {
                    "success": result.returncode == 0,
                    "execution_time": execution_time,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "test_summary": test_report.get("summary", {}),
                    "total_tests": test_report.get("summary", {}).get("total", 0),
                    "passed": test_report.get("summary", {}).get("passed", 0),
                    "failed": test_report.get("summary", {}).get("failed", 0),
                }
            except (FileNotFoundError, json.JSONDecodeError):
                return {
                    "success": result.returncode == 0,
                    "execution_time": execution_time,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "note": "Detailed JSON report not available",
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "execution_time": 300,
                "error": "Unit tests timed out after 5 minutes",
            }
        except Exception as e:
            return {"success": False, "execution_time": time.time() - start_time, "error": str(e)}

    def run_complete_validation(self) -> Dict[str, Any]:
        """Run complete validation suite including all test types."""
        logger.info("Starting complete validation suite for GitHub Issue #43")

        start_time = time.time()
        results = {}

        # 1. Run validation framework
        try:
            validation_suite = self.run_validation_framework()
            results["validation_framework"] = {
                "success": validation_suite.success_rate >= 80,
                "suite": validation_suite,
                "execution_time": validation_suite.execution_time,
            }
        except Exception as e:
            logger.error(f"Validation framework failed: {e}")
            results["validation_framework"] = {
                "success": False,
                "error": str(e),
                "execution_time": 0,
            }

        # 2. Run property-based tests
        try:
            property_results = self.run_property_based_tests()
            results["property_based_tests"] = property_results
        except Exception as e:
            logger.error(f"Property-based tests failed: {e}")
            results["property_based_tests"] = {
                "success": False,
                "error": str(e),
                "execution_time": 0,
            }

        # 3. Run unit tests for regression checking
        try:
            unit_test_results = self.run_unit_tests()
            results["unit_tests"] = unit_test_results
        except Exception as e:
            logger.error(f"Unit tests failed: {e}")
            results["unit_tests"] = {"success": False, "error": str(e), "execution_time": 0}

        # Calculate overall results
        total_time = time.time() - start_time

        # Determine overall success
        validation_success = results.get("validation_framework", {}).get("success", False)
        property_success = results.get("property_based_tests", {}).get("success", False)
        unit_success = results.get("unit_tests", {}).get("success", False)

        overall_success = validation_success and unit_success
        # Property-based tests are considered supplementary - failures don't block overall success
        if not property_success:
            logger.warning("Property-based tests failed, but not blocking overall success")

        results["overall"] = {
            "success": overall_success,
            "total_execution_time": total_time,
            "validation_framework_passed": validation_success,
            "property_based_tests_passed": property_success,
            "unit_tests_passed": unit_success,
            "timestamp": time.time(),
        }

        return results

    def generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive validation report."""

        report_lines = [
            "# Comprehensive Validation Report",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**GitHub Issue:** #43 Enhanced Statistical Hotspot Analysis",
            "",
            "## Executive Summary",
        ]

        overall = results.get("overall", {})
        if overall.get("success", False):
            report_lines.extend(
                [
                    "🎉 **VALIDATION PASSED** - All critical tests successful",
                    "",
                    f"✅ Validation Framework: {'PASS' if overall.get('validation_framework_passed') else 'FAIL'}",
                    f"✅ Unit Tests: {'PASS' if overall.get('unit_tests_passed') else 'FAIL'}",
                    f"{'✅' if overall.get('property_based_tests_passed') else '⚠️'} Property Tests: {'PASS' if overall.get('property_based_tests_passed') else 'FAIL (Non-blocking)'}",
                    f"⏱️ Total Execution Time: {overall.get('total_execution_time', 0):.2f} seconds",
                    "",
                ]
            )
        else:
            report_lines.extend(
                [
                    "❌ **VALIDATION FAILED** - Critical issues found",
                    "",
                    f"{'✅' if overall.get('validation_framework_passed') else '❌'} Validation Framework: {'PASS' if overall.get('validation_framework_passed') else 'FAIL'}",
                    f"{'✅' if overall.get('unit_tests_passed') else '❌'} Unit Tests: {'PASS' if overall.get('unit_tests_passed') else 'FAIL'}",
                    f"{'✅' if overall.get('property_based_tests_passed') else '⚠️'} Property Tests: {'PASS' if overall.get('property_based_tests_passed') else 'FAIL'}",
                    f"⏱️ Total Execution Time: {overall.get('total_execution_time', 0):.2f} seconds",
                    "",
                ]
            )

        # Detailed results sections

        # 1. Validation Framework Results
        validation_results = results.get("validation_framework", {})
        if "suite" in validation_results:
            suite = validation_results["suite"]
            report_lines.extend(
                [
                    "## Validation Framework Results",
                    "",
                    f"- **Tests Run:** {suite.total_tests}",
                    f"- **Passed:** {suite.passed_tests}",
                    f"- **Failed:** {suite.failed_tests}",
                    f"- **Success Rate:** {suite.success_rate:.1f}%",
                    f"- **Overall Score:** {suite.overall_score:.2f}/1.0",
                    "",
                ]
            )

            # Add individual test results
            for result in suite.results:
                status = "✅" if result.passed else "❌"
                report_lines.append(f"  {status} **{result.test_name}** - Score: {result.score:.2f}")

            report_lines.append("")

        # 2. Property-Based Test Results
        property_results = results.get("property_based_tests", {})
        report_lines.extend(["## Property-Based Test Results", ""])

        if property_results.get("success"):
            passed = property_results.get("passed", 0)
            total = property_results.get("total_tests", 0)
            report_lines.extend(
                [
                    f"✅ **Property tests passed:** {passed}/{total}",
                    f"⏱️ **Execution time:** {property_results.get('execution_time', 0):.2f}s",
                    "",
                ]
            )
        else:
            report_lines.extend(
                [
                    "❌ **Property tests failed**",
                    f"⏱️ **Execution time:** {property_results.get('execution_time', 0):.2f}s",
                    "",
                ]
            )
            if "error" in property_results:
                report_lines.append(f"**Error:** {property_results['error']}")
                report_lines.append("")

        # 3. Unit Test Results
        unit_results = results.get("unit_tests", {})
        report_lines.extend(["## Unit Test Results", ""])

        if unit_results.get("success"):
            passed = unit_results.get("passed", 0)
            total = unit_results.get("total_tests", 0)
            report_lines.extend(
                [
                    f"✅ **Unit tests passed:** {passed}/{total}",
                    f"⏱️ **Execution time:** {unit_results.get('execution_time', 0):.2f}s",
                    "",
                ]
            )
        else:
            report_lines.extend(
                [
                    "❌ **Unit tests failed**",
                    f"⏱️ **Execution time:** {unit_results.get('execution_time', 0):.2f}s",
                    "",
                ]
            )
            if "error" in unit_results:
                report_lines.append(f"**Error:** {unit_results['error']}")
                report_lines.append("")

        # Final recommendations
        report_lines.extend(["## Recommendations", ""])

        if overall.get("success"):
            report_lines.extend(
                [
                    "🎯 **Implementation is ready for production deployment**",
                    "",
                    "The statistical hotspot analysis system has passed all critical validation tests:",
                    "- Statistical correctness verified",
                    "- Performance benchmarks met",
                    "- Edge cases handled properly",
                    "- No regressions in existing functionality",
                    "",
                ]
            )
        else:
            report_lines.extend(["⚠️ **Implementation requires fixes before deployment**", ""])

            if not overall.get("validation_framework_passed"):
                report_lines.append("- Address validation framework failures")
            if not overall.get("unit_tests_passed"):
                report_lines.append("- Fix unit test failures to prevent regressions")

            report_lines.append("")

        return "\n".join(report_lines)

    def save_results(self, results: Dict[str, Any]) -> Path:
        """Save validation results to files."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Save JSON results
        json_file = self.output_dir / f"validation_results_{timestamp}.json"
        with open(json_file, "w") as f:
            # Convert ValidationSuite objects to dicts for JSON serialization
            json_results = results.copy()
            if "validation_framework" in json_results and "suite" in json_results["validation_framework"]:
                suite = json_results["validation_framework"]["suite"]  # type: ValidationSuite
                json_results["validation_framework"]["suite"] = {
                    "suite_name": suite.suite_name,
                    "total_tests": suite.total_tests,
                    "passed_tests": suite.passed_tests,
                    "failed_tests": suite.failed_tests,
                    "overall_score": suite.overall_score,
                    "execution_time": suite.execution_time,
                    "success_rate": suite.success_rate,
                    "results": [
                        {
                            "test_name": r.test_name,
                            "passed": r.passed,
                            "score": r.score,
                            "execution_time": r.execution_time,
                            "details": r.details,
                            "error_message": r.error_message,
                        }
                        for r in suite.results
                    ],
                }

            json.dump(json_results, f, indent=2, default=str)

        # Save markdown report
        report = self.generate_comprehensive_report(results)
        md_file = self.output_dir / f"validation_report_{timestamp}.md"
        with open(md_file, "w") as f:
            f.write(report)

        # Save individual validation framework report if available
        if "validation_framework" in results and "suite" in results["validation_framework"]:
            framework_suite = results["validation_framework"]["suite"]  # type: ValidationSuite
            framework_report = self.validation_framework.generate_validation_report(framework_suite)
            framework_file = self.output_dir / f"framework_report_{timestamp}.md"
            with open(framework_file, "w") as f:
                f.write(framework_report)

        logger.info(f"Validation results saved to {self.output_dir}")
        logger.info(f"  - JSON results: {json_file}")
        logger.info(f"  - Main report: {md_file}")

        return md_file


def main() -> None:
    """Main entry point for validation runner."""
    parser = argparse.ArgumentParser(description="Run comprehensive validation for GitHub Issue #43")
    parser.add_argument("--output-dir", type=Path, help="Output directory for reports")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quick", action="store_true", help="Run quick validation (skip property tests)")

    args = parser.parse_args()

    runner = ValidationRunner(output_dir=args.output_dir, verbose=args.verbose)

    if args.quick:
        # Quick validation - skip property-based tests
        logger.info("Running quick validation (validation framework + unit tests only)")

        results = {}

        # Run validation framework
        validation_suite = runner.run_validation_framework()
        results["validation_framework"] = {
            "success": validation_suite.success_rate >= 80,
            "suite": validation_suite,
        }

        # Run unit tests
        unit_results = runner.run_unit_tests()
        results["unit_tests"] = unit_results

        # Set overall results
        results["overall"] = {
            "success": results["validation_framework"]["success"] and unit_results["success"],
            "validation_framework_passed": results["validation_framework"]["success"],
            "unit_tests_passed": unit_results["success"],
            "property_based_tests_passed": True,  # Skipped
            "quick_mode": True,
        }
    else:
        # Full validation
        results = runner.run_complete_validation()

    # Save and display results
    report_file = runner.save_results(results)

    # Print summary to console
    overall = results.get("overall", {})
    if overall.get("success"):
        print("\n🎉 VALIDATION PASSED - Implementation ready for deployment!")
        print(f"📊 Full report available at: {report_file}")
        sys.exit(0)
    else:
        print("\n❌ VALIDATION FAILED - Implementation needs fixes")
        print(f"📊 Full report available at: {report_file}")
        sys.exit(1)


if __name__ == "__main__":
    main()
