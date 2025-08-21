#!/usr/bin/env python3
"""Run all performance tests and generate a comprehensive report."""

import json
import subprocess  # nosec B404 # Needed for test execution
import sys
import time
from datetime import datetime
from pathlib import Path


def run_test_module(module_name: str, output_file: Path) -> dict:
    """Run a specific test module and capture results."""
    print(f"\n{'='*60}")
    print(f"Running {module_name}...")
    print(f"{'='*60}")

    start_time = time.time()

    # Run pytest with JSON output
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        f"tests/performance/{module_name}",
        "-v",
        "-s",
        "--tb=short",
        "--junit-xml",
        str(output_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 # Controlled pytest execution

    duration = time.time() - start_time

    return {
        "module": module_name,
        "duration": duration,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "success": result.returncode == 0,
    }


def main():
    """Run all performance tests and generate report."""
    # Create results directory
    results_dir = Path("tests/performance/results")
    results_dir.mkdir(exist_ok=True)

    # Timestamp for this run
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Test modules to run
    test_modules = [
        "test_connection_pooling_load_fixed.py",
        "test_retry_logic_load.py",
        "test_session_leak_prevention.py",
        "test_performance_benchmarks.py",
    ]

    # Run each test module
    results = []
    for module in test_modules:
        output_file = results_dir / f"{module}_{timestamp}.xml"
        result = run_test_module(module, output_file)
        results.append(result)

        # Print immediate feedback
        if result["success"]:
            print(f"✅ {module} completed successfully")
        else:
            print(f"❌ {module} failed")
            if result["stderr"]:
                print(f"Error: {result['stderr']}")

    # Generate summary report
    summary = {
        "timestamp": timestamp,
        "total_duration": sum(r["duration"] for r in results),
        "total_tests": len(results),
        "passed": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results,
    }

    # Save summary
    summary_file = results_dir / f"performance_test_summary_{timestamp}.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Print final summary
    print(f"\n{'='*60}")
    print("PERFORMANCE TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total tests run: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Total duration: {summary['total_duration']:.2f} seconds")
    print(f"\nResults saved to: {summary_file}")

    # Exit with appropriate code
    sys.exit(0 if summary["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
