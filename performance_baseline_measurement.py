#!/usr/bin/env python3
"""
Baseline Performance Measurement Script for Issue #89.

This script establishes performance baselines for the repository pattern implementation
to validate the <5% performance impact requirement.

The current implementation with repository pattern will be compared against these baselines
in subsequent phases.
"""

import asyncio
import json
import statistics
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi.testclient import TestClient

from app.main import app


class PerformanceBaseline:
    """Performance baseline measurement utility."""

    def __init__(self) -> None:
        self.client = TestClient(app)
        self.results: Dict[str, Any] = {}

    def measure_endpoint_performance(
        self,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, Any]] = None,
        data: Any = None,
        iterations: int = 10,
    ) -> Dict[str, Any]:
        """Measure endpoint performance metrics."""
        response_times = []
        status_codes = []

        for _ in range(iterations):
            start_time = time.perf_counter()

            if method.upper() == "GET":
                response = self.client.get(endpoint, headers=headers or {})
            elif method.upper() == "POST":
                response = self.client.post(endpoint, json=data, headers=headers or {})

            end_time = time.perf_counter()

            response_times.append(end_time - start_time)
            status_codes.append(response.status_code)

        return {
            "avg_time": statistics.mean(response_times),
            "min_time": min(response_times),
            "max_time": max(response_times),
            "success_rate": sum(1 for code in status_codes if code < 400) / len(status_codes),
            "iterations": iterations,
            "method": method,
            "endpoint": endpoint,
        }

    def measure_health_endpoint(self) -> Dict[str, Any]:
        """Measure health endpoint performance."""
        return self.measure_endpoint_performance("GET", "/api/v1/health")

    def measure_readiness_endpoint(self) -> Dict[str, Any]:
        """Measure readiness endpoint performance."""
        return self.measure_endpoint_performance("GET", "/api/v1/ready")

    def measure_api_root(self) -> Dict[str, float]:
        """Measure API root endpoint performance."""
        return self.measure_endpoint_performance("GET", "/")

    def run_baseline_measurements(self) -> Dict[str, Any]:
        """Run comprehensive baseline measurements."""
        print("🔍 Starting Performance Baseline Measurements...")
        print("=" * 60)

        # Measure core endpoints that should work without authentication
        measurements = {}

        # Health check endpoint
        print("📊 Measuring /api/v1/health endpoint...")
        measurements["health"] = self.measure_health_endpoint()
        self.print_measurement_results("Health Endpoint", measurements["health"])

        # Readiness check endpoint
        print("📊 Measuring /api/v1/ready endpoint...")
        measurements["readiness"] = self.measure_readiness_endpoint()
        self.print_measurement_results("Readiness Endpoint", measurements["readiness"])

        # API root endpoint
        print("📊 Measuring / (API root) endpoint...")
        measurements["api_root"] = self.measure_api_root()
        self.print_measurement_results("API Root", measurements["api_root"])

        # Calculate overall metrics
        all_times = []
        for endpoint_data in measurements.values():
            if endpoint_data["success_rate"] > 0:  # Only include successful endpoints
                all_times.append(endpoint_data["avg_time"])

        if all_times:
            overall_metrics = {
                "avg_response_time": statistics.mean(all_times),
                "total_endpoints_measured": len(measurements),
                "successful_endpoints": sum(1 for m in measurements.values() if m["success_rate"] > 0),
                "measurement_timestamp": datetime.now().isoformat(),
                "baseline_type": "repository_pattern_current",  # This is post-repository pattern
            }
            measurements["overall"] = overall_metrics

        print("\n" + "=" * 60)
        print("📈 Overall Performance Baseline Summary:")
        if all_times:
            print(f"   Average Response Time: {overall_metrics['avg_response_time']:.4f}s")
            print(
                f"   Successful Endpoints: {overall_metrics['successful_endpoints']}/{overall_metrics['total_endpoints_measured']}"
            )
        else:
            print("   ⚠️  No successful measurements recorded")

        return measurements

    def print_measurement_results(self, name: str, data: Dict[str, Any]) -> None:
        """Print measurement results in a formatted way."""
        print(f"   {name}:")
        print(f"      Average: {data['avg_time']:.4f}s")
        print(f"      Min:     {data['min_time']:.4f}s")
        print(f"      Max:     {data['max_time']:.4f}s")
        print(f"      Success: {data['success_rate']:.1%}")
        print()

    def save_baseline_to_file(self, measurements: Dict[str, Any], filename: str = "performance_baseline.json") -> None:
        """Save baseline measurements to file."""
        with open(filename, "w") as f:
            json.dump(measurements, f, indent=2)
        print(f"💾 Baseline measurements saved to {filename}")


def main() -> bool:
    """Main execution function."""
    print("🎯 Issue #89 Performance Baseline Measurement")
    print("Repository Pattern Implementation - Current Performance State")
    print("=" * 60)

    baseline = PerformanceBaseline()

    try:
        measurements = baseline.run_baseline_measurements()
        baseline.save_baseline_to_file(measurements)

        print("\n✅ Performance baseline measurement completed successfully!")
        print("📋 Results Summary:")

        if "overall" in measurements:
            overall = measurements["overall"]
            print(f"   📊 Average Response Time: {overall['avg_response_time']:.4f}s")
            print(f"   ✅ Endpoints Measured: {overall['successful_endpoints']}/{overall['total_endpoints_measured']}")
            print(f"   📅 Timestamp: {overall['measurement_timestamp']}")

        print("\n🔄 Next Steps:")
        print("   1. These measurements represent the current repository pattern performance")
        print("   2. Use these as baseline for performance regression testing")
        print("   3. Compare future performance changes against these baselines")
        print("   4. Ensure any changes maintain <5% performance impact")

        return True

    except Exception as e:
        print(f"❌ Performance measurement failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
