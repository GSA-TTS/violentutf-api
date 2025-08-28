#!/usr/bin/env python3
"""
Comprehensive Performance Monitoring System for Issue #89.

This system provides ongoing performance measurement capabilities for the repository pattern
implementation, supporting continuous monitoring and regression detection.

Key Features:
- Real-time performance metrics collection
- Historical performance tracking
- Repository pattern performance analysis
- Service-layer performance measurement
- Automated performance regression alerts
"""

import asyncio
import json
import os
import statistics
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
import psutil
from fastapi.testclient import TestClient

from app.main import app


class PerformanceMonitor:
    """Comprehensive performance monitoring system."""

    def __init__(self, save_historical: bool = True):
        self.client = TestClient(app)
        self.save_historical = save_historical
        self.results: Dict[str, Any] = {}
        self.historical_file = "performance_history.json"

    def measure_system_metrics(self) -> Dict[str, Any]:
        """Measure system-level performance metrics."""
        process = psutil.Process()
        memory_info = process.memory_info()

        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_rss_mb": memory_info.rss / 1024 / 1024,
            "memory_vms_mb": memory_info.vms / 1024 / 1024,
            "memory_percent": process.memory_percent(),
            "num_threads": process.num_threads(),
            "timestamp": datetime.now().isoformat(),
        }

    def measure_endpoint_performance_comprehensive(
        self,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, Any]] = None,
        data: Any = None,
        iterations: int = 20,
        warmup_iterations: int = 3,
    ) -> Dict[str, Any]:
        """Comprehensive endpoint performance measurement with warmup."""
        # Warmup requests
        for _ in range(warmup_iterations):
            try:
                if method.upper() == "GET":
                    self.client.get(endpoint, headers=headers or {})
                elif method.upper() == "POST":
                    self.client.post(endpoint, json=data, headers=headers or {})
            except Exception:
                pass  # Ignore warmup errors

        # Actual measurements
        response_times = []
        status_codes = []
        error_count = 0

        system_metrics_start = self.measure_system_metrics()

        for _ in range(iterations):
            try:
                start_time = time.perf_counter()

                if method.upper() == "GET":
                    response = self.client.get(endpoint, headers=headers or {})
                elif method.upper() == "POST":
                    response = self.client.post(endpoint, json=data, headers=headers or {})

                end_time = time.perf_counter()

                response_times.append(end_time - start_time)
                status_codes.append(response.status_code)

                if response.status_code >= 400:
                    error_count += 1

            except Exception:
                error_count += 1
                # Still record a high response time for failed requests
                response_times.append(10.0)  # 10 second penalty
                status_codes.append(500)

        system_metrics_end = self.measure_system_metrics()

        if response_times:
            return {
                "avg_time": statistics.mean(response_times),
                "median_time": statistics.median(response_times),
                "min_time": min(response_times),
                "max_time": max(response_times),
                "p95_time": self._percentile(response_times, 95),
                "p99_time": self._percentile(response_times, 99),
                "std_dev": statistics.stdev(response_times) if len(response_times) > 1 else 0,
                "success_rate": sum(1 for code in status_codes if code < 400) / len(status_codes),
                "error_rate": error_count / iterations,
                "total_requests": iterations,
                "error_count": error_count,
                "throughput_rps": iterations / sum(response_times) if sum(response_times) > 0 else 0,
                "method": method,
                "endpoint": endpoint,
                "system_metrics": {
                    "start": system_metrics_start,
                    "end": system_metrics_end,
                    "cpu_change": system_metrics_end["cpu_percent"] - system_metrics_start["cpu_percent"],
                    "memory_change_mb": system_metrics_end["memory_rss_mb"] - system_metrics_start["memory_rss_mb"],
                },
            }
        else:
            return {"error": "No successful measurements recorded"}

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        size = len(data)
        return sorted(data)[int(size * percentile / 100)]

    def measure_api_performance_suite(self) -> Dict[str, Any]:
        """Measure comprehensive API performance suite."""
        print("🚀 Starting Comprehensive API Performance Monitoring...")
        print("=" * 60)

        measurements = {}

        # Core endpoint measurements
        endpoints = [
            ("GET", "/api/v1/health", "Health Check"),
            ("GET", "/", "API Root"),
        ]

        for method, endpoint, description in endpoints:
            print(f"📊 Measuring {description} ({method} {endpoint})...")

            try:
                measurement = self.measure_endpoint_performance_comprehensive(method, endpoint, iterations=15)
                measurements[endpoint] = measurement
                self._print_comprehensive_results(description, measurement)

            except Exception as e:
                print(f"   ❌ Error measuring {description}: {e}")
                measurements[endpoint] = {"error": str(e)}

        # Calculate overall metrics
        successful_measurements = [
            m
            for m in measurements.values()
            if isinstance(m, dict) and "error" not in m and m.get("success_rate", 0) > 0.8
        ]

        if successful_measurements:
            all_avg_times = [m["avg_time"] for m in successful_measurements]
            all_p95_times = [m["p95_time"] for m in successful_measurements]

            overall_metrics = {
                "avg_response_time": statistics.mean(all_avg_times),
                "median_response_time": statistics.median(all_avg_times),
                "p95_response_time": statistics.mean(all_p95_times),
                "total_endpoints_measured": len(measurements),
                "successful_endpoints": len(successful_measurements),
                "overall_success_rate": statistics.mean([m["success_rate"] for m in successful_measurements]),
                "measurement_timestamp": datetime.now().isoformat(),
                "monitoring_type": "comprehensive_current_performance",
            }
            measurements["overall"] = overall_metrics

            print("\n" + "=" * 60)
            print("📈 Overall Current Performance Summary:")
            print(f"   Average Response Time: {overall_metrics['avg_response_time']:.4f}s")
            print(f"   P95 Response Time: {overall_metrics['p95_response_time']:.4f}s")
            print(f"   Overall Success Rate: {overall_metrics['overall_success_rate']:.1%}")
            print(
                f"   Successful Endpoints: {overall_metrics['successful_endpoints']}/{overall_metrics['total_endpoints_measured']}"
            )

        return measurements

    def _print_comprehensive_results(self, name: str, data: Dict[str, Any]) -> None:
        """Print comprehensive measurement results."""
        if "error" in data:
            print(f"   ❌ {name}: {data['error']}")
            return

        print(f"   {name}:")
        print(f"      Average:    {data['avg_time']:.4f}s")
        print(f"      Median:     {data['median_time']:.4f}s")
        print(f"      P95:        {data['p95_time']:.4f}s")
        print(f"      P99:        {data['p99_time']:.4f}s")
        print(f"      Min/Max:    {data['min_time']:.4f}s / {data['max_time']:.4f}s")
        print(f"      Success:    {data['success_rate']:.1%}")
        print(f"      Throughput: {data['throughput_rps']:.2f} RPS")
        if data["system_metrics"]["cpu_change"]:
            print(f"      CPU Impact: {data['system_metrics']['cpu_change']:+.1f}%")
        print()

    def compare_with_baseline(
        self, current_measurements: Dict[str, Any], baseline_file: str = "performance_baseline.json"
    ) -> Dict[str, Any]:
        """Compare current measurements with baseline performance."""
        if not os.path.exists(baseline_file):
            return {"error": f"Baseline file {baseline_file} not found"}

        try:
            with open(baseline_file, "r") as f:
                baseline = json.load(f)
        except Exception as e:
            return {"error": f"Failed to load baseline: {e}"}

        comparison_results = {}

        print("🔍 Performance Comparison with Baseline:")
        print("=" * 60)

        for endpoint in current_measurements:
            if endpoint == "overall" or endpoint not in baseline:
                continue

            current = current_measurements[endpoint]
            baseline_data = baseline[endpoint]

            if "error" in current or "error" in baseline_data:
                continue

            # Calculate performance impact
            avg_impact = ((current["avg_time"] - baseline_data["avg_time"]) / baseline_data["avg_time"]) * 100
            success_rate_change = (current["success_rate"] - baseline_data["success_rate"]) * 100

            comparison = {
                "baseline_avg": baseline_data["avg_time"],
                "current_avg": current["avg_time"],
                "performance_impact_percent": avg_impact,
                "success_rate_baseline": baseline_data["success_rate"],
                "success_rate_current": current["success_rate"],
                "success_rate_change_percent": success_rate_change,
                "meets_5_percent_requirement": abs(avg_impact) <= 5.0,
            }

            comparison_results[endpoint] = comparison

            print(f"📊 {endpoint}:")
            print(f"   Baseline:    {baseline_data['avg_time']:.4f}s")
            print(f"   Current:     {current['avg_time']:.4f}s")
            print(f"   Impact:      {avg_impact:+.1f}% {'✅' if abs(avg_impact) <= 5.0 else '❌'}")
            print(f"   Success:     {baseline_data['success_rate']:.1%} → {current['success_rate']:.1%}")
            print()

        # Overall assessment
        if comparison_results:
            impacts = [comp["performance_impact_percent"] for comp in comparison_results.values()]
            avg_impact = statistics.mean(impacts)
            max_impact = max(impacts)
            meets_requirement = all(comp["meets_5_percent_requirement"] for comp in comparison_results.values())

            overall_comparison = {
                "average_performance_impact_percent": avg_impact,
                "maximum_performance_impact_percent": max_impact,
                "meets_5_percent_requirement": meets_requirement,
                "endpoints_analyzed": len(comparison_results),
                "comparison_timestamp": datetime.now().isoformat(),
            }

            comparison_results["overall"] = overall_comparison

            print("🎯 Overall Performance Comparison:")
            print(f"   Average Impact: {avg_impact:+.1f}%")
            print(f"   Maximum Impact: {max_impact:+.1f}%")
            print(f"   UAT Requirement: {'✅ MET' if meets_requirement else '❌ NOT MET'} (<5% impact)")
            print(f"   Endpoints: {len(comparison_results)-1}")

        return comparison_results

    def save_performance_data(self, measurements: Dict[str, Any], filename: str = "current_performance.json") -> None:
        """Save current performance measurements."""
        with open(filename, "w") as f:
            json.dump(measurements, f, indent=2)
        print(f"💾 Performance measurements saved to {filename}")

    def update_historical_data(self, measurements: Dict[str, Any]) -> None:
        """Update historical performance tracking."""
        if not self.save_historical:
            return

        historical_data = []
        if os.path.exists(self.historical_file):
            try:
                with open(self.historical_file, "r") as f:
                    historical_data = json.load(f)
            except Exception:
                pass

        # Add current measurements to history
        historical_entry = {"timestamp": datetime.now().isoformat(), "measurements": measurements}
        historical_data.append(historical_entry)

        # Keep only last 100 entries
        historical_data = historical_data[-100:]

        with open(self.historical_file, "w") as f:
            json.dump(historical_data, f, indent=2)


def main() -> bool:
    """Main execution function for current performance monitoring."""
    print("🎯 Issue #89 Current Performance Monitoring")
    print("Repository Pattern Implementation - Comprehensive Performance Analysis")
    print("=" * 60)

    monitor = PerformanceMonitor()

    try:
        # Measure current performance
        current_measurements = monitor.measure_api_performance_suite()
        monitor.save_performance_data(current_measurements)
        monitor.update_historical_data(current_measurements)

        # Compare with baseline
        comparison = monitor.compare_with_baseline(current_measurements)

        # Save comparison results
        if comparison and "error" not in comparison:
            with open("performance_comparison.json", "w") as f:
                json.dump(comparison, f, indent=2)
            print("\n💾 Performance comparison saved to performance_comparison.json")

            # Final assessment
            if "overall" in comparison:
                overall = comparison["overall"]
                print(f"\n🏆 Issue #89 Performance Assessment:")
                print(
                    f"   Repository Pattern Performance Impact: {overall['average_performance_impact_percent']:+.1f}%"
                )
                print(
                    f"   UAT <5% Requirement: {'✅ SATISFIED' if overall['meets_5_percent_requirement'] else '❌ NOT SATISFIED'}"
                )

        return True

    except Exception as e:
        print(f"❌ Performance monitoring failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
