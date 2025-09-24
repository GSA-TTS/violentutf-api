#!/usr/bin/env python3
"""Aggressive profiler to identify critical bottlenecks for final optimization."""

import cProfile
import io
import json
import pstats
import tempfile
from pathlib import Path

from scripts.backup_coverage_audit import BackupCoverageAuditor, BackupGap, CriticalityLevel
from scripts.config_baseline_manager import ConfigurationBaselineManager


def profile_critical_operations():
    """Profile critical operations to identify bottlenecks."""
    print("=" * 80)
    print("PROFILING CRITICAL OPERATIONS FOR FINAL OPTIMIZATION")
    print("=" * 80)

    # Profile 1: Large Gap Prioritization (most time-consuming operation)
    print("\n1. PROFILING LARGE GAP PRIORITIZATION...")
    pr = cProfile.Profile()
    pr.enable()

    auditor = BackupCoverageAuditor()
    large_gaps = [
        BackupGap(
            f"enterprise_repo_{i}",
            CriticalityLevel.CRITICAL if i % 4 == 0 else CriticalityLevel.STANDARD,
            float(i % 200) + (i * 0.1),
            None,
        )
        for i in range(15000)
    ]

    # Run the operation
    _ = auditor.prioritize_backup_gaps(large_gaps)[:100]

    pr.disable()

    # Analyze results
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(20)  # Top 20 functions
    print(s.getvalue())

    # Profile 2: Configuration Baseline Heavy I/O
    print("\n2. PROFILING CONFIGURATION BASELINE I/O...")
    with tempfile.TemporaryDirectory() as temp_dir:
        baseline_dir = Path(temp_dir)

        # Create 500 files for heavy I/O test
        for i in range(500):
            filename = f"production_heavy_{i}_v1.0_20240101_120000.json"
            content = {
                "environment": "production",
                "configurations": {f"key_{j}": f"value_{j}" * 50 for j in range(100)},  # Large content
                "timestamp": "2024-01-01T12:00:00Z",
                "version": "v1.0",
                "checksum": f"hash_{i}",
            }
            with open(baseline_dir / filename, "w") as f:
                json.dump(content, f)

        pr = cProfile.Profile()
        pr.enable()

        manager = ConfigurationBaselineManager(baseline_dir=temp_dir)
        # Run heavy operation multiple times
        for _ in range(10):
            _ = manager.list_baselines()

        pr.disable()

        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
        ps.print_stats(20)
        print(s.getvalue())

    print("\n" + "=" * 80)
    print("PROFILING COMPLETE - IDENTIFY TOP BOTTLENECKS ABOVE")
    print("=" * 80)


if __name__ == "__main__":
    profile_critical_operations()
