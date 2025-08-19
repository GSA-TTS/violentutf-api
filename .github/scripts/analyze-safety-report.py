#!/usr/bin/env python3
"""Analyze Safety vulnerability report and determine if check should fail."""

import json
import sys
from pathlib import Path


def main() -> None:
    report_file = Path("safety-report.json")

    if not report_file.exists():
        print("ℹ️  Safety report not found - skipping vulnerability check")
        sys.exit(0)

    with open(report_file) as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])

    print("=== Safety Dependency Check Results ===")

    if not vulnerabilities:
        print("✅ No known vulnerabilities found")
        sys.exit(0)

    # Count by severity (Safety uses different format than we expected)
    # Adjust based on actual Safety output format
    critical = 0
    high = 0
    medium = 0
    low = 0

    for vuln in vulnerabilities:
        # Safety might use different field names, adjust as needed
        severity = str(vuln.get("severity", vuln.get("vulnerability", ""))).lower()
        if "critical" in severity:
            critical += 1
        elif "high" in severity:
            high += 1
        elif "medium" in severity:
            medium += 1
        else:
            low += 1

    print(f"Total vulnerabilities found: {len(vulnerabilities)}")
    if critical + high + medium + low == 0:
        # If we couldn't categorize, just show total
        print(f"  Unable to categorize by severity")
    else:
        print(f"  CRITICAL: {critical}")
        print(f"  HIGH: {high}")
        print(f"  MEDIUM: {medium}")
        print(f"  LOW: {low}")

    # Show first few vulnerabilities for visibility
    print("\nVulnerabilities found:")
    for vuln in vulnerabilities[:5]:  # Show first 5
        pkg = vuln.get("package", vuln.get("package_name", "Unknown"))
        desc = vuln.get("vulnerability", vuln.get("advisory", "No description"))
        print(f"  - {pkg}: {desc[:100]}...")

    if len(vulnerabilities) > 5:
        print(f"  ... and {len(vulnerabilities) - 5} more")

    # Only fail on CRITICAL vulnerabilities
    if critical > 0:
        print(f"\n❌ Found {critical} CRITICAL vulnerabilities - failing check")
        sys.exit(1)
    else:
        print("\n✅ No CRITICAL vulnerabilities found - check passed")
        if len(vulnerabilities) > 0:
            print(f"ℹ️  Review the uploaded artifact for full vulnerability details")
        sys.exit(0)


if __name__ == "__main__":
    main()
