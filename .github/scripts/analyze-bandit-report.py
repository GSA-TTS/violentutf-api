#!/usr/bin/env python3
"""Analyze Bandit security report and determine if check should fail."""

import json
import sys
from pathlib import Path


def main() -> None:
    report_file = Path("bandit-report.json")

    if not report_file.exists():
        print("❌ Bandit report not found")
        sys.exit(1)

    with open(report_file) as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    total = metrics.get("_totals", {})
    results = data.get("results", [])

    # Display metrics
    print("=== Bandit Security Scan Results ===")
    print(f"Total issues found: {len(results)}")
    print(f"Severity breakdown:")
    print(f"  HIGH: {total.get('SEVERITY.HIGH', 0)}")
    print(f"  MEDIUM: {total.get('SEVERITY.MEDIUM', 0)}")
    print(f"  LOW: {total.get('SEVERITY.LOW', 0)}")
    print(f"Confidence breakdown:")
    print(f"  HIGH: {total.get('CONFIDENCE.HIGH', 0)}")
    print(f"  MEDIUM: {total.get('CONFIDENCE.MEDIUM', 0)}")
    print(f"  LOW: {total.get('CONFIDENCE.LOW', 0)}")

    # Check for high severity issues
    high_severity = total.get("SEVERITY.HIGH", 0)

    if high_severity > 0:
        print(f"\n❌ Found {high_severity} HIGH severity issues:")
        for result in results:
            if result.get("issue_severity", "").upper() == "HIGH":
                print(f"  - {result.get('filename')}:{result.get('line_number')}: {result.get('issue_text')}")
        print("\nFailing check due to HIGH severity security issues")
        sys.exit(1)
    else:
        print("\n✅ No HIGH severity issues found - check passed")
        if len(results) > 0:
            print(f"ℹ️  {len(results)} lower severity issues found - review artifact for details")
        sys.exit(0)


if __name__ == "__main__":
    main()
