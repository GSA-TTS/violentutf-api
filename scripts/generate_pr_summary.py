#!/usr/bin/env python3
"""Generate PR summary from analysis results"""
import json
import os
import sys

try:
    with open("analysis_results.json", "r") as f:
        results = json.load(f)

    print("## Architectural Compliance Summary\n")
    print(f'- **Compliance Score**: {results.get("compliance_score", 0):.1f}%')
    print(f'- **Files Analyzed**: {results.get("files_analyzed", 0)}')
    print(f'- **Total Violations**: {results.get("total_violations", 0)}')

    sev = results.get("violations_by_severity", {})
    if any(sev.values()):
        print("\n### Violations by Severity:")
        for level in ["critical", "high", "medium", "low"]:
            count = sev.get(level, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[level]
                print(f"- {emoji} {level.capitalize()}: {count}")

    # Set output for next steps
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)

    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"critical_violations={critical}\n")
        f.write(f"high_violations={high}\n")
        f.write(f'total_violations={results.get("total_violations", 0)}\n')
        f.write(f'compliance_score={results.get("compliance_score", 100)}\n')

except Exception as e:
    print(f"Error processing results: {e}")
    sys.exit(1)
