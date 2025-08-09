#!/usr/bin/env python3
"""
Test script to demonstrate enhanced HTML reports with debug mode details.

This script creates sample audit data that includes the rich details from debug mode
and generates an HTML report showcasing all the new features.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.pre_audit.reporting import ExportManager, ReportConfig, SecurityLevel


def create_sample_audit_data() -> dict[str, Any]:
    """Create sample audit data with debug mode details."""
    return {
        "audit_metadata": {
            "repository_path": "/Users/test/violentutf-api",
            "adr_path": "/Users/test/violentutf-api/docs/architecture/ADRs",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_seconds": 42.7,
            "mode": "comprehensive",
            "total_adrs_analyzed": 12,
            "total_files_analyzed": 156,
            "audit_version": "2.0.1",
            "multi_tool_analysis": True,
            "git_forensics_enabled": True,
            "rag_analysis_enabled": True,
            "hotspot_analysis_time": 5.3,
            "multi_tool_time": 12.4,
            "forensics_time": 8.7,
            "rag_time": 6.2,
            "multi_tool_findings": [
                "SonarQube: 23 code smells detected",
                "Bandit: 5 security issues found",
                "Lizard: 8 complex functions identified",
            ],
            "forensics_findings": [
                "15 violation patterns identified in git history",
                "3 recurring architectural regression patterns",
            ],
            "rag_findings": [
                "7 implicit architectural patterns detected",
                "4 undocumented architectural decisions found",
            ],
        },
        "overall_compliance_score": 73.5,
        "discovered_adrs": [
            {"adr_id": "ADR-001", "title": "API Authentication Strategy", "file_path": "ADRs/adr-001.md"},
            {"adr_id": "ADR-002", "title": "RBAC Authorization Model", "file_path": "ADRs/adr-002.md"},
            {"adr_id": "ADR-003", "title": "Rate Limiting Strategy", "file_path": "ADRs/adr-003.md"},
        ],
        "adr_compliance": {
            "ADR-001": {
                "adr_title": "API Authentication Strategy",
                "compliance_score": 85,
                "analysis_methods": ["Semantic Claude Code", "Static Analysis", "Git Forensics", "RAG Enhanced"],
                "confidence": 0.92,
                "dimensions_analyzed": 4,
                "execution_time": 3.2,
                "cache_hit_rate": 0.65,
                "tools_executed": ["SonarQube", "Bandit", "PyTestArch"],
                "requirements": [
                    "All API endpoints must use JWT authentication",
                    "Tokens must expire within 15 minutes",
                    "Refresh tokens must be used for session management",
                    "API keys must be hashed using bcrypt",
                    "Rate limiting must be applied per API key",
                ],
                "violations": [
                    {
                        "file_path": "app/api/endpoints/users.py",
                        "line_number": 45,
                        "risk_level": "high",
                        "description": "API endpoint missing JWT authentication",
                        "evidence": "@app.get('/users/{user_id}') # No auth decorator",
                        "adr_id": "ADR-001",
                        "technical_debt_hours": 4,
                    },
                    {
                        "file_path": "app/core/auth.py",
                        "line_number": 123,
                        "risk_level": "medium",
                        "description": "Token expiration set to 60 minutes instead of 15",
                        "evidence": "expires_delta=timedelta(minutes=60)",
                        "adr_id": "ADR-001",
                        "technical_debt_hours": 1,
                    },
                ],
                "compliant_areas": [
                    "JWT implementation using industry-standard library",
                    "Proper token validation in middleware",
                    "Secure token storage practices",
                    "API key hashing implemented correctly",
                ],
                "insights": [
                    {"type": "Security", "text": "Authentication coverage at 85% - critical gaps in user endpoints"},
                    {"type": "Performance", "text": "Token validation adds ~50ms latency per request"},
                    {"type": "Maintenance", "text": "Authentication logic well-modularized and testable"},
                ],
                "remediation_plan": {
                    "estimated_effort": "2-3 days",
                    "priority": "high",
                    "steps": [
                        "Add authentication decorator to all user endpoints",
                        "Update token expiration configuration",
                        "Add integration tests for auth flows",
                    ],
                },
            },
            "ADR-002": {
                "adr_title": "RBAC Authorization Model",
                "compliance_score": 62,
                "analysis_methods": ["Semantic Claude Code", "Static Analysis"],
                "confidence": 0.88,
                "dimensions_analyzed": 2,
                "execution_time": 2.8,
                "violations": [
                    {
                        "file_path": "app/api/endpoints/admin.py",
                        "line_number": 78,
                        "risk_level": "critical",
                        "description": "Admin endpoint accessible without role check",
                        "evidence": "# TODO: Add role validation",
                        "adr_id": "ADR-002",
                        "technical_debt_hours": 8,
                    }
                ],
                "compliant_areas": ["Role model properly defined in database", "Permission system implemented"],
                "requirements": [
                    "All endpoints must validate user roles",
                    "Role hierarchy must be enforced",
                    "Permission checks must be granular",
                ],
            },
        },
        "all_violations": [
            {
                "file_path": "app/api/endpoints/users.py",
                "line_number": 45,
                "risk_level": "high",
                "description": "API endpoint missing JWT authentication",
                "evidence": "@app.get('/users/{user_id}') # No auth decorator",
                "adr_id": "ADR-001",
                "adr_title": "API Authentication Strategy",
                "technical_debt_hours": 4,
                "remediation_guidance": "Add @require_auth decorator to endpoint",
            },
            {
                "file_path": "app/core/auth.py",
                "line_number": 123,
                "risk_level": "medium",
                "description": "Token expiration set to 60 minutes instead of 15",
                "evidence": "expires_delta=timedelta(minutes=60)",
                "adr_id": "ADR-001",
                "adr_title": "API Authentication Strategy",
                "technical_debt_hours": 1,
                "remediation_guidance": "Update to timedelta(minutes=15)",
            },
            {
                "file_path": "app/api/endpoints/admin.py",
                "line_number": 78,
                "risk_level": "critical",
                "description": "Admin endpoint accessible without role check",
                "evidence": "# TODO: Add role validation",
                "adr_id": "ADR-002",
                "adr_title": "RBAC Authorization Model",
                "technical_debt_hours": 8,
                "remediation_guidance": "Implement role-based access control",
            },
        ],
        "architectural_hotspots": [
            {
                "file_path": "app/api/endpoints/admin.py",
                "risk_score": 92,
                "churn_score": 85,
                "complexity_score": 78,
                "violation_history": ["ADR-002", "ADR-003", "ADR-008"],
                "recommendations": [
                    "Refactor admin endpoints to use proper RBAC",
                    "Add comprehensive security tests",
                    "Consider splitting into smaller modules",
                ],
            },
            {
                "file_path": "app/core/auth.py",
                "risk_score": 75,
                "churn_score": 68,
                "complexity_score": 62,
                "violation_history": ["ADR-001"],
                "recommendations": ["Standardize authentication patterns", "Add token refresh mechanism"],
            },
        ],
        "recommendations": [
            {
                "priority": "critical",
                "category": "Security",
                "description": "Implement role-based access control for all admin endpoints",
                "effort": "1 week",
                "impact": "Prevents unauthorized access to sensitive operations",
            },
            {
                "priority": "high",
                "category": "Security",
                "description": "Add authentication to all API endpoints",
                "effort": "3 days",
                "impact": "Ensures all APIs are properly secured",
            },
            {
                "priority": "medium",
                "category": "Architecture",
                "description": "Refactor authentication module to reduce complexity",
                "effort": "5 days",
                "impact": "Improves maintainability and reduces bugs",
            },
        ],
    }


def main() -> int:
    """Generate enhanced HTML report with debug details."""
    print("🚀 Testing Enhanced HTML Reports with Debug Mode Details")
    print("=" * 60)

    # Create output directory
    output_dir = Path("./test_reports")
    output_dir.mkdir(exist_ok=True)

    # Configure reporting
    config = ReportConfig(
        output_dir=output_dir,
        security_level=SecurityLevel.INTERNAL,
        enable_charts=True,
        include_hotspots=True,
        include_recommendations=True,
        include_executive_summary=True,
        export_formats=["html", "json"],
    )

    # Create sample data
    print("\n📊 Creating sample audit data with debug details...")
    audit_data = create_sample_audit_data()

    # Generate reports
    print("\n📝 Generating enhanced reports...")
    export_manager = ExportManager(config)

    try:
        reports = export_manager.export_all(audit_data)

        print("\n✅ Reports generated successfully!")
        print("\nGenerated files:")
        for format_type, path in reports.items():
            print(f"  - {format_type.upper()}: {path}")

        # Also save the raw audit data for reference
        raw_data_path = output_dir / "sample_audit_data.json"
        with open(raw_data_path, "w") as f:
            json.dump(audit_data, f, indent=2, default=str)
        print(f"  - Raw audit data: {raw_data_path}")

        if "html" in reports and reports["html"]:
            print(f"\n🎉 Open the HTML report in your browser:")
            print(f"   file://{reports['html'].absolute()}")
        else:
            print("\n⚠️  HTML report generation failed. Check logs for details.")

    except Exception as e:
        print(f"\n❌ Error generating reports: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
