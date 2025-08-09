#!/usr/bin/env python3
"""
Usage example for the enhanced reporting module.

This example demonstrates how to integrate the new reporting
capabilities with the existing claude_code_auditor.py system.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

# Import existing auditor
try:
    from tools.pre_audit.claude_code_auditor import EnterpriseClaudeCodeAuditor, EnterpriseClaudeCodeConfig
except ImportError:
    # Mock classes for environments where claude_code_auditor is not available
    print("Warning: claude_code_auditor not available. Using mock classes.")

    class EnterpriseClaudeCodeConfig:
        """Mock configuration class."""

        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    class EnterpriseClaudeCodeAuditor:
        """Mock auditor class."""

        def __init__(self, config):
            self.config = config

        async def analyze_repository(self):
            """Mock analysis method."""
            return {
                "status": "success",
                "violations": [],
                "compliance_score": 100.0,
                "hotspot_analysis": {},
                "summary": {"total_files": 0, "files_analyzed": 0},
            }


# Import new reporting components
from tools.pre_audit.reporting import (
    ExportManager,
    HTMLReportGenerator,
    JSONReportGenerator,
    PDFReportGenerator,
    ReportConfig,
    SecurityLevel,
)


async def generate_comprehensive_reports(repo_path: str, output_dir: str = "reports"):
    """
    Generate comprehensive reports using the enhanced reporting module.

    Args:
        repo_path: Path to repository to audit
        output_dir: Directory for report output
    """
    print(f"\n🔍 Starting architectural audit for: {repo_path}")

    # Step 1: Configure and run audit
    config = EnterpriseClaudeCodeConfig(
        repo_path=repo_path,
        enable_multi_tool_analysis=True,
        enable_caching=True,
        enable_html_reports=False,  # Disable old HTML generation
        enable_sarif_output=True,
        cache_ttl=3600,
        max_workers=4,
    )

    # Initialize auditor
    auditor = EnterpriseClaudeCodeAuditor(config)

    # Run comprehensive audit
    print("📊 Running architectural audit...")
    audit_results = await auditor.run_comprehensive_audit()

    # Step 2: Configure enhanced reporting
    report_config = ReportConfig(
        base_config=config,
        output_dir=Path(output_dir),
        enable_charts=True,
        include_recommendations=True,
        include_executive_summary=True,
        security_level=SecurityLevel.INTERNAL,
        include_hotspots=True,
        hotspot_detail_level="full",
        enable_parallel_export=True,
        export_formats=["html", "json", "pdf"],
    )

    # Step 3: Generate reports using ExportManager
    print("\n📄 Generating enhanced reports...")
    export_manager = ExportManager(report_config)

    # Export all formats in parallel
    output_paths = export_manager.export_all(audit_results)

    # Step 4: Display results
    print("\n✅ Report generation complete!")
    print("\nGenerated reports:")
    for format_name, path in output_paths.items():
        if path:
            size = path.stat().st_size / 1024  # KB
            print(f"  - {format_name.upper()}: {path} ({size:.1f} KB)")
        else:
            print(f"  - {format_name.upper()}: Failed to generate")

    # Step 5: Get statistics
    stats = export_manager.get_export_stats()
    print(f"\nExport statistics:")
    print(f"  - Total exports: {stats['successful_exports']}")
    print(f"  - Total time: {stats['total_time']:.2f} seconds")
    if stats.get("average_format_times"):
        print("  - Average times by format:")
        for fmt, time in stats["average_format_times"].items():
            print(f"    - {fmt}: {time:.2f}s")

    # Step 6: Create archive for distribution
    if report_config.security_level == SecurityLevel.PUBLIC:
        print("\n📦 Creating archive for public distribution...")
        archive_path = export_manager.export_to_archive(audit_results)
        print(f"  - Archive created: {archive_path}")

    return output_paths


async def generate_security_focused_report(repo_path: str):
    """
    Generate security-focused report with restricted data.

    Args:
        repo_path: Path to repository to audit
    """
    # Configure for security team
    config = EnterpriseClaudeCodeConfig(
        repo_path=repo_path, enable_security_testing=True, enable_adversarial_testing=True
    )

    # Run audit
    auditor = EnterpriseClaudeCodeAuditor(config)
    audit_results = await auditor.run_comprehensive_audit()

    # Configure restricted report
    report_config = ReportConfig(
        base_config=config,
        security_level=SecurityLevel.RESTRICTED,
        include_hotspots=True,
        statistical_confidence_threshold=0.99,  # Higher confidence
        max_hotspots_display=50,  # More details
        export_formats=["json", "pdf"],  # No HTML for security
    )

    # Generate using individual generators
    json_gen = JSONReportGenerator(report_config)
    json_path = json_gen.generate(audit_results)

    pdf_gen = PDFReportGenerator(report_config)
    pdf_path = pdf_gen.generate(audit_results)

    print(f"\n🔒 Security reports generated:")
    print(f"  - JSON: {json_path}")
    print(f"  - PDF: {pdf_path}")

    return json_path, pdf_path


async def generate_executive_summary(repo_path: str):
    """
    Generate executive summary for stakeholders.

    Args:
        repo_path: Path to repository to audit
    """
    # Quick audit for summary
    config = EnterpriseClaudeCodeConfig(repo_path=repo_path, quick_mode=True)

    auditor = EnterpriseClaudeCodeAuditor(config)
    audit_results = await auditor.run_comprehensive_audit()

    # Configure public-safe report
    report_config = ReportConfig(
        base_config=config,
        security_level=SecurityLevel.PUBLIC,
        include_executive_summary=True,
        include_recommendations=True,
        include_hotspots=False,  # No technical details
        export_formats=["html", "pdf"],
    )

    # Generate HTML for web viewing
    html_gen = HTMLReportGenerator(report_config)
    html_path = html_gen.generate(audit_results)

    print(f"\n📊 Executive summary generated: {html_path}")

    # Extract key metrics for dashboard
    with open(html_path.with_suffix(".json"), "r") as f:
        data = json.load(f)

    print("\nKey Metrics:")
    print(f"  - Compliance Score: {data['summary']['compliance_score']:.1f}%")
    print(f"  - Risk Level: {data['summary']['risk_assessment']}")
    print(f"  - Technical Debt: {data['summary']['technical_debt_days']:.1f} days")

    return html_path


def demonstrate_security_features():
    """Demonstrate security features of the reporting module."""
    from tools.pre_audit.reporting.security import InputValidator, OutputEncoder, ValidationError

    print("\n🔒 Security Features Demonstration")

    # Input validation
    validator = InputValidator(strict_mode=True)

    # Test XSS prevention
    malicious_inputs = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "'; DROP TABLE users; --",
    ]

    print("\n1. Input Validation:")
    for input_str in malicious_inputs:
        try:
            validator.validate_string(input_str, "test_field")
            print(f"  ❌ Failed to block: {input_str[:30]}...")
        except ValidationError as e:
            print(f"  ✅ Blocked: {input_str[:30]}... - {str(e)[:50]}...")

    # Output encoding
    encoder = OutputEncoder()

    print("\n2. Output Encoding:")
    test_data = {"file_path": "../../etc/passwd", "message": "<script>alert('XSS')</script>", "risk_score": 0.95}

    encoded_html = encoder.encode_dict_values(test_data)
    print(f"  Original: {test_data['message']}")
    print(f"  Encoded:  {encoded_html['message']}")

    # Path sanitization
    print("\n3. Path Sanitization:")
    dangerous_paths = [
        "../../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32\\config\\sam",
        "path/with\x00null/byte",
    ]

    for path in dangerous_paths:
        try:
            validator.validate_file_path(path)
            print(f"  ❌ Failed to block: {path}")
        except ValidationError:
            print(f"  ✅ Blocked dangerous path: {path}")


async def main():
    """Main demonstration function."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python usage_example.py <repo_path> [report_type]")
        print("\nReport types:")
        print("  - comprehensive (default)")
        print("  - security")
        print("  - executive")
        print("  - demo-security")
        return

    repo_path = sys.argv[1]
    report_type = sys.argv[2] if len(sys.argv) > 2 else "comprehensive"

    try:
        if report_type == "comprehensive":
            await generate_comprehensive_reports(repo_path)
        elif report_type == "security":
            await generate_security_focused_report(repo_path)
        elif report_type == "executive":
            await generate_executive_summary(repo_path)
        elif report_type == "demo-security":
            demonstrate_security_features()
        else:
            print(f"Unknown report type: {report_type}")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
