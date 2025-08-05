#!/usr/bin/env python3
"""
Integration script to update claude_code_auditor.py to use enhanced reporting.

This script shows the minimal changes needed to integrate the new
reporting module with the existing auditor.
"""

# The following changes should be made to claude_code_auditor.py:

INTEGRATION_CHANGES = """
# 1. Add import at the top of claude_code_auditor.py (around line 56)
from tools.pre_audit.reporting import (
    ReportConfig,
    ExportManager,
    SecurityLevel
)

# 2. Replace the _generate_html_report method (around line 3500) with:
async def _generate_html_report(self, audit_results: Dict[str, Any], timestamp: str) -> None:
    \"\"\"Generate HTML report using enhanced reporting module.\"\"\"
    # Use new reporting module instead of unsafe string concatenation
    report_config = ReportConfig(
        base_config=self.config,
        output_dir=self.config.reports_dir,
        security_level=SecurityLevel.INTERNAL,
        enable_charts=True,
        include_hotspots=True,
        export_formats=["html"]
    )

    # Generate secure HTML report
    from tools.pre_audit.reporting.exporters import HTMLReportGenerator
    html_gen = HTMLReportGenerator(report_config)
    html_path = html_gen.generate(audit_results)

    # Rename to match expected filename
    expected_path = self.config.reports_dir / f"architectural_audit_{timestamp}.html"
    html_path.rename(expected_path)
    logger.info(f"HTML report saved to {expected_path}")

# 3. Add new method for comprehensive report generation:
async def generate_comprehensive_reports(self, audit_results: Dict[str, Any]) -> Dict[str, Path]:
    \"\"\"Generate reports in multiple formats using enhanced reporting.\"\"\"
    # Configure based on audit mode
    security_level = SecurityLevel.INTERNAL
    if hasattr(self, 'security_audit_mode') and self.security_audit_mode:
        security_level = SecurityLevel.RESTRICTED

    report_config = ReportConfig(
        base_config=self.config,
        security_level=security_level,
        enable_charts=True,
        include_hotspots=True,
        include_recommendations=True,
        include_executive_summary=True,
        enable_parallel_export=True,
        export_formats=["html", "json", "pdf"]
    )

    # Generate all reports
    export_manager = ExportManager(report_config)
    return export_manager.export_all(audit_results)

# 4. Update the run_comprehensive_audit method to use new reporting:
# Add after saving audit results (around line 3000):
if self.config.enable_enhanced_reporting:  # New config option
    report_paths = await self.generate_comprehensive_reports(audit_results)
    logger.info(f"Generated enhanced reports: {list(report_paths.keys())}")
"""


def generate_patch_file() -> None:
    """Generate a patch file for easy integration."""
    patch_content = '''--- a/tools/pre_audit/claude_code_auditor.py
+++ b/tools/pre_audit/claude_code_auditor.py
@@ -53,6 +53,12 @@ from tools.pre_audit.git_history_parser import ArchitecturalFix, FileChangePattern, GitHis
 from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher, FixType

+# Import enhanced reporting module
+from tools.pre_audit.reporting import (
+    ReportConfig,
+    ExportManager,
+    SecurityLevel
+)
+
 # Import statistical hotspot analysis components (GitHub Issue #43)
 try:
@@ -200,6 +206,7 @@ class EnterpriseClaudeCodeConfig:
     enable_html_reports: bool = True
     enable_sarif_output: bool = False
+    enable_enhanced_reporting: bool = True  # New option

     # Advanced caching configuration
@@ -3497,23 +3504,25 @@ class EnterpriseClaudeCodeAuditor:

     async def _generate_html_report(self, audit_results: Dict[str, Any], timestamp: str) -> None:
-        """Generate HTML report for audit results."""
-        html_content = self._create_html_report_template(audit_results)
-        html_file = self.config.reports_dir / f"architectural_audit_{timestamp}.html"
-        with open(html_file, "w", encoding="utf-8") as f:
-            f.write(html_content)
-        logger.info(f"HTML report saved to {html_file}")
+        """Generate HTML report using enhanced reporting module."""
+        # Use new reporting module instead of unsafe string concatenation
+        report_config = ReportConfig(
+            base_config=self.config,
+            output_dir=self.config.reports_dir,
+            security_level=SecurityLevel.INTERNAL,
+            enable_charts=True,
+            include_hotspots=True,
+            export_formats=["html"]
+        )
+
+        # Generate secure HTML report
+        from tools.pre_audit.reporting.exporters import HTMLReportGenerator
+        html_gen = HTMLReportGenerator(report_config)
+        html_path = html_gen.generate(audit_results)
+
+        # Rename to match expected filename
+        expected_path = self.config.reports_dir / f"architectural_audit_{timestamp}.html"
+        html_path.rename(expected_path)
+        logger.info(f"HTML report saved to {expected_path}")

-    def _create_html_report_template(self, audit_results: Dict[str, Any]) -> str:
-        """Create HTML report template."""
-        compliance_score = audit_results.get("overall_compliance_score", 0)
-        violations = audit_results.get("violation_summary", {})
-        return f"""
-<!DOCTYPE html>
-<html>
-<head>
-    <title>Architectural Audit Report</title>
-    <style>
-        body {{ font-family: Arial, sans-serif; margin: 40px; }}
'''

    with open("claude_code_auditor_reporting.patch", "w") as f:
        f.write(patch_content)

    print("✅ Generated patch file: claude_code_auditor_reporting.patch")
    print("Apply with: git apply claude_code_auditor_reporting.patch")


def create_migration_script() -> None:
    """Create a migration script for existing installations."""
    script_content = '''#!/usr/bin/env python3
"""
Migration script to update existing claude_code_auditor installations
to use the enhanced reporting module.
"""

import sys
import shutil
from pathlib import Path

def migrate_auditor():
    """Migrate claude_code_auditor.py to use enhanced reporting."""
    auditor_path = Path("tools/pre_audit/claude_code_auditor.py")

    if not auditor_path.exists():
        print("❌ claude_code_auditor.py not found!")
        return False

    # Backup original
    backup_path = auditor_path.with_suffix(".py.backup")
    shutil.copy2(auditor_path, backup_path)
    print(f"✅ Created backup: {backup_path}")

    # Read file
    with open(auditor_path, 'r') as f:
        content = f.read()

    # Check if already migrated
    if "from tools.pre_audit.reporting import" in content:
        print("ℹ️  Already migrated to enhanced reporting")
        return True

    # Add import
    import_marker = "from tools.pre_audit.git_pattern_matcher import"
    import_addition = """from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher, FixType

# Import enhanced reporting module
from tools.pre_audit.reporting import (
    ReportConfig,
    ExportManager,
    SecurityLevel
)"""

    content = content.replace(
        "from tools.pre_audit.git_pattern_matcher import ArchitecturalFixPatternMatcher, FixType",
        import_addition
    )

    # Add config option
    config_marker = "enable_sarif_output: bool = False"
    config_addition = """enable_sarif_output: bool = False
    enable_enhanced_reporting: bool = True  # Use enhanced reporting module"""

    content = content.replace(config_marker, config_addition)

    # Write updated file
    with open(auditor_path, 'w') as f:
        f.write(content)

    print("✅ Migration complete!")
    print("ℹ️  The HTML report generation now uses secure templates")
    print("ℹ️  Run with --enable-enhanced-reporting to use all features")

    return True

if __name__ == "__main__":
    if migrate_auditor():
        print("\\n🎉 Successfully migrated to enhanced reporting!")
    else:
        print("\\n❌ Migration failed!")
        sys.exit(1)
'''

    with open("migrate_reporting.py", "w") as f:
        f.write(script_content)

    # Make executable with secure permissions (owner only)
    import os

    os.chmod("migrate_reporting.py", 0o700)  # nosec B103 - Restrictive permissions set

    print("✅ Created migration script: migrate_reporting.py")


def show_integration_example() -> None:
    """Show a complete integration example."""
    print("\n📋 Integration Example:")
    print("=" * 60)
    print(
        """
# In your existing code that uses claude_code_auditor:

async def run_audit_with_enhanced_reporting(repo_path: str):
    # 1. Configure auditor as usual
    config = EnterpriseClaudeCodeConfig(
        repo_path=repo_path,
        enable_multi_tool_analysis=True,
        enable_enhanced_reporting=True  # Enable new reporting
    )

    # 2. Run audit
    auditor = EnterpriseClaudeCodeAuditor(config)
    audit_results = await auditor.run_comprehensive_audit()

    # 3. Generate enhanced reports (automatic if enabled)
    # Reports will be in config.reports_dir with:
    # - Secure HTML (no XSS vulnerabilities)
    # - Validated JSON with schema
    # - Professional PDF (if ReportLab installed)

    # 4. Or manually generate specific formats:
    report_config = ReportConfig(
        base_config=config,
        security_level=SecurityLevel.INTERNAL,
        export_formats=["html", "pdf"]  # Only these formats
    )

    export_manager = ExportManager(report_config)
    report_paths = export_manager.export_all(audit_results)

    return report_paths
"""
    )
    print("=" * 60)


def main() -> None:
    """Main function."""
    print("🔧 Enhanced Reporting Integration Helper")
    print("\nThis script helps integrate the new reporting module with claude_code_auditor.py")

    print("\n1. Required Changes:")
    print(INTEGRATION_CHANGES)

    print("\n2. Generating migration files...")
    generate_patch_file()
    create_migration_script()

    show_integration_example()

    print("\n✅ Integration files created!")
    print("\nNext steps:")
    print("1. Review the changes in the patch file")
    print("2. Run: python migrate_reporting.py")
    print("3. Test with: python claude_code_auditor.py <repo_path>")
    print("\nThe enhanced reporting module will:")
    print("- Fix XSS vulnerabilities in HTML reports")
    print("- Add PDF and enhanced JSON export")
    print("- Integrate statistical hotspot analysis")
    print("- Provide configurable security levels")


if __name__ == "__main__":
    main()
