# Complete Audit Scenario

This document provides a comprehensive example of performing a complete database audit using the ViolentUTF API audit tools.

## Scenario Overview

**Objective**: Perform comprehensive audit of production database before major release

**Requirements**:
- Full data asset inventory
- Dependency analysis
- Security classification
- Backup verification
- Performance assessment

## Step-by-Step Execution

### Step 1: Data Asset Discovery

```bash
# Run comprehensive data asset inventory
python3 tools/inventory/data_asset_inventory.py \
  --config production.yaml \
  --output audit-$(date +%Y%m%d) \
  --format json,yaml
```

```python
# Programmatic execution
import asyncio
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def perform_data_asset_discovery():
    tool = DataAssetInventoryTool(project_root=".")

    # Perform comprehensive inventory
    audit_result = await tool.perform_full_inventory()

    # Save results
    inventory = audit_result.findings[0] if audit_result.findings else {}
    output_path = await tool.save_inventory(inventory, "yaml")

    print(f"Data asset inventory completed: {output_path}")
    return audit_result

# Execute
result = asyncio.run(perform_data_asset_discovery())
```

### Step 2: Dependency Analysis

```bash
# Analyze project dependencies with runtime analysis
python3 tools/dependency/comprehensive_analyzer.py \
  --project-root . \
  --include-runtime-analysis \
  --output-format html
```

```python
# Comprehensive dependency analysis
from tools.dependency.comprehensive_analyzer import ComprehensiveAnalyzer

async def perform_dependency_analysis():
    analyzer = ComprehensiveAnalyzer(".")

    # Perform analysis with runtime dependencies
    results = await analyzer.analyze_project_dependencies(include_runtime=True)

    # Check for circular dependencies
    circular_deps = results.get("circular_dependencies", [])
    if circular_deps:
        print(f"WARNING: {len(circular_deps)} circular dependencies detected")
        for dep in circular_deps[:3]:  # Show first 3
            print(f"  - {' -> '.join(dep['chain'])}")

    # Generate report
    report_path = await analyzer.generate_dependency_report("html")
    print(f"Dependency analysis completed: {report_path}")

    return results

dependency_results = asyncio.run(perform_dependency_analysis())
```

### Step 3: Backup Verification

```bash
# Verify backup coverage and test restore capability
python3 scripts/backup_coverage_audit.py \
  --verify-recent-backups \
  --test-restore-capability \
  --report-format html
```

```python
# Programmatic backup verification
from scripts.backup_coverage_audit import perform_backup_coverage_audit

async def verify_backup_coverage():
    # Comprehensive backup audit with restore testing
    results = await perform_backup_coverage_audit(
        verify_recent=True,
        test_restore=True  # This is slow but thorough
    )

    coverage_summary = results.get("coverage_summary", {})
    coverage_percentage = coverage_summary.get("coverage_percentage", 0)

    if coverage_percentage < 95:
        print(f"WARNING: Backup coverage below target ({coverage_percentage}%)")
    else:
        print(f"Backup coverage meets requirements ({coverage_percentage}%)")

    # Test restore results
    restore_results = results.get("restore_test_results", {})
    successful_tests = restore_results.get("successful_tests", 0)
    total_tests = restore_results.get("total_tests", 0)

    print(f"Restore tests: {successful_tests}/{total_tests} successful")

    return results

backup_results = asyncio.run(verify_backup_coverage())
```

### Step 4: Security Classification

```python
# Apply security classification to discovered assets
from tools.inventory.security_classification import classify_data_assets

def perform_security_classification(inventory_data):
    # Apply security classification framework
    classified_inventory = classify_data_assets(inventory_data)

    # Analyze classification results
    classification_summary = classified_inventory.get("security_classification_summary", {})
    classifications = classification_summary.get("classifications", {})

    critical_assets = classifications.get("critical", 0)
    sensitive_assets = classifications.get("sensitive", 0)
    total_assets = classification_summary.get("total_assets", 0)

    print(f"Security Classification Results:")
    print(f"  Critical assets: {critical_assets}")
    print(f"  Sensitive assets: {sensitive_assets}")
    print(f"  Total classified: {total_assets}")

    if critical_assets > 0:
        print(f"  WARNING: {critical_assets} critical assets require enhanced security")

    return classified_inventory

# Apply to inventory results
classified_data = perform_security_classification(result.findings[0] if result.findings else {})
```

### Step 5: Configuration Baseline

```bash
# Establish configuration baseline for production
python3 scripts/config_baseline_manager.py \
  --establish-baseline \
  --name "production_v2.1.0" \
  --sources database,environment,files
```

```python
# Programmatic configuration baseline
from scripts.config_baseline_manager import establish_configuration_baseline

async def establish_production_baseline():
    baseline_result = await establish_configuration_baseline(
        config_sources=["database", "environment", "files"],
        baseline_name=f"production_v2.1.0_{datetime.now().strftime('%Y%m%d')}",
        include_sensitive=False  # Exclude sensitive data for security
    )

    if baseline_result.get("success"):
        config_count = baseline_result.get("configuration_count", 0)
        baseline_file = baseline_result.get("baseline_file_path")
        print(f"Configuration baseline established: {baseline_file}")
        print(f"Configuration items captured: {config_count}")

    return baseline_result

baseline_results = asyncio.run(establish_production_baseline())
```

## Integration Example

### Complete Audit Orchestration

```python
import asyncio
from datetime import datetime
from pathlib import Path

async def complete_production_audit():
    """Complete production audit orchestration."""

    audit_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {
        "audit_timestamp": audit_timestamp,
        "data_assets": None,
        "dependencies": None,
        "backups": None,
        "security": None,
        "configuration": None,
        "summary": {}
    }

    print(f"Starting complete production audit: {audit_timestamp}")

    try:
        # 1. Data Asset Discovery
        print("Phase 1: Data Asset Discovery...")
        asset_tool = DataAssetInventoryTool()
        asset_result = await asset_tool.perform_full_inventory_parallel()
        results["data_assets"] = asset_result
        print("✓ Data asset discovery completed")

        # 2. Dependency Analysis
        print("Phase 2: Dependency Analysis...")
        dep_analyzer = ComprehensiveAnalyzer(".")
        dep_result = await dep_analyzer.analyze_project_dependencies(include_runtime=True)
        results["dependencies"] = dep_result
        print("✓ Dependency analysis completed")

        # 3. Backup Verification
        print("Phase 3: Backup Verification...")
        backup_result = await perform_backup_coverage_audit(
            verify_recent=True,
            test_restore=False  # Skip slow restore tests in orchestrated run
        )
        results["backups"] = backup_result
        print("✓ Backup verification completed")

        # 4. Security Classification
        print("Phase 4: Security Classification...")
        inventory_data = asset_result.findings[0] if asset_result.findings else {}
        security_result = classify_data_assets(inventory_data)
        results["security"] = security_result
        print("✓ Security classification completed")

        # 5. Configuration Baseline
        print("Phase 5: Configuration Baseline...")
        config_result = await establish_configuration_baseline(
            config_sources=["database", "environment"],
            baseline_name=f"production_audit_{audit_timestamp}"
        )
        results["configuration"] = config_result
        print("✓ Configuration baseline completed")

    except Exception as e:
        print(f"Audit failed during execution: {e}")
        results["error"] = str(e)
        raise

    # Generate summary
    results["summary"] = generate_audit_summary(results)

    # Save comprehensive results
    output_dir = Path(f"./audit-results/complete-audit-{audit_timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "complete_audit_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Complete audit finished: {output_dir}/complete_audit_results.json")
    print_audit_summary(results["summary"])

    return results

def generate_audit_summary(results):
    """Generate comprehensive audit summary."""
    summary = {
        "execution_time": None,
        "total_assets": 0,
        "security_critical_assets": 0,
        "circular_dependencies": 0,
        "backup_coverage": 0,
        "configuration_items": 0,
        "recommendations": []
    }

    # Data assets summary
    if results.get("data_assets"):
        asset_data = results["data_assets"]
        if hasattr(asset_data, 'findings') and asset_data.findings:
            inventory = asset_data.findings[0]
            stats = inventory.get("usage_statistics", {})
            asset_counts = stats.get("asset_counts", {})
            summary["total_assets"] = (
                asset_counts.get("total_physical_stores", 0) +
                asset_counts.get("total_logical_assets", 0)
            )

    # Security summary
    if results.get("security"):
        security_data = results["security"]
        classification_summary = security_data.get("security_classification_summary", {})
        classifications = classification_summary.get("classifications", {})
        summary["security_critical_assets"] = classifications.get("critical", 0)

    # Dependencies summary
    if results.get("dependencies"):
        dep_data = results["dependencies"]
        circular_deps = dep_data.get("circular_dependencies", [])
        summary["circular_dependencies"] = len(circular_deps)

    # Backup summary
    if results.get("backups"):
        backup_data = results["backups"]
        coverage_summary = backup_data.get("coverage_summary", {})
        summary["backup_coverage"] = coverage_summary.get("coverage_percentage", 0)

    # Configuration summary
    if results.get("configuration"):
        config_data = results["configuration"]
        summary["configuration_items"] = config_data.get("configuration_count", 0)

    # Generate recommendations
    if summary["security_critical_assets"] > 0:
        summary["recommendations"].append(
            f"Review security measures for {summary['security_critical_assets']} critical assets"
        )

    if summary["circular_dependencies"] > 0:
        summary["recommendations"].append(
            f"Resolve {summary['circular_dependencies']} circular dependencies"
        )

    if summary["backup_coverage"] < 95:
        summary["recommendations"].append(
            f"Improve backup coverage from {summary['backup_coverage']:.1f}% to 95%+"
        )

    return summary

def print_audit_summary(summary):
    """Print formatted audit summary."""
    print("\\n" + "="*60)
    print("PRODUCTION AUDIT SUMMARY")
    print("="*60)
    print(f"Total Assets Discovered: {summary['total_assets']}")
    print(f"Critical Security Assets: {summary['security_critical_assets']}")
    print(f"Circular Dependencies: {summary['circular_dependencies']}")
    print(f"Backup Coverage: {summary['backup_coverage']:.1f}%")
    print(f"Configuration Items: {summary['configuration_items']}")

    if summary["recommendations"]:
        print("\\nRECOMMENDATIONS:")
        for i, rec in enumerate(summary["recommendations"], 1):
            print(f"  {i}. {rec}")
    else:
        print("\\n✓ No critical recommendations - system is in good state")

    print("="*60)

# Execute complete audit
if __name__ == "__main__":
    import json
    audit_results = asyncio.run(complete_production_audit())
```

## Expected Output

The complete audit scenario produces comprehensive reports including:

**Data Asset Inventory**:
- 150+ database tables catalogued
- 45 repository patterns identified
- 12 security-sensitive data stores classified

**Dependency Analysis**:
- 0 circular dependencies (target achieved)
- 89% code coverage in dependency mapping
- 3 optimization recommendations

**Backup Verification**:
- 98% backup coverage achieved
- All critical systems have daily backups
- Restore tests: 15/15 successful

**Security Classification**:
- 8 critical assets requiring enhanced security
- 23 sensitive assets with appropriate controls
- PII data properly classified and protected

**Configuration Baseline**:
- 156 configuration parameters captured
- Production baseline established
- 0 critical configuration drift detected

## Usage Patterns

### Scheduled Execution

```bash
# Add to crontab for weekly production audits
0 2 * * 0 cd /path/to/violentutf-api && python3 -c "
import asyncio
from examples.complete_audit_scenario import complete_production_audit
asyncio.run(complete_production_audit())
" >> /var/log/audit-cron.log 2>&1
```

### CI/CD Integration

```yaml
# .github/workflows/production-audit.yml
name: Production Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sunday at 2 AM

jobs:
  production-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v3
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run Production Audit
        env:
          DATABASE_URL: ${{ secrets.PROD_DATABASE_URL }}
          REDIS_URL: ${{ secrets.PROD_REDIS_URL }}
        run: python3 -c "
import asyncio
from examples.complete_audit_scenario import complete_production_audit
asyncio.run(complete_production_audit())
"

      - name: Upload Audit Results
        uses: actions/upload-artifact@v3
        with:
          name: audit-results
          path: audit-results/
```

## Customization Options

The complete audit scenario can be customized for different environments:

**Development Environment**:
```python
# Lighter audit for development
async def development_audit():
    return await complete_production_audit(
        include_runtime_analysis=False,
        test_restore_capability=False,
        security_classification=False
    )
```

**Staging Environment**:
```python
# Staging-specific audit
async def staging_audit():
    return await complete_production_audit(
        include_performance_testing=True,
        validate_production_readiness=True
    )
```

This complete audit scenario demonstrates the full capabilities of the ViolentUTF API audit tools and provides a template for comprehensive database and application auditing.
