# Configuration Tools API Reference

This document provides comprehensive API documentation for configuration management audit automation tools in the ViolentUTF API system.

## Overview

The configuration tools provide comprehensive configuration management capabilities including baseline establishment, drift detection, and configuration validation. These tools ensure system configurations remain consistent and compliant with established standards.

## Tools and Functions

### Configuration Baseline Manager

**Location**: `scripts/config_baseline_manager.py`

Manages configuration baselines and provides comparison capabilities for configuration drift detection.

#### Key Functions

##### establish_configuration_baseline()

Creates a new configuration baseline from current system state.

```python
async def establish_configuration_baseline(
    config_sources: List[str],
    baseline_name: str,
    include_sensitive: bool = False,
    output_directory: str = "./config-baselines"
) -> Dict[str, Any]:
    """
    Establish configuration baseline from current system state.

    Args:
        config_sources: List of configuration sources to include
        baseline_name: Name for the baseline configuration
        include_sensitive: Whether to include sensitive configuration data
        output_directory: Directory to store baseline files

    Returns:
        Dict containing baseline establishment results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_sources` | `List[str]` | - | Configuration sources: "database", "environment", "files", "secrets" |
| `baseline_name` | `str` | - | Unique name for the baseline configuration |
| `include_sensitive` | `bool` | `False` | Include sensitive data (use with caution) |
| `output_directory` | `str` | `"./config-baselines"` | Directory to store baseline files |

**Returns**:
- `Dict[str, Any]`: Baseline establishment results including:
  - `baseline_file_path`: Path to created baseline file
  - `configuration_count`: Number of configuration items captured
  - `source_summary`: Summary of configuration sources included
  - `checksum`: Baseline file integrity checksum
  - `timestamp`: Baseline creation timestamp
  - `success`: Boolean indicating operation success

**Example Usage**:

```python
import asyncio
from scripts.config_baseline_manager import establish_configuration_baseline

async def create_production_baseline():
    # Establish comprehensive baseline
    baseline_result = await establish_configuration_baseline(
        config_sources=["database", "environment", "files"],
        baseline_name="production_v2.1.0",
        include_sensitive=False,  # Exclude sensitive data for security
        output_directory="./baselines/production"
    )

    if baseline_result.get("success"):
        baseline_file = baseline_result.get("baseline_file_path")
        config_count = baseline_result.get("configuration_count", 0)
        print(f"Baseline created: {baseline_file}")
        print(f"Configuration items captured: {config_count}")
    else:
        print("Baseline creation failed - check logs for details")

    return baseline_result

asyncio.run(create_production_baseline())
```

**Command Line Usage**:

```bash
# Establish basic configuration baseline
python3 scripts/config_baseline_manager.py --create-baseline production_v1.0

# Establish comprehensive baseline with multiple sources
python3 scripts/config_baseline_manager.py --create-baseline production_v1.0 \
  --sources database,environment,files --output-dir ./baselines

# Compare current config with baseline
python3 scripts/config_baseline_manager.py --compare-baseline ./baselines/production_v1.0.yaml

# Run drift detection
python3 scripts/config_drift_detector.py --baseline ./baselines/production_v1.0.yaml
```

##### compare_with_baseline()

Compares current configuration state with established baseline.

```python
async def compare_with_baseline(
    baseline_file_path: str,
    comparison_sources: Optional[List[str]] = None,
    ignore_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Compare current configuration with established baseline.

    Args:
        baseline_file_path: Path to baseline configuration file
        comparison_sources: Configuration sources to compare (defaults to all)
        ignore_patterns: Configuration patterns to ignore in comparison

    Returns:
        Dict containing comparison results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `baseline_file_path` | `str` | - | Path to baseline configuration file |
| `comparison_sources` | `Optional[List[str]]` | `None` | Sources to compare. Uses all if None |
| `ignore_patterns` | `Optional[List[str]]` | `None` | Regex patterns to ignore in comparison |

**Returns**:
- `Dict[str, Any]`: Comparison results including:
  - `drift_detected`: Boolean indicating if drift was found
  - `configuration_changes`: List of detected configuration changes
  - `added_configurations`: New configurations not in baseline
  - `removed_configurations`: Configurations removed since baseline
  - `modified_configurations`: Configurations that have changed
  - `drift_severity`: Overall drift severity ("low", "medium", "high")

**Example Usage**:

```python
# Compare current state with production baseline
comparison_result = await compare_with_baseline(
    baseline_file_path="./baselines/production/production_v2.1.0.json",
    ignore_patterns=["timestamp_.*", "temp_.*"]  # Ignore timestamp and temp configs
)

drift_detected = comparison_result.get("drift_detected", False)
if drift_detected:
    changes = comparison_result.get("configuration_changes", [])
    severity = comparison_result.get("drift_severity", "unknown")

    print(f"Configuration drift detected (severity: {severity})")
    print(f"Total changes: {len(changes)}")

    for change in changes[:5]:  # Show first 5 changes
        print(f"- {change['type']}: {change['key']} = {change['current_value']}")
else:
    print("No configuration drift detected")
```

##### update_baseline()

Updates an existing baseline with approved configuration changes.

```python
async def update_baseline(
    baseline_file_path: str,
    approved_changes: List[Dict[str, Any]],
    update_reason: str
) -> Dict[str, Any]:
    """
    Update baseline with approved configuration changes.

    Args:
        baseline_file_path: Path to baseline configuration file
        approved_changes: List of approved configuration changes
        update_reason: Reason for baseline update

    Returns:
        Dict containing update results
    """
```

**Example Usage**:

```python
# Update baseline with approved changes
approved_changes = [
    {
        "key": "database.pool_size",
        "old_value": 10,
        "new_value": 15,
        "approved_by": "admin@example.com"
    }
]

update_result = await update_baseline(
    baseline_file_path="./baselines/production/production_v2.1.0.json",
    approved_changes=approved_changes,
    update_reason="Performance optimization - increased pool size"
)
```

### Configuration Drift Detector

**Location**: `scripts/config_drift_detector.py`

Provides automated configuration drift detection and alerting capabilities.

#### Key Functions

##### detect_configuration_drift()

Detects configuration drift across multiple systems and environments.

```python
async def detect_configuration_drift(
    baseline_directory: str,
    target_environments: List[str],
    drift_threshold: float = 0.05,
    include_real_time: bool = True
) -> Dict[str, Any]:
    """
    Detect configuration drift across environments.

    Args:
        baseline_directory: Directory containing baseline configurations
        target_environments: List of environments to check for drift
        drift_threshold: Threshold percentage for drift alerting (0.0-1.0)
        include_real_time: Include real-time configuration monitoring

    Returns:
        Dict containing drift detection results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `baseline_directory` | `str` | - | Directory containing baseline configuration files |
| `target_environments` | `List[str]` | - | Environments to monitor: "production", "staging", "development" |
| `drift_threshold` | `float` | `0.05` | Drift percentage threshold for alerts (5% default) |
| `include_real_time` | `bool` | `True` | Enable real-time configuration monitoring |

**Returns**:
- `Dict[str, Any]`: Drift detection results including:
  - `environments_analyzed`: List of analyzed environments
  - `drift_summary`: Summary of drift across all environments
  - `environment_results`: Per-environment drift analysis
  - `critical_drift_items`: High-priority drift items requiring attention
  - `recommendations`: Automated recommendations for drift resolution
  - `real_time_monitoring_status`: Status of real-time monitoring

**Example Usage**:

```python
import asyncio
from scripts.config_drift_detector import detect_configuration_drift

async def monitor_configuration_drift():
    # Monitor drift across environments
    drift_results = await detect_configuration_drift(
        baseline_directory="./baselines",
        target_environments=["production", "staging"],
        drift_threshold=0.03,  # 3% threshold for alerts
        include_real_time=True
    )

    drift_summary = drift_results.get("drift_summary", {})
    total_drift_percentage = drift_summary.get("overall_drift_percentage", 0)

    if total_drift_percentage > 3.0:
        print(f"ALERT: Significant configuration drift detected ({total_drift_percentage:.2f}%)")

        critical_items = drift_results.get("critical_drift_items", [])
        for item in critical_items:
            print(f"Critical drift: {item['key']} in {item['environment']}")
    else:
        print(f"Configuration drift within acceptable range ({total_drift_percentage:.2f}%)")

    return drift_results

asyncio.run(monitor_configuration_drift())
```

##### generate_drift_report()

Generates comprehensive configuration drift reports.

```python
async def generate_drift_report(
    drift_results: Dict[str, Any],
    report_format: str = "html",
    output_directory: str = "./drift-reports",
    include_recommendations: bool = True
) -> str:
    """
    Generate comprehensive configuration drift report.

    Args:
        drift_results: Results from drift detection analysis
        report_format: Report format ("html", "pdf", "json", "csv")
        output_directory: Directory to save report files
        include_recommendations: Include automated recommendations

    Returns:
        Path to generated report file
    """
```

**Example Usage**:

```python
# Generate HTML report for stakeholders
report_path = await generate_drift_report(
    drift_results=drift_analysis,
    report_format="html",
    include_recommendations=True
)
print(f"Drift report generated: {report_path}")
```

##### setup_continuous_monitoring()

Sets up continuous configuration monitoring with alerting.

```python
def setup_continuous_monitoring(
    monitoring_config: Dict[str, Any],
    alert_webhook_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Set up continuous configuration drift monitoring.

    Args:
        monitoring_config: Configuration for continuous monitoring
        alert_webhook_url: Webhook URL for drift alerts

    Returns:
        Dict containing monitoring setup results
    """
```

**Example Usage**:

```python
# Set up continuous monitoring with Slack alerts
monitoring_config = {
    "check_interval_minutes": 60,
    "baseline_directory": "./baselines",
    "environments": ["production", "staging"],
    "drift_threshold": 0.02,
    "alert_on_critical": True,
    "auto_generate_reports": True
}

monitoring_setup = setup_continuous_monitoring(
    monitoring_config=monitoring_config,
    alert_webhook_url="https://hooks.slack.com/services/..."
)

if monitoring_setup.get("success"):
    print("Continuous monitoring enabled")
```

## Advanced Configuration Management

### Multi-Environment Configuration Sync

```python
async def synchronize_configurations():
    """Synchronize configurations across multiple environments."""

    environments = ["development", "staging", "production"]
    sync_results = {}

    # Establish baselines for each environment
    for env in environments:
        print(f"Establishing baseline for {env}...")

        baseline_result = await establish_configuration_baseline(
            config_sources=["database", "environment", "files"],
            baseline_name=f"{env}_baseline_{datetime.now().strftime('%Y%m%d')}",
            output_directory=f"./baselines/{env}"
        )
        sync_results[env] = baseline_result

    # Detect differences between environments
    print("Analyzing configuration differences...")

    production_baseline = f"./baselines/production/production_baseline_{datetime.now().strftime('%Y%m%d')}.json"

    for env in ["development", "staging"]:
        env_baseline = f"./baselines/{env}/{env}_baseline_{datetime.now().strftime('%Y%m%d')}.json"

        comparison = await compare_with_baseline(
            baseline_file_path=production_baseline,
            comparison_sources=["environment", "files"]
        )

        drift_detected = comparison.get("drift_detected", False)
        if drift_detected:
            print(f"Configuration differences detected between production and {env}")

            # Generate sync recommendations
            changes = comparison.get("configuration_changes", [])
            critical_changes = [c for c in changes if c.get("criticality") == "high"]

            if critical_changes:
                print(f"Critical configuration differences in {env}: {len(critical_changes)}")

    return sync_results
```

### Configuration Compliance Validation

```python
async def validate_configuration_compliance():
    """Validate configuration compliance against security and operational standards."""

    compliance_rules = {
        "security": [
            {
                "rule": "database_ssl_required",
                "pattern": "database.*ssl.*",
                "expected_value": True,
                "severity": "high"
            },
            {
                "rule": "debug_mode_disabled_production",
                "pattern": "debug.*",
                "expected_value": False,
                "environments": ["production"],
                "severity": "critical"
            }
        ],
        "operational": [
            {
                "rule": "backup_enabled",
                "pattern": "backup.*enabled.*",
                "expected_value": True,
                "severity": "high"
            },
            {
                "rule": "log_level_appropriate",
                "pattern": "log.*level.*",
                "expected_values": ["INFO", "WARN", "ERROR"],
                "severity": "medium"
            }
        ]
    }

    compliance_results = {
        "total_rules": 0,
        "passed_rules": 0,
        "failed_rules": 0,
        "violations": [],
        "compliance_score": 0
    }

    # Get current configuration
    current_config = await get_current_configuration()

    # Validate against each rule
    for category, rules in compliance_rules.items():
        for rule in rules:
            compliance_results["total_rules"] += 1

            # Check rule compliance
            violation = validate_compliance_rule(current_config, rule)

            if violation:
                compliance_results["failed_rules"] += 1
                compliance_results["violations"].append({
                    "category": category,
                    "rule": rule["rule"],
                    "severity": rule["severity"],
                    "violation_details": violation
                })
            else:
                compliance_results["passed_rules"] += 1

    # Calculate compliance score
    total_rules = compliance_results["total_rules"]
    passed_rules = compliance_results["passed_rules"]
    compliance_results["compliance_score"] = (passed_rules / total_rules * 100) if total_rules > 0 else 0

    # Generate compliance report
    critical_violations = [v for v in compliance_results["violations"] if v["severity"] == "critical"]

    print(f"Configuration compliance check complete:")
    print(f"- Compliance score: {compliance_results['compliance_score']:.1f}%")
    print(f"- Rules passed: {passed_rules}/{total_rules}")
    print(f"- Critical violations: {len(critical_violations)}")

    return compliance_results

def validate_compliance_rule(config: Dict[str, Any], rule: Dict[str, Any]) -> Optional[str]:
    """Validate a single compliance rule against configuration."""
    # Implementation would check specific rule against configuration
    pass

async def get_current_configuration() -> Dict[str, Any]:
    """Get current system configuration."""
    # Implementation would collect current configuration
    pass
```

## Configuration Automation and Orchestration

### Automated Configuration Deployment

```python
async def deploy_configuration_changes():
    """Deploy approved configuration changes across environments."""

    deployment_pipeline = {
        "development": {
            "auto_deploy": True,
            "approval_required": False,
            "rollback_on_failure": True
        },
        "staging": {
            "auto_deploy": True,
            "approval_required": True,
            "rollback_on_failure": True,
            "validation_tests": ["config_validation", "integration_tests"]
        },
        "production": {
            "auto_deploy": False,
            "approval_required": True,
            "rollback_on_failure": True,
            "validation_tests": ["config_validation", "smoke_tests", "security_scan"],
            "deployment_window": "02:00-04:00"  # Maintenance window
        }
    }

    pending_changes = await get_pending_configuration_changes()

    deployment_results = {}

    for env, config in deployment_pipeline.items():
        env_changes = [c for c in pending_changes if c["target_environment"] == env]

        if not env_changes:
            continue

        print(f"Processing {len(env_changes)} configuration changes for {env}")

        # Check if deployment is within allowed window
        if "deployment_window" in config:
            if not is_within_deployment_window(config["deployment_window"]):
                print(f"Skipping {env} - outside deployment window")
                continue

        # Check if approval is required and obtained
        if config.get("approval_required"):
            approved_changes = [c for c in env_changes if c.get("approved", False)]
            if len(approved_changes) != len(env_changes):
                print(f"Skipping {env} - not all changes approved")
                continue

        # Deploy changes
        deployment_result = await deploy_to_environment(env, env_changes, config)
        deployment_results[env] = deployment_result

        # Run validation tests
        if config.get("validation_tests") and deployment_result.get("success"):
            validation_result = await run_validation_tests(env, config["validation_tests"])

            if not validation_result.get("success") and config.get("rollback_on_failure"):
                print(f"Validation failed for {env} - initiating rollback")
                rollback_result = await rollback_configuration_changes(env, env_changes)
                deployment_results[env]["rollback_result"] = rollback_result

    return deployment_results

async def get_pending_configuration_changes() -> List[Dict[str, Any]]:
    """Get list of pending configuration changes."""
    # Implementation would retrieve pending changes from change management system
    pass

def is_within_deployment_window(window: str) -> bool:
    """Check if current time is within deployment window."""
    # Implementation would check if current time is within allowed window
    pass

async def deploy_to_environment(env: str, changes: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Deploy configuration changes to specific environment."""
    # Implementation would deploy changes to environment
    pass

async def run_validation_tests(env: str, tests: List[str]) -> Dict[str, Any]:
    """Run validation tests after configuration deployment."""
    # Implementation would run specified validation tests
    pass

async def rollback_configuration_changes(env: str, changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Rollback configuration changes in case of failure."""
    # Implementation would rollback changes
    pass
```

## Integration with External Systems

### Git-based Configuration Management

```python
async def integrate_with_git_config():
    """Integrate configuration management with Git version control."""

    git_integration = {
        "repository_url": "https://github.com/company/config-repo.git",
        "branch_strategy": {
            "main": "production",
            "staging": "staging",
            "develop": "development"
        },
        "commit_on_changes": True,
        "create_pull_requests": True
    }

    # Detect configuration changes
    drift_results = await detect_configuration_drift(
        baseline_directory="./baselines",
        target_environments=["production", "staging", "development"]
    )

    # For each environment with significant drift
    for env, results in drift_results.get("environment_results", {}).items():
        if results.get("drift_detected") and results.get("drift_severity") in ["medium", "high"]:

            # Create Git branch for configuration updates
            branch_name = f"config-update-{env}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

            # Update configuration files
            config_changes = results.get("configuration_changes", [])
            updated_files = await update_configuration_files(env, config_changes)

            # Commit changes to Git
            commit_result = await commit_configuration_changes(
                branch_name=branch_name,
                files=updated_files,
                commit_message=f"Configuration drift remediation for {env}\\n\\nUpdated {len(config_changes)} configuration items"
            )

            # Create pull request
            if commit_result.get("success") and git_integration.get("create_pull_requests"):
                pr_result = await create_configuration_pull_request(
                    branch_name=branch_name,
                    target_branch=git_integration["branch_strategy"][env],
                    title=f"Configuration Update - {env}",
                    description=generate_pr_description(config_changes)
                )

                print(f"Pull request created for {env} configuration updates: {pr_result.get('pr_url')}")

async def update_configuration_files(env: str, changes: List[Dict[str, Any]]) -> List[str]:
    """Update configuration files based on detected changes."""
    # Implementation would update actual configuration files
    pass

async def commit_configuration_changes(branch_name: str, files: List[str], commit_message: str) -> Dict[str, Any]:
    """Commit configuration changes to Git repository."""
    # Implementation would commit changes to Git
    pass

async def create_configuration_pull_request(branch_name: str, target_branch: str, title: str, description: str) -> Dict[str, Any]:
    """Create pull request for configuration changes."""
    # Implementation would create PR using Git API
    pass

def generate_pr_description(changes: List[Dict[str, Any]]) -> str:
    """Generate pull request description from configuration changes."""
    # Implementation would generate detailed PR description
    pass
```

## Error Handling and Recovery

### Common Exceptions

| Exception | Description | Resolution |
|-----------|-------------|------------|
| `BaselineCreationError` | Failed to create configuration baseline | Check permissions and storage availability |
| `ConfigurationDriftError` | Critical configuration drift detected | Review and approve changes or restore baseline |
| `ComplianceViolationError` | Configuration violates compliance rules | Update configuration to meet compliance requirements |
| `DeploymentFailureError` | Configuration deployment failed | Review deployment logs and rollback if necessary |
| `ValidationError` | Configuration validation failed | Check configuration syntax and required values |

### Robust Error Handling

```python
async def robust_configuration_management():
    """Robust configuration management with comprehensive error handling."""

    try:
        # Establish baseline
        baseline_result = await establish_configuration_baseline(
            config_sources=["database", "environment", "files"],
            baseline_name="robust_baseline"
        )

        if not baseline_result.get("success"):
            raise BaselineCreationError("Failed to create configuration baseline")

        # Check for drift
        drift_results = await detect_configuration_drift(
            baseline_directory="./baselines",
            target_environments=["production"]
        )

        # Handle critical drift
        critical_drift = drift_results.get("critical_drift_items", [])
        if critical_drift:
            print(f"Critical configuration drift detected: {len(critical_drift)} items")

            # Attempt automatic remediation for approved patterns
            remediation_result = await auto_remediate_drift(critical_drift)

            if not remediation_result.get("success"):
                raise ConfigurationDriftError("Critical drift could not be automatically remediated")

        return {"success": True, "baseline": baseline_result, "drift_check": drift_results}

    except BaselineCreationError as e:
        print(f"Baseline creation failed: {e}")
        # Fallback to partial baseline
        try:
            partial_baseline = await establish_configuration_baseline(
                config_sources=["environment"],  # Reduced scope
                baseline_name="fallback_baseline"
            )
            return {"success": False, "fallback_baseline": partial_baseline}
        except Exception as fallback_error:
            print(f"Fallback baseline creation also failed: {fallback_error}")

    except ConfigurationDriftError as e:
        print(f"Configuration drift error: {e}")
        # Send alert to administrators
        await send_configuration_alert(
            severity="critical",
            message=f"Critical configuration drift requires immediate attention: {e}"
        )

    except Exception as e:
        print(f"Unexpected configuration management error: {e}")

    return {"success": False, "error": "Configuration management failed"}

async def auto_remediate_drift(critical_drift: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Attempt automatic remediation of configuration drift."""
    # Implementation would attempt to automatically fix known drift patterns
    pass

async def send_configuration_alert(severity: str, message: str):
    """Send configuration alert to administrators."""
    # Implementation would send alert via configured channels (email, Slack, etc.)
    pass
```

## Configuration Options

### Configuration Management Settings

```yaml
# config-management.yaml
configuration_management:
  baselines:
    storage_directory: "./baselines"
    retention_days: 90
    compression: true
    encryption: true

  drift_detection:
    check_interval_minutes: 30
    threshold_percentage: 5.0
    ignore_patterns:
      - "timestamp_.*"
      - "temp_.*"
      - "cache_.*"
    critical_patterns:
      - "security.*"
      - "database.*password.*"
      - "api.*key.*"

  compliance:
    rules_file: "./compliance-rules.yaml"
    auto_check: true
    fail_on_violation: false

  deployment:
    auto_deploy_environments:
      - "development"
    approval_required_environments:
      - "staging"
      - "production"
    deployment_windows:
      production: "02:00-04:00"
      staging: "20:00-22:00"
    rollback_on_failure: true

  integration:
    git_repository: "https://github.com/company/config-repo.git"
    create_pull_requests: true
    notification_webhook: "${SLACK_WEBHOOK_URL}"

  monitoring:
    enable_real_time: true
    alert_on_drift: true
    generate_reports: true
    report_formats:
      - "html"
      - "json"
```

## See Also

- [Backup Tools API](backup-tools.md) - Backup configuration management
- [Integration Guides](../integration-guides/configuration-guide.md) - Configuration setup
- [Troubleshooting](../troubleshooting/common-issues.md) - Configuration troubleshooting
- [Examples](../examples/automated-monitoring.md) - Automated configuration monitoring
