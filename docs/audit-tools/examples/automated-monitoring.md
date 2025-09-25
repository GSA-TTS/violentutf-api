# Automated Monitoring Example

This example shows how to set up automated monitoring and alerting for the audit tools.

## Usage

### Basic Monitoring Setup

```python
from scripts.config_drift_detector import setup_continuous_monitoring

# Set up continuous monitoring
monitoring_config = {
    "check_interval_minutes": 60,
    "baseline_directory": "./baselines",
    "environments": ["production", "staging"],
    "drift_threshold": 0.02
}

result = setup_continuous_monitoring(monitoring_config)
```

### Advanced Monitoring

```bash
# Set up automated monitoring with alerts
python3 scripts/setup_monitoring.py --config monitoring.yaml
```

## Configuration

Configure monitoring intervals, thresholds, and alert channels:

```yaml
monitoring:
  interval: 3600  # 1 hour
  alerts:
    slack_webhook: "${SLACK_WEBHOOK_URL}"
    email: "admin@example.com"
```

## Installation

Install monitoring dependencies:

```bash
pip install schedule prometheus-client
```

## Examples

See [Complete Audit Scenario](complete-audit-scenario.md) for monitoring integration examples.
