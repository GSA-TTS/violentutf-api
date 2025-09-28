# Execution Workflows

This guide covers execution workflows and automation for the database audit tools.

## Prerequisites

Ensure you have completed the [Setup and Installation](setup-and-installation.md) and [Configuration](configuration-guide.md) guides.

## Usage

### Basic Workflow Execution

**Command Line Execution**:

```bash
# Execute full audit workflow
python3 tools/inventory/data_asset_inventory.py --full-audit

# Execute specific components
python3 tools/inventory/schema_discovery.py
python3 scripts/backup_coverage_audit.py
```

**Programmatic Execution**:

```python
import asyncio
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def execute_audit_workflow():
    tool = DataAssetInventoryTool()
    result = await tool.perform_full_inventory()
    return result

# Execute workflow
result = asyncio.run(execute_audit_workflow())
```

## Configuration

Configure workflow execution parameters:

```yaml
workflows:
  full_audit:
    enabled: true
    schedule: "0 2 * * *"
    timeout: 3600

  incremental:
    enabled: true
    schedule: "0 */6 * * *"
    timeout: 900
```

## Installation

Install workflow dependencies:

```bash
pip install schedule celery
```

## Examples

See [Automated Monitoring](../examples/automated-monitoring.md) for advanced workflow examples.

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `schedule` | `str` | Cron expression for workflow scheduling |
| `timeout` | `int` | Workflow timeout in seconds |

## Returns

Workflow execution returns:
- `status`: Execution status ("success", "failed", "timeout")
- `results`: Audit results data
- `duration`: Execution time in seconds
