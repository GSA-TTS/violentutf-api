# Configuration Guide

This guide covers comprehensive configuration options for the database audit tools.

## Prerequisites

Before configuring the audit tools, ensure you have completed the [Setup and Installation](setup-and-installation.md) process.

## Configuration

### Database Configuration

Configure your primary database connection:

```yaml
database:
  primary:
    url: "${DATABASE_URL}"
    pool_size: 10
    timeout: 30
```

### Usage Examples

**Basic Configuration Example**:

```bash
# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost:5432/db"
export REDIS_URL="redis://localhost:6379"

# Run configuration validation
python3 scripts/validate_config.py
```

**Advanced Configuration**:

```python
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

# Configure with custom settings
config = {
    "database": {"pool_size": 20},
    "audit": {"include_schemas": ["public", "audit"]}
}

tool = DataAssetInventoryTool(config=config)
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `database_url` | `str` | - | Primary database connection string |
| `pool_size` | `int` | `10` | Database connection pool size |

## Returns

Configuration validation returns:
- `success`: Boolean indicating configuration validity
- `errors`: List of configuration errors if any
- `warnings`: List of configuration warnings

## Installation

To install configuration dependencies:

```bash
pip install pyyaml python-dotenv
```

## Examples

See [Complete Audit Scenario](../examples/complete-audit-scenario.md) for practical usage examples.
