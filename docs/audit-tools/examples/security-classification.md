# Security Classification Example

This example demonstrates how to use the security classification tools to identify and classify sensitive data assets.

## Usage

### Basic Security Classification

```python
from tools.inventory.security_classification import classify_data_assets

# Apply security classification to inventory data
classified_inventory = classify_data_assets(master_inventory)
```

### Advanced Classification

```bash
# Run security classification from command line
python3 tools/inventory/security_classification.py --input inventory.json
```

## Examples

**PII Data Classification**:
```python
# Classify PII data
sensitive_tables = identify_pii_tables(inventory_data)
print(f"Found {len(sensitive_tables)} tables with PII data")
```

## Parameters

- `inventory`: Master inventory data structure
- `classification_rules`: Custom classification rules

## Returns

Enhanced inventory with security classifications and risk assessments.
