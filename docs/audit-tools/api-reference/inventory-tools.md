# Inventory Tools API Reference

This document provides comprehensive API documentation for all inventory-related audit automation tools in the ViolentUTF API system.

## Overview

The inventory tools provide comprehensive data asset discovery and inventory capabilities across database schemas, repositories, and security assets. These tools form the foundation of the database audit system by cataloging all data assets and their relationships.

## Classes and Methods

### DataAssetInventoryTool

**Location**: `tools/inventory/data_asset_inventory.py`

The `DataAssetInventoryTool` is the main unified tool for comprehensive data asset discovery and inventory across multiple phases.

#### Class Definition

```python
class DataAssetInventoryTool(AuditDatabaseMixin):
    """Unified tool for comprehensive data asset discovery and inventory."""

    def __init__(self, project_root: Optional[str] = None)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `project_root` | `Optional[str]` | `None` | Root directory of the project. If `None`, uses current working directory. |

#### Key Methods

##### perform_full_inventory()

Performs comprehensive data asset inventory across all phases.

```python
async def perform_full_inventory(self) -> AuditResult:
    """
    Perform comprehensive data asset inventory.

    Returns:
        AuditResult containing complete asset inventory with standardized format
    """
```

**Returns**:
- `AuditResult`: Standardized audit result containing:
  - `metadata`: Discovery metadata and configuration
  - `physical_stores`: Database and file system assets
  - `logical_assets`: Models and data structures
  - `access_patterns`: Usage and permission patterns
  - `security_assets`: Security classifications and policies
  - `configuration_assets`: Configuration-related assets
  - `repository_analysis`: Repository pattern analysis
  - `gap_analysis`: Identified gaps in documentation and security
  - `risk_assessment`: Risk analysis of identified assets
  - `usage_statistics`: Comprehensive usage and discovery statistics

**Raises**:
- `DatabaseConnectionError`: If database is unreachable
- `PermissionError`: If insufficient access rights
- `ValidationError`: If configuration is invalid

**Example Usage**:

```python
import asyncio
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def main():
    # Initialize the tool
    tool = DataAssetInventoryTool(project_root="/path/to/project")

    # Perform comprehensive inventory
    audit_result = await tool.perform_full_inventory()

    # Access the inventory data
    inventory = audit_result.findings[0] if audit_result.findings else {}

    # Print summary statistics
    stats = inventory.get("usage_statistics", {})
    asset_counts = stats.get("asset_counts", {})
    print(f"Physical Stores: {asset_counts.get('total_physical_stores', 0)}")
    print(f"Logical Assets: {asset_counts.get('total_logical_assets', 0)}")
    print(f"Security Assets: {asset_counts.get('total_security_assets', 0)}")

if __name__ == "__main__":
    asyncio.run(main())
```

**Command Line Usage**:

```bash
# Run data asset inventory from command line
python3 tools/inventory/data_asset_inventory.py

# Run with specific configuration
python3 tools/inventory/data_asset_inventory.py --config audit-config.yaml

# Run with output directory
python3 tools/inventory/data_asset_inventory.py --output ./audit-results
```

##### perform_full_inventory_parallel()

Optimized version with parallel execution for 60-70% performance improvement.

```python
async def perform_full_inventory_parallel(self) -> Dict[str, Any]:
    """
    Perform comprehensive data asset inventory with parallel execution optimization.

    Returns:
        Dict containing complete asset inventory
    """
```

**Returns**:
- `Dict[str, Any]`: Complete asset inventory data structure

**Example Usage**:

```python
# For performance-critical scenarios
inventory = await tool.perform_full_inventory_parallel()
```

##### save_inventory()

Saves comprehensive inventory to file in YAML or JSON format.

```python
async def save_inventory(self, inventory: Dict[str, Any], output_format: str = "yaml") -> str:
    """Save comprehensive inventory to file."""
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `inventory` | `Dict[str, Any]` | - | Inventory data to save |
| `output_format` | `str` | `"yaml"` | Output format: "yaml" or "json" |

**Returns**:
- `str`: Path to the saved file

**Example Usage**:

```python
# Save inventory in YAML format
yaml_path = await tool.save_inventory(inventory, "yaml")
print(f"Inventory saved to: {yaml_path}")

# Save inventory in JSON format
json_path = await tool.save_inventory(inventory, "json")
```

### RepositoryAnalyzer

**Location**: `tools/inventory/repository_analyzer.py`

Analyzes repository patterns, CRUD operations, and API endpoint mappings.

#### Class Definition

```python
class RepositoryAnalyzer:
    """Repository pattern analysis tool for database audit."""

    def __init__(self, project_root: str)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `project_root` | `str` | - | Root directory of the project to analyze |

#### Key Methods

##### analyze_repositories()

Performs comprehensive repository analysis.

```python
async def analyze_repositories(self) -> Dict[str, Any]:
    """
    Analyze repository patterns and data access patterns.

    Returns:
        Dict containing repository analysis results
    """
```

**Returns**:
- `Dict[str, Any]`: Repository analysis including:
  - `repositories`: List of discovered repositories with metadata
  - `crud_patterns`: CRUD operation statistics
  - `api_endpoint_mappings`: API to repository mappings
  - `dependency_graph`: Repository dependency relationships

**Example Usage**:

```python
from tools.inventory.repository_analyzer import RepositoryAnalyzer

analyzer = RepositoryAnalyzer("/path/to/project")
repository_data = await analyzer.analyze_repositories()

# Access repository information
repositories = repository_data.get("repositories", [])
for repo in repositories:
    print(f"Repository: {repo.get('repository_name')}")
    print(f"Methods: {len(repo.get('methods', []))}")
```

### SchemaDiscoveryTool

**Location**: `tools/inventory/schema_discovery.py`

Discovers and catalogs database schema information.

#### Class Definition

```python
class SchemaDiscoveryTool:
    """Database schema discovery and analysis tool."""

    def __init__(self)
```

#### Key Methods

##### discover_schema()

Discovers database schema structure and metadata.

```python
async def discover_schema(self) -> Dict[str, Any]:
    """
    Discover and catalog database schema information.

    Returns:
        Dict containing schema discovery results
    """
```

**Returns**:
- `Dict[str, Any]`: Schema information including:
  - `tables`: List of database tables with metadata
  - `columns`: Column information and data types
  - `relationships`: Foreign key relationships
  - `indexes`: Index information
  - `constraints`: Database constraints

**Example Usage**:

```python
from tools.inventory.schema_discovery import SchemaDiscoveryTool

tool = SchemaDiscoveryTool()
schema_data = await tool.discover_schema()

# Access table information
tables = schema_data.get("tables", [])
print(f"Discovered {len(tables)} tables")

for table in tables:
    print(f"Table: {table.get('name')}")
    print(f"Columns: {len(table.get('columns', []))}")
```

### Security Classification Functions

**Location**: `tools/inventory/security_classification.py`

Provides data asset security classification capabilities.

#### Key Functions

##### classify_data_assets()

Applies security classification framework to discovered data assets.

```python
def classify_data_assets(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply security classification framework to data assets.

    Args:
        inventory: Master inventory data structure

    Returns:
        Enhanced inventory with security classifications
    """
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `inventory` | `Dict[str, Any]` | Master inventory data to classify |

**Returns**:
- `Dict[str, Any]`: Enhanced inventory with security classification data including:
  - `security_classification_summary`: Classification statistics
  - Enhanced asset entries with security levels
  - Risk assessments for classified assets

**Example Usage**:

```python
from tools.inventory.security_classification import classify_data_assets

# Apply security classification to inventory
classified_inventory = classify_data_assets(master_inventory)

# Access classification summary
classification_summary = classified_inventory.get("security_classification_summary", {})
critical_assets = classification_summary.get("classifications", {}).get("critical", 0)
print(f"Critical assets identified: {critical_assets}")
```

## Integration Patterns

### Basic Workflow

```python
import asyncio
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def complete_audit_workflow():
    """Complete audit workflow using inventory tools."""

    # Initialize tool
    tool = DataAssetInventoryTool()

    # Perform comprehensive inventory
    audit_result = await tool.perform_full_inventory()
    inventory = audit_result.findings[0] if audit_result.findings else {}

    # Save results
    yaml_path = await tool.save_inventory(inventory, "yaml")
    json_path = await tool.save_inventory(inventory, "json")

    # Generate summary report
    stats = inventory.get("usage_statistics", {})
    print("=== Audit Summary ===")
    print(f"Discovery completed at: {inventory.get('metadata', {}).get('discovery_time')}")
    print(f"Assets discovered: {stats.get('asset_counts', {})}")
    print(f"Reports saved: {yaml_path}, {json_path}")

    return audit_result

# Run the workflow
asyncio.run(complete_audit_workflow())
```

### Advanced Usage with Parallel Execution

```python
async def optimized_audit_workflow():
    """Optimized audit workflow with parallel execution."""

    tool = DataAssetInventoryTool()

    # Use parallel execution for better performance
    inventory = await tool.perform_full_inventory_parallel()

    # Process results
    gap_analysis = inventory.get("gap_analysis", {})
    risk_assessment = inventory.get("risk_assessment", {})

    print(f"Gaps identified: {sum(len(gaps) for gaps in gap_analysis.values() if isinstance(gaps, list))}")
    print(f"High-risk assets: {len(risk_assessment.get('high_risk_assets', []))}")

    return inventory
```

## Error Handling

### Common Exceptions

| Exception | Description | Resolution |
|-----------|-------------|------------|
| `DatabaseConnectionError` | Database is unreachable | Check connection string, network, and database status |
| `PermissionError` | Insufficient access rights | Verify user permissions and database access |
| `ValidationError` | Invalid configuration | Check configuration file format and required fields |
| `FileNotFoundError` | Required files not found | Ensure project structure is complete |

### Error Handling Example

```python
import asyncio
from tools.inventory.data_asset_inventory import DataAssetInventoryTool
from audit_utils.exceptions import audit_error_handler

async def robust_inventory_execution():
    """Example of robust error handling in inventory execution."""

    try:
        tool = DataAssetInventoryTool()
        audit_result = await tool.perform_full_inventory()

        if audit_result.status == AuditStatus.FAILED:
            print("Inventory execution failed:")
            print(f"Error: {audit_result.summary.get('error', 'Unknown error')}")
            return None

        return audit_result

    except DatabaseConnectionError as e:
        print(f"Database connection failed: {e}")
        print("Solution: Check DATABASE_URL and database availability")

    except PermissionError as e:
        print(f"Permission denied: {e}")
        print("Solution: Verify user has required database permissions")

    except Exception as e:
        print(f"Unexpected error: {e}")
        print("Solution: Check logs for detailed error information")

    return None
```

## Performance Considerations

### Optimization Strategies

1. **Parallel Execution**: Use `perform_full_inventory_parallel()` for 60-70% performance improvement
2. **Database Connection Pooling**: Configure appropriate pool sizes in settings
3. **Selective Discovery**: Use configuration filters to limit scope when appropriate
4. **Caching**: Results are cached during execution to avoid redundant operations

### Performance Monitoring

```python
import time
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def performance_comparison():
    """Compare sequential vs parallel execution performance."""

    tool = DataAssetInventoryTool()

    # Sequential execution
    start_time = time.time()
    sequential_result = await tool.perform_full_inventory()
    sequential_time = time.time() - start_time

    # Parallel execution
    start_time = time.time()
    parallel_result = await tool.perform_full_inventory_parallel()
    parallel_time = time.time() - start_time

    print(f"Sequential execution: {sequential_time:.2f}s")
    print(f"Parallel execution: {parallel_time:.2f}s")
    print(f"Performance improvement: {((sequential_time - parallel_time) / sequential_time * 100):.1f}%")
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Primary database connection string | Required |
| `REDIS_URL` | Redis connection for caching | Optional |
| `AUDIT_LOG_LEVEL` | Logging verbosity | `INFO` |
| `AUDIT_OUTPUT_DIR` | Directory for output files | `./docs/inventory/` |

### Configuration File Example

```yaml
# audit-config.yaml
database:
  primary:
    url: "${DATABASE_URL}"
    pool_size: 10
    timeout: 30

inventory:
  include_schemas: ["public", "audit"]
  exclude_tables: ["temp_*", "cache_*"]
  classify_sensitive_data: true

output:
  format: ["json", "html"]
  destination: "./audit-reports"
  retention_days: 90
```

## See Also

- [Integration Guides](../integration-guides/setup-and-installation.md) - Setup and configuration
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions
- [Examples](../examples/complete-audit-scenario.md) - Practical usage examples
