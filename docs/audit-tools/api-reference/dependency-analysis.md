# Dependency Analysis Tools API Reference

This document provides comprehensive API documentation for dependency analysis audit automation tools in the ViolentUTF API system.

## Overview

The dependency analysis tools provide comprehensive analysis of code dependencies, repository relationships, and dependency mappings across the entire project. These tools help identify potential risks, circular dependencies, and optimization opportunities.

## Classes and Methods

### ComprehensiveAnalyzer

**Location**: `tools/dependency/comprehensive_analyzer.py`

The `ComprehensiveAnalyzer` provides comprehensive project-wide dependency analysis including code analysis, repository dependencies, and runtime analysis.

#### Class Definition

```python
class ComprehensiveAnalyzer:
    """Comprehensive dependency analysis tool for project-wide audit."""

    def __init__(self, project_root: str, config: Optional[Dict[str, Any]] = None)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `project_root` | `str` | - | Root directory of the project to analyze |
| `config` | `Optional[Dict[str, Any]]` | `None` | Configuration options for analysis scope and behavior |

#### Key Methods

##### analyze_project_dependencies()

Performs comprehensive project dependency analysis.

```python
async def analyze_project_dependencies(self, include_runtime: bool = False) -> Dict[str, Any]:
    """
    Analyze project dependencies comprehensively.

    Args:
        include_runtime: Whether to include runtime dependency analysis

    Returns:
        Dict containing comprehensive dependency analysis results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_runtime` | `bool` | `False` | Include runtime dependency analysis (slower but more thorough) |

**Returns**:
- `Dict[str, Any]`: Comprehensive dependency analysis including:
  - `static_dependencies`: Static code dependencies from imports
  - `runtime_dependencies`: Runtime dependencies (if enabled)
  - `circular_dependencies`: Detected circular dependency chains
  - `dependency_graph`: Visual dependency graph data
  - `risk_analysis`: Dependency risk assessment
  - `recommendations`: Optimization recommendations

**Example Usage**:

```python
import asyncio
from tools.dependency.comprehensive_analyzer import ComprehensiveAnalyzer

async def analyze_dependencies():
    # Initialize analyzer
    analyzer = ComprehensiveAnalyzer("/path/to/project")

    # Perform comprehensive analysis
    analysis_results = await analyzer.analyze_project_dependencies(include_runtime=True)

    # Access results
    static_deps = analysis_results.get("static_dependencies", {})
    circular_deps = analysis_results.get("circular_dependencies", [])

    print(f"Static dependencies found: {len(static_deps)}")
    print(f"Circular dependencies detected: {len(circular_deps)}")

    return analysis_results

asyncio.run(analyze_dependencies())
```

**Command Line Usage**:

```bash
# Run comprehensive dependency analysis
python3 tools/dependency/comprehensive_analyzer.py

# Run with runtime analysis enabled
python3 tools/dependency/comprehensive_analyzer.py --include-runtime

# Run with specific project root
python3 tools/dependency/comprehensive_analyzer.py --project-root /path/to/project

# Generate specific output format
python3 tools/dependency/comprehensive_analyzer.py --output-format html
```

##### detect_circular_dependencies()

Detects circular dependency chains in the project.

```python
def detect_circular_dependencies(self, dependency_graph: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Detect circular dependencies in the dependency graph.

    Args:
        dependency_graph: Graph of module dependencies

    Returns:
        List of circular dependency chains with metadata
    """
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `dependency_graph` | `Dict[str, List[str]]` | Graph representation of module dependencies |

**Returns**:
- `List[Dict[str, Any]]`: List of circular dependencies including:
  - `chain`: The circular dependency chain
  - `severity`: Risk level (low, medium, high)
  - `impact`: Potential impact description
  - `recommendations`: Suggested fixes

**Example Usage**:

```python
# Build dependency graph
dependency_graph = analyzer.build_dependency_graph()

# Detect circular dependencies
circular_deps = analyzer.detect_circular_dependencies(dependency_graph)

for circular_dep in circular_deps:
    print(f"Circular dependency: {' -> '.join(circular_dep['chain'])}")
    print(f"Severity: {circular_dep['severity']}")
    print(f"Recommendation: {circular_dep['recommendations'][0]}")
```

##### generate_dependency_report()

Generates comprehensive dependency analysis report.

```python
async def generate_dependency_report(self, output_format: str = "json") -> str:
    """
    Generate comprehensive dependency analysis report.

    Args:
        output_format: Report format ("json", "html", "yaml")

    Returns:
        Path to generated report file
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_format` | `str` | `"json"` | Output format: "json", "html", or "yaml" |

**Returns**:
- `str`: Path to the generated report file

**Example Usage**:

```python
# Generate HTML report for stakeholders
html_report = await analyzer.generate_dependency_report("html")
print(f"Report generated: {html_report}")

# Generate JSON report for automated processing
json_report = await analyzer.generate_dependency_report("json")
```

### Repository Dependency Analyzer

**Location**: `tools/dependency/repository_analyzer.py`

Specialized analyzer focusing on repository-level dependency patterns.

#### Class Definition

```python
class RepositoryDependencyAnalyzer:
    """Repository-focused dependency analysis tool."""

    def __init__(self, project_root: str)
```

#### Key Methods

##### analyze_repository_dependencies()

Analyzes dependencies between repository classes and modules.

```python
async def analyze_repository_dependencies(self) -> Dict[str, Any]:
    """
    Analyze dependencies between repository classes.

    Returns:
        Dict containing repository dependency analysis
    """
```

**Returns**:
- `Dict[str, Any]`: Repository dependency analysis including:
  - `repository_imports`: Import relationships between repositories
  - `service_dependencies`: Service layer dependencies
  - `model_relationships`: Model to repository mappings
  - `coupling_metrics`: Coupling strength measurements

**Example Usage**:

```python
from tools.dependency.repository_analyzer import RepositoryDependencyAnalyzer

analyzer = RepositoryDependencyAnalyzer("/path/to/project")
repo_deps = await analyzer.analyze_repository_dependencies()

# Analyze coupling metrics
coupling = repo_deps.get("coupling_metrics", {})
print(f"High coupling detected: {coupling.get('high_coupling_pairs', [])}")
```

## Advanced Analysis Features

### Runtime Dependency Analysis

For thorough analysis including runtime dependencies:

```python
async def comprehensive_runtime_analysis():
    """Perform comprehensive analysis including runtime dependencies."""

    config = {
        "include_test_dependencies": True,
        "analyze_dynamic_imports": True,
        "profile_runtime_calls": True,
        "generate_call_graph": True
    }

    analyzer = ComprehensiveAnalyzer("/path/to/project", config)

    # Enable runtime analysis (slower but more thorough)
    results = await analyzer.analyze_project_dependencies(include_runtime=True)

    runtime_deps = results.get("runtime_dependencies", {})
    call_graph = results.get("call_graph", {})

    print(f"Runtime dependencies: {len(runtime_deps)}")
    print(f"Call graph nodes: {len(call_graph.get('nodes', []))}")

    return results
```

### Dependency Risk Assessment

```python
async def assess_dependency_risks():
    """Assess risks in project dependencies."""

    analyzer = ComprehensiveAnalyzer("/path/to/project")
    analysis = await analyzer.analyze_project_dependencies()

    risk_analysis = analysis.get("risk_analysis", {})

    # High-risk dependencies
    high_risk = risk_analysis.get("high_risk_dependencies", [])
    for dep in high_risk:
        print(f"High-risk dependency: {dep['name']}")
        print(f"Risk factors: {dep['risk_factors']}")
        print(f"Mitigation: {dep['recommended_mitigation']}")

    # Outdated dependencies
    outdated = risk_analysis.get("outdated_dependencies", [])
    print(f"Outdated dependencies requiring updates: {len(outdated)}")

    return risk_analysis
```

## Integration with Other Tools

### Combining with Inventory Analysis

```python
async def combined_inventory_and_dependency_analysis():
    """Combine inventory and dependency analysis for comprehensive audit."""

    from tools.inventory.data_asset_inventory import DataAssetInventoryTool
    from tools.dependency.comprehensive_analyzer import ComprehensiveAnalyzer

    # Initialize tools
    inventory_tool = DataAssetInventoryTool()
    dependency_analyzer = ComprehensiveAnalyzer(".")

    # Perform analyses in parallel
    inventory_result, dependency_result = await asyncio.gather(
        inventory_tool.perform_full_inventory(),
        dependency_analyzer.analyze_project_dependencies(include_runtime=True)
    )

    # Correlate results
    inventory_data = inventory_result.findings[0] if inventory_result.findings else {}
    repository_analysis = inventory_data.get("repository_analysis", {})

    # Cross-reference repository patterns with dependency analysis
    repos_with_issues = []
    circular_deps = dependency_result.get("circular_dependencies", [])

    for circular_dep in circular_deps:
        affected_repos = [r for r in repository_analysis.get("repositories", [])
                         if any(module in circular_dep["chain"] for module in r.get("modules", []))]
        if affected_repos:
            repos_with_issues.extend(affected_repos)

    print(f"Repositories affected by circular dependencies: {len(repos_with_issues)}")

    return {
        "inventory": inventory_data,
        "dependencies": dependency_result,
        "cross_analysis": {
            "affected_repositories": repos_with_issues,
            "risk_correlation": "High coupling detected in repositories with circular dependencies"
        }
    }
```

## Visualization and Reporting

### Dependency Graph Visualization

```python
async def generate_dependency_visualization():
    """Generate visual dependency graphs."""

    analyzer = ComprehensiveAnalyzer("/path/to/project")
    analysis = await analyzer.analyze_project_dependencies()

    dependency_graph = analysis.get("dependency_graph", {})

    # Generate graph visualization data
    visualization_data = {
        "nodes": [
            {"id": module, "group": "repository" if "repository" in module else "service"}
            for module in dependency_graph.get("nodes", [])
        ],
        "edges": [
            {"source": edge["from"], "target": edge["to"], "weight": edge.get("strength", 1)}
            for edge in dependency_graph.get("edges", [])
        ]
    }

    # Save visualization data for frontend rendering
    import json
    with open("dependency_visualization.json", "w") as f:
        json.dump(visualization_data, f, indent=2)

    print("Dependency visualization data saved to dependency_visualization.json")
    return visualization_data
```

### Custom Analysis Configuration

```python
# Custom configuration for specific analysis needs
analysis_config = {
    "scope": {
        "include_directories": ["app/", "tools/", "scripts/"],
        "exclude_patterns": ["**/tests/**", "**/__pycache__/**"],
        "file_extensions": [".py"]
    },
    "analysis_options": {
        "detect_circular_deps": True,
        "analyze_coupling": True,
        "profile_performance": False,
        "include_external_deps": True
    },
    "output": {
        "generate_graphs": True,
        "include_metrics": True,
        "detailed_reports": True
    }
}

analyzer = ComprehensiveAnalyzer("/path/to/project", analysis_config)
```

## Error Handling

### Common Exceptions

| Exception | Description | Resolution |
|-----------|-------------|------------|
| `ImportError` | Missing dependencies for analysis | Install required analysis packages |
| `FileNotFoundError` | Project files not accessible | Check project path and permissions |
| `MemoryError` | Large project analysis out of memory | Use incremental analysis or increase memory |
| `TimeoutError` | Analysis taking too long | Reduce scope or increase timeout |

### Robust Error Handling

```python
async def robust_dependency_analysis():
    """Robust dependency analysis with comprehensive error handling."""

    try:
        analyzer = ComprehensiveAnalyzer("/path/to/project")
        results = await analyzer.analyze_project_dependencies()

        # Validate results
        if not results.get("static_dependencies"):
            print("Warning: No static dependencies found - check project structure")

        return results

    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install required packages: pip install -r requirements.txt")

    except FileNotFoundError as e:
        print(f"File not found: {e}")
        print("Check project path and file permissions")

    except MemoryError:
        print("Out of memory - try analyzing smaller scopes")
        # Retry with reduced scope
        config = {"scope": {"include_directories": ["app/"]}}
        analyzer = ComprehensiveAnalyzer("/path/to/project", config)
        return await analyzer.analyze_project_dependencies()

    except Exception as e:
        print(f"Unexpected error: {e}")

    return {}
```

## Performance Optimization

### Incremental Analysis

```python
async def incremental_dependency_analysis():
    """Perform incremental analysis for large projects."""

    analyzer = ComprehensiveAnalyzer("/path/to/project")

    # Analyze in chunks
    directories = ["app/", "tools/", "scripts/"]
    combined_results = {
        "static_dependencies": {},
        "circular_dependencies": [],
        "recommendations": []
    }

    for directory in directories:
        print(f"Analyzing {directory}...")

        config = {"scope": {"include_directories": [directory]}}
        dir_analyzer = ComprehensiveAnalyzer("/path/to/project", config)

        dir_results = await dir_analyzer.analyze_project_dependencies()

        # Combine results
        combined_results["static_dependencies"].update(
            dir_results.get("static_dependencies", {})
        )
        combined_results["circular_dependencies"].extend(
            dir_results.get("circular_dependencies", [])
        )

    print("Incremental analysis complete")
    return combined_results
```

## Configuration Options

### Analysis Configuration

```yaml
# dependency-analysis-config.yaml
analysis:
  scope:
    include_directories:
      - "app/"
      - "tools/"
      - "scripts/"
    exclude_patterns:
      - "**/tests/**"
      - "**/__pycache__/**"
    file_extensions:
      - ".py"

  options:
    detect_circular_dependencies: true
    analyze_coupling_strength: true
    include_runtime_analysis: false
    generate_call_graph: true

  performance:
    max_analysis_time: 300  # seconds
    memory_limit: "2GB"
    parallel_workers: 4

output:
  formats:
    - "json"
    - "html"
  destination: "./dependency-reports"
  include_visualizations: true
```

## See Also

- [Inventory Tools API](inventory-tools.md) - Data asset inventory tools
- [Integration Guides](../integration-guides/execution-workflows.md) - Workflow integration
- [Examples](../examples/complete-audit-scenario.md) - Complete audit scenarios
- [Troubleshooting](../troubleshooting/performance-tuning.md) - Performance optimization
