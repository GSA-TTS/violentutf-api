# Performance Tuning Guide

This document provides comprehensive performance optimization strategies for the database audit tools.

## Overview

The audit tools are designed to handle large-scale database analysis efficiently. This guide covers optimization strategies for different performance scenarios and bottlenecks.

## Common Issues

### Slow Execution Times
- Large database schemas with many tables
- Complex repository analysis
- Network latency to database
- Insufficient system resources

### Solutions

**Use Parallel Execution**:
```python
# Use optimized parallel version for 60-70% improvement
tool = DataAssetInventoryTool()
result = await tool.perform_full_inventory_parallel()
```

**Database Connection Optimization**:
```yaml
database:
  primary:
    pool_size: 20        # Increase connection pool
    max_overflow: 30     # Allow overflow connections
    pool_timeout: 60     # Increase timeout
    pool_recycle: 3600   # Recycle connections hourly
```

## Performance Monitoring

### Execution Time Measurement

```python
import time
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

async def benchmark_audit_performance():
    tool = DataAssetInventoryTool()

    # Measure sequential execution
    start_time = time.time()
    sequential_result = await tool.perform_full_inventory()
    sequential_time = time.time() - start_time

    # Measure parallel execution
    start_time = time.time()
    parallel_result = await tool.perform_full_inventory_parallel()
    parallel_time = time.time() - start_time

    improvement = ((sequential_time - parallel_time) / sequential_time) * 100

    print(f"Sequential: {sequential_time:.2f}s")
    print(f"Parallel: {parallel_time:.2f}s")
    print(f"Improvement: {improvement:.1f}%")

    return {
        "sequential_time": sequential_time,
        "parallel_time": parallel_time,
        "improvement_percentage": improvement
    }
```

## Database Optimization

### Connection Pool Tuning

```python
# Optimal connection pool settings
DATABASE_CONFIG = {
    "pool_size": 10,           # Base connection pool size
    "max_overflow": 20,        # Additional connections when needed
    "pool_timeout": 30,        # Seconds to wait for connection
    "pool_recycle": 3600,      # Recycle connections after 1 hour
    "pool_pre_ping": True,     # Validate connections before use
    "echo": False              # Disable SQL query logging
}
```

### Query Optimization

```sql
-- Add indexes for common audit queries
CREATE INDEX CONCURRENTLY idx_audit_tables_schema
ON information_schema.tables(table_schema);

CREATE INDEX CONCURRENTLY idx_audit_columns_table
ON information_schema.columns(table_name, table_schema);

-- Analyze database statistics
ANALYZE;

-- Update table statistics
UPDATE pg_stat_user_tables SET last_analyze = now();
```

## System Resource Optimization

### Memory Management

```python
# Configure Python memory optimization
import os
import gc

# Enable garbage collection optimization
gc.set_threshold(700, 10, 10)

# Optimize Python memory usage
os.environ['PYTHONOPTIMIZE'] = '1'
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
```

### Disk I/O Optimization

```bash
# Use faster storage for temporary files
export TMPDIR="/path/to/fast/ssd"

# Configure output directory on fast storage
export AUDIT_OUTPUT_DIR="/fast/storage/audit-reports"

# Use compression for large reports
export AUDIT_COMPRESS_REPORTS=true
```

## Parallel Processing Strategies

### Task-Level Parallelism

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def optimized_parallel_audit():
    """Optimized parallel audit with task-level parallelism."""

    # Independent tasks that can run in parallel
    tasks = [
        discover_database_schema(),
        analyze_repository_patterns(),
        inventory_configuration_assets(),
        assess_backup_coverage()
    ]

    # Execute in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any exceptions
    successful_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Task {i} failed: {result}")
        else:
            successful_results.append(result)

    return successful_results
```

### Process-Level Parallelism

```python
from multiprocessing import Pool
import os

def cpu_intensive_analysis(schema_chunk):
    """CPU-intensive analysis that benefits from multiprocessing."""
    # Perform complex analysis on schema chunk
    return analyze_schema_chunk(schema_chunk)

def parallel_schema_analysis(schema_data):
    """Use multiprocessing for CPU-intensive tasks."""

    # Split schema into chunks
    chunk_size = len(schema_data) // os.cpu_count()
    chunks = [schema_data[i:i+chunk_size]
              for i in range(0, len(schema_data), chunk_size)]

    # Process chunks in parallel
    with Pool(processes=os.cpu_count()) as pool:
        results = pool.map(cpu_intensive_analysis, chunks)

    # Combine results
    return combine_analysis_results(results)
```

## Network Optimization

### Connection Pooling

```python
# Use connection pooling for distributed databases
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    pool_recycle=3600
)
```

### Batch Operations

```python
# Batch database operations for efficiency
async def batch_table_analysis(tables):
    """Analyze tables in batches for better performance."""

    batch_size = 10
    results = []

    for i in range(0, len(tables), batch_size):
        batch = tables[i:i+batch_size]

        # Process batch
        batch_results = await asyncio.gather(
            *[analyze_single_table(table) for table in batch]
        )

        results.extend(batch_results)

        # Brief pause between batches to avoid overwhelming database
        await asyncio.sleep(0.1)

    return results
```

## Diagnosis

### Performance Bottleneck Identification

```python
import cProfile
import pstats
from io import StringIO

def profile_audit_performance():
    """Profile audit execution to identify bottlenecks."""

    # Create profiler
    profiler = cProfile.Profile()

    # Profile the audit execution
    profiler.enable()

    # Run audit (use sync version for profiling)
    tool = DataAssetInventoryTool()
    # result = await tool.perform_full_inventory()  # This would be async

    profiler.disable()

    # Analyze results
    s = StringIO()
    stats = pstats.Stats(profiler, stream=s)
    stats.sort_stats('cumulative')
    stats.print_stats(20)  # Top 20 functions

    print(s.getvalue())

    return stats
```

### Resource Monitoring

```python
import psutil
import time

class PerformanceMonitor:
    """Monitor system performance during audit execution."""

    def __init__(self):
        self.metrics = []

    def start_monitoring(self):
        """Start continuous performance monitoring."""
        self.monitoring = True

        while self.monitoring:
            metric = {
                'timestamp': time.time(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io': psutil.disk_io_counters(),
                'network_io': psutil.net_io_counters()
            }

            self.metrics.append(metric)
            time.sleep(5)  # Sample every 5 seconds

    def stop_monitoring(self):
        """Stop performance monitoring."""
        self.monitoring = False

    def get_performance_report(self):
        """Generate performance report."""
        if not self.metrics:
            return "No metrics collected"

        avg_cpu = sum(m['cpu_percent'] for m in self.metrics) / len(self.metrics)
        avg_memory = sum(m['memory_percent'] for m in self.metrics) / len(self.metrics)

        return {
            'average_cpu_percent': avg_cpu,
            'average_memory_percent': avg_memory,
            'peak_cpu_percent': max(m['cpu_percent'] for m in self.metrics),
            'peak_memory_percent': max(m['memory_percent'] for m in self.metrics),
            'sample_count': len(self.metrics)
        }
```

## Configuration Optimization

### Optimal Settings for Different Scenarios

**Large Database (>1000 tables)**:
```yaml
database:
  pool_size: 25
  max_overflow: 50
  query_timeout: 120

audit:
  parallel_workers: 8
  batch_size: 20
  memory_limit: "2GB"

performance:
  enable_caching: true
  cache_ttl: 3600
  compress_output: true
```

**Network-Limited Environment**:
```yaml
database:
  pool_size: 5
  max_overflow: 10
  pool_timeout: 60
  connection_retries: 3

audit:
  parallel_workers: 2
  batch_size: 5
  network_timeout: 180
```

**Memory-Constrained Systems**:
```yaml
audit:
  parallel_workers: 2
  batch_size: 10
  streaming_mode: true
  memory_limit: "512MB"

performance:
  enable_swapping: false
  gc_frequency: 100
```

## Scaling Strategies

### Horizontal Scaling

```python
# Distribute audit work across multiple workers
from celery import Celery

app = Celery('audit_workers')

@app.task
def audit_schema_chunk(schema_tables):
    """Audit a chunk of database schema."""
    tool = DataAssetInventoryTool()
    return tool.analyze_tables(schema_tables)

def distributed_audit():
    """Distribute audit work across Celery workers."""

    # Get all tables
    tables = get_database_tables()

    # Split into chunks
    chunk_size = 50
    chunks = [tables[i:i+chunk_size]
              for i in range(0, len(tables), chunk_size)]

    # Submit tasks to workers
    job = [audit_schema_chunk.delay(chunk) for chunk in chunks]

    # Collect results
    results = [task.get() for task in job]

    return combine_audit_results(results)
```

### Vertical Scaling

```python
# Optimize for high-performance single machine
async def vertical_scaled_audit():
    """Optimize audit for maximum single-machine performance."""

    # Use all available CPU cores
    import os
    worker_count = os.cpu_count()

    # Configure for maximum throughput
    config = {
        'database': {
            'pool_size': worker_count * 5,
            'max_overflow': worker_count * 10
        },
        'performance': {
            'parallel_workers': worker_count,
            'memory_limit': '8GB',
            'enable_all_optimizations': True
        }
    }

    tool = DataAssetInventoryTool(config=config)
    return await tool.perform_full_inventory_parallel()
```

## See Also

- [Common Issues](common-issues.md) - Troubleshooting performance problems
- [Configuration Guide](../integration-guides/configuration-guide.md) - Configuration optimization
- [API Reference](../api-reference/inventory-tools.md) - Performance-related API options
