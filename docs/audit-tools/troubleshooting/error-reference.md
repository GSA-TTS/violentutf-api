# Error Reference Guide

This document provides a comprehensive reference for error codes, error messages, and diagnostic procedures for the database audit tools.

## Error Code Categories

### AUDIT-0xx: Connection and Infrastructure Errors
### AUDIT-1xx: Configuration and Validation Errors
### AUDIT-2xx: Permission and Security Errors
### AUDIT-3xx: Performance and Resource Errors
### AUDIT-4xx: Data and Processing Errors

## Detailed Error Reference

### AUDIT-001: Database Connection Failure

**Error Message**: `DatabaseConnectionError: Unable to connect to PostgreSQL`

**Common Issues**:
- Invalid connection string format
- Database server unavailable
- Authentication failure
- Network connectivity problems

**Diagnosis Commands**:
```bash
# Test basic connectivity
pg_isready -h hostname -p port

# Test authentication
psql "postgresql://user:pass@host:port/db" -c "SELECT version();"

# Check network connectivity
telnet hostname port
```

**Resolution Steps**:
1. Validate connection string format
2. Verify database server status
3. Check credentials and permissions
4. Test network connectivity

**Related Error Codes**: AUDIT-003, AUDIT-004

---

### AUDIT-002: Configuration Validation Error

**Error Message**: `ValidationError: Configuration file contains invalid settings`

**Common Issues**:
- YAML/JSON syntax errors
- Missing required configuration fields
- Invalid data types or values
- Environment variable substitution failures

**Diagnosis Commands**:
```python
# Validate YAML syntax
import yaml
with open('config.yaml', 'r') as f:
    try:
        config = yaml.safe_load(f)
        print("Valid YAML")
    except yaml.YAMLError as e:
        print(f"YAML Error: {e}")
```

**Resolution Steps**:
1. Check file syntax with YAML/JSON validator
2. Verify all required fields are present
3. Validate data types and value ranges
4. Test environment variable expansion

---

### AUDIT-003: Permission Denied

**Error Message**: `PermissionError: Insufficient privileges for operation`

**Common Issues**:
- File system permission errors
- Database user lacks required privileges
- Directory access restrictions
- Security policy violations

**Diagnosis Commands**:
```bash
# Check file permissions
ls -la audit-reports/
ls -la audit-baselines/

# Check database permissions
psql $DATABASE_URL -c "
SELECT grantee, privilege_type, table_name
FROM information_schema.role_table_grants
WHERE grantee = current_user;
"
```

**Resolution Steps**:
1. Set appropriate file system permissions
2. Grant required database privileges
3. Verify user role assignments
4. Check security policies

---

### AUDIT-004: Resource Timeout

**Error Message**: `TimeoutError: Operation exceeded configured timeout (300s)`

**Common Issues**:
- Long-running database queries
- Network latency issues
- Insufficient system resources
- Configuration timeout too low

**Diagnosis Commands**:
```python
# Profile operation timing
import time
start = time.time()
# ... operation ...
duration = time.time() - start
print(f"Operation took {duration:.2f}s")
```

**Resolution Steps**:
1. Increase timeout configuration values
2. Optimize database queries
3. Use parallel execution mode
4. Monitor system resources

---

### AUDIT-005: Invalid Input Data

**Error Message**: `ValidationError: Input data does not meet requirements`

**Common Issues**:
- Data type mismatches
- Missing required fields
- Value out of valid range
- Format validation failures

**Diagnosis Commands**:
```python
# Validate input data structure
def validate_input(data):
    required_fields = ['database_url', 'output_dir']
    for field in required_fields:
        if field not in data:
            print(f"Missing field: {field}")

    if 'timeout' in data and data['timeout'] < 0:
        print("Invalid timeout value")
```

---

### AUDIT-101: Schema Discovery Failure

**Error Message**: `SchemaDiscoveryError: Cannot analyze database schema`

**Common Issues**:
- Database user lacks INFORMATION_SCHEMA access
- Unsupported database version
- Corrupted system catalogs
- Network interruption during discovery

**Diagnosis Commands**:
```sql
-- Test schema access
SELECT COUNT(*) FROM information_schema.tables;
SELECT COUNT(*) FROM information_schema.columns;

-- Check database version
SELECT version();
```

---

### AUDIT-102: Repository Analysis Error

**Error Message**: `RepositoryAnalysisError: Cannot parse repository structure`

**Common Issues**:
- Python syntax errors in analyzed files
- Missing or corrupted source files
- Import resolution failures
- Unsupported code patterns

**Diagnosis Commands**:
```python
# Test Python file parsing
import ast
try:
    with open('problematic_file.py', 'r') as f:
        ast.parse(f.read())
    print("File parses successfully")
except SyntaxError as e:
    print(f"Syntax error: {e}")
```

---

### AUDIT-201: Backup Operation Failure

**Error Message**: `BackupError: Backup operation failed`

**Common Issues**:
- Insufficient disk space
- Database connection lost during backup
- Backup directory permissions
- Backup tool not available

**Diagnosis Commands**:
```bash
# Check disk space
df -h /backup/location

# Test backup tool availability
which pg_dump
pg_dump --version

# Check backup directory
ls -la /backup/directory
```

---

### AUDIT-202: Restore Operation Failure

**Error Message**: `RestoreError: Cannot restore from backup`

**Common Issues**:
- Corrupted backup files
- Version mismatch between backup and target
- Target database not empty
- Insufficient privileges

**Diagnosis Commands**:
```bash
# Verify backup file integrity
gzip -t backup_file.sql.gz

# Check backup file format
file backup_file.sql.gz
head -n 10 backup_file.sql
```

---

### AUDIT-301: Memory Exhaustion

**Error Message**: `MemoryError: Insufficient memory for operation`

**Common Issues**:
- Large dataset processing
- Memory leaks in long-running processes
- Insufficient system RAM
- Inefficient algorithms

**Diagnosis Commands**:
```python
# Monitor memory usage
import psutil
import os

process = psutil.Process(os.getpid())
memory_mb = process.memory_info().rss / 1024 / 1024
print(f"Current memory usage: {memory_mb:.2f} MB")
```

**Resolution Steps**:
1. Process data in smaller chunks
2. Use memory-efficient algorithms
3. Increase system memory
4. Enable memory optimization flags

---

### AUDIT-302: Disk Space Insufficient

**Error Message**: `DiskSpaceError: Insufficient disk space for audit reports`

**Common Issues**:
- Output directory disk full
- Large audit reports
- Log file accumulation
- Backup files consuming space

**Diagnosis Commands**:
```bash
# Check disk usage
df -h
du -sh audit-reports/
du -sh audit-baselines/
du -sh logs/
```

## Error Message Patterns

### Database Connection Patterns

```
DatabaseConnectionError: could not connect to server
DatabaseConnectionError: FATAL: password authentication failed
DatabaseConnectionError: FATAL: database "..." does not exist
DatabaseConnectionError: timeout expired
```

### Configuration Error Patterns

```
ValidationError: missing required field 'database.url'
ValidationError: invalid value for 'timeout': must be positive integer
YAMLError: mapping values are not allowed here
JSONDecodeError: Expecting ',' delimiter
```

### Permission Error Patterns

```
PermissionError: [Errno 13] Permission denied: 'audit-reports/'
psycopg2.errors.InsufficientPrivilege: permission denied for table
OSError: [Errno 1] Operation not permitted
```

## Diagnostic Tools and Commands

### System Diagnostics

```bash
# Check system resources
free -h                    # Memory usage
df -h                     # Disk usage
top -p $(pgrep python)    # Process monitoring
lsof -i :5432             # Network connections

# Check Python environment
python3 --version
pip list | grep -E "(psycopg2|redis|sqlalchemy)"
python3 -c "import sys; print(sys.path)"
```

### Database Diagnostics

```sql
-- Check database connectivity and permissions
SELECT current_user, current_database(), version();

-- Check table access
SELECT schemaname, tablename, tableowner
FROM pg_tables
WHERE schemaname = 'public';

-- Monitor active connections
SELECT count(*) as active_connections
FROM pg_stat_activity
WHERE state = 'active';

-- Check database size
SELECT pg_size_pretty(pg_database_size(current_database()));
```

### Application Diagnostics

```python
# Test audit tool components
from tools.inventory.data_asset_inventory import DataAssetInventoryTool

# Test tool initialization
try:
    tool = DataAssetInventoryTool()
    print("Tool initialized successfully")
except Exception as e:
    print(f"Initialization failed: {e}")

# Test database connectivity
try:
    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    print("Database connection successful")
    conn.close()
except Exception as e:
    print(f"Database connection failed: {e}")
```

## Error Recovery Procedures

### Automatic Recovery

```python
# Retry mechanism with exponential backoff
import time
import random

def retry_operation(operation, max_retries=3):
    for attempt in range(max_retries):
        try:
            return operation()
        except Exception as e:
            if attempt == max_retries - 1:
                raise e

            wait_time = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(wait_time)
            print(f"Retry attempt {attempt + 1} after {wait_time:.2f}s")
```

### Manual Recovery

```bash
# Reset audit environment
./scripts/reset_audit_environment.sh

# Clean temporary files
find . -name "*.tmp" -delete
find . -name "*.lock" -delete

# Restart services
systemctl restart postgresql
systemctl restart redis

# Verify system state
./scripts/verify_audit_environment.sh
```

## Preventive Monitoring

### Health Checks

```python
async def comprehensive_health_check():
    """Comprehensive system health check."""
    health_status = {
        "database": False,
        "redis": False,
        "disk_space": False,
        "memory": False,
        "permissions": False
    }

    # Database connectivity
    try:
        # Test database connection
        health_status["database"] = True
    except Exception:
        pass

    # Redis connectivity
    try:
        # Test Redis connection
        health_status["redis"] = True
    except Exception:
        pass

    # Resource checks
    health_status["disk_space"] = check_disk_space() > 1024  # > 1GB free
    health_status["memory"] = check_memory_usage() < 80     # < 80% used
    health_status["permissions"] = check_file_permissions()

    return health_status
```

### Alerting Setup

```bash
# Set up monitoring alerts
# Add to crontab: */15 * * * * /path/to/health_check.sh

#!/bin/bash
# health_check.sh

if ! python3 -c "from tools.inventory.data_asset_inventory import DataAssetInventoryTool; print('OK')"; then
    echo "ALERT: Audit tools health check failed" | mail -s "Audit Tools Alert" admin@example.com
fi
```

## Related Documentation

- [Common Issues](common-issues.md) - Solutions for frequent problems
- [Performance Tuning](performance-tuning.md) - Optimization strategies
- [API Reference](../api-reference/inventory-tools.md) - Detailed API documentation
