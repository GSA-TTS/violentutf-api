# Common Issues and Solutions

This document covers common issues encountered when using the database audit tools and their solutions.

## Database Connection Issues

### Issue: `DatabaseConnectionError: Unable to connect to PostgreSQL`

**Symptoms**: Scripts fail immediately with connection error

**Causes**:
- Incorrect DATABASE_URL configuration
- Database server unreachable
- Authentication failures
- Network connectivity issues

**Solutions**:

1. **Verify DATABASE_URL format**:
   ```bash
   # Correct format
   export DATABASE_URL="postgresql://username:password@host:port/database_name"

   # Test connection
   psql $DATABASE_URL -c "SELECT 1"
   ```

2. **Check database server status**:
   ```bash
   # Check if PostgreSQL is running
   pg_isready -h localhost -p 5432

   # Check service status
   systemctl status postgresql  # Linux
   brew services list | grep postgresql  # macOS
   ```

3. **Verify authentication**:
   ```bash
   # Test authentication
   psql -h localhost -U username -d database_name

   # Check user permissions
   psql $DATABASE_URL -c "SELECT current_user, session_user;"
   ```

### Issue: Redis Connection Failures

**Symptoms**: Cache-related operations fail

**Solutions**:

```bash
# Check Redis server
redis-cli ping

# Test connection with URL
redis-cli -u $REDIS_URL ping

# Start Redis if not running
redis-server  # Default configuration
```

## Configuration Issues

### Issue: `ValidationError: Configuration file invalid`

**Symptoms**: Configuration validation fails during startup

**Common Issues and Diagnosis**:

```python
# Test configuration file
import yaml
try:
    with open('audit-config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print("Configuration file is valid YAML")
except yaml.YAMLError as e:
    print(f"YAML error: {e}")
```

**Solutions**:

1. **Fix YAML syntax**:
   ```yaml
   # Correct YAML format
   database:
     primary:
       url: "${DATABASE_URL}"
       pool_size: 10

   # Common mistake - incorrect indentation
   # database:
   # primary:  # This should be indented
   #   url: "${DATABASE_URL}"
   ```

2. **Validate required fields**:
   ```python
   required_fields = ['database.primary.url']
   for field in required_fields:
       if not get_nested_config_value(config, field):
           raise ValidationError(f"Required field missing: {field}")
   ```

## Permission and Access Errors

### Issue: `PermissionError: Access denied to audit logs`

**Symptoms**: Cannot write audit reports or access log files

**Solutions**:

```bash
# Check directory permissions
ls -la audit-reports/

# Fix permissions
chmod 755 audit-reports/
chmod 644 audit-reports/*.json

# Create directories with correct permissions
mkdir -p audit-reports audit-baselines logs
chmod 755 audit-reports audit-baselines logs
```

### Issue: Database Permission Denied

**Symptoms**: Cannot access database tables or schemas

**Solutions**:

```sql
-- Grant necessary permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO audit_user;
GRANT USAGE ON SCHEMA public TO audit_user;

-- Check current permissions
SELECT grantee, privilege_type, table_name
FROM information_schema.role_table_grants
WHERE grantee = 'audit_user';
```

## Performance and Timeout Issues

### Issue: Audit Tools Running Slowly

**Symptoms**: Long execution times, timeouts

**Diagnosis**:

```python
# Profile audit execution
import time
start_time = time.time()
result = await tool.perform_full_inventory()
execution_time = time.time() - start_time
print(f"Execution time: {execution_time:.2f} seconds")
```

**Solutions**:

1. **Use parallel execution**:
   ```python
   # Use optimized parallel version
   result = await tool.perform_full_inventory_parallel()
   ```

2. **Optimize database connections**:
   ```yaml
   database:
     primary:
       pool_size: 20  # Increase pool size
       max_overflow: 30
       pool_timeout: 60
   ```

3. **Reduce audit scope**:
   ```yaml
   inventory:
     include_schemas: ["public"]  # Limit to specific schemas
     exclude_tables: ["temp_*", "cache_*", "log_*"]
   ```

### Issue: Memory Usage Too High

**Symptoms**: Out of memory errors, system slowdown

**Solutions**:

```bash
# Monitor memory usage
python3 -c "
import psutil
process = psutil.Process()
print(f'Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"

# Use memory-efficient processing
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
```

## File System and Output Issues

### Issue: Cannot Create Audit Reports

**Symptoms**: Reports are not generated, file system errors

**Solutions**:

```bash
# Check disk space
df -h

# Check output directory
ls -la ./audit-reports/

# Create output directories
mkdir -p audit-reports/$(date +%Y-%m-%d)
chmod 755 audit-reports/$(date +%Y-%m-%d)
```

### Issue: Corrupted Audit Reports

**Symptoms**: Reports are incomplete or unreadable

**Solutions**:

```python
# Validate report files
import json
try:
    with open('audit-report.json', 'r') as f:
        data = json.load(f)
    print("Report file is valid JSON")
except json.JSONDecodeError as e:
    print(f"Report corruption detected: {e}")
    # Regenerate report
```

## Integration and Dependency Issues

### Issue: Import Errors

**Symptoms**: `ModuleNotFoundError` or import failures

**Solutions**:

```bash
# Check Python path
python3 -c "import sys; print('\\n'.join(sys.path))"

# Verify virtual environment
which python3
pip list | grep -E "(sqlalchemy|redis|pyyaml)"

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Issue: Docker Container Failures

**Symptoms**: Container exits with errors

**Solutions**:

```bash
# Check container logs
docker logs violentutf-audit-tools

# Debug container interactively
docker run -it --entrypoint /bin/bash violentutf-audit-tools

# Verify environment variables
docker run --rm violentutf-audit-tools env | grep -E "(DATABASE|REDIS)"
```

## Error Codes Reference

### AUDIT-001: Database Connection Failure

**Description**: Cannot establish connection to primary database

**Resolution**:
1. Verify DATABASE_URL format and credentials
2. Check database server availability
3. Validate network connectivity
4. Review firewall settings

### AUDIT-002: Configuration Validation Error

**Description**: Configuration file contains invalid settings

**Resolution**:
1. Validate YAML/JSON syntax
2. Check required fields are present
3. Verify environment variable substitution
4. Review configuration schema

### AUDIT-003: Permission Denied

**Description**: Insufficient permissions for operation

**Resolution**:
1. Check file system permissions
2. Verify database user permissions
3. Review directory access rights
4. Validate user role assignments

### AUDIT-004: Resource Timeout

**Description**: Operation exceeded configured timeout

**Resolution**:
1. Increase timeout values in configuration
2. Optimize query performance
3. Use parallel execution mode
4. Reduce audit scope

### AUDIT-005: Invalid Input Data

**Description**: Input data does not meet validation requirements

**Resolution**:
1. Validate input data format
2. Check data type requirements
3. Review field constraints
4. Verify data integrity

## Prevention Strategies

### Regular Maintenance

```bash
# Weekly maintenance script
#!/bin/bash

# Clean old audit reports (older than 30 days)
find audit-reports/ -name "*.json" -mtime +30 -delete

# Rotate log files
logrotate /etc/logrotate.d/audit-tools

# Update database statistics
psql $DATABASE_URL -c "ANALYZE;"
```

### Monitoring Setup

```python
# Health check script
async def health_check():
    checks = {
        "database": test_database_connection(),
        "redis": test_redis_connection(),
        "disk_space": check_disk_space(),
        "memory": check_memory_usage()
    }

    failed_checks = [k for k, v in checks.items() if not v]
    if failed_checks:
        send_alert(f"Health check failed: {failed_checks}")

    return len(failed_checks) == 0
```

## Getting Help

If you continue to experience issues:

1. **Check System Requirements**: Verify all prerequisites are met
2. **Review Logs**: Check application and system logs for error details
3. **Test Incrementally**: Isolate the issue by testing individual components
4. **Consult Documentation**: Review relevant API and integration guides
5. **Contact Support**: Reach out to the development team with specific error messages and system information

## Related Documentation

- [Setup and Installation](../integration-guides/setup-and-installation.md)
- [Configuration Guide](../integration-guides/configuration-guide.md)
- [Performance Tuning](performance-tuning.md)
- [Error Reference](error-reference.md)
