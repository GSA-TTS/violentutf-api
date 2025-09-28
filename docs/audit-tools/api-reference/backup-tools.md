# Backup Tools API Reference

This document provides comprehensive API documentation for backup-related audit automation tools in the ViolentUTF API system.

## Overview

The backup tools provide comprehensive backup management, coverage auditing, and restoration capabilities for PostgreSQL and Redis data stores. These tools ensure data protection strategies are properly implemented and validated.

## Tools and Functions

### Backup Coverage Audit

**Location**: `scripts/backup_coverage_audit.py`

Provides comprehensive backup coverage analysis and validation across all data stores.

#### Key Functions

##### perform_backup_coverage_audit()

Performs comprehensive backup coverage analysis.

```python
async def perform_backup_coverage_audit(
    config_path: Optional[str] = None,
    verify_recent: bool = True,
    test_restore: bool = False
) -> Dict[str, Any]:
    """
    Perform comprehensive backup coverage audit.

    Args:
        config_path: Path to backup configuration file
        verify_recent: Whether to verify recent backups exist
        test_restore: Whether to test restore capability (slow)

    Returns:
        Dict containing backup coverage audit results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_path` | `Optional[str]` | `None` | Path to backup configuration file. Uses default if None |
| `verify_recent` | `bool` | `True` | Verify recent backups exist within configured timeframe |
| `test_restore` | `bool` | `False` | Test restore capability (requires additional time and resources) |

**Returns**:
- `Dict[str, Any]`: Backup coverage audit results including:
  - `coverage_summary`: Overall backup coverage statistics
  - `data_store_coverage`: Per-data-store coverage analysis
  - `backup_validation`: Backup file validation results
  - `restore_test_results`: Restore test results (if enabled)
  - `recommendations`: Backup strategy recommendations
  - `compliance_status`: Compliance with backup policies

**Example Usage**:

```python
import asyncio
from scripts.backup_coverage_audit import perform_backup_coverage_audit

async def audit_backup_coverage():
    # Basic coverage audit
    results = await perform_backup_coverage_audit()

    coverage_summary = results.get("coverage_summary", {})
    print(f"Overall coverage score: {coverage_summary.get('coverage_percentage', 0)}%")
    print(f"Data stores covered: {coverage_summary.get('covered_stores', 0)}")

    # Comprehensive audit with restore testing
    comprehensive_results = await perform_backup_coverage_audit(
        verify_recent=True,
        test_restore=True
    )

    restore_results = comprehensive_results.get("restore_test_results", {})
    successful_restores = restore_results.get("successful_tests", 0)
    print(f"Successful restore tests: {successful_restores}")

    return results

asyncio.run(audit_backup_coverage())
```

**Command Line Usage**:

```bash
# Run basic backup coverage audit
python3 scripts/backup_coverage_audit.py

# Run comprehensive audit with restore testing
python3 scripts/backup_coverage_audit.py --verify-recent --test-restore

# Run with custom configuration
python3 scripts/backup_coverage_audit.py --config /path/to/backup-config.yaml

# Generate detailed report
python3 scripts/backup_coverage_audit.py --output-format html --output-dir ./reports
```

##### validate_backup_files()

Validates integrity and accessibility of backup files.

```python
def validate_backup_files(backup_directory: str) -> Dict[str, Any]:
    """
    Validate backup file integrity and accessibility.

    Args:
        backup_directory: Directory containing backup files

    Returns:
        Dict containing validation results
    """
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `backup_directory` | `str` | Path to directory containing backup files |

**Returns**:
- `Dict[str, Any]`: Validation results including:
  - `total_files`: Total backup files found
  - `valid_files`: Number of valid backup files
  - `corrupted_files`: List of corrupted backup files
  - `missing_checksums`: Files without integrity checksums
  - `size_analysis`: Backup file size analysis

**Example Usage**:

```python
validation_results = validate_backup_files("/backups/postgres")

corrupted = validation_results.get("corrupted_files", [])
if corrupted:
    print(f"Corrupted backup files detected: {corrupted}")
    print("Action required: Investigate backup corruption")
```

### PostgreSQL Backup Tool

**Location**: `scripts/postgres_backup.py`

Provides comprehensive PostgreSQL backup operations with multiple strategies.

#### Key Functions

##### create_postgres_backup()

Creates PostgreSQL database backup with specified strategy.

```python
async def create_postgres_backup(
    database_url: str,
    backup_type: str = "full",
    output_directory: str = "./backups",
    compression: bool = True,
    include_schema_only: bool = False
) -> Dict[str, Any]:
    """
    Create PostgreSQL database backup.

    Args:
        database_url: PostgreSQL connection string
        backup_type: Type of backup ("full", "incremental", "differential")
        output_directory: Directory to store backup files
        compression: Whether to compress backup files
        include_schema_only: Include schema-only backup

    Returns:
        Dict containing backup operation results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `database_url` | `str` | - | PostgreSQL connection string |
| `backup_type` | `str` | `"full"` | Backup type: "full", "incremental", or "differential" |
| `output_directory` | `str` | `"./backups"` | Directory to store backup files |
| `compression` | `bool` | `True` | Enable compression for backup files |
| `include_schema_only` | `bool` | `False` | Also create schema-only backup for structure |

**Returns**:
- `Dict[str, Any]`: Backup operation results including:
  - `backup_file_path`: Path to created backup file
  - `backup_size`: Size of backup file in bytes
  - `backup_duration`: Time taken for backup operation
  - `checksum`: Backup file integrity checksum
  - `metadata`: Backup metadata and configuration
  - `success`: Boolean indicating backup success

**Example Usage**:

```python
import asyncio
from scripts.postgres_backup import create_postgres_backup

async def backup_database():
    # Create full backup with compression
    backup_result = await create_postgres_backup(
        database_url="postgresql://user:pass@localhost:5432/mydb",
        backup_type="full",
        compression=True,
        include_schema_only=True
    )

    if backup_result.get("success"):
        backup_file = backup_result.get("backup_file_path")
        size_mb = backup_result.get("backup_size", 0) / (1024 * 1024)
        print(f"Backup successful: {backup_file}")
        print(f"Backup size: {size_mb:.2f} MB")
    else:
        print("Backup failed - check logs for details")

    return backup_result

asyncio.run(backup_database())
```

##### restore_postgres_backup()

Restores PostgreSQL database from backup file.

```python
async def restore_postgres_backup(
    backup_file_path: str,
    target_database_url: str,
    restore_options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Restore PostgreSQL database from backup.

    Args:
        backup_file_path: Path to backup file
        target_database_url: Target database connection string
        restore_options: Additional restore configuration options

    Returns:
        Dict containing restore operation results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `backup_file_path` | `str` | - | Path to backup file to restore |
| `target_database_url` | `str` | - | Target database connection string |
| `restore_options` | `Optional[Dict[str, Any]]` | `None` | Additional restore options |

**Returns**:
- `Dict[str, Any]`: Restore operation results including:
  - `success`: Boolean indicating restore success
  - `restore_duration`: Time taken for restore operation
  - `tables_restored`: Number of tables restored
  - `data_rows_restored`: Total data rows restored
  - `warnings`: Any warnings during restore process

**Example Usage**:

```python
# Restore database from backup
restore_result = await restore_postgres_backup(
    backup_file_path="/backups/postgres/mydb_20240101_120000.sql.gz",
    target_database_url="postgresql://user:pass@localhost:5432/test_restore",
    restore_options={
        "clean_target": True,
        "verbose": True,
        "ignore_errors": False
    }
)

if restore_result.get("success"):
    print("Database restored successfully")
    print(f"Tables restored: {restore_result.get('tables_restored', 0)}")
else:
    print("Restore failed - check logs for errors")
```

##### schedule_automated_backups()

Sets up automated backup scheduling.

```python
def schedule_automated_backups(
    database_url: str,
    schedule_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Schedule automated PostgreSQL backups.

    Args:
        database_url: PostgreSQL connection string
        schedule_config: Backup schedule configuration

    Returns:
        Dict containing scheduling results
    """
```

**Example Usage**:

```python
# Schedule daily backups at 2 AM
schedule_config = {
    "frequency": "daily",
    "time": "02:00",
    "backup_type": "full",
    "retention_days": 30,
    "compression": True,
    "notification_email": "admin@example.com"
}

schedule_result = schedule_automated_backups(
    database_url="postgresql://user:pass@localhost:5432/mydb",
    schedule_config=schedule_config
)
```

### Redis Backup Tool

**Location**: `scripts/redis_backup.py`

Provides comprehensive Redis backup operations with multiple strategies.

#### Key Functions

##### create_redis_backup()

Creates Redis data backup with specified strategy.

```python
async def create_redis_backup(
    redis_url: str,
    backup_type: str = "rdb",
    output_directory: str = "./backups",
    include_all_databases: bool = True
) -> Dict[str, Any]:
    """
    Create Redis data backup.

    Args:
        redis_url: Redis connection string
        backup_type: Type of backup ("rdb", "aof", "memory_dump")
        output_directory: Directory to store backup files
        include_all_databases: Include all Redis databases

    Returns:
        Dict containing backup operation results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redis_url` | `str` | - | Redis connection string |
| `backup_type` | `str` | `"rdb"` | Backup type: "rdb", "aof", or "memory_dump" |
| `output_directory` | `str` | `"./backups"` | Directory to store backup files |
| `include_all_databases` | `bool` | `True` | Include all Redis databases (0-15) |

**Returns**:
- `Dict[str, Any]`: Backup operation results including:
  - `backup_files`: List of created backup files
  - `total_keys_backed_up`: Total number of keys backed up
  - `backup_size`: Total size of backup files
  - `databases_included`: List of database numbers included
  - `success`: Boolean indicating backup success

**Example Usage**:

```python
import asyncio
from scripts.redis_backup import create_redis_backup

async def backup_redis():
    # Create RDB backup of all databases
    backup_result = await create_redis_backup(
        redis_url="redis://localhost:6379",
        backup_type="rdb",
        include_all_databases=True
    )

    if backup_result.get("success"):
        total_keys = backup_result.get("total_keys_backed_up", 0)
        backup_files = backup_result.get("backup_files", [])
        print(f"Redis backup successful: {len(backup_files)} files created")
        print(f"Total keys backed up: {total_keys}")

    return backup_result

asyncio.run(backup_redis())
```

##### restore_redis_backup()

Restores Redis data from backup files.

```python
async def restore_redis_backup(
    backup_files: List[str],
    target_redis_url: str,
    restore_mode: str = "replace"
) -> Dict[str, Any]:
    """
    Restore Redis data from backup files.

    Args:
        backup_files: List of backup files to restore
        target_redis_url: Target Redis connection string
        restore_mode: Restore mode ("replace", "merge", "selective")

    Returns:
        Dict containing restore operation results
    """
```

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `backup_files` | `List[str]` | - | List of backup files to restore |
| `target_redis_url` | `str` | - | Target Redis connection string |
| `restore_mode` | `str` | `"replace"` | Restore mode: "replace", "merge", or "selective" |

**Example Usage**:

```python
# Restore Redis from backup files
restore_result = await restore_redis_backup(
    backup_files=["/backups/redis/redis_db0.rdb", "/backups/redis/redis_db1.rdb"],
    target_redis_url="redis://localhost:6379",
    restore_mode="replace"
)

if restore_result.get("success"):
    print("Redis restore completed successfully")
```

## Advanced Backup Strategies

### Multi-Database Backup Orchestration

```python
import asyncio
from scripts.postgres_backup import create_postgres_backup
from scripts.redis_backup import create_redis_backup
from scripts.backup_coverage_audit import perform_backup_coverage_audit

async def orchestrated_backup_strategy():
    """Orchestrated backup across multiple data stores."""

    backup_results = {}

    # PostgreSQL backup
    print("Starting PostgreSQL backup...")
    pg_result = await create_postgres_backup(
        database_url="postgresql://user:pass@localhost:5432/maindb",
        backup_type="full",
        compression=True
    )
    backup_results["postgresql"] = pg_result

    # Redis backup
    print("Starting Redis backup...")
    redis_result = await create_redis_backup(
        redis_url="redis://localhost:6379",
        backup_type="rdb",
        include_all_databases=True
    )
    backup_results["redis"] = redis_result

    # Verify backup coverage
    print("Verifying backup coverage...")
    coverage_result = await perform_backup_coverage_audit(
        verify_recent=True,
        test_restore=False  # Skip slow restore tests in regular runs
    )
    backup_results["coverage_audit"] = coverage_result

    # Generate summary report
    summary = {
        "total_backups": len(backup_results),
        "successful_backups": sum(1 for result in backup_results.values()
                                 if result.get("success", False)),
        "timestamp": datetime.now().isoformat(),
        "coverage_score": coverage_result.get("coverage_summary", {}).get("coverage_percentage", 0)
    }

    print(f"Backup orchestration complete:")
    print(f"- Successful backups: {summary['successful_backups']}/{summary['total_backups']}")
    print(f"- Coverage score: {summary['coverage_score']}%")

    return {
        "results": backup_results,
        "summary": summary
    }
```

### Disaster Recovery Testing

```python
async def disaster_recovery_test():
    """Comprehensive disaster recovery capability test."""

    # Create test backups
    test_results = {
        "backup_creation": {},
        "restoration_tests": {},
        "data_integrity": {},
        "recovery_time": {}
    }

    start_time = time.time()

    # Test PostgreSQL backup and restore
    print("Testing PostgreSQL backup/restore...")
    pg_backup = await create_postgres_backup(
        database_url="postgresql://user:pass@localhost:5432/testdb",
        backup_type="full"
    )

    if pg_backup.get("success"):
        pg_restore = await restore_postgres_backup(
            backup_file_path=pg_backup.get("backup_file_path"),
            target_database_url="postgresql://user:pass@localhost:5432/testdb_restore"
        )
        test_results["restoration_tests"]["postgresql"] = pg_restore

    # Test Redis backup and restore
    print("Testing Redis backup/restore...")
    redis_backup = await create_redis_backup(
        redis_url="redis://localhost:6379",
        backup_type="rdb"
    )

    if redis_backup.get("success"):
        redis_restore = await restore_redis_backup(
            backup_files=redis_backup.get("backup_files", []),
            target_redis_url="redis://localhost:6380"  # Different port for test
        )
        test_results["restoration_tests"]["redis"] = redis_restore

    total_time = time.time() - start_time
    test_results["recovery_time"]["total_seconds"] = total_time

    # Analyze results
    successful_tests = sum(1 for test in test_results["restoration_tests"].values()
                          if test.get("success", False))

    print(f"Disaster recovery test complete:")
    print(f"- Successful restore tests: {successful_tests}/2")
    print(f"- Total recovery time: {total_time:.2f} seconds")

    return test_results
```

## Backup Monitoring and Alerting

### Backup Health Monitoring

```python
async def monitor_backup_health():
    """Monitor backup system health and generate alerts."""

    health_status = {
        "backup_freshness": {},
        "storage_capacity": {},
        "backup_integrity": {},
        "alerts": []
    }

    # Check backup freshness
    coverage_audit = await perform_backup_coverage_audit(verify_recent=True)
    data_store_coverage = coverage_audit.get("data_store_coverage", {})

    for store, coverage in data_store_coverage.items():
        last_backup = coverage.get("last_backup_time")
        if last_backup:
            hours_since_backup = (datetime.now() - datetime.fromisoformat(last_backup)).total_seconds() / 3600

            if hours_since_backup > 24:  # Alert if backup is older than 24 hours
                health_status["alerts"].append({
                    "type": "stale_backup",
                    "store": store,
                    "hours_since_backup": hours_since_backup,
                    "severity": "high" if hours_since_backup > 48 else "medium"
                })

    # Check storage capacity
    backup_dirs = ["/backups/postgres", "/backups/redis"]
    for backup_dir in backup_dirs:
        if os.path.exists(backup_dir):
            total, used, free = shutil.disk_usage(backup_dir)
            usage_percent = (used / total) * 100

            if usage_percent > 85:  # Alert if storage is >85% full
                health_status["alerts"].append({
                    "type": "storage_capacity",
                    "directory": backup_dir,
                    "usage_percent": usage_percent,
                    "severity": "high" if usage_percent > 95 else "medium"
                })

    # Generate health report
    health_score = 100 - (len(health_status["alerts"]) * 10)  # Simple scoring
    health_status["overall_health_score"] = max(0, health_score)

    return health_status
```

## Error Handling and Recovery

### Common Exceptions

| Exception | Description | Resolution |
|-----------|-------------|------------|
| `BackupCreationError` | Failed to create backup | Check database connectivity and permissions |
| `BackupCorruptionError` | Backup file is corrupted | Recreate backup and verify checksums |
| `InsufficientStorageError` | Not enough storage space | Clean old backups or increase storage |
| `RestoreFailureError` | Restore operation failed | Verify backup integrity and target database |
| `PermissionError` | Insufficient file/database permissions | Check user permissions and access rights |

### Robust Error Handling

```python
async def robust_backup_operation():
    """Robust backup operation with comprehensive error handling and recovery."""

    try:
        # Attempt primary backup
        backup_result = await create_postgres_backup(
            database_url="postgresql://user:pass@localhost:5432/mydb",
            backup_type="full"
        )

        if not backup_result.get("success"):
            raise BackupCreationError("Primary backup failed")

        # Validate backup integrity
        validation_result = validate_backup_files(
            backup_result.get("backup_file_path")
        )

        if validation_result.get("corrupted_files"):
            raise BackupCorruptionError("Backup validation failed")

        return backup_result

    except BackupCreationError as e:
        print(f"Backup creation failed: {e}")
        # Attempt incremental backup as fallback
        try:
            fallback_result = await create_postgres_backup(
                database_url="postgresql://user:pass@localhost:5432/mydb",
                backup_type="incremental"
            )
            print("Fallback incremental backup successful")
            return fallback_result
        except Exception as fallback_error:
            print(f"Fallback backup also failed: {fallback_error}")

    except InsufficientStorageError as e:
        print(f"Storage issue: {e}")
        # Cleanup old backups
        cleanup_old_backups(retention_days=7)
        # Retry backup
        return await create_postgres_backup(
            database_url="postgresql://user:pass@localhost:5432/mydb",
            backup_type="full"
        )

    except Exception as e:
        print(f"Unexpected backup error: {e}")

    return {"success": False, "error": "Backup operation failed"}

def cleanup_old_backups(retention_days: int = 30):
    """Clean up backup files older than retention period."""
    # Implementation would remove old backup files
    pass
```

## Configuration Options

### Backup Configuration

```yaml
# backup-config.yaml
backup:
  postgresql:
    connection_url: "${DATABASE_URL}"
    backup_types:
      - "full"
      - "incremental"
    schedule:
      full_backup: "0 2 * * 0"  # Weekly full backup at 2 AM Sunday
      incremental_backup: "0 2 * * 1-6"  # Daily incremental backups
    retention:
      full_backups: 30  # days
      incremental_backups: 7  # days
    compression: true
    encryption: true

  redis:
    connection_url: "${REDIS_URL}"
    backup_type: "rdb"
    schedule: "0 3 * * *"  # Daily at 3 AM
    retention_days: 14
    include_all_databases: true

  storage:
    base_directory: "/backups"
    max_storage_usage: 85  # percent
    cleanup_threshold: 95  # percent

  monitoring:
    health_check_interval: 3600  # seconds
    alert_on_failure: true
    notification_email: "admin@example.com"

  disaster_recovery:
    test_restore_frequency: "weekly"
    test_environment_url: "${TEST_DATABASE_URL}"
    max_recovery_time: 1800  # seconds
```

## See Also

- [Integration Guides](../integration-guides/docker-integration.md) - Docker backup strategies
- [Troubleshooting](../troubleshooting/common-issues.md) - Backup troubleshooting
- [Examples](../examples/automated-monitoring.md) - Automated backup monitoring
- [Configuration Tools API](configuration-tools.md) - Configuration management
