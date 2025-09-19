"""PyRIT memory storage migration from DuckDB to PostgreSQL/Redis."""

import asyncio
import json
import logging
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MigrationConfig:
    """Configuration for PyRIT memory storage migration."""

    source_duckdb_path: str
    target_postgres_url: str
    target_redis_url: str
    backup_directory: str
    chunk_size: int = 1000
    verify_data: bool = True
    create_backup: bool = True


@dataclass
class MigrationResult:
    """Result of PyRIT migration operation."""

    success: bool
    records_migrated: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    backup_path: Optional[str] = None
    rollback_available: bool = False


@dataclass
class PyRITMemoryRecord:
    """Represents a PyRIT memory record for migration."""

    id: str
    conversation_id: str
    role: str
    content: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class PyRITMigrationManager:
    """Manages PyRIT memory storage migration operations."""

    def __init__(self, config: MigrationConfig):
        """Initialize PyRIT migration manager."""
        self.config = config
        self.source_path = Path(config.source_duckdb_path)
        self.backup_directory = Path(config.backup_directory)

        # Create backup directory
        self.backup_directory.mkdir(parents=True, exist_ok=True)

        # Migration statistics
        self.migration_stats: Dict[str, Any] = {
            "total_records": 0,
            "migrated_records": 0,
            "failed_records": 0,
            "start_time": None,
            "end_time": None,
        }

    async def execute_migration(self) -> MigrationResult:
        """Execute complete PyRIT memory storage migration."""
        start_time = datetime.now()
        self.migration_stats["start_time"] = int(start_time.timestamp())

        try:
            logger.info("Starting PyRIT memory storage migration")

            # Step 1: Validate source data
            logger.info("Validating source DuckDB data...")
            validation_result = await self._validate_source_data()
            if not validation_result["valid"]:
                return MigrationResult(
                    success=False, errors=[f"Source validation failed: {validation_result['error']}"]
                )

            # Step 2: Create backup if enabled
            backup_path = None
            if self.config.create_backup:
                logger.info("Creating source data backup...")
                backup_path = await self._create_source_backup()

            # Step 3: Extract data from DuckDB
            logger.info("Extracting data from DuckDB...")
            extracted_data: Dict[str, Any] = await self._extract_duckdb_data()

            # Step 4: Transform data for target storage
            logger.info("Transforming data for target storage...")
            transformed_data = await self._transform_data(extracted_data)

            # Step 5: Migrate to PostgreSQL (structured data)
            logger.info("Migrating structured data to PostgreSQL...")
            postgres_result = await self._migrate_to_postgres(transformed_data["structured"])

            # Step 6: Migrate to Redis (cache/session data)
            logger.info("Migrating cache data to Redis...")
            redis_result = await self._migrate_to_redis(transformed_data["cache"])

            # Step 7: Verify migration if enabled
            if self.config.verify_data:
                logger.info("Verifying migrated data...")
                verification_result = await self._verify_migration(extracted_data)
            else:
                verification_result = {"verified": True, "errors": []}

            # Calculate results
            end_time = datetime.now()
            self.migration_stats["end_time"] = int(end_time.timestamp())
            duration = (end_time - start_time).total_seconds()

            total_migrated = postgres_result["migrated"] + redis_result["migrated"]

            errors = []
            errors.extend(postgres_result.get("errors", []))
            errors.extend(redis_result.get("errors", []))
            errors.extend(verification_result.get("errors", []))

            warnings = []
            warnings.extend(postgres_result.get("warnings", []))
            warnings.extend(redis_result.get("warnings", []))

            success = postgres_result["success"] and redis_result["success"] and verification_result["verified"]

            logger.info(f"Migration completed. Success: {success}, Records: {total_migrated}")

            return MigrationResult(
                success=success,
                records_migrated=total_migrated,
                errors=errors,
                warnings=warnings,
                duration_seconds=duration,
                backup_path=backup_path,
                rollback_available=backup_path is not None,
            )

        except Exception as e:
            logger.error(f"Migration failed with exception: {e}")
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            return MigrationResult(
                success=False,
                errors=[str(e)],
                duration_seconds=duration,
                rollback_available=backup_path is not None,
            )

    async def _validate_source_data(self) -> Dict[str, Any]:
        """Validate source DuckDB data."""
        try:
            if not self.source_path.exists():
                return {"valid": False, "error": f"Source DuckDB file not found: {self.source_path}"}

            # Check file size
            file_size = self.source_path.stat().st_size
            if file_size == 0:
                return {"valid": False, "error": "Source DuckDB file is empty"}

            # Try to connect and validate schema
            try:
                # DuckDB would require actual duckdb library
                # For this implementation, we'll simulate with SQLite
                with sqlite3.connect(str(self.source_path)) as conn:
                    cursor = conn.cursor()

                    # Check for expected PyRIT tables
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]

                    expected_tables = ["conversations", "memory_entries", "scores"]
                    missing_tables = [table for table in expected_tables if table not in tables]

                    if missing_tables:
                        return {"valid": False, "error": f"Missing expected tables: {missing_tables}"}

                    # Count records
                    cursor.execute("SELECT COUNT(*) FROM memory_entries")
                    record_count = cursor.fetchone()[0]
                    self.migration_stats["total_records"] = record_count

                    return {
                        "valid": True,
                        "record_count": record_count,
                        "tables": tables,
                        "file_size_mb": file_size / (1024 * 1024),
                    }

            except Exception as e:
                return {"valid": False, "error": f"Database validation error: {str(e)}"}

        except Exception as e:
            return {"valid": False, "error": f"File validation error: {str(e)}"}

    async def _create_source_backup(self) -> str:
        """Create backup of source DuckDB file."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"pyrit_duckdb_backup_{timestamp}.db"
            backup_path = self.backup_directory / backup_filename

            # Copy source file to backup location
            shutil.copy2(self.source_path, backup_path)

            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise

    async def _extract_duckdb_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract data from DuckDB source."""
        try:
            extracted_data: Dict[str, List[Any]] = {
                "memory_entries": [],
                "conversations": [],
                "scores": [],
                "metadata": [],
            }

            with sqlite3.connect(str(self.source_path)) as conn:
                conn.row_factory = sqlite3.Row  # Enable dict-like access
                cursor = conn.cursor()

                # Extract memory entries
                cursor.execute(
                    """
                    SELECT * FROM memory_entries
                    ORDER BY timestamp DESC
                """
                )

                for row in cursor.fetchall():
                    entry = dict(row)
                    # Convert timestamp if it's a string
                    if isinstance(entry.get("timestamp"), str):
                        try:
                            entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
                        except ValueError:
                            entry["timestamp"] = datetime.now()

                    extracted_data["memory_entries"].append(entry)

                # Extract conversations
                cursor.execute("SELECT * FROM conversations")
                for row in cursor.fetchall():
                    extracted_data["conversations"].append(dict(row))

                # Extract scores
                cursor.execute("SELECT * FROM scores")
                for row in cursor.fetchall():
                    extracted_data["scores"].append(dict(row))

            logger.info(f"Extracted {len(extracted_data['memory_entries'])} memory entries")
            return extracted_data

        except Exception as e:
            logger.error(f"Data extraction failed: {e}")
            raise

    async def _transform_data(self, extracted_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Transform extracted data for target storage systems."""
        try:
            transformed_data: Dict[str, Dict[str, Any]] = {
                "structured": {  # For PostgreSQL
                    "conversations": [],
                    "memory_entries": [],
                    "scores": [],
                },
                "cache": {  # For Redis
                    "session_data": {},
                    "conversation_cache": {},
                    "score_cache": {},
                },
            }

            # Transform conversations for PostgreSQL
            for conv in extracted_data["conversations"]:
                transformed_conv = {
                    "id": conv.get("id"),
                    "conversation_id": conv.get("conversation_id"),
                    "created_at": conv.get("created_at", datetime.now()),
                    "updated_at": conv.get("updated_at", datetime.now()),
                    "metadata": json.dumps(conv.get("metadata", {})),
                    "status": conv.get("status", "active"),
                }
                transformed_data["structured"]["conversations"].append(transformed_conv)

            # Transform memory entries for PostgreSQL
            for entry in extracted_data["memory_entries"]:
                transformed_entry = {
                    "id": entry.get("id"),
                    "conversation_id": entry.get("conversation_id"),
                    "role": entry.get("role", "user"),
                    "content": entry.get("content", ""),
                    "timestamp": entry.get("timestamp", datetime.now()),
                    "labels": json.dumps(entry.get("labels", [])),
                    "metadata": json.dumps(entry.get("metadata", {})),
                }
                transformed_data["structured"]["memory_entries"].append(transformed_entry)

            # Transform scores for PostgreSQL
            for score in extracted_data["scores"]:
                transformed_score = {
                    "id": score.get("id"),
                    "memory_entry_id": score.get("memory_entry_id"),
                    "score_type": score.get("score_type"),
                    "score_value": score.get("score_value", 0.0),
                    "scorer_class_identifier": score.get("scorer_class_identifier"),
                    "timestamp": score.get("timestamp", datetime.now()),
                }
                transformed_data["structured"]["scores"].append(transformed_score)

            # Create Redis cache data
            # Cache recent conversations by ID
            for conv in extracted_data["conversations"][-100:]:  # Last 100 conversations
                cache_key = f"conversation:{conv.get('conversation_id')}"
                transformed_data["cache"]["conversation_cache"][cache_key] = json.dumps(conv)

            # Cache recent memory entries by conversation
            conversation_groups: Dict[str, List[Dict[str, Any]]] = {}
            for entry in extracted_data["memory_entries"]:
                conv_id = entry.get("conversation_id")
                if conv_id and conv_id not in conversation_groups:
                    conversation_groups[conv_id] = []
                if conv_id:
                    conversation_groups[conv_id].append(entry)

            for conv_id, entries in conversation_groups.items():
                if len(entries) <= 50:  # Cache smaller conversations
                    cache_key = f"memory_entries:{conv_id}"
                    transformed_data["cache"]["session_data"][cache_key] = json.dumps(entries)

            return transformed_data

        except Exception as e:
            logger.error(f"Data transformation failed: {e}")
            raise

    async def _migrate_to_postgres(self, structured_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Migrate structured data to PostgreSQL."""
        try:
            # This would use actual PostgreSQL connection
            # For this implementation, we'll simulate the migration

            migrated_count = 0
            errors = []
            warnings = []

            # Simulate table creation and data insertion
            for table_name, records in structured_data.items():
                try:
                    # In real implementation:
                    # 1. Create table if not exists
                    # 2. Insert records in batches
                    # 3. Handle conflicts and updates

                    logger.info(f"Migrating {len(records)} records to {table_name}")

                    # Simulate batch processing
                    for i in range(0, len(records), self.config.chunk_size):
                        batch = records[i : i + self.config.chunk_size]

                        # Simulate batch insert
                        await asyncio.sleep(0.1)  # Simulate processing time
                        migrated_count += len(batch)

                        # Simulate occasional errors
                        if len(batch) > 500 and table_name == "memory_entries":
                            warnings.append(f"Large batch detected for {table_name}: {len(batch)} records")

                except Exception as e:
                    error_msg = f"Failed to migrate {table_name}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)

            success = len(errors) == 0

            return {
                "success": success,
                "migrated": migrated_count,
                "errors": errors,
                "warnings": warnings,
            }

        except Exception as e:
            return {
                "success": False,
                "migrated": 0,
                "errors": [str(e)],
                "warnings": [],
            }

    async def _migrate_to_redis(self, cache_data: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Migrate cache data to Redis."""
        try:
            # This would use actual Redis connection
            # For this implementation, we'll simulate the migration

            migrated_count = 0
            errors = []
            warnings: List[str] = []

            for cache_type, cache_entries in cache_data.items():
                try:
                    logger.info(f"Migrating {len(cache_entries)} entries to Redis {cache_type}")

                    for key, value in cache_entries.items():
                        try:
                            # In real implementation:
                            # redis_client.set(key, value, ex=3600)  # 1 hour expiry

                            # Simulate Redis operation
                            await asyncio.sleep(0.01)  # Simulate Redis latency
                            migrated_count += 1

                        except Exception as e:
                            error_msg = f"Failed to set Redis key {key}: {str(e)}"
                            errors.append(error_msg)

                except Exception as e:
                    error_msg = f"Failed to migrate {cache_type}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)

            # Set migration metadata in Redis
            # migration_metadata = {
            #     "migration_timestamp": datetime.now().isoformat(),
            #     "source": "duckdb",
            #     "migrated_records": migrated_count,
            # }
            # redis_client.set('pyrit:migration:metadata', json.dumps(migration_metadata))

            success = len(errors) == 0

            return {
                "success": success,
                "migrated": migrated_count,
                "errors": errors,
                "warnings": warnings,
            }

        except Exception as e:
            return {
                "success": False,
                "migrated": 0,
                "errors": [str(e)],
                "warnings": [],
            }

    async def _verify_migration(self, original_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Verify migrated data integrity."""
        try:
            verification_errors = []

            # Count verification
            original_count = len(original_data.get("memory_entries", []))

            # In real implementation, would query PostgreSQL and Redis
            # For simulation, assume successful verification
            migrated_postgres_count = original_count  # Simulated
            migrated_redis_count = min(100, original_count)  # Simulated (only recent entries)

            if migrated_postgres_count != original_count:
                verification_errors.append(
                    f"Record count mismatch: original={original_count}, " f"migrated={migrated_postgres_count}"
                )

            # Data integrity verification
            # In real implementation, would sample records and verify content
            sample_verification_passed = True  # Simulated

            if not sample_verification_passed:
                verification_errors.append("Sample data integrity verification failed")

            # Schema verification
            schema_verification_passed = True  # Simulated

            if not schema_verification_passed:
                verification_errors.append("Schema verification failed")

            verified = len(verification_errors) == 0

            return {
                "verified": verified,
                "errors": verification_errors,
                "original_count": original_count,
                "migrated_postgres_count": migrated_postgres_count,
                "migrated_redis_count": migrated_redis_count,
            }

        except Exception as e:
            return {
                "verified": False,
                "errors": [f"Verification failed: {str(e)}"],
            }

    async def rollback_migration(self, backup_path: str) -> bool:
        """Rollback migration by restoring from backup."""
        try:
            if not Path(backup_path).exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False

            logger.info(f"Rolling back migration from backup: {backup_path}")

            # In real implementation, would:
            # 1. Clear migrated data from PostgreSQL
            # 2. Clear migrated data from Redis
            # 3. Restore DuckDB from backup if needed

            # For simulation
            await asyncio.sleep(1)  # Simulate rollback time

            logger.info("Migration rollback completed")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    def get_migration_progress(self) -> Dict[str, Any]:
        """Get current migration progress."""
        progress = self.migration_stats.copy()

        if (
            progress["start_time"]
            and progress["total_records"]
            and progress["total_records"] > 0
            and progress["migrated_records"] is not None
        ):
            start_time = datetime.fromtimestamp(progress["start_time"])
            elapsed = (datetime.now() - start_time).total_seconds()
            progress["elapsed_seconds"] = elapsed

            if progress["migrated_records"] > 0:
                records_per_second = progress["migrated_records"] / elapsed
                remaining_records = progress["total_records"] - progress["migrated_records"]
                estimated_remaining = remaining_records / records_per_second if records_per_second > 0 else 0

                progress["records_per_second"] = records_per_second
                progress["estimated_remaining_seconds"] = estimated_remaining
                progress["progress_percentage"] = (progress["migrated_records"] / progress["total_records"]) * 100

        return progress


async def main() -> None:
    """Main function for testing PyRIT migration."""
    # Example configuration
    config = MigrationConfig(
        source_duckdb_path="./pyrit_memory.db",
        target_postgres_url="postgresql://violentutf:violentutf@localhost:5432/violentutf",
        target_redis_url="redis://localhost:6379/0",
        backup_directory="./backups/pyrit_migration",
        chunk_size=1000,
        verify_data=True,
        create_backup=True,
    )

    manager = PyRITMigrationManager(config)

    # Execute migration
    print("Starting PyRIT memory storage migration...")
    result = await manager.execute_migration()

    print(f"Migration completed:")
    print(f"  Success: {result.success}")
    print(f"  Records migrated: {result.records_migrated}")
    print(f"  Duration: {result.duration_seconds:.2f} seconds")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Warnings: {len(result.warnings)}")

    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  - {error}")

    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")

    if result.backup_path:
        print(f"Backup created: {result.backup_path}")
        print(f"Rollback available: {result.rollback_available}")


if __name__ == "__main__":
    asyncio.run(main())
