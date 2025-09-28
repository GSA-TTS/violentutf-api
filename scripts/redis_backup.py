"""Redis backup automation with snapshot and AOF support."""

import asyncio
import gzip
import os
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import redis

from audit_utils.exceptions import AuditError, audit_error_handler
from audit_utils.file_operations import safe_write_json
from audit_utils.logging import setup_audit_logger

# Setup audit logger
logger = setup_audit_logger(__name__)


class RedisConnectionError(AuditError):
    """Raised when Redis connection fails."""

    pass


class RedisBackupError(AuditError):
    """Raised when Redis backup operations fail."""

    pass


@dataclass
class RedisBackupConfig:
    """Redis backup configuration."""

    redis_url: str
    backup_directory: str
    retention_days: int = 14
    aof_enabled: bool = True
    compression_enabled: bool = True
    snapshot_interval_hours: int = 6
    ssl_cert_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.redis_url:
            raise ValueError("Redis URL is required")

        if not self.redis_url.startswith(("redis://", "rediss://")):
            raise ValueError("Invalid Redis URL")

        if self.retention_days <= 0:
            raise ValueError("Retention days must be positive")

    def is_valid(self) -> bool:
        """Check if configuration is valid."""
        try:
            self.__post_init__()
            return True
        except ValueError:
            return False


@dataclass
class RedisBackupResult:
    """Result of a Redis backup operation."""

    success: bool
    backup_type: str = ""
    file_path: Optional[str] = None
    file_size: int = 0
    duration_seconds: float = 0.0
    error_message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    memory_usage_mb: float = 0.0
    compression_ratio: float = 0.0


class RedisBackupManager:
    """Manages Redis backup operations."""

    def __init__(self, config: RedisBackupConfig):
        """Initialize Redis backup manager with configuration."""
        self.config = config
        self.backup_directory = Path(config.backup_directory)
        self.aof_enabled = config.aof_enabled
        self._backup_in_progress = False

        # Create backup directory if it doesn't exist
        self.backup_directory.mkdir(parents=True, exist_ok=True)

        # Parse Redis connection details
        self._parse_redis_url()

        # Initialize Redis client
        self._init_redis_client()

    def _parse_redis_url(self) -> None:
        """Parse Redis URL into connection components."""
        parsed = urllib.parse.urlparse(self.config.redis_url)
        self.redis_host = parsed.hostname or "localhost"
        self.redis_port = parsed.port or 6379
        self.redis_db = int(parsed.path.lstrip("/")) if parsed.path else 0
        self.redis_password = parsed.password
        self.redis_ssl = parsed.scheme == "rediss"

    def _init_redis_client(self) -> None:
        """Initialize Redis client connection."""
        try:
            redis_kwargs = {
                "host": self.redis_host,
                "port": self.redis_port,
                "db": self.redis_db,
                "decode_responses": False,  # Keep binary for backup operations
            }

            if self.redis_password:
                redis_kwargs["password"] = self.redis_password

            if self.redis_ssl:
                redis_kwargs["ssl"] = True
                if self.config.ssl_cert_path:
                    redis_kwargs["ssl_certfile"] = self.config.ssl_cert_path

            self.redis_client = redis.Redis(**redis_kwargs)  # type: ignore

        except Exception as e:
            logger.error(f"Failed to initialize Redis client: {e}")
            raise RedisConnectionError(str(e))

    @audit_error_handler
    async def create_snapshot_backup(
        self, progress_callback: Optional[Callable[..., None]] = None
    ) -> RedisBackupResult:
        """Create a Redis snapshot backup using BGSAVE."""
        if self._backup_in_progress:
            return RedisBackupResult(success=False, error_message="Backup already in progress")

        self._backup_in_progress = True
        start_time = datetime.now()

        try:
            # Check Redis connection
            await self.check_redis_health()

            if progress_callback:
                progress_callback("Starting Redis snapshot backup...")

            # Get current memory usage
            memory_stats = self.get_memory_usage()

            # Trigger BGSAVE
            last_save_before = self.redis_client.lastsave()
            self.redis_client.bgsave()

            # Wait for BGSAVE to complete
            timeout = 300  # 5 minutes
            elapsed = 0
            while elapsed < timeout:
                current_save = self.redis_client.lastsave()
                if current_save > last_save_before:
                    break
                await asyncio.sleep(1)
                elapsed += 1

            if elapsed >= timeout:
                return RedisBackupResult(success=False, error_message="BGSAVE timeout")

            # Copy RDB file to backup location
            timestamp = datetime.now()
            filename = self.generate_backup_filename("snapshot", timestamp)
            backup_path = self.backup_directory / filename

            # Find Redis data directory and RDB file
            info = self.redis_client.info()
            redis_data_dir = info.get("dir", "/data")
            rdb_filename = info.get("dbfilename", "dump.rdb")
            source_path = Path(redis_data_dir) / rdb_filename

            if not source_path.exists():
                return RedisBackupResult(success=False, error_message=f"RDB file not found: {source_path}")

            # Copy RDB file
            shutil.copy2(source_path, backup_path)

            # Compress if enabled
            if self.config.compression_enabled:
                if progress_callback:
                    progress_callback("Compressing backup...")
                compressed_path = await self.compress_backup_file(str(backup_path))
                backup_path.unlink()  # Remove uncompressed file
                backup_path = Path(compressed_path)

            # Validate backup
            if progress_callback:
                progress_callback("Validating backup...")
            self.validate_rdb_backup(str(backup_path))

            # Calculate metrics
            file_size = backup_path.stat().st_size
            duration = (datetime.now() - start_time).total_seconds()

            # Store metadata
            metadata = {
                "backup_type": "snapshot",
                "timestamp": timestamp.isoformat(),
                "file_size": file_size,
                "duration_seconds": duration,
                "redis_memory_usage": memory_stats.get("used_memory", 0),
                "compressed": self.config.compression_enabled,
            }
            self.store_backup_metadata(str(backup_path), metadata)

            return RedisBackupResult(
                success=True,
                backup_type="snapshot",
                file_path=str(backup_path),
                file_size=file_size,
                duration_seconds=duration,
                timestamp=timestamp,
                memory_usage_mb=memory_stats.get("used_memory", 0) / (1024 * 1024),
            )

        except Exception as e:
            logger.error(f"Snapshot backup failed: {e}")
            return RedisBackupResult(success=False, error_message=str(e))
        finally:
            self._backup_in_progress = False

    @audit_error_handler
    async def create_aof_backup(self) -> RedisBackupResult:
        """Create AOF (Append Only File) backup."""
        if not self.aof_enabled:
            return RedisBackupResult(success=False, error_message="AOF not enabled")

        start_time = datetime.now()

        try:
            # Trigger AOF rewrite
            self.redis_client.bgrewriteaof()

            # Wait for rewrite to complete
            timeout = 300  # 5 minutes
            elapsed = 0
            while elapsed < timeout:
                info = self.redis_client.info("persistence")
                if info.get("aof_rewrite_in_progress", 0) == 0:
                    break
                await asyncio.sleep(1)
                elapsed += 1

            # Copy AOF file
            timestamp = datetime.now()
            filename = self.generate_backup_filename("aof", timestamp)
            backup_path = self.backup_directory / filename

            # Find AOF file
            info = self.redis_client.info()
            redis_data_dir = info.get("dir", "/data")
            aof_filename = info.get("aof_filename", "appendonly.aof")
            source_path = Path(redis_data_dir) / aof_filename

            if source_path.exists():
                shutil.copy2(source_path, backup_path)
            else:
                return RedisBackupResult(success=False, error_message=f"AOF file not found: {source_path}")

            file_size = backup_path.stat().st_size
            duration = (datetime.now() - start_time).total_seconds()

            return RedisBackupResult(
                success=True,
                backup_type="aof",
                file_path=str(backup_path),
                file_size=file_size,
                duration_seconds=duration,
                timestamp=timestamp,
            )

        except Exception as e:
            logger.error(f"AOF backup failed: {e}")
            return RedisBackupResult(success=False, error_message=str(e))

    @audit_error_handler
    def validate_rdb_backup(self, backup_file: str) -> bool:
        """Validate RDB backup file using redis-check-rdb."""
        try:
            # Check if file is compressed
            if backup_file.endswith(".gz"):
                # Decompress temporarily for validation
                with tempfile.NamedTemporaryFile(suffix=".rdb", delete=False) as temp_file:
                    with gzip.open(backup_file, "rb") as gz_file:
                        temp_file.write(gz_file.read())
                    temp_rdb_path = temp_file.name
            else:
                temp_rdb_path = backup_file

            try:
                cmd = ["redis-check-rdb", temp_rdb_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if result.returncode != 0:
                    raise RedisBackupError(f"RDB validation failed: {result.stderr}")

                return True

            finally:
                # Clean up temporary file if created
                if temp_rdb_path != backup_file:
                    Path(temp_rdb_path).unlink(missing_ok=True)

        except Exception as e:
            logger.error(f"RDB validation error: {e}")
            raise RedisBackupError(str(e))

    @audit_error_handler
    def apply_retention_policy(self) -> List[str]:
        """Apply retention policy and remove old backups."""
        removed_files = []
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_days)

        try:
            # Find all backup files
            backup_patterns = ["snapshot_*.rdb*", "aof_*.aof*", "*.gz"]

            for pattern in backup_patterns:
                for backup_file in self.backup_directory.glob(pattern):
                    try:
                        # Extract timestamp from filename
                        parts = backup_file.stem.split("_")
                        if len(parts) >= 3:
                            # Combine date and time parts: parts[1]_parts[2]
                            timestamp_str = f"{parts[1]}_{parts[2]}"
                            if "." in timestamp_str:
                                timestamp_str = timestamp_str.split(".")[0]

                            file_timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                            if file_timestamp < cutoff_date:
                                backup_file.unlink()
                                removed_files.append(str(backup_file))
                                logger.info(f"Removed old backup: {backup_file}")

                                # Also remove metadata file
                                metadata_file = backup_file.with_suffix(backup_file.suffix + ".metadata")
                                if metadata_file.exists():
                                    metadata_file.unlink()

                    except (ValueError, IndexError) as e:
                        logger.warning(f"Could not parse timestamp from {backup_file}: {e}")
                        continue

            return removed_files

        except Exception as e:
            logger.error(f"Error applying retention policy: {e}")
            return removed_files

    @audit_error_handler
    async def compress_backup_file(self, backup_file: str) -> str:
        """Compress backup file using gzip."""
        try:
            compressed_file = f"{backup_file}.gz"

            with open(backup_file, "rb") as f_in:
                with gzip.open(compressed_file, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            return compressed_file

        except Exception as e:
            logger.error(f"Compression error: {e}")
            raise RedisBackupError(str(e))

    @audit_error_handler
    async def check_redis_health(self) -> bool:
        """Check Redis connection health."""
        try:
            response = self.redis_client.ping()
            if response:
                logger.debug("Redis health check passed")
                return True
            else:
                raise RedisConnectionError("Redis ping failed")

        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            raise RedisConnectionError(str(e))

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get Redis memory usage statistics."""
        try:
            info = self.redis_client.info("memory")

            used_memory = info.get("used_memory", 0)
            max_memory = info.get("maxmemory", 0)

            stats = {
                "used_memory": used_memory,
                "used_memory_human": info.get("used_memory_human", "0B"),
                "maxmemory": max_memory,
                "usage_percentage": (used_memory / max_memory * 100) if max_memory > 0 else 0,
            }

            return stats

        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return {}

    def generate_backup_filename(self, backup_type: str, timestamp: datetime) -> str:
        """Generate backup filename with timestamp and type."""
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")

        if backup_type == "snapshot":
            return f"snapshot_{timestamp_str}.rdb"
        elif backup_type == "aof":
            return f"aof_{timestamp_str}.aof"
        else:
            return f"{backup_type}_{timestamp_str}.backup"

    def validate_schedule_config(self, schedule_config: Dict[str, str]) -> bool:
        """Validate backup schedule configuration."""
        required_keys = ["snapshot_schedule", "aof_backup_schedule"]

        for key in required_keys:
            if key not in schedule_config:
                return False

            # Basic cron expression validation
            cron_parts = schedule_config[key].split()
            if len(cron_parts) != 5:
                return False

        return True

    @audit_error_handler
    def store_backup_metadata(self, backup_file: str, metadata: Dict[str, Any]) -> None:
        """Store backup metadata in separate file using safe JSON operations."""
        metadata_file = Path(f"{backup_file}.metadata")
        safe_write_json(metadata_file, metadata)

    @audit_error_handler
    async def backup_multiple_databases(self, databases: List[int]) -> List[RedisBackupResult]:
        """Backup multiple Redis databases."""
        results = []

        for db_num in databases:
            try:
                # Switch to database
                original_db = self.redis_db
                self.redis_db = db_num
                self._init_redis_client()

                # Create backup
                result = await self.create_snapshot_backup()
                results.append(result)

                # Restore original database
                self.redis_db = original_db
                self._init_redis_client()

            except Exception as e:
                logger.error(f"Failed to backup database {db_num}: {e}")
                results.append(
                    RedisBackupResult(success=False, error_message=f"Database {db_num} backup failed: {str(e)}")
                )

        return results

    def _classify_error(self, error_message: str) -> str:
        """Classify error types for better error handling."""
        error_lower = error_message.lower()

        if "connection refused" in error_lower:
            return "connection_error"
        elif "noauth" in error_lower:
            return "auth_error"
        elif "out of memory" in error_lower:
            return "memory_error"
        elif "permission denied" in error_lower:
            return "permission_error"
        else:
            return "unknown_error"


async def main() -> None:
    """Main function for testing Redis backup functionality."""
    # Example configuration
    config = RedisBackupConfig(
        redis_url="redis://localhost:6379/0",
        backup_directory=f"{tempfile.gettempdir()}/redis_backups",
        retention_days=14,
        aof_enabled=True,
        compression_enabled=True,
    )

    manager = RedisBackupManager(config)

    # Test snapshot backup
    print("Creating Redis snapshot backup...")
    result = await manager.create_snapshot_backup()

    if result.success:
        print(f"Backup successful: {result.file_path}")
        print(f"File size: {result.file_size} bytes")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Memory usage: {result.memory_usage_mb:.2f} MB")
    else:
        print(f"Backup failed: {result.error_message}")

    # Test retention policy
    print("Applying retention policy...")
    removed_files = manager.apply_retention_policy()
    print(f"Removed {len(removed_files)} old backup files")


if __name__ == "__main__":
    asyncio.run(main())
