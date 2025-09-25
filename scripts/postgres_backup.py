"""PostgreSQL backup automation with WAL archiving and encryption."""

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

from audit_utils.exceptions import AuditError, audit_error_handler
from audit_utils.file_operations import safe_write_json
from audit_utils.logging import setup_audit_logger

# Setup audit logger
logger = setup_audit_logger(__name__)


class BackupValidationError(AuditError):
    """Raised when backup validation fails."""

    pass


class BackupStorageError(AuditError):
    """Raised when backup storage operations fail."""

    pass


@dataclass
class BackupConfig:
    """PostgreSQL backup configuration."""

    database_url: str
    backup_directory: str
    retention_days: int = 30
    compression_level: int = 6
    encryption_enabled: bool = False
    wal_archiving_enabled: bool = True
    max_concurrent_backups: int = 2

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.database_url:
            raise ValueError("Database URL is required")

        if not self.database_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("Invalid PostgreSQL database URL")

        if self.retention_days <= 0:
            raise ValueError("Retention days must be positive")

        if not (1 <= self.compression_level <= 9):
            raise ValueError("Compression level must be between 1 and 9")

    def is_valid(self) -> bool:
        """Check if configuration is valid."""
        try:
            self.__post_init__()
            return True
        except ValueError:
            return False


@dataclass
class BackupResult:
    """Result of a backup operation."""

    success: bool
    backup_type: str = ""
    file_path: Optional[str] = None
    file_size: int = 0
    duration_seconds: float = 0.0
    error_message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    checksum: str = ""
    compression_ratio: float = 0.0


class PostgresBackupManager:
    """Manages PostgreSQL backup operations."""

    def __init__(self, config: BackupConfig):
        """Initialize backup manager with configuration."""
        self.config = config
        self.backup_directory = Path(config.backup_directory)
        self.encryption_enabled = config.encryption_enabled
        self._backup_in_progress = False

        # Create backup directory if it doesn't exist
        self.backup_directory.mkdir(parents=True, exist_ok=True)

        # Parse database connection details
        self._parse_database_url()

    def _parse_database_url(self) -> None:
        """Parse database URL into connection components."""
        parsed = urllib.parse.urlparse(self.config.database_url)
        self.db_host = parsed.hostname or "localhost"
        self.db_port = parsed.port or 5432
        self.db_name = parsed.path.lstrip("/") or "postgres"
        self.db_user = parsed.username or "postgres"
        self.db_password = parsed.password

    @audit_error_handler
    async def create_full_backup(self, progress_callback: Optional[Callable[..., None]] = None) -> BackupResult:
        """Create a full database backup."""
        if self._backup_in_progress:
            return BackupResult(success=False, error_message="Backup already in progress")

        self._backup_in_progress = True
        start_time = datetime.now()

        try:
            # Generate backup filename
            timestamp = datetime.now()
            filename = self.generate_backup_filename("full", timestamp)
            backup_path = self.backup_directory / filename

            # Build pg_dump command
            cmd = self._build_pg_dump_command(str(backup_path))

            # Execute backup
            if progress_callback:
                progress_callback("Starting full backup...")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour timeout

            if result.returncode != 0:
                return BackupResult(success=False, error_message=f"pg_dump failed: {result.stderr}")

            # Verify backup file exists and has content
            if not backup_path.exists() or backup_path.stat().st_size == 0:
                return BackupResult(success=False, error_message="Backup file not created or empty")

            # Calculate file size and duration
            file_size = backup_path.stat().st_size
            duration = (datetime.now() - start_time).total_seconds()

            # Encrypt if enabled
            if self.encryption_enabled:
                if progress_callback:
                    progress_callback("Encrypting backup...")
                encrypted_path = await self.encrypt_backup_file(str(backup_path))
                # Remove unencrypted file
                backup_path.unlink()
                backup_path = Path(encrypted_path)
                file_size = backup_path.stat().st_size

            # Validate backup integrity
            if progress_callback:
                progress_callback("Validating backup integrity...")

            self.validate_backup_integrity(str(backup_path))

            # Store metadata
            metadata = {
                "backup_type": "full",
                "timestamp": timestamp.isoformat(),
                "file_size": file_size,
                "duration_seconds": duration,
                "compression_level": self.config.compression_level,
                "encrypted": self.encryption_enabled,
            }
            self.store_backup_metadata(str(backup_path), metadata)

            return BackupResult(
                success=True,
                backup_type="full",
                file_path=str(backup_path),
                file_size=file_size,
                duration_seconds=duration,
                timestamp=timestamp,
            )

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return BackupResult(success=False, error_message=str(e))
        finally:
            self._backup_in_progress = False

    @audit_error_handler
    async def create_incremental_backup(self) -> BackupResult:
        """Create an incremental backup using WAL archiving."""
        if not self.config.wal_archiving_enabled:
            return BackupResult(success=False, error_message="WAL archiving not enabled")

        start_time = datetime.now()

        try:
            # Generate WAL backup filename
            timestamp = datetime.now()
            filename = self.generate_backup_filename("incremental", timestamp)
            backup_path = self.backup_directory / filename

            # Archive current WAL files
            cmd = [
                "pg_receivewal",
                "-h",
                self.db_host,
                "-p",
                str(self.db_port),
                "-U",
                self.db_user,
                "-D",
                str(backup_path.parent),
                "--synchronous",
                "--slot",
                f"backup_slot_{timestamp.strftime('%Y%m%d_%H%M%S')}",
            ]

            if self.db_password:
                env = os.environ.copy()
                env["PGPASSWORD"] = self.db_password
            else:
                env = None

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)  # 10 minute timeout

            if result.returncode != 0:
                return BackupResult(success=False, error_message=f"WAL archiving failed: {result.stderr}")

            duration = (datetime.now() - start_time).total_seconds()

            return BackupResult(
                success=True,
                backup_type="incremental",
                file_path=str(backup_path),
                duration_seconds=duration,
                timestamp=timestamp,
            )

        except Exception as e:
            logger.error(f"Incremental backup failed: {e}")
            return BackupResult(success=False, error_message=str(e))

    def _build_pg_dump_command(self, output_file: str) -> List[str]:
        """Build pg_dump command with proper options."""
        cmd = [
            "pg_dump",
            "-h",
            self.db_host,
            "-p",
            str(self.db_port),
            "-U",
            self.db_user,
            "-d",
            self.db_name,
            "--format=custom",
            f"--compress={self.config.compression_level}",
            "--verbose",
            "--file",
            output_file,
        ]

        return cmd

    @audit_error_handler
    def validate_backup_integrity(self, backup_file: str) -> bool:
        """Validate backup file integrity using pg_restore."""
        try:
            cmd = ["pg_restore", "--list", backup_file]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minute timeout

            if result.returncode != 0:
                raise BackupValidationError(f"Backup validation failed: {result.stderr}")

            # Check if output contains expected structure
            if not result.stdout or "Archive created at" not in result.stdout:
                logger.warning("Backup validation output unexpected, but pg_restore succeeded")

            return True

        except Exception as e:
            logger.error(f"Backup validation error: {e}")
            raise BackupValidationError(str(e))

    @audit_error_handler
    def apply_retention_policy(self) -> List[str]:
        """Apply retention policy and remove old backups."""
        removed_files = []
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_days)

        try:
            # Find all backup files
            backup_patterns = ["backup_*.sql.gz", "backup_*.sql", "backup_*.gpg"]

            for pattern in backup_patterns:
                for backup_file in self.backup_directory.glob(pattern):
                    try:
                        # Extract timestamp from filename
                        # For backup_full_20250101_120000.sql.gz -> ['backup', 'full', '20250101', '120000']
                        parts = backup_file.stem.split("_")
                        if len(parts) >= 3:
                            # Join the last two parts as date_time
                            timestamp_str = f"{parts[-2]}_{parts[-1]}"
                        else:
                            # Fallback for simple backup_20250101_120000.sql.gz format
                            timestamp_str = parts[1] if len(parts) > 1 else parts[0]

                        if timestamp_str.endswith(".sql"):
                            timestamp_str = timestamp_str[:-4]

                        file_timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                        if file_timestamp < cutoff_date:
                            backup_file.unlink()
                            removed_files.append(str(backup_file))
                            logger.info(f"Removed old backup: {backup_file}")

                            # Also remove metadata file if it exists
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
    async def encrypt_backup_file(self, backup_file: str) -> str:
        """Encrypt backup file using GPG."""
        try:
            encrypted_file = f"{backup_file}.gpg"

            cmd = [
                "gpg",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--compress-algo",
                "2",
                "--output",
                encrypted_file,
                backup_file,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input="backup_passphrase\n",  # In production, use proper key management
                timeout=300,
            )

            if result.returncode != 0:
                raise BackupStorageError(f"Encryption failed: {result.stderr}")

            return encrypted_file

        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise BackupStorageError(str(e))

    def get_backup_file_size(self, backup_file: str) -> int:
        """Get backup file size in bytes."""
        try:
            return Path(backup_file).stat().st_size
        except Exception:
            return 0

    def generate_backup_filename(self, backup_type: str, timestamp: datetime) -> str:
        """Generate backup filename with timestamp and type."""
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")

        if backup_type == "full":
            return f"backup_full_{timestamp_str}.sql.gz"
        elif backup_type == "incremental":
            return f"backup_incremental_{timestamp_str}.wal"
        else:
            return f"backup_{backup_type}_{timestamp_str}.sql.gz"

    def validate_schedule_config(self, schedule_config: Dict[str, str]) -> bool:
        """Validate backup schedule configuration."""
        required_keys = ["full_backup_schedule", "incremental_schedule"]

        for key in required_keys:
            if key not in schedule_config:
                return False

            # Basic cron expression validation (5 fields)
            cron_parts = schedule_config[key].split()
            if len(cron_parts) != 5:
                return False

        return True

    @audit_error_handler
    def store_backup_metadata(self, backup_file: str, metadata: Dict[str, Any]) -> None:
        """Store backup metadata in separate file using safe JSON operations."""
        # Ensure we use the full path in backup directory
        if not os.path.isabs(backup_file):
            backup_file = os.path.join(self.backup_directory, backup_file)

        metadata_file = Path(f"{backup_file}.metadata")
        safe_write_json(metadata_file, metadata)

    def _handle_backup_error(self, error_message: str) -> None:
        """Handle and classify backup errors."""
        error_lower = error_message.lower()

        if "could not connect" in error_lower:
            raise ConnectionError(f"Database connection failed: {error_message}")
        elif "permission denied" in error_lower:
            raise PermissionError(f"Permission denied: {error_message}")
        elif "no space left" in error_lower:
            raise OSError(f"Disk full: {error_message}")
        elif "database does not exist" in error_lower:
            raise ValueError(f"Invalid database: {error_message}")
        else:
            raise Exception(f"Backup error: {error_message}")


async def main() -> None:
    """Main function for testing backup functionality."""
    # Example configuration
    config = BackupConfig(
        database_url="postgresql://violentutf:violentutf@localhost:5432/violentutf",
        backup_directory=f"{tempfile.gettempdir()}/postgres_backups",
        retention_days=30,
        compression_level=6,
        encryption_enabled=False,
    )

    manager = PostgresBackupManager(config)

    # Test full backup
    print("Creating full backup...")
    result = await manager.create_full_backup()

    if result.success:
        print(f"Backup successful: {result.file_path}")
        print(f"File size: {result.file_size} bytes")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
    else:
        print(f"Backup failed: {result.error_message}")

    # Test retention policy
    print("Applying retention policy...")
    removed_files = manager.apply_retention_policy()
    print(f"Removed {len(removed_files)} old backup files")


if __name__ == "__main__":
    asyncio.run(main())
