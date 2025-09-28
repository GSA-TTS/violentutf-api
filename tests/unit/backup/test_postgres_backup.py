"""Unit tests for PostgreSQL backup functionality."""

import asyncio
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.postgres_backup import (
    BackupConfig,
    BackupResult,
    BackupStorageError,
    BackupValidationError,
    PostgresBackupManager,
)


class TestPostgresBackupManager:
    """Test suite for PostgreSQL backup management."""

    @pytest.fixture
    def backup_config(self):
        """Create test backup configuration."""
        return BackupConfig(
            database_url="postgresql://test:test@localhost:5432/test_db",
            backup_directory=f"{tempfile.gettempdir()}/test_backups",
            retention_days=30,
            compression_level=6,
            encryption_enabled=True,
            wal_archiving_enabled=True,
        )

    @pytest.fixture
    def backup_manager(self, backup_config):
        """Create backup manager instance for testing."""
        return PostgresBackupManager(backup_config)

    def test_backup_manager_initialization(self, backup_config):
        """Test backup manager initializes correctly."""
        manager = PostgresBackupManager(backup_config)

        assert manager.config == backup_config
        assert manager.backup_directory == Path(backup_config.backup_directory)
        assert manager.encryption_enabled == backup_config.encryption_enabled

    def test_backup_directory_creation(self, backup_manager):
        """Test backup directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = BackupConfig(
                database_url="postgresql://test:test@localhost:5432/test_db",
                backup_directory=f"{temp_dir}/new_backup_dir",
                retention_days=30,
            )
            manager = PostgresBackupManager(config)

            # Directory should be created during initialization
            assert Path(config.backup_directory).exists()

    @pytest.mark.asyncio
    async def test_create_full_backup_success(self, backup_manager):
        """Test successful full backup creation."""
        with (
            patch("scripts.postgres_backup.subprocess.run") as mock_run,
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "stat") as mock_stat,
            patch.object(Path, "unlink"),
            patch.object(Path, "mkdir"),
            patch.object(backup_manager, "encrypt_backup_file") as mock_encrypt,
        ):

            # Mock successful pg_dump execution
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Backup completed successfully"

            # Mock file size
            mock_stat_obj = MagicMock()
            mock_stat_obj.st_size = 1024 * 1024  # 1MB backup
            mock_stat_obj.st_mode = 0o100644  # Regular file mode
            mock_stat.return_value = mock_stat_obj

            # Mock encryption returning encrypted file path
            async def mock_encrypt_func(file_path):
                return f"{file_path}.gpg"

            mock_encrypt.side_effect = mock_encrypt_func

            result = await backup_manager.create_full_backup()

            assert isinstance(result, BackupResult)
            assert result.success is True
            assert result.backup_type == "full"
            assert result.file_size > 0
            # File path should end with .sql.gz (or .sql.gz.gpg if encrypted)
            assert result.file_path.endswith(".sql.gz") or result.file_path.endswith(".sql.gz.gpg")

    @pytest.mark.asyncio
    async def test_create_full_backup_pg_dump_failure(self, backup_manager):
        """Test backup creation handles pg_dump failure."""
        with patch("scripts.postgres_backup.subprocess.run") as mock_run:
            # Mock pg_dump failure
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "pg_dump: error: connection failed"

            result = await backup_manager.create_full_backup()

            assert result.success is False
            assert "pg_dump: error" in result.error_message

    @pytest.mark.asyncio
    async def test_create_incremental_backup(self, backup_manager):
        """Test incremental backup creation using WAL archiving."""
        with (
            patch("scripts.postgres_backup.subprocess.run") as mock_run,
            patch("scripts.postgres_backup.Path.exists", return_value=True),
        ):

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "WAL archive completed"

            result = await backup_manager.create_incremental_backup()

            assert result.success is True
            assert result.backup_type == "incremental"
            assert "wal" in result.file_path.lower()

    def test_validate_backup_integrity_success(self, backup_manager):
        """Test backup integrity validation succeeds."""
        with (
            patch("scripts.postgres_backup.subprocess.run") as mock_run,
            patch("scripts.postgres_backup.Path.exists", return_value=True),
        ):

            # Mock successful pg_restore --list
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Archive created at 2024-01-01 12:00:00"

            backup_file = f"{tempfile.gettempdir()}/test_backup.sql.gz"
            is_valid = backup_manager.validate_backup_integrity(backup_file)

            assert is_valid is True

    def test_validate_backup_integrity_failure(self, backup_manager):
        """Test backup integrity validation detects corruption."""
        with patch("scripts.postgres_backup.subprocess.run") as mock_run:
            # Mock pg_restore failure indicating corruption
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "pg_restore: error: invalid archive"

            backup_file = f"{tempfile.gettempdir()}/corrupted_backup.sql.gz"

            with pytest.raises(BackupValidationError):
                backup_manager.validate_backup_integrity(backup_file)

    def test_apply_retention_policy(self, backup_manager):
        """Test retention policy removes old backups."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_manager.backup_directory = Path(temp_dir)

            # Create mock old backup files
            old_date = datetime.now() - timedelta(days=35)
            recent_date = datetime.now() - timedelta(days=5)

            # Create filenames that match what the retention policy expects
            # The policy extracts split('_')[1] so for 'backup_20250101_120000.sql.gz' it gets the timestamp
            old_backup = Path(temp_dir) / f"backup_{old_date.strftime('%Y%m%d_%H%M%S')}.sql.gz"
            recent_backup = Path(temp_dir) / f"backup_{recent_date.strftime('%Y%m%d_%H%M%S')}.sql.gz"

            old_backup.touch()
            recent_backup.touch()

            # Apply retention policy (30 days)
            removed_files = backup_manager.apply_retention_policy()

            assert len(removed_files) == 1
            assert not old_backup.exists()
            assert recent_backup.exists()

    @pytest.mark.asyncio
    async def test_encrypt_backup_file(self, backup_manager):
        """Test backup file encryption."""
        with (
            tempfile.NamedTemporaryFile(suffix=".sql") as temp_file,
            patch("scripts.postgres_backup.subprocess.run") as mock_run,
        ):

            # Mock successful GPG encryption
            mock_run.return_value.returncode = 0

            encrypted_file = await backup_manager.encrypt_backup_file(temp_file.name)

            assert encrypted_file.endswith(".gpg")
            assert mock_run.called

    @pytest.mark.asyncio
    async def test_encrypt_backup_file_failure(self, backup_manager):
        """Test backup encryption handles GPG failure."""
        with (
            tempfile.NamedTemporaryFile(suffix=".sql") as temp_file,
            patch("scripts.postgres_backup.subprocess.run") as mock_run,
        ):

            # Mock GPG failure
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "gpg: encryption failed"

            with pytest.raises(BackupStorageError):
                await backup_manager.encrypt_backup_file(temp_file.name)

    def test_get_backup_file_size(self, backup_manager):
        """Test backup file size calculation."""
        with tempfile.NamedTemporaryFile() as temp_file:
            # Write test data
            test_data = b"x" * 1024  # 1KB
            temp_file.write(test_data)
            temp_file.flush()

            size = backup_manager.get_backup_file_size(temp_file.name)
            assert size == 1024

    def test_generate_backup_filename(self, backup_manager):
        """Test backup filename generation."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)

        full_filename = backup_manager.generate_backup_filename("full", timestamp)
        assert "full" in full_filename
        assert "20240101_120000" in full_filename
        assert full_filename.endswith(".sql.gz")

        incremental_filename = backup_manager.generate_backup_filename("incremental", timestamp)
        assert "incremental" in incremental_filename
        assert incremental_filename.endswith(".wal")

    @pytest.mark.asyncio
    async def test_backup_scheduling_integration(self, backup_manager):
        """Test backup scheduling with cron-like functionality."""
        # This test would verify integration with task scheduling
        # For now, test the schedule validation logic

        schedule_config = {
            "full_backup_schedule": "0 2 * * *",  # Daily at 2 AM
            "incremental_schedule": "0 * * * *",  # Hourly
        }

        is_valid = backup_manager.validate_schedule_config(schedule_config)
        assert is_valid is True

    def test_backup_compression_levels(self, backup_manager):
        """Test different compression levels."""
        for level in [1, 6, 9]:
            backup_manager.config.compression_level = level

            # Verify compression level is correctly applied
            cmd_args = backup_manager._build_pg_dump_command("test_backup.sql")
            assert f"-Z{level}" in cmd_args or f"--compress={level}" in cmd_args

    @pytest.mark.asyncio
    async def test_concurrent_backup_prevention(self, backup_manager):
        """Test prevention of concurrent backup operations."""
        # Mock an ongoing backup
        backup_manager._backup_in_progress = True

        result = await backup_manager.create_full_backup()

        assert result.success is False
        assert "backup already in progress" in result.error_message.lower()

    def test_backup_metadata_storage(self, backup_manager):
        """Test backup metadata is correctly stored."""
        metadata = {
            "backup_type": "full",
            "timestamp": datetime.now().isoformat(),
            "database_size": 1024 * 1024,
            "compression_ratio": 0.6,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_manager.backup_directory = Path(temp_dir)

            backup_manager.store_backup_metadata("test_backup.sql.gz", metadata)

            metadata_file = Path(temp_dir) / "test_backup.sql.gz.metadata"
            assert metadata_file.exists()

    @pytest.mark.asyncio
    async def test_backup_progress_monitoring(self, backup_manager):
        """Test backup progress can be monitored."""
        progress_callback = MagicMock()

        with patch("scripts.postgres_backup.subprocess.Popen") as mock_popen:
            # Mock subprocess for progress monitoring
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            await backup_manager.create_full_backup(progress_callback=progress_callback)

            # Verify progress callback was called
            assert progress_callback.called

    def test_backup_error_handling(self, backup_manager):
        """Test comprehensive error handling."""
        # Test various error scenarios
        error_scenarios = [
            ("connection_error", "could not connect to database"),
            ("permission_error", "permission denied"),
            ("disk_full", "no space left on device"),
            ("invalid_database", "database does not exist"),
        ]

        for error_type, error_message in error_scenarios:
            with patch("scripts.postgres_backup.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 1
                mock_run.return_value.stderr = error_message

                with pytest.raises(Exception) as exc_info:
                    backup_manager._handle_backup_error(error_message)

                assert error_message in str(exc_info.value)


class TestBackupConfiguration:
    """Test backup configuration validation."""

    def test_valid_configuration(self):
        """Test valid backup configuration."""
        config = BackupConfig(
            database_url="postgresql://user:pass@localhost:5432/db",
            backup_directory="/backups",
            retention_days=30,
        )

        assert config.is_valid()

    def test_invalid_database_url(self):
        """Test invalid database URL validation."""
        with pytest.raises(ValueError):
            BackupConfig(
                database_url="invalid_url",
                backup_directory="/backups",
                retention_days=30,
            )

    def test_invalid_retention_days(self):
        """Test invalid retention days validation."""
        with pytest.raises(ValueError):
            BackupConfig(
                database_url="postgresql://user:pass@localhost:5432/db",
                backup_directory="/backups",
                retention_days=-1,
            )


class TestBackupResult:
    """Test backup result data structure."""

    def test_backup_result_creation(self):
        """Test backup result object creation."""
        result = BackupResult(
            success=True,
            backup_type="full",
            file_path="/backups/backup_20240101.sql.gz",
            file_size=1024 * 1024,
            duration_seconds=300,
        )

        assert result.success is True
        assert result.backup_type == "full"
        assert result.file_size == 1024 * 1024
        assert result.duration_seconds == 300

    def test_backup_result_failure(self):
        """Test backup result for failed operation."""
        result = BackupResult(
            success=False,
            error_message="Database connection failed",
        )

        assert result.success is False
        assert result.error_message == "Database connection failed"
        assert result.file_path is None
        assert result.file_size == 0


if __name__ == "__main__":
    pytest.main([__file__])
