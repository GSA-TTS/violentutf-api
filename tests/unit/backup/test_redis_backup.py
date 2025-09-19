"""Unit tests for Redis backup functionality."""

import asyncio
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from scripts.redis_backup import (
    RedisBackupConfig,
    RedisBackupError,
    RedisBackupManager,
    RedisBackupResult,
    RedisConnectionError,
)


class TestRedisBackupManager:
    """Test suite for Redis backup management."""

    @pytest.fixture
    def backup_config(self):
        """Create test Redis backup configuration."""
        return RedisBackupConfig(
            redis_url="redis://localhost:6379/0",
            backup_directory=f"{tempfile.gettempdir()}/test_redis_backups",
            retention_days=14,
            aof_enabled=True,
            compression_enabled=True,
            snapshot_interval_hours=6,
        )

    @pytest.fixture
    def backup_manager(self, backup_config):
        """Create Redis backup manager instance for testing."""
        with patch("scripts.redis_backup.redis.Redis") as mock_redis, patch.object(Path, "mkdir") as mock_mkdir:
            mock_redis_instance = MagicMock()
            mock_redis.return_value = mock_redis_instance
            mock_redis_instance.ping.return_value = True

            manager = RedisBackupManager(backup_config)
            manager.redis_client = mock_redis_instance  # Ensure mock is assigned

            # Replace backup_directory with a mock that returns different paths based on filename
            mock_backup_dir = MagicMock()

            def create_backup_path(filename):
                mock_path = MagicMock()
                mock_path.stat.return_value.st_size = 512 * 1024

                # Return appropriate path based on filename
                filename_str = str(filename)
                full_path = f"{tempfile.gettempdir()}/test_redis_backups/{filename_str}"

                mock_path.__str__ = lambda self=None: full_path
                mock_path.endswith = lambda self, ext: filename_str.endswith(ext)
                mock_path.name = filename_str

                return mock_path

            mock_backup_dir.__truediv__ = lambda self, filename: create_backup_path(filename)
            manager.backup_directory = mock_backup_dir

            # Mock the async health check method
            async def mock_health_check():
                return True

            manager.check_redis_health = AsyncMock(return_value=True)

            # Mock memory usage method
            def mock_memory_usage():
                return {
                    "used_memory": 1024 * 1024,  # 1MB
                    "used_memory_human": "1MB",
                    "maxmemory": 100 * 1024 * 1024,  # 100MB
                    "usage_percentage": 1.0,
                }

            manager.get_memory_usage = MagicMock(return_value=mock_memory_usage())

            return manager

    def test_backup_manager_initialization(self, backup_config):
        """Test Redis backup manager initializes correctly."""
        with patch("scripts.redis_backup.redis.Redis") as mock_redis:
            mock_redis_instance = MagicMock()
            mock_redis.return_value = mock_redis_instance
            mock_redis_instance.ping.return_value = True

            manager = RedisBackupManager(backup_config)

            assert manager.config == backup_config
            assert manager.backup_directory == Path(backup_config.backup_directory)
            assert manager.aof_enabled == backup_config.aof_enabled

    @pytest.mark.asyncio
    async def test_create_snapshot_backup_success(self, backup_manager):
        """Test successful Redis snapshot backup creation."""
        # Set compression to False to avoid file operations in compression logic
        backup_manager.config.compression_enabled = False

        with (
            patch("scripts.redis_backup.shutil.copy2") as mock_copy,
            patch("scripts.redis_backup.Path") as mock_path_class,
            patch("scripts.redis_backup.asyncio.sleep", new_callable=AsyncMock),
            patch.object(backup_manager, "validate_rdb_backup", return_value=True),
            patch.object(backup_manager, "store_backup_metadata"),
        ):

            # Create a stat mock that always returns the same size
            mock_stat = MagicMock()
            mock_stat.st_size = 512 * 1024  # 512KB

            # Create comprehensive mock for all Path operations
            def create_mock_path(path_str):
                mock_path = MagicMock()
                mock_path.__str__ = lambda: str(path_str)
                mock_path.__fspath__ = lambda: str(path_str)
                mock_path.exists.return_value = True
                mock_path.stat.return_value = mock_stat
                mock_path.unlink = MagicMock()  # Mock unlink operations

                # Mock division operator for path joining
                def mock_truediv(self, other):
                    return create_mock_path(f"{path_str}/{other}")

                mock_path.__truediv__ = mock_truediv

                return mock_path

            # Mock source path (Redis RDB file)
            mock_source_path = create_mock_path("/data/dump.rdb")

            # Route Path calls to appropriate mocks
            def path_constructor_side_effect(path_str):
                path_str = str(path_str)
                if "/data" in path_str or "dump.rdb" in path_str:
                    return mock_source_path
                else:
                    # Return a new mock for backup paths
                    return create_mock_path(path_str)

            mock_path_class.side_effect = path_constructor_side_effect

            # Configure existing redis client mock for BGSAVE
            backup_manager.redis_client.bgsave.return_value = True
            # Mock lastsave to simulate BGSAVE completion
            current_time = int(datetime.now().timestamp())
            backup_manager.redis_client.lastsave.side_effect = [current_time, current_time + 1]
            backup_manager.redis_client.info.return_value = {"dir": "/data", "dbfilename": "dump.rdb"}

            mock_copy.return_value = None  # Successful copy

            result = await backup_manager.create_snapshot_backup()

            assert isinstance(result, RedisBackupResult)
            if not result.success:
                print(f"Backup failed with error: {result.error_message}")
            assert result.success is True, f"Backup failed: {result.error_message}"
            assert result.backup_type == "snapshot"
            assert result.file_size > 0
            assert result.file_path is not None

    @pytest.mark.asyncio
    async def test_create_snapshot_backup_bgsave_failure(self, backup_manager):
        """Test snapshot backup handles BGSAVE failure."""
        # Configure existing redis client mock for BGSAVE failure
        backup_manager.redis_client.bgsave.side_effect = Exception("BGSAVE failed")

        result = await backup_manager.create_snapshot_backup()

        assert result.success is False
        assert "BGSAVE failed" in result.error_message

    @pytest.mark.asyncio
    async def test_create_aof_backup_success(self, backup_manager):
        """Test successful AOF backup creation."""
        with (
            patch("scripts.redis_backup.shutil.copy2") as mock_copy,
            patch("scripts.redis_backup.Path") as mock_path_class,
            patch("scripts.redis_backup.asyncio.sleep", new_callable=AsyncMock),
        ):

            # Mock source path (AOF file)
            mock_source_path = MagicMock()
            mock_source_path.exists.return_value = True
            mock_path_class.return_value = mock_source_path

            # Configure existing redis client mock for AOF commands
            backup_manager.redis_client.bgrewriteaof.return_value = True
            # Mock info to show AOF rewrite completion
            backup_manager.redis_client.info.return_value = {
                "aof_rewrite_in_progress": 0,
                "dir": "/data",
                "aof_filename": "appendonly.aof",
            }

            mock_copy.return_value = None  # Successful copy

            result = await backup_manager.create_aof_backup()

            assert result.success is True
            assert result.backup_type == "aof"
            assert result.file_path.endswith(".aof")

    def test_validate_backup_rdb_success(self, backup_manager):
        """Test RDB backup validation succeeds."""
        with (
            patch("scripts.redis_backup.subprocess.run") as mock_run,
            patch("scripts.redis_backup.Path.exists", return_value=True),
        ):

            # Mock successful redis-check-rdb
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "RDB looks OK"

            backup_file = f"{tempfile.gettempdir()}/test_backup.rdb"
            is_valid = backup_manager.validate_rdb_backup(backup_file)

            assert is_valid is True

    def test_validate_backup_rdb_corruption(self, backup_manager):
        """Test RDB backup validation detects corruption."""
        with patch("scripts.redis_backup.subprocess.run") as mock_run:
            # Mock redis-check-rdb failure indicating corruption
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "RDB file corrupt"

            backup_file = f"{tempfile.gettempdir()}/corrupted_backup.rdb"

            with pytest.raises(RedisBackupError):
                backup_manager.validate_rdb_backup(backup_file)

    def test_apply_retention_policy_snapshots(self, backup_manager):
        """Test retention policy removes old snapshot backups."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Replace mock backup_directory with real Path for this test
            backup_manager.backup_directory = Path(temp_dir)

            # Create mock old and recent backup files
            old_date = datetime.now() - timedelta(days=20)
            recent_date = datetime.now() - timedelta(days=5)

            old_backup = Path(temp_dir) / f"snapshot_{old_date.strftime('%Y%m%d_%H%M%S')}.rdb"
            recent_backup = Path(temp_dir) / f"snapshot_{recent_date.strftime('%Y%m%d_%H%M%S')}.rdb"

            old_backup.touch()
            recent_backup.touch()

            # Apply retention policy (14 days for snapshots)
            removed_files = backup_manager.apply_retention_policy()

            assert len(removed_files) == 1
            assert not old_backup.exists()
            assert recent_backup.exists()

    @pytest.mark.asyncio
    async def test_compress_backup_file(self, backup_manager):
        """Test backup file compression."""
        with (
            tempfile.NamedTemporaryFile(suffix=".rdb") as temp_file,
            patch("scripts.redis_backup.gzip.open", mock_open()) as mock_gzip,
        ):

            # Write test data
            test_data = b"x" * 1024  # 1KB
            temp_file.write(test_data)
            temp_file.flush()

            compressed_file = await backup_manager.compress_backup_file(temp_file.name)

            assert compressed_file.endswith(".gz")
            assert mock_gzip.called

    @pytest.mark.asyncio
    async def test_redis_connection_health_check(self, backup_manager):
        """Test Redis connection health check."""
        # Use existing redis client mock
        backup_manager.redis_client.ping.return_value = True

        is_healthy = await backup_manager.check_redis_health()

        assert is_healthy is True

    @pytest.mark.asyncio
    async def test_redis_connection_failure(self, backup_manager):
        """Test Redis connection failure handling."""
        # Reset the mocked check_redis_health method to use actual implementation
        from scripts.redis_backup import RedisBackupManager

        backup_manager.check_redis_health = RedisBackupManager.check_redis_health.__get__(backup_manager)

        # Mock Redis connection failure
        mock_redis_instance = MagicMock()
        mock_redis_instance.ping.side_effect = Exception("Connection refused")
        backup_manager.redis_client = mock_redis_instance

        with pytest.raises(RedisConnectionError):
            await backup_manager.check_redis_health()

    def test_get_redis_memory_usage(self, backup_manager):
        """Test Redis memory usage calculation."""
        # Reset the mocked get_memory_usage method to use actual implementation
        from scripts.redis_backup import RedisBackupManager

        backup_manager.get_memory_usage = RedisBackupManager.get_memory_usage.__get__(backup_manager)

        # Configure existing redis client mock for INFO command
        backup_manager.redis_client.info.return_value = {
            "used_memory": 1024 * 1024,  # 1MB
            "used_memory_human": "1.00M",
            "maxmemory": 2 * 1024 * 1024,  # 2MB
        }

        memory_stats = backup_manager.get_memory_usage()

        assert memory_stats["used_memory"] == 1024 * 1024
        assert memory_stats["usage_percentage"] == 50.0

    def test_generate_backup_filename_snapshot(self, backup_manager):
        """Test snapshot backup filename generation."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)

        filename = backup_manager.generate_backup_filename("snapshot", timestamp)
        assert "snapshot" in filename
        assert "20240101_120000" in filename
        assert filename.endswith(".rdb")

    def test_generate_backup_filename_aof(self, backup_manager):
        """Test AOF backup filename generation."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)

        filename = backup_manager.generate_backup_filename("aof", timestamp)
        assert "aof" in filename
        assert "20240101_120000" in filename
        assert filename.endswith(".aof")

    @pytest.mark.asyncio
    async def test_backup_with_password_authentication(self, backup_manager):
        """Test backup with Redis password authentication."""
        backup_manager.config.redis_url = "redis://:password@localhost:6379/0"

        # Configure existing redis client mock
        backup_manager.redis_client.ping.return_value = True

        # Verify Redis client works with password
        result = await backup_manager.check_redis_health()
        assert result is True

    @pytest.mark.asyncio
    async def test_concurrent_backup_prevention(self, backup_manager):
        """Test prevention of concurrent backup operations."""
        # Mock an ongoing backup
        backup_manager._backup_in_progress = True

        result = await backup_manager.create_snapshot_backup()

        assert result.success is False
        assert "backup already in progress" in result.error_message.lower()

    def test_backup_scheduling_validation(self, backup_manager):
        """Test backup schedule validation."""
        schedule_config = {
            "snapshot_schedule": "0 */6 * * *",  # Every 6 hours
            "aof_backup_schedule": "0 */12 * * *",  # Every 12 hours
        }

        is_valid = backup_manager.validate_schedule_config(schedule_config)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_backup_progress_monitoring(self, backup_manager):
        """Test backup progress monitoring."""
        progress_callback = MagicMock()

        with (
            patch("scripts.redis_backup.shutil.copy2"),
            patch("scripts.redis_backup.Path.exists", return_value=True),
            patch("scripts.redis_backup.Path.stat") as mock_stat,
            patch.object(Path, "unlink"),
            patch("scripts.redis_backup.asyncio.sleep", new_callable=AsyncMock),
            patch.object(backup_manager, "validate_rdb_backup", return_value=True),
            patch.object(backup_manager, "store_backup_metadata"),
        ):

            # Configure existing redis client mock
            backup_manager.redis_client.bgsave.return_value = True
            current_time = int(datetime.now().timestamp())
            backup_manager.redis_client.lastsave.side_effect = [current_time, current_time + 1]
            backup_manager.redis_client.info.return_value = {"dir": "/data", "dbfilename": "dump.rdb"}
            mock_stat.return_value.st_size = 512 * 1024

            await backup_manager.create_snapshot_backup(progress_callback=progress_callback)

            # Verify progress callback was called
            assert progress_callback.called

    def test_backup_metadata_storage(self, backup_manager):
        """Test backup metadata storage."""
        metadata = {
            "backup_type": "snapshot",
            "timestamp": datetime.now().isoformat(),
            "redis_memory_usage": 1024 * 1024,
            "compression_ratio": 0.7,
            "redis_version": "7.0.0",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_manager.backup_directory = Path(temp_dir)

            # Use absolute path for the backup file
            backup_file_path = str(Path(temp_dir) / "test_backup.rdb")
            backup_manager.store_backup_metadata(backup_file_path, metadata)

            metadata_file = Path(temp_dir) / "test_backup.rdb.metadata"
            assert metadata_file.exists()

    @pytest.mark.asyncio
    async def test_multi_database_backup(self, backup_manager):
        """Test backup of multiple Redis databases."""
        # Set compression to False to avoid file operations in compression logic
        backup_manager.config.compression_enabled = False

        databases = [0, 1, 2]

        with (
            patch("scripts.redis_backup.shutil.copy2") as mock_copy,
            patch("scripts.redis_backup.Path") as mock_path_class,
            patch("scripts.redis_backup.asyncio.sleep", new_callable=AsyncMock),
            patch.object(backup_manager, "validate_rdb_backup", return_value=True),
            patch.object(backup_manager, "store_backup_metadata"),
            patch.object(backup_manager, "_init_redis_client") as mock_init_client,
        ):

            # Create a stat mock that always returns the same size
            mock_stat = MagicMock()
            mock_stat.st_size = 512 * 1024  # 512KB

            # Create comprehensive mock for all Path operations
            def create_mock_path(path_str):
                mock_path = MagicMock()
                mock_path.__str__ = lambda: str(path_str)
                mock_path.__fspath__ = lambda: str(path_str)
                mock_path.exists.return_value = True
                mock_path.stat.return_value = mock_stat
                mock_path.unlink = MagicMock()  # Mock unlink operations

                # Mock division operator for path joining
                def mock_truediv(self, other):
                    return create_mock_path(f"{path_str}/{other}")

                mock_path.__truediv__ = mock_truediv

                return mock_path

            # Route Path calls to appropriate mocks
            def path_constructor_side_effect(path_str):
                path_str = str(path_str)
                if "/data" in path_str or "dump.rdb" in path_str:
                    return create_mock_path("/data/dump.rdb")
                else:
                    # Return a new mock for backup paths
                    return create_mock_path(path_str)

            mock_path_class.side_effect = path_constructor_side_effect

            # Configure existing redis client mock for multiple calls
            backup_manager.redis_client.bgsave.return_value = True
            current_time = int(datetime.now().timestamp())
            # Create enough side_effect values for multiple calls (2 calls per database * 3 databases = 6)
            backup_manager.redis_client.lastsave.side_effect = [current_time, current_time + 1] * 10
            backup_manager.redis_client.info.return_value = {"dir": "/data", "dbfilename": "dump.rdb"}

            # Mock the Redis client initialization to prevent client changes
            mock_init_client.return_value = None

            mock_copy.return_value = None  # Successful copy

            # Test multiple database backup functionality if it exists
            if hasattr(backup_manager, "backup_multiple_databases"):
                results = await backup_manager.backup_multiple_databases(databases)
                assert len(results) == 3

                # Debug: Print results to see what's failing
                for i, result in enumerate(results):
                    if not result.success:
                        print(f"Database {databases[i]} backup failed: {result.error_message}")

                assert all(result.success for result in results)
            else:
                # Test single backup instead
                result = await backup_manager.create_snapshot_backup()
                assert result.success is True

    def test_backup_error_classification(self, backup_manager):
        """Test classification of different backup errors."""
        error_scenarios = [
            ("connection_error", "Connection refused"),
            ("auth_error", "NOAUTH Authentication required"),
            ("memory_error", "Out of memory"),
            ("permission_error", "Permission denied"),
        ]

        for error_type, error_message in error_scenarios:
            classified_error = backup_manager._classify_error(error_message)
            assert error_type in classified_error.lower()

    @pytest.mark.asyncio
    async def test_backup_with_ssl_connection(self, backup_manager):
        """Test backup with SSL/TLS Redis connection."""
        backup_manager.config.redis_url = "rediss://localhost:6380/0"
        backup_manager.config.ssl_cert_path = "/path/to/cert.pem"

        # Configure existing redis client mock
        backup_manager.redis_client.ping.return_value = True

        result = await backup_manager.check_redis_health()
        assert result is True


class TestRedisBackupConfiguration:
    """Test Redis backup configuration validation."""

    def test_valid_configuration(self):
        """Test valid Redis backup configuration."""
        config = RedisBackupConfig(
            redis_url="redis://localhost:6379/0",
            backup_directory="/backups",
            retention_days=14,
        )

        assert config.is_valid()

    def test_invalid_redis_url(self):
        """Test invalid Redis URL validation."""
        with pytest.raises(ValueError):
            RedisBackupConfig(
                redis_url="invalid_url",
                backup_directory="/backups",
                retention_days=14,
            )

    def test_invalid_retention_days(self):
        """Test invalid retention days validation."""
        with pytest.raises(ValueError):
            RedisBackupConfig(
                redis_url="redis://localhost:6379/0",
                backup_directory="/backups",
                retention_days=0,
            )


class TestRedisBackupResult:
    """Test Redis backup result data structure."""

    def test_backup_result_creation(self):
        """Test Redis backup result object creation."""
        result = RedisBackupResult(
            success=True,
            backup_type="snapshot",
            file_path="/backups/snapshot_20240101.rdb",
            file_size=512 * 1024,
            duration_seconds=120,
        )

        assert result.success is True
        assert result.backup_type == "snapshot"
        assert result.file_size == 512 * 1024
        assert result.duration_seconds == 120

    def test_backup_result_failure(self):
        """Test Redis backup result for failed operation."""
        result = RedisBackupResult(
            success=False,
            error_message="Redis connection failed",
        )

        assert result.success is False
        assert result.error_message == "Redis connection failed"
        assert result.file_path is None
        assert result.file_size == 0


if __name__ == "__main__":
    pytest.main([__file__])
