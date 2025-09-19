"""Backup monitoring service for integration with health check framework."""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from structlog.stdlib import get_logger

# Configure logging
logger = get_logger(__name__)


@dataclass
class BackupStatus:
    """Backup status information."""

    backup_type: str
    last_backup_time: Optional[datetime]
    file_path: str
    file_size_mb: float
    success: bool
    age_hours: float
    next_scheduled: Optional[datetime] = None


@dataclass
class BackupHealthResult:
    """Result of backup health check."""

    overall_status: str  # healthy, warning, critical
    postgres_status: BackupStatus
    redis_status: BackupStatus
    backup_storage_usage_gb: float
    alerts: List[str]
    recommendations: List[str]
    last_check_time: datetime


class BackupMonitoringService:
    """Service for monitoring backup operations and integration with health checks."""

    def __init__(self):
        """Initialize backup monitoring service."""
        self.backup_directories = {
            "postgres": Path("./backups/postgres"),
            "redis": Path("./backups/redis"),
        }
        self.alert_thresholds = {
            "critical_backup_age_hours": 25,  # Critical alert if backup older than 25 hours
            "warning_backup_age_hours": 13,  # Warning if backup older than 13 hours
            "storage_warning_gb": 50,  # Warning if backup storage > 50GB
            "storage_critical_gb": 100,  # Critical if backup storage > 100GB
        }

    async def check_backup_health(self) -> BackupHealthResult:
        """Perform comprehensive backup health check."""
        try:
            # Check PostgreSQL backup status
            postgres_status = await self._check_postgres_backup_status()

            # Check Redis backup status
            redis_status = await self._check_redis_backup_status()

            # Calculate storage usage
            storage_usage = await self._calculate_storage_usage()

            # Generate alerts and recommendations
            alerts = self._generate_alerts(postgres_status, redis_status, storage_usage)
            recommendations = self._generate_recommendations(postgres_status, redis_status, storage_usage)

            # Determine overall status
            overall_status = self._determine_overall_status(postgres_status, redis_status, alerts)

            return BackupHealthResult(
                overall_status=overall_status,
                postgres_status=postgres_status,
                redis_status=redis_status,
                backup_storage_usage_gb=storage_usage,
                alerts=alerts,
                recommendations=recommendations,
                last_check_time=datetime.now(),
            )

        except Exception as e:
            logger.error("Backup health check failed", error=str(e), exc_info=True)

            # Return error state
            return BackupHealthResult(
                overall_status="error",
                postgres_status=BackupStatus("unknown", None, "", 0, False, 999),
                redis_status=BackupStatus("unknown", None, "", 0, False, 999),
                backup_storage_usage_gb=0,
                alerts=["Backup health check service error"],
                recommendations=["Check backup monitoring service logs"],
                last_check_time=datetime.now(),
            )

    async def _check_postgres_backup_status(self) -> BackupStatus:
        """Check PostgreSQL backup status."""
        try:
            backup_dir = self.backup_directories["postgres"]

            if not backup_dir.exists():
                return BackupStatus(
                    backup_type="postgres",
                    last_backup_time=None,
                    file_path="",
                    file_size_mb=0,
                    success=False,
                    age_hours=999,
                )

            # Find most recent backup file
            backup_patterns = ["backup_full_*.sql.gz", "backup_full_*.sql.gpg", "backup_full_*.sql"]
            latest_backup = None
            latest_time = None

            for pattern in backup_patterns:
                for backup_file in backup_dir.glob(pattern):
                    try:
                        # Extract timestamp from filename
                        timestamp_str = backup_file.stem.split("_")[2]  # backup_full_TIMESTAMP
                        if timestamp_str.endswith(".sql"):
                            timestamp_str = timestamp_str[:-4]

                        file_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                        if latest_time is None or file_time > latest_time:
                            latest_backup = backup_file
                            latest_time = file_time

                    except (ValueError, IndexError) as e:
                        logger.warning(f"Could not parse timestamp from {backup_file}: {e}")
                        continue

            if latest_backup and latest_time:
                file_size_mb = latest_backup.stat().st_size / (1024 * 1024)
                age_hours = (datetime.now() - latest_time).total_seconds() / 3600

                # Check if backup is valid by looking for metadata
                metadata_file = latest_backup.with_suffix(latest_backup.suffix + ".metadata")
                success = metadata_file.exists()

                return BackupStatus(
                    backup_type="postgres",
                    last_backup_time=latest_time,
                    file_path=str(latest_backup),
                    file_size_mb=file_size_mb,
                    success=success,
                    age_hours=age_hours,
                )
            else:
                return BackupStatus(
                    backup_type="postgres",
                    last_backup_time=None,
                    file_path="",
                    file_size_mb=0,
                    success=False,
                    age_hours=999,
                )

        except Exception as e:
            logger.error(f"Error checking PostgreSQL backup status: {e}")
            return BackupStatus(
                backup_type="postgres",
                last_backup_time=None,
                file_path="",
                file_size_mb=0,
                success=False,
                age_hours=999,
            )

    async def _check_redis_backup_status(self) -> BackupStatus:
        """Check Redis backup status."""
        try:
            backup_dir = self.backup_directories["redis"]

            if not backup_dir.exists():
                return BackupStatus(
                    backup_type="redis",
                    last_backup_time=None,
                    file_path="",
                    file_size_mb=0,
                    success=False,
                    age_hours=999,
                )

            # Find most recent snapshot backup
            backup_patterns = ["snapshot_*.rdb.gz", "snapshot_*.rdb"]
            latest_backup = None
            latest_time = None

            for pattern in backup_patterns:
                for backup_file in backup_dir.glob(pattern):
                    try:
                        # Extract timestamp from filename
                        timestamp_str = backup_file.stem.split("_")[1]  # snapshot_TIMESTAMP
                        if timestamp_str.endswith(".rdb"):
                            timestamp_str = timestamp_str[:-4]

                        file_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                        if latest_time is None or file_time > latest_time:
                            latest_backup = backup_file
                            latest_time = file_time

                    except (ValueError, IndexError) as e:
                        logger.warning(f"Could not parse timestamp from {backup_file}: {e}")
                        continue

            if latest_backup and latest_time:
                file_size_mb = latest_backup.stat().st_size / (1024 * 1024)
                age_hours = (datetime.now() - latest_time).total_seconds() / 3600

                # Check if backup is valid by looking for metadata
                metadata_file = latest_backup.with_suffix(latest_backup.suffix + ".metadata")
                success = metadata_file.exists()

                return BackupStatus(
                    backup_type="redis",
                    last_backup_time=latest_time,
                    file_path=str(latest_backup),
                    file_size_mb=file_size_mb,
                    success=success,
                    age_hours=age_hours,
                )
            else:
                return BackupStatus(
                    backup_type="redis",
                    last_backup_time=None,
                    file_path="",
                    file_size_mb=0,
                    success=False,
                    age_hours=999,
                )

        except Exception as e:
            logger.error(f"Error checking Redis backup status: {e}")
            return BackupStatus(
                backup_type="redis",
                last_backup_time=None,
                file_path="",
                file_size_mb=0,
                success=False,
                age_hours=999,
            )

    async def _calculate_storage_usage(self) -> float:
        """Calculate total backup storage usage in GB."""
        total_size = 0

        try:
            for backup_dir in self.backup_directories.values():
                if backup_dir.exists():
                    for backup_file in backup_dir.rglob("*"):
                        if backup_file.is_file() and not backup_file.name.endswith(".metadata"):
                            total_size += backup_file.stat().st_size

            return total_size / (1024**3)  # Convert to GB

        except Exception as e:
            logger.error(f"Error calculating storage usage: {e}")
            return 0.0

    def _generate_alerts(
        self, postgres_status: BackupStatus, redis_status: BackupStatus, storage_usage: float
    ) -> List[str]:
        """Generate alerts based on backup status."""
        alerts = []

        # Check PostgreSQL backup age
        if postgres_status.age_hours > self.alert_thresholds["critical_backup_age_hours"]:
            alerts.append(f"CRITICAL: PostgreSQL backup is {postgres_status.age_hours:.1f} hours old")
        elif postgres_status.age_hours > self.alert_thresholds["warning_backup_age_hours"]:
            alerts.append(f"WARNING: PostgreSQL backup is {postgres_status.age_hours:.1f} hours old")

        # Check Redis backup age
        if redis_status.age_hours > self.alert_thresholds["critical_backup_age_hours"]:
            alerts.append(f"CRITICAL: Redis backup is {redis_status.age_hours:.1f} hours old")
        elif redis_status.age_hours > self.alert_thresholds["warning_backup_age_hours"]:
            alerts.append(f"WARNING: Redis backup is {redis_status.age_hours:.1f} hours old")

        # Check backup success status
        if not postgres_status.success and postgres_status.last_backup_time:
            alerts.append("CRITICAL: Last PostgreSQL backup failed validation")

        if not redis_status.success and redis_status.last_backup_time:
            alerts.append("CRITICAL: Last Redis backup failed validation")

        # Check if no backups exist
        if postgres_status.last_backup_time is None:
            alerts.append("CRITICAL: No PostgreSQL backups found")

        if redis_status.last_backup_time is None:
            alerts.append("CRITICAL: No Redis backups found")

        # Check storage usage
        if storage_usage > self.alert_thresholds["storage_critical_gb"]:
            alerts.append(f"CRITICAL: Backup storage usage {storage_usage:.1f}GB exceeds critical threshold")
        elif storage_usage > self.alert_thresholds["storage_warning_gb"]:
            alerts.append(f"WARNING: Backup storage usage {storage_usage:.1f}GB exceeds warning threshold")

        return alerts

    def _generate_recommendations(
        self, postgres_status: BackupStatus, redis_status: BackupStatus, storage_usage: float
    ) -> List[str]:
        """Generate recommendations based on backup analysis."""
        recommendations = []

        # Age-based recommendations
        if postgres_status.age_hours > 24:
            recommendations.append("Schedule immediate PostgreSQL backup")

        if redis_status.age_hours > 24:
            recommendations.append("Schedule immediate Redis backup")

        # Size-based recommendations
        if postgres_status.file_size_mb > 1000:  # > 1GB
            recommendations.append("Consider PostgreSQL incremental backup strategy for large database")

        # Storage optimization
        if storage_usage > 20:  # > 20GB
            recommendations.append("Review backup retention policy to optimize storage usage")

        # General recommendations
        if not any(status.success for status in [postgres_status, redis_status]):
            recommendations.append("Verify backup automation scripts and schedules")

        return recommendations

    def _determine_overall_status(
        self, postgres_status: BackupStatus, redis_status: BackupStatus, alerts: List[str]
    ) -> str:
        """Determine overall backup health status."""
        critical_alerts = [alert for alert in alerts if alert.startswith("CRITICAL")]
        warning_alerts = [alert for alert in alerts if alert.startswith("WARNING")]

        if critical_alerts:
            return "critical"
        elif warning_alerts:
            return "warning"
        elif postgres_status.success and redis_status.success:
            return "healthy"
        else:
            return "warning"

    async def get_backup_coverage_summary(self) -> Dict[str, Any]:
        """Get backup coverage summary for reporting."""
        try:
            # Import backup coverage auditor
            from scripts.backup_coverage_audit import BackupCoverageAuditor

            auditor = BackupCoverageAuditor()
            repositories = auditor.discover_repositories()
            report = auditor.generate_coverage_report(repositories)

            return {
                "total_repositories": report.total_repositories,
                "compliant_repositories": report.compliant_repositories,
                "compliance_score": report.compliance_score,
                "status": report.status.value,
                "backup_gaps_count": len(report.backup_gaps),
                "storage_usage_gb": report.storage_usage_gb,
            }

        except Exception as e:
            logger.error(f"Error getting backup coverage summary: {e}")
            return {
                "total_repositories": 0,
                "compliant_repositories": 0,
                "compliance_score": 0,
                "status": "error",
                "backup_gaps_count": 0,
                "storage_usage_gb": 0,
            }

    async def validate_backup_integrity(self) -> Dict[str, Any]:
        """Validate backup file integrity."""
        integrity_results = {}

        try:
            # Check PostgreSQL backup integrity
            postgres_status = await self._check_postgres_backup_status()
            if postgres_status.file_path:
                integrity_results["postgres"] = await self._validate_postgres_file(postgres_status.file_path)
            else:
                integrity_results["postgres"] = {"valid": False, "error": "No backup file found"}

            # Check Redis backup integrity
            redis_status = await self._check_redis_backup_status()
            if redis_status.file_path:
                integrity_results["redis"] = await self._validate_redis_file(redis_status.file_path)
            else:
                integrity_results["redis"] = {"valid": False, "error": "No backup file found"}

        except Exception as e:
            logger.error(f"Error validating backup integrity: {e}")
            integrity_results = {
                "postgres": {"valid": False, "error": str(e)},
                "redis": {"valid": False, "error": str(e)},
            }

        return integrity_results

    async def _validate_postgres_file(self, file_path: str) -> Dict[str, Any]:
        """Validate PostgreSQL backup file integrity."""
        try:
            # Import PostgreSQL backup manager for validation
            from scripts.postgres_backup import BackupConfig, PostgresBackupManager

            # Create temporary config for validation
            config = BackupConfig(
                database_url="postgresql://test:test@localhost:5432/test",
                backup_directory=str(Path(file_path).parent),
            )
            manager = PostgresBackupManager(config)

            # Validate backup integrity
            is_valid = manager.validate_backup_integrity(file_path)

            return {
                "valid": is_valid,
                "file_path": file_path,
                "validation_method": "pg_restore --list",
            }

        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "file_path": file_path,
            }

    async def _validate_redis_file(self, file_path: str) -> Dict[str, Any]:
        """Validate Redis backup file integrity."""
        try:
            # Import Redis backup manager for validation
            from scripts.redis_backup import RedisBackupConfig, RedisBackupManager

            # Create temporary config for validation
            config = RedisBackupConfig(
                redis_url="redis://localhost:6379/0",
                backup_directory=str(Path(file_path).parent),
            )
            manager = RedisBackupManager(config)

            # Validate backup integrity
            is_valid = manager.validate_rdb_backup(file_path)

            return {
                "valid": is_valid,
                "file_path": file_path,
                "validation_method": "redis-check-rdb",
            }

        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "file_path": file_path,
            }

    async def get_backup_schedule_status(self) -> Dict[str, Any]:
        """Get backup schedule status and next scheduled times."""
        try:
            # This would integrate with actual scheduling system
            # For now, provide estimated next backup times

            now = datetime.now()

            # Estimate next backup times based on typical schedules
            next_postgres_full = now.replace(hour=2, minute=0, second=0) + timedelta(days=1)
            if now.hour >= 2:  # If past 2 AM today, schedule for tomorrow
                next_postgres_full += timedelta(days=1)

            next_redis_snapshot = now.replace(minute=0, second=0) + timedelta(hours=6)

            return {
                "postgres_full_backup": {
                    "next_scheduled": next_postgres_full.isoformat(),
                    "frequency": "daily",
                    "last_run_status": "success",  # Would check actual status
                },
                "redis_snapshot": {
                    "next_scheduled": next_redis_snapshot.isoformat(),
                    "frequency": "every_6_hours",
                    "last_run_status": "success",  # Would check actual status
                },
                "schedule_active": True,
            }

        except Exception as e:
            logger.error(f"Error getting backup schedule status: {e}")
            return {
                "schedule_active": False,
                "error": str(e),
            }


# Integration function for health service
async def get_backup_health() -> Dict[str, Any]:
    """Get backup health status for integration with main health service."""
    try:
        monitoring_service = BackupMonitoringService()
        health_result = await monitoring_service.check_backup_health()

        return {
            "status": health_result.overall_status,
            "postgres_backup_age_hours": health_result.postgres_status.age_hours,
            "redis_backup_age_hours": health_result.redis_status.age_hours,
            "storage_usage_gb": health_result.backup_storage_usage_gb,
            "alerts_count": len(health_result.alerts),
            "last_check": health_result.last_check_time.isoformat(),
            "details": {
                "postgres": {
                    "last_backup": (
                        health_result.postgres_status.last_backup_time.isoformat()
                        if health_result.postgres_status.last_backup_time
                        else None
                    ),
                    "success": health_result.postgres_status.success,
                    "file_size_mb": health_result.postgres_status.file_size_mb,
                },
                "redis": {
                    "last_backup": (
                        health_result.redis_status.last_backup_time.isoformat()
                        if health_result.redis_status.last_backup_time
                        else None
                    ),
                    "success": health_result.redis_status.success,
                    "file_size_mb": health_result.redis_status.file_size_mb,
                },
                "alerts": health_result.alerts[:5],  # Limit to first 5 alerts
            },
        }

    except Exception as e:
        logger.error("Backup health check failed", error=str(e), exc_info=True)
        return {
            "status": "error",
            "error": "Backup health check service error",
            "last_check": datetime.now().isoformat(),
        }
