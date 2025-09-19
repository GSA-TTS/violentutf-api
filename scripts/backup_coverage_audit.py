"""Backup coverage audit for all repositories and data stores."""

import csv
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CriticalityLevel(Enum):
    """Data criticality levels for backup prioritization."""

    CRITICAL = "critical"
    IMPORTANT = "important"
    STANDARD = "standard"


class ComplianceStatus(Enum):
    """Backup compliance status."""

    COMPLIANT = "compliant"
    WARNING = "warning"
    NON_COMPLIANT = "non_compliant"


@dataclass
class RepositoryInfo:
    """Information about a repository for backup auditing."""

    name: str
    table_name: str = ""
    criticality: CriticalityLevel = CriticalityLevel.STANDARD
    data_size_mb: float = 0.0
    last_backup: Optional[datetime] = None
    backup_frequency: str = "daily"
    retention_required_days: int = 30

    def is_backup_overdue(self) -> bool:
        """Check if backup is overdue based on criticality."""
        if not self.last_backup:
            return True

        now = datetime.now()
        hours_since_backup = (now - self.last_backup).total_seconds() / 3600

        # Define maximum allowed hours based on criticality
        max_hours = {
            CriticalityLevel.CRITICAL: 2,  # 2 hours
            CriticalityLevel.IMPORTANT: 8,  # 8 hours
            CriticalityLevel.STANDARD: 26,  # 26 hours (daily + buffer)
        }

        return hours_since_backup > max_hours.get(self.criticality, 26)


@dataclass
class BackupGap:
    """Represents a backup gap that needs attention."""

    repository: str
    criticality: CriticalityLevel
    gap_hours: float
    last_backup: Optional[datetime]
    severity: str = "medium"

    def __post_init__(self) -> None:
        """Calculate severity based on gap and criticality."""
        if self.criticality == CriticalityLevel.CRITICAL and self.gap_hours > 24:
            self.severity = "critical"
        elif self.criticality == CriticalityLevel.CRITICAL and self.gap_hours > 4:
            self.severity = "high"
        elif self.gap_hours > 72:  # 3 days
            self.severity = "high"
        elif self.gap_hours > 48:  # 2 days
            self.severity = "medium"
        else:
            self.severity = "low"


@dataclass
class BackupCoverageReport:
    """Comprehensive backup coverage report."""

    total_repositories: int
    compliant_repositories: int = 0
    compliance_score: float = 0.0
    backup_gaps: List[BackupGap] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    status: ComplianceStatus = ComplianceStatus.COMPLIANT
    storage_usage_gb: float = 0.0
    recommendations: List[Dict[str, str]] = field(default_factory=list)

    def determine_status(self) -> ComplianceStatus:
        """Determine overall compliance status."""
        if self.compliance_score >= 95:
            return ComplianceStatus.COMPLIANT
        elif self.compliance_score >= 80:
            return ComplianceStatus.WARNING
        else:
            return ComplianceStatus.NON_COMPLIANT


class BackupCoverageAuditor:
    """Audits backup coverage across all repositories and data stores."""

    def __init__(self) -> None:
        """Initialize backup coverage auditor."""
        self.repositories: List[RepositoryInfo] = []
        self.backup_policies = self._load_backup_policies()

    def _load_backup_policies(self) -> Dict[CriticalityLevel, Dict[str, Any]]:
        """Load backup policies configuration."""
        # Default backup policies based on data criticality
        return {
            CriticalityLevel.CRITICAL: {
                "frequency": "hourly",
                "max_age_hours": 2,
                "retention_days": 90,
                "backup_type": "incremental",
            },
            CriticalityLevel.IMPORTANT: {
                "frequency": "every_6_hours",
                "max_age_hours": 8,
                "retention_days": 30,
                "backup_type": "mixed",
            },
            CriticalityLevel.STANDARD: {
                "frequency": "daily",
                "max_age_hours": 26,
                "retention_days": 14,
                "backup_type": "full",
            },
        }

    def discover_repositories(self) -> List[RepositoryInfo]:
        """Discover all repositories from the service container."""
        repositories = []

        try:
            # Import here to avoid circular dependencies
            from app.core.container import (
                get_api_key_repository,
                get_audit_repository,
                get_container,
                get_health_repository,
                get_role_repository,
                get_security_scan_repository,
                get_session_repository,
                get_user_repository,
                get_vulnerability_repository,
            )

            # Get all repository instances
            registered_repos = {
                "user": get_user_repository(),
                "session": get_session_repository(),
                "api_key": get_api_key_repository(),
                "audit": get_audit_repository(),
                "security_scan": get_security_scan_repository(),
                "health": get_health_repository(),
                "vulnerability": get_vulnerability_repository(),
                "role": get_role_repository(),
            }

            for repo_name, repo_instance in registered_repos.items():
                if repo_instance is None:
                    continue
                # Classify repository criticality
                criticality = self.classify_repository_criticality(repo_name)

                # Get table information if available
                table_name = getattr(repo_instance, "table_name", repo_name)

                # Estimate data size (would need actual implementation)
                data_size = self._estimate_repository_size(repo_name)

                repo_info = RepositoryInfo(
                    name=repo_name,
                    table_name=table_name,
                    criticality=criticality,
                    data_size_mb=data_size,
                    last_backup=self._get_last_backup_time(repo_name),
                    backup_frequency=self._get_backup_frequency(criticality),
                    retention_required_days=self._get_retention_days(criticality),
                )

                repositories.append(repo_info)

        except Exception as e:
            logger.error(f"Failed to discover repositories: {e}")
            # Fallback to known repository list
            repositories = self._get_fallback_repositories()

        self.repositories = repositories
        return repositories

    def classify_repository_criticality(self, repo_name: str) -> CriticalityLevel:
        """Classify repository criticality based on name and function."""
        # Critical repositories - core business data
        critical_repos = [
            "user_repository",
            "audit_log_repository",
            "api_key_repository",
            "security_scan_repository",
            "vulnerability_finding_repository",
            "oauth_access_token",
            "oauth_authorization_code",
        ]

        # Important repositories - operational data
        important_repos = [
            "session_repository",
            "mfa_policy_repository",
            "role_repository",
            "mfa_device_repository",
            "mfa_challenge_repository",
        ]

        repo_lower = repo_name.lower()

        if any(critical in repo_lower for critical in critical_repos):
            return CriticalityLevel.CRITICAL
        elif any(important in repo_lower for important in important_repos):
            return CriticalityLevel.IMPORTANT
        else:
            return CriticalityLevel.STANDARD

    def analyze_backup_gaps(self, repositories: List[RepositoryInfo]) -> List[BackupGap]:
        """Analyze backup gaps across repositories."""
        gaps = []

        for repo in repositories:
            if repo.is_backup_overdue():
                gap_hours: float = 0
                if repo.last_backup:
                    gap_hours = (datetime.now() - repo.last_backup).total_seconds() / 3600
                else:
                    gap_hours = 168.0  # 1 week if never backed up

                gap = BackupGap(
                    repository=repo.name,
                    criticality=repo.criticality,
                    gap_hours=gap_hours,
                    last_backup=repo.last_backup,
                )
                gaps.append(gap)

        return gaps

    def calculate_compliance_score(self, repositories: List[RepositoryInfo]) -> float:
        """Calculate overall backup compliance score."""
        if not repositories:
            return 0.0

        compliant_count = 0
        total_weight = 0
        weighted_compliant = 0

        # Weight by criticality
        weights = {
            CriticalityLevel.CRITICAL: 3,
            CriticalityLevel.IMPORTANT: 2,
            CriticalityLevel.STANDARD: 1,
        }

        for repo in repositories:
            weight = weights.get(repo.criticality, 1)
            total_weight += weight

            if not repo.is_backup_overdue():
                compliant_count += 1
                weighted_compliant += weight

        # Calculate weighted compliance score
        if total_weight > 0:
            weighted_score = (weighted_compliant / total_weight) * 100
        else:
            weighted_score = 0

        return round(weighted_score, 2)

    def get_backup_frequency_requirements(self, criticality: CriticalityLevel) -> Dict[str, Any]:
        """Get backup frequency requirements for criticality level."""
        return self.backup_policies.get(criticality, self.backup_policies[CriticalityLevel.STANDARD])

    def generate_coverage_report(self, repositories: List[RepositoryInfo]) -> BackupCoverageReport:
        """Generate comprehensive backup coverage report."""
        gaps = self.analyze_backup_gaps(repositories)
        compliance_score = self.calculate_compliance_score(repositories)
        compliant_repos = len(repositories) - len(gaps)

        # Calculate storage usage
        storage_usage = self.calculate_backup_storage_usage()

        # Generate recommendations
        recommendations = self.generate_recommendations(repositories)

        report = BackupCoverageReport(
            total_repositories=len(repositories),
            compliant_repositories=compliant_repos,
            compliance_score=compliance_score,
            backup_gaps=gaps,
            storage_usage_gb=storage_usage.get("total_size_gb", 0),
            recommendations=recommendations,
        )

        report.status = report.determine_status()
        return report

    def optimize_backup_schedule(
        self, repositories: List[RepositoryInfo], constraints: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Optimize backup schedule based on repository characteristics."""
        if constraints is None:
            constraints = {}

        optimized_schedules = []

        for repo in repositories:
            requirements = self.get_backup_frequency_requirements(repo.criticality)

            # Base schedule on criticality and size
            if repo.criticality == CriticalityLevel.CRITICAL:
                if repo.data_size_mb > 1000:  # > 1GB
                    frequency = "every_30_minutes"
                    backup_type = "incremental"
                else:
                    frequency = "hourly"
                    backup_type = "mixed"
            elif repo.criticality == CriticalityLevel.IMPORTANT:
                frequency = "every_6_hours"
                backup_type = "mixed" if repo.data_size_mb > 500 else "full"
            else:
                frequency = "daily"
                backup_type = "full"

            # Apply resource constraints
            if constraints.get("max_concurrent_backups", 0) > 0:
                # Stagger backup times to avoid conflicts
                import hashlib

                repo_hash = int(hashlib.sha256(repo.name.encode()).hexdigest()[:8], 16)
                start_offset = repo_hash % 60  # Minutes offset
                start_time = f"{2 + (start_offset // 60):02d}:{start_offset % 60:02d}"
            else:
                start_time = "02:00"  # Default 2 AM

            schedule = {
                "repository": repo.name,
                "frequency": frequency,
                "type": backup_type,
                "start_time": start_time,
                "retention_days": requirements["retention_days"],
                "priority": repo.criticality.value,
            }

            optimized_schedules.append(schedule)

        return optimized_schedules

    def calculate_backup_storage_usage(self) -> Dict[str, Any]:
        """Calculate backup storage usage across all backup locations."""
        storage_info = {
            "total_size_gb": 0.0,
            "file_count": 0,
            "oldest_backup": None,
            "newest_backup": None,
        }

        try:
            import tempfile

            temp_dir = tempfile.gettempdir()
            backup_directories = [
                Path("./backups"),
                Path(temp_dir) / "postgres_backups",
                Path(temp_dir) / "redis_backups",
            ]

            total_size = 0
            file_count = 0
            oldest_time = None
            newest_time = None

            for backup_dir in backup_directories:
                if backup_dir.exists():
                    for backup_file in backup_dir.glob("**/*"):
                        if backup_file.is_file() and not backup_file.name.endswith(".metadata"):
                            try:
                                stat = backup_file.stat()
                                total_size += stat.st_size
                                file_count += 1

                                file_time = datetime.fromtimestamp(stat.st_mtime)
                                if oldest_time is None or file_time < oldest_time:
                                    oldest_time = file_time
                                if newest_time is None or file_time > newest_time:
                                    newest_time = file_time

                            except Exception as e:
                                logger.warning(f"Error reading file {backup_file}: {e}")

            storage_info.update(
                {
                    "total_size_gb": round(total_size / (1024**3), 2),
                    "file_count": file_count,
                    "oldest_backup": oldest_time.timestamp() if oldest_time else None,
                    "newest_backup": newest_time.timestamp() if newest_time else None,
                }
            )

        except Exception as e:
            logger.error(f"Error calculating storage usage: {e}")

        return storage_info

    def validate_retention_compliance(self, repositories: List[RepositoryInfo]) -> List[Dict[str, Any]]:
        """Validate backup retention compliance."""
        compliance_results = []

        for repo in repositories:
            requirements = self.get_backup_frequency_requirements(repo.criticality)
            required_retention = requirements["retention_days"]

            # Check actual retention (simplified - would need real backup analysis)
            actual_retention = self._get_actual_retention_days(repo.name)

            result = {
                "repository": repo.name,
                "compliant": actual_retention >= required_retention,
                "required_retention_days": required_retention,
                "current_retention_days": actual_retention,
                "gap_days": max(0, required_retention - actual_retention),
            }

            compliance_results.append(result)

        return compliance_results

    def generate_recommendations(self, repositories: List[RepositoryInfo]) -> List[Dict[str, str]]:
        """Generate backup recommendations based on analysis."""
        recommendations = []

        for repo in repositories:
            if repo.is_backup_overdue():
                if repo.criticality == CriticalityLevel.CRITICAL:
                    recommendations.append(
                        {
                            "repository": repo.name,
                            "action": "immediate_backup",
                            "reason": "Critical repository backup overdue",
                            "priority": "high",
                        }
                    )
                else:
                    recommendations.append(
                        {
                            "repository": repo.name,
                            "action": "schedule_backup",
                            "reason": "Repository backup overdue",
                            "priority": "medium",
                        }
                    )

            # Size-based recommendations
            if repo.data_size_mb > 2000:  # > 2GB
                recommendations.append(
                    {
                        "repository": repo.name,
                        "action": "increase_frequency",
                        "reason": "Large repository should have more frequent incremental backups",
                        "priority": "medium",
                    }
                )

        return recommendations

    def prioritize_backup_gaps(self, gaps: List[BackupGap]) -> List[BackupGap]:
        """Prioritize backup gaps by criticality and severity."""

        def gap_priority(gap: BackupGap) -> Tuple[int, int, float]:
            # Priority by: criticality (lower is higher priority), severity, gap hours
            criticality_order = {
                CriticalityLevel.CRITICAL: 0,
                CriticalityLevel.IMPORTANT: 1,
                CriticalityLevel.STANDARD: 2,
            }

            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
            }

            return (criticality_order.get(gap.criticality, 3), severity_order.get(gap.severity, 4), gap.gap_hours)

        return sorted(gaps, key=gap_priority)

    def export_report_json(self, report: BackupCoverageReport) -> Dict[str, Any]:
        """Export report to JSON format."""
        return {
            "timestamp": report.timestamp.isoformat(),
            "total_repositories": report.total_repositories,
            "compliant_repositories": report.compliant_repositories,
            "compliance_score": report.compliance_score,
            "status": report.status.value,
            "storage_usage_gb": report.storage_usage_gb,
            "backup_gaps": [
                {
                    "repository": gap.repository,
                    "criticality": gap.criticality.value,
                    "gap_hours": gap.gap_hours,
                    "severity": gap.severity,
                    "last_backup": gap.last_backup.isoformat() if gap.last_backup else None,
                }
                for gap in report.backup_gaps
            ],
            "recommendations": report.recommendations,
        }

    def export_report_csv(self, report: BackupCoverageReport) -> str:
        """Export report to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(["Repository Name", "Criticality", "Gap Hours", "Severity", "Last Backup", "Status"])

        # Data rows
        for gap in report.backup_gaps:
            writer.writerow(
                [
                    gap.repository,
                    gap.criticality.value,
                    gap.gap_hours,
                    gap.severity,
                    gap.last_backup.isoformat() if gap.last_backup else "Never",
                    "Non-Compliant",
                ]
            )

        return output.getvalue()

    def get_historical_compliance(self) -> List[Dict[str, Any]]:
        """Get historical compliance data."""
        # Simplified - would read from stored historical data
        history_file = Path("./reports/compliance_history.json")

        if history_file.exists():
            try:
                with open(history_file, "r") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except Exception as e:
                logger.error(f"Error reading compliance history: {e}")

        return []

    def calculate_compliance_trend(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance trend from historical data."""
        if len(historical_data) < 2:
            return {"direction": "unknown", "change_percentage": 0}

        recent_score = historical_data[-1]["compliance_score"]
        previous_score = historical_data[-2]["compliance_score"]

        change = recent_score - previous_score
        change_percentage = (change / previous_score) * 100 if previous_score > 0 else 0

        direction = "improving" if change > 0 else "declining" if change < 0 else "stable"

        return {
            "direction": direction,
            "change_percentage": round(change_percentage, 2),
            "recent_score": recent_score,
            "previous_score": previous_score,
        }

    def _get_fallback_repositories(self) -> List[RepositoryInfo]:
        """Get fallback repository list when discovery fails."""
        # Known repositories from the ViolentUTF system
        known_repos = [
            "user_repository",
            "audit_log_repository",
            "api_key_repository",
            "session_repository",
            "role_repository",
            "mfa_policy_repository",
            "security_scan_repository",
            "vulnerability_finding_repository",
            "oauth_access_token",
            "template_repository",
        ]

        repositories = []
        for repo_name in known_repos:
            criticality = self.classify_repository_criticality(repo_name)
            repositories.append(
                RepositoryInfo(
                    name=repo_name,
                    criticality=criticality,
                    last_backup=datetime.now() - timedelta(hours=1),  # Assume recent backup
                )
            )

        return repositories

    def _estimate_repository_size(self, repo_name: str) -> float:
        """Estimate repository size in MB."""
        # Simplified estimation based on repository type
        size_estimates = {
            "audit_log": 500,  # Large due to logging volume
            "user": 100,
            "session": 50,
            "security_scan": 200,
            "vulnerability_finding": 150,
        }

        for key, size in size_estimates.items():
            if key in repo_name.lower():
                return size

        return 25  # Default size estimate

    def _get_last_backup_time(self, repo_name: str) -> Optional[datetime]:
        """Get last backup time for repository."""
        # Simplified - would check actual backup metadata
        # For demo, assume recent backups
        return datetime.now() - timedelta(hours=2)

    def _get_backup_frequency(self, criticality: CriticalityLevel) -> str:
        """Get backup frequency for criticality level."""
        frequency = self.backup_policies[criticality]["frequency"]
        return str(frequency) if frequency is not None else "daily"

    def _get_retention_days(self, criticality: CriticalityLevel) -> int:
        """Get retention days for criticality level."""
        retention = self.backup_policies[criticality]["retention_days"]
        return int(retention) if isinstance(retention, (int, float)) else 30

    def _get_actual_retention_days(self, repo_name: str) -> int:
        """Get actual retention days for repository."""
        # Simplified - would analyze actual backup files
        return 30  # Default


async def main() -> None:
    """Main function for testing backup coverage audit."""
    auditor = BackupCoverageAuditor()

    # Discover repositories
    print("Discovering repositories...")
    repositories = auditor.discover_repositories()
    print(f"Found {len(repositories)} repositories")

    # Generate coverage report
    print("Generating coverage report...")
    report = auditor.generate_coverage_report(repositories)

    print(f"Compliance Score: {report.compliance_score}%")
    print(f"Status: {report.status.value}")
    print(f"Backup Gaps: {len(report.backup_gaps)}")
    print(f"Storage Usage: {report.storage_usage_gb} GB")

    # Export report
    json_report = auditor.export_report_json(report)
    import os
    import tempfile

    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix="_backup_coverage_report.json", delete=False)
    with temp_file as f:
        json.dump(json_report, f, indent=2)

    print(f"Report exported to {temp_file.name}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
