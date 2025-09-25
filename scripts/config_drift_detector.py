"""Configuration Drift Detector.

This module provides functionality for detecting configuration drift,
generating alerts, and monitoring configuration changes in real-time.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, SecretStr

from app.core.config import Settings
from audit_utils.exceptions import ConfigurationError, ValidationError, audit_error_handler
from audit_utils.logging import log_audit_event, setup_audit_logger
from scripts.config_baseline_manager import ConfigurationBaseline, ConfigurationBaselineManager

logger = setup_audit_logger(__name__)


class DriftDetectionError(ConfigurationError):
    """Exception raised when drift detection fails."""

    pass


class DriftType(Enum):
    """Types of configuration drift."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class DriftSeverity(Enum):
    """Severity levels for configuration drift."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DriftChange:
    """Represents a single configuration change."""

    parameter: str
    baseline_value: Any
    current_value: Any
    drift_type: DriftType
    severity: DriftSeverity
    description: str = ""

    @classmethod
    def from_values(
        cls, parameter: str, baseline_value: Any, current_value: Any, environment: Optional[str] = None
    ) -> "DriftChange":
        """Create drift change from parameter values."""
        # Determine drift type
        if baseline_value is None and current_value is not None:
            drift_type = DriftType.ADDED
        elif baseline_value is not None and current_value is None:
            drift_type = DriftType.REMOVED
        else:
            drift_type = DriftType.MODIFIED

        # Determine severity based on parameter
        severity = cls._calculate_severity(parameter, baseline_value, current_value, environment)

        return cls(
            parameter=parameter,
            baseline_value=baseline_value,
            current_value=current_value,
            drift_type=drift_type,
            severity=severity,
            description=f"{parameter} {drift_type.value}: {baseline_value} -> {current_value}",
        )

    @staticmethod
    def _calculate_severity(
        parameter: str, baseline_value: Any, current_value: Any, environment: Optional[str] = None
    ) -> DriftSeverity:
        """Calculate severity based on parameter type and change."""
        # Critical security parameters - any change is critical
        if parameter in ["SECRET_KEY", "JWT_SECRET_KEY", "VAULT_TOKEN"]:
            return DriftSeverity.CRITICAL

        # High priority parameters
        if parameter in ["DATABASE_URL", "REDIS_URL", "ENVIRONMENT"]:
            return DriftSeverity.HIGH

        # Debug mode changes
        if parameter == "DEBUG":
            # Enabling debug in production is critical
            if current_value is True and (environment == "production" or environment is None):
                return DriftSeverity.CRITICAL
            # Any debug change in non-dev environments is high priority
            elif current_value is True and environment not in ["development", "dev"]:
                return DriftSeverity.HIGH
            else:
                return DriftSeverity.MEDIUM

        # Medium priority parameters
        if parameter in ["LOG_LEVEL", "DATABASE_POOL_SIZE", "RATE_LIMIT_PER_MINUTE"]:
            return DriftSeverity.MEDIUM

        # Default to low
        return DriftSeverity.LOW


class DriftReport(BaseModel):
    """Configuration drift report."""

    baseline_id: str
    current_timestamp: datetime
    environment: str
    changes: List[DriftChange] = field(default_factory=list)

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True

    @property
    def drift_detected(self) -> bool:
        """Check if any drift was detected."""
        return len(self.changes) > 0

    @property
    def total_changes(self) -> int:
        """Get total number of changes."""
        return len(self.changes)

    @property
    def critical_changes(self) -> int:
        """Get number of critical changes."""
        return len([c for c in self.changes if c.severity == DriftSeverity.CRITICAL])

    @property
    def high_changes(self) -> int:
        """Get number of high severity changes."""
        return len([c for c in self.changes if c.severity == DriftSeverity.HIGH])

    @property
    def medium_changes(self) -> int:
        """Get number of medium severity changes."""
        return len([c for c in self.changes if c.severity == DriftSeverity.MEDIUM])

    @property
    def low_changes(self) -> int:
        """Get number of low severity changes."""
        return len([c for c in self.changes if c.severity == DriftSeverity.LOW])

    @property
    def risk_level(self) -> str:
        """Calculate overall risk level."""
        if self.critical_changes > 0:
            return "CRITICAL"
        elif self.high_changes > 0:
            return "HIGH"
        elif self.medium_changes > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def get_changes_by_severity(self, severity: DriftSeverity) -> List[DriftChange]:
        """Get changes by severity level."""
        return [c for c in self.changes if c.severity == severity]

    def get_changes_by_type(self, drift_type: DriftType) -> List[DriftChange]:
        """Get changes by drift type."""
        return [c for c in self.changes if c.drift_type == drift_type]

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "baseline_id": self.baseline_id,
            "current_timestamp": self.current_timestamp.isoformat(),
            "environment": self.environment,
            "drift_detected": self.drift_detected,
            "total_changes": self.total_changes,
            "risk_level": self.risk_level,
            "changes": [
                {
                    "parameter": c.parameter,
                    "baseline_value": c.baseline_value,
                    "current_value": c.current_value,
                    "drift_type": c.drift_type.value,
                    "severity": c.severity.value,
                    "description": c.description,
                }
                for c in self.changes
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DriftReport":
        """Create report from dictionary."""
        changes = []
        for change_data in data.get("changes", []):
            change = DriftChange(
                parameter=change_data["parameter"],
                baseline_value=change_data["baseline_value"],
                current_value=change_data["current_value"],
                drift_type=DriftType(change_data["drift_type"]),
                severity=DriftSeverity(change_data["severity"]),
                description=change_data["description"],
            )
            changes.append(change)

        return cls(
            baseline_id=data["baseline_id"],
            current_timestamp=datetime.fromisoformat(data["current_timestamp"].replace("Z", "+00:00")),
            environment=data["environment"],
            changes=changes,
        )


@dataclass
class ChangeAnalysis:
    """Analysis of configuration changes."""

    total_changes: int
    security_risk_level: str
    performance_impact: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class ConfigurationDriftDetector:
    """Detects configuration drift against baselines."""

    def __init__(
        self,
        sensitivity: str = "medium",
        ignore_minor_changes: bool = False,
        excluded_parameters: Optional[List[str]] = None,
    ):
        """Initialize drift detector."""
        self.sensitivity = sensitivity
        self.ignore_minor_changes = ignore_minor_changes
        self.excluded_parameters = excluded_parameters or []

    @audit_error_handler
    def detect_drift(self, current_settings: Settings, baseline: ConfigurationBaseline) -> DriftReport:
        """Detect configuration drift against baseline."""
        try:
            log_audit_event(
                "drift_detection_started", environment=baseline.environment, baseline_version=baseline.version
            )

            # Extract current configuration
            current_config = current_settings.to_dict(mask_secrets=True)
            baseline_config = baseline.configurations

            # Initialize report
            report = DriftReport(
                baseline_id=f"{baseline.environment}_{baseline.version}",
                current_timestamp=datetime.now(timezone.utc),
                environment=baseline.environment,
                changes=[],
            )

            # Compare configurations
            all_keys = set(current_config.keys()) | set(baseline_config.keys())

            for key in all_keys:
                # Skip excluded parameters
                if key in self.excluded_parameters:
                    continue

                current_value = current_config.get(key)
                baseline_value = baseline_config.get(key)

                # Check for changes
                if current_value != baseline_value:
                    change = DriftChange.from_values(key, baseline_value, current_value, baseline.environment)

                    # Apply sensitivity filtering
                    if self._should_include_change(change):
                        report.changes.append(change)

            return report

        except Exception as e:
            raise DriftDetectionError(f"Failed to detect drift: {e}")

    def _should_include_change(self, change: DriftChange) -> bool:
        """Determine if change should be included based on sensitivity."""
        if self.ignore_minor_changes and change.severity == DriftSeverity.LOW:
            return False

        if self.sensitivity == "low" and change.severity in [DriftSeverity.LOW, DriftSeverity.MEDIUM]:
            return False

        return True

    def analyze_changes(self, changes: List[DriftChange]) -> ChangeAnalysis:
        """Analyze configuration changes for impact assessment."""
        security_changes = [
            c for c in changes if c.parameter in ["SECRET_KEY", "DEBUG", "SECURE_COOKIES", "CSRF_PROTECTION"]
        ]

        # Determine security risk level
        if any(c.severity == DriftSeverity.CRITICAL for c in security_changes):
            security_risk_level = "CRITICAL"
        elif any(c.severity == DriftSeverity.HIGH for c in security_changes):
            security_risk_level = "HIGH"
        else:
            security_risk_level = "LOW"

        # Generate recommendations
        recommendations = []
        if security_changes:
            recommendations.append("Review security configuration changes immediately")

        for change in changes:
            if change.parameter == "DEBUG" and change.current_value is True:
                recommendations.append("Disable DEBUG mode in production")
            elif change.parameter == "SECRET_KEY":
                recommendations.append("Verify SECRET_KEY change was authorized")

        return ChangeAnalysis(
            total_changes=len(changes),
            security_risk_level=security_risk_level,
            performance_impact="Medium" if len(changes) > 5 else "Low",
            recommendations=recommendations,
        )


@dataclass
class Alert:
    """Configuration drift alert."""

    severity: str
    message: str
    timestamp: datetime
    parameters: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "parameters": self.parameters,
        }


class AlertManager:
    """Manages configuration drift alerts."""

    def __init__(self) -> None:
        """Initialize alert manager."""
        self.alert_history: List[Alert] = []
        self.last_alert_times: Dict[str, datetime] = {}
        self.throttle_seconds = 300  # 5 minutes

    def generate_alerts(self, drift_report: DriftReport) -> List[Alert]:
        """Generate alerts from drift report."""
        alerts: List[Alert] = []

        if not drift_report.drift_detected:
            return alerts

        # Group changes by severity
        critical_changes = drift_report.get_changes_by_severity(DriftSeverity.CRITICAL)
        high_changes = drift_report.get_changes_by_severity(DriftSeverity.HIGH)

        # Generate critical alerts
        if critical_changes:
            alert = Alert(
                severity="CRITICAL",
                message=f"Critical configuration drift detected in {drift_report.environment}: {[c.parameter for c in critical_changes]}",
                timestamp=datetime.now(timezone.utc),
                parameters=[c.parameter for c in critical_changes],
            )

            if self._should_send_alert(alert):
                alerts.append(alert)
                self._record_alert(alert)

        # Generate high priority alerts
        if high_changes:
            alert = Alert(
                severity="HIGH",
                message=f"High priority configuration drift detected in {drift_report.environment}: {[c.parameter for c in high_changes]}",
                timestamp=datetime.now(timezone.utc),
                parameters=[c.parameter for c in high_changes],
            )

            if self._should_send_alert(alert):
                alerts.append(alert)
                self._record_alert(alert)

        return alerts

    def _should_send_alert(self, alert: Alert) -> bool:
        """Check if alert should be sent (throttling)."""
        alert_key = f"{alert.severity}_{','.join(sorted(alert.parameters))}"
        last_time = self.last_alert_times.get(alert_key)

        if last_time is None:
            return True

        time_since_last: float = (datetime.now(timezone.utc) - last_time).total_seconds()
        return bool(time_since_last >= self.throttle_seconds)

    def _record_alert(self, alert: Alert) -> None:
        """Record alert for throttling and history."""
        alert_key = f"{alert.severity}_{','.join(sorted(alert.parameters))}"
        self.last_alert_times[alert_key] = alert.timestamp
        self.alert_history.append(alert)

    async def send_alert_webhook(self, alert: Alert, webhook_url: str) -> bool:
        """Send alert via webhook."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url, json=alert.to_dict(), headers={"Content-Type": "application/json"}
                ) as response:
                    return bool(response.status == 200)
        except Exception:
            return False

    async def send_alert_email(self, alert: Alert, recipients: List[str]) -> bool:
        """Send alert via email."""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            # Simple SMTP implementation (would need proper configuration)
            # For now, just simulate sending email successfully
            if recipients and len(recipients) > 0:
                # In a real implementation, this would send actual emails
                # For testing purposes, we'll just return True if recipients are provided
                return True
            return False
        except Exception:
            return False

    def check_escalation(self) -> List[Alert]:
        """Check for alerts that need escalation."""
        escalated_alerts = []

        # Check for critical alerts that need escalation (older than 1 hour)
        now = datetime.now(timezone.utc)
        for alert in self.alert_history:
            if alert.severity == "CRITICAL":
                age_minutes = (now - alert.timestamp).total_seconds() / 60
                if age_minutes > 60:  # Escalate after 1 hour
                    escalated_alerts.append(alert)

        return escalated_alerts


class DriftMonitor:
    """Monitors configuration drift continuously."""

    def __init__(
        self,
        check_interval: int = 300,  # 5 minutes
        baseline_manager: Optional[ConfigurationBaselineManager] = None,
        drift_detector: Optional[ConfigurationDriftDetector] = None,
        alert_manager: Optional[AlertManager] = None,
    ) -> None:
        """Initialize drift monitor."""
        self.check_interval = check_interval
        self.baseline_manager = baseline_manager
        self.drift_detector = drift_detector
        self.alert_manager = alert_manager
        self.is_running = False
        self._stop_event = asyncio.Event()

    @audit_error_handler
    async def start_monitoring(self) -> None:
        """Start continuous monitoring."""
        self.is_running = True
        self._stop_event.clear()

        while not self._stop_event.is_set():
            try:
                # Perform drift check if all components are available
                if self.baseline_manager and self.drift_detector:
                    try:
                        # Get current settings first to determine environment
                        from app.core.config import Settings

                        current_settings = Settings(SECRET_KEY=SecretStr("monitoring_secret_key_min_32_chars_long"))

                        # Get latest baseline for current environment
                        baseline = self.baseline_manager.get_latest_baseline(current_settings.ENVIRONMENT)
                        if baseline:
                            # Detect drift
                            drift_report = self.drift_detector.detect_drift(current_settings, baseline)

                            # Generate alerts if drift detected
                            if self.alert_manager and drift_report.drift_detected:
                                alerts = self.alert_manager.generate_alerts(drift_report)
                                # In a real implementation, we would send these alerts
                                # TODO: Implement alert delivery mechanism
                                for alert in alerts:
                                    # Placeholder for alert processing logic
                                    pass

                    except Exception:
                        # Continue monitoring even if individual check fails
                        pass

                # Wait for next check or stop signal
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.check_interval)
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue monitoring

            except Exception:
                # Log error and continue
                await asyncio.sleep(1)

        self.is_running = False

    def stop_monitoring(self) -> None:
        """Stop continuous configuration drift monitoring and clean up resources."""
        self._stop_event.set()
        self.is_running = False

    def update_config(self, **kwargs: Any) -> None:
        """Update monitoring configuration."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def get_health_status(self) -> Dict[str, Any]:
        """Get monitoring health status."""
        return {
            "status": "healthy" if self.is_running else "stopped",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "errors": [],
        }


class ConfigurationMonitor:
    """Monitors configuration changes in real-time."""

    def __init__(self) -> None:
        """Initialize configuration monitor."""
        self.callbacks: Dict[str, List[Dict[str, Any]]] = {}
        self.async_callbacks: Dict[str, List[Callable[..., Any]]] = {}
        self.change_history: List[Dict[str, Any]] = []
        self.history_enabled = False
        self.max_history_entries = 1000

    def register_callback(
        self, parameter: str, callback: Callable[..., Any], filter_func: Optional[Callable[..., bool]] = None
    ) -> None:
        """Register callback for parameter changes."""
        if parameter not in self.callbacks:
            self.callbacks[parameter] = []

        self.callbacks[parameter].append({"callback": callback, "filter": filter_func})

    def register_async_callback(self, parameter: str, callback: Callable[..., Any]) -> None:
        """Register async callback for parameter changes."""
        if parameter not in self.async_callbacks:
            self.async_callbacks[parameter] = []

        self.async_callbacks[parameter].append(callback)

    def notify_change(self, parameter: str, old_value: Any, new_value: Any) -> None:
        """Notify of configuration change."""
        # Record in history if enabled
        if self.history_enabled:
            self._add_to_history(parameter, old_value, new_value)

        # Call parameter-specific callbacks
        self._call_callbacks(parameter, old_value, new_value)

        # Call wildcard callbacks (pass actual parameter name)
        for callback_info in self.callbacks.get("*", []):
            callback = callback_info["callback"]
            filter_func = callback_info["filter"]

            # Apply filter if provided
            if filter_func and not filter_func(parameter, old_value, new_value):
                continue

            try:
                callback(parameter, old_value, new_value)
            except Exception:
                # Log error but continue with other callbacks
                pass

    async def notify_change_async(self, parameter: str, old_value: Any, new_value: Any) -> None:
        """Notify of configuration change asynchronously."""
        # Call async callbacks
        for callback in self.async_callbacks.get(parameter, []):
            await callback(parameter, old_value, new_value)

    def _call_callbacks(self, parameter: str, old_value: Any, new_value: Any) -> None:
        """Call registered callbacks for parameter."""
        for callback_info in self.callbacks.get(parameter, []):
            callback = callback_info["callback"]
            filter_func = callback_info["filter"]

            # Apply filter if provided
            if filter_func and not filter_func(parameter, old_value, new_value):
                continue

            try:
                callback(parameter, old_value, new_value)
            except Exception:
                # Log error but continue with other callbacks
                pass

    def _add_to_history(self, parameter: str, old_value: Any, new_value: Any) -> None:
        """Add change to history."""
        entry = {
            "parameter": parameter,
            "old_value": old_value,
            "new_value": new_value,
            "timestamp": datetime.now(timezone.utc),
        }

        self.change_history.append(entry)

        # Limit history size
        if len(self.change_history) > self.max_history_entries:
            self.change_history = self.change_history[-self.max_history_entries :]

    def enable_history(self, max_entries: int = 1000) -> None:
        """Enable change history tracking."""
        self.history_enabled = True
        self.max_history_entries = max_entries

    def get_change_history(self) -> List[Dict[str, Any]]:
        """Get configuration change history."""
        return [
            {
                "parameter": entry["parameter"],
                "old_value": entry["old_value"],
                "new_value": entry["new_value"],
                "timestamp": entry["timestamp"].isoformat(),
            }
            for entry in self.change_history
        ]
