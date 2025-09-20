"""
Automated Performance Alerting Service for Issue #123 - Phase 5 Database Monitoring.

This service provides comprehensive automated performance alerting with threshold monitoring,
regression detection, and escalation procedures for database operations.

Features:
- Real-time performance threshold monitoring
- Automated alert generation and delivery
- Performance regression detection
- Alert escalation and throttling
- Integration with existing monitoring infrastructure
"""

import asyncio
import json
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from structlog.stdlib import get_logger

from ..utils.monitoring import get_database_performance_summary, get_enhanced_system_metrics, track_database_query
from ..utils.performance_tracker import PerformanceTracker, get_global_performance_tracker

logger = get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of performance alerts."""

    SLOW_QUERY = "slow_query"
    HIGH_ERROR_RATE = "high_error_rate"
    PERFORMANCE_REGRESSION = "performance_regression"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CONNECTION_POOL_EXHAUSTION = "connection_pool_exhaustion"
    MEMORY_LEAK = "memory_leak"
    DEADLOCK_DETECTED = "deadlock_detected"


@dataclass
class PerformanceAlert:
    """Performance alert data structure."""

    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    operation: str
    repository: Optional[str]
    model: Optional[str]
    timestamp: datetime
    details: Dict[str, Any]
    threshold_config: Dict[str, Any]
    suggested_actions: List[str]
    escalation_level: int = 0
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class AlertThreshold:
    """Performance threshold configuration."""

    metric_name: str
    operation_pattern: str  # regex pattern for operations
    threshold_value: float
    comparison_operator: str  # >, <, >=, <=, ==, !=
    time_window_seconds: int
    min_samples: int
    severity: AlertSeverity
    alert_type: AlertType
    enabled: bool = True


@dataclass
class EscalationRule:
    """Alert escalation rule configuration."""

    alert_type: AlertType
    severity: AlertSeverity
    escalation_delay_minutes: int
    max_escalation_level: int
    escalation_channels: List[str]  # email, slack, webhook, etc.
    auto_resolve_minutes: Optional[int] = None


class PerformanceAlertingService:
    """
    Comprehensive automated performance alerting service.

    Provides real-time monitoring, threshold checking, alert generation,
    and escalation management for database performance issues.
    """

    def __init__(self, performance_tracker: Optional[PerformanceTracker] = None):
        """
        Initialize the performance alerting service.

        Args:
            performance_tracker: Optional performance tracker instance
        """
        self.performance_tracker = performance_tracker or get_global_performance_tracker()

        # Alert management
        self.active_alerts: Dict[str, PerformanceAlert] = {}
        self.alert_history: deque = deque(maxlen=1000)  # Keep last 1000 alerts
        self.alert_throttle: Dict[str, float] = {}  # Throttle duplicate alerts

        # Configuration
        self.thresholds = self._initialize_default_thresholds()
        self.escalation_rules = self._initialize_escalation_rules()
        self.notification_handlers: Dict[str, Callable] = {}

        # State tracking
        self.last_check_time = time.time()
        self.check_interval = 30  # Check every 30 seconds
        self.is_monitoring = False

        logger.info("Performance alerting service initialized")

    def _initialize_default_thresholds(self) -> List[AlertThreshold]:
        """
        Initialize default performance thresholds.

        Returns:
            List of default threshold configurations
        """
        return [
            # Database operation thresholds
            AlertThreshold(
                metric_name="average_duration",
                operation_pattern=".*get_by_id.*",
                threshold_value=0.5,  # 500ms
                comparison_operator=">=",
                time_window_seconds=300,  # 5 minutes
                min_samples=10,
                severity=AlertSeverity.MEDIUM,
                alert_type=AlertType.SLOW_QUERY,
            ),
            AlertThreshold(
                metric_name="average_duration",
                operation_pattern=".*update.*",
                threshold_value=1.0,  # 1 second
                comparison_operator=">=",
                time_window_seconds=300,
                min_samples=5,
                severity=AlertSeverity.MEDIUM,
                alert_type=AlertType.SLOW_QUERY,
            ),
            AlertThreshold(
                metric_name="average_duration",
                operation_pattern=".*list_with_pagination.*",
                threshold_value=2.0,  # 2 seconds
                comparison_operator=">=",
                time_window_seconds=300,
                min_samples=5,
                severity=AlertSeverity.HIGH,
                alert_type=AlertType.SLOW_QUERY,
            ),
            AlertThreshold(
                metric_name="success_rate",
                operation_pattern=".*",
                threshold_value=0.95,  # 95%
                comparison_operator="<",
                time_window_seconds=600,  # 10 minutes
                min_samples=20,
                severity=AlertSeverity.HIGH,
                alert_type=AlertType.HIGH_ERROR_RATE,
            ),
            AlertThreshold(
                metric_name="success_rate",
                operation_pattern=".*",
                threshold_value=0.90,  # 90%
                comparison_operator="<",
                time_window_seconds=300,
                min_samples=10,
                severity=AlertSeverity.CRITICAL,
                alert_type=AlertType.HIGH_ERROR_RATE,
            ),
            # System resource thresholds
            AlertThreshold(
                metric_name="database_pool_utilization",
                operation_pattern=".*",
                threshold_value=0.8,  # 80%
                comparison_operator=">=",
                time_window_seconds=120,
                min_samples=1,
                severity=AlertSeverity.HIGH,
                alert_type=AlertType.CONNECTION_POOL_EXHAUSTION,
            ),
            AlertThreshold(
                metric_name="memory_usage_percent",
                operation_pattern=".*",
                threshold_value=85.0,  # 85%
                comparison_operator=">=",
                time_window_seconds=300,
                min_samples=1,
                severity=AlertSeverity.HIGH,
                alert_type=AlertType.RESOURCE_EXHAUSTION,
            ),
        ]

    def _initialize_escalation_rules(self) -> List[EscalationRule]:
        """
        Initialize default escalation rules.

        Returns:
            List of escalation rule configurations
        """
        return [
            EscalationRule(
                alert_type=AlertType.CRITICAL,
                severity=AlertSeverity.CRITICAL,
                escalation_delay_minutes=5,
                max_escalation_level=3,
                escalation_channels=["email", "slack", "webhook"],
                auto_resolve_minutes=60,
            ),
            EscalationRule(
                alert_type=AlertType.HIGH_ERROR_RATE,
                severity=AlertSeverity.HIGH,
                escalation_delay_minutes=15,
                max_escalation_level=2,
                escalation_channels=["email", "slack"],
                auto_resolve_minutes=120,
            ),
            EscalationRule(
                alert_type=AlertType.SLOW_QUERY,
                severity=AlertSeverity.HIGH,
                escalation_delay_minutes=30,
                max_escalation_level=2,
                escalation_channels=["email"],
                auto_resolve_minutes=180,
            ),
            EscalationRule(
                alert_type=AlertType.PERFORMANCE_REGRESSION,
                severity=AlertSeverity.MEDIUM,
                escalation_delay_minutes=60,
                max_escalation_level=1,
                escalation_channels=["email"],
                auto_resolve_minutes=360,
            ),
        ]

    async def start_monitoring(self) -> None:
        """Start automated performance monitoring."""
        if self.is_monitoring:
            logger.warning("Performance monitoring already running")
            return

        self.is_monitoring = True
        logger.info("Starting automated performance monitoring")

        # Start monitoring loop in background
        asyncio.create_task(self._monitoring_loop())

    async def stop_monitoring(self) -> None:
        """Stop automated performance monitoring."""
        self.is_monitoring = False
        logger.info("Stopped automated performance monitoring")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop for checking performance thresholds."""
        while self.is_monitoring:
            try:
                await self._check_performance_thresholds()
                await self._process_alert_escalations()
                await self._auto_resolve_alerts()

                # Update last check time
                self.last_check_time = time.time()

                # Wait for next check
                await asyncio.sleep(self.check_interval)

            except Exception as e:
                logger.error("Error in monitoring loop", error=str(e), exception_type=type(e).__name__)
                await asyncio.sleep(self.check_interval)

    async def _check_performance_thresholds(self) -> None:
        """Check all configured performance thresholds."""
        try:
            # Get current performance metrics
            current_time = time.time()

            # Check operation-based thresholds
            for operation_name in self.performance_tracker._history.keys():
                await self._check_operation_thresholds(operation_name, current_time)

            # Check system-wide thresholds
            await self._check_system_thresholds(current_time)

            # Check for performance regressions
            await self._check_performance_regressions(current_time)

        except Exception as e:
            logger.error("Failed to check performance thresholds", error=str(e))

    async def _check_operation_thresholds(self, operation_name: str, current_time: float) -> None:
        """
        Check thresholds for a specific operation.

        Args:
            operation_name: Name of the operation to check
            current_time: Current timestamp
        """
        import re

        # Get recent operation metrics
        recent_history = self.performance_tracker.get_operation_history(operation_name, limit=100)
        if not recent_history:
            return

        # Check each threshold
        for threshold in self.thresholds:
            if not threshold.enabled:
                continue

            # Check if operation matches pattern
            if not re.match(threshold.operation_pattern, operation_name):
                continue

            # Filter recent operations by time window
            cutoff_time = current_time - threshold.time_window_seconds
            recent_ops = [op for op in recent_history if op.start_time > cutoff_time]

            if len(recent_ops) < threshold.min_samples:
                continue

            # Calculate metric value
            metric_value = await self._calculate_metric_value(recent_ops, threshold.metric_name)

            # Check threshold violation
            if self._check_threshold_violation(metric_value, threshold):
                await self._generate_alert(operation_name, threshold, metric_value, recent_ops, current_time)

    async def _calculate_metric_value(self, operations: List[Any], metric_name: str) -> float:
        """
        Calculate metric value from operation history.

        Args:
            operations: List of operation metrics
            metric_name: Name of the metric to calculate

        Returns:
            Calculated metric value
        """
        if not operations:
            return 0.0

        if metric_name == "average_duration":
            return sum(op.duration for op in operations) / len(operations)
        elif metric_name == "max_duration":
            return max(op.duration for op in operations)
        elif metric_name == "p95_duration":
            durations = sorted([op.duration for op in operations])
            index = int(0.95 * len(durations))
            return durations[index] if index < len(durations) else durations[-1]
        elif metric_name == "success_rate":
            # Assume success if no error status in metadata
            successful = len([op for op in operations if "error" not in op.metadata.get("status", "")])
            return successful / len(operations)
        elif metric_name == "error_rate":
            # Calculate error rate
            errors = len([op for op in operations if "error" in op.metadata.get("status", "")])
            return errors / len(operations)
        else:
            return 0.0

    def _check_threshold_violation(self, metric_value: float, threshold: AlertThreshold) -> bool:
        """
        Check if a metric value violates the threshold.

        Args:
            metric_value: Current metric value
            threshold: Threshold configuration

        Returns:
            True if threshold is violated
        """
        operator = threshold.comparison_operator
        threshold_value = threshold.threshold_value

        if operator == ">=":
            return metric_value >= threshold_value
        elif operator == ">":
            return metric_value > threshold_value
        elif operator == "<=":
            return metric_value <= threshold_value
        elif operator == "<":
            return metric_value < threshold_value
        elif operator == "==":
            return metric_value == threshold_value
        elif operator == "!=":
            return metric_value != threshold_value
        else:
            return False

    async def _generate_alert(
        self,
        operation_name: str,
        threshold: AlertThreshold,
        metric_value: float,
        recent_ops: List[Any],
        current_time: float,
    ) -> None:
        """
        Generate a performance alert.

        Args:
            operation_name: Operation that violated threshold
            threshold: Violated threshold configuration
            metric_value: Current metric value
            recent_ops: Recent operation history
            current_time: Current timestamp
        """
        # Create alert ID for throttling
        alert_id = f"{threshold.alert_type.value}_{operation_name}_{threshold.metric_name}"

        # Check if alert is throttled
        if self._is_alert_throttled(alert_id, current_time):
            return

        # Extract repository and model information
        repository = None
        model = None
        if recent_ops:
            metadata = recent_ops[0].metadata
            repository = metadata.get("repository")
            model = metadata.get("model")

        # Generate alert
        alert = PerformanceAlert(
            id=alert_id,
            alert_type=threshold.alert_type,
            severity=threshold.severity,
            title=self._generate_alert_title(threshold, operation_name),
            message=self._generate_alert_message(threshold, operation_name, metric_value),
            operation=operation_name,
            repository=repository,
            model=model,
            timestamp=datetime.fromtimestamp(current_time),
            details={
                "metric_name": threshold.metric_name,
                "metric_value": metric_value,
                "threshold_value": threshold.threshold_value,
                "comparison_operator": threshold.comparison_operator,
                "sample_size": len(recent_ops),
                "time_window_seconds": threshold.time_window_seconds,
            },
            threshold_config=asdict(threshold),
            suggested_actions=self._generate_suggested_actions(threshold, operation_name, metric_value),
        )

        # Store alert
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)

        # Set throttle
        self._set_alert_throttle(alert_id, current_time)

        # Send notification
        await self._send_alert_notification(alert)

        logger.warning(
            "Performance alert generated",
            alert_type=threshold.alert_type.value,
            severity=threshold.severity.value,
            operation=operation_name,
            metric_value=metric_value,
            threshold_value=threshold.threshold_value,
        )

    def _is_alert_throttled(self, alert_id: str, current_time: float) -> bool:
        """
        Check if an alert is throttled.

        Args:
            alert_id: Alert identifier
            current_time: Current timestamp

        Returns:
            True if alert is throttled
        """
        if alert_id not in self.alert_throttle:
            return False

        last_sent = self.alert_throttle[alert_id]
        throttle_period = 300  # 5 minutes default throttle

        return (current_time - last_sent) < throttle_period

    def _set_alert_throttle(self, alert_id: str, current_time: float) -> None:
        """
        Set alert throttle timestamp.

        Args:
            alert_id: Alert identifier
            current_time: Current timestamp
        """
        self.alert_throttle[alert_id] = current_time

    def _generate_alert_title(self, threshold: AlertThreshold, operation_name: str) -> str:
        """Generate alert title."""
        return f"{threshold.alert_type.value.replace('_', ' ').title()}: {operation_name}"

    def _generate_alert_message(self, threshold: AlertThreshold, operation_name: str, metric_value: float) -> str:
        """Generate alert message."""
        return (
            f"Performance threshold violated for {operation_name}. "
            f"{threshold.metric_name} = {metric_value:.3f} "
            f"{threshold.comparison_operator} {threshold.threshold_value}"
        )

    def _generate_suggested_actions(
        self, threshold: AlertThreshold, operation_name: str, metric_value: float
    ) -> List[str]:
        """Generate suggested remediation actions."""
        actions = []

        if threshold.alert_type == AlertType.SLOW_QUERY:
            actions.extend(
                [
                    "Review query execution plan for optimization opportunities",
                    "Check for missing indexes on filtered columns",
                    "Consider query result caching for frequently accessed data",
                    "Review connection pool configuration",
                ]
            )
        elif threshold.alert_type == AlertType.HIGH_ERROR_RATE:
            actions.extend(
                [
                    "Check application logs for error details",
                    "Verify database connectivity and health",
                    "Review recent code changes for potential issues",
                    "Check for database deadlocks or locking issues",
                ]
            )
        elif threshold.alert_type == AlertType.CONNECTION_POOL_EXHAUSTION:
            actions.extend(
                [
                    "Increase database connection pool size",
                    "Review connection leak patterns",
                    "Optimize connection usage in application code",
                    "Check for long-running transactions",
                ]
            )
        elif threshold.alert_type == AlertType.RESOURCE_EXHAUSTION:
            actions.extend(
                [
                    "Scale up system resources",
                    "Review memory usage patterns",
                    "Check for memory leaks in application",
                    "Optimize resource-intensive operations",
                ]
            )

        return actions

    async def _check_system_thresholds(self, current_time: float) -> None:
        """
        Check system-wide performance thresholds.

        Args:
            current_time: Current timestamp
        """
        try:
            # Get system metrics
            system_metrics = await get_enhanced_system_metrics()
            db_summary = get_database_performance_summary()

            # Check memory usage
            memory_usage = system_metrics.get("system", {}).get("memory_percent", 0)
            await self._check_single_threshold(
                "system_memory_usage", memory_usage, current_time, AlertType.RESOURCE_EXHAUSTION, "memory_usage_percent"
            )

            # Check database pool utilization
            pool_utilization = db_summary.get("connection_pool", {}).get("utilization", 0)
            await self._check_single_threshold(
                "database_pool_utilization",
                pool_utilization,
                current_time,
                AlertType.CONNECTION_POOL_EXHAUSTION,
                "database_pool_utilization",
            )

        except Exception as e:
            logger.error("Failed to check system thresholds", error=str(e))

    async def _check_single_threshold(
        self, operation_name: str, metric_value: float, current_time: float, alert_type: AlertType, metric_name: str
    ) -> None:
        """
        Check a single threshold against a metric value.

        Args:
            operation_name: Operation identifier
            metric_value: Current metric value
            current_time: Current timestamp
            alert_type: Type of alert
            metric_name: Name of the metric
        """
        # Find matching thresholds
        for threshold in self.thresholds:
            if threshold.alert_type == alert_type and threshold.metric_name == metric_name and threshold.enabled:

                if self._check_threshold_violation(metric_value, threshold):
                    await self._generate_system_alert(operation_name, threshold, metric_value, current_time)

    async def _generate_system_alert(
        self, operation_name: str, threshold: AlertThreshold, metric_value: float, current_time: float
    ) -> None:
        """
        Generate a system-level alert.

        Args:
            operation_name: System operation identifier
            threshold: Violated threshold
            metric_value: Current metric value
            current_time: Current timestamp
        """
        alert_id = f"{threshold.alert_type.value}_{operation_name}"

        if self._is_alert_throttled(alert_id, current_time):
            return

        alert = PerformanceAlert(
            id=alert_id,
            alert_type=threshold.alert_type,
            severity=threshold.severity,
            title=f"System Alert: {operation_name}",
            message=f"System threshold violated: {threshold.metric_name} = {metric_value:.2f}",
            operation=operation_name,
            repository=None,
            model=None,
            timestamp=datetime.fromtimestamp(current_time),
            details={
                "metric_name": threshold.metric_name,
                "metric_value": metric_value,
                "threshold_value": threshold.threshold_value,
                "comparison_operator": threshold.comparison_operator,
            },
            threshold_config=asdict(threshold),
            suggested_actions=self._generate_suggested_actions(threshold, operation_name, metric_value),
        )

        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        self._set_alert_throttle(alert_id, current_time)

        await self._send_alert_notification(alert)

    async def _check_performance_regressions(self, current_time: float) -> None:
        """
        Check for performance regressions against baselines.

        Args:
            current_time: Current timestamp
        """
        for operation_name in self.performance_tracker._history.keys():
            regression = self.performance_tracker.detect_performance_regression(operation_name)

            if regression and regression["is_regression"]:
                alert_id = f"regression_{operation_name}"

                if self._is_alert_throttled(alert_id, current_time):
                    continue

                severity = AlertSeverity.HIGH if regression["regression_factor"] > 0.5 else AlertSeverity.MEDIUM

                alert = PerformanceAlert(
                    id=alert_id,
                    alert_type=AlertType.PERFORMANCE_REGRESSION,
                    severity=severity,
                    title=f"Performance Regression: {operation_name}",
                    message=f"Performance regression detected: {regression['regression_percentage']:.1f}% slower than baseline",
                    operation=operation_name,
                    repository=None,
                    model=None,
                    timestamp=datetime.fromtimestamp(current_time),
                    details=regression,
                    threshold_config={},
                    suggested_actions=[
                        "Review recent code changes that may impact performance",
                        "Compare current query execution plans with baseline",
                        "Check for infrastructure changes or resource constraints",
                        "Consider reverting recent changes if regression is severe",
                    ],
                )

                self.active_alerts[alert_id] = alert
                self.alert_history.append(alert)
                self._set_alert_throttle(alert_id, current_time)

                await self._send_alert_notification(alert)

    async def _process_alert_escalations(self) -> None:
        """Process alert escalations based on configured rules."""
        current_time = time.time()

        for alert in self.active_alerts.values():
            if alert.acknowledged or alert.resolved:
                continue

            # Find escalation rule
            escalation_rule = self._find_escalation_rule(alert)
            if not escalation_rule:
                continue

            # Check if escalation is due
            alert_age_minutes = (current_time - alert.timestamp.timestamp()) / 60
            escalation_delay = escalation_rule.escalation_delay_minutes * (alert.escalation_level + 1)

            if alert_age_minutes >= escalation_delay and alert.escalation_level < escalation_rule.max_escalation_level:

                alert.escalation_level += 1
                await self._escalate_alert(alert, escalation_rule)

    def _find_escalation_rule(self, alert: PerformanceAlert) -> Optional[EscalationRule]:
        """
        Find matching escalation rule for an alert.

        Args:
            alert: Performance alert

        Returns:
            Matching escalation rule or None
        """
        for rule in self.escalation_rules:
            if rule.alert_type == alert.alert_type and rule.severity == alert.severity:
                return rule
        return None

    async def _escalate_alert(self, alert: PerformanceAlert, rule: EscalationRule) -> None:
        """
        Escalate an alert according to escalation rule.

        Args:
            alert: Alert to escalate
            rule: Escalation rule to apply
        """
        logger.warning(
            "Escalating alert",
            alert_id=alert.id,
            escalation_level=alert.escalation_level,
            channels=rule.escalation_channels,
        )

        # Send escalated notification
        await self._send_escalated_notification(alert, rule)

    async def _auto_resolve_alerts(self) -> None:
        """Automatically resolve alerts based on auto-resolution rules."""
        current_time = time.time()

        alerts_to_resolve = []

        for alert in self.active_alerts.values():
            if alert.resolved:
                continue

            # Find escalation rule for auto-resolution
            escalation_rule = self._find_escalation_rule(alert)
            if not escalation_rule or not escalation_rule.auto_resolve_minutes:
                continue

            # Check if auto-resolution time has passed
            alert_age_minutes = (current_time - alert.timestamp.timestamp()) / 60

            if alert_age_minutes >= escalation_rule.auto_resolve_minutes:
                alerts_to_resolve.append(alert)

        # Resolve alerts
        for alert in alerts_to_resolve:
            await self.resolve_alert(alert.id, "auto_resolved", "Automatically resolved after timeout")

    async def _send_alert_notification(self, alert: PerformanceAlert) -> None:
        """
        Send alert notification through configured channels.

        Args:
            alert: Alert to send notification for
        """
        # Log alert
        logger.warning(
            "Performance alert triggered",
            alert_id=alert.id,
            alert_type=alert.alert_type.value,
            severity=alert.severity.value,
            operation=alert.operation,
            message=alert.message,
        )

        # Send through registered notification handlers
        for channel, handler in self.notification_handlers.items():
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Failed to send alert through {channel}", error=str(e))

    async def _send_escalated_notification(self, alert: PerformanceAlert, rule: EscalationRule) -> None:
        """
        Send escalated alert notification.

        Args:
            alert: Alert being escalated
            rule: Escalation rule
        """
        logger.critical(
            "Performance alert escalated",
            alert_id=alert.id,
            escalation_level=alert.escalation_level,
            channels=rule.escalation_channels,
        )

    def register_notification_handler(self, channel: str, handler: Callable[[PerformanceAlert], None]) -> None:
        """
        Register a notification handler for alerts.

        Args:
            channel: Channel name (email, slack, webhook, etc.)
            handler: Async function to handle alert notifications
        """
        self.notification_handlers[channel] = handler
        logger.info(f"Registered notification handler for {channel}")

    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str, notes: str = "") -> bool:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert identifier
            acknowledged_by: User acknowledging the alert
            notes: Optional acknowledgment notes

        Returns:
            True if alert was acknowledged successfully
        """
        if alert_id not in self.active_alerts:
            return False

        alert = self.active_alerts[alert_id]
        alert.acknowledged = True
        alert.details["acknowledged_by"] = acknowledged_by
        alert.details["acknowledged_at"] = datetime.now().isoformat()
        alert.details["acknowledgment_notes"] = notes

        logger.info("Alert acknowledged", alert_id=alert_id, acknowledged_by=acknowledged_by)

        return True

    async def resolve_alert(self, alert_id: str, resolved_by: str, resolution_notes: str = "") -> bool:
        """
        Resolve an alert.

        Args:
            alert_id: Alert identifier
            resolved_by: User resolving the alert
            resolution_notes: Resolution notes

        Returns:
            True if alert was resolved successfully
        """
        if alert_id not in self.active_alerts:
            return False

        alert = self.active_alerts[alert_id]
        alert.resolved = True
        alert.details["resolved_by"] = resolved_by
        alert.details["resolved_at"] = datetime.now().isoformat()
        alert.details["resolution_notes"] = resolution_notes

        # Remove from active alerts
        del self.active_alerts[alert_id]

        logger.info("Alert resolved", alert_id=alert_id, resolved_by=resolved_by)

        return True

    def get_active_alerts(
        self, severity_filter: Optional[AlertSeverity] = None, alert_type_filter: Optional[AlertType] = None
    ) -> List[PerformanceAlert]:
        """
        Get currently active alerts.

        Args:
            severity_filter: Optional severity filter
            alert_type_filter: Optional alert type filter

        Returns:
            List of active alerts
        """
        alerts = list(self.active_alerts.values())

        if severity_filter:
            alerts = [a for a in alerts if a.severity == severity_filter]

        if alert_type_filter:
            alerts = [a for a in alerts if a.alert_type == alert_type_filter]

        # Sort by severity and timestamp
        severity_order = {
            AlertSeverity.CRITICAL: 0,
            AlertSeverity.HIGH: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.LOW: 3,
        }

        alerts.sort(key=lambda x: (severity_order[x.severity], x.timestamp), reverse=True)

        return alerts

    def get_alert_history(self, limit: int = 100) -> List[PerformanceAlert]:
        """
        Get alert history.

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of historical alerts
        """
        return list(self.alert_history)[-limit:]

    def get_alerting_statistics(self) -> Dict[str, Any]:
        """
        Get alerting service statistics.

        Returns:
            Dictionary with alerting statistics
        """
        total_alerts = len(self.alert_history)
        active_alerts = len(self.active_alerts)

        # Count by severity
        severity_counts: Dict[str, int] = defaultdict(int)
        for alert in self.alert_history:
            severity_counts[alert.severity.value] += 1

        # Count by type
        type_counts: Dict[str, int] = defaultdict(int)
        for alert in self.alert_history:
            type_counts[alert.alert_type.value] += 1

        return {
            "is_monitoring": self.is_monitoring,
            "check_interval": self.check_interval,
            "last_check_time": self.last_check_time,
            "total_alerts_generated": total_alerts,
            "active_alerts_count": active_alerts,
            "configured_thresholds": len(self.thresholds),
            "escalation_rules": len(self.escalation_rules),
            "notification_handlers": list(self.notification_handlers.keys()),
            "severity_distribution": dict(severity_counts),
            "alert_type_distribution": dict(type_counts),
        }
