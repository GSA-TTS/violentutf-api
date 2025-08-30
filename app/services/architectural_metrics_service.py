"""Architectural Metrics and ROI Tracking Service.

This service provides comprehensive metrics collection and analysis for architectural
audit initiatives, including automation coverage, detection time, developer adoption,
compliance scores, and ROI calculations.
"""

import json
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import Severity as VulnerabilitySeverity
from app.models.audit_log import AuditLog
from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import Scan
from app.models.security_scan import SecurityScan
from app.models.task import Task, TaskStatus
from app.models.vulnerability_finding import VulnerabilityFinding

logger = logging.getLogger(__name__)


class ArchitecturalMetricsService:
    """Service for calculating architectural audit metrics and ROI."""

    def __init__(self, db_session: AsyncSession):
        """Initialize the metrics service.

        Args:
            db_session: AsyncSQL database session
        """
        self.db = db_session
        self._cache: Dict[str, Any] = {}
        self._cache_ttl = 3600  # 1 hour cache TTL

    async def calculate_leading_indicators(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Calculate leading indicator metrics for architectural audits.

        Leading indicators predict future performance and help identify
        potential issues before they become problems.

        Args:
            start_date: Start date for metrics calculation
            end_date: End date for metrics calculation

        Returns:
            Dictionary containing leading indicator metrics
        """
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        metrics = {
            "automation_coverage": await self._calculate_automation_coverage(start_date, end_date),
            "detection_time": await self._calculate_detection_time_metrics(start_date, end_date),
            "developer_adoption_rate": await self._calculate_developer_adoption(start_date, end_date),
            "compliance_scores": await self._calculate_compliance_scores(start_date, end_date),
            "violation_frequency": await self._calculate_violation_frequency(start_date, end_date),
            "preventive_actions": await self._calculate_preventive_actions(start_date, end_date),
            "tool_utilization": await self._calculate_tool_utilization(start_date, end_date),
            "training_effectiveness": await self._calculate_training_effectiveness(start_date, end_date),
            "calculated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": (end_date - start_date).days,
            },
        }

        return metrics

    async def calculate_lagging_indicators(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Calculate lagging indicator metrics for architectural audits.

        Lagging indicators measure past performance and actual outcomes
        from architectural audit initiatives.

        Args:
            start_date: Start date for metrics calculation
            end_date: End date for metrics calculation

        Returns:
            Dictionary containing lagging indicator metrics
        """
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=90)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        metrics = {
            "architectural_debt_velocity": await self._calculate_debt_velocity(start_date, end_date),
            "security_incident_reduction": await self._calculate_security_reduction(start_date, end_date),
            "maintainability_improvements": await self._calculate_maintainability(start_date, end_date),
            "development_velocity_impact": await self._calculate_velocity_impact(start_date, end_date),
            "quality_metrics": await self._calculate_quality_metrics(start_date, end_date),
            "remediation_effectiveness": await self._calculate_remediation_effectiveness(start_date, end_date),
            "compliance_achievements": await self._calculate_compliance_achievements(start_date, end_date),
            "calculated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": (end_date - start_date).days,
            },
        }

        return metrics

    async def calculate_roi_analysis(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        cost_data: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """Calculate comprehensive ROI analysis for architectural audits.

        Args:
            start_date: Start date for ROI calculation
            end_date: End date for ROI calculation
            cost_data: Optional cost data for more accurate calculations

        Returns:
            Dictionary containing ROI analysis metrics
        """
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=180)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        # Default cost estimates if not provided
        if not cost_data:
            cost_data = {
                "hourly_developer_rate": 150.0,
                "tool_licensing_cost": 5000.0,
                "training_cost_per_person": 1000.0,
                "incident_cost": 25000.0,
                "bug_fix_cost": 2500.0,
            }

        # Calculate various cost and benefit metrics
        implementation_costs = await self._calculate_implementation_costs(start_date, end_date, cost_data)
        cost_avoidance = await self._calculate_cost_avoidance(start_date, end_date, cost_data)
        productivity_gains = await self._calculate_productivity_gains(start_date, end_date, cost_data)
        quality_improvements = await self._calculate_quality_improvements(start_date, end_date, cost_data)

        total_costs = sum(implementation_costs.values())
        total_benefits = (
            sum(cost_avoidance.values()) + sum(productivity_gains.values()) + sum(quality_improvements.values())
        )

        roi_percentage = ((total_benefits - total_costs) / total_costs * 100) if total_costs > 0 else 0
        payback_period_months = (total_costs / (total_benefits / 12)) if total_benefits > 0 else None

        return {
            "implementation_costs": implementation_costs,
            "cost_avoidance": cost_avoidance,
            "productivity_gains": productivity_gains,
            "quality_improvements": quality_improvements,
            "total_costs": total_costs,
            "total_benefits": total_benefits,
            "net_benefit": total_benefits - total_costs,
            "roi_percentage": round(roi_percentage, 2),
            "payback_period_months": (round(payback_period_months, 1) if payback_period_months else None),
            "cost_benefit_ratio": (round(total_benefits / total_costs, 2) if total_costs > 0 else None),
            "calculated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": (end_date - start_date).days,
            },
            "assumptions": cost_data,
        }

    async def _calculate_automation_coverage(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate automation coverage metrics."""
        # Query for automated vs manual scans
        auto_scan_query = select(func.count(Scan.id)).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.is_deleted.is_(False),
                Scan.scan_type.in_(["automated", "scheduled", "continuous"]),
            )
        )

        manual_scan_query = select(func.count(Scan.id)).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.is_deleted.is_(False),
                Scan.scan_type == "manual",
            )
        )

        auto_result = await self.db.execute(auto_scan_query)
        manual_result = await self.db.execute(manual_scan_query)

        auto_count = auto_result.scalar() or 0
        manual_count = manual_result.scalar() or 0
        total_count = auto_count + manual_count

        coverage_percentage = (auto_count / total_count * 100) if total_count > 0 else 0

        return {
            "automated_scans": auto_count,
            "manual_scans": manual_count,
            "total_scans": total_count,
            "automation_percentage": round(coverage_percentage, 2),
            "trend": "increasing" if auto_count > manual_count else "decreasing",
        }

    async def _calculate_detection_time_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate metrics for violation detection time."""
        # Query vulnerability findings with detection times
        findings_query = select(
            VulnerabilityFinding.created_at,
            VulnerabilityFinding.detected_at,
            VulnerabilityFinding.severity,
        ).where(
            and_(
                VulnerabilityFinding.created_at.between(start_date, end_date),
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(findings_query)
        findings = result.all()

        detection_times = []
        severity_times = defaultdict(list)

        for finding in findings:
            if finding.detected_at and finding.created_at:
                detection_time = (finding.created_at - finding.detected_at).total_seconds() / 3600  # hours
                detection_times.append(detection_time)
                severity_times[finding.severity.value].append(detection_time)

        if detection_times:
            avg_detection = statistics.mean(detection_times)
            median_detection = statistics.median(detection_times)
            min_detection = min(detection_times)
            max_detection = max(detection_times)
        else:
            avg_detection = median_detection = min_detection = max_detection = 0

        severity_averages = {
            severity: round(statistics.mean(times), 2) if times else 0 for severity, times in severity_times.items()
        }

        return {
            "average_detection_hours": round(avg_detection, 2),
            "median_detection_hours": round(median_detection, 2),
            "min_detection_hours": round(min_detection, 2),
            "max_detection_hours": round(max_detection, 2),
            "total_detections": len(detection_times),
            "by_severity": severity_averages,
        }

    async def _calculate_developer_adoption(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate developer adoption metrics."""
        # Query unique users who have run scans
        active_users_query = select(func.count(func.distinct(Scan.created_by))).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.is_deleted.is_(False),
            )
        )

        # Query for audit log entries showing tool usage
        tool_usage_query = select(func.count(func.distinct(AuditLog.user_id))).where(
            and_(
                AuditLog.created_at.between(start_date, end_date),
                AuditLog.action.in_(["scan.create", "report.generate", "vulnerability.review"]),
            )
        )

        active_result = await self.db.execute(active_users_query)
        usage_result = await self.db.execute(tool_usage_query)

        active_users = active_result.scalar() or 0
        tool_users = usage_result.scalar() or 0

        # Calculate growth rate (compare with previous period)
        prev_start = start_date - (end_date - start_date)
        prev_end = start_date

        prev_users_query = select(func.count(func.distinct(Scan.created_by))).where(
            and_(
                Scan.created_at.between(prev_start, prev_end),
                Scan.is_deleted.is_(False),
            )
        )

        prev_result = await self.db.execute(prev_users_query)
        prev_users = prev_result.scalar() or 0

        growth_rate = ((active_users - prev_users) / prev_users * 100) if prev_users > 0 else 0

        return {
            "active_users": active_users,
            "tool_users": tool_users,
            "adoption_rate": round((tool_users / active_users * 100) if active_users > 0 else 0, 2),
            "growth_rate": round(growth_rate, 2),
            "period_comparison": {
                "current": active_users,
                "previous": prev_users,
                "change": active_users - prev_users,
            },
        }

    async def _calculate_compliance_scores(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate compliance score metrics."""
        # Query findings by compliance category
        findings_query = (
            select(
                VulnerabilityFinding.category,
                VulnerabilityFinding.severity,
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.is_deleted.is_(False),
                )
            )
            .group_by(VulnerabilityFinding.category, VulnerabilityFinding.severity)
        )

        result = await self.db.execute(findings_query)
        findings = result.all()

        # Calculate compliance scores by category
        category_scores: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "resolved": 0, "critical": 0, "high": 0}
        )

        for finding in findings:
            category_scores[finding.category]["total"] += finding.count
            if finding.severity == VulnerabilitySeverity.CRITICAL:
                category_scores[finding.category]["critical"] += finding.count
            elif finding.severity == VulnerabilitySeverity.HIGH:
                category_scores[finding.category]["high"] += finding.count

        # Query resolved findings
        resolved_query = (
            select(
                VulnerabilityFinding.category,
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.is_deleted.is_(False),
                    VulnerabilityFinding.status == "resolved",
                )
            )
            .group_by(VulnerabilityFinding.category)
        )

        resolved_result = await self.db.execute(resolved_query)
        resolved_findings = resolved_result.all()

        for finding in resolved_findings:
            category_scores[finding.category]["resolved"] += finding.count

        # Calculate overall compliance score
        total_findings = sum(cat["total"] for cat in category_scores.values())
        total_resolved = sum(cat["resolved"] for cat in category_scores.values())
        total_critical = sum(cat["critical"] for cat in category_scores.values())

        overall_score = 100.0
        if total_findings > 0:
            # Weighted scoring: critical = -10, high = -5, other = -2
            penalty = (total_critical * 10) + (sum(cat["high"] for cat in category_scores.values()) * 5)
            penalty += (total_findings - total_critical - sum(cat["high"] for cat in category_scores.values())) * 2
            overall_score = max(0, 100 - (penalty / total_findings))

        category_compliance = {}
        for category, scores in category_scores.items():
            if scores["total"] > 0:
                resolution_rate = (scores["resolved"] / scores["total"]) * 100
                category_compliance[category] = {
                    "total_findings": scores["total"],
                    "resolved": scores["resolved"],
                    "critical": scores["critical"],
                    "high": scores["high"],
                    "resolution_rate": round(resolution_rate, 2),
                    "compliance_score": round(
                        100 - (scores["critical"] * 10 + scores["high"] * 5) / max(scores["total"], 1),
                        2,
                    ),
                }

        return {
            "overall_score": round(overall_score, 2),
            "total_findings": total_findings,
            "resolved_findings": total_resolved,
            "critical_findings": total_critical,
            "resolution_rate": round(
                (total_resolved / total_findings * 100) if total_findings > 0 else 100,
                2,
            ),
            "by_category": category_compliance,
        }

    async def _calculate_violation_frequency(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate violation frequency metrics."""
        # Query violations over time
        violations_query = (
            select(
                func.date_trunc("week", VulnerabilityFinding.created_at).label("week"),
                VulnerabilityFinding.category,
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.is_deleted.is_(False),
                )
            )
            .group_by("week", VulnerabilityFinding.category)
        )

        result = await self.db.execute(violations_query)
        violations = result.all()

        # Organize by week and category
        weekly_violations: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        categories = set()

        for violation in violations:
            week_str = violation.week.strftime("%Y-%W")
            weekly_violations[week_str][violation.category] += violation.count
            categories.add(violation.category)

        # Calculate trends
        weeks = sorted(weekly_violations.keys())
        if len(weeks) >= 2:
            first_half = weeks[: len(weeks) // 2]
            second_half = weeks[len(weeks) // 2 :]

            first_half_avg = (
                statistics.mean([sum(weekly_violations[week].values()) for week in first_half]) if first_half else 0
            )

            second_half_avg = (
                statistics.mean([sum(weekly_violations[week].values()) for week in second_half]) if second_half else 0
            )

            trend = "decreasing" if second_half_avg < first_half_avg else "increasing"
            trend_percentage = ((second_half_avg - first_half_avg) / first_half_avg * 100) if first_half_avg > 0 else 0
        else:
            trend = "stable"
            trend_percentage = 0

        # Most common violations
        category_totals: Dict[str, int] = defaultdict(int)
        for week_data in weekly_violations.values():
            for category, count in week_data.items():
                category_totals[category] += count

        top_violations = sorted(category_totals.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "weekly_average": round(
                (
                    statistics.mean([sum(week.values()) for week in weekly_violations.values()])
                    if weekly_violations
                    else 0
                ),
                2,
            ),
            "total_violations": sum(category_totals.values()),
            "unique_categories": len(categories),
            "trend": trend,
            "trend_percentage": round(trend_percentage, 2),
            "top_violations": (
                [
                    {
                        "category": cat,
                        "count": count,
                        "percentage": round(count / sum(category_totals.values()) * 100, 2),
                    }
                    for cat, count in top_violations
                ]
                if category_totals
                else []
            ),
            "weekly_data": dict(weekly_violations),
        }

    async def _calculate_preventive_actions(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate preventive actions taken."""
        # Query audit logs for preventive actions
        preventive_actions_query = (
            select(AuditLog.action, func.count(AuditLog.id).label("count"))
            .where(
                and_(
                    AuditLog.created_at.between(start_date, end_date),
                    AuditLog.action.in_(
                        [
                            "scan.scheduled",
                            "policy.created",
                            "rule.added",
                            "training.completed",
                            "review.performed",
                        ]
                    ),
                )
            )
            .group_by(AuditLog.action)
        )

        result = await self.db.execute(preventive_actions_query)
        actions = result.all()

        action_counts = {action.action: action.count for action in actions}
        total_actions = sum(action_counts.values())

        return {
            "total_preventive_actions": total_actions,
            "actions_by_type": action_counts,
            "daily_average": round(total_actions / max((end_date - start_date).days, 1), 2),
        }

    async def _calculate_tool_utilization(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate tool utilization metrics."""
        # Query for tool usage
        scans_query = select(func.count(Scan.id)).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.is_deleted.is_(False),
            )
        )

        reports_query = select(func.count(Report.id)).where(
            and_(
                Report.created_at.between(start_date, end_date),
                Report.is_deleted.is_(False),
            )
        )

        tasks_query = select(func.count(Task.id)).where(
            and_(
                Task.created_at.between(start_date, end_date),
                Task.status == TaskStatus.COMPLETED,
            )
        )

        scans_result = await self.db.execute(scans_query)
        reports_result = await self.db.execute(reports_query)
        tasks_result = await self.db.execute(tasks_query)

        scans_count = scans_result.scalar() or 0
        reports_count = reports_result.scalar() or 0
        tasks_count = tasks_result.scalar() or 0

        days = max((end_date - start_date).days, 1)

        return {
            "total_scans": scans_count,
            "total_reports": reports_count,
            "completed_tasks": tasks_count,
            "daily_utilization": {
                "scans_per_day": round(scans_count / days, 2),
                "reports_per_day": round(reports_count / days, 2),
                "tasks_per_day": round(tasks_count / days, 2),
            },
        }

    async def _calculate_training_effectiveness(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate training effectiveness metrics."""
        # This would typically integrate with a training system
        # For now, we'll use audit logs as a proxy
        training_query = select(func.count(func.distinct(AuditLog.user_id))).where(
            and_(
                AuditLog.created_at.between(start_date, end_date),
                AuditLog.action == "training.completed",
            )
        )

        result = await self.db.execute(training_query)
        trained_users = result.scalar() or 0

        return {
            "users_trained": trained_users,
            "training_completion_rate": 100.0,  # Would be calculated from actual training data
            "skill_improvement": "N/A",  # Would require pre/post assessments
        }

    async def _calculate_debt_velocity(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate architectural debt velocity."""
        # Query for new vs resolved violations
        new_violations = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.created_at.between(start_date, end_date),
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        resolved_violations = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.updated_at.between(start_date, end_date),
                VulnerabilityFinding.status == "resolved",
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        new_result = await self.db.execute(new_violations)
        resolved_result = await self.db.execute(resolved_violations)

        new_count = new_result.scalar() or 0
        resolved_count = resolved_result.scalar() or 0

        net_change = new_count - resolved_count
        velocity = net_change / max((end_date - start_date).days, 1)

        return {
            "new_violations": new_count,
            "resolved_violations": resolved_count,
            "net_change": net_change,
            "daily_velocity": round(velocity, 2),
            "trend": "improving" if velocity < 0 else "worsening",
        }

    async def _calculate_security_reduction(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate security incident reduction metrics."""
        # Query for security incidents
        incidents_query = (
            select(
                func.date_trunc("month", VulnerabilityFinding.created_at).label("month"),
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.severity.in_([VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]),
                    VulnerabilityFinding.is_deleted.is_(False),
                )
            )
            .group_by("month")
        )

        result = await self.db.execute(incidents_query)
        incidents = result.all()

        monthly_counts: List[int] = [int(incident.count) for incident in incidents]

        if len(monthly_counts) >= 2:
            first_month = monthly_counts[0]
            last_month = monthly_counts[-1]
            reduction_percentage = ((first_month - last_month) / first_month * 100) if first_month > 0 else 0
            trend = "improving" if last_month < first_month else "worsening"
        else:
            reduction_percentage = 0
            trend = "stable"

        return {
            "total_incidents": sum(monthly_counts),
            "monthly_average": (round(statistics.mean(monthly_counts), 2) if monthly_counts else 0),
            "reduction_percentage": round(reduction_percentage, 2),
            "trend": trend,
            "monthly_data": {incident.month.strftime("%Y-%m"): incident.count for incident in incidents},
        }

    async def _calculate_maintainability(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate maintainability improvement metrics."""
        # Query for code quality metrics
        quality_findings = (
            select(
                VulnerabilityFinding.category,
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.category.in_(["code_quality", "maintainability", "complexity"]),
                    VulnerabilityFinding.is_deleted.is_(False),
                )
            )
            .group_by(VulnerabilityFinding.category)
        )

        result = await self.db.execute(quality_findings)
        findings = result.all()

        maintainability_issues = sum(finding.count for finding in findings)

        # Compare with previous period
        prev_start = start_date - (end_date - start_date)
        prev_quality_findings = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.created_at.between(prev_start, start_date),
                VulnerabilityFinding.category.in_(["code_quality", "maintainability", "complexity"]),
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        prev_result = await self.db.execute(prev_quality_findings)
        prev_issues = prev_result.scalar() or 0

        improvement_rate = ((prev_issues - maintainability_issues) / prev_issues * 100) if prev_issues > 0 else 0

        return {
            "maintainability_issues": maintainability_issues,
            "previous_period_issues": prev_issues,
            "improvement_rate": round(improvement_rate, 2),
            "categories": {finding.category: finding.count for finding in findings},
        }

    async def _calculate_velocity_impact(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate development velocity impact."""
        # Query for task completion rates
        completed_tasks = select(func.count(Task.id)).where(
            and_(
                Task.completed_at.between(start_date, end_date),
                Task.status == TaskStatus.COMPLETED,
            )
        )

        failed_tasks = select(func.count(Task.id)).where(
            and_(
                Task.completed_at.between(start_date, end_date),
                Task.status == TaskStatus.FAILED,
            )
        )

        completed_result = await self.db.execute(completed_tasks)
        failed_result = await self.db.execute(failed_tasks)

        completed_count = completed_result.scalar() or 0
        failed_count = failed_result.scalar() or 0

        total_tasks = completed_count + failed_count
        success_rate = (completed_count / total_tasks * 100) if total_tasks > 0 else 100

        # Calculate average completion time
        completion_times_query = select(Task.started_at, Task.completed_at).where(
            and_(
                Task.completed_at.between(start_date, end_date),
                Task.status == TaskStatus.COMPLETED,
                Task.started_at.isnot(None),
            )
        )

        times_result = await self.db.execute(completion_times_query)
        times = times_result.all()

        completion_times = [
            (task.completed_at - task.started_at).total_seconds() / 3600
            for task in times
            if task.completed_at and task.started_at
        ]

        avg_completion_time = statistics.mean(completion_times) if completion_times else 0.0

        return {
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "success_rate": round(success_rate, 2),
            "average_completion_hours": round(avg_completion_time, 2),
            "daily_throughput": round(completed_count / max((end_date - start_date).days, 1), 2),
        }

    async def _calculate_quality_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate quality improvement metrics."""
        # Query for defect density
        total_findings = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.created_at.between(start_date, end_date),
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        critical_findings = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.created_at.between(start_date, end_date),
                VulnerabilityFinding.severity == VulnerabilitySeverity.CRITICAL,
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        total_result = await self.db.execute(total_findings)
        critical_result = await self.db.execute(critical_findings)

        total_count = total_result.scalar() or 0
        critical_count = critical_result.scalar() or 0

        # Calculate severity distribution
        severity_dist_query = (
            select(
                VulnerabilityFinding.severity,
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(
                and_(
                    VulnerabilityFinding.created_at.between(start_date, end_date),
                    VulnerabilityFinding.is_deleted.is_(False),
                )
            )
            .group_by(VulnerabilityFinding.severity)
        )

        severity_result = await self.db.execute(severity_dist_query)
        severity_distribution = {finding.severity.value: finding.count for finding in severity_result.all()}

        return {
            "total_defects": total_count,
            "critical_defects": critical_count,
            "defect_density": round(total_count / max((end_date - start_date).days, 1), 2),
            "critical_rate": round((critical_count / total_count * 100) if total_count > 0 else 0, 2),
            "severity_distribution": severity_distribution,
        }

    async def _calculate_remediation_effectiveness(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate remediation effectiveness metrics."""
        # Query for remediation times
        remediated_findings = select(
            VulnerabilityFinding.severity,
            VulnerabilityFinding.created_at,
            VulnerabilityFinding.updated_at,
        ).where(
            and_(
                VulnerabilityFinding.updated_at.between(start_date, end_date),
                VulnerabilityFinding.status == "resolved",
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(remediated_findings)
        findings = result.all()

        remediation_times = defaultdict(list)
        for finding in findings:
            if finding.updated_at and finding.created_at:
                time_to_fix = (finding.updated_at - finding.created_at).total_seconds() / 86400  # days
                remediation_times[finding.severity.value].append(time_to_fix)

        avg_remediation_times = {
            severity: round(statistics.mean(times), 2) if times else 0 for severity, times in remediation_times.items()
        }

        all_times = [time for times in remediation_times.values() for time in times]
        overall_avg = statistics.mean(all_times) if all_times else 0

        return {
            "total_remediated": len(findings),
            "average_remediation_days": round(overall_avg, 2),
            "by_severity": avg_remediation_times,
            "remediation_rate": round(len(findings) / max((end_date - start_date).days, 1), 2),
        }

    async def _calculate_compliance_achievements(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Calculate compliance achievement metrics."""
        # Query for compliance-related scans
        compliance_scans = select(func.count(Scan.id)).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.scan_type == "compliance",
                Scan.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(compliance_scans)
        compliance_scan_count = result.scalar() or 0

        # Query for passed vs failed compliance checks
        passed_checks = select(func.count(SecurityScan.id)).where(
            and_(
                SecurityScan.created_at.between(start_date, end_date),
                SecurityScan.status == "passed",
                SecurityScan.is_deleted.is_(False),
            )
        )

        failed_checks = select(func.count(SecurityScan.id)).where(
            and_(
                SecurityScan.created_at.between(start_date, end_date),
                SecurityScan.status == "failed",
                SecurityScan.is_deleted.is_(False),
            )
        )

        passed_result = await self.db.execute(passed_checks)
        failed_result = await self.db.execute(failed_checks)

        passed_count = passed_result.scalar() or 0
        failed_count = failed_result.scalar() or 0

        total_checks = passed_count + failed_count
        compliance_rate = (passed_count / total_checks * 100) if total_checks > 0 else 100

        return {
            "compliance_scans": compliance_scan_count,
            "passed_checks": passed_count,
            "failed_checks": failed_count,
            "compliance_rate": round(compliance_rate, 2),
            "daily_compliance_scans": round(compliance_scan_count / max((end_date - start_date).days, 1), 2),
        }

    async def _calculate_implementation_costs(
        self, start_date: datetime, end_date: datetime, cost_data: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate implementation costs."""
        # Estimate based on activity
        days = max((end_date - start_date).days, 1)

        # Query for developer hours (estimated from activity)
        activity_query = select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.created_at.between(start_date, end_date),
                AuditLog.action.in_(["scan.create", "vulnerability.review", "report.generate"]),
            )
        )

        result = await self.db.execute(activity_query)
        activities = result.scalar() or 0

        # Estimate hours based on activities (rough estimate)
        estimated_hours = activities * 0.25  # 15 minutes per activity

        return {
            "tool_licensing": cost_data["tool_licensing_cost"] * (days / 365),
            "developer_time": estimated_hours * cost_data["hourly_developer_rate"],
            "training": cost_data["training_cost_per_person"] * 10,  # Assume 10 people trained
            "infrastructure": 1000.0 * (days / 30),  # Monthly infrastructure cost
        }

    async def _calculate_cost_avoidance(
        self, start_date: datetime, end_date: datetime, cost_data: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate cost avoidance from prevented issues."""
        # Query for prevented incidents
        prevented_criticals = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.created_at.between(start_date, end_date),
                VulnerabilityFinding.severity == VulnerabilitySeverity.CRITICAL,
                VulnerabilityFinding.status == "resolved",
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(prevented_criticals)
        critical_count = result.scalar() or 0

        # Estimate prevented incidents (assume 10% of criticals would become incidents)
        prevented_incidents = critical_count * 0.1

        return {
            "prevented_incidents": prevented_incidents * cost_data["incident_cost"],
            "avoided_emergency_fixes": critical_count * cost_data["bug_fix_cost"] * 2,  # Emergency fixes cost 2x
            "compliance_penalties_avoided": (50000.0 if critical_count > 0 else 0),  # Assume potential penalty
        }

    async def _calculate_productivity_gains(
        self, start_date: datetime, end_date: datetime, cost_data: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate productivity gains from improved processes."""
        # Query for automation metrics
        auto_scans = select(func.count(Scan.id)).where(
            and_(
                Scan.created_at.between(start_date, end_date),
                Scan.scan_type.in_(["automated", "scheduled"]),
                Scan.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(auto_scans)
        auto_scan_count = result.scalar() or 0

        # Estimate time saved (2 hours per automated scan vs manual)
        hours_saved = auto_scan_count * 2

        return {
            "automation_savings": hours_saved * cost_data["hourly_developer_rate"],
            "reduced_rework": auto_scan_count * 0.5 * cost_data["hourly_developer_rate"],  # 30 min saved per scan
            "faster_resolution": auto_scan_count * 0.25 * cost_data["hourly_developer_rate"],  # 15 min saved
        }

    async def _calculate_quality_improvements(
        self, start_date: datetime, end_date: datetime, cost_data: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate value from quality improvements."""
        # Query for resolved issues
        resolved_issues = select(func.count(VulnerabilityFinding.id)).where(
            and_(
                VulnerabilityFinding.updated_at.between(start_date, end_date),
                VulnerabilityFinding.status == "resolved",
                VulnerabilityFinding.is_deleted.is_(False),
            )
        )

        result = await self.db.execute(resolved_issues)
        resolved_count = result.scalar() or 0

        # Estimate value from resolved issues
        bug_prevention_value = resolved_count * cost_data["bug_fix_cost"] * 0.3  # 30% would become bugs

        return {
            "bug_prevention": bug_prevention_value,
            "reduced_technical_debt": resolved_count * cost_data["hourly_developer_rate"] * 2,  # 2 hours per issue
            "improved_maintainability": resolved_count
            * cost_data["hourly_developer_rate"]
            * 0.5,  # 30 min ongoing savings
        }
