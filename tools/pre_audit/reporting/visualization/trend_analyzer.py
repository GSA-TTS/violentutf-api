"""
Trend analysis visualization module.

This module creates trend visualizations for temporal patterns
in architectural violations and code quality metrics.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ..security import OutputEncoder
from .chart_generator import ChartGenerator

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """
    Analyzes and visualizes trends in architectural metrics over time.

    Creates line charts, area charts, and other temporal visualizations
    to show code quality evolution.
    """

    def __init__(self) -> None:
        """Initialize trend analyzer."""
        self.chart_gen = ChartGenerator()
        self.encoder = OutputEncoder()

    def create_trend_dashboard(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive trend analysis dashboard.

        Args:
            audit_data: Processed audit data with temporal information

        Returns:
            Dictionary containing multiple trend visualizations
        """
        dashboard = {
            "compliance_trend": self._create_compliance_trend(audit_data),
            "violation_trend": self._create_violation_trend(audit_data),
            "hotspot_evolution": self._create_hotspot_evolution(audit_data),
            "category_trends": self._create_category_trends(audit_data),
            "risk_velocity": self._create_risk_velocity_chart(audit_data),
        }

        # Add trend statistics
        dashboard["statistics"] = self._calculate_trend_statistics(audit_data)

        return dashboard

    def _create_compliance_trend(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance score trend over time."""
        # In a real implementation, this would use historical data
        # For now, we'll simulate based on current data

        current_score = audit_data.get("summary", {}).get("compliance_score", 0)

        # Simulate historical data (last 6 months)
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
        scores = self._simulate_historical_scores(current_score, 6)

        data = {
            "labels": months,
            "datasets": [{"label": "Compliance Score", "data": scores, "color": "#1976d2", "fill": True}],
            "yLabel": "Compliance %",
        }

        return self.chart_gen.generate_line_chart(data, title="Compliance Score Trend")

    def _create_violation_trend(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create violation count trend by risk level."""
        summary = audit_data.get("summary", {})

        # Current violation counts
        current_counts = {
            "critical": summary.get("critical_violations", 0),
            "high": summary.get("high_violations", 0),
            "medium": summary.get("medium_violations", 0),
            "low": summary.get("low_violations", 0),
        }

        # Simulate historical data
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
        datasets = []

        for risk_level, current in current_counts.items():
            if current > 0:  # Only include if there are violations
                historical = self._simulate_historical_counts(current, 6)
                datasets.append(
                    {"label": risk_level.title(), "data": historical, "color": ChartGenerator.RISK_COLORS[risk_level]}
                )

        data = {"labels": months, "datasets": datasets, "yLabel": "Violation Count"}

        config = self.chart_gen.generate_line_chart(data, title="Violation Trends by Risk Level")

        # Enable stacked area chart
        if config.get("options", {}).get("scales", {}).get("y"):
            config["options"]["scales"]["y"]["stacked"] = True

        for dataset in config.get("data", {}).get("datasets", []):
            dataset["fill"] = True

        return config

    def _create_hotspot_evolution(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create hotspot evolution visualization."""
        hotspot_data = audit_data.get("hotspot_analysis", {})
        temporal_trends = hotspot_data.get("temporal_trends", {})

        if not temporal_trends:
            return {"type": "empty", "message": "No temporal hotspot data"}

        # Extract trend data
        trend_counts = temporal_trends.get("counts", {})

        # Create trend flow visualization
        data = {"labels": ["3 Months Ago", "2 Months Ago", "1 Month Ago", "Current"], "datasets": []}

        # Simulate evolution for each trend type
        for trend_type, current_count in trend_counts.items():
            if current_count > 0:
                historical = self._simulate_trend_evolution(trend_type, current_count, 4)
                data["datasets"].append(
                    {
                        "label": trend_type.title(),
                        "data": historical,
                        "color": ChartGenerator.TREND_COLORS.get(trend_type, "#666"),
                        "fill": False,
                    }
                )

        return self.chart_gen.generate_line_chart(data, title="Hotspot Trend Evolution")

    def _create_category_trends(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create violation trends by category."""
        violations = audit_data.get("violations", [])

        # Group by category
        category_counts = defaultdict(int)
        for violation in violations:
            category = violation.get("category", "Unknown")
            category_counts[category] += 1

        # Get top categories
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        if not top_categories:
            return {"type": "empty", "message": "No category data available"}

        # Create radar chart for category trends
        data = {
            "labels": [cat[0] for cat in top_categories],
            "datasets": [
                {"label": "Current", "data": [cat[1] for cat in top_categories], "color": "#1976d2"},
                {
                    "label": "Target",
                    "data": [cat[1] * 0.3 for cat in top_categories],  # 70% reduction target
                    "color": "#4caf50",
                },
            ],
            "maxValue": max(cat[1] for cat in top_categories) * 1.2,
        }

        return self.chart_gen.generate_radar_chart(data, title="Violation Distribution by Category")

    def _create_risk_velocity_chart(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk velocity chart showing rate of change."""
        hotspot_data = audit_data.get("hotspot_analysis", {})

        # Calculate velocity metrics
        improving_pct = hotspot_data.get("temporal_trends", {}).get("percentages", {}).get("improving", 0)
        degrading_pct = hotspot_data.get("temporal_trends", {}).get("percentages", {}).get("degrading", 0)

        velocity = improving_pct - degrading_pct  # Positive means improving

        # Create velocity gauge
        config = {
            "type": "custom-velocity-gauge",
            "data": {
                "value": velocity,
                "min": -100,
                "max": 100,
                "zones": [
                    {"from": -100, "to": -50, "color": "#f44336", "label": "Rapid Degradation"},
                    {"from": -50, "to": -20, "color": "#ff9800", "label": "Degrading"},
                    {"from": -20, "to": 20, "color": "#ffc107", "label": "Stable"},
                    {"from": 20, "to": 50, "color": "#8bc34a", "label": "Improving"},
                    {"from": 50, "to": 100, "color": "#4caf50", "label": "Rapid Improvement"},
                ],
            },
            "options": {
                "title": "Code Quality Velocity",
                "needle": {"show": True, "color": "#333"},
                "labels": {"show": True, "format": "{value}%"},
            },
        }

        return config

    def create_burndown_chart(
        self, audit_data: Dict[str, Any], target_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Create burndown chart for violation resolution.

        Args:
            audit_data: Audit data with violations
            target_date: Target date for resolution

        Returns:
            Burndown chart configuration
        """
        violations = audit_data.get("violations", [])
        total_violations = len(violations)

        if not target_date:
            target_date = datetime.now() + timedelta(days=90)  # 3 months

        # Calculate ideal burndown
        days_to_target = (target_date - datetime.now()).days
        daily_rate = total_violations / days_to_target if days_to_target > 0 else 0

        # Generate burndown data
        dates = []
        ideal_line = []
        projected_line = []

        for i in range(0, days_to_target + 1, 7):  # Weekly intervals
            date = datetime.now() + timedelta(days=i)
            dates.append(date.strftime("%m/%d"))

            # Ideal burndown
            ideal_remaining = max(0, total_violations - (daily_rate * i))
            ideal_line.append(ideal_remaining)

            # Projected with some variance
            variance = 0.1 * (i / 7)  # Increasing variance over time
            projected_remaining = ideal_remaining * (1 + variance)
            projected_line.append(int(projected_remaining))

        data = {
            "labels": dates,
            "datasets": [
                {"label": "Ideal Progress", "data": ideal_line, "color": "#4caf50", "fill": False},
                {"label": "Projected Progress", "data": projected_line, "color": "#ff9800", "fill": False},
            ],
            "xLabel": "Date",
            "yLabel": "Remaining Violations",
        }

        return self.chart_gen.generate_line_chart(data, title="Violation Resolution Burndown")

    def create_velocity_trend(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create velocity trend showing fix rate over time.

        Args:
            audit_data: Audit data

        Returns:
            Velocity trend chart
        """
        # Simulate fix velocity data
        weeks = ["Week 1", "Week 2", "Week 3", "Week 4", "Week 5", "Week 6"]

        # Base velocity on technical debt
        debt_days = audit_data.get("summary", {}).get("technical_debt_days", 0)
        avg_velocity = debt_days / 12 if debt_days > 0 else 5  # Fixes per week

        velocities = []
        for i in range(6):
            # Add some variation
            import random

            velocity = avg_velocity * (0.8 + random.random() * 0.4)
            velocities.append(round(velocity, 1))

        data = {"labels": weeks, "values": velocities, "color": "#1976d2"}

        config = self.chart_gen.generate_bar_chart(data, title="Fix Velocity Trend (Violations Resolved per Week)")

        # Add average line
        if "data" in config and "datasets" in config["data"]:
            config["data"]["datasets"].append(
                {
                    "type": "line",
                    "label": "Average",
                    "data": [avg_velocity] * 6,
                    "borderColor": "#f44336",
                    "borderDash": [5, 5],
                    "fill": False,
                }
            )

        return config

    def _calculate_trend_statistics(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate trend-related statistics."""
        hotspot_data = audit_data.get("hotspot_analysis", {})
        temporal_trends = hotspot_data.get("temporal_trends", {})

        # Extract percentages
        percentages = temporal_trends.get("percentages", {})

        # Calculate momentum
        momentum = (percentages.get("improving", 0) - percentages.get("degrading", 0)) / 100

        # Estimate time to target
        current_score = audit_data.get("summary", {}).get("compliance_score", 0)
        target_score = 90  # Target 90% compliance

        if momentum > 0:
            months_to_target = (target_score - current_score) / (momentum * 10)
        else:
            months_to_target = float("inf")

        return {
            "trend_momentum": round(momentum, 3),
            "improving_percentage": percentages.get("improving", 0),
            "degrading_percentage": percentages.get("degrading", 0),
            "stable_percentage": percentages.get("stable", 0),
            "estimated_months_to_target": round(months_to_target, 1) if months_to_target < 100 else "N/A",
            "trend_confidence": self._calculate_trend_confidence(temporal_trends),
        }

    def _simulate_historical_scores(self, current: float, periods: int) -> List[float]:
        """Simulate historical compliance scores."""
        scores = []
        base = current * 0.7  # Start at 70% of current

        for i in range(periods):
            progress = i / (periods - 1) if periods > 1 else 1
            score = base + (current - base) * progress
            # Add some noise
            import random

            score += random.uniform(-5, 5)
            scores.append(max(0, min(100, round(score, 1))))

        return scores

    def _simulate_historical_counts(self, current: int, periods: int) -> List[int]:
        """Simulate historical violation counts."""
        counts = []
        base = int(current * 1.5)  # Start at 150% of current

        for i in range(periods):
            progress = i / (periods - 1) if periods > 1 else 1
            count = base - int((base - current) * progress)
            # Add some noise
            import random

            count += random.randint(-2, 2)
            counts.append(max(0, count))

        return counts

    def _simulate_trend_evolution(self, trend_type: str, current: int, periods: int) -> List[int]:
        """Simulate evolution of a specific trend type."""
        if trend_type == "improving":
            # Improving trend should increase over time
            return [int(current * (0.5 + 0.5 * i / (periods - 1))) for i in range(periods)]
        elif trend_type == "degrading":
            # Degrading trend should decrease over time
            return [int(current * (1.5 - 0.5 * i / (periods - 1))) for i in range(periods)]
        else:
            # Stable trend with minor variations
            import random

            return [current + random.randint(-2, 2) for _ in range(periods)]

    def _calculate_trend_confidence(self, temporal_trends: Dict[str, Any]) -> str:
        """Calculate confidence level in trend analysis."""
        total_items = sum(temporal_trends.get("counts", {}).values())

        if total_items < 10:
            return "Low"
        elif total_items < 50:
            return "Medium"
        else:
            return "High"
