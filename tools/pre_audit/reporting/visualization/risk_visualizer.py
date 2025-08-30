"""
Risk visualization module for architectural audit reports.

This module provides specialized visualizations for risk assessment
and distribution analysis.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..security import OutputEncoder
from .chart_generator import ChartGenerator, ChartType

logger = logging.getLogger(__name__)


class RiskVisualizer:
    """
    Creates risk-focused visualizations for audit reports.

    Specializes in risk distribution, severity analysis, and
    risk trend visualization.
    """

    def __init__(self) -> None:
        """Initialize risk visualizer."""
        self.chart_gen = ChartGenerator()
        self.encoder = OutputEncoder()

    def create_risk_dashboard(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive risk dashboard with multiple visualizations.

        Args:
            audit_data: Processed audit data

        Returns:
            Dictionary containing multiple chart configurations
        """
        dashboard = {
            "compliance_gauge": self._create_compliance_gauge(audit_data),
            "risk_distribution": self._create_risk_distribution(audit_data),
            "risk_by_category": self._create_risk_by_category(audit_data),
            "risk_timeline": self._create_risk_timeline(audit_data),
            "risk_heatmap": self._create_risk_heatmap(audit_data),
        }

        # Add summary statistics
        dashboard["statistics"] = self._calculate_risk_statistics(audit_data)

        return dashboard

    def _create_compliance_gauge(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance score gauge chart."""
        score = audit_data.get("summary", {}).get("compliance_score", 0)

        return self.chart_gen.generate_gauge_chart(
            value=score,
            min_value=0,
            max_value=100,
            thresholds={"critical": 50, "warning": 70, "good": 85},
        )

    def _create_risk_distribution(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk distribution doughnut chart."""
        summary = audit_data.get("summary", {})

        risk_counts = {
            "critical": summary.get("critical_violations", 0),
            "high": summary.get("high_violations", 0),
            "medium": summary.get("medium_violations", 0),
            "low": summary.get("low_violations", 0),
        }

        # Filter out zero values
        filtered_risks = {k: v for k, v in risk_counts.items() if v > 0}

        if not filtered_risks:
            return {"type": "empty", "message": "No violations found"}

        return self.chart_gen.generate_risk_distribution_chart(filtered_risks)

    def _create_risk_by_category(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk by category bar chart."""
        violations = audit_data.get("violations", [])

        # Group by category and risk level
        category_risks = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})

        for violation in violations:
            category = violation.get("category", "Unknown")
            risk_level = violation.get("risk_level", "unknown").lower()

            if risk_level in category_risks[category]:
                category_risks[category][risk_level] += 1

        # Prepare data for stacked bar chart
        categories = list(category_risks.keys())
        datasets = []

        for risk_level, color in [
            ("critical", ChartGenerator.RISK_COLORS["critical"]),
            ("high", ChartGenerator.RISK_COLORS["high"]),
            ("medium", ChartGenerator.RISK_COLORS["medium"]),
            ("low", ChartGenerator.RISK_COLORS["low"]),
        ]:
            data = [category_risks[cat][risk_level] for cat in categories]
            if any(data):  # Only include if there's data
                datasets.append(
                    {
                        "label": risk_level.title(),
                        "data": data,
                        "backgroundColor": color,
                        "borderColor": color,
                        "borderWidth": 1,
                    }
                )

        config = {
            "type": "bar",
            "data": {"labels": categories, "datasets": datasets},
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Risk Distribution by Category",
                        "font": {"size": 16},
                    },
                    "legend": {"position": "bottom"},
                },
                "scales": {
                    "x": {"stacked": True},
                    "y": {"stacked": True, "beginAtZero": True},
                },
            },
        }

        return config

    def _create_risk_timeline(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk trend timeline if temporal data available."""
        # Check for temporal data from hotspot analysis
        hotspot_data = audit_data.get("hotspot_analysis", {})
        temporal_trends = hotspot_data.get("temporal_trends", {})

        if not temporal_trends:
            return {"type": "empty", "message": "No temporal data available"}

        # Extract trend percentages
        percentages = temporal_trends.get("percentages", {})

        data = {
            "labels": ["Improving", "Stable", "Degrading"],
            "values": [
                percentages.get("improving", 0),
                percentages.get("stable", 0),
                percentages.get("degrading", 0),
            ],
            "colors": [
                ChartGenerator.TREND_COLORS["improving"],
                ChartGenerator.TREND_COLORS["stable"],
                ChartGenerator.TREND_COLORS["degrading"],
            ],
        }

        return self.chart_gen.generate_doughnut_chart(data, title="Temporal Risk Trends")

    def _create_risk_heatmap(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk heatmap for top files."""
        violations = audit_data.get("violations", [])

        # Aggregate risk scores by file
        file_risks = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})

        for violation in violations:
            file_path = violation.get("file_path", "Unknown")
            risk_level = violation.get("risk_level", "unknown").lower()

            if risk_level in ["critical", "high", "medium", "low"]:
                file_risks[file_path][risk_level] += 1
                file_risks[file_path]["total"] += 1

        # Calculate weighted risk scores
        risk_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        file_scores = []

        for file_path, risks in file_risks.items():
            score = sum(risks[level] * risk_weights[level] for level in risk_weights)
            file_scores.append((file_path, score, risks))

        # Sort by score and take top 20
        file_scores.sort(key=lambda x: x[1], reverse=True)
        top_files = file_scores[:20]

        if not top_files:
            return {"type": "empty", "message": "No file risk data available"}

        # Prepare heatmap data
        labels = [self._truncate_path(f[0]) for f in top_files]
        values = [f[1] for f in top_files]

        # Normalize values to 0-100 scale
        max_score = max(values) if values else 1
        normalized_values = [int(v / max_score * 100) for v in values]

        config = {
            "type": "custom-heatmap",
            "data": {
                "labels": labels,
                "values": normalized_values,
                "rawValues": values,
                "details": [f[2] for f in top_files],
            },
            "options": {
                "title": "File Risk Heatmap (Top 20)",
                "colorScale": "Reds",
                "showValues": True,
                "tooltip": {
                    "enabled": True,
                    "format": "File: {label}<br>Risk Score: {rawValue}<br>Critical: {detail.critical}, High: {detail.high}",
                },
            },
        }

        return config

    def create_risk_matrix(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create risk matrix visualization (likelihood vs impact).

        Args:
            violations: List of violation dictionaries

        Returns:
            Risk matrix configuration
        """
        # Define matrix quadrants
        matrix = {
            "high_high": [],  # High likelihood, high impact
            "high_low": [],  # High likelihood, low impact
            "low_high": [],  # Low likelihood, high impact
            "low_low": [],  # Low likelihood, low impact
        }

        # Categorize violations
        for violation in violations:
            risk_level = violation.get("risk_level", "unknown").lower()
            impact = violation.get("impact_assessment", "")

            # Determine likelihood based on violation count in same file
            file_path = violation.get("file_path", "")
            file_violations = [v for v in violations if v.get("file_path") == file_path]
            likelihood = "high" if len(file_violations) > 5 else "low"

            # Determine impact level
            impact_level = "high" if risk_level in ["critical", "high"] else "low"

            # Add to appropriate quadrant
            quadrant = f"{likelihood}_{impact_level}"
            matrix[quadrant].append(violation)

        # Create scatter plot data
        scatter_data = []

        for quadrant, items in matrix.items():
            if items:
                likelihood, impact = quadrant.split("_")
                x_base = 75 if likelihood == "high" else 25
                y_base = 75 if impact == "high" else 25

                # Add some random spread to avoid overlapping
                import random

                for item in items[:10]:  # Limit to 10 per quadrant
                    scatter_data.append(
                        {
                            "x": x_base + random.randint(-15, 15),
                            "y": y_base + random.randint(-15, 15),
                            "label": self._truncate_path(item.get("file_path", ""), 20),
                            "risk": item.get("risk_level", "unknown"),
                        }
                    )

        config = {
            "type": "scatter",
            "data": {
                "datasets": [
                    {
                        "label": "Violations",
                        "data": scatter_data,
                        "backgroundColor": "rgba(255, 99, 132, 0.5)",
                        "borderColor": "rgba(255, 99, 132, 1)",
                        "pointRadius": 6,
                    }
                ]
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Risk Matrix: Likelihood vs Impact",
                        "font": {"size": 16},
                    }
                },
                "scales": {
                    "x": {
                        "title": {"display": True, "text": "Likelihood"},
                        "min": 0,
                        "max": 100,
                        "ticks": {"callback": "function(value) { return value > 50 ? 'High' : 'Low'; }"},
                    },
                    "y": {
                        "title": {"display": True, "text": "Impact"},
                        "min": 0,
                        "max": 100,
                        "ticks": {"callback": "function(value) { return value > 50 ? 'High' : 'Low'; }"},
                    },
                },
            },
        }

        return config

    def _calculate_risk_statistics(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk-related statistics."""
        violations = audit_data.get("violations", [])
        total_violations = len(violations)

        if not violations:
            return {
                "total_violations": 0,
                "average_risk_score": 0,
                "risk_concentration": 0,
                "top_risk_category": "None",
            }

        # Risk score calculation
        risk_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_score = sum(risk_scores.get(v.get("risk_level", "").lower(), 0) for v in violations)

        # Category analysis
        category_counts = defaultdict(int)
        for v in violations:
            category_counts[v.get("category", "Unknown")] += 1

        top_category = max(category_counts.items(), key=lambda x: x[1])[0]

        # File concentration
        file_counts = defaultdict(int)
        for v in violations:
            file_counts[v.get("file_path", "Unknown")] += 1

        # Calculate Gini coefficient for concentration
        counts = sorted(file_counts.values())
        n = len(counts)
        if n > 0:
            cumsum = 0
            for i, count in enumerate(counts):
                cumsum += (n - i) * count
            concentration = (n + 1 - 2 * cumsum / sum(counts)) / n
        else:
            concentration = 0

        return {
            "total_violations": total_violations,
            "average_risk_score": (round(total_score / total_violations, 2) if total_violations > 0 else 0),
            "risk_concentration": round(concentration, 3),
            "top_risk_category": top_category,
            "categories": dict(category_counts),
            "file_distribution": {
                "total_files": len(file_counts),
                "max_violations_per_file": (max(file_counts.values()) if file_counts else 0),
                "average_violations_per_file": (
                    round(sum(file_counts.values()) / len(file_counts), 2) if file_counts else 0
                ),
            },
        }

    def _truncate_path(self, path: str, max_length: int = 30) -> str:
        """Truncate file path for display."""
        if len(path) <= max_length:
            return path

        # Try to keep filename
        parts = path.split("/")
        if parts:
            filename = parts[-1]
            if len(filename) <= max_length - 3:
                return f".../{filename}"

        # Fallback to simple truncation
        return path[: max_length - 3] + "..."
