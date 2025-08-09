"""
Base chart generator for creating visualizations.

This module provides Chart.js configuration generation for
client-side rendering in HTML reports.
"""

import json
import logging
import threading
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..security import OutputEncoder

logger = logging.getLogger(__name__)


class ChartType(Enum):
    """Supported chart types."""

    PIE = "pie"
    DOUGHNUT = "doughnut"
    BAR = "bar"
    HORIZONTAL_BAR = "horizontalBar"
    LINE = "line"
    RADAR = "radar"
    GAUGE = "gauge"
    HEATMAP = "heatmap"


class ChartGenerator:
    """
    Generates Chart.js configurations for various chart types.

    Creates secure, client-side chart configurations that can be
    embedded in HTML reports.
    """

    # Default color schemes
    RISK_COLORS = {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#fbc02d",
        "low": "#388e3c",
        "minimal": "#81c784",
    }

    TREND_COLORS = {"improving": "#4caf50", "stable": "#ff9800", "degrading": "#f44336", "unknown": "#9e9e9e"}

    DEFAULT_COLORS = [
        "#1976d2",
        "#388e3c",
        "#d32f2f",
        "#f57c00",
        "#7b1fa2",
        "#00796b",
        "#5d4037",
        "#455a64",
        "#e91e63",
        "#00bcd4",
        "#ff5722",
        "#795548",
    ]

    def __init__(self) -> None:
        """Initialize chart generator."""
        self.encoder = OutputEncoder()
        self._chart_id_counter = 0
        self._chart_id_lock = threading.Lock()

    def generate_pie_chart(self, data: Dict[str, Any], title: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate pie chart configuration.

        Args:
            data: Dictionary with 'labels' and 'values' keys
            title: Optional chart title

        Returns:
            Chart.js configuration
        """
        config = {
            "type": ChartType.PIE.value,
            "data": {
                "labels": self._encode_labels(data.get("labels", [])),
                "datasets": [
                    {
                        "data": data.get("values", []),
                        "backgroundColor": self._get_colors(data.get("colors"), len(data.get("labels", []))),
                        "borderWidth": 1,
                        "borderColor": "#fff",
                    }
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {
                    "legend": {"position": "bottom", "labels": {"padding": 15, "font": {"size": 12}}},
                    "tooltip": {"callbacks": {"label": self._get_percentage_tooltip()}},
                },
            },
        }

        if title:
            config["options"]["plugins"]["title"] = {
                "display": True,
                "text": self.encoder.encode_for_javascript(title),
                "font": {"size": 16},
            }

        return config

    def generate_bar_chart(
        self, data: Dict[str, Any], title: Optional[str] = None, horizontal: bool = False
    ) -> Dict[str, Any]:
        """
        Generate bar chart configuration.

        Args:
            data: Dictionary with 'labels' and 'values' keys
            title: Optional chart title
            horizontal: Whether to create horizontal bars

        Returns:
            Chart.js configuration
        """
        chart_type = ChartType.HORIZONTAL_BAR if horizontal else ChartType.BAR

        config = {
            "type": chart_type.value,
            "data": {
                "labels": self._encode_labels(data.get("labels", [])),
                "datasets": [
                    {
                        "label": data.get("label", "Value"),
                        "data": data.get("values", []),
                        "backgroundColor": data.get("color", self.DEFAULT_COLORS[0]),
                        "borderColor": data.get("borderColor", self.DEFAULT_COLORS[0]),
                        "borderWidth": 1,
                    }
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {"legend": {"display": False}},
                "scales": {
                    "x": {"beginAtZero": True, "ticks": {"autoSkip": True, "maxRotation": 45, "minRotation": 0}},
                    "y": {"beginAtZero": True},
                },
            },
        }

        if horizontal:
            # Swap axis configuration for horizontal bars
            config["options"]["indexAxis"] = "y"

        if title:
            config["options"]["plugins"]["title"] = {
                "display": True,
                "text": self.encoder.encode_for_javascript(title),
                "font": {"size": 16},
            }

        return config

    def generate_line_chart(self, data: Dict[str, Any], title: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate line chart configuration for trends.

        Args:
            data: Dictionary with 'labels' and 'datasets' keys
            title: Optional chart title

        Returns:
            Chart.js configuration
        """
        datasets = []

        for i, dataset in enumerate(data.get("datasets", [])):
            color = dataset.get("color", self.DEFAULT_COLORS[i % len(self.DEFAULT_COLORS)])
            datasets.append(
                {
                    "label": self.encoder.encode_for_javascript(dataset.get("label", f"Series {i+1}")),
                    "data": dataset.get("data", []),
                    "borderColor": color,
                    "backgroundColor": color + "20",  # Add transparency
                    "tension": 0.1,
                    "fill": dataset.get("fill", False),
                }
            )

        config = {
            "type": ChartType.LINE.value,
            "data": {"labels": self._encode_labels(data.get("labels", [])), "datasets": datasets},
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {"legend": {"position": "bottom"}},
                "scales": {
                    "x": {
                        "display": True,
                        "title": {
                            "display": bool(data.get("xLabel")),
                            "text": self.encoder.encode_for_javascript(data.get("xLabel", "")),
                        },
                    },
                    "y": {
                        "display": True,
                        "beginAtZero": True,
                        "title": {
                            "display": bool(data.get("yLabel")),
                            "text": self.encoder.encode_for_javascript(data.get("yLabel", "")),
                        },
                    },
                },
            },
        }

        if title:
            config["options"]["plugins"]["title"] = {
                "display": True,
                "text": self.encoder.encode_for_javascript(title),
                "font": {"size": 16},
            }

        return config

    def generate_gauge_chart(
        self, value: float, min_value: float = 0, max_value: float = 100, thresholds: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Generate gauge chart configuration.

        Args:
            value: Current value to display
            min_value: Minimum value
            max_value: Maximum value
            thresholds: Dictionary of threshold names to values

        Returns:
            Custom gauge configuration for rendering
        """
        if thresholds is None:
            thresholds = {"critical": 60, "warning": 80, "good": 90}

        # Determine color based on value and thresholds
        color = self._get_gauge_color(value, thresholds)

        # Create gauge-specific configuration
        config = {
            "type": "custom-gauge",
            "data": {"value": value, "min": min_value, "max": max_value, "label": f"{value:.1f}%"},
            "options": {
                "color": color,
                "thresholds": thresholds,
                "backgroundColor": "#e0e0e0",
                "thickness": 0.3,
                "animationDuration": 1000,
            },
        }

        return config

    def generate_radar_chart(self, data: Dict[str, Any], title: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate radar chart for multi-dimensional analysis.

        Args:
            data: Dictionary with 'labels' and 'datasets' keys
            title: Optional chart title

        Returns:
            Chart.js configuration
        """
        datasets = []

        for i, dataset in enumerate(data.get("datasets", [])):
            color = dataset.get("color", self.DEFAULT_COLORS[i % len(self.DEFAULT_COLORS)])
            datasets.append(
                {
                    "label": self.encoder.encode_for_javascript(dataset.get("label", f"Series {i+1}")),
                    "data": dataset.get("data", []),
                    "borderColor": color,
                    "backgroundColor": color + "40",  # Add transparency
                    "pointBackgroundColor": color,
                    "pointBorderColor": "#fff",
                    "pointHoverBackgroundColor": "#fff",
                    "pointHoverBorderColor": color,
                }
            )

        config = {
            "type": ChartType.RADAR.value,
            "data": {"labels": self._encode_labels(data.get("labels", [])), "datasets": datasets},
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {"legend": {"position": "bottom"}},
                "scales": {
                    "r": {
                        "beginAtZero": True,
                        "max": data.get("maxValue", 100),
                        "ticks": {"stepSize": data.get("stepSize", 20)},
                    }
                },
            },
        }

        if title:
            config["options"]["plugins"]["title"] = {
                "display": True,
                "text": self.encoder.encode_for_javascript(title),
                "font": {"size": 16},
            }

        return config

    def generate_risk_distribution_chart(self, risk_data: Dict[str, int]) -> Dict[str, Any]:
        """
        Generate specialized risk distribution chart.

        Args:
            risk_data: Dictionary mapping risk levels to counts

        Returns:
            Chart configuration
        """
        # Order risk levels
        ordered_risks = ["critical", "high", "medium", "low", "minimal"]
        labels = []
        values = []
        colors = []

        for risk in ordered_risks:
            if risk in risk_data and risk_data[risk] > 0:
                labels.append(risk.title())
                values.append(risk_data[risk])
                colors.append(self.RISK_COLORS.get(risk, "#666"))

        return self.generate_doughnut_chart(
            {"labels": labels, "values": values, "colors": colors}, title="Risk Distribution"
        )

    def generate_doughnut_chart(self, data: Dict[str, Any], title: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate doughnut chart (pie with center cutout).

        Args:
            data: Dictionary with 'labels' and 'values' keys
            title: Optional chart title

        Returns:
            Chart.js configuration
        """
        config = self.generate_pie_chart(data, title)
        config["type"] = ChartType.DOUGHNUT.value

        # Add center text plugin configuration
        if "plugins" not in config["options"]:
            config["options"]["plugins"] = {}

        config["options"]["cutout"] = "60%"

        return config

    def create_chart_container(
        self, chart_config: Dict[str, Any], container_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a complete chart container with HTML and JavaScript.

        Args:
            chart_config: Chart.js configuration
            container_id: Optional container ID

        Returns:
            Dictionary with HTML and JavaScript code
        """
        if not container_id:
            with self._chart_id_lock:
                self._chart_id_counter += 1
                container_id = f"chart-{self._chart_id_counter}"

        # Encode configuration for safe embedding
        config_json = self.encoder.encode_for_javascript(json.dumps(chart_config, separators=(",", ":")))

        return {
            "id": container_id,
            "html": f'<div class="chart-container"><canvas id="{container_id}"></canvas></div>',
            "script": f"""
(function() {{
    const ctx = document.getElementById('{container_id}').getContext('2d');
    const config = JSON.parse('{config_json}');
    new Chart(ctx, config);
}})();
""",
            "config": chart_config,
        }

    # Helper methods
    def _encode_labels(self, labels: List[Any]) -> List[str]:
        """Encode labels for safe display."""
        return [self.encoder.encode_for_javascript(str(label)) for label in labels]

    def _get_colors(self, custom_colors: Optional[List[str]], count: int) -> List[str]:
        """Get color array for charts."""
        if custom_colors and len(custom_colors) >= count:
            return custom_colors[:count]

        # Use default colors, cycling if needed
        colors = []
        for i in range(count):
            colors.append(self.DEFAULT_COLORS[i % len(self.DEFAULT_COLORS)])

        return colors

    def _get_gauge_color(self, value: float, thresholds: Dict[str, float]) -> str:
        """Determine gauge color based on value and thresholds."""
        if value >= thresholds.get("good", 90):
            return self.RISK_COLORS["low"]  # Green
        elif value >= thresholds.get("warning", 80):
            return self.TREND_COLORS["stable"]  # Orange
        elif value >= thresholds.get("critical", 60):
            return self.RISK_COLORS["high"]  # Orange-red
        else:
            return self.RISK_COLORS["critical"]  # Red

    def _get_percentage_tooltip(self) -> str:
        """Get tooltip callback for percentage display."""
        return """function(context) {
            let label = context.label || '';
            if (label) {
                label += ': ';
            }
            const value = context.parsed;
            const total = context.dataset.data.reduce((a, b) => a + b, 0);
            const percentage = ((value / total) * 100).toFixed(1);
            return label + percentage + '%';
        }"""
