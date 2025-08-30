"""
Hotspot heatmap visualization for architectural analysis.

This module creates heatmap visualizations for architectural hotspots
identified by the statistical analysis module.
"""

import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..security import OutputEncoder
from .chart_generator import ChartGenerator

logger = logging.getLogger(__name__)


class HotspotHeatmapGenerator:
    """
    Generates heatmap visualizations for architectural hotspots.

    Creates various heatmap representations showing risk concentration,
    complexity distribution, and temporal patterns.
    """

    def __init__(self) -> None:
        """Initialize heatmap generator."""
        self.chart_gen = ChartGenerator()
        self.encoder = OutputEncoder()

    def create_hotspot_heatmap(self, hotspot_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive hotspot heatmap visualization.

        Args:
            hotspot_data: Hotspot analysis data from reporting module

        Returns:
            Heatmap configuration
        """
        hotspots = hotspot_data.get("hotspots", [])

        if not hotspots:
            return {"type": "empty", "message": "No hotspot data available"}

        # Prepare data for heatmap
        heatmap_data = self._prepare_heatmap_data(hotspots)

        config = {
            "type": "custom-heatmap",
            "data": heatmap_data,
            "options": {
                "title": "Architectural Hotspot Heatmap",
                "responsive": True,
                "maintainAspectRatio": False,
                "colorScale": {
                    "type": "sequential",
                    "scheme": "YlOrRd",  # Yellow-Orange-Red
                    "domain": [0, 100],
                    "labels": ["Low Risk", "High Risk"],
                },
                "grid": {"show": True, "color": "#e0e0e0"},
                "tooltip": {
                    "enabled": True,
                    "formatter": self._get_tooltip_formatter(),
                },
                "legend": {"show": True, "position": "right", "title": "Risk Score"},
            },
        }

        return config

    def create_complexity_heatmap(self, hotspot_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create heatmap focused on code complexity.

        Args:
            hotspot_data: Hotspot analysis data

        Returns:
            Complexity heatmap configuration
        """
        hotspots = hotspot_data.get("hotspots", [])

        # Group by directory and aggregate complexity
        dir_complexity = self._aggregate_by_directory(hotspots, "complexity_score")

        if not dir_complexity:
            return {"type": "empty", "message": "No complexity data available"}

        # Create hierarchical structure for treemap
        treemap_data = self._create_treemap_structure(dir_complexity)

        config = {
            "type": "treemap",
            "data": treemap_data,
            "options": {
                "title": "Code Complexity Distribution",
                "colorScale": {
                    "type": "sequential",
                    "scheme": "Blues",
                    "domain": [0, 100],
                },
                "labels": {"show": True, "formatter": "{name}\n{value:.1f}"},
                "tooltip": {"formatter": "Complexity: {value:.1f}<br>Files: {fileCount}"},
            },
        }

        return config

    def create_temporal_heatmap(self, hotspot_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create temporal heatmap showing risk evolution over time.

        Args:
            hotspot_data: Hotspot analysis data with temporal information

        Returns:
            Temporal heatmap configuration
        """
        hotspots = hotspot_data.get("hotspots", [])
        temporal_data = []

        # Extract temporal patterns
        for hotspot in hotspots:
            if "temporal" in hotspot:
                temporal_info = hotspot["temporal"]
                temporal_data.append(
                    {
                        "file": self._truncate_path(hotspot.get("file_path", "")),
                        "weight": temporal_info.get("weight", 0),
                        "trend": temporal_info.get("trend", "unknown"),
                        "age_days": temporal_info.get("average_age_days", 0),
                    }
                )

        if not temporal_data:
            return {"type": "empty", "message": "No temporal data available"}

        # Sort by temporal weight
        temporal_data.sort(key=lambda x: x["weight"], reverse=True)
        temporal_data = temporal_data[:30]  # Top 30

        # Create timeline visualization
        config = {
            "type": "custom-timeline-heatmap",
            "data": {
                "items": temporal_data,
                "timeRange": {
                    "start": 0,
                    "end": max(item["age_days"] for item in temporal_data),
                },
            },
            "options": {
                "title": "Temporal Risk Patterns",
                "xAxis": {"title": "Days Ago", "type": "time"},
                "yAxis": {"title": "Files", "type": "category"},
                "colorScale": {
                    "field": "weight",
                    "scheme": "Viridis",
                    "domain": [0, 1],
                },
                "markers": {
                    "show": True,
                    "size": "weight",
                    "color": "trend",
                    "colorMap": {
                        "improving": "#4caf50",
                        "stable": "#ff9800",
                        "degrading": "#f44336",
                        "unknown": "#9e9e9e",
                    },
                },
            },
        }

        return config

    def create_correlation_heatmap(self, hotspot_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create correlation heatmap between different risk factors.

        Args:
            hotspot_data: Hotspot analysis data

        Returns:
            Correlation matrix heatmap
        """
        hotspots = hotspot_data.get("hotspots", [])

        if len(hotspots) < 3:
            return {
                "type": "empty",
                "message": "Insufficient data for correlation analysis",
            }

        # Extract metrics for correlation
        metrics = {
            "risk_score": [],
            "complexity_score": [],
            "churn_score": [],
            "violation_count": [],
        }

        for hotspot in hotspots:
            for metric in metrics:
                value = hotspot.get(metric, 0)
                # Normalize percentage values
                if metric == "risk_score" and value <= 1:
                    value *= 100
                metrics[metric].append(value)

        # Calculate correlations
        correlation_matrix = self._calculate_correlations(metrics)

        config = {
            "type": "heatmap",
            "data": {
                "rows": list(metrics.keys()),
                "columns": list(metrics.keys()),
                "values": correlation_matrix,
            },
            "options": {
                "title": "Risk Factor Correlations",
                "colorScale": {
                    "type": "diverging",
                    "scheme": "RdBu",
                    "domain": [-1, 1],
                    "midpoint": 0,
                },
                "cells": {"show": True, "format": ".2f"},
                "annotations": {
                    "show": True,
                    "threshold": 0.5,
                    "text": "Strong correlation",
                },
            },
        }

        return config

    def create_module_dependency_heatmap(
        self, hotspot_data: Dict[str, Any], audit_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create heatmap showing module dependencies and risk propagation.

        Args:
            hotspot_data: Hotspot analysis data
            audit_data: Full audit data for dependency information

        Returns:
            Module dependency heatmap
        """
        # Extract module structure from file paths
        modules = self._extract_module_structure(hotspot_data.get("hotspots", []))

        # Create adjacency matrix for dependencies
        dependency_matrix = self._create_dependency_matrix(modules, audit_data)

        if not dependency_matrix:
            return {"type": "empty", "message": "No module dependency data available"}

        config = {
            "type": "adjacency-matrix",
            "data": dependency_matrix,
            "options": {
                "title": "Module Risk Dependencies",
                "symmetric": False,
                "colorScale": {
                    "type": "sequential",
                    "scheme": "Purples",
                    "domain": [0, 1],
                    "label": "Risk Propagation",
                },
                "labels": {"rotate": 45, "fontSize": 10},
                "cells": {"size": "value", "minSize": 5, "maxSize": 20},
            },
        }

        return config

    # Helper methods
    def _prepare_heatmap_data(self, hotspots: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare hotspot data for heatmap visualization."""
        # Group hotspots by directory
        directory_groups = defaultdict(list)

        for hotspot in hotspots:
            file_path = hotspot.get("file_path", "")
            directory = "/".join(file_path.split("/")[:-1]) or "root"
            directory_groups[directory].append(hotspot)

        # Create hierarchical structure
        heatmap_items = []

        for directory, dir_hotspots in directory_groups.items():
            # Calculate aggregate metrics for directory
            avg_risk = sum(h.get("risk_score", 0) for h in dir_hotspots) / len(dir_hotspots)

            # Add directory node
            dir_item = {
                "name": self._truncate_path(directory, 30),
                "value": avg_risk * 100,  # Convert to percentage
                "type": "directory",
                "children": [],
            }

            # Add file nodes
            for hotspot in dir_hotspots:
                file_name = hotspot.get("file_path", "").split("/")[-1]
                dir_item["children"].append(
                    {
                        "name": file_name,
                        "value": hotspot.get("risk_score", 0) * 100,
                        "complexity": hotspot.get("complexity_score", 0),
                        "violations": hotspot.get("violation_count", 0),
                        "category": hotspot.get("risk_category", "Unknown"),
                    }
                )

            heatmap_items.append(dir_item)

        # Sort by risk score
        heatmap_items.sort(key=lambda x: x["value"], reverse=True)

        return {"root": {"name": "Repository", "children": heatmap_items[:20]}}  # Top 20 directories

    def _aggregate_by_directory(self, hotspots: List[Dict[str, Any]], metric: str) -> Dict[str, float]:
        """Aggregate hotspot metrics by directory."""
        directory_metrics = defaultdict(list)

        for hotspot in hotspots:
            file_path = hotspot.get("file_path", "")
            directory = "/".join(file_path.split("/")[:-1]) or "root"

            value = hotspot.get(metric, 0)
            if metric == "risk_score" and value <= 1:
                value *= 100

            directory_metrics[directory].append(value)

        # Calculate averages
        return {directory: sum(values) / len(values) for directory, values in directory_metrics.items()}

    def _create_treemap_structure(self, dir_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Create hierarchical structure for treemap visualization."""
        # Build tree structure from paths
        root = {"name": "root", "children": {}}

        for path, value in dir_metrics.items():
            parts = path.split("/")
            current = root

            for part in parts:
                if part not in current["children"]:
                    current["children"][part] = {"name": part, "children": {}}
                current = current["children"][part]

            current["value"] = value
            current["fileCount"] = len([h for h in dir_metrics if h.startswith(path)])

        # Convert to list format
        def dict_to_list(node):
            if not node["children"]:
                return {
                    "name": node["name"],
                    "value": node.get("value", 0),
                    "fileCount": node.get("fileCount", 1),
                }

            children = [dict_to_list(child) for child in node["children"].values()]
            return {"name": node["name"], "children": children}

        return dict_to_list(root)

    def _calculate_correlations(self, metrics: Dict[str, List[float]]) -> List[List[float]]:
        """Calculate correlation matrix between metrics."""
        import numpy as np

        # Convert to numpy array
        data = np.array([metrics[key] for key in metrics.keys()])

        # Calculate correlation matrix
        correlation_matrix = np.corrcoef(data)

        # Convert to list format
        return correlation_matrix.tolist()

    def _extract_module_structure(self, hotspots: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract module structure from hotspot file paths."""
        modules = defaultdict(list)

        for hotspot in hotspots:
            file_path = hotspot.get("file_path", "")
            parts = file_path.split("/")

            if len(parts) >= 2:
                module = parts[0]
                modules[module].append(file_path)

        return dict(modules)

    def _create_dependency_matrix(self, modules: Dict[str, List[str]], audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create dependency matrix between modules based on violations."""
        # This is a simplified version - in practice, you'd analyze imports
        module_names = list(modules.keys())
        matrix = [[0] * len(module_names) for _ in range(len(module_names))]

        # Simulate dependencies based on violation patterns
        violations = audit_data.get("violations", [])

        for i, module_a in enumerate(module_names):
            for j, module_b in enumerate(module_names):
                if i != j:
                    # Count cross-module violations
                    cross_violations = sum(
                        1 for v in violations if module_a in v.get("file_path", "") and module_b in v.get("message", "")
                    )

                    if cross_violations > 0:
                        matrix[i][j] = min(cross_violations / 10, 1.0)

        return {"rows": module_names, "columns": module_names, "values": matrix}

    def _get_tooltip_formatter(self) -> str:
        """Get JavaScript tooltip formatter function."""
        return """function(data) {
            return `
                <div class="heatmap-tooltip">
                    <strong>${data.name}</strong><br>
                    Risk Score: ${data.value.toFixed(1)}%<br>
                    Complexity: ${data.complexity || 'N/A'}<br>
                    Violations: ${data.violations || 0}<br>
                    Category: ${data.category || 'Unknown'}
                </div>
            `;
        }"""

    def _truncate_path(self, path: str, max_length: int = 40) -> str:
        """Truncate file path for display."""
        if len(path) <= max_length:
            return path

        parts = path.split("/")
        if len(parts) > 2:
            return f"{parts[0]}/.../{parts[-1]}"

        return path[: max_length - 3] + "..."
