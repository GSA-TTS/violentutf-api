"""
Hotspot data integration module.

This module integrates the statistical hotspot analysis from Issue #43
with the reporting system, providing data transformation and aggregation
capabilities for comprehensive reports.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

    # Fallback implementations for numpy functions
    def mean(values):
        return sum(values) / len(values) if values else 0

    def median(values):
        if not values:
            return 0
        sorted_values = sorted(values)
        n = len(sorted_values)
        if n % 2 == 0:
            return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
        return sorted_values[n // 2]

    def std(values):
        if not values:
            return 0
        m = mean(values)
        return (sum((x - m) ** 2 for x in values) / len(values)) ** 0.5

    # Create a mock np module
    class MockNp:
        """Mock numpy module for when numpy is not available."""

        mean = staticmethod(mean)
        median = staticmethod(median)
        std = staticmethod(std)

    np = MockNp()

# Import statistical analysis components if available
try:
    from ..statistical_analysis.statistical_hotspot_orchestrator import (
        EnhancedArchitecturalHotspot,
        StatisticalHotspotOrchestrator,
    )
    from ..statistical_analysis.temporal_weighting_engine import TemporalWeightingResult

    HAS_STATISTICAL_ANALYSIS = True
except ImportError:
    HAS_STATISTICAL_ANALYSIS = False
    EnhancedArchitecturalHotspot = None

    # Create dummy class for type hints
    class TemporalWeightingResult:
        """Dummy class for temporal weighting results when statistical analysis is not available."""

        pass


logger = logging.getLogger(__name__)


@dataclass
class HotspotAnalysisResult:
    """Container for hotspot analysis results formatted for reporting."""

    hotspots: List[Dict[str, Any]]
    statistical_summary: Dict[str, Any]
    temporal_trends: Dict[str, Any]
    risk_distribution: Dict[str, int]
    analysis_metadata: Dict[str, Any]


class HotspotDataTransformer:
    """Transform statistical hotspot data for report consumption."""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def transform_hotspot_for_report(self, hotspot: Any, security_level: str = "internal") -> Dict[str, Any]:
        """
        Transform statistical hotspot data for report consumption.

        This method handles both EnhancedArchitecturalHotspot objects from the
        statistical analysis module and simpler dictionary hotspots from the
        basic analysis.
        """
        if HAS_STATISTICAL_ANALYSIS and isinstance(hotspot, EnhancedArchitecturalHotspot):
            return self._transform_enhanced_hotspot(hotspot, security_level)
        else:
            return self._transform_basic_hotspot(hotspot, security_level)

    def _transform_enhanced_hotspot(self, hotspot: EnhancedArchitecturalHotspot, security_level: str) -> Dict[str, Any]:
        """Transform EnhancedArchitecturalHotspot for reporting."""
        transformed = {
            "file_path": hotspot.file_path,
            "risk_score": round(hotspot.integrated_risk_probability, 3),
            "confidence": f"{hotspot.risk_confidence_interval[0]:.2f}-{hotspot.risk_confidence_interval[1]:.2f}",
            "evidence_strength": hotspot.risk_evidence_strength,
            "churn_score": round(hotspot.churn_score, 2),
            "complexity_score": round(hotspot.complexity_score, 2),
            "violation_count": len(hotspot.violation_history),
            "violation_history": hotspot.violation_history[:5],  # Recent 5
        }

        # Add temporal data
        if hasattr(hotspot, "temporal_assessment") and hotspot.temporal_assessment:
            transformed["temporal"] = {
                "weight": round(hotspot.temporal_assessment.temporal_weight, 3),
                "decay_rate": round(hotspot.temporal_assessment.decay_rate, 4),
                "average_age_days": round(hotspot.temporal_assessment.average_violation_age_days, 0),
                "trend": hotspot.temporal_patterns.get("trend", "unknown"),
            }

        # Add statistical significance if not public
        if security_level != "public" and hasattr(hotspot, "statistical_significance"):
            transformed["statistical"] = {
                "p_value": round(hotspot.statistical_significance.p_value, 4),
                "effect_size": round(hotspot.statistical_significance.effect_size, 3),
                "test_statistic": round(hotspot.statistical_significance.test_statistic, 3),
                "distribution_type": getattr(hotspot.statistical_significance, "best_fit_distribution", "unknown"),
            }

        # Add business impact assessment
        if hasattr(hotspot, "feature_contributions"):
            transformed["business_impact"] = self._assess_business_impact(hotspot.feature_contributions)

        # Add risk categorization
        transformed["risk_category"] = self._categorize_risk(hotspot.integrated_risk_probability)

        return transformed

    def _transform_basic_hotspot(self, hotspot: Any, security_level: str) -> Dict[str, Any]:
        """Transform basic hotspot dictionary for reporting."""
        # Handle basic hotspot structure from claude_code_auditor.py
        if isinstance(hotspot, dict):
            transformed = {
                "file_path": hotspot.get("file_path", "unknown"),
                "risk_score": hotspot.get("risk_score", 0),
                "churn_score": hotspot.get("churn_score", 0),
                "complexity_score": hotspot.get("complexity_score", 0),
                "risk_level": hotspot.get("risk_level", "unknown"),
                "violation_history": hotspot.get("violation_history", []),
                "violation_count": len(hotspot.get("violation_history", [])),
                "recommendations": hotspot.get("recommendations", []),
            }

            # Add risk categorization
            risk_score = hotspot.get("risk_score", 0)
            if isinstance(risk_score, (int, float)):
                transformed["risk_category"] = self._categorize_risk(risk_score)

            return transformed
        else:
            # Fallback for unknown hotspot format
            return {
                "file_path": str(hotspot),
                "risk_score": 0,
                "risk_category": "unknown",
                "error": "Unsupported hotspot format",
            }

    def aggregate_hotspot_statistics(self, hotspots: List[Any]) -> Dict[str, Any]:
        """Aggregate hotspot data for executive summary."""
        if not hotspots:
            return self._empty_statistics()

        # Extract risk scores
        risk_scores = []
        for hotspot in hotspots:
            if HAS_STATISTICAL_ANALYSIS and isinstance(hotspot, EnhancedArchitecturalHotspot):
                risk_scores.append(hotspot.integrated_risk_probability)
            elif isinstance(hotspot, dict):
                score = hotspot.get("risk_score", 0)
                # Normalize if needed (some may be 0-100, others 0-1)
                if score > 1:
                    score = score / 100
                risk_scores.append(score)

        # Calculate statistics
        critical_hotspots = [s for s in risk_scores if s > 0.8]
        high_risk_hotspots = [s for s in risk_scores if 0.6 <= s <= 0.8]

        # Extract temporal trends if available
        temporal_trends = self._extract_temporal_trends(hotspots)

        # Get top risk areas
        top_risk_areas = self._identify_top_risk_areas(hotspots)

        # Calculate confidence statistics if available
        confidence_stats = self._calculate_confidence_statistics(hotspots)

        return {
            "total_hotspots": len(hotspots),
            "critical_count": len(critical_hotspots),
            "high_risk_count": len(high_risk_hotspots),
            "average_risk": float(np.mean(risk_scores)) if risk_scores else 0,
            "median_risk": float(np.median(risk_scores)) if risk_scores else 0,
            "risk_std_dev": float(np.std(risk_scores)) if risk_scores else 0,
            "temporal_trends": temporal_trends,
            "top_risk_areas": top_risk_areas,
            "confidence_statistics": confidence_stats,
            "risk_distribution": self._calculate_risk_distribution(risk_scores),
        }

    def create_hotspot_analysis_result(
        self, audit_results: Dict[str, Any], config: Optional[Dict[str, Any]] = None
    ) -> HotspotAnalysisResult:
        """
        Create a complete hotspot analysis result from audit data.

        This method integrates both basic hotspots from claude_code_auditor.py
        and enhanced hotspots from the statistical analysis module.
        """
        hotspots_raw = audit_results.get("architectural_hotspots", [])

        # Transform all hotspots
        transformed_hotspots = []
        for hotspot in hotspots_raw:
            transformed = self.transform_hotspot_for_report(
                hotspot,
                config.get("security_level", "internal") if config else "internal",
            )
            transformed_hotspots.append(transformed)

        # Sort by risk score
        transformed_hotspots.sort(key=lambda h: h.get("risk_score", 0), reverse=True)

        # Limit to configured maximum if specified
        if config and config.get("max_hotspots_display"):
            transformed_hotspots = transformed_hotspots[: config["max_hotspots_display"]]

        # Generate statistics
        statistics = self.aggregate_hotspot_statistics(hotspots_raw)

        # Extract temporal trends
        temporal_trends = self._extract_temporal_trends(hotspots_raw)

        # Calculate risk distribution
        risk_distribution = self._calculate_risk_distribution([h.get("risk_score", 0) for h in transformed_hotspots])

        # Create metadata
        metadata = {
            "analysis_timestamp": datetime.now().isoformat(),
            "total_files_analyzed": len(set(h.get("file_path") for h in transformed_hotspots)),
            "statistical_analysis_available": HAS_STATISTICAL_ANALYSIS,
            "confidence_threshold": (config.get("statistical_confidence_threshold", 0.95) if config else 0.95),
            "temporal_window_months": (config.get("temporal_window_months", 6) if config else 6),
        }

        return HotspotAnalysisResult(
            hotspots=transformed_hotspots,
            statistical_summary=statistics,
            temporal_trends=temporal_trends,
            risk_distribution=risk_distribution,
            analysis_metadata=metadata,
        )

    # Helper methods
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk score into levels."""
        if risk_score >= 0.8:
            return "Critical"
        elif risk_score >= 0.6:
            return "High"
        elif risk_score >= 0.4:
            return "Medium"
        elif risk_score >= 0.2:
            return "Low"
        else:
            return "Minimal"

    def _assess_business_impact(self, feature_contributions: Dict[str, float]) -> str:
        """Assess business impact based on feature contributions."""
        # Extract key contributions
        business_impact = feature_contributions.get("business_impact", 0)
        security_impact = feature_contributions.get("security_impact", 0)

        if business_impact > 0.7 or security_impact > 0.7:
            return "Critical - High business/security impact"
        elif business_impact > 0.5 or security_impact > 0.5:
            return "High - Significant operational impact"
        elif business_impact > 0.3 or security_impact > 0.3:
            return "Medium - Moderate impact expected"
        else:
            return "Low - Limited impact"

    def _extract_temporal_trends(self, hotspots: List[Any]) -> Dict[str, Any]:
        """Extract temporal trend information from hotspots."""
        trends = {"improving": 0, "stable": 0, "degrading": 0, "unknown": 0}

        for hotspot in hotspots:
            trend = "unknown"

            if HAS_STATISTICAL_ANALYSIS and isinstance(hotspot, EnhancedArchitecturalHotspot):
                if hasattr(hotspot, "temporal_patterns"):
                    trend = hotspot.temporal_patterns.get("trend", "unknown")
            elif isinstance(hotspot, dict):
                # Try to extract from basic hotspot
                if "temporal_patterns" in hotspot:
                    trend = hotspot["temporal_patterns"].get("trend", "unknown")
                elif "trend" in hotspot:
                    trend = hotspot["trend"]

            trends[trend] = trends.get(trend, 0) + 1

        # Calculate percentages
        total = sum(trends.values())
        if total > 0:
            trend_percentages = {k: round(v / total * 100, 1) for k, v in trends.items()}
        else:
            trend_percentages = trends

        return {
            "counts": trends,
            "percentages": trend_percentages,
            "summary": self._summarize_trends(trends),
        }

    def _summarize_trends(self, trends: Dict[str, int]) -> str:
        """Create a summary of temporal trends."""
        total = sum(trends.values())
        if total == 0:
            return "No trend data available"

        improving_pct = trends.get("improving", 0) / total * 100
        degrading_pct = trends.get("degrading", 0) / total * 100

        if degrading_pct > 50:
            return f"Concerning: {degrading_pct:.0f}% of hotspots are degrading"
        elif improving_pct > 50:
            return f"Positive: {improving_pct:.0f}% of hotspots are improving"
        else:
            return f"Mixed: {improving_pct:.0f}% improving, {degrading_pct:.0f}% degrading"

    def _identify_top_risk_areas(self, hotspots: List[Any], limit: int = 5) -> List[Dict[str, Any]]:
        """Identify top risk areas from hotspots."""
        # Extract file paths and risk scores
        risk_by_area = {}

        for hotspot in hotspots:
            file_path = ""
            risk_score = 0

            if HAS_STATISTICAL_ANALYSIS and isinstance(hotspot, EnhancedArchitecturalHotspot):
                file_path = hotspot.file_path
                risk_score = hotspot.integrated_risk_probability
            elif isinstance(hotspot, dict):
                file_path = hotspot.get("file_path", "unknown")
                risk_score = hotspot.get("risk_score", 0)
                if risk_score > 1:
                    risk_score = risk_score / 100

            # Extract area from file path (e.g., app/core, app/services)
            if file_path and "/" in file_path:
                parts = file_path.split("/")
                if len(parts) >= 2:
                    area = f"{parts[0]}/{parts[1]}"
                else:
                    area = parts[0]
            else:
                area = "root"

            if area not in risk_by_area:
                risk_by_area[area] = {"total_risk": 0, "count": 0, "files": set()}

            risk_by_area[area]["total_risk"] += risk_score
            risk_by_area[area]["count"] += 1
            risk_by_area[area]["files"].add(file_path)

        # Calculate average risk and sort
        top_areas = []
        for area, data in risk_by_area.items():
            avg_risk = data["total_risk"] / data["count"] if data["count"] > 0 else 0
            top_areas.append(
                {
                    "area": area,
                    "average_risk": round(avg_risk, 3),
                    "hotspot_count": data["count"],
                    "file_count": len(data["files"]),
                }
            )

        # Sort by average risk
        top_areas.sort(key=lambda x: x["average_risk"], reverse=True)

        return top_areas[:limit]

    def _calculate_confidence_statistics(self, hotspots: List[Any]) -> Dict[str, Any]:
        """Calculate confidence statistics from enhanced hotspots."""
        if not HAS_STATISTICAL_ANALYSIS:
            return {"available": False}

        confidence_levels = {"very_strong": 0, "strong": 0, "moderate": 0, "weak": 0}

        p_values = []
        effect_sizes = []

        for hotspot in hotspots:
            if isinstance(hotspot, EnhancedArchitecturalHotspot):
                # Extract evidence strength
                evidence = hotspot.risk_evidence_strength
                confidence_levels[evidence] = confidence_levels.get(evidence, 0) + 1

                # Extract statistical values
                if hasattr(hotspot, "statistical_significance"):
                    p_values.append(hotspot.statistical_significance.p_value)
                    effect_sizes.append(hotspot.statistical_significance.effect_size)

        return {
            "available": True,
            "confidence_distribution": confidence_levels,
            "average_p_value": float(np.mean(p_values)) if p_values else None,
            "average_effect_size": (float(np.mean(effect_sizes)) if effect_sizes else None),
            "high_confidence_percentage": self._calculate_high_confidence_percentage(confidence_levels),
        }

    def _calculate_high_confidence_percentage(self, confidence_levels: Dict[str, int]) -> float:
        """Calculate percentage of high confidence assessments."""
        total = sum(confidence_levels.values())
        if total == 0:
            return 0.0

        high_confidence = confidence_levels.get("very_strong", 0) + confidence_levels.get("strong", 0)
        return round(high_confidence / total * 100, 1)

    def _calculate_risk_distribution(self, risk_scores: List[float]) -> Dict[str, int]:
        """Calculate distribution of risk scores."""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}

        for score in risk_scores:
            category = self._categorize_risk(score)
            distribution[category.lower()] = distribution.get(category.lower(), 0) + 1

        return distribution

    def _empty_statistics(self) -> Dict[str, Any]:
        """Return empty statistics structure."""
        return {
            "total_hotspots": 0,
            "critical_count": 0,
            "high_risk_count": 0,
            "average_risk": 0,
            "median_risk": 0,
            "risk_std_dev": 0,
            "temporal_trends": {
                "counts": {"improving": 0, "stable": 0, "degrading": 0, "unknown": 0},
                "percentages": {
                    "improving": 0,
                    "stable": 0,
                    "degrading": 0,
                    "unknown": 0,
                },
                "summary": "No hotspot data available",
            },
            "top_risk_areas": [],
            "confidence_statistics": {"available": False},
            "risk_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "minimal": 0,
            },
        }
