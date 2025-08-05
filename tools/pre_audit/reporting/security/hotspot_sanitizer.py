"""
Hotspot data sanitization module.

This module provides specialized sanitization for architectural hotspot
data from the statistical analysis module (Issue #43).
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .input_validator import InputValidator, ValidationError
from .output_encoder import EncodingType, OutputEncoder

logger = logging.getLogger(__name__)


class HotspotSanitizer:
    """
    Sanitizes hotspot data for secure report generation.

    Handles both EnhancedArchitecturalHotspot objects and basic
    hotspot dictionaries with appropriate security measures.
    """

    def __init__(self, security_level: str = "internal"):
        """
        Initialize the sanitizer.

        Args:
            security_level: Security level (public, internal, restricted, full)
        """
        self.security_level = security_level
        self.validator = InputValidator(strict_mode=(security_level == "public"))
        self.encoder = OutputEncoder()
        self._sanitization_stats = {"total_sanitized": 0, "paths_redacted": 0, "sensitive_removed": 0}

    def sanitize_hotspot(self, hotspot: Any) -> Dict[str, Any]:
        """
        Sanitize a single hotspot entry.

        Args:
            hotspot: Hotspot data (dict or EnhancedArchitecturalHotspot)

        Returns:
            Sanitized hotspot dictionary
        """
        self._sanitization_stats["total_sanitized"] += 1

        # Convert to dictionary if needed
        if hasattr(hotspot, "__dict__"):
            hotspot_dict = self._object_to_dict(hotspot, set())
            # Debug: log what we got
            if not hotspot_dict:
                logger.debug(f"Empty dict from _object_to_dict for {type(hotspot)}")
        elif isinstance(hotspot, dict):
            hotspot_dict = hotspot.copy()
        elif isinstance(hotspot, str):
            # Handle string hotspots
            return {"type": "basic", "value": hotspot}
        else:
            return {"error": "Invalid hotspot format", "type": str(type(hotspot))}

        # Sanitize based on security level
        sanitized = {}

        # File path handling
        if "file_path" in hotspot_dict:
            sanitized["file_path"] = self._sanitize_file_path(hotspot_dict["file_path"])

        # Numeric fields (safe to copy)
        numeric_fields = [
            "risk_score",
            "integrated_risk_probability",
            "churn_score",
            "complexity_score",
            "temporal_weight",
            "p_value",
            "effect_size",
            "violation_count",
        ]
        for field in numeric_fields:
            if field in hotspot_dict and isinstance(hotspot_dict[field], (int, float)):
                sanitized[field] = round(float(hotspot_dict[field]), 4)

        # Map integrated_risk_probability to risk_score if not present
        if "integrated_risk_probability" in sanitized and "risk_score" not in sanitized:
            sanitized["risk_score"] = sanitized.get("integrated_risk_probability", 0)

        # String fields requiring encoding
        string_fields = ["risk_evidence_strength", "risk_category", "trend"]
        for field in string_fields:
            if field in hotspot_dict and hotspot_dict[field]:
                sanitized[field] = self.encoder.encode_for_html(str(hotspot_dict[field]))

        # Arrays and complex fields
        if "violation_history" in hotspot_dict:
            sanitized["violation_history"] = self._sanitize_violation_history(hotspot_dict.get("violation_history", []))

        if "recommendations" in hotspot_dict:
            sanitized["recommendations"] = self._sanitize_recommendations(hotspot_dict.get("recommendations", []))

        # Confidence intervals
        if "risk_confidence_interval" in hotspot_dict:
            interval = hotspot_dict["risk_confidence_interval"]
            if isinstance(interval, (list, tuple)) and len(interval) >= 2:
                sanitized["confidence_interval"] = {
                    "lower": round(float(interval[0]), 3),
                    "upper": round(float(interval[1]), 3),
                }

        # Statistical significance (only for non-public)
        if self.security_level != "public" and "statistical_significance" in hotspot_dict:
            sanitized["statistical_significance"] = self._sanitize_statistical_data(
                hotspot_dict["statistical_significance"]
            )

        # Temporal patterns
        if "temporal_patterns" in hotspot_dict:
            sanitized["temporal_patterns"] = self._sanitize_temporal_patterns(hotspot_dict["temporal_patterns"])

        # Add temporal data for restricted level (from temporal_assessment)
        if self.security_level in ["restricted", "full"] and "temporal_assessment" in hotspot_dict:
            temporal_data = hotspot_dict["temporal_assessment"]
            if hasattr(temporal_data, "__dict__"):
                # Extract from object
                sanitized["temporal"] = {
                    "weight": getattr(temporal_data, "temporal_weight", 0),
                    "trend": hotspot_dict.get("temporal_patterns", {}).get("trend", "unknown"),
                }
            elif isinstance(temporal_data, dict):
                # Extract from dict
                sanitized["temporal"] = {
                    "weight": temporal_data.get("temporal_weight", 0),
                    "trend": hotspot_dict.get("temporal_patterns", {}).get("trend", "unknown"),
                }

        # Business impact (redact for public)
        if "business_impact" in hotspot_dict:
            if self.security_level == "public":
                sanitized["business_impact"] = "Redacted"
                self._sanitization_stats["sensitive_removed"] += 1
            else:
                sanitized["business_impact"] = self.encoder.encode_for_html(str(hotspot_dict["business_impact"]))

        return sanitized

    def sanitize_hotspot_list(self, hotspots: List[Any]) -> List[Dict[str, Any]]:
        """
        Sanitize a list of hotspots.

        Args:
            hotspots: List of hotspot entries

        Returns:
            List of sanitized hotspot dictionaries
        """
        sanitized_list = []

        for hotspot in hotspots:
            try:
                sanitized = self.sanitize_hotspot(hotspot)
                sanitized_list.append(sanitized)
            except Exception as e:
                logger.error(f"Error sanitizing hotspot: {str(e)}")
                sanitized_list.append({"error": "Sanitization failed", "type": str(type(hotspot))})

        return sanitized_list

    def _sanitize_file_path(self, file_path: Union[str, Path]) -> str:
        """
        Sanitize file path based on security level.

        Args:
            file_path: Original file path

        Returns:
            Sanitized path string
        """
        if not file_path:
            return "unknown"

        path_str = str(file_path)

        # For public reports, redact detailed paths
        if self.security_level == "public":
            # Only show file extension and depth
            parts = Path(path_str).parts
            if parts:
                ext = Path(parts[-1]).suffix
                depth = len(parts)
                self._sanitization_stats["paths_redacted"] += 1
                return f"[{depth}-level-path]{ext}"
            return "[redacted]"

        # For internal/restricted, validate and encode
        try:
            validated_path = self.validator.validate_file_path(path_str)
            return self.encoder.encode_for_html(str(validated_path))
        except ValidationError:
            # Fallback to safe representation
            parts = Path(path_str).parts
            if parts:
                # Show only last two components
                safe_parts = parts[-2:] if len(parts) > 1 else parts
                return self.encoder.encode_for_html("/".join(safe_parts))
            return "invalid-path"

    def _sanitize_violation_history(self, violations: List[Any]) -> List[Dict[str, Any]]:
        """Sanitize violation history entries."""
        if not isinstance(violations, list):
            return []

        # Limit number of violations shown
        max_violations = 5 if self.security_level == "public" else 20
        violations = violations[:max_violations]

        sanitized = []
        for violation in violations:
            if isinstance(violation, dict):
                sanitized_violation = {}

                # Safe fields
                safe_fields = ["timestamp", "adr_id", "risk_level", "line_number"]
                for field in safe_fields:
                    if field in violation:
                        sanitized_violation[field] = violation[field]

                # Encode message
                if "message" in violation:
                    sanitized_violation["message"] = self.encoder.encode_for_html(
                        str(violation["message"])[:200]  # Limit length
                    )

                sanitized.append(sanitized_violation)
            else:
                # Handle string violations
                sanitized.append({"message": self.encoder.encode_for_html(str(violation)[:200])})

        return sanitized

    def _sanitize_recommendations(self, recommendations: List[Any]) -> List[str]:
        """Sanitize recommendation strings."""
        if not isinstance(recommendations, list):
            return []

        sanitized = []
        max_recommendations = 3 if self.security_level == "public" else 10

        for rec in recommendations[:max_recommendations]:
            if isinstance(rec, str):
                sanitized.append(self.encoder.encode_for_html(rec[:500]))
            elif isinstance(rec, dict) and "description" in rec:
                sanitized.append(self.encoder.encode_for_html(str(rec["description"])[:500]))

        return sanitized

    def _sanitize_statistical_data(self, stats: Any) -> Dict[str, Any]:
        """Sanitize statistical significance data."""
        if not stats:
            return {}

        sanitized = {}

        # Handle dict or object
        if hasattr(stats, "__dict__"):
            stats_dict = stats.__dict__
        elif isinstance(stats, dict):
            stats_dict = stats
        else:
            return {}

        # Safe numeric fields
        numeric_fields = ["p_value", "effect_size", "test_statistic"]
        for field in numeric_fields:
            if field in stats_dict and isinstance(stats_dict[field], (int, float)):
                sanitized[field] = round(float(stats_dict[field]), 6)

        # String fields
        if "best_fit_distribution" in stats_dict:
            sanitized["distribution"] = self.encoder.encode_for_html(str(stats_dict["best_fit_distribution"]))

        return sanitized

    def _sanitize_temporal_patterns(self, patterns: Any) -> Dict[str, Any]:
        """Sanitize temporal pattern data."""
        if not patterns:
            return {}

        if isinstance(patterns, dict):
            sanitized = {}

            # Process all fields in the patterns dict
            for field, value in patterns.items():
                if isinstance(value, str):
                    # Encode string values for safety
                    sanitized[field] = self.encoder.encode_for_html(value)
                else:
                    # Keep numeric/other values as-is
                    sanitized[field] = value

            return sanitized

        return {}

    def _object_to_dict(self, obj: Any, seen_objects: Optional[set] = None) -> Dict[str, Any]:
        """Convert object to dictionary safely."""
        # Prevent infinite recursion
        if seen_objects is None:
            seen_objects = set()

        obj_id = id(obj)
        if obj_id in seen_objects:
            return {"circular_reference": str(type(obj))}
        seen_objects.add(obj_id)

        # Check if it's a real to_dict method (not a Mock)
        if hasattr(obj, "to_dict") and callable(obj.to_dict) and not hasattr(obj, "_mock_name"):
            try:
                return obj.to_dict()
            except Exception as e:
                logger.debug(f"Failed to convert object to dict using to_dict(): {type(obj).__name__} - {str(e)}")

        # Build dict from known attributes
        result = {}

        # Common hotspot attributes
        attrs_to_check = [
            "file_path",
            "integrated_risk_probability",
            "risk_score",
            "churn_score",
            "complexity_score",
            "risk_evidence_strength",
            "risk_confidence_interval",
            "temporal_patterns",
            "recommendations",
            "violation_history",
            "statistical_significance",
            "temporal_assessment",
            "feature_contributions",
        ]

        # Try to extract all known attributes
        for attr in attrs_to_check:
            try:
                if hasattr(obj, attr):
                    value = getattr(obj, attr, None)
                    if value is not None:
                        # Handle nested objects (but not Mocks to avoid infinite recursion)
                        if (
                            hasattr(value, "__dict__")
                            and not isinstance(value, (str, int, float, list, dict, tuple))
                            and not hasattr(value, "_mock_name")
                        ):
                            result[attr] = self._object_to_dict(value, seen_objects)
                        else:
                            result[attr] = value
            except Exception as e:
                # Skip any attribute that can't be accessed
                logger.debug(f"Skipping attribute '{attr}' on {type(obj).__name__}: {str(e)}")

        # If no known attributes found, try generic approach
        if not result and hasattr(obj, "__dict__"):
            try:
                result = {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
            except Exception as e:
                logger.debug(f"Failed to access __dict__ on {type(obj).__name__}: {str(e)}")

        return result if result else {"type": str(type(obj)), "value": str(obj)}

    def get_sanitization_stats(self) -> Dict[str, int]:
        """Get sanitization statistics."""
        return self._sanitization_stats.copy()

    def create_redacted_summary(self, hotspots: List[Any]) -> Dict[str, Any]:
        """
        Create a redacted summary suitable for public consumption.

        Args:
            hotspots: List of hotspot entries

        Returns:
            Summary with sensitive data removed
        """
        total = len(hotspots)

        # Risk distribution without paths
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for hotspot in hotspots:
            if isinstance(hotspot, dict):
                risk = hotspot.get("risk_score", 0)
            elif hasattr(hotspot, "integrated_risk_probability"):
                risk = hotspot.integrated_risk_probability
            else:
                continue

            if risk >= 0.8:
                risk_distribution["critical"] += 1
            elif risk >= 0.6:
                risk_distribution["high"] += 1
            elif risk >= 0.4:
                risk_distribution["medium"] += 1
            else:
                risk_distribution["low"] += 1

        return {
            "total_hotspots": total,
            "risk_distribution": risk_distribution,
            "analysis_complete": True,
            "details": "Full details available in restricted report",
        }
