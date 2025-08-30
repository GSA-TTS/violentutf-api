"""
Unit tests for hotspot data sanitization module.

Tests specialized sanitization for architectural hotspot data
with different security levels.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.pre_audit.reporting.security import HotspotSanitizer


class TestHotspotSanitizer:
    """Test suite for HotspotSanitizer class."""

    @pytest.fixture
    def public_sanitizer(self):
        """Create sanitizer for public security level."""
        return HotspotSanitizer(security_level="public")

    @pytest.fixture
    def internal_sanitizer(self):
        """Create sanitizer for internal security level."""
        return HotspotSanitizer(security_level="internal")

    @pytest.fixture
    def restricted_sanitizer(self):
        """Create sanitizer for restricted security level."""
        return HotspotSanitizer(security_level="restricted")

    @pytest.fixture
    def sample_hotspot_dict(self):
        """Create sample hotspot dictionary."""
        return {
            "file_path": "src/security/auth.py",
            "risk_score": 0.85,
            "integrated_risk_probability": 0.82,
            "churn_score": 45,
            "complexity_score": 78,
            "temporal_weight": 0.92,
            "risk_evidence_strength": "strong",
            "risk_category": "High",
            "violation_history": [
                {"message": "Missing auth check", "timestamp": "2024-01-01"},
                {"message": "<script>alert('XSS')</script>", "timestamp": "2024-01-02"},
            ],
            "recommendations": [
                "Add authentication middleware",
                "Review security policies",
            ],
            "risk_confidence_interval": [0.75, 0.89],
            "business_impact": "Critical - Authentication bypass possible",
        }

    @pytest.fixture
    def enhanced_hotspot_object(self):
        """Create mock EnhancedArchitecturalHotspot object."""
        hotspot = MagicMock()
        hotspot.file_path = "src/api/endpoints.py"
        hotspot.integrated_risk_probability = 0.91
        hotspot.churn_score = 67
        hotspot.complexity_score = 82
        hotspot.risk_evidence_strength = "very_strong"
        hotspot.risk_confidence_interval = [0.88, 0.94]
        hotspot.temporal_assessment = MagicMock(temporal_weight=0.95, decay_rate=0.02, average_violation_age_days=45)
        hotspot.temporal_patterns = {"trend": "degrading"}
        hotspot.statistical_significance = MagicMock(
            p_value=0.001,
            effect_size=0.85,
            test_statistic=3.24,
            best_fit_distribution="lognormal",
        )
        hotspot.feature_contributions = {"business_impact": 0.8, "security_impact": 0.9}
        hotspot.violation_history = ["ADR-001", "ADR-002", "ADR-003"]
        return hotspot

    # Test Public Security Level
    def test_sanitize_hotspot_public_level(self, public_sanitizer, sample_hotspot_dict):
        """Test sanitization at public security level."""
        result = public_sanitizer.sanitize_hotspot(sample_hotspot_dict)

        # File path should be redacted
        assert result["file_path"] == "[3-level-path].py"
        assert public_sanitizer._sanitization_stats["paths_redacted"] == 1

        # Numeric fields should be preserved
        assert result["risk_score"] == 0.85
        assert result["complexity_score"] == 78

        # Business impact should be redacted
        assert result["business_impact"] == "Redacted"
        assert public_sanitizer._sanitization_stats["sensitive_removed"] == 1

        # Statistical data should not be included
        assert "statistical_significance" not in result

    def test_sanitize_hotspot_public_redacts_paths(self, public_sanitizer):
        """Test that public level redacts all file paths."""
        test_paths = [
            ("src/main.py", "[2-level-path].py"),
            ("deep/nested/path/to/file.js", "[5-level-path].js"),
            ("single.py", "[1-level-path].py"),
            ("no_extension", "[1-level-path]"),
        ]

        for original, expected in test_paths:
            hotspot = {"file_path": original}
            result = public_sanitizer.sanitize_hotspot(hotspot)
            assert result["file_path"] == expected

    # Test Internal Security Level
    def test_sanitize_hotspot_internal_level(self, internal_sanitizer, sample_hotspot_dict):
        """Test sanitization at internal security level."""
        result = internal_sanitizer.sanitize_hotspot(sample_hotspot_dict)

        # File path should be validated but not redacted
        assert "auth.py" in result["file_path"]

        # Business impact should be preserved
        assert "Authentication bypass" in result["business_impact"]

        # Statistical data should not be included (internal level)
        assert "statistical_significance" not in result

    def test_sanitize_hotspot_internal_validates_paths(self, internal_sanitizer):
        """Test that internal level validates paths."""
        # Dangerous path should fallback to safe representation
        hotspot = {"file_path": "../../../etc/passwd"}
        result = internal_sanitizer.sanitize_hotspot(hotspot)

        # Should show only safe parts - last two components
        assert "passwd" in result["file_path"]
        # Should not contain dangerous traversal patterns
        assert ".." not in result["file_path"]

    # Test Restricted Security Level
    def test_sanitize_hotspot_restricted_level(self, restricted_sanitizer, enhanced_hotspot_object):
        """Test sanitization at restricted security level with enhanced object."""
        result = restricted_sanitizer.sanitize_hotspot(enhanced_hotspot_object)

        # All data should be preserved at restricted level
        assert "endpoints.py" in result["file_path"]
        assert result["risk_score"] == 0.91

        # Statistical significance should be included
        assert "statistical_significance" in result
        assert result["statistical_significance"]["p_value"] == 0.001
        assert result["statistical_significance"]["effect_size"] == 0.85

        # Temporal data should be included
        assert "temporal" in result
        assert result["temporal"]["weight"] == 0.95
        assert result["temporal"]["trend"] == "degrading"

    # Test Violation History Sanitization
    def test_sanitize_violation_history(self, internal_sanitizer, sample_hotspot_dict):
        """Test that violation history is properly sanitized."""
        result = internal_sanitizer.sanitize_hotspot(sample_hotspot_dict)

        violations = result["violation_history"]
        assert len(violations) == 2

        # First violation should be safe
        assert violations[0]["message"] == "Missing auth check"

        # Second violation with XSS should be encoded
        assert "<script>" not in violations[1]["message"]
        assert "&lt;script&gt;" in violations[1]["message"]

    def test_sanitize_violation_history_limits_size(self, internal_sanitizer):
        """Test that violation history is limited in size."""
        # Create hotspot with many violations
        violations = [{"message": f"Violation {i}"} for i in range(30)]
        hotspot = {"violation_history": violations}

        result = internal_sanitizer.sanitize_hotspot(hotspot)

        # Should limit based on security level
        assert len(result["violation_history"]) <= 20

    # Test Recommendation Sanitization
    def test_sanitize_recommendations(self, internal_sanitizer, sample_hotspot_dict):
        """Test that recommendations are sanitized."""
        result = internal_sanitizer.sanitize_hotspot(sample_hotspot_dict)

        assert len(result["recommendations"]) == 2
        assert all(isinstance(rec, str) for rec in result["recommendations"])
        assert result["recommendations"][0] == "Add authentication middleware"

    def test_sanitize_recommendations_with_xss(self, internal_sanitizer):
        """Test that recommendations with XSS are encoded."""
        hotspot = {"recommendations": ["Safe recommendation", "<script>alert('XSS')</script>"]}

        result = internal_sanitizer.sanitize_hotspot(hotspot)

        assert result["recommendations"][0] == "Safe recommendation"
        assert "&lt;script&gt;" in result["recommendations"][1]

    # Test List Sanitization
    def test_sanitize_hotspot_list(self, internal_sanitizer):
        """Test sanitization of multiple hotspots."""
        hotspots = [
            {"file_path": "file1.py", "risk_score": 0.8},
            {"file_path": "file2.py", "risk_score": 0.6},
            None,  # Invalid hotspot
            "string_hotspot",  # Non-dict hotspot
        ]

        results = internal_sanitizer.sanitize_hotspot_list(hotspots)

        assert len(results) == 4
        assert results[0]["file_path"] == "file1.py"
        assert results[1]["file_path"] == "file2.py"
        assert "error" in results[2]
        assert results[3]["type"] == "basic"

    # Test Temporal Pattern Sanitization
    def test_sanitize_temporal_patterns(self, restricted_sanitizer):
        """Test temporal pattern sanitization."""
        hotspot = {
            "temporal_patterns": {
                "trend": "improving",
                "seasonality": "quarterly",
                "change_rate": -0.05,
                "unsafe": "<script>alert(1)</script>",
            }
        }

        result = restricted_sanitizer.sanitize_hotspot(hotspot)

        temporal = result["temporal_patterns"]
        assert temporal["trend"] == "improving"
        assert temporal["seasonality"] == "quarterly"
        assert temporal["change_rate"] == -0.05
        assert "&lt;script&gt;" in temporal.get("unsafe", "")

    # Test Object to Dict Conversion
    def test_object_to_dict_conversion(self, internal_sanitizer):
        """Test conversion of objects to dictionaries."""

        # Object with to_dict method
        class CustomHotspot:
            def to_dict(self):
                return {"file_path": "custom.py", "risk_score": 0.7}

        result = internal_sanitizer.sanitize_hotspot(CustomHotspot())
        assert result["file_path"] == "custom.py"
        assert result["risk_score"] == 0.7

        # Object with __dict__
        class SimpleHotspot:
            def __init__(self):
                self.file_path = "simple.py"
                self.risk_score = 0.6
                self._private = "should_not_appear"

        result = internal_sanitizer.sanitize_hotspot(SimpleHotspot())
        assert result["file_path"] == "simple.py"
        assert result["risk_score"] == 0.6
        assert "_private" not in result

    # Test Redacted Summary
    def test_create_redacted_summary_public(self, public_sanitizer):
        """Test creation of redacted summary for public consumption."""
        hotspots = [
            {"risk_score": 0.9},
            {"risk_score": 0.7},
            {"risk_score": 0.5},
            {"risk_score": 0.3},
            {"risk_score": 0.1},
        ]

        summary = public_sanitizer.create_redacted_summary(hotspots)

        assert summary["total_hotspots"] == 5
        assert summary["risk_distribution"]["critical"] == 1
        assert summary["risk_distribution"]["high"] == 1
        assert summary["risk_distribution"]["medium"] == 1
        assert summary["risk_distribution"]["low"] == 2
        assert summary["details"] == "Full details available in restricted report"

    def test_create_redacted_summary_with_objects(self, public_sanitizer, enhanced_hotspot_object):
        """Test redacted summary with enhanced objects."""
        hotspots = [enhanced_hotspot_object]

        summary = public_sanitizer.create_redacted_summary(hotspots)

        assert summary["total_hotspots"] == 1
        assert summary["risk_distribution"]["critical"] == 1

    # Test Statistics
    def test_get_sanitization_stats(self, public_sanitizer):
        """Test sanitization statistics tracking."""
        # Perform some sanitizations
        public_sanitizer.sanitize_hotspot({"file_path": "test.py"})
        public_sanitizer.sanitize_hotspot({"file_path": "test2.py", "business_impact": "High"})

        stats = public_sanitizer.get_sanitization_stats()

        assert stats["total_sanitized"] == 2
        assert stats["paths_redacted"] == 2
        assert stats["sensitive_removed"] == 1
