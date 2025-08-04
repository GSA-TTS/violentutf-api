"""
Unit tests for TemporalWeightingEngine (GitHub Issue #43).

Tests the exponential decay temporal weighting implementation that addresses
the core requirement of GitHub Issue #43.
"""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import numpy as np
import pytest

# Skip tests if statistical components not available
try:
    from tools.pre_audit.statistical_analysis.temporal_weighting_engine import (
        TemporalViolation,
        TemporalWeightingEngine,
        TemporalWeightingResult,
    )

    TEMPORAL_COMPONENTS_AVAILABLE = True
except ImportError:
    TEMPORAL_COMPONENTS_AVAILABLE = False
    pytest.skip("TemporalWeightingEngine not available", allow_module_level=True)


@pytest.fixture
def temporal_engine():
    """Create TemporalWeightingEngine instance for testing."""
    return TemporalWeightingEngine(
        default_half_life_days=30,
        max_age_days=365,
        business_multipliers={
            "critical": 2.0,
            "high": 1.5,
            "security": 1.3,
            "medium": 1.0,
            "low": 0.7,
        },
    )


@pytest.fixture
def sample_violations():
    """Create sample temporal violations for testing."""
    current_time = datetime.now()
    return [
        TemporalViolation(
            timestamp=current_time - timedelta(days=1),
            file_path="app/core/security.py",
            violation_type="security_issue",
            severity=8.5,
            context={"commit": "abc123"},
            business_impact="critical",
        ),
        TemporalViolation(
            timestamp=current_time - timedelta(days=7),
            file_path="app/core/security.py",
            violation_type="complexity_issue",
            severity=6.0,
            context={"commit": "def456"},
            business_impact="critical",
        ),
        TemporalViolation(
            timestamp=current_time - timedelta(days=30),
            file_path="app/core/security.py",
            violation_type="performance_issue",
            severity=4.5,
            context={"commit": "ghi789"},
            business_impact="critical",
        ),
        TemporalViolation(
            timestamp=current_time - timedelta(days=60),
            file_path="app/api/users.py",
            violation_type="minor_issue",
            severity=2.0,
            context={"commit": "jkl012"},
            business_impact="medium",
        ),
        TemporalViolation(
            timestamp=current_time - timedelta(days=200),
            file_path="app/utils/helpers.py",
            violation_type="style_issue",
            severity=1.0,
            context={"commit": "mno345"},
            business_impact="low",
        ),
    ]


class TestTemporalWeightingEngine:
    """Test suite for TemporalWeightingEngine."""

    def test_initialization(self, temporal_engine):
        """Test temporal weighting engine initialization."""
        assert temporal_engine.default_half_life_days == 30
        assert temporal_engine.max_age_days == 365
        assert temporal_engine.business_multipliers["critical"] == 2.0
        assert temporal_engine.business_multipliers["security"] == 1.3

    def test_exponential_decay_calculation(self, temporal_engine):
        """Test exponential decay weight calculation (core GitHub Issue #43 requirement)."""
        # Test decay function: weight = exp(-λ * age_days) where λ = ln(2) / half_life

        # At half-life (30 days), weight should be 0.5
        weight_half_life = temporal_engine._calculate_exponential_decay_weight(30, 30)
        assert abs(weight_half_life - 0.5) < 0.001

        # At 0 days, weight should be 1.0
        weight_current = temporal_engine._calculate_exponential_decay_weight(0, 30)
        assert abs(weight_current - 1.0) < 0.001

        # At 60 days (2 * half_life), weight should be 0.25
        weight_double = temporal_engine._calculate_exponential_decay_weight(60, 30)
        assert abs(weight_double - 0.25) < 0.001

        # At 90 days (3 * half_life), weight should be 0.125
        weight_triple = temporal_engine._calculate_exponential_decay_weight(90, 30)
        assert abs(weight_triple - 0.125) < 0.001

    def test_business_impact_multiplier(self, temporal_engine):
        """Test business impact multiplier application."""
        base_weight = 0.5

        # Critical business impact should double the weight
        critical_weight = temporal_engine._apply_business_multiplier(base_weight, "critical")
        assert critical_weight == 1.0  # 0.5 * 2.0

        # High business impact should multiply by 1.5
        high_weight = temporal_engine._apply_business_multiplier(base_weight, "high")
        assert high_weight == 0.75  # 0.5 * 1.5

        # Security business impact should multiply by 1.3
        security_weight = temporal_engine._apply_business_multiplier(base_weight, "security")
        assert security_weight == 0.65  # 0.5 * 1.3

        # Medium business impact should not change weight
        medium_weight = temporal_engine._apply_business_multiplier(base_weight, "medium")
        assert medium_weight == 0.5  # 0.5 * 1.0

        # Low business impact should reduce weight
        low_weight = temporal_engine._apply_business_multiplier(base_weight, "low")
        assert low_weight == 0.35  # 0.5 * 0.7

    def test_temporal_weighted_risk_calculation(self, temporal_engine, sample_violations):
        """Test comprehensive temporal weighted risk calculation."""
        current_time = datetime.now()

        results = temporal_engine.calculate_temporal_weighted_risk(sample_violations, current_time)

        # Should have results for each file
        assert "app/core/security.py" in results
        assert "app/api/users.py" in results
        assert "app/utils/helpers.py" in results

        # Security file should have highest weighted risk (3 violations, all critical)
        security_result = results["app/core/security.py"]
        assert isinstance(security_result, TemporalWeightingResult)
        assert security_result.violation_count == 3
        assert security_result.weighted_risk_score > 0

        # More recent violations should contribute more to the score
        # 1-day old violation should have much higher weight than 30-day old

    def test_violation_age_filtering(self, temporal_engine, sample_violations):
        """Test that violations older than max_age are filtered out."""
        # Create engine with short max age
        short_engine = TemporalWeightingEngine(max_age_days=90)
        current_time = datetime.now()

        results = short_engine.calculate_temporal_weighted_risk(sample_violations, current_time)

        # 200-day old violation should be filtered out
        if "app/utils/helpers.py" in results:
            helpers_result = results["app/utils/helpers.py"]
            # Should have 0 violations due to age filtering
            assert helpers_result.violation_count == 0 or helpers_result.weighted_risk_score == 0

    def test_temporal_concentration_calculation(self, temporal_engine):
        """Test temporal concentration measurement."""
        current_time = datetime.now()

        # Create violations clustered in time (burst pattern)
        burst_violations = [
            TemporalViolation(
                timestamp=current_time - timedelta(days=1),
                file_path="test_file.py",
                violation_type="issue",
                severity=5.0,
                context={},
                business_impact="medium",
            ),
            TemporalViolation(
                timestamp=current_time - timedelta(days=2),
                file_path="test_file.py",
                violation_type="issue",
                severity=5.0,
                context={},
                business_impact="medium",
            ),
            TemporalViolation(
                timestamp=current_time - timedelta(days=3),
                file_path="test_file.py",
                violation_type="issue",
                severity=5.0,
                context={},
                business_impact="medium",
            ),
        ]

        results = temporal_engine.calculate_temporal_weighted_risk(burst_violations, current_time)
        test_result = results["test_file.py"]

        # Should detect high temporal concentration (violations close together)
        assert test_result.temporal_concentration > 0.5

    def test_recent_violations_counting(self, temporal_engine, sample_violations):
        """Test recent violations counting (within recency window)."""
        current_time = datetime.now()

        results = temporal_engine.calculate_temporal_weighted_risk(sample_violations, current_time)
        security_result = results["app/core/security.py"]

        # Should count violations within 30-day recency window
        # Security file has violations at 1, 7, and 30 days - all within window
        assert security_result.recent_violations >= 2  # At least 1-day and 7-day violations

    def test_age_range_calculation(self, temporal_engine, sample_violations):
        """Test age range calculation for violation spread."""
        current_time = datetime.now()

        results = temporal_engine.calculate_temporal_weighted_risk(sample_violations, current_time)
        security_result = results["app/core/security.py"]

        # Security file has violations spanning from 1 to 30 days
        assert security_result.age_range_days >= 29  # Approximately 30-1 = 29 days

    def test_empty_violations_handling(self, temporal_engine):
        """Test handling of empty violation list."""
        current_time = datetime.now()

        results = temporal_engine.calculate_temporal_weighted_risk([], current_time)

        assert len(results) == 0

    def test_single_violation_handling(self, temporal_engine):
        """Test handling of single violation."""
        current_time = datetime.now()
        single_violation = [
            TemporalViolation(
                timestamp=current_time - timedelta(days=5),
                file_path="single_file.py",
                violation_type="test_issue",
                severity=3.0,
                context={},
                business_impact="low",
            )
        ]

        results = temporal_engine.calculate_temporal_weighted_risk(single_violation, current_time)

        assert "single_file.py" in results
        result = results["single_file.py"]
        assert result.violation_count == 1
        assert result.weighted_risk_score > 0
        assert result.temporal_concentration == 0  # No concentration with single violation

    def test_decay_parameter_optimization(self, temporal_engine, sample_violations):
        """Test decay parameter optimization functionality."""
        optimization_results = temporal_engine.optimize_decay_parameters(sample_violations)

        assert "optimal_half_life" in optimization_results
        assert "optimization_score" in optimization_results
        assert "optimization_method" in optimization_results

        # Optimal half-life should be positive
        assert optimization_results["optimal_half_life"] > 0

        # Optimization score should be between 0 and 1
        assert 0 <= optimization_results["optimization_score"] <= 1

    def test_temporal_analysis_summary(self, temporal_engine):
        """Test temporal analysis summary generation."""
        summary = temporal_engine.get_temporal_analysis_summary()

        assert "configuration" in summary
        assert "optimization_history" in summary
        assert "statistics" in summary

        assert summary["configuration"]["default_half_life_days"] == 30
        assert summary["configuration"]["max_age_days"] == 365

    @pytest.mark.parametrize(
        "half_life,age,expected_weight",
        [
            (30, 0, 1.0),  # Current time
            (30, 30, 0.5),  # One half-life
            (30, 60, 0.25),  # Two half-lives
            (15, 15, 0.5),  # Different half-life
            (60, 60, 0.5),  # Different half-life
        ],
    )
    def test_exponential_decay_parameters(self, temporal_engine, half_life, age, expected_weight):
        """Test exponential decay with various parameters."""
        weight = temporal_engine._calculate_exponential_decay_weight(age, half_life)
        assert abs(weight - expected_weight) < 0.001

    def test_violation_severity_weighting(self, temporal_engine):
        """Test that violation severity affects weighted risk score."""
        current_time = datetime.now()

        # High severity violation
        high_severity = [
            TemporalViolation(
                timestamp=current_time - timedelta(days=1),
                file_path="high_severity.py",
                violation_type="critical_issue",
                severity=9.0,
                context={},
                business_impact="medium",
            )
        ]

        # Low severity violation
        low_severity = [
            TemporalViolation(
                timestamp=current_time - timedelta(days=1),
                file_path="low_severity.py",
                violation_type="minor_issue",
                severity=1.0,
                context={},
                business_impact="medium",
            )
        ]

        high_results = temporal_engine.calculate_temporal_weighted_risk(high_severity, current_time)
        low_results = temporal_engine.calculate_temporal_weighted_risk(low_severity, current_time)

        high_score = high_results["high_severity.py"].weighted_risk_score
        low_score = low_results["low_severity.py"].weighted_risk_score

        # High severity should result in higher weighted risk score
        assert high_score > low_score


class TestTemporalViolation:
    """Test suite for TemporalViolation data class."""

    def test_violation_creation(self):
        """Test creation of temporal violation."""
        timestamp = datetime.now()
        violation = TemporalViolation(
            timestamp=timestamp,
            file_path="test.py",
            violation_type="test_violation",
            severity=5.0,
            context={"key": "value"},
            business_impact="medium",
        )

        assert violation.timestamp == timestamp
        assert violation.file_path == "test.py"
        assert violation.violation_type == "test_violation"
        assert violation.severity == 5.0
        assert violation.context == {"key": "value"}
        assert violation.business_impact == "medium"

    def test_violation_age_calculation(self):
        """Test violation age calculation."""
        current_time = datetime.now()
        old_time = current_time - timedelta(days=10)

        violation = TemporalViolation(
            timestamp=old_time,
            file_path="test.py",
            violation_type="test",
            severity=1.0,
            context={},
            business_impact="low",
        )

        age = violation.age_in_days(current_time)
        assert abs(age - 10.0) < 0.1  # Allow small floating point differences


class TestTemporalWeightingResult:
    """Test suite for TemporalWeightingResult data class."""

    def test_result_creation(self):
        """Test creation of temporal weighting result."""
        result = TemporalWeightingResult(
            file_path="test.py",
            weighted_risk_score=45.7,
            violation_count=5,
            age_range_days=30,
            temporal_concentration=0.8,
            recent_violations=3,
            decay_parameters={"method": "exponential", "half_life": 30.0},
            metadata={"test": "data"},
        )

        assert result.file_path == "test.py"
        assert result.weighted_risk_score == 45.7
        assert result.violation_count == 5
        assert result.recent_violations == 3
        assert result.temporal_concentration == 0.8

    def test_result_to_dict(self):
        """Test result serialization to dictionary."""
        result = TemporalWeightingResult(
            file_path="test.py",
            weighted_risk_score=100.0,
            violation_count=10,
            age_range_days=60,
            temporal_concentration=0.5,
            recent_violations=7,
            decay_parameters={"method": "exponential"},
            metadata={},
        )

        result_dict = result.to_dict()

        assert result_dict["file_path"] == "test.py"
        assert result_dict["weighted_risk_score"] == 100.0
        assert result_dict["violation_count"] == 10
        assert result_dict["temporal_concentration"] == 0.5
