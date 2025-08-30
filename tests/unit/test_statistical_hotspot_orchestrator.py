"""
Unit tests for StatisticalHotspotOrchestrator (GitHub Issue #43).

Tests the comprehensive statistical hotspot analysis system that replaces
the inadequate implementation in claude_code_auditor.py.
"""

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Skip tests if statistical components not available
try:
    import numpy as np
    import pandas as pd

    from tools.pre_audit.statistical_analysis.statistical_hotspot_orchestrator import (
        EnhancedArchitecturalHotspot,
        StatisticalHotspotOrchestrator,
    )
    from tools.pre_audit.statistical_analysis.temporal_weighting_engine import (
        TemporalViolation,
    )

    STATISTICAL_COMPONENTS_AVAILABLE = True
except ImportError:
    STATISTICAL_COMPONENTS_AVAILABLE = False
    # Create dummy classes for test collection
    EnhancedArchitecturalHotspot = None  # type: ignore
    StatisticalHotspotOrchestrator = None  # type: ignore
    TemporalViolation = None  # type: ignore
    pytest.skip("Statistical analysis dependencies not available", allow_module_level=True)


@pytest.fixture
def orchestrator():
    """Create StatisticalHotspotOrchestrator instance for testing."""
    return StatisticalHotspotOrchestrator()


@pytest.fixture
def sample_file_metrics():
    """Sample file metrics for testing."""
    return {
        "app/core/security.py": {
            "file_path": "app/core/security.py",
            "churn_score": 150.0,
            "complexity_score": 65.0,
            "change_frequency": 12.0,
            "file_size": 5432,
            "business_context": {
                "component_criticality": "critical",
                "usage_frequency": "high",
                "test_coverage_percent": 85.0,
                "team_experience_years": 4.0,
            },
        },
        "app/api/endpoints/users.py": {
            "file_path": "app/api/endpoints/users.py",
            "churn_score": 89.0,
            "complexity_score": 45.0,
            "change_frequency": 8.0,
            "file_size": 3210,
            "business_context": {
                "component_criticality": "high",
                "usage_frequency": "medium",
                "test_coverage_percent": 72.0,
                "team_experience_years": 3.0,
            },
        },
        "tests/test_utils.py": {
            "file_path": "tests/test_utils.py",
            "churn_score": 25.0,
            "complexity_score": 15.0,
            "change_frequency": 3.0,
            "file_size": 1200,
            "business_context": {
                "component_criticality": "low",
                "usage_frequency": "low",
                "test_coverage_percent": 95.0,
                "team_experience_years": 2.0,
            },
        },
    }


@pytest.fixture
def sample_violation_history():
    """Sample violation history for testing."""
    base_time = datetime.now() - timedelta(days=30)
    return [
        {
            "timestamp": base_time + timedelta(days=1),
            "file_path": "app/core/security.py",
            "violation_type": "security_issue",
            "severity": 8.5,
            "context": {"commit": "abc123", "message": "fix auth vulnerability"},
            "business_impact": "critical",
        },
        {
            "timestamp": base_time + timedelta(days=15),
            "file_path": "app/core/security.py",
            "violation_type": "complexity_issue",
            "severity": 6.0,
            "context": {"commit": "def456", "message": "refactor security module"},
            "business_impact": "critical",
        },
        {
            "timestamp": base_time + timedelta(days=20),
            "file_path": "app/api/endpoints/users.py",
            "violation_type": "performance_issue",
            "severity": 4.5,
            "context": {"commit": "ghi789", "message": "optimize user queries"},
            "business_impact": "high",
        },
        {
            "timestamp": base_time + timedelta(days=28),
            "file_path": "tests/test_utils.py",
            "violation_type": "minor_issue",
            "severity": 2.0,
            "context": {"commit": "jkl012", "message": "fix test assertion"},
            "business_impact": "low",
        },
    ]


class TestStatisticalHotspotOrchestrator:
    """Test suite for StatisticalHotspotOrchestrator."""

    def test_initialization(self, orchestrator):
        """Test orchestrator initialization."""
        assert orchestrator is not None
        assert hasattr(orchestrator, "statistical_detector")
        assert hasattr(orchestrator, "temporal_engine")
        assert hasattr(orchestrator, "bayesian_engine")
        assert hasattr(orchestrator, "feature_engineer")
        assert orchestrator.is_trained is False
        assert orchestrator.model_version == "1.0.0"

    def test_configuration_loading(self):
        """Test configuration loading from YAML."""
        # Test with default configuration
        orchestrator = StatisticalHotspotOrchestrator()
        assert orchestrator.config is not None
        assert "statistical_detection" in orchestrator.config
        assert "temporal_weighting" in orchestrator.config
        assert "bayesian_risk" in orchestrator.config

    def test_training_data_preparation(self, orchestrator, sample_file_metrics, sample_violation_history):
        """Test training data preparation."""
        training_data = orchestrator._prepare_training_data(sample_file_metrics, sample_violation_history)

        assert isinstance(training_data, pd.DataFrame)
        assert len(training_data) == len(sample_file_metrics)
        assert "file_path" in training_data.columns
        assert "churn_score" in training_data.columns
        assert "complexity_score" in training_data.columns
        assert "is_violation" in training_data.columns

        # Check violation counts are correct
        security_file_violations = training_data[training_data["file_path"] == "app/core/security.py"][
            "violation_count"
        ].iloc[0]
        assert security_file_violations == 2  # Two violations for security.py

    def test_business_impact_assessment(self, orchestrator):
        """Test business impact assessment from file paths."""
        assert orchestrator._assess_business_impact_from_path("app/core/auth.py") == "critical"
        assert orchestrator._assess_business_impact_from_path("app/api/users.py") == "high"
        assert orchestrator._assess_business_impact_from_path("tests/test_auth.py") == "low"
        assert orchestrator._assess_business_impact_from_path("app/utils/helpers.py") == "medium"

    def test_component_criticality_assessment(self, orchestrator):
        """Test component criticality assessment."""
        assert orchestrator._assess_component_criticality("app/core/security.py") == "critical"
        assert orchestrator._assess_component_criticality("app/api/endpoints/users.py") == "high"
        assert orchestrator._assess_component_criticality("app/utils/common.py") == "medium"
        assert orchestrator._assess_component_criticality("tests/test_api.py") == "low"

    def test_usage_frequency_assessment(self, orchestrator):
        """Test usage frequency assessment."""
        assert orchestrator._assess_usage_frequency("app/main.py") == "very_high"
        assert orchestrator._assess_usage_frequency("app/core/config.py") == "high"
        assert orchestrator._assess_usage_frequency("app/api/endpoints/health.py") == "high"
        assert orchestrator._assess_usage_frequency("tests/conftest.py") == "low"
        assert orchestrator._assess_usage_frequency("app/middleware/logging.py") == "medium"

    @pytest.mark.asyncio
    async def test_analyze_without_training(self, orchestrator, sample_file_metrics, sample_violation_history):
        """Test that analysis fails gracefully when models not trained."""
        with pytest.raises(ValueError, match="Statistical models must be trained"):
            orchestrator.analyze_architectural_hotspots(sample_file_metrics, sample_violation_history)

    def test_temporal_violation_conversion(self, orchestrator, sample_violation_history):
        """Test conversion of violation history to temporal violations."""
        temporal_violations = orchestrator._convert_to_temporal_violations(sample_violation_history)

        assert len(temporal_violations) == len(sample_violation_history)

        for violation in temporal_violations:
            assert hasattr(violation, "timestamp")
            assert hasattr(violation, "file_path")
            assert hasattr(violation, "violation_type")
            assert hasattr(violation, "severity")
            assert hasattr(violation, "business_impact")

    def test_orchestrator_summary(self, orchestrator):
        """Test orchestrator summary generation."""
        summary = orchestrator.get_orchestrator_summary()

        assert "model_state" in summary
        assert "component_summaries" in summary
        assert "configuration" in summary
        assert "training_history" in summary

        assert summary["model_state"]["is_trained"] is False
        assert summary["model_state"]["model_version"] == "1.0.0"
        assert summary["model_state"]["training_sessions"] == 0

    def test_risk_assessment_integration(self, orchestrator):
        """Test integrated risk assessment calculation."""
        # Mock statistical components for testing
        mock_statistical_result = Mock()
        mock_statistical_result.risk_probability = 0.7

        mock_temporal_result = Mock()
        mock_temporal_result.weighted_risk_score = 45.0

        mock_bayesian_result = Mock()
        mock_bayesian_result.risk_probability = 0.6

        integrated_risk = orchestrator._integrate_risk_assessments(
            mock_statistical_result, mock_temporal_result, mock_bayesian_result
        )

        assert 0.0 <= integrated_risk <= 1.0
        # Expected: 0.3*0.7 + 0.3*0.45 + 0.4*0.6 = 0.21 + 0.135 + 0.24 = 0.585
        assert abs(integrated_risk - 0.585) < 0.01

    def test_confidence_interval_calculation(self, orchestrator):
        """Test integrated confidence interval calculation."""
        mock_statistical_result = Mock()
        mock_statistical_result.confidence_interval = (0.2, 0.8)

        mock_bayesian_result = Mock()
        mock_bayesian_result.credible_interval = (0.3, 0.7)

        confidence_interval = orchestrator._calculate_integrated_confidence_interval(
            mock_statistical_result, mock_bayesian_result
        )

        assert confidence_interval[0] == 0.2  # min lower bound
        assert confidence_interval[1] == 0.8  # max upper bound

    def test_evidence_strength_assessment(self, orchestrator):
        """Test integrated evidence strength assessment."""
        mock_statistical_result = Mock()
        mock_statistical_result.evidence_strength = "strong"

        mock_bayesian_result = Mock()
        mock_bayesian_result.evidence_strength = "moderate"

        evidence_strength = orchestrator._assess_integrated_evidence_strength(
            mock_statistical_result, mock_bayesian_result
        )

        assert evidence_strength in [
            "insufficient",
            "weak",
            "moderate",
            "strong",
            "very_strong",
        ]
        # Expected: average of strong(3) and moderate(2) = 2.5 -> moderate
        assert evidence_strength == "moderate"

    def test_default_configuration_fallback(self):
        """Test fallback to default configuration when YAML loading fails."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            orchestrator = StatisticalHotspotOrchestrator()

            # Should have default configuration
            assert orchestrator.config is not None
            assert orchestrator.config["statistical_detection"]["significance_level"] == 0.05
            assert orchestrator.config["temporal_weighting"]["default_half_life_days"] == 30
            assert orchestrator.config["bayesian_risk"]["mcmc_samples"] == 10000

    @pytest.mark.parametrize(
        "file_path,expected_patterns",
        [
            ("app/core/security.py", ["security_patterns"]),
            ("app/api/endpoints/users.py", ["api_interface_patterns"]),
            ("app/models/user.py", ["database_patterns"]),
            ("tests/test_auth.py", ["testing_patterns"]),
            ("docs/readme.md", ["documentation_patterns"]),
            ("app/core/config.yaml", ["configuration_patterns"]),
        ],
    )
    def test_domain_pattern_detection(self, orchestrator, file_path, expected_patterns):
        """Test domain pattern detection for various file types."""
        # This would be tested through the feature engineer component
        # Verify the patterns are configured correctly
        for pattern_name in expected_patterns:
            assert pattern_name in orchestrator.feature_engineer.domain_patterns

    def test_model_version_tracking(self, orchestrator):
        """Test model version tracking and history."""
        assert orchestrator.model_version == "1.0.0"
        assert len(orchestrator.training_history) == 0

        # Training history would be populated after training
        # This ensures the infrastructure is in place


class TestEnhancedArchitecturalHotspot:
    """Test suite for EnhancedArchitecturalHotspot data class."""

    def test_hotspot_creation(self):
        """Test creation of enhanced hotspot."""
        # Mock the required components
        mock_statistical_result = Mock()
        mock_temporal_result = Mock()
        mock_bayesian_result = Mock()

        hotspot = EnhancedArchitecturalHotspot(
            file_path="app/core/security.py",
            statistical_significance=mock_statistical_result,
            temporal_assessment=mock_temporal_result,
            bayesian_risk=mock_bayesian_result,
            churn_score=150.0,
            complexity_score=65.0,
            integrated_risk_probability=0.75,
            risk_confidence_interval=(0.6, 0.9),
            risk_evidence_strength="strong",
            feature_contributions={"churn_score": 0.4, "complexity_score": 0.3},
            violation_history=["High churn: 150 changes"],
            temporal_patterns={"trend": "increasing"},
            analysis_timestamp=datetime.now(),
            model_version="1.0.0",
        )

        assert hotspot.file_path == "app/core/security.py"
        assert hotspot.churn_score == 150.0
        assert hotspot.complexity_score == 65.0
        assert hotspot.integrated_risk_probability == 0.75
        assert hotspot.risk_evidence_strength == "strong"

    def test_hotspot_to_dict(self):
        """Test hotspot serialization to dictionary."""
        # Mock the required components with to_dict methods
        mock_statistical_result = Mock()
        mock_statistical_result.to_dict.return_value = {"significance": 0.01}

        mock_temporal_result = Mock()
        mock_temporal_result.to_dict.return_value = {"weighted_score": 45.0}

        mock_bayesian_result = Mock()
        mock_bayesian_result.to_dict.return_value = {"probability": 0.7}

        timestamp = datetime.now()

        hotspot = EnhancedArchitecturalHotspot(
            file_path="test.py",
            statistical_significance=mock_statistical_result,
            temporal_assessment=mock_temporal_result,
            bayesian_risk=mock_bayesian_result,
            churn_score=100.0,
            complexity_score=50.0,
            integrated_risk_probability=0.6,
            risk_confidence_interval=(0.4, 0.8),
            risk_evidence_strength="moderate",
            feature_contributions={"test": 0.5},
            violation_history=["test"],
            temporal_patterns={"test": "pattern"},
            analysis_timestamp=timestamp,
            model_version="1.0.0",
        )

        result_dict = hotspot.to_dict()

        assert result_dict["file_path"] == "test.py"
        assert result_dict["churn_score"] == 100.0
        assert result_dict["integrated_risk_probability"] == 0.6
        assert result_dict["analysis_timestamp"] == timestamp.isoformat()
        assert result_dict["statistical_significance"] == {"significance": 0.01}
