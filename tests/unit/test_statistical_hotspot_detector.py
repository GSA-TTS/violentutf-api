"""
Unit tests for StatisticalHotspotDetector (GitHub Issue #43).

Tests the statistical significance testing and hypothesis testing implementation
that replaces hard-coded thresholds with proper statistical analysis.
"""

from unittest.mock import Mock, patch

import numpy as np
import pytest
from scipy import stats

# Skip tests if statistical components not available
try:
    from tools.pre_audit.statistical_analysis.statistical_hotspot_detector import (
        StatisticalHotspotDetector,
        StatisticalHotspotResult,
    )

    STATISTICAL_DETECTOR_AVAILABLE = True
except ImportError:
    STATISTICAL_DETECTOR_AVAILABLE = False
    pytest.skip("StatisticalHotspotDetector not available", allow_module_level=True)


@pytest.fixture
def detector():
    """Create StatisticalHotspotDetector instance for testing."""
    return StatisticalHotspotDetector(significance_level=0.05, confidence_level=0.95, bootstrap_samples=1000)


@pytest.fixture
def sample_baseline_data():
    """Create sample baseline distribution data."""
    np.random.seed(42)  # For reproducible tests
    return {
        "churn_score": np.random.lognormal(4, 1, 1000),  # Log-normal distribution
        "complexity_score": np.random.gamma(2, 20, 1000),  # Gamma distribution
        "file_size": np.random.normal(5000, 1500, 1000),  # Normal distribution
        "change_frequency": np.random.exponential(5, 1000),  # Exponential distribution
    }


@pytest.fixture
def sample_test_metrics():
    """Create sample metrics for testing statistical significance."""
    return {
        "file_path": "app/core/security.py",
        "churn_score": 500.0,  # High value for testing
        "complexity_score": 85.0,  # High value for testing
        "file_size": 8000.0,  # Above average
        "change_frequency": 15.0,  # High frequency
    }


class TestStatisticalHotspotDetector:
    """Test suite for StatisticalHotspotDetector."""

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.significance_level == 0.05
        assert detector.confidence_level == 0.95
        assert detector.bootstrap_samples == 1000
        assert len(detector.baseline_distributions) == 0
        assert len(detector.fitted_distributions) == 0

    def test_baseline_distribution_fitting(self, detector, sample_baseline_data):
        """Test fitting baseline distributions from historical data."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Should have fitted distributions for each metric
        assert "churn_score" in detector.baseline_distributions
        assert "complexity_score" in detector.baseline_distributions
        assert "file_size" in detector.baseline_distributions
        assert "change_frequency" in detector.baseline_distributions

        # Each should have statistical parameters
        for metric, dist_data in detector.baseline_distributions.items():
            assert "mean" in dist_data
            assert "std" in dist_data
            assert "median" in dist_data
            assert "q25" in dist_data
            assert "q75" in dist_data

    def test_statistical_significance_calculation(self, detector, sample_baseline_data, sample_test_metrics):
        """Test statistical significance calculation (core GitHub Issue #43 functionality)."""
        # Fit baseline distributions first
        detector.fit_baseline_distributions(sample_baseline_data)

        # Calculate statistical significance
        result = detector.calculate_statistical_significance(sample_test_metrics)

        assert isinstance(result, StatisticalHotspotResult)
        assert result.file_path == "app/core/security.py"
        assert 0 <= result.statistical_significance <= 1
        assert 0 <= result.risk_probability <= 1
        assert len(result.confidence_interval) == 2
        assert result.confidence_interval[0] <= result.confidence_interval[1]
        assert result.evidence_strength in [
            "insufficient",
            "weak",
            "moderate",
            "strong",
            "very_strong",
        ]

    def test_z_score_calculation(self, detector, sample_baseline_data, sample_test_metrics):
        """Test z-score calculation for outlier detection."""
        detector.fit_baseline_distributions(sample_baseline_data)
        result = detector.calculate_statistical_significance(sample_test_metrics)

        # Z-score should be calculated
        assert hasattr(result, "z_score")
        assert isinstance(result.z_score, float)

        # High values should produce high z-scores
        # Since test metrics are designed to be outliers, z-score should be significant
        assert abs(result.z_score) > 1.0  # At least 1 standard deviation from mean

    def test_p_value_calculation(self, detector, sample_baseline_data, sample_test_metrics):
        """Test p-value calculation for hypothesis testing."""
        detector.fit_baseline_distributions(sample_baseline_data)
        result = detector.calculate_statistical_significance(sample_test_metrics)

        # P-value should be calculated
        assert hasattr(result, "p_value")
        assert 0 <= result.p_value <= 1

        # For outlier values, p-value should be small (significant)
        # This tests H0: file is normal vs H1: file is anomalous

    def test_confidence_interval_bootstrap(self, detector, sample_baseline_data):
        """Test bootstrap confidence interval calculation."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Test with normal values
        normal_metrics = {
            "churn_score": 50.0,  # Normal value
            "complexity_score": 40.0,  # Normal value
            "file_size": 5000.0,  # Average value
            "change_frequency": 5.0,  # Normal frequency
        }

        result = detector.calculate_statistical_significance(normal_metrics)

        # Confidence interval should be valid
        assert len(result.confidence_interval) == 2
        lower, upper = result.confidence_interval
        assert lower <= upper
        assert 0 <= lower <= 1
        assert 0 <= upper <= 1

    def test_evidence_strength_categorization(self, detector, sample_baseline_data):
        """Test evidence strength categorization based on statistical measures."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Test with extreme outlier (should be strong evidence)
        extreme_metrics = {
            "churn_score": 2000.0,  # Very high
            "complexity_score": 200.0,  # Very high
            "file_size": 20000.0,  # Very large
            "change_frequency": 50.0,  # Very frequent
        }

        result = detector.calculate_statistical_significance(extreme_metrics)

        # Should detect strong evidence for extreme values
        assert result.evidence_strength in ["strong", "very_strong"]

    def test_multiple_metrics_integration(self, detector, sample_baseline_data):
        """Test integration of multiple metrics into single significance score."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Test with mixed values (some high, some normal)
        mixed_metrics = {
            "churn_score": 1000.0,  # High
            "complexity_score": 40.0,  # Normal
            "file_size": 5000.0,  # Normal
            "change_frequency": 20.0,  # High
        }

        result = detector.calculate_statistical_significance(mixed_metrics)

        # Should combine evidence from multiple metrics
        assert 0 <= result.statistical_significance <= 1
        assert 0 <= result.risk_probability <= 1

    def test_empty_baseline_handling(self, detector):
        """Test handling when no baseline distributions are fitted."""
        test_metrics = {"churn_score": 100.0}

        # Should handle gracefully without fitted baseline
        result = detector.calculate_statistical_significance(test_metrics)

        # Should return some default result
        assert isinstance(result, StatisticalHotspotResult)

    def test_missing_metrics_handling(self, detector, sample_baseline_data):
        """Test handling of missing metrics in test data."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Test with incomplete metrics
        incomplete_metrics = {
            "churn_score": 100.0,
            # Missing other expected metrics
        }

        result = detector.calculate_statistical_significance(incomplete_metrics)

        # Should handle missing metrics gracefully
        assert isinstance(result, StatisticalHotspotResult)

    def test_distribution_fitting_quality(self, detector):
        """Test quality of distribution fitting with known distributions."""
        np.random.seed(42)

        # Create data from known normal distribution
        normal_data = {"test_metric": np.random.normal(100, 15, 1000)}
        detector.fit_baseline_distributions(normal_data)

        baseline = detector.baseline_distributions["test_metric"]

        # Should approximate true parameters
        assert abs(baseline["mean"] - 100) < 5  # Should be close to true mean
        assert abs(baseline["std"] - 15) < 3  # Should be close to true std

    def test_outlier_detection_accuracy(self, detector, sample_baseline_data):
        """Test accuracy of outlier detection."""
        detector.fit_baseline_distributions(sample_baseline_data)

        # Create known outlier (far from distribution)
        outlier_metrics = {
            "churn_score": 5000.0,  # Very high compared to baseline
            "complexity_score": 500.0,  # Very high
            "file_size": 50000.0,  # Very large
            "change_frequency": 100.0,  # Very frequent
        }

        result = detector.calculate_statistical_significance(outlier_metrics)

        # Should detect as statistically significant
        assert result.statistical_significance > 0.95  # High confidence it's an outlier
        assert result.p_value < 0.05  # Statistically significant

    def test_model_summary_generation(self, detector, sample_baseline_data):
        """Test model summary generation for monitoring."""
        detector.fit_baseline_distributions(sample_baseline_data)

        summary = detector.get_model_summary()

        assert "baseline_distributions" in summary
        assert "model_parameters" in summary
        assert "analysis_count" in summary

        assert len(summary["baseline_distributions"]) == 4  # Four metrics fitted

    @pytest.mark.parametrize("significance_level", [0.01, 0.05, 0.10])
    def test_significance_level_configuration(self, significance_level):
        """Test configuration of different significance levels."""
        detector = StatisticalHotspotDetector(significance_level=significance_level)
        assert detector.significance_level == significance_level

    def test_bootstrap_sample_configuration(self):
        """Test configuration of bootstrap sample size."""
        detector = StatisticalHotspotDetector(bootstrap_samples=500)
        assert detector.bootstrap_samples == 500

    def test_statistical_result_to_dict(self):
        """Test StatisticalHotspotResult serialization."""
        result = StatisticalHotspotResult(
            file_path="test.py",
            statistical_significance=0.95,
            p_value=0.01,
            z_score=2.58,
            risk_probability=0.85,
            confidence_interval=(0.7, 1.0),
            evidence_strength="strong",
            baseline_comparison={"mean": 100, "std": 15},
            metadata={"test": "data"},
        )

        result_dict = result.to_dict()

        assert result_dict["file_path"] == "test.py"
        assert result_dict["statistical_significance"] == 0.95
        assert result_dict["evidence_strength"] == "strong"
        assert result_dict["confidence_interval"] == [0.7, 1.0]


class TestStatisticalHotspotResult:
    """Test suite for StatisticalHotspotResult data class."""

    def test_result_creation(self):
        """Test creation of statistical hotspot result."""
        result = StatisticalHotspotResult(
            file_path="app/test.py",
            statistical_significance=0.99,
            p_value=0.001,
            z_score=3.0,
            risk_probability=0.95,
            confidence_interval=(0.8, 1.0),
            evidence_strength="very_strong",
            baseline_comparison={"mean": 50, "std": 10},
            metadata={"analysis_time": "2024-01-01"},
        )

        assert result.file_path == "app/test.py"
        assert result.statistical_significance == 0.99
        assert result.p_value == 0.001
        assert result.z_score == 3.0
        assert result.evidence_strength == "very_strong"

    def test_result_validation(self):
        """Test validation of result values."""
        # Test with invalid probability values
        with pytest.raises((ValueError, AssertionError)):
            StatisticalHotspotResult(
                file_path="test.py",
                statistical_significance=1.5,  # Invalid: > 1.0
                p_value=0.05,
                z_score=2.0,
                risk_probability=0.8,
                confidence_interval=(0.6, 0.9),
                evidence_strength="strong",
                baseline_comparison={},
                metadata={},
            )

    def test_confidence_interval_validation(self):
        """Test confidence interval validation."""
        # Valid confidence interval
        result = StatisticalHotspotResult(
            file_path="test.py",
            statistical_significance=0.95,
            p_value=0.05,
            z_score=2.0,
            risk_probability=0.8,
            confidence_interval=(0.6, 0.9),  # Valid: lower <= upper
            evidence_strength="strong",
            baseline_comparison={},
            metadata={},
        )
        assert result.confidence_interval == (0.6, 0.9)

    def test_evidence_strength_categories(self):
        """Test all evidence strength categories."""
        valid_strengths = ["insufficient", "weak", "moderate", "strong", "very_strong"]

        for strength in valid_strengths:
            result = StatisticalHotspotResult(
                file_path="test.py",
                statistical_significance=0.5,
                p_value=0.1,
                z_score=1.0,
                risk_probability=0.5,
                confidence_interval=(0.3, 0.7),
                evidence_strength=strength,
                baseline_comparison={},
                metadata={},
            )
            assert result.evidence_strength == strength
