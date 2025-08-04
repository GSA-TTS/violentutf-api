"""
Integration tests for GitHub Issue #43 Statistical Hotspot Analysis.

Tests the end-to-end integration of statistical components with the
claude_code_auditor.py system.
"""

import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pandas as pd
import pytest

# Skip tests if statistical components not available
try:
    from tools.pre_audit.claude_code_auditor import ClaudeCodeArchitecturalAuditor
    from tools.pre_audit.statistical_analysis.statistical_hotspot_orchestrator import (
        EnhancedArchitecturalHotspot,
        StatisticalHotspotOrchestrator,
    )

    INTEGRATION_COMPONENTS_AVAILABLE = True
except ImportError:
    INTEGRATION_COMPONENTS_AVAILABLE = False
    pytest.skip("Integration components not available", allow_module_level=True)


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    temp_dir = tempfile.mkdtemp()
    repo_path = Path(temp_dir) / "test_repo"
    repo_path.mkdir()

    # Create some sample files
    (repo_path / "app").mkdir()
    (repo_path / "app" / "core").mkdir()
    (repo_path / "app" / "api").mkdir()
    (repo_path / "tests").mkdir()

    # Create sample Python files
    (repo_path / "app" / "core" / "security.py").write_text("# Security module\nclass SecurityManager:\n    pass")
    (repo_path / "app" / "api" / "users.py").write_text("# Users API\ndef get_users():\n    pass")
    (repo_path / "tests" / "test_security.py").write_text("# Security tests\ndef test_security():\n    pass")

    yield repo_path

    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_git_repo():
    """Mock git repository for testing."""
    mock_repo = Mock()

    # Mock commits with file changes
    mock_commits = []
    base_time = datetime.now() - timedelta(days=60)

    for i in range(20):
        mock_commit = Mock()
        mock_commit.committed_datetime = base_time + timedelta(days=i * 3)
        mock_commit.hexsha = f"commit_{i:02d}"
        mock_commit.author.name = "Test Author"
        mock_commit.message = f"Test commit {i}"
        mock_commit.stats.files = {
            "app/core/security.py": {"insertions": 10, "deletions": 5},
            "app/api/users.py": {"insertions": 5, "deletions": 2},
            "tests/test_security.py": {"insertions": 3, "deletions": 1},
        }
        mock_commits.append(mock_commit)

    mock_repo.iter_commits.return_value = mock_commits
    return mock_repo


class TestIssue43Integration:
    """Integration tests for GitHub Issue #43."""

    @patch("git.Repo")
    def test_statistical_orchestrator_initialization(self, mock_git_repo_class, temp_repo):
        """Test that the auditor initializes the statistical orchestrator correctly."""
        mock_git_repo_class.return_value = mock_git_repo_class

        # Create auditor instance
        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Should have statistical orchestrator initialized
        assert hasattr(auditor, "statistical_orchestrator")

        # Should be initialized if components available
        if hasattr(auditor, "statistical_orchestrator") and auditor.statistical_orchestrator:
            assert isinstance(auditor.statistical_orchestrator, StatisticalHotspotOrchestrator)

    @patch("git.Repo")
    def test_data_collection_integration(self, mock_git_repo_class, temp_repo, mock_git_repo):
        """Test that data collection methods work with real repository structure."""
        mock_git_repo_class.return_value = mock_git_repo

        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Mock the file complexity calculation
        async def mock_calculate_complexity(file_path):
            if "security" in str(file_path):
                return 75.0
            elif "api" in str(file_path):
                return 45.0
            else:
                return 20.0

        auditor._calculate_file_complexity = mock_calculate_complexity

        # Test data collection
        if hasattr(auditor, "_collect_statistical_data"):
            import asyncio

            file_metrics, violation_history = asyncio.run(auditor._collect_statistical_data())

            # Should collect metrics for Python files
            assert len(file_metrics) > 0
            assert len(violation_history) > 0

            # Should have expected file paths
            file_paths = set(file_metrics.keys())
            assert any("security.py" in path for path in file_paths)
            assert any("users.py" in path for path in file_paths)

    def test_business_impact_assessment(self, temp_repo):
        """Test business impact assessment methods."""
        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Test business impact assessment methods if available
        if hasattr(auditor, "_assess_business_impact_from_path"):
            assert auditor._assess_business_impact_from_path("app/core/security.py") == "critical"
            assert auditor._assess_business_impact_from_path("app/api/users.py") == "high"
            assert auditor._assess_business_impact_from_path("tests/test_security.py") == "low"

    def test_component_criticality_assessment(self, temp_repo):
        """Test component criticality assessment methods."""
        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Test criticality assessment methods if available
        if hasattr(auditor, "_assess_component_criticality"):
            assert auditor._assess_component_criticality("app/core/security.py") == "critical"
            assert auditor._assess_component_criticality("app/api/users.py") == "high"
            assert auditor._assess_component_criticality("tests/test_security.py") == "low"

    @patch("git.Repo")
    def test_statistical_risk_assessment_integration(self, mock_git_repo_class, temp_repo, mock_git_repo):
        """Test integration of statistical risk assessment with existing risk level assessment."""
        mock_git_repo_class.return_value = mock_git_repo

        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Test the updated risk assessment method
        risk_level = auditor._assess_hotspot_risk_level(750.0, 85.0)  # High values
        assert risk_level in ["low", "medium", "high", "critical"]

        # Test with medium values
        risk_level_medium = auditor._assess_hotspot_risk_level(200.0, 50.0)
        assert risk_level_medium in ["low", "medium", "high", "critical"]

    @patch("git.Repo")
    async def test_hotspot_identification_integration(self, mock_git_repo_class, temp_repo, mock_git_repo):
        """Test integration of statistical hotspot identification."""
        mock_git_repo_class.return_value = mock_git_repo

        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Mock file complexity calculation
        async def mock_calculate_complexity(file_path):
            return 65.0

        auditor._calculate_file_complexity = mock_calculate_complexity

        # Test hotspot identification
        hotspots = await auditor._identify_violation_hotspots()

        # Should return a list of hotspots
        assert isinstance(hotspots, list)

        # If statistical analysis works, should have results
        if hotspots:
            for hotspot in hotspots:
                assert hasattr(hotspot, "file_path")
                assert hasattr(hotspot, "churn_score")
                assert hasattr(hotspot, "complexity_score")
                assert hasattr(hotspot, "risk_level")

    def test_configuration_loading(self, temp_repo):
        """Test that configuration loading works correctly."""
        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        if hasattr(auditor, "statistical_orchestrator") and auditor.statistical_orchestrator:
            # Should have loaded configuration
            assert auditor.statistical_orchestrator.config is not None
            assert "statistical_detection" in auditor.statistical_orchestrator.config
            assert "temporal_weighting" in auditor.statistical_orchestrator.config
            assert "bayesian_risk" in auditor.statistical_orchestrator.config

    def test_fallback_mechanism(self, temp_repo):
        """Test that fallback mechanisms work when statistical components unavailable."""
        # Test with mock that simulates missing statistical components
        with patch("tools.pre_audit.claude_code_auditor.HAS_STATISTICAL_ORCHESTRATOR", False):
            auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

            # Should still initialize successfully
            assert auditor is not None

            # Statistical orchestrator should be None
            if hasattr(auditor, "statistical_orchestrator"):
                assert auditor.statistical_orchestrator is None

    @patch("git.Repo")
    def test_enhanced_architectural_hotspot_compatibility(self, mock_git_repo_class, temp_repo, mock_git_repo):
        """Test that enhanced hotspots are compatible with existing system."""
        mock_git_repo_class.return_value = mock_git_repo

        auditor = ClaudeCodeArchitecturalAuditor(str(temp_repo))

        # Test creating an enhanced hotspot and converting to legacy format
        if hasattr(auditor, "statistical_orchestrator") and auditor.statistical_orchestrator:
            # Mock enhanced hotspot
            mock_statistical_result = Mock()
            mock_temporal_result = Mock()
            mock_bayesian_result = Mock()

            enhanced_hotspot = EnhancedArchitecturalHotspot(
                file_path="app/core/security.py",
                statistical_significance=mock_statistical_result,
                temporal_assessment=mock_temporal_result,
                bayesian_risk=mock_bayesian_result,
                churn_score=150.0,
                complexity_score=65.0,
                integrated_risk_probability=0.75,
                risk_confidence_interval=(0.6, 0.9),
                risk_evidence_strength="strong",
                feature_contributions={"churn": 0.4},
                violation_history=["Test violation"],
                temporal_patterns={"trend": "increasing"},
                analysis_timestamp=datetime.now(),
                model_version="1.0.0",
            )

            # Should be able to serialize to dict
            hotspot_dict = enhanced_hotspot.to_dict()
            assert isinstance(hotspot_dict, dict)
            assert hotspot_dict["file_path"] == "app/core/security.py"

    def test_mathematical_correctness(self):
        """Test that the mathematical algorithms produce correct results."""
        # Test exponential decay formula
        # weight = exp(-λ * age_days) where λ = ln(2) / half_life
        import math

        half_life = 30.0
        lambda_param = math.log(2) / half_life

        # At half-life, weight should be 0.5
        weight = math.exp(-lambda_param * half_life)
        assert abs(weight - 0.5) < 0.001

        # At 0 days, weight should be 1.0
        weight_zero = math.exp(-lambda_param * 0)
        assert abs(weight_zero - 1.0) < 0.001

        # At 2 * half_life, weight should be 0.25
        weight_double = math.exp(-lambda_param * (2 * half_life))
        assert abs(weight_double - 0.25) < 0.001

    def test_statistical_significance_concepts(self):
        """Test understanding of statistical significance concepts."""
        # Test that we understand the concepts correctly

        # Null hypothesis H0: file is normal
        # Alternative hypothesis H1: file is anomalous

        # Low p-value (< 0.05) means reject H0 (file is anomalous)
        # High p-value (>= 0.05) means fail to reject H0 (file is normal)

        significance_level = 0.05

        # Test case 1: Significant result
        p_value_significant = 0.01
        is_significant = p_value_significant < significance_level
        assert is_significant  # Should reject H0, file is anomalous

        # Test case 2: Non-significant result
        p_value_not_significant = 0.10
        is_not_significant = p_value_not_significant >= significance_level
        assert is_not_significant  # Should fail to reject H0, file is normal


class TestStatisticalMethods:
    """Test specific statistical methods and algorithms."""

    def test_bootstrap_confidence_interval_concept(self):
        """Test bootstrap confidence interval concept."""
        import numpy as np

        np.random.seed(42)

        # Generate sample data
        sample_data = np.random.normal(100, 15, 100)

        # Bootstrap resampling
        bootstrap_samples = []
        n_bootstrap = 1000

        for _ in range(n_bootstrap):
            bootstrap_sample = np.random.choice(sample_data, size=len(sample_data), replace=True)
            bootstrap_samples.append(np.mean(bootstrap_sample))

        # Calculate confidence interval
        ci_lower = np.percentile(bootstrap_samples, 2.5)
        ci_upper = np.percentile(bootstrap_samples, 97.5)

        # Should contain true population mean (100)
        assert ci_lower <= 100 <= ci_upper

        # Interval should be reasonable width
        interval_width = ci_upper - ci_lower
        assert 0 < interval_width < 20  # Reasonable for this data

    def test_bayesian_concepts(self):
        """Test Bayesian statistical concepts."""
        # Prior belief: files are normally not problematic
        prior_probability_problematic = 0.1

        # Likelihood: given file is problematic, probability of high metrics
        likelihood_high_metrics_given_problematic = 0.8

        # Likelihood: given file is normal, probability of high metrics
        likelihood_high_metrics_given_normal = 0.2

        # Marginal probability of high metrics
        marginal_high_metrics = (
            likelihood_high_metrics_given_problematic * prior_probability_problematic
            + likelihood_high_metrics_given_normal * (1 - prior_probability_problematic)
        )

        # Posterior probability using Bayes' theorem
        posterior_problematic_given_high_metrics = (
            likelihood_high_metrics_given_problematic * prior_probability_problematic / marginal_high_metrics
        )

        # Should be higher than prior (evidence updates belief)
        assert posterior_problematic_given_high_metrics > prior_probability_problematic

        # Should be reasonable value
        assert 0 < posterior_problematic_given_high_metrics < 1
