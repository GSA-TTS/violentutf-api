"""
Statistical Hotspot Detector for GitHub Issue #43
Implements statistically rigorous hotspot detection following academic best practices.

Based on:
- Fenton & Neil (2012) Risk Assessment and Decision Analysis
- Gelman et al. (2013) Bayesian Data Analysis
- Efron & Tibshirani (1993) An Introduction to the Bootstrap
"""

import logging
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# Scientific computing dependencies with graceful degradation
try:
    import numpy as np
    import pandas as pd
    from scipy import stats
    from sklearn.preprocessing import StandardScaler

    HAS_SCIENTIFIC_DEPS = True
except ImportError:
    HAS_SCIENTIFIC_DEPS = False
    # Create dummy modules for type checking
    np = None
    pd = None
    stats = None
    StandardScaler = None

# Suppress specific warnings for cleaner output
warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class StatisticalHotspotResult:
    """
    Statistically validated hotspot result with comprehensive uncertainty quantification.

    Attributes:
        file_path: Path to the analyzed file
        statistical_significance: Numeric statistical significance score [0,1]
        p_value: Statistical significance p-value
        z_score: Standardized z-score for anomaly detection
        risk_probability: Probability that file is a hotspot [0,1]
        confidence_interval: 95% confidence interval for risk probability
        evidence_strength: Categorical evidence strength assessment
        baseline_comparison: Information about baseline distribution comparison
        metadata: Additional metadata about the analysis
        bootstrap_samples: Number of bootstrap samples used (optional)
        is_statistically_significant: Boolean indicating statistical significance (optional)
        distribution_info: Detailed distribution info (optional, for backward compatibility)
    """

    file_path: str
    statistical_significance: float  # Primary significance score [0,1]
    p_value: float
    z_score: float
    risk_probability: float
    confidence_interval: Tuple[float, float]
    evidence_strength: str
    baseline_comparison: Dict[str, Any]  # Baseline distribution comparison info
    metadata: Optional[Dict[str, Any]] = None  # Analysis metadata
    bootstrap_samples: int = 1000
    is_statistically_significant: Optional[bool] = None  # Optional boolean version
    distribution_info: Optional[Dict[str, Any]] = None  # Optional detailed info

    def __post_init__(self) -> None:
        """Validate input parameters after initialization."""
        # Validate statistical_significance is in [0, 1]
        if not (0.0 <= self.statistical_significance <= 1.0):
            raise ValueError(f"statistical_significance must be in [0, 1], got {self.statistical_significance}")

        # Validate p_value is in [0, 1]
        if not (0.0 <= self.p_value <= 1.0):
            raise ValueError(f"p_value must be in [0, 1], got {self.p_value}")

        # Validate risk_probability is in [0, 1]
        if not (0.0 <= self.risk_probability <= 1.0):
            raise ValueError(f"risk_probability must be in [0, 1], got {self.risk_probability}")

        # Validate confidence_interval is a valid tuple with proper ordering
        if len(self.confidence_interval) != 2:
            raise ValueError(f"confidence_interval must be a tuple of length 2, got {len(self.confidence_interval)}")

        lower, upper = self.confidence_interval
        if lower > upper:
            raise ValueError(f"confidence_interval lower bound ({lower}) must be <= upper bound ({upper})")

        if not (0.0 <= lower <= 1.0 and 0.0 <= upper <= 1.0):
            raise ValueError(f"confidence_interval bounds must be in [0, 1], got ({lower}, {upper})")

        # Validate evidence_strength is one of expected values
        valid_strengths = {"insufficient", "weak", "moderate", "strong", "very_strong"}
        if self.evidence_strength not in valid_strengths:
            raise ValueError(f"evidence_strength must be one of {valid_strengths}, got '{self.evidence_strength}'")

        # Validate bootstrap_samples is positive
        if self.bootstrap_samples < 0:
            raise ValueError(f"bootstrap_samples must be non-negative, got {self.bootstrap_samples}")

        # Set default metadata if None
        if self.metadata is None:
            self.metadata = {}

        # Set default distribution_info if None
        if self.distribution_info is None:
            self.distribution_info = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "file_path": self.file_path,
            "statistical_significance": self.statistical_significance,
            "p_value": self.p_value,
            "z_score": self.z_score,
            "risk_probability": self.risk_probability,
            "confidence_interval": list(self.confidence_interval),
            "evidence_strength": self.evidence_strength,
            "baseline_comparison": self.baseline_comparison,
            "bootstrap_samples": self.bootstrap_samples,
        }

        # Add optional fields if they exist
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.is_statistically_significant is not None:
            result["is_statistically_significant"] = self.is_statistically_significant
        if self.distribution_info is not None:
            result["distribution_info"] = self.distribution_info

        return result


class StatisticalHotspotDetector:
    """
    Statistical hotspot detector following academic best practices.

    Implements proper hypothesis testing, distribution fitting, and uncertainty
    quantification for government-grade software quality assurance.

    Statistical Methods:
    - Hypothesis Testing: H0 (file is normal) vs H1 (file is hotspot)
    - Distribution Fitting: Multiple distributions with AIC model selection
    - Uncertainty Quantification: Bootstrap confidence intervals
    - Multiple Comparison Correction: Bonferroni adjustment
    """

    def __init__(
        self,
        significance_level: float = 0.05,
        confidence_level: float = 0.95,
        bootstrap_samples: int = 1000,
        random_state: int = 42,
    ):
        """
        Initialize statistical hotspot detector.

        Args:
            significance_level: Statistical significance threshold (default: 0.05)
            confidence_level: Confidence level for intervals (default: 0.95)
            bootstrap_samples: Number of bootstrap samples (default: 1000)
            random_state: Random seed for reproducibility (default: 42)

        Raises:
            ImportError: If required scientific computing dependencies are not available
        """
        if not HAS_SCIENTIFIC_DEPS:
            raise ImportError(
                "Scientific computing dependencies (numpy, pandas, scipy, scikit-learn) are required "
                "for StatisticalHotspotDetector. Please install them with: "
                "pip install numpy pandas scipy scikit-learn"
            )
        self.significance_level = significance_level
        self.confidence_level = confidence_level
        self.bootstrap_samples = bootstrap_samples
        self.random_state = random_state

        # Set random seed for reproducibility
        np.random.seed(random_state)

        # Model components
        self.baseline_distributions: Dict[str, Dict[str, Any]] = {}
        self.fitted_distributions: Dict[str, Dict[str, Any]] = {}  # For test compatibility
        self.scaler = StandardScaler()
        self.is_fitted = False

        # Statistical validation metrics
        self.model_diagnostics: Dict[str, Any] = {}
        self.analysis_count: int = 0  # Track number of analyses performed

        logger.info(f"Initialized StatisticalHotspotDetector with significance_level={significance_level}")

    def fit_baseline_distributions(self, historical_data: Dict[str, np.ndarray]) -> None:
        """
        Fit baseline statistical distributions from historical data.

        Uses empirical Bayes approach with multiple distribution candidates
        and AIC-based model selection for robust baseline estimation.

        Args:
            historical_data: Dictionary mapping metric names to historical values
                           e.g., {'churn_score': array([...]), 'complexity_score': array([...])}

        Raises:
            ValueError: If insufficient data provided for fitting
        """
        if not historical_data:
            raise ValueError("Historical data cannot be empty")

        logger.info(f"Fitting baseline distributions for {len(historical_data)} metrics")

        # Distribution candidates with their scipy.stats objects
        distribution_candidates = [
            ("normal", stats.norm),
            ("lognormal", stats.lognorm),
            ("gamma", stats.gamma),
            ("weibull_min", stats.weibull_min),
        ]

        for metric_name, values in historical_data.items():
            if len(values) < 10:
                logger.warning(f"Insufficient data for {metric_name}: {len(values)} samples")
                continue

            # Remove invalid values
            clean_values = values[np.isfinite(values) & (values >= 0)]

            if len(clean_values) < 10:
                logger.warning(f"Insufficient valid data for {metric_name} after cleaning")
                continue

            best_distribution = self._fit_best_distribution(clean_values, distribution_candidates)

            # Calculate summary statistics for all distributions
            summary_stats = {
                "mean": np.mean(clean_values),
                "std": np.std(clean_values),
                "median": np.median(clean_values),
                "q25": np.percentile(clean_values, 25),
                "q75": np.percentile(clean_values, 75),
                "min": np.min(clean_values),
                "max": np.max(clean_values),
                "values": clean_values,
            }

            if best_distribution:
                # Merge best distribution with summary stats
                distribution_info = {**best_distribution, **summary_stats}
                self.baseline_distributions[metric_name] = distribution_info

                # Also store in fitted_distributions for test compatibility
                self.fitted_distributions[metric_name] = summary_stats

                logger.info(
                    f"Fitted {best_distribution['name']} distribution for {metric_name} "
                    f"(AIC: {best_distribution['aic']:.2f})"
                )
            else:
                # Fallback to empirical distribution
                empirical_info = {
                    "distribution": "empirical",
                    "name": "empirical",
                    "aic": np.inf,
                    "mad": np.median(np.abs(clean_values - np.median(clean_values))),
                    **summary_stats,
                }
                self.baseline_distributions[metric_name] = empirical_info
                self.fitted_distributions[metric_name] = summary_stats

                logger.info(f"Using empirical distribution for {metric_name}")

        if not self.baseline_distributions:
            raise ValueError("No valid baseline distributions could be fitted")

        self.is_fitted = True
        self._validate_fitted_distributions()

        logger.info(f"Successfully fitted baseline distributions for {len(self.baseline_distributions)} metrics")

    def _fit_best_distribution(self, data: np.ndarray, candidates: List[Tuple[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Fit multiple distributions and select best using AIC.

        Args:
            data: Clean numerical data for fitting
            candidates: List of (name, distribution) tuples

        Returns:
            Dictionary with best distribution info or None if fitting fails
        """
        best_distribution = None
        best_aic = np.inf

        for dist_name, dist_class in candidates:
            try:
                # Special handling for different distributions
                if dist_name == "lognormal" and np.any(data <= 0):
                    continue  # Skip lognormal for non-positive data

                # Fit distribution parameters
                if dist_name == "normal":
                    params = dist_class.fit(data)
                elif dist_name == "lognormal":
                    # Ensure positive data for lognormal
                    positive_data = data[data > 0]
                    if len(positive_data) < len(data) * 0.8:  # Too many zeros
                        continue
                    params = dist_class.fit(positive_data, floc=0)
                else:
                    params = dist_class.fit(data, floc=0)  # Fix location parameter for stability

                # Calculate log-likelihood
                log_likelihood = np.sum(dist_class.logpdf(data, *params))

                # Skip if likelihood is invalid
                if not np.isfinite(log_likelihood):
                    continue

                # Calculate AIC (Akaike Information Criterion)
                k = len(params)  # Number of parameters
                aic = 2 * k - 2 * log_likelihood

                # Kolmogorov-Smirnov goodness-of-fit test
                ks_statistic, ks_p_value = stats.kstest(data, lambda x: dist_class.cdf(x, *params))

                if aic < best_aic and ks_p_value > 0.01:  # Require reasonable fit
                    best_aic = aic
                    best_distribution = {
                        "distribution": dist_class,
                        "parameters": params,
                        "name": dist_name,
                        "aic": aic,
                        "log_likelihood": log_likelihood,
                        "ks_statistic": ks_statistic,
                        "ks_p_value": ks_p_value,
                    }

            except Exception as e:
                logger.debug(f"Failed to fit {dist_name}: {str(e)}")
                continue

        return best_distribution

    def _validate_fitted_distributions(self) -> None:
        """Validate fitted distributions and store diagnostic information."""
        diagnostics = {}

        for metric_name, dist_info in self.baseline_distributions.items():
            if dist_info["name"] != "empirical":
                # Test distribution properties
                try:
                    # Sample from distribution to test validity
                    dist = dist_info["distribution"]
                    params = dist_info["parameters"]
                    samples = dist.rvs(*params, size=100, random_state=self.random_state)

                    diagnostics[metric_name] = {
                        "distribution": dist_info["name"],
                        "aic": dist_info["aic"],
                        "ks_p_value": dist_info.get("ks_p_value", 0.0),
                        "sample_mean": np.mean(samples),
                        "sample_std": np.std(samples),
                        "valid": True,
                    }
                except Exception as e:
                    logger.warning(f"Distribution validation failed for {metric_name}: {str(e)}")
                    diagnostics[metric_name] = {"valid": False, "error": str(e)}
            else:
                diagnostics[metric_name] = {
                    "distribution": "empirical",
                    "mean": dist_info["mean"],
                    "std": dist_info["std"],
                    "valid": True,
                }

        self.model_diagnostics = diagnostics

    def calculate_statistical_significance(
        self, file_metrics: Dict[str, Union[float, str]]
    ) -> StatisticalHotspotResult:
        """
        Calculate statistical significance of hotspot detection.

        Implements comprehensive hypothesis testing:
        H0: File metrics are consistent with baseline population
        H1: File metrics indicate anomalous behavior (hotspot)

        Args:
            file_metrics: Dictionary containing file path and metric values

        Returns:
            StatisticalHotspotResult with comprehensive statistical assessment

        Raises:
            ValueError: If detector not fitted or invalid metrics provided
        """
        file_path = str(file_metrics.get("file_path", "unknown"))

        # Increment analysis counter
        self.analysis_count += 1

        if not self.is_fitted:
            logger.warning(f"Detector not fitted, returning default result for {file_path}")
            return self._create_default_result(file_path, "Detector not fitted")

        # Extract numerical metrics
        numerical_metrics = {
            k: v for k, v in file_metrics.items() if isinstance(v, (int, float)) and k != "file_path" and np.isfinite(v)
        }

        if not numerical_metrics:
            logger.warning(f"No valid numerical metrics found for {file_path}")
            return self._create_default_result(file_path, "No valid metrics")

        # Calculate statistical measures for each metric
        metric_results = {}
        p_values = []
        z_scores = []

        for metric_name, value in numerical_metrics.items():
            if metric_name in self.baseline_distributions:
                result = self._calculate_metric_significance(metric_name, value)
                metric_results[metric_name] = result
                p_values.append(result["p_value"])
                z_scores.append(result["z_score"])

        if not p_values:
            logger.warning(f"No baseline distributions available for metrics in {file_path}")
            return self._create_default_result(file_path, "No baseline distributions")

        # Combine p-values using Fisher's method
        combined_p_value = self._combine_p_values(p_values)

        # Calculate overall z-score using weighted average
        combined_z_score = np.mean(z_scores)  # Simple average for now

        # Apply Bonferroni correction for multiple comparisons
        corrected_p_value = min(combined_p_value * len(p_values), 1.0)

        # Determine statistical significance
        is_significant = corrected_p_value < self.significance_level

        # Calculate risk probability from z-score
        risk_probability = max(0.0, min(1.0, stats.norm.cdf(combined_z_score)))

        # Calculate statistical significance as numeric score [0,1]
        # Convert p-value to significance score (1 - p_value, capped at reasonable range)
        statistical_significance_score = max(0.0, min(1.0, 1.0 - corrected_p_value))

        # Calculate confidence interval using bootstrap
        confidence_interval = self._calculate_bootstrap_confidence_interval(file_metrics, numerical_metrics)

        # Assess evidence strength
        evidence_strength = self._assess_evidence_strength(corrected_p_value, combined_z_score)

        # Create baseline comparison summary
        baseline_comparison = {}
        if metric_results:
            for metric_name, result in metric_results.items():
                if metric_name in self.baseline_distributions:
                    baseline = self.baseline_distributions[metric_name]
                    baseline_comparison[metric_name] = {
                        "mean": baseline.get("mean", 0),
                        "std": baseline.get("std", 1),
                        "distribution_type": baseline.get("name", "unknown"),
                    }

        # Create analysis metadata
        metadata = {
            "analysis_time": datetime.now().isoformat(),
            "n_metrics_analyzed": len(p_values),
            "baseline_distributions_count": len(self.baseline_distributions),
            "significance_level": self.significance_level,
            "confidence_level": self.confidence_level,
        }

        return StatisticalHotspotResult(
            file_path=file_path,
            statistical_significance=statistical_significance_score,  # Primary field
            p_value=corrected_p_value,
            z_score=combined_z_score,
            risk_probability=risk_probability,
            confidence_interval=confidence_interval,
            evidence_strength=evidence_strength,
            baseline_comparison=baseline_comparison,  # New required field
            metadata=metadata,  # New required field
            bootstrap_samples=self.bootstrap_samples,
            is_statistically_significant=is_significant,  # Optional boolean
            distribution_info={  # Optional detailed info
                "metric_results": metric_results,
                "n_metrics_analyzed": len(p_values),
                "baseline_distributions": len(self.baseline_distributions),
            },
        )

    def _calculate_metric_significance(self, metric_name: str, value: float) -> Dict[str, Any]:
        """Calculate statistical significance for a single metric."""
        baseline = self.baseline_distributions[metric_name]

        if baseline["name"] == "empirical":
            # Use empirical distribution
            values = baseline["values"]
            percentile = stats.percentileofscore(values, value) / 100.0
            z_score = stats.norm.ppf(percentile) if 0 < percentile < 1 else 0
            p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))
        else:
            # Use fitted parametric distribution
            dist = baseline["distribution"]
            params = baseline["parameters"]

            # Calculate percentile and z-score
            percentile = dist.cdf(value, *params)
            z_score = stats.norm.ppf(percentile) if 0 < percentile < 1 else 0

            # Two-tailed test p-value
            p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))

        return {
            "metric_name": metric_name,
            "value": value,
            "percentile": percentile,
            "z_score": z_score,
            "p_value": p_value,
            "baseline_distribution": baseline["name"],
        }

    def _combine_p_values(self, p_values: List[float]) -> float:
        """
        Combine multiple p-values using Fisher's method.

        Fisher's combined probability test:
        X² = -2 * Σ ln(p_i) ~ χ²(2k) where k is number of tests
        """
        if not p_values:
            return 1.0

        # Avoid log(0) by setting minimum p-value
        safe_p_values = [max(p, 1e-10) for p in p_values]

        # Fisher's method
        fisher_statistic = -2 * sum(np.log(p) for p in safe_p_values)
        degrees_of_freedom = 2 * len(safe_p_values)

        # Combined p-value from chi-square distribution
        combined_p_value = 1 - stats.chi2.cdf(fisher_statistic, degrees_of_freedom)

        return float(combined_p_value)

    def _calculate_bootstrap_confidence_interval(
        self, file_metrics: Dict[str, Any], numerical_metrics: Dict[str, float]
    ) -> Tuple[float, float]:
        """
        Calculate bootstrap confidence interval for risk probability.

        Uses bootstrap resampling from baseline distributions to estimate
        uncertainty in risk probability calculation.
        """
        bootstrap_risks = []

        for _ in range(self.bootstrap_samples):
            # Generate bootstrap sample by resampling from baselines
            bootstrap_metrics = {}

            for metric_name in numerical_metrics.keys():
                if metric_name in self.baseline_distributions:
                    baseline = self.baseline_distributions[metric_name]

                    if baseline["name"] == "empirical":
                        # Sample from empirical distribution
                        bootstrap_value = np.random.choice(baseline["values"])
                    else:
                        # Sample from fitted distribution
                        dist = baseline["distribution"]
                        params = baseline["parameters"]
                        bootstrap_value = dist.rvs(*params, random_state=None)

                    bootstrap_metrics[metric_name] = bootstrap_value

            # Calculate risk for bootstrap sample
            if bootstrap_metrics:
                p_values = []
                z_scores = []

                for metric_name, value in bootstrap_metrics.items():
                    result = self._calculate_metric_significance(metric_name, value)
                    p_values.append(result["p_value"])
                    z_scores.append(result["z_score"])

                if p_values:
                    combined_z = np.mean(z_scores)
                    bootstrap_risk = max(0.0, min(1.0, stats.norm.cdf(combined_z)))
                    bootstrap_risks.append(bootstrap_risk)

        if not bootstrap_risks:
            return (0.0, 1.0)  # Default wide interval

        # Calculate confidence interval
        alpha = 1 - self.confidence_level
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100

        lower_bound = np.percentile(bootstrap_risks, lower_percentile)
        upper_bound = np.percentile(bootstrap_risks, upper_percentile)

        return (lower_bound, upper_bound)

    def _assess_evidence_strength(self, p_value: float, z_score: float) -> str:
        """
        Assess evidence strength using standard thresholds.

        Based on Cohen (1988) and Benjamin & Hochberg (1995) recommendations.
        """
        if p_value < 0.001:
            return "very_strong"
        elif p_value < 0.01:
            return "strong"
        elif p_value < 0.05:
            return "moderate"
        elif p_value < 0.1:
            return "weak"
        else:
            return "insufficient"

    def _create_default_result(self, file_path: str, reason: str) -> StatisticalHotspotResult:
        """Create default result when analysis cannot be performed."""
        return StatisticalHotspotResult(
            file_path=file_path,
            statistical_significance=0.0,  # No significance score
            p_value=1.0,  # No significance
            z_score=0.0,  # No deviation
            risk_probability=0.5,  # Neutral probability
            confidence_interval=(0.0, 1.0),  # Wide uncertainty
            evidence_strength="insufficient",
            baseline_comparison={"error": reason},  # Required field
            metadata={  # Required field
                "analysis_time": datetime.now().isoformat(),
                "error": reason,
                "n_metrics_analyzed": 0,
                "baseline_distributions_count": (
                    len(self.baseline_distributions) if hasattr(self, "baseline_distributions") else 0
                ),
            },
            bootstrap_samples=0,
            is_statistically_significant=False,  # Boolean version
            distribution_info={"error": reason},  # Optional detailed info
        )

    def get_model_summary(self) -> Dict[str, Any]:
        """Get comprehensive model summary and diagnostics."""
        if not self.is_fitted:
            return {"error": "Model not fitted"}

        return {
            "is_fitted": self.is_fitted,
            "n_baseline_distributions": len(self.baseline_distributions),
            "significance_level": self.significance_level,
            "confidence_level": self.confidence_level,
            "bootstrap_samples": self.bootstrap_samples,
            "analysis_count": self.analysis_count,  # Add analysis count field
            "baseline_distributions": {
                name: {
                    "distribution_type": info["name"],
                    "aic": info.get("aic", np.inf),
                    "ks_p_value": info.get("ks_p_value", 0.0),
                }
                for name, info in self.baseline_distributions.items()
            },
            "model_diagnostics": self.model_diagnostics,
            "model_parameters": {  # Add this field that tests expect
                "significance_level": self.significance_level,
                "confidence_level": self.confidence_level,
                "bootstrap_samples": self.bootstrap_samples,
                "random_state": self.random_state,
                "n_distributions_fitted": len(self.baseline_distributions),
            },
        }
