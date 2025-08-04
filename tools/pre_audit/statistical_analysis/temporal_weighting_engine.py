"""
Temporal Weighting Engine for GitHub Issue #43
Implements exponential decay weighting for violation age as specified in issue #43.

This addresses the core requirement: "violations from 6 months ago should have less
weight than recent violations" through statistically sound temporal analysis.

Based on:
- Hamilton (1994) Time Series Analysis
- Box & Jenkins (1976) Time Series Analysis: Forecasting and Control
- Exponential decay models for temporal weighting in risk assessment
"""

import logging
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy.optimize import minimize_scalar

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class TemporalViolation:
    """
    Violation with comprehensive temporal context.

    Attributes:
        timestamp: When the violation occurred
        file_path: Path to the file with the violation
        violation_type: Type/category of violation
        severity: Numerical severity score
        context: Additional context information
        business_impact: Business impact category
    """

    timestamp: datetime
    file_path: str
    violation_type: str
    severity: float
    context: Dict[str, Any]
    business_impact: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "file_path": self.file_path,
            "violation_type": self.violation_type,
            "severity": self.severity,
            "context": self.context,
            "business_impact": self.business_impact,
        }

    def age_in_days(self, current_time: datetime) -> float:
        """Calculate age of violation in days from a reference time."""
        return (current_time - self.timestamp).total_seconds() / 86400.0


@dataclass
class TemporalWeightingResult:
    """
    Result of temporal weighting analysis.

    Attributes:
        file_path: Path to analyzed file
        weighted_risk_score: Temporally weighted risk score
        violation_count: Total number of violations
        age_range_days: Age range of violations in days
        temporal_concentration: Measure of violation clustering in time
        recent_violations: Count of violations in last 30 days
        decay_parameters: Parameters used for exponential decay
        metadata: Additional analysis metadata
    """

    file_path: str
    weighted_risk_score: float
    violation_count: int
    age_range_days: int
    temporal_concentration: float
    recent_violations: int
    decay_parameters: Dict[str, Any]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "weighted_risk_score": self.weighted_risk_score,
            "violation_count": self.violation_count,
            "age_range_days": self.age_range_days,
            "temporal_concentration": self.temporal_concentration,
            "recent_violations": self.recent_violations,
            "decay_parameters": self.decay_parameters,
            "metadata": self.metadata,
        }


class TemporalWeightingEngine:
    """
    Temporal weighting engine implementing exponential decay for GitHub issue #43.

    Core functionality:
    - Exponential decay weighting: weight = exp(-λ * age_days)
    - Parameter optimization using time series cross-validation
    - Business impact multipliers for different violation types
    - Temporal concentration analysis for burst detection
    - Predictive risk assessment based on temporal patterns
    """

    def __init__(
        self,
        default_half_life_days: float = 30.0,
        max_age_days: float = 365.0,
        optimization_window_days: int = 30,
        business_multipliers: Optional[Dict[str, float]] = None,
        random_state: int = 42,
    ):
        """
        Initialize temporal weighting engine.

        Args:
            default_half_life_days: Default half-life for exponential decay
            max_age_days: Maximum age to consider for violations
            optimization_window_days: Window for predictive optimization
            business_multipliers: Business impact multipliers by category
            random_state: Random seed for reproducibility
        """
        self.default_half_life_days = default_half_life_days
        self.max_age_days = max_age_days
        self.optimization_window_days = optimization_window_days
        self.random_state = random_state

        # Business impact multipliers
        self.business_multipliers = business_multipliers or {
            "critical": 2.0,
            "high": 1.5,
            "security": 1.3,
            "medium": 1.0,
            "low": 0.7,
        }

        # Decay function implementations
        self.decay_functions: Dict[str, Callable[..., float]] = {
            "exponential": self._exponential_decay,
            "linear": self._linear_decay,
            "hyperbolic": self._hyperbolic_decay,
            "step_function": self._step_function_decay,
        }

        # Optimized parameters
        self.optimal_parameters: Dict[str, float] = {}
        self.parameter_optimization_history: List[Dict[str, Any]] = []

        # Performance tracking
        self.performance_metrics: Dict[str, float] = {}

        np.random.seed(random_state)

        logger.info(f"Initialized TemporalWeightingEngine with half_life={default_half_life_days} days")

    def _exponential_decay(self, age_days: float, half_life: float = 30.0) -> float:
        """
        Exponential decay function as specified in GitHub issue #43.

        Formula: weight = exp(-λ * age_days)
        where λ = ln(2) / half_life

        Args:
            age_days: Age of violation in days
            half_life: Half-life parameter in days

        Returns:
            Decay weight between 0 and 1
        """
        if age_days < 0:
            return 1.0  # Future violations get full weight

        lambda_param = np.log(2) / half_life
        weight = np.exp(-lambda_param * age_days)

        return float(weight)

    def _calculate_exponential_decay_weight(self, age_days: float, half_life: float) -> float:
        """Calculate exponential decay weight (API method expected by tests)."""
        return self._exponential_decay(age_days, half_life)

    def _apply_business_multiplier(self, base_weight: float, business_impact: str) -> float:
        """Apply business impact multiplier to base weight (API method expected by tests)."""
        multiplier = self.business_multipliers.get(business_impact, 1.0)
        return base_weight * multiplier

    def _linear_decay(self, age_days: float, max_age: float = 180.0) -> float:
        """Linear decay function with configurable maximum age."""
        if age_days < 0:
            return 1.0
        if age_days >= max_age:
            return 0.0
        return 1.0 - (age_days / max_age)

    def _hyperbolic_decay(self, age_days: float, scale: float = 30.0) -> float:
        """Hyperbolic decay function for long-tail weighting."""
        if age_days < 0:
            return 1.0
        return 1.0 / (1.0 + age_days / scale)

    def _step_function_decay(self, age_days: float, thresholds: List[float] = [7, 30, 90, 180]) -> float:
        """Step function decay for business-aligned time periods."""
        if age_days < 0:
            return 1.0

        weights = [1.0, 0.8, 0.6, 0.4, 0.2]

        for i, threshold in enumerate(thresholds):
            if age_days <= threshold:
                return weights[i]

        return weights[-1]

    def optimize_decay_parameters(
        self,
        historical_violations: List[TemporalViolation],
        prediction_window_days: int = 30,
        optimization_method: str = "f1_score",
    ) -> Dict[str, float]:
        """
        Optimize decay parameters using historical effectiveness.

        Uses time series cross-validation to find optimal half-life parameter
        that maximizes predictive performance for future violations.

        Args:
            historical_violations: List of historical violations with timestamps
            prediction_window_days: Days ahead to predict for optimization
            optimization_method: Optimization criterion ("f1_score", "precision", "recall")

        Returns:
            Dictionary with optimal parameters and performance metrics

        Raises:
            ValueError: If insufficient data for optimization
        """
        if len(historical_violations) < 3:
            raise ValueError(f"Insufficient data for optimization: {len(historical_violations)} violations")

        logger.info(f"Optimizing decay parameters using {len(historical_violations)} violations")

        # Convert to DataFrame for easier manipulation
        violations_df = pd.DataFrame(
            [
                {
                    "timestamp": v.timestamp,
                    "file_path": v.file_path,
                    "severity": v.severity,
                    "violation_type": v.violation_type,
                    "business_impact": v.business_impact,
                }
                for v in historical_violations
            ]
        )

        violations_df = violations_df.sort_values("timestamp")

        # Define objective function for optimization
        def objective_function(half_life: float) -> float:
            """Objective function for parameter optimization."""
            return self._calculate_prediction_error(
                violations_df, half_life, prediction_window_days, optimization_method
            )

        # Optimize half-life parameter
        try:
            result = minimize_scalar(objective_function, bounds=(1.0, 365.0), method="bounded", options={"xatol": 0.1})

            optimal_half_life = result.x
            optimization_score = 1.0 - result.fun  # Convert error to score

        except Exception as e:
            logger.warning(f"Optimization failed: {str(e)}, using default parameters")
            optimal_half_life = self.default_half_life_days
            optimization_score = 0.5

        # Store optimal parameters
        self.optimal_parameters = {
            "optimal_half_life": float(optimal_half_life),
            "optimization_score": float(optimization_score),
            "validation_method": float(0.0),  # Placeholder for method score
            "prediction_window": float(prediction_window_days),
            "optimization_method": float(0.0),  # Placeholder for method score
        }

        # Record optimization history
        self.parameter_optimization_history.append(
            {
                "timestamp": datetime.now(),
                "n_violations": len(historical_violations),
                "optimal_half_life": optimal_half_life,
                "optimization_score": optimization_score,
                "method": optimization_method,
            }
        )

        logger.info(f"Optimized half-life: {optimal_half_life:.1f} days (score: {optimization_score:.3f})")

        return self.optimal_parameters

    def _calculate_prediction_error(
        self, violations_df: pd.DataFrame, half_life: float, prediction_window: int, metric: str
    ) -> float:
        """
        Calculate prediction error using time series cross-validation.

        Args:
            violations_df: DataFrame with violation data
            half_life: Half-life parameter to test
            prediction_window: Days to predict ahead
            metric: Evaluation metric to use

        Returns:
            Prediction error (lower is better)
        """
        n_splits = 5
        total_error = 0.0
        valid_splits = 0

        # Time series cross-validation
        for i in range(n_splits):
            # Create chronological split
            split_point = len(violations_df) * (i + 1) // (n_splits + 1)
            train_data = violations_df.iloc[:split_point]

            # Define test period
            train_end = train_data["timestamp"].max()
            test_start = train_end
            test_end = train_end + timedelta(days=prediction_window)

            test_data = violations_df[
                (violations_df["timestamp"] >= test_start) & (violations_df["timestamp"] <= test_end)
            ]

            if len(test_data) == 0:
                continue

            try:
                # Calculate weighted risk scores for training data
                current_time = train_end
                weighted_scores = {}

                for _, violation in train_data.iterrows():
                    age_days = (current_time - violation["timestamp"]).days
                    weight = self._exponential_decay(age_days, half_life)

                    # Apply business multiplier
                    business_multiplier = self.business_multipliers.get(violation["business_impact"], 1.0)

                    total_weight = weight * business_multiplier
                    file_path = violation["file_path"]

                    if file_path not in weighted_scores:
                        weighted_scores[file_path] = 0.0

                    weighted_scores[file_path] += violation["severity"] * total_weight

                if not weighted_scores:
                    continue

                # Predict high-risk files (top 20%)
                threshold = np.percentile(list(weighted_scores.values()), 80)
                predicted_high_risk_files = set(
                    file_path for file_path, score in weighted_scores.items() if score > threshold
                )

                # Actual violations in test period
                actual_violation_files = set(test_data["file_path"].unique())

                # Calculate performance metrics
                if len(predicted_high_risk_files) > 0 and len(actual_violation_files) > 0:
                    tp = len(predicted_high_risk_files & actual_violation_files)
                    fp = len(predicted_high_risk_files - actual_violation_files)
                    fn = len(actual_violation_files - predicted_high_risk_files)

                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

                    if metric == "f1_score":
                        if precision + recall > 0:
                            f1_score = 2 * (precision * recall) / (precision + recall)
                        else:
                            f1_score = 0.0
                        error = 1.0 - f1_score
                    elif metric == "precision":
                        error = 1.0 - precision
                    elif metric == "recall":
                        error = 1.0 - recall
                    else:
                        error = 1.0  # Unknown metric

                    total_error += error
                    valid_splits += 1

            except Exception as e:
                logger.debug(f"Cross-validation split failed: {str(e)}")
                continue

        return total_error / valid_splits if valid_splits > 0 else 1.0

    def calculate_temporal_weighted_risk(
        self,
        violations: List[TemporalViolation],
        current_time: Optional[datetime] = None,
        weighting_method: str = "exponential",
    ) -> Dict[str, TemporalWeightingResult]:
        """
        Calculate temporally weighted risk scores for files.

        Implementation of GitHub issue #43 requirement for temporal weighting
        where older violations receive exponentially decaying weights.

        Args:
            violations: List of violations with temporal information
            current_time: Reference time for age calculation (default: now)
            weighting_method: Decay function to use

        Returns:
            Dictionary mapping file paths to temporal weighting results

        Raises:
            ValueError: If no violations provided or invalid method
        """
        if not violations:
            return {}

        if current_time is None:
            current_time = datetime.now()

        if weighting_method not in self.decay_functions:
            raise ValueError(f"Unknown weighting method: {weighting_method}")

        logger.info(f"Calculating temporal weighted risk for {len(violations)} violations")

        # Get optimal parameters if available
        if weighting_method == "exponential" and "optimal_half_life" in self.optimal_parameters:
            half_life = self.optimal_parameters["optimal_half_life"]
        else:
            half_life = self.default_half_life_days

        # Group violations by file path
        file_violations: Dict[str, List[TemporalViolation]] = {}
        for violation in violations:
            if violation.file_path not in file_violations:
                file_violations[violation.file_path] = []
            file_violations[violation.file_path].append(violation)

        results = {}

        for file_path, file_violations_list in file_violations.items():
            try:
                result = self._calculate_file_temporal_weight(
                    file_path, file_violations_list, current_time, weighting_method, half_life
                )
                results[file_path] = result

            except Exception as e:
                logger.warning(f"Failed to calculate temporal weight for {file_path}: {str(e)}")
                continue

        logger.info(f"Calculated temporal weights for {len(results)} files")
        return results

    def _calculate_file_temporal_weight(
        self,
        file_path: str,
        violations: List[TemporalViolation],
        current_time: datetime,
        weighting_method: str,
        half_life: float,
    ) -> TemporalWeightingResult:
        """Calculate temporal weighting result for a single file."""
        if not violations:
            raise ValueError(f"No violations for file {file_path}")

        # Sort violations by timestamp
        violations.sort(key=lambda v: v.timestamp)

        # Calculate basic temporal statistics
        oldest_violation = min(v.timestamp for v in violations)
        newest_violation = max(v.timestamp for v in violations)
        age_range_days = (newest_violation - oldest_violation).days

        # Count recent violations (last 30 days)
        recent_threshold = current_time - timedelta(days=30)
        recent_violations = sum(1 for v in violations if v.timestamp >= recent_threshold)

        # Calculate weighted risk score
        total_weighted_score = 0.0
        total_raw_severity = 0.0

        for violation in violations:
            age_days = (current_time - violation.timestamp).days

            # Skip violations older than max age
            if age_days > self.max_age_days:
                continue

            # Calculate temporal weight
            if weighting_method == "exponential":
                weight = self.decay_functions[weighting_method](age_days, half_life)
            else:
                weight = self.decay_functions[weighting_method](age_days)

            # Apply business impact multiplier
            business_multiplier = self.business_multipliers.get(violation.business_impact, 1.0)

            # Calculate component weights
            severity_weight = violation.severity * weight * business_multiplier
            total_weighted_score += severity_weight
            total_raw_severity += violation.severity

        # Calculate temporal concentration
        temporal_concentration = self._calculate_temporal_concentration(violations)

        # Prepare decay parameters used
        decay_parameters = {
            "method": weighting_method,
            "half_life": half_life,
            "max_age_days": self.max_age_days,
        }

        # Additional metadata
        metadata = {
            "oldest_violation": oldest_violation.isoformat(),
            "newest_violation": newest_violation.isoformat(),
            "total_raw_severity": total_raw_severity,
            "average_severity": total_raw_severity / len(violations),
            "business_impact_distribution": self._calculate_business_impact_distribution(violations),
            "violation_types": list(set(v.violation_type for v in violations)),
        }

        return TemporalWeightingResult(
            file_path=file_path,
            weighted_risk_score=total_weighted_score,
            violation_count=len(violations),
            age_range_days=age_range_days,
            temporal_concentration=temporal_concentration,
            recent_violations=recent_violations,
            decay_parameters=decay_parameters,
            metadata=metadata,
        )

    def _calculate_temporal_concentration(self, violations: List[TemporalViolation]) -> float:
        """
        Calculate temporal concentration of violations.

        High concentration indicates burst of violations (higher risk).
        Returns value between 0 (spread out) and 1 (highly concentrated).
        """
        if len(violations) <= 1:
            return 0.0

        timestamps = [v.timestamp for v in violations]
        timestamps.sort()

        # Calculate gaps between consecutive violations in days
        gaps = [(timestamps[i + 1] - timestamps[i]).days for i in range(len(timestamps) - 1)]

        if not gaps:
            return 0.0

        # Concentration is inverse of average gap (normalized)
        avg_gap = np.mean(gaps)
        max_possible_gap = 365  # 1 year normalization

        # Inverse relationship: smaller gaps = higher concentration
        concentration = 1.0 - min(float(avg_gap) / max_possible_gap, 1.0)

        return float(concentration)

    def _calculate_business_impact_distribution(self, violations: List[TemporalViolation]) -> Dict[str, int]:
        """Calculate distribution of business impact categories."""
        distribution: Dict[str, int] = {}
        for violation in violations:
            impact = violation.business_impact
            distribution[impact] = distribution.get(impact, 0) + 1
        return distribution

    def predict_future_risk(
        self,
        historical_violations: List[TemporalViolation],
        prediction_horizon_days: int = 30,
        confidence_level: float = 0.95,
    ) -> Dict[str, Dict[str, float]]:
        """
        Predict future risk based on temporal patterns.

        Uses temporal weighting patterns to forecast which files are likely
        to have violations in the near future.

        Args:
            historical_violations: Historical violation data
            prediction_horizon_days: Days ahead to predict
            confidence_level: Confidence level for predictions

        Returns:
            Dictionary with risk predictions by file
        """
        if not historical_violations:
            return {}

        logger.info(f"Predicting future risk for {prediction_horizon_days} days")

        # Calculate current temporal weights
        current_weights = self.calculate_temporal_weighted_risk(historical_violations)

        # Simple predictive model: files with higher temporal concentration
        # and recent violations are more likely to have future violations
        predictions = {}

        for file_path, weight_result in current_weights.items():
            # Base prediction on weighted score and temporal concentration
            base_risk = weight_result.weighted_risk_score
            concentration_factor = weight_result.temporal_concentration
            recent_factor = min(weight_result.recent_violations / 5.0, 1.0)

            # Combined risk prediction
            predicted_risk = base_risk * (1 + concentration_factor + recent_factor)

            # Simple confidence interval (could be improved with more sophisticated modeling)
            uncertainty = 0.2 * predicted_risk  # 20% uncertainty
            lower_bound = max(0, predicted_risk - uncertainty)
            upper_bound = predicted_risk + uncertainty

            predictions[file_path] = {
                "predicted_risk": predicted_risk,
                "confidence_lower": lower_bound,
                "confidence_upper": upper_bound,
                "temporal_concentration": concentration_factor,
                "recent_activity": recent_factor,
            }

        return predictions

    def get_temporal_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of temporal analysis capabilities and parameters."""
        summary = {
            "configuration": {
                "default_half_life_days": self.default_half_life_days,
                "max_age_days": self.max_age_days,
                "optimization_window_days": self.optimization_window_days,
                "business_multipliers": self.business_multipliers,
            },
            "statistics": {
                "optimization_runs": len(self.parameter_optimization_history),
                "available_decay_functions": list(self.decay_functions.keys()),
                "performance_metrics": self.performance_metrics,
            },
            "optimal_parameters": self.optimal_parameters,
            "optimization_history": self.parameter_optimization_history,
        }

        return summary
