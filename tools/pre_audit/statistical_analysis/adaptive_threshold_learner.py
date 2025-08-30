"""
Adaptive Threshold Learner for GitHub Issue #43
Implements data-driven threshold learning using ROC analysis and precision-recall optimization.

Replaces hard-coded thresholds with empirically optimized values based on historical
violation patterns for government-grade software quality assurance.

Based on:
- Fawcett (2006) An Introduction to ROC Analysis
- Davis & Goadrich (2006) The Relationship Between Precision-Recall and ROC Curves
- Youden (1950) Index for rating diagnostic tests
"""

import logging
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.metrics import (
    auc,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_curve,
)

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class ThresholdOptimizationResult:
    """
    Result of threshold optimization process.

    Attributes:
        metric_name: Name of the metric being optimized
        optimal_threshold: Optimal threshold value
        optimization_method: Method used (ROC, F1, etc.)
        performance_metrics: Dictionary of performance metrics at optimal threshold
        threshold_analysis: Detailed analysis across threshold range
    """

    metric_name: str
    optimal_threshold: float
    optimization_method: str
    performance_metrics: Dict[str, float]
    threshold_analysis: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "metric_name": self.metric_name,
            "optimal_threshold": self.optimal_threshold,
            "optimization_method": self.optimization_method,
            "performance_metrics": self.performance_metrics,
            "threshold_analysis": self.threshold_analysis,
        }


class AdaptiveThresholdLearner:
    """
    Adaptive threshold learner using ROC analysis and precision-recall optimization.

    Replaces hard-coded thresholds with data-driven optimal thresholds learned
    from historical violation patterns. Implements multiple optimization criteria
    to support different operational requirements.

    Methods:
    - ROC-based optimization using Youden's J statistic
    - Precision-Recall optimization using F1 score
    - Custom cost-sensitive optimization
    - Cross-validation for robust threshold selection
    """

    def __init__(
        self,
        default_optimization_method: str = "roc_youden",
        cross_validation_folds: int = 5,
        min_samples_required: int = 100,
        random_state: int = 42,
    ):
        """
        Initialize adaptive threshold learner.

        Args:
            default_optimization_method: Default optimization method
                Options: "roc_youden", "f1_score", "precision_recall", "cost_sensitive"
            cross_validation_folds: Number of CV folds for robust estimation
            min_samples_required: Minimum samples required for reliable optimization
            random_state: Random seed for reproducibility
        """
        self.default_optimization_method = default_optimization_method
        self.cross_validation_folds = cross_validation_folds
        self.min_samples_required = min_samples_required
        self.random_state = random_state

        # Learned thresholds and performance metrics
        self.optimal_thresholds: Dict[str, ThresholdOptimizationResult] = {}
        self.performance_history: List[Dict[str, Any]] = []

        # Validation results
        self.cross_validation_results: Dict[str, Dict[str, float]] = {}

        np.random.seed(random_state)

        logger.info(f"Initialized AdaptiveThresholdLearner with method={default_optimization_method}")

    def learn_optimal_thresholds(
        self,
        historical_data: pd.DataFrame,
        target_column: str = "is_violation",
        optimization_method: Optional[str] = None,
    ) -> Dict[str, ThresholdOptimizationResult]:
        """
        Learn optimal thresholds from historical violation data.

        Uses ROC analysis, precision-recall curves, and cross-validation to determine
        optimal thresholds that maximize detection performance while minimizing
        false positives for government operations.

        Args:
            historical_data: DataFrame with feature columns and violation target
            target_column: Name of binary target column (0/1 for non-violation/violation)
            optimization_method: Override default optimization method

        Returns:
            Dictionary mapping metric names to optimization results

        Raises:
            ValueError: If insufficient data or invalid target column
        """
        if len(historical_data) < self.min_samples_required:
            raise ValueError(f"Insufficient data: {len(historical_data)} < {self.min_samples_required}")

        if target_column not in historical_data.columns:
            raise ValueError(f"Target column '{target_column}' not found")

        # Validate target column
        unique_targets = historical_data[target_column].unique()
        if not set(unique_targets).issubset({0, 1}):
            raise ValueError(f"Target column must be binary (0/1), found: {unique_targets}")

        method = optimization_method or self.default_optimization_method
        logger.info(f"Learning optimal thresholds using method: {method}")

        # Identify feature columns (exclude target and metadata)
        exclude_columns = {target_column, "file_path", "timestamp", "commit_hash"}
        feature_columns = [
            col
            for col in historical_data.columns
            if col not in exclude_columns and historical_data[col].dtype in ["int64", "float64"]
        ]

        if not feature_columns:
            raise ValueError("No numerical feature columns found for threshold optimization")

        logger.info(f"Optimizing thresholds for {len(feature_columns)} features")

        optimization_results = {}

        for feature_name in feature_columns:
            try:
                result = self._optimize_single_threshold(historical_data, feature_name, target_column, method)
                optimization_results[feature_name] = result

                logger.info(
                    f"Optimized {feature_name}: threshold={result.optimal_threshold:.3f}, "
                    f"F1={result.performance_metrics.get('f1_score', 0):.3f}"
                )

            except Exception as e:
                logger.warning(f"Failed to optimize threshold for {feature_name}: {str(e)}")
                continue

        if not optimization_results:
            raise ValueError("No thresholds could be optimized")

        # Store results and validate with cross-validation
        self.optimal_thresholds = optimization_results
        self._validate_thresholds_with_cv(historical_data, target_column)

        # Record performance history
        self.performance_history.append(
            {
                "timestamp": pd.Timestamp.now(),
                "n_samples": len(historical_data),
                "n_features": len(feature_columns),
                "optimization_method": method,
                "avg_f1_score": np.mean(
                    [r.performance_metrics.get("f1_score", 0) for r in optimization_results.values()]
                ),
                "features_optimized": list(optimization_results.keys()),
            }
        )

        logger.info(f"Successfully learned optimal thresholds for {len(optimization_results)} features")
        return optimization_results

    def _optimize_single_threshold(
        self, data: pd.DataFrame, feature_name: str, target_column: str, method: str
    ) -> ThresholdOptimizationResult:
        """
        Optimize threshold for a single feature using specified method.

        Args:
            data: Historical data DataFrame
            feature_name: Name of feature to optimize
            target_column: Name of target column
            method: Optimization method to use

        Returns:
            ThresholdOptimizationResult with optimal threshold and performance metrics
        """
        # Extract feature values and targets
        y_true = data[target_column].values
        y_scores = data[feature_name].values

        # Remove any invalid values
        valid_mask = np.isfinite(y_scores)
        y_true = y_true[valid_mask]
        y_scores = y_scores[valid_mask]

        if len(y_true) < 10:
            raise ValueError(f"Insufficient valid data for {feature_name}")

        # Check for class balance
        positive_rate = np.mean(y_true)
        if positive_rate < 0.01 or positive_rate > 0.99:
            logger.warning(f"Severe class imbalance for {feature_name}: {positive_rate:.3f}")

        # Optimize based on method
        if method == "roc_youden":
            return self._optimize_roc_youden(feature_name, y_true, y_scores)
        elif method == "f1_score":
            return self._optimize_f1_score(feature_name, y_true, y_scores)
        elif method == "precision_recall":
            return self._optimize_precision_recall(feature_name, y_true, y_scores)
        elif method == "cost_sensitive":
            return self._optimize_cost_sensitive(feature_name, y_true, y_scores)
        else:
            raise ValueError(f"Unknown optimization method: {method}")

    def _optimize_roc_youden(
        self, feature_name: str, y_true: np.ndarray, y_scores: np.ndarray
    ) -> ThresholdOptimizationResult:
        """
        Optimize threshold using ROC analysis and Youden's J statistic.

        Youden's J = Sensitivity + Specificity - 1 = TPR - FPR
        Maximizes the sum of sensitivity and specificity.
        """
        # Calculate ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        # Calculate Youden's J statistic for each threshold
        j_scores = tpr - fpr
        optimal_idx = np.argmax(j_scores)
        optimal_threshold = thresholds[optimal_idx]

        # Calculate performance metrics at optimal threshold
        y_pred = (y_scores >= optimal_threshold).astype(int)

        performance_metrics = {
            "roc_auc": roc_auc,
            "optimal_sensitivity": tpr[optimal_idx],
            "optimal_specificity": 1 - fpr[optimal_idx],
            "youden_j": j_scores[optimal_idx],
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1_score": f1_score(y_true, y_pred, zero_division=0),
            "threshold_idx": optimal_idx,
            "n_thresholds": len(thresholds),
        }

        # Detailed threshold analysis
        threshold_analysis = {
            "method": "roc_youden",
            "roc_curve": {
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "thresholds": thresholds.tolist(),
            },
            "j_scores": j_scores.tolist(),
            "optimal_point": {
                "fpr": fpr[optimal_idx],
                "tpr": tpr[optimal_idx],
                "threshold": optimal_threshold,
            },
        }

        return ThresholdOptimizationResult(
            metric_name=feature_name,
            optimal_threshold=float(optimal_threshold),
            optimization_method="roc_youden",
            performance_metrics=performance_metrics,
            threshold_analysis=threshold_analysis,
        )

    def _optimize_f1_score(
        self, feature_name: str, y_true: np.ndarray, y_scores: np.ndarray
    ) -> ThresholdOptimizationResult:
        """
        Optimize threshold using F1 score maximization.

        F1 = 2 * (precision * recall) / (precision + recall)
        Balances precision and recall for detection tasks.
        """
        # Calculate precision-recall curve
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall, precision)

        # Calculate F1 scores for each threshold
        # Handle division by zero
        with np.errstate(divide="ignore", invalid="ignore"):
            f1_scores = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1])
            f1_scores = np.nan_to_num(f1_scores)

        optimal_idx = np.argmax(f1_scores)
        optimal_threshold = thresholds[optimal_idx]

        # Calculate performance metrics at optimal threshold
        y_pred = (y_scores >= optimal_threshold).astype(int)

        performance_metrics = {
            "pr_auc": pr_auc,
            "optimal_precision": precision[optimal_idx],
            "optimal_recall": recall[optimal_idx],
            "optimal_f1": f1_scores[optimal_idx],
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1_score": f1_score(y_true, y_pred, zero_division=0),
            "threshold_idx": optimal_idx,
            "n_thresholds": len(thresholds),
        }

        # Detailed threshold analysis
        threshold_analysis = {
            "method": "f1_score",
            "pr_curve": {
                "precision": precision.tolist(),
                "recall": recall.tolist(),
                "thresholds": thresholds.tolist(),
            },
            "f1_scores": f1_scores.tolist(),
            "optimal_point": {
                "precision": precision[optimal_idx],
                "recall": recall[optimal_idx],
                "f1_score": f1_scores[optimal_idx],
                "threshold": optimal_threshold,
            },
        }

        return ThresholdOptimizationResult(
            metric_name=feature_name,
            optimal_threshold=float(optimal_threshold),
            optimization_method="f1_score",
            performance_metrics=performance_metrics,
            threshold_analysis=threshold_analysis,
        )

    def _optimize_precision_recall(
        self,
        feature_name: str,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        target_precision: float = 0.9,
    ) -> ThresholdOptimizationResult:
        """
        Optimize threshold to achieve target precision while maximizing recall.

        Useful for government applications where false positives are costly.
        """
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall, precision)

        # Find thresholds that meet target precision
        valid_indices = precision[:-1] >= target_precision

        if not np.any(valid_indices):
            logger.warning(f"Cannot achieve target precision {target_precision} for {feature_name}")
            # Fall back to best precision available
            optimal_idx = np.argmax(precision[:-1])
        else:
            # Among valid thresholds, choose one with highest recall
            valid_recall = recall[:-1][valid_indices]
            valid_idx_in_subset = np.argmax(valid_recall)
            # Map back to original indices
            valid_original_indices = np.where(valid_indices)[0]
            optimal_idx = valid_original_indices[valid_idx_in_subset]

        optimal_threshold = thresholds[optimal_idx]

        # Calculate performance metrics at optimal threshold
        y_pred = (y_scores >= optimal_threshold).astype(int)

        performance_metrics = {
            "pr_auc": pr_auc,
            "target_precision": target_precision,
            "achieved_precision": precision[optimal_idx],
            "achieved_recall": recall[optimal_idx],
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1_score": f1_score(y_true, y_pred, zero_division=0),
            "threshold_idx": optimal_idx,
            "n_thresholds": len(thresholds),
        }

        # Detailed threshold analysis
        threshold_analysis = {
            "method": "precision_recall",
            "target_precision": target_precision,
            "pr_curve": {
                "precision": precision.tolist(),
                "recall": recall.tolist(),
                "thresholds": thresholds.tolist(),
            },
            "optimal_point": {
                "precision": precision[optimal_idx],
                "recall": recall[optimal_idx],
                "threshold": optimal_threshold,
            },
        }

        return ThresholdOptimizationResult(
            metric_name=feature_name,
            optimal_threshold=float(optimal_threshold),
            optimization_method="precision_recall",
            performance_metrics=performance_metrics,
            threshold_analysis=threshold_analysis,
        )

    def _optimize_cost_sensitive(
        self,
        feature_name: str,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        false_positive_cost: float = 1.0,
        false_negative_cost: float = 5.0,
    ) -> ThresholdOptimizationResult:
        """
        Optimize threshold using cost-sensitive analysis.

        Minimizes expected cost = FP_cost * FPR + FN_cost * FNR
        Useful when false negatives are more costly than false positives.
        """
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)

        # Calculate false negative rate
        fnr = 1 - tpr

        # Calculate expected cost for each threshold
        expected_costs = false_positive_cost * fpr + false_negative_cost * fnr

        # Find threshold that minimizes expected cost
        optimal_idx = np.argmin(expected_costs)
        optimal_threshold = thresholds[optimal_idx]

        # Calculate performance metrics at optimal threshold
        y_pred = (y_scores >= optimal_threshold).astype(int)

        performance_metrics = {
            "false_positive_cost": false_positive_cost,
            "false_negative_cost": false_negative_cost,
            "optimal_expected_cost": expected_costs[optimal_idx],
            "optimal_fpr": fpr[optimal_idx],
            "optimal_fnr": fnr[optimal_idx],
            "optimal_tpr": tpr[optimal_idx],
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1_score": f1_score(y_true, y_pred, zero_division=0),
            "threshold_idx": optimal_idx,
            "n_thresholds": len(thresholds),
        }

        # Detailed threshold analysis
        threshold_analysis = {
            "method": "cost_sensitive",
            "cost_parameters": {
                "false_positive_cost": false_positive_cost,
                "false_negative_cost": false_negative_cost,
            },
            "roc_curve": {
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "thresholds": thresholds.tolist(),
            },
            "expected_costs": expected_costs.tolist(),
            "optimal_point": {
                "fpr": fpr[optimal_idx],
                "tpr": tpr[optimal_idx],
                "expected_cost": expected_costs[optimal_idx],
                "threshold": optimal_threshold,
            },
        }

        return ThresholdOptimizationResult(
            metric_name=feature_name,
            optimal_threshold=float(optimal_threshold),
            optimization_method="cost_sensitive",
            performance_metrics=performance_metrics,
            threshold_analysis=threshold_analysis,
        )

    def _validate_thresholds_with_cv(self, data: pd.DataFrame, target_column: str) -> None:
        """
        Validate learned thresholds using cross-validation.

        Ensures thresholds generalize well and are not overfitted to training data.
        """
        logger.info("Validating thresholds with cross-validation")

        from sklearn.model_selection import StratifiedKFold

        y = data[target_column].values
        skf = StratifiedKFold(
            n_splits=self.cross_validation_folds,
            shuffle=True,
            random_state=self.random_state,
        )

        cv_results = {}

        for feature_name, threshold_result in self.optimal_thresholds.items():
            X = data[feature_name].values
            optimal_threshold = threshold_result.optimal_threshold

            fold_scores = []

            for train_idx, val_idx in skf.split(X, y):
                X_val, y_val = X[val_idx], y[val_idx]

                # Apply learned threshold to validation set
                y_val_pred = (X_val >= optimal_threshold).astype(int)

                # Calculate performance metrics
                fold_score = {
                    "precision": precision_score(y_val, y_val_pred, zero_division=0),
                    "recall": recall_score(y_val, y_val_pred, zero_division=0),
                    "f1_score": f1_score(y_val, y_val_pred, zero_division=0),
                }
                fold_scores.append(fold_score)

            # Aggregate cross-validation results
            cv_results[feature_name] = {
                "mean_precision": np.mean([s["precision"] for s in fold_scores]),
                "std_precision": np.std([s["precision"] for s in fold_scores]),
                "mean_recall": np.mean([s["recall"] for s in fold_scores]),
                "std_recall": np.std([s["recall"] for s in fold_scores]),
                "mean_f1_score": np.mean([s["f1_score"] for s in fold_scores]),
                "std_f1_score": np.std([s["f1_score"] for s in fold_scores]),
                "n_folds": self.cross_validation_folds,
            }

        self.cross_validation_results = cv_results

        # Log validation summary
        avg_cv_f1 = np.mean([r["mean_f1_score"] for r in cv_results.values()])
        logger.info(f"Cross-validation complete. Average F1 score: {avg_cv_f1:.3f}")

    def get_threshold_for_metric(self, metric_name: str, default_threshold: Optional[float] = None) -> float:
        """
        Get optimal threshold for a specific metric.

        Args:
            metric_name: Name of the metric
            default_threshold: Default value if no learned threshold available

        Returns:
            Optimal threshold value
        """
        if metric_name in self.optimal_thresholds:
            return self.optimal_thresholds[metric_name].optimal_threshold
        elif default_threshold is not None:
            return default_threshold
        else:
            logger.warning(f"No threshold learned for {metric_name}, using median heuristic")
            return 0.5  # Default to median split

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary of learned thresholds."""
        if not self.optimal_thresholds:
            return {"error": "No thresholds learned yet"}

        summary: Dict[str, Any] = {
            "n_thresholds_learned": len(self.optimal_thresholds),
            "optimization_method": self.default_optimization_method,
            "cross_validation_folds": self.cross_validation_folds,
            "learning_history": self.performance_history,
            "threshold_summary": {},
            "cross_validation_summary": {},
        }

        # Summarize individual thresholds
        for name, result in self.optimal_thresholds.items():
            summary["threshold_summary"][name] = {
                "optimal_threshold": result.optimal_threshold,
                "f1_score": result.performance_metrics.get("f1_score", 0),
                "precision": result.performance_metrics.get("precision", 0),
                "recall": result.performance_metrics.get("recall", 0),
            }

        # Summarize cross-validation results
        if self.cross_validation_results:
            for name, cv_result in self.cross_validation_results.items():
                summary["cross_validation_summary"][name] = {
                    "cv_f1_mean": cv_result["mean_f1_score"],
                    "cv_f1_std": cv_result["std_f1_score"],
                    "cv_precision_mean": cv_result["mean_precision"],
                    "cv_recall_mean": cv_result["mean_recall"],
                }

        return summary
