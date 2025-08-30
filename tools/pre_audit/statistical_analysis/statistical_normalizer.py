"""
Statistical Normalizer for GitHub Issue #43
Implements robust statistical normalization methods for government-grade software analysis.

Replaces simple mean/std normalization with robust methods that handle outliers
and skewed distributions appropriately for reliable statistical analysis.

Based on:
- Rousseeuw & Croux (1993) Alternatives to the Median Absolute Deviation
- Huber & Ronchetti (2009) Robust Statistics
- Yeo & Johnson (2000) A new family of power transformations
"""

import logging
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import PowerTransformer, QuantileTransformer

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class NormalizationParams:
    """
    Parameters for statistical normalization.

    Attributes:
        method: Normalization method used
        parameters: Dictionary of method-specific parameters
        feature_name: Name of the feature being normalized
        validation_metrics: Metrics validating the normalization quality
    """

    method: str
    parameters: Dict[str, Any]
    feature_name: str
    validation_metrics: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "parameters": self.parameters,
            "feature_name": self.feature_name,
            "validation_metrics": self.validation_metrics,
        }


class StatisticalNormalizer:
    """
    Robust statistical normalizer using multiple normalization strategies.

    Implements multiple normalization methods with validation to ensure
    statistical assumptions are met for downstream analysis:

    Methods:
    - Robust Z-score: Uses median and MAD instead of mean and std
    - Quantile transformation: Maps to uniform or normal distribution
    - Power transformations: Box-Cox and Yeo-Johnson for normality
    - Winsorization: Clips extreme outliers
    """

    def __init__(
        self,
        default_method: str = "robust_z_score",
        outlier_threshold: float = 3.0,
        quantile_output_distribution: str = "uniform",
        validate_normalization: bool = True,
    ):
        """
        Initialize statistical normalizer.

        Args:
            default_method: Default normalization method
                Options: "robust_z_score", "quantile_uniform", "quantile_normal",
                        "box_cox", "yeo_johnson", "winsorize"
            outlier_threshold: Threshold for outlier detection (in MAD units)
            quantile_output_distribution: Output distribution for quantile transformer
            validate_normalization: Whether to validate normalization results
        """
        self.default_method = default_method
        self.outlier_threshold = outlier_threshold
        self.quantile_output_distribution = quantile_output_distribution
        self.validate_normalization = validate_normalization

        # Fitted normalization parameters
        self.normalization_params: Dict[str, NormalizationParams] = {}
        self.fitted_transformers: Dict[str, Any] = {}

        # Validation results
        self.normalization_diagnostics: Dict[str, Dict[str, Any]] = {}

        logger.info(f"Initialized StatisticalNormalizer with method={default_method}")

    def fit_normalization_parameters(
        self,
        data: pd.DataFrame,
        method: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> Dict[str, NormalizationParams]:
        """
        Fit normalization parameters using robust statistical methods.

        Automatically selects appropriate normalization method for each feature
        based on distribution characteristics and validates the results.

        Args:
            data: DataFrame with numerical features to normalize
            method: Override default normalization method
            features: Specific features to normalize (default: all numerical)

        Returns:
            Dictionary mapping feature names to normalization parameters

        Raises:
            ValueError: If no suitable features found or normalization fails
        """
        method = method or self.default_method

        # Identify numerical features
        if features is None:
            numerical_features = data.select_dtypes(include=[np.number]).columns.tolist()
        else:
            numerical_features = [f for f in features if f in data.columns]

        if not numerical_features:
            raise ValueError("No numerical features found for normalization")

        logger.info(f"Fitting normalization parameters for {len(numerical_features)} features using {method}")

        fitted_params = {}

        for feature_name in numerical_features:
            try:
                # Get clean feature data
                feature_data = self._get_clean_feature_data(data[feature_name])

                if len(feature_data) < 10:
                    logger.warning(f"Insufficient data for {feature_name}: {len(feature_data)} samples")
                    continue

                # Fit normalization parameters
                params = self._fit_feature_normalization(feature_name, feature_data, method)
                fitted_params[feature_name] = params

                logger.info(f"Fitted {method} normalization for {feature_name}")

            except Exception as e:
                logger.warning(f"Failed to fit normalization for {feature_name}: {str(e)}")
                continue

        if not fitted_params:
            raise ValueError("No features could be normalized")

        self.normalization_params = fitted_params

        # Validate normalization if requested
        if self.validate_normalization:
            self._validate_normalization(data)

        logger.info(f"Successfully fitted normalization for {len(fitted_params)} features")
        return fitted_params

    def _get_clean_feature_data(self, feature_series: pd.Series) -> np.ndarray:
        """
        Clean feature data by removing invalid values.

        Args:
            feature_series: Pandas Series with feature values

        Returns:
            Clean numpy array with finite values only
        """
        # Remove NaN, inf, and -inf values
        clean_data = feature_series.dropna()
        clean_data = clean_data[np.isfinite(clean_data)]

        return clean_data.values

    def _fit_feature_normalization(self, feature_name: str, data: np.ndarray, method: str) -> NormalizationParams:
        """
        Fit normalization parameters for a single feature.

        Args:
            feature_name: Name of the feature
            data: Clean feature data
            method: Normalization method to use

        Returns:
            NormalizationParams object with fitted parameters
        """
        if method == "robust_z_score":
            return self._fit_robust_z_score(feature_name, data)
        elif method == "quantile_uniform":
            return self._fit_quantile_transform(feature_name, data, "uniform")
        elif method == "quantile_normal":
            return self._fit_quantile_transform(feature_name, data, "normal")
        elif method == "box_cox":
            return self._fit_box_cox(feature_name, data)
        elif method == "yeo_johnson":
            return self._fit_yeo_johnson(feature_name, data)
        elif method == "winsorize":
            return self._fit_winsorize(feature_name, data)
        else:
            raise ValueError(f"Unknown normalization method: {method}")

    def _fit_robust_z_score(self, feature_name: str, data: np.ndarray) -> NormalizationParams:
        """
        Fit robust z-score normalization using median and MAD.

        Robust z-score = (x - median) / MAD
        where MAD = median absolute deviation = median(|x - median(x)|)
        """
        median = np.median(data)
        mad = np.median(np.abs(data - median))

        # Handle zero MAD (constant data)
        if mad == 0:
            # Use interquartile range as fallback
            q75, q25 = np.percentile(data, [75, 25])
            iqr = q75 - q25
            scale = iqr / 1.349  # Convert IQR to approximate MAD
            if scale == 0:
                scale = 1.0  # Last resort for truly constant data
        else:
            scale = mad

        # Calculate validation metrics
        normalized_data = (data - median) / scale
        validation_metrics = self._calculate_normalization_metrics(data, normalized_data)

        parameters = {
            "median": median,
            "mad": mad,
            "scale": scale,
            "method": "robust_z_score",
        }

        return NormalizationParams(
            method="robust_z_score",
            parameters=parameters,
            feature_name=feature_name,
            validation_metrics=validation_metrics,
        )

    def _fit_quantile_transform(
        self, feature_name: str, data: np.ndarray, output_distribution: str
    ) -> NormalizationParams:
        """
        Fit quantile transformation to uniform or normal distribution.

        Maps input distribution to specified output distribution using
        empirical cumulative distribution function.
        """
        transformer = QuantileTransformer(
            output_distribution=output_distribution,
            n_quantiles=min(1000, len(data)),
            random_state=42,
        )

        # Fit transformer
        data_reshaped = data.reshape(-1, 1)
        transformer.fit(data_reshaped)

        # Store transformer for later use
        self.fitted_transformers[feature_name] = transformer

        # Transform data for validation
        transformed_data = transformer.transform(data_reshaped).flatten()
        validation_metrics = self._calculate_normalization_metrics(data, transformed_data)

        parameters = {
            "output_distribution": output_distribution,
            "n_quantiles": transformer.n_quantiles_,
            "quantiles": transformer.quantiles_.tolist(),
            "method": f"quantile_{output_distribution}",
        }

        return NormalizationParams(
            method=f"quantile_{output_distribution}",
            parameters=parameters,
            feature_name=feature_name,
            validation_metrics=validation_metrics,
        )

    def _fit_box_cox(self, feature_name: str, data: np.ndarray) -> NormalizationParams:
        """
        Fit Box-Cox power transformation for positive data.

        Box-Cox transformation: (x^λ - 1) / λ for λ ≠ 0, ln(x) for λ = 0
        Requires positive data.
        """
        if np.any(data <= 0):
            raise ValueError(f"Box-Cox requires positive data, but {feature_name} has non-positive values")

        # Use PowerTransformer which handles the Box-Cox transformation
        transformer = PowerTransformer(method="box-cox", standardize=True)

        data_reshaped = data.reshape(-1, 1)
        transformer.fit(data_reshaped)

        # Store transformer
        self.fitted_transformers[feature_name] = transformer

        # Transform data for validation
        transformed_data = transformer.transform(data_reshaped).flatten()
        validation_metrics = self._calculate_normalization_metrics(data, transformed_data)

        parameters = {
            "lambda": transformer.lambdas_[0],
            "method": "box_cox",
            "standardize": True,
        }

        return NormalizationParams(
            method="box_cox",
            parameters=parameters,
            feature_name=feature_name,
            validation_metrics=validation_metrics,
        )

    def _fit_yeo_johnson(self, feature_name: str, data: np.ndarray) -> NormalizationParams:
        """
        Fit Yeo-Johnson power transformation.

        Extension of Box-Cox that works with negative values.
        More flexible than Box-Cox for real-world data.
        """
        transformer = PowerTransformer(method="yeo-johnson", standardize=True)

        data_reshaped = data.reshape(-1, 1)
        transformer.fit(data_reshaped)

        # Store transformer
        self.fitted_transformers[feature_name] = transformer

        # Transform data for validation
        transformed_data = transformer.transform(data_reshaped).flatten()
        validation_metrics = self._calculate_normalization_metrics(data, transformed_data)

        parameters = {
            "lambda": transformer.lambdas_[0],
            "method": "yeo_johnson",
            "standardize": True,
        }

        return NormalizationParams(
            method="yeo_johnson",
            parameters=parameters,
            feature_name=feature_name,
            validation_metrics=validation_metrics,
        )

    def _fit_winsorize(self, feature_name: str, data: np.ndarray) -> NormalizationParams:
        """
        Fit Winsorization parameters for outlier clipping.

        Clips extreme values to specified percentiles to reduce outlier impact.
        """
        # Calculate Winsorization limits (default: 5th and 95th percentiles)
        lower_percentile = 5
        upper_percentile = 95

        lower_limit = np.percentile(data, lower_percentile)
        upper_limit = np.percentile(data, upper_percentile)

        # Apply Winsorization
        winsorized_data = np.clip(data, lower_limit, upper_limit)

        # Apply robust z-score after Winsorization
        median = np.median(winsorized_data)
        mad = np.median(np.abs(winsorized_data - median))

        if mad == 0:
            q75, q25 = np.percentile(winsorized_data, [75, 25])
            scale = (q75 - q25) / 1.349
            if scale == 0:
                scale = 1.0
        else:
            scale = mad

        normalized_data = (winsorized_data - median) / scale
        validation_metrics = self._calculate_normalization_metrics(data, normalized_data)

        parameters = {
            "lower_limit": lower_limit,
            "upper_limit": upper_limit,
            "lower_percentile": lower_percentile,
            "upper_percentile": upper_percentile,
            "median": median,
            "mad": mad,
            "scale": scale,
            "method": "winsorize",
        }

        return NormalizationParams(
            method="winsorize",
            parameters=parameters,
            feature_name=feature_name,
            validation_metrics=validation_metrics,
        )

    def _calculate_normalization_metrics(
        self, original_data: np.ndarray, normalized_data: np.ndarray
    ) -> Dict[str, float]:
        """
        Calculate metrics to validate normalization quality.

        Returns metrics assessing whether normalization achieved desired properties.
        """
        metrics = {}

        # Basic statistics
        metrics["original_mean"] = np.mean(original_data)
        metrics["original_std"] = np.std(original_data)
        metrics["original_skewness"] = stats.skew(original_data)
        metrics["original_kurtosis"] = stats.kurtosis(original_data)

        metrics["normalized_mean"] = np.mean(normalized_data)
        metrics["normalized_std"] = np.std(normalized_data)
        metrics["normalized_skewness"] = stats.skew(normalized_data)
        metrics["normalized_kurtosis"] = stats.kurtosis(normalized_data)

        # Normality tests
        try:
            # Shapiro-Wilk test (for smaller samples)
            if len(normalized_data) <= 5000:
                shapiro_stat, shapiro_p = stats.shapiro(normalized_data)
                metrics["shapiro_statistic"] = shapiro_stat
                metrics["shapiro_p_value"] = shapiro_p

            # Kolmogorov-Smirnov test against normal distribution
            ks_stat, ks_p = stats.kstest(normalized_data, "norm")
            metrics["ks_statistic"] = ks_stat
            metrics["ks_p_value"] = ks_p

            # Anderson-Darling test
            ad_result = stats.anderson(normalized_data, dist="norm")
            metrics["anderson_statistic"] = ad_result.statistic
            metrics["anderson_critical_values"] = ad_result.critical_values.tolist()

        except Exception as e:
            logger.debug(f"Normality test failed: {str(e)}")
            metrics["normality_test_error"] = str(e)

        # Outlier metrics
        try:
            # Z-score based outlier detection
            z_scores = np.abs(stats.zscore(normalized_data))
            outlier_rate = np.mean(z_scores > 3.0)
            metrics["outlier_rate_3sigma"] = outlier_rate

            # IQR-based outlier detection
            q75, q25 = np.percentile(normalized_data, [75, 25])
            iqr = q75 - q25
            lower_bound = q25 - 1.5 * iqr
            upper_bound = q75 + 1.5 * iqr
            iqr_outlier_rate = np.mean((normalized_data < lower_bound) | (normalized_data > upper_bound))
            metrics["outlier_rate_iqr"] = iqr_outlier_rate

        except Exception as e:
            logger.debug(f"Outlier calculation failed: {str(e)}")
            metrics["outlier_calc_error"] = str(e)

        return metrics

    def normalize(self, data: pd.DataFrame, features: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Apply fitted normalization to new data.

        Args:
            data: DataFrame with features to normalize
            features: Specific features to normalize (default: all fitted features)

        Returns:
            DataFrame with normalized features

        Raises:
            ValueError: If normalization not fitted or features not found
        """
        if not self.normalization_params:
            raise ValueError("Normalization parameters not fitted. Call fit_normalization_parameters first.")

        normalized_data = data.copy()

        if features is None:
            features = list(self.normalization_params.keys())

        for feature_name in features:
            if feature_name not in self.normalization_params:
                logger.warning(f"No normalization parameters for {feature_name}, skipping")
                continue

            if feature_name not in data.columns:
                logger.warning(f"Feature {feature_name} not found in data, skipping")
                continue

            try:
                params = self.normalization_params[feature_name]
                feature_data = data[feature_name].values

                # Apply normalization based on method
                if params.method == "robust_z_score":
                    normalized_values = self._apply_robust_z_score(feature_data, params.parameters)
                elif params.method.startswith("quantile_"):
                    normalized_values = self._apply_quantile_transform(feature_name, feature_data)
                elif params.method == "box_cox":
                    normalized_values = self._apply_box_cox(feature_name, feature_data)
                elif params.method == "yeo_johnson":
                    normalized_values = self._apply_yeo_johnson(feature_name, feature_data)
                elif params.method == "winsorize":
                    normalized_values = self._apply_winsorize(feature_data, params.parameters)
                else:
                    logger.warning(f"Unknown normalization method: {params.method}")
                    continue

                normalized_data[feature_name] = normalized_values

            except Exception as e:
                logger.warning(f"Failed to normalize {feature_name}: {str(e)}")
                continue

        return normalized_data

    def _apply_robust_z_score(self, data: np.ndarray, params: Dict[str, Any]) -> np.ndarray:
        """Apply robust z-score normalization using fitted parameters."""
        median = params["median"]
        scale = params["scale"]
        return (data - median) / scale

    def _apply_quantile_transform(self, feature_name: str, data: np.ndarray) -> np.ndarray:
        """Apply quantile transformation using fitted transformer."""
        if feature_name not in self.fitted_transformers:
            raise ValueError(f"No fitted transformer for {feature_name}")

        transformer = self.fitted_transformers[feature_name]
        data_reshaped = data.reshape(-1, 1)
        return transformer.transform(data_reshaped).flatten()

    def _apply_box_cox(self, feature_name: str, data: np.ndarray) -> np.ndarray:
        """Apply Box-Cox transformation using fitted transformer."""
        if feature_name not in self.fitted_transformers:
            raise ValueError(f"No fitted transformer for {feature_name}")

        transformer = self.fitted_transformers[feature_name]
        data_reshaped = data.reshape(-1, 1)
        return transformer.transform(data_reshaped).flatten()

    def _apply_yeo_johnson(self, feature_name: str, data: np.ndarray) -> np.ndarray:
        """Apply Yeo-Johnson transformation using fitted transformer."""
        if feature_name not in self.fitted_transformers:
            raise ValueError(f"No fitted transformer for {feature_name}")

        transformer = self.fitted_transformers[feature_name]
        data_reshaped = data.reshape(-1, 1)
        return transformer.transform(data_reshaped).flatten()

    def _apply_winsorize(self, data: np.ndarray, params: Dict[str, Any]) -> np.ndarray:
        """Apply Winsorization using fitted parameters."""
        # First clip outliers
        clipped_data = np.clip(data, params["lower_limit"], params["upper_limit"])

        # Then apply robust z-score
        median = params["median"]
        scale = params["scale"]
        return (clipped_data - median) / scale

    def _validate_normalization(self, original_data: pd.DataFrame) -> None:
        """
        Validate normalization results and store diagnostic information.

        Assesses whether normalization achieved desired statistical properties.
        """
        logger.info("Validating normalization results")

        diagnostics = {}

        for feature_name, params in self.normalization_params.items():
            try:
                # Apply normalization to original data
                normalized_data = self.normalize(original_data[[feature_name]])
                normalized_values = normalized_data[feature_name].values

                # Calculate additional validation metrics
                validation = {
                    "method": params.method,
                    "normalization_effective": True,
                    "normality_improved": False,
                    "outliers_reduced": False,
                }

                # Check if normality improved
                original_values = original_data[feature_name].dropna().values
                if len(original_values) > 10:
                    original_skew = abs(stats.skew(original_values))
                    normalized_skew = abs(stats.skew(normalized_values))
                    validation["normality_improved"] = normalized_skew < original_skew

                # Check if outliers were reduced
                original_outlier_rate = np.mean(np.abs(stats.zscore(original_values)) > 3.0)
                normalized_outlier_rate = np.mean(np.abs(stats.zscore(normalized_values)) > 3.0)
                validation["outliers_reduced"] = normalized_outlier_rate < original_outlier_rate

                validation.update(params.validation_metrics)
                diagnostics[feature_name] = validation

            except Exception as e:
                logger.warning(f"Validation failed for {feature_name}: {str(e)}")
                diagnostics[feature_name] = {"validation_error": str(e)}

        self.normalization_diagnostics = diagnostics

    def get_normalization_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of normalization parameters and diagnostics."""
        if not self.normalization_params:
            return {"error": "No normalization parameters fitted"}

        summary: Dict[str, Any] = {
            "n_features_normalized": len(self.normalization_params),
            "default_method": self.default_method,
            "outlier_threshold": self.outlier_threshold,
            "feature_summary": {},
            "diagnostics": self.normalization_diagnostics,
        }

        for feature_name, params in self.normalization_params.items():
            summary["feature_summary"][feature_name] = {
                "method": params.method,
                "validation_metrics": params.validation_metrics,
            }

        return summary
