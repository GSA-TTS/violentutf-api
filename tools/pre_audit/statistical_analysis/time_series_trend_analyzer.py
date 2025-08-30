"""
Time Series Trend Analyzer for GitHub Issue #43
Implements comprehensive time series analysis for temporal violation patterns.

Provides statistical trend analysis, seasonal decomposition, and anomaly detection
to support temporally-aware risk assessment for government software quality.

Based on:
- Hamilton (1994) Time Series Analysis
- Tsay (2005) Analysis of Financial Time Series
- Box & Jenkins (1976) Time Series Analysis: Forecasting and Control
- Seasonal decomposition methods for violation pattern analysis
"""

import logging
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats

# Handle optional dependencies gracefully
try:
    from statsmodels.stats.diagnostic import acorr_ljungbox
    from statsmodels.tsa.seasonal import seasonal_decompose
    from statsmodels.tsa.stattools import acf, adfuller, pacf

    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("statsmodels not available. Some time series features will be limited.")

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class TrendAnalysisResult:
    """
    Comprehensive trend analysis result.

    Attributes:
        trend_direction: Overall trend direction (increasing/decreasing/no_trend)
        trend_significance: Statistical significance of trend (p-value)
        trend_slope: Linear trend slope coefficient
        trend_strength: Quantitative measure of trend strength [0,1]
        seasonal_patterns: Information about seasonal patterns
        anomalies: Detected anomalies with timestamps and severity
        stationarity: Stationarity test results
        autocorrelation: Autocorrelation analysis results
        decomposition_available: Whether seasonal decomposition was performed
        analysis_metadata: Additional analysis metadata
    """

    trend_direction: str
    trend_significance: float
    trend_slope: float
    trend_strength: float
    seasonal_patterns: Dict[str, Any]
    anomalies: List[Dict[str, Any]]
    stationarity: Dict[str, Any]
    autocorrelation: Dict[str, Any]
    decomposition_available: bool
    analysis_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "trend_direction": self.trend_direction,
            "trend_significance": self.trend_significance,
            "trend_slope": self.trend_slope,
            "trend_strength": self.trend_strength,
            "seasonal_patterns": self.seasonal_patterns,
            "anomalies": self.anomalies,
            "stationarity": self.stationarity,
            "autocorrelation": self.autocorrelation,
            "decomposition_available": self.decomposition_available,
            "analysis_metadata": self.analysis_metadata,
        }


class TimeSeriesTrendAnalyzer:
    """
    Time series trend analyzer for violation patterns.

    Implements comprehensive time series analysis methods to understand
    temporal patterns in software violations, supporting risk assessment
    and predictive modeling for government software quality assurance.

    Key Features:
    - Statistical trend testing (Mann-Kendall, linear regression)
    - Seasonal decomposition for pattern identification
    - Anomaly detection using statistical process control
    - Stationarity testing for model validation
    - Autocorrelation analysis for dependency detection
    """

    def __init__(
        self,
        anomaly_threshold: float = 2.5,
        min_observations: int = 30,
        seasonal_period: Optional[int] = None,
        trend_significance_level: float = 0.05,
    ):
        """
        Initialize time series trend analyzer.

        Args:
            anomaly_threshold: Standard deviations for anomaly detection
            min_observations: Minimum observations required for analysis
            seasonal_period: Expected seasonal period (auto-detect if None)
            trend_significance_level: Significance level for trend tests
        """
        self.anomaly_threshold = anomaly_threshold
        self.min_observations = min_observations
        self.seasonal_period = seasonal_period
        self.trend_significance_level = trend_significance_level

        # Analysis results cache
        self.analysis_cache: Dict[str, TrendAnalysisResult] = {}

        # Performance tracking
        self.analysis_performance: Dict[str, float] = {}

        logger.info(f"Initialized TimeSeriesTrendAnalyzer with anomaly_threshold={anomaly_threshold}")

    def analyze_violation_trends(
        self,
        violations: List[Dict[str, Any]],
        analysis_frequency: str = "daily",
        file_path_filter: Optional[str] = None,
    ) -> TrendAnalysisResult:
        """
        Comprehensive trend analysis with statistical validation.

        Performs seasonal decomposition, trend testing, and anomaly detection
        on violation time series data.

        Args:
            violations: List of violation dictionaries with timestamp and severity
            analysis_frequency: Frequency for aggregation ("daily", "weekly", "monthly")
            file_path_filter: Optional filter for specific file path

        Returns:
            TrendAnalysisResult with comprehensive trend analysis

        Raises:
            ValueError: If insufficient data or invalid parameters
        """
        if len(violations) < self.min_observations:
            raise ValueError(f"Insufficient data: {len(violations)} < {self.min_observations}")

        logger.info(f"Analyzing violation trends for {len(violations)} violations")

        # Convert to time series format
        try:
            violations_ts = self._create_time_series(violations, analysis_frequency, file_path_filter)
        except Exception as e:
            raise ValueError(f"Failed to create time series: {str(e)}")

        if len(violations_ts) < self.min_observations:
            raise ValueError(f"Insufficient time series data: {len(violations_ts)} observations")

        # Initialize analysis components
        analysis_components = {
            "decomposition_available": STATSMODELS_AVAILABLE,
            "trend_tests": {},
            "seasonal_patterns": {},
            "anomalies": [],
            "stationarity": {},
            "autocorrelation": {},
        }

        try:
            # 1. Seasonal Decomposition (if statsmodels available)
            if STATSMODELS_AVAILABLE and len(violations_ts) >= 2 * (self.seasonal_period or 30):
                decomposition_result = self._perform_seasonal_decomposition(violations_ts, analysis_frequency)
                analysis_components.update(decomposition_result)
            else:
                # Fallback trend analysis without seasonal decomposition
                analysis_components.update(self._basic_trend_analysis(violations_ts))

            # 2. Statistical Trend Testing
            trend_tests = self._perform_comprehensive_trend_tests(violations_ts.values)
            analysis_components["trend_tests"] = trend_tests

            # 3. Anomaly Detection
            anomalies = self._detect_anomalies_basic(violations_ts)
            analysis_components["anomalies"] = anomalies

            # 4. Stationarity Testing
            if STATSMODELS_AVAILABLE:
                stationarity_test = self._test_stationarity(violations_ts.values)
                analysis_components["stationarity"] = stationarity_test

            # 5. Autocorrelation Analysis
            autocorr_result = self._analyze_autocorrelation_basic(violations_ts.values)
            analysis_components["autocorrelation"] = autocorr_result

        except Exception as e:
            logger.warning(f"Some analysis components failed: {str(e)}")

        # Synthesize results
        result = self._synthesize_analysis_results(violations_ts, analysis_components, analysis_frequency)

        # Cache results
        cache_key = f"{file_path_filter or 'all'}_{analysis_frequency}"
        self.analysis_cache[cache_key] = result

        logger.info(
            f"Trend analysis complete: {result.trend_direction} trend " + f"(p={result.trend_significance:.4f})"
        )

        return result

    def _create_time_series(
        self,
        violations: List[Dict[str, Any]],
        frequency: str,
        file_path_filter: Optional[str] = None,
    ) -> pd.Series:
        """
        Convert violations to time series with specified frequency.

        Args:
            violations: List of violation dictionaries
            frequency: Aggregation frequency
            file_path_filter: Optional file path filter

        Returns:
            Pandas Series with time series data
        """
        # Create DataFrame from violations
        df_data = []
        for violation in violations:
            # Handle different timestamp formats
            if isinstance(violation.get("timestamp"), str):
                timestamp = pd.to_datetime(violation["timestamp"])
            elif isinstance(violation.get("timestamp"), datetime):
                timestamp = violation["timestamp"]
            else:
                continue  # Skip invalid timestamps

            # Apply file path filter if specified
            if file_path_filter and violation.get("file_path") != file_path_filter:
                continue

            df_data.append(
                {
                    "timestamp": timestamp,
                    "severity": float(violation.get("severity", 1.0)),
                    "file_path": violation.get("file_path", "unknown"),
                }
            )

        if not df_data:
            raise ValueError("No valid violation data after filtering")

        df = pd.DataFrame(df_data)
        df.set_index("timestamp", inplace=True)
        df.sort_index(inplace=True)

        # Aggregate by frequency
        if frequency == "daily":
            ts = df.resample("D")["severity"].sum()
        elif frequency == "weekly":
            ts = df.resample("W")["severity"].sum()
        elif frequency == "monthly":
            ts = df.resample("M")["severity"].sum()
        else:
            raise ValueError(f"Unsupported frequency: {frequency}")

        # Fill missing values with 0
        ts = ts.fillna(0)

        # Remove leading/trailing zeros for better analysis
        first_nonzero = ts[ts > 0].index.min() if ts.sum() > 0 else ts.index.min()
        last_nonzero = ts[ts > 0].index.max() if ts.sum() > 0 else ts.index.max()

        if pd.isna(first_nonzero) or pd.isna(last_nonzero):
            ts = ts  # Keep original if no non-zero values
        else:
            ts = ts[first_nonzero:last_nonzero]

        return ts

    def _perform_seasonal_decomposition(self, time_series: pd.Series, frequency: str) -> Dict[str, Any]:
        """
        Perform seasonal decomposition using statsmodels.

        Args:
            time_series: Time series data
            frequency: Analysis frequency for period determination

        Returns:
            Dictionary with decomposition results
        """
        try:
            # Determine seasonal period
            if self.seasonal_period:
                period = self.seasonal_period
            else:
                # Auto-determine period based on frequency
                if frequency == "daily":
                    period = 30  # Monthly seasonality
                elif frequency == "weekly":
                    period = 12  # Quarterly seasonality
                elif frequency == "monthly":
                    period = 12  # Annual seasonality
                else:
                    period = 7  # Default weekly

            # Ensure we have enough data for decomposition
            if len(time_series) < 2 * period:
                period = max(4, len(time_series) // 3)

            # Perform seasonal decomposition
            decomposition = seasonal_decompose(
                time_series.values,
                model="additive",
                period=period,
                extrapolate_trend="freq",
            )

            trend_component = decomposition.trend
            seasonal_component = decomposition.seasonal
            residual_component = decomposition.resid

            # Calculate trend strength
            trend_strength = self._calculate_trend_strength(time_series.values, trend_component, seasonal_component)

            # Calculate seasonal strength
            seasonal_strength = self._calculate_seasonal_strength(seasonal_component)

            # Identify dominant frequencies
            dominant_frequencies = self._identify_dominant_frequencies(seasonal_component)

            return {
                "decomposition_components": {
                    "trend": trend_component,
                    "seasonal": seasonal_component,
                    "residual": residual_component,
                },
                "trend_strength": trend_strength,
                "seasonal_patterns": {
                    "has_seasonality": seasonal_strength > 0.1,
                    "seasonal_strength": seasonal_strength,
                    "dominant_frequencies": dominant_frequencies,
                    "period": period,
                },
            }

        except Exception as e:
            logger.warning(f"Seasonal decomposition failed: {str(e)}")
            return self._basic_trend_analysis(time_series)

    def _basic_trend_analysis(self, time_series: pd.Series) -> Dict[str, Any]:
        """
        Basic trend analysis without seasonal decomposition.

        Fallback method when statsmodels is not available.
        """
        values = time_series.values

        # Simple linear trend
        x = np.arange(len(values))
        slope, intercept, r_value, p_value, std_err = stats.linregress(x, values)

        # Calculate trend strength as R-squared
        trend_strength = r_value**2

        return {
            "decomposition_components": {
                "trend": slope * x + intercept,
                "seasonal": np.zeros_like(values),
                "residual": values - (slope * x + intercept),
            },
            "trend_strength": trend_strength,
            "seasonal_patterns": {
                "has_seasonality": False,
                "seasonal_strength": 0.0,
                "dominant_frequencies": [],
                "period": None,
            },
        }

    def _perform_comprehensive_trend_tests(self, data: np.ndarray) -> Dict[str, Any]:
        """
        Perform comprehensive trend testing.

        Args:
            data: Time series data array

        Returns:
            Dictionary with trend test results
        """
        results = {}

        # Mann-Kendall trend test (non-parametric)
        try:
            mann_kendall_result = self._mann_kendall_test(data)
            results["mann_kendall"] = mann_kendall_result
        except Exception as e:
            logger.debug(f"Mann-Kendall test failed: {str(e)}")
            results["mann_kendall"] = {"error": str(e)}

        # Linear regression trend test
        try:
            x = np.arange(len(data))
            slope, intercept, r_value, p_value, std_err = stats.linregress(x, data)

            results["linear_regression"] = {
                "slope": slope,
                "intercept": intercept,
                "r_squared": r_value**2,
                "p_value": p_value,
                "std_error": std_err,
                "significant": p_value < self.trend_significance_level,
            }
        except Exception as e:
            logger.debug(f"Linear regression test failed: {str(e)}")
            results["linear_regression"] = {"error": str(e)}

        # Spearman rank correlation test
        try:
            x = np.arange(len(data))
            correlation, p_value = stats.spearmanr(x, data)

            results["spearman_trend"] = {
                "correlation": correlation,
                "p_value": p_value,
                "significant": p_value < self.trend_significance_level,
            }
        except Exception as e:
            logger.debug(f"Spearman trend test failed: {str(e)}")
            results["spearman_trend"] = {"error": str(e)}

        return results

    def _mann_kendall_test(self, data: np.ndarray) -> Dict[str, Any]:
        """
        Mann-Kendall trend test implementation.

        Non-parametric test for monotonic trend detection.
        """
        n = len(data)
        s = 0

        # Calculate S statistic
        for i in range(n - 1):
            for j in range(i + 1, n):
                if data[j] > data[i]:
                    s += 1
                elif data[j] < data[i]:
                    s -= 1

        # Calculate variance of S
        var_s = n * (n - 1) * (2 * n + 5) / 18

        # Calculate standardized test statistic
        if var_s > 0:
            if s > 0:
                z = (s - 1) / np.sqrt(var_s)
            elif s < 0:
                z = (s + 1) / np.sqrt(var_s)
            else:
                z = 0
        else:
            z = 0

        # Calculate p-value (two-tailed test)
        p_value = 2 * (1 - stats.norm.cdf(abs(z)))

        # Determine trend direction
        if p_value < self.trend_significance_level:
            if s > 0:
                trend = "increasing"
            else:
                trend = "decreasing"
        else:
            trend = "no_trend"

        return {
            "statistic": s,
            "z_score": z,
            "p_value": p_value,
            "trend": trend,
            "significant": p_value < self.trend_significance_level,
        }

    def _detect_anomalies_basic(self, time_series: pd.Series) -> List[Dict[str, Any]]:
        """
        Basic anomaly detection using statistical control limits.

        Uses control chart methodology with configurable threshold.
        """
        values = time_series.values

        # Calculate control limits using moving statistics
        window_size = min(30, len(values) // 4)
        if window_size < 3:
            window_size = len(values)

        # Rolling mean and standard deviation
        if len(values) > window_size:
            rolling_mean = pd.Series(values).rolling(window_size, center=True).mean()
            rolling_std = pd.Series(values).rolling(window_size, center=True).std()
        else:
            rolling_mean = pd.Series([np.mean(values)] * len(values))
            rolling_std = pd.Series([np.std(values)] * len(values))

        anomalies = []

        for i, (timestamp, value) in enumerate(time_series.items()):
            if pd.isna(rolling_mean.iloc[i]) or pd.isna(rolling_std.iloc[i]):
                continue

            mean_val = rolling_mean.iloc[i]
            std_val = rolling_std.iloc[i]

            if std_val > 0:
                z_score = abs(value - mean_val) / std_val

                if z_score > self.anomaly_threshold:
                    anomaly_type = "high" if value > mean_val else "low"

                    anomalies.append(
                        {
                            "timestamp": timestamp.isoformat(),
                            "value": float(value),
                            "z_score": float(z_score),
                            "type": anomaly_type,
                            "severity": min(z_score / self.anomaly_threshold, 3.0),
                            "expected_value": float(mean_val),
                            "control_limits": {
                                "upper": float(mean_val + self.anomaly_threshold * std_val),
                                "lower": float(mean_val - self.anomaly_threshold * std_val),
                            },
                        }
                    )

        return anomalies

    def _test_stationarity(self, data: np.ndarray) -> Dict[str, Any]:
        """Test for stationarity using Augmented Dickey-Fuller test."""
        try:
            adf_result = adfuller(data, autolag="AIC")

            return {
                "adf_statistic": adf_result[0],
                "p_value": adf_result[1],
                "critical_values": adf_result[4],
                "is_stationary": adf_result[1] < 0.05,
                "used_lags": adf_result[2],
            }
        except Exception as e:
            return {"error": f"Stationarity test failed: {str(e)}"}

    def _analyze_autocorrelation_basic(self, data: np.ndarray) -> Dict[str, Any]:
        """
        Basic autocorrelation analysis.

        Fallback method when statsmodels is not available.
        """
        try:
            # Simple lag-1 autocorrelation
            if len(data) > 1:
                lag1_autocorr = np.corrcoef(data[:-1], data[1:])[0, 1]
                if np.isnan(lag1_autocorr):
                    lag1_autocorr = 0.0
            else:
                lag1_autocorr = 0.0

            # Durbin-Watson statistic approximation
            if len(data) > 1:
                dw_stat = np.sum(np.diff(data) ** 2) / np.sum((data - np.mean(data)) ** 2)
            else:
                dw_stat = 2.0

            return {
                "lag1_autocorrelation": lag1_autocorr,
                "durbin_watson": dw_stat,
                "has_autocorrelation": abs(lag1_autocorr) > 0.2,
                "method": "basic",
            }

        except Exception as e:
            return {"error": f"Autocorrelation analysis failed: {str(e)}"}

    def _calculate_trend_strength(
        self,
        original_data: np.ndarray,
        trend_component: np.ndarray,
        seasonal_component: np.ndarray,
    ) -> float:
        """
        Calculate trend strength as proportion of variation explained by trend.

        Based on STL decomposition strength measures.
        """
        try:
            # Remove NaN values
            valid_mask = ~(np.isnan(original_data) | np.isnan(trend_component))
            if not np.any(valid_mask):
                return 0.0

            original_clean = original_data[valid_mask]
            trend_clean = trend_component[valid_mask]

            if len(original_clean) == 0:
                return 0.0

            # Calculate remainder after removing trend
            remainder = original_clean - trend_clean

            # Trend strength = 1 - Var(remainder) / Var(original)
            var_remainder = np.var(remainder)
            var_original = np.var(original_clean)

            if var_original > 0:
                trend_strength = 1 - (var_remainder / var_original)
                return float(max(0.0, min(1.0, trend_strength)))
            else:
                return 0.0

        except Exception:
            return 0.0

    def _calculate_seasonal_strength(self, seasonal_component: np.ndarray) -> float:
        """Calculate strength of seasonal component."""
        try:
            # Remove NaN values
            valid_seasonal = seasonal_component[~np.isnan(seasonal_component)]

            if len(valid_seasonal) == 0:
                return 0.0

            # Seasonal strength based on variance of seasonal component
            seasonal_var = np.var(valid_seasonal)

            # Normalize by comparing to typical seasonal variation
            # This is a simplified measure
            if seasonal_var > 0:
                return float(min(1.0, seasonal_var / (np.mean(np.abs(valid_seasonal)) + 1e-10)))
            else:
                return 0.0

        except Exception:
            return 0.0

    def _identify_dominant_frequencies(self, seasonal_component: np.ndarray) -> List[int]:
        """
        Identify dominant frequencies in seasonal component.

        Simple implementation using basic frequency analysis.
        """
        try:
            # Remove NaN values
            valid_seasonal = seasonal_component[~np.isnan(seasonal_component)]

            if len(valid_seasonal) < 8:
                return []

            # Simple frequency analysis using FFT (basic implementation)
            fft_values = np.fft.fft(valid_seasonal)
            fft_freqs = np.fft.fftfreq(len(valid_seasonal))

            # Find dominant frequencies (simple peak detection)
            magnitude = np.abs(fft_values)

            # Get indices of largest magnitudes (excluding DC component)
            sorted_indices = np.argsort(magnitude[1 : len(magnitude) // 2])[::-1]

            # Convert to periods (simplified)
            dominant_periods = []
            for idx in sorted_indices[:3]:  # Top 3 frequencies
                freq = fft_freqs[idx + 1]  # +1 to skip DC
                if freq > 0:
                    period = int(1.0 / freq)
                    if period > 1 and period < len(valid_seasonal) // 2:
                        dominant_periods.append(period)

            return dominant_periods

        except Exception:
            return []

    def _synthesize_analysis_results(
        self, time_series: pd.Series, components: Dict[str, Any], frequency: str
    ) -> TrendAnalysisResult:
        """
        Synthesize all analysis components into final result.

        Args:
            time_series: Original time series data
            components: Dictionary with analysis components
            frequency: Analysis frequency

        Returns:
            TrendAnalysisResult with synthesized results
        """
        # Extract trend information
        trend_tests = components.get("trend_tests", {})

        # Determine overall trend direction
        trend_direction = "no_trend"
        trend_significance = 1.0
        trend_slope = 0.0

        # Prioritize Mann-Kendall test if available
        if "mann_kendall" in trend_tests and "trend" in trend_tests["mann_kendall"]:
            mk_result = trend_tests["mann_kendall"]
            trend_direction = mk_result["trend"]
            trend_significance = mk_result["p_value"]
        elif "linear_regression" in trend_tests:
            lr_result = trend_tests["linear_regression"]
            trend_slope = lr_result.get("slope", 0.0)
            trend_significance = lr_result.get("p_value", 1.0)

            if trend_significance < self.trend_significance_level:
                trend_direction = "increasing" if trend_slope > 0 else "decreasing"

        # Get trend strength
        trend_strength = components.get("trend_strength", 0.0)

        # Get seasonal patterns
        seasonal_patterns = components.get(
            "seasonal_patterns",
            {
                "has_seasonality": False,
                "seasonal_strength": 0.0,
                "dominant_frequencies": [],
                "period": None,
            },
        )

        # Get anomalies
        anomalies = components.get("anomalies", [])

        # Get stationarity results
        stationarity = components.get("stationarity", {"is_stationary": True})

        # Get autocorrelation results
        autocorrelation = components.get("autocorrelation", {"has_autocorrelation": False})

        # Analysis metadata
        analysis_metadata = {
            "n_observations": len(time_series),
            "time_range": {
                "start": time_series.index.min().isoformat(),
                "end": time_series.index.max().isoformat(),
            },
            "frequency": frequency,
            "total_severity": float(time_series.sum()),
            "average_severity": float(time_series.mean()),
            "statsmodels_available": STATSMODELS_AVAILABLE,
            "analysis_components": list(components.keys()),
        }

        return TrendAnalysisResult(
            trend_direction=trend_direction,
            trend_significance=trend_significance,
            trend_slope=trend_slope,
            trend_strength=trend_strength,
            seasonal_patterns=seasonal_patterns,
            anomalies=anomalies,
            stationarity=stationarity,
            autocorrelation=autocorrelation,
            decomposition_available=components.get("decomposition_available", False),
            analysis_metadata=analysis_metadata,
        )

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of analysis capabilities and cached results."""
        return {
            "analyzer_configuration": {
                "anomaly_threshold": self.anomaly_threshold,
                "min_observations": self.min_observations,
                "seasonal_period": self.seasonal_period,
                "trend_significance_level": self.trend_significance_level,
            },
            "statsmodels_available": STATSMODELS_AVAILABLE,
            "cached_analyses": len(self.analysis_cache),
            "analysis_performance": self.analysis_performance,
            "supported_frequencies": ["daily", "weekly", "monthly"],
        }
