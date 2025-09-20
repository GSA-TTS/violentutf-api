"""
Performance Baseline Service for Issue #123 - Phase 5 Database Monitoring.

This service manages performance baselines for all repository operations,
enabling regression detection and performance trend analysis.

Features:
- Automatic baseline establishment from historical data
- Baseline persistence and loading
- Performance deviation detection
- Baseline updates and maintenance
- Repository-specific baseline management
"""

import json
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from structlog.stdlib import get_logger

from ..utils.performance_tracker import OperationMetrics, PerformanceTracker, get_global_performance_tracker

logger = get_logger(__name__)


@dataclass
class PerformanceBaseline:
    """Performance baseline for a specific operation."""

    operation_name: str
    repository: str
    model: str
    baseline_duration_ms: float
    baseline_p50_ms: float
    baseline_p95_ms: float
    baseline_p99_ms: float
    sample_size: int
    confidence_level: float
    established_date: datetime
    last_updated: datetime
    baseline_version: str
    metadata: Dict[str, Any]


@dataclass
class BaselineStatistics:
    """Statistical analysis for baseline establishment."""

    operation_name: str
    total_samples: int
    duration_mean: float
    duration_median: float
    duration_std: float
    p50: float
    p95: float
    p99: float
    min_duration: float
    max_duration: float
    outliers_removed: int
    confidence_interval: Tuple[float, float]


@dataclass
class PerformanceDeviation:
    """Performance deviation from baseline."""

    operation_name: str
    current_duration: float
    baseline_duration: float
    deviation_percentage: float
    deviation_type: str  # "improvement", "regression", "within_normal"
    severity: str  # "low", "medium", "high", "critical"
    sample_size: int
    confidence_level: float


class PerformanceBaselineService:
    """
    Service for managing performance baselines across all repositories.

    Provides baseline establishment, maintenance, and deviation detection
    for comprehensive performance monitoring.
    """

    def __init__(
        self,
        performance_tracker: Optional[PerformanceTracker] = None,
        baseline_storage_path: str = "./data/performance_baselines",
    ):
        """
        Initialize the performance baseline service.

        Args:
            performance_tracker: Performance tracker instance
            baseline_storage_path: Path to store baseline data
        """
        self.performance_tracker = performance_tracker or get_global_performance_tracker()
        self.baseline_storage_path = Path(baseline_storage_path)
        self.baseline_storage_path.mkdir(parents=True, exist_ok=True)

        # Baseline storage
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.baseline_statistics: Dict[str, BaselineStatistics] = {}

        # Configuration
        self.min_samples_for_baseline = 50
        self.confidence_level = 0.95
        self.outlier_threshold = 3.0  # Standard deviations
        self.deviation_thresholds = {
            "low": 0.15,  # 15%
            "medium": 0.30,  # 30%
            "high": 0.50,  # 50%
            "critical": 1.0,  # 100%
        }

        # Load existing baselines
        self._load_baselines()

        logger.info(
            "Performance baseline service initialized",
            baseline_count=len(self.baselines),
            storage_path=str(self.baseline_storage_path),
        )

    async def establish_all_baselines(
        self, force_update: bool = False, min_samples: Optional[int] = None
    ) -> Dict[str, PerformanceBaseline]:
        """
        Establish baselines for all tracked operations.

        Args:
            force_update: Whether to force update existing baselines
            min_samples: Minimum samples required (overrides default)

        Returns:
            Dictionary of established baselines
        """
        logger.info("Establishing performance baselines for all operations")

        min_samples = min_samples or self.min_samples_for_baseline
        established_baselines = {}

        # Process each operation
        for operation_name in self.performance_tracker._history.keys():
            try:
                baseline = await self._establish_operation_baseline(operation_name, force_update, min_samples)
                if baseline:
                    established_baselines[operation_name] = baseline
            except Exception as e:
                logger.error("Failed to establish baseline", operation=operation_name, error=str(e))

        # Save all baselines
        await self._save_baselines()

        logger.info(
            "Baseline establishment completed",
            total_operations=len(self.performance_tracker._history),
            baselines_established=len(established_baselines),
        )

        return established_baselines

    async def _establish_operation_baseline(
        self, operation_name: str, force_update: bool, min_samples: int
    ) -> Optional[PerformanceBaseline]:
        """
        Establish baseline for a specific operation.

        Args:
            operation_name: Name of the operation
            force_update: Whether to force update existing baseline
            min_samples: Minimum samples required

        Returns:
            Established baseline or None if insufficient data
        """
        # Check if baseline already exists and force_update is False
        if operation_name in self.baselines and not force_update:
            logger.debug(f"Baseline already exists for {operation_name}, skipping")
            return self.baselines[operation_name]

        # Get operation history
        history = self.performance_tracker.get_operation_history(operation_name)
        if len(history) < min_samples:
            logger.debug(f"Insufficient samples for {operation_name}", samples=len(history), required=min_samples)
            return None

        # Calculate baseline statistics
        statistics_result = self._calculate_baseline_statistics(operation_name, history)
        if not statistics_result:
            return None

        # Extract metadata from operation history
        metadata = self._extract_operation_metadata(history)

        # Create baseline
        baseline = PerformanceBaseline(
            operation_name=operation_name,
            repository=metadata.get("repository", "unknown"),
            model=metadata.get("model", "unknown"),
            baseline_duration_ms=statistics_result.duration_mean * 1000,
            baseline_p50_ms=statistics_result.p50 * 1000,
            baseline_p95_ms=statistics_result.p95 * 1000,
            baseline_p99_ms=statistics_result.p99 * 1000,
            sample_size=statistics_result.total_samples,
            confidence_level=self.confidence_level,
            established_date=datetime.now(),
            last_updated=datetime.now(),
            baseline_version="1.0",
            metadata=metadata,
        )

        # Store baseline and statistics
        self.baselines[operation_name] = baseline
        self.baseline_statistics[operation_name] = statistics_result

        logger.info(
            "Baseline established",
            operation=operation_name,
            baseline_duration_ms=baseline.baseline_duration_ms,
            sample_size=baseline.sample_size,
            repository=baseline.repository,
        )

        return baseline

    def _calculate_baseline_statistics(
        self, operation_name: str, history: List[OperationMetrics]
    ) -> Optional[BaselineStatistics]:
        """
        Calculate baseline statistics from operation history.

        Args:
            operation_name: Operation name
            history: Operation history

        Returns:
            Baseline statistics or None if calculation fails
        """
        try:
            # Extract durations
            durations = [op.duration for op in history]

            # Remove outliers using IQR method
            cleaned_durations, outliers_removed = self._remove_outliers(durations)

            if len(cleaned_durations) < self.min_samples_for_baseline // 2:
                logger.warning(
                    f"Too many outliers removed for {operation_name}",
                    original_samples=len(durations),
                    remaining_samples=len(cleaned_durations),
                )
                return None

            # Calculate statistics
            duration_mean = statistics.mean(cleaned_durations)
            duration_median = statistics.median(cleaned_durations)
            duration_std = statistics.stdev(cleaned_durations) if len(cleaned_durations) > 1 else 0.0

            # Calculate percentiles
            sorted_durations = sorted(cleaned_durations)
            p50 = self._calculate_percentile(sorted_durations, 0.50)
            p95 = self._calculate_percentile(sorted_durations, 0.95)
            p99 = self._calculate_percentile(sorted_durations, 0.99)

            # Calculate confidence interval
            confidence_interval = self._calculate_confidence_interval(cleaned_durations, self.confidence_level)

            return BaselineStatistics(
                operation_name=operation_name,
                total_samples=len(cleaned_durations),
                duration_mean=duration_mean,
                duration_median=duration_median,
                duration_std=duration_std,
                p50=p50,
                p95=p95,
                p99=p99,
                min_duration=min(cleaned_durations),
                max_duration=max(cleaned_durations),
                outliers_removed=outliers_removed,
                confidence_interval=confidence_interval,
            )

        except Exception as e:
            logger.error("Failed to calculate baseline statistics", operation=operation_name, error=str(e))
            return None

    def _remove_outliers(self, durations: List[float]) -> Tuple[List[float], int]:
        """
        Remove outliers using the IQR method.

        Args:
            durations: List of duration values

        Returns:
            Tuple of (cleaned_durations, outliers_removed_count)
        """
        if len(durations) < 4:
            return durations, 0

        # Calculate quartiles
        sorted_durations = sorted(durations)
        q1 = self._calculate_percentile(sorted_durations, 0.25)
        q3 = self._calculate_percentile(sorted_durations, 0.75)
        iqr = q3 - q1

        # Define outlier bounds
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        # Filter outliers
        cleaned_durations = [d for d in durations if lower_bound <= d <= upper_bound]

        outliers_removed = len(durations) - len(cleaned_durations)

        return cleaned_durations, outliers_removed

    def _calculate_percentile(self, sorted_values: List[float], percentile: float) -> float:
        """
        Calculate percentile from sorted values.

        Args:
            sorted_values: Sorted list of values
            percentile: Percentile to calculate (0.0 to 1.0)

        Returns:
            Calculated percentile value
        """
        if not sorted_values:
            return 0.0

        index = percentile * (len(sorted_values) - 1)
        lower_index = int(index)
        upper_index = min(lower_index + 1, len(sorted_values) - 1)

        if lower_index == upper_index:
            return sorted_values[lower_index]

        # Linear interpolation
        weight = index - lower_index
        return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight

    def _calculate_confidence_interval(self, values: List[float], confidence_level: float) -> Tuple[float, float]:
        """
        Calculate confidence interval for the mean.

        Args:
            values: List of values
            confidence_level: Confidence level (e.g., 0.95 for 95%)

        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        try:
            import scipy.stats as stats

            mean = statistics.mean(values)
            std_err = statistics.stdev(values) / (len(values) ** 0.5)

            # Calculate t-critical value
            alpha = 1 - confidence_level
            degrees_of_freedom = len(values) - 1
            t_critical = stats.t.ppf(1 - alpha / 2, degrees_of_freedom)

            margin_of_error = t_critical * std_err

            return (mean - margin_of_error, mean + margin_of_error)

        except ImportError:
            # Fallback without scipy
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0.0
            std_err = std / (len(values) ** 0.5)

            # Approximate t-critical for 95% confidence
            t_critical = 1.96 if len(values) > 30 else 2.0
            margin_of_error = t_critical * std_err

            return (mean - margin_of_error, mean + margin_of_error)

    def _extract_operation_metadata(self, history: List[OperationMetrics]) -> Dict[str, Any]:
        """
        Extract metadata from operation history.

        Args:
            history: Operation history

        Returns:
            Extracted metadata
        """
        metadata = {
            "repository": "unknown",
            "model": "unknown",
            "query_type": "unknown",
            "operation_count": len(history),
        }

        if history:
            first_op = history[0]
            metadata.update(first_op.metadata)

            # Add timing information
            metadata.update(
                {
                    "first_execution": datetime.fromtimestamp(first_op.start_time).isoformat(),
                    "last_execution": datetime.fromtimestamp(history[-1].start_time).isoformat(),
                    "total_duration_hours": (history[-1].start_time - first_op.start_time) / 3600,
                }
            )

        return metadata

    async def detect_performance_deviations(
        self, time_window_hours: int = 1, min_recent_samples: int = 5
    ) -> List[PerformanceDeviation]:
        """
        Detect performance deviations from established baselines.

        Args:
            time_window_hours: Time window for recent performance analysis
            min_recent_samples: Minimum recent samples required

        Returns:
            List of detected performance deviations
        """
        logger.info("Detecting performance deviations", time_window_hours=time_window_hours)

        deviations = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=time_window_hours)

        for operation_name, baseline in self.baselines.items():
            try:
                deviation = await self._detect_operation_deviation(
                    operation_name, baseline, cutoff_time, min_recent_samples
                )
                if deviation:
                    deviations.append(deviation)
            except Exception as e:
                logger.error("Failed to detect deviation", operation=operation_name, error=str(e))

        # Sort by severity and deviation percentage
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deviations.sort(key=lambda x: (severity_order.get(x.severity, 4), abs(x.deviation_percentage)), reverse=True)

        logger.info(
            "Performance deviation detection completed",
            total_operations=len(self.baselines),
            deviations_found=len(deviations),
        )

        return deviations

    async def _detect_operation_deviation(
        self, operation_name: str, baseline: PerformanceBaseline, cutoff_time: datetime, min_recent_samples: int
    ) -> Optional[PerformanceDeviation]:
        """
        Detect deviation for a specific operation.

        Args:
            operation_name: Operation name
            baseline: Established baseline
            cutoff_time: Cutoff time for recent samples
            min_recent_samples: Minimum recent samples required

        Returns:
            Performance deviation or None
        """
        # Get recent operation history
        history = self.performance_tracker.get_operation_history(operation_name)
        recent_ops = [op for op in history if datetime.fromtimestamp(op.start_time) >= cutoff_time]

        if len(recent_ops) < min_recent_samples:
            return None

        # Calculate recent performance
        recent_durations = [op.duration for op in recent_ops]
        recent_mean = statistics.mean(recent_durations) * 1000  # Convert to ms

        # Calculate deviation
        baseline_duration = baseline.baseline_duration_ms
        deviation_percentage = ((recent_mean - baseline_duration) / baseline_duration) * 100

        # Determine deviation type and severity
        deviation_type = self._classify_deviation_type(deviation_percentage)
        severity = self._classify_deviation_severity(abs(deviation_percentage))

        return PerformanceDeviation(
            operation_name=operation_name,
            current_duration=recent_mean,
            baseline_duration=baseline_duration,
            deviation_percentage=deviation_percentage,
            deviation_type=deviation_type,
            severity=severity,
            sample_size=len(recent_ops),
            confidence_level=self.confidence_level,
        )

    def _classify_deviation_type(self, deviation_percentage: float) -> str:
        """
        Classify deviation type based on percentage.

        Args:
            deviation_percentage: Deviation percentage

        Returns:
            Deviation type classification
        """
        if deviation_percentage > 10:
            return "regression"
        elif deviation_percentage < -10:
            return "improvement"
        else:
            return "within_normal"

    def _classify_deviation_severity(self, abs_deviation_percentage: float) -> str:
        """
        Classify deviation severity.

        Args:
            abs_deviation_percentage: Absolute deviation percentage

        Returns:
            Severity classification
        """
        if abs_deviation_percentage >= self.deviation_thresholds["critical"] * 100:
            return "critical"
        elif abs_deviation_percentage >= self.deviation_thresholds["high"] * 100:
            return "high"
        elif abs_deviation_percentage >= self.deviation_thresholds["medium"] * 100:
            return "medium"
        else:
            return "low"

    async def update_baseline(
        self, operation_name: str, include_recent_data: bool = True, recent_data_hours: int = 24
    ) -> Optional[PerformanceBaseline]:
        """
        Update an existing baseline with recent data.

        Args:
            operation_name: Operation to update baseline for
            include_recent_data: Whether to include recent data
            recent_data_hours: Hours of recent data to include

        Returns:
            Updated baseline or None if update failed
        """
        if operation_name not in self.baselines:
            logger.warning(f"No existing baseline found for {operation_name}")
            return None

        logger.info(f"Updating baseline for {operation_name}")

        # Get operation history
        history = self.performance_tracker.get_operation_history(operation_name)

        if include_recent_data:
            # Filter to recent data only
            cutoff_time = datetime.now() - timedelta(hours=recent_data_hours)
            history = [op for op in history if datetime.fromtimestamp(op.start_time) >= cutoff_time]

        if len(history) < self.min_samples_for_baseline:
            logger.warning(f"Insufficient data for baseline update", operation=operation_name, samples=len(history))
            return None

        # Recalculate baseline
        updated_baseline = await self._establish_operation_baseline(
            operation_name, force_update=True, min_samples=len(history)
        )

        if updated_baseline:
            updated_baseline.baseline_version = "2.0"  # Increment version
            await self._save_baselines()

            logger.info(
                f"Baseline updated for {operation_name}",
                old_duration_ms=self.baselines[operation_name].baseline_duration_ms,
                new_duration_ms=updated_baseline.baseline_duration_ms,
            )

        return updated_baseline

    def get_baseline(self, operation_name: str) -> Optional[PerformanceBaseline]:
        """
        Get baseline for a specific operation.

        Args:
            operation_name: Operation name

        Returns:
            Performance baseline or None if not found
        """
        return self.baselines.get(operation_name)

    def get_all_baselines(self) -> Dict[str, PerformanceBaseline]:
        """
        Get all established baselines.

        Returns:
            Dictionary of all baselines
        """
        return self.baselines.copy()

    def get_baseline_statistics(self, operation_name: str) -> Optional[BaselineStatistics]:
        """
        Get baseline statistics for an operation.

        Args:
            operation_name: Operation name

        Returns:
            Baseline statistics or None if not found
        """
        return self.baseline_statistics.get(operation_name)

    async def generate_baseline_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive baseline report.

        Returns:
            Baseline report dictionary
        """
        logger.info("Generating baseline report")

        # Detect recent deviations
        deviations = await self.detect_performance_deviations()

        # Calculate summary statistics
        total_baselines = len(self.baselines)
        repositories = set(b.repository for b in self.baselines.values())
        models = set(b.model for b in self.baselines.values())

        # Group baselines by repository
        repository_baselines = defaultdict(list)
        for baseline in self.baselines.values():
            repository_baselines[baseline.repository].append(baseline)

        # Calculate baseline ages
        now = datetime.now()
        baseline_ages = [(now - baseline.established_date).days for baseline in self.baselines.values()]

        report = {
            "generated_at": now.isoformat(),
            "summary": {
                "total_baselines": total_baselines,
                "unique_repositories": len(repositories),
                "unique_models": len(models),
                "recent_deviations": len(deviations),
                "critical_deviations": len([d for d in deviations if d.severity == "critical"]),
                "avg_baseline_age_days": statistics.mean(baseline_ages) if baseline_ages else 0,
            },
            "repository_breakdown": {
                repo: {
                    "baseline_count": len(baselines),
                    "avg_duration_ms": statistics.mean([b.baseline_duration_ms for b in baselines]),
                    "models": list(set(b.model for b in baselines)),
                }
                for repo, baselines in repository_baselines.items()
            },
            "performance_deviations": [asdict(d) for d in deviations[:20]],  # Top 20
            "baseline_details": [asdict(b) for b in self.baselines.values()],
            "configuration": {
                "min_samples_for_baseline": self.min_samples_for_baseline,
                "confidence_level": self.confidence_level,
                "outlier_threshold": self.outlier_threshold,
                "deviation_thresholds": self.deviation_thresholds,
            },
        }

        return report

    async def _save_baselines(self) -> None:
        """Save baselines to persistent storage."""
        try:
            baseline_file = self.baseline_storage_path / "baselines.json"
            statistics_file = self.baseline_storage_path / "statistics.json"

            # Prepare data for serialization
            baseline_data = {name: asdict(baseline) for name, baseline in self.baselines.items()}

            statistics_data = {name: asdict(stats) for name, stats in self.baseline_statistics.items()}

            # Convert datetime objects to ISO strings
            for data in baseline_data.values():
                data["established_date"] = data["established_date"].isoformat()
                data["last_updated"] = data["last_updated"].isoformat()

            # Save files
            with open(baseline_file, "w") as f:
                json.dump(baseline_data, f, indent=2, default=str)

            with open(statistics_file, "w") as f:
                json.dump(statistics_data, f, indent=2, default=str)

            logger.debug(
                "Baselines saved to storage",
                baseline_count=len(self.baselines),
                storage_path=str(self.baseline_storage_path),
            )

        except Exception as e:
            logger.error("Failed to save baselines", error=str(e))

    def _load_baselines(self) -> None:
        """Load baselines from persistent storage."""
        try:
            baseline_file = self.baseline_storage_path / "baselines.json"
            statistics_file = self.baseline_storage_path / "statistics.json"

            # Load baselines
            if baseline_file.exists():
                with open(baseline_file, "r") as f:
                    baseline_data = json.load(f)

                for name, data in baseline_data.items():
                    # Convert ISO strings back to datetime objects
                    data["established_date"] = datetime.fromisoformat(data["established_date"])
                    data["last_updated"] = datetime.fromisoformat(data["last_updated"])

                    self.baselines[name] = PerformanceBaseline(**data)

            # Load statistics
            if statistics_file.exists():
                with open(statistics_file, "r") as f:
                    statistics_data = json.load(f)

                for name, data in statistics_data.items():
                    self.baseline_statistics[name] = BaselineStatistics(**data)

            logger.info(
                "Baselines loaded from storage",
                baseline_count=len(self.baselines),
                statistics_count=len(self.baseline_statistics),
            )

        except Exception as e:
            logger.error("Failed to load baselines", error=str(e))
            # Initialize empty if loading fails
            self.baselines = {}
            self.baseline_statistics = {}
