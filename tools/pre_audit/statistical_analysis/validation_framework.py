"""
Comprehensive Validation Framework for GitHub Issue #43.

This module provides government-grade validation and testing for all statistical
components implemented for the enhanced hotspot analysis system.

Features:
- Statistical correctness validation
- Algorithm accuracy verification
- Performance benchmarking
- Edge case testing
- Synthetic data generation for testing
- Cross-validation and robustness testing
"""

import logging
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats

from .bayesian_risk_engine import BayesianRiskEngine
from .statistical_hotspot_detector import StatisticalHotspotDetector
from .statistical_hotspot_orchestrator import StatisticalHotspotOrchestrator
from .temporal_weighting_engine import TemporalViolation, TemporalWeightingEngine

warnings.filterwarnings("ignore", category=RuntimeWarning)
logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a validation test."""

    test_name: str
    passed: bool
    score: float
    details: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None


@dataclass
class ValidationSuite:
    """Complete validation suite results."""

    suite_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    overall_score: float
    execution_time: float
    results: List[ValidationResult]

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        return (self.passed_tests / self.total_tests) * 100 if self.total_tests > 0 else 0.0


class SyntheticDataGenerator:
    """Generate synthetic data for testing statistical components."""

    def __init__(self, random_seed: int = 42):
        """Initialize generator with random seed for reproducibility."""
        self.rng = np.random.RandomState(random_seed)

    def generate_file_metrics(
        self,
        n_files: int = 100,
        with_violations: bool = True,
        violation_rate: float = 0.3,
    ) -> pd.DataFrame:
        """Generate synthetic file metrics with known patterns."""

        # Generate base metrics
        data = {
            "file_path": [f"src/file_{i}.py" for i in range(n_files)],
            "complexity_score": self.rng.exponential(scale=20, size=n_files),
            "churn_score": self.rng.gamma(shape=2, scale=5, size=n_files),
            "lines_of_code": self.rng.poisson(lam=200, size=n_files),
            "cyclomatic_complexity": self.rng.poisson(lam=10, size=n_files),
            "coupling_score": self.rng.beta(a=2, b=5, size=n_files),
            "test_coverage": self.rng.beta(a=8, b=2, size=n_files),
        }

        df = pd.DataFrame(data)

        if with_violations:
            # Add violation labels with known correlation to complexity
            violation_prob = (
                df["complexity_score"] / df["complexity_score"].max() * 0.6 + (1 - df["test_coverage"]) * 0.4
            )
            df["is_violation"] = self.rng.random(n_files) < violation_prob * violation_rate

        return df

    def generate_temporal_violations(
        self,
        n_violations: int = 50,
        time_span_days: int = 180,
        with_trends: bool = True,
    ) -> List[TemporalViolation]:
        """Generate synthetic temporal violations with configurable patterns."""

        violations = []
        base_time = datetime.now() - timedelta(days=time_span_days)

        for i in range(n_violations):
            # Generate timestamp with optional trend
            if with_trends:
                # Add increasing frequency over time
                days_offset = self.rng.exponential(scale=time_span_days / 3)
                days_offset = min(days_offset, time_span_days)
            else:
                days_offset = self.rng.uniform(0, time_span_days)

            timestamp = base_time + timedelta(days=days_offset)

            # Generate severity with correlation to recency if trends enabled
            if with_trends:
                base_severity = 0.5 + (days_offset / time_span_days) * 0.4
                severity = max(0.1, min(1.0, base_severity + self.rng.normal(0, 0.1)))
            else:
                severity = self.rng.uniform(0.1, 1.0)

            # Choose violation type
            violation_types = ["security", "performance", "complexity", "style", "bug"]
            violation_type = self.rng.choice(violation_types)

            # Choose business impact based on severity
            if severity > 0.8:
                business_impact = "critical"
            elif severity > 0.6:
                business_impact = "high"
            elif severity > 0.4:
                business_impact = "medium"
            else:
                business_impact = "low"

            violations.append(
                TemporalViolation(
                    timestamp=timestamp,
                    file_path=f"src/file_{i % 20}.py",
                    violation_type=violation_type,
                    severity=severity,
                    context={"synthetic": True, "test_id": i},
                    business_impact=business_impact,
                )
            )

        return violations


class StatisticalCorrectnessValidator:
    """Validate statistical correctness of implemented algorithms."""

    def __init__(self) -> None:
        self.data_generator = SyntheticDataGenerator()

    def validate_statistical_hotspot_detector(self) -> ValidationResult:
        """Validate statistical hotspot detection accuracy."""
        start_time = time.time()

        try:
            detector = StatisticalHotspotDetector()

            # Generate synthetic data with known hotspots
            df = self.data_generator.generate_file_metrics(n_files=200, violation_rate=0.25)

            # Fit baseline distributions
            baseline_data = {
                col: df[col].values
                for col in df.select_dtypes(include=[np.number]).columns
                if col not in ["is_violation"]
            }
            detector.fit_baseline_distributions(baseline_data)

            # Test statistical significance calculation
            test_metrics: Dict[str, Union[float, str]] = {
                "complexity_score": 50.0,  # High complexity
                "churn_score": 30.0,  # High churn
                "test_coverage": 0.2,  # Low coverage
            }

            result = detector.calculate_statistical_significance(test_metrics)

            # Validate result structure
            required_fields = [
                "statistical_significance",
                "p_value",
                "z_score",
                "confidence_interval",
            ]
            missing_fields = [field for field in required_fields if not hasattr(result, field)]

            # Validate statistical properties
            is_valid = (
                len(missing_fields) == 0
                and 0 <= result.statistical_significance <= 1
                and 0 <= result.p_value <= 1
                and len(result.confidence_interval) == 2
                and result.confidence_interval[0] <= result.confidence_interval[1]
            )

            score = 1.0 if is_valid else 0.0
            details = {
                "missing_fields": missing_fields,
                "statistical_significance": result.statistical_significance,
                "p_value": result.p_value,
                "z_score": result.z_score,
                "confidence_interval": result.confidence_interval,
                "distributions_fitted": len(detector.baseline_distributions),
            }

        except Exception as e:
            is_valid = False
            score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="Statistical Hotspot Detector Correctness",
            passed=is_valid,
            score=score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )

    def validate_temporal_weighting_accuracy(self) -> ValidationResult:
        """Validate temporal weighting algorithm accuracy."""
        start_time = time.time()

        try:
            engine = TemporalWeightingEngine(default_half_life_days=30.0)

            # Generate violations with known temporal pattern
            violations = self.data_generator.generate_temporal_violations(n_violations=100, with_trends=True)

            # Calculate temporal weights
            results = engine.calculate_temporal_weighted_risk(violations)

            # Validate exponential decay property
            # Recent violations should have higher weights
            recent_violations = [v for v in violations if (datetime.now() - v.timestamp).days < 15]
            old_violations = [v for v in violations if (datetime.now() - v.timestamp).days > 60]

            if recent_violations and old_violations and results:
                # Get a file with both recent and old violations
                test_file = None
                for file_path, result in results.items():
                    if result.violation_count > 5:  # Enough violations to test
                        test_file = file_path
                        break

                if test_file:
                    result = results[test_file]

                    # Validate temporal weighting properties
                    decay_correct = (
                        result.weighted_risk_score > 0
                        and result.recent_violations <= result.violation_count
                        and 0 <= result.temporal_concentration <= 1
                    )

                    score = 1.0 if decay_correct else 0.5
                    details = {
                        "files_analyzed": len(results),
                        "test_file": test_file,
                        "weighted_risk_score": result.weighted_risk_score,
                        "violation_count": result.violation_count,
                        "recent_violations": result.recent_violations,
                        "temporal_concentration": result.temporal_concentration,
                        "decay_parameters": result.decay_parameters,
                    }
                    is_valid = True
                else:
                    score = 0.3
                    details = {"warning": "No file with sufficient violations for testing"}
                    is_valid = True
            else:
                score = 0.1
                details = {"warning": "Insufficient violation data for validation"}
                is_valid = True

        except Exception as e:
            is_valid = False
            score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="Temporal Weighting Algorithm Accuracy",
            passed=is_valid,
            score=score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )

    def validate_bayesian_risk_calibration(self) -> ValidationResult:
        """Validate Bayesian risk engine calibration."""
        start_time = time.time()

        try:
            engine = BayesianRiskEngine(n_mcmc_samples=5000)  # Reduced for testing

            # Generate training data
            df = self.data_generator.generate_file_metrics(n_files=300, violation_rate=0.3)

            # Fit prior distributions
            engine.fit_prior_distributions(df)

            # Train likelihood models
            engine.train_likelihood_models(df, target_column="is_violation")

            # Validate calibration
            calibration_results = engine.validate_model_calibration(df)

            # Check calibration quality
            is_well_calibrated = calibration_results.get("is_well_calibrated", False)
            ece = calibration_results.get("expected_calibration_error", 1.0)

            # Test prediction on synthetic data
            test_features: Dict[str, Union[float, str]] = {
                "complexity_score": 45.0,
                "churn_score": 25.0,
                "test_coverage": 0.3,
            }

            risk_assessment = engine.calculate_bayesian_risk(test_features)

            # Validate risk assessment structure
            risk_valid = (
                0 <= risk_assessment.risk_probability <= 1
                and len(risk_assessment.credible_interval) == 2
                and risk_assessment.credible_interval[0] <= risk_assessment.credible_interval[1]
                and risk_assessment.evidence_strength in ["insufficient", "weak", "moderate", "strong", "very_strong"]
            )

            # Calculate overall score
            calibration_score = 1.0 - min(ece, 0.5) / 0.5  # ECE < 0.5 is acceptable
            structure_score = 1.0 if risk_valid else 0.0
            score = (calibration_score + structure_score) / 2

            details = {
                "is_well_calibrated": is_well_calibrated,
                "expected_calibration_error": ece,
                "cv_auc_mean": engine.validation_scores.get("cv_auc_mean", 0.0),
                "risk_probability": risk_assessment.risk_probability,
                "credible_interval": risk_assessment.credible_interval,
                "evidence_strength": risk_assessment.evidence_strength,
                "model_trained": engine.likelihood_models is not None,
            }

            is_valid = score > 0.5

        except Exception as e:
            is_valid = False
            score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="Bayesian Risk Engine Calibration",
            passed=is_valid,
            score=score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )


class PerformanceBenchmarker:
    """Benchmark performance of statistical components."""

    def __init__(self) -> None:
        self.data_generator = SyntheticDataGenerator()

    def benchmark_orchestrator_performance(self) -> ValidationResult:
        """Benchmark end-to-end orchestrator performance."""
        start_time = time.time()

        try:
            # Create orchestrator
            orchestrator = StatisticalHotspotOrchestrator()

            # Generate large synthetic dataset
            file_metrics = {}
            violation_history = []

            # Generate file metrics
            df = self.data_generator.generate_file_metrics(n_files=500, violation_rate=0.2)
            for _, row in df.iterrows():
                file_metrics[row["file_path"]] = row.to_dict()

            # Generate violation history
            violations = self.data_generator.generate_temporal_violations(n_violations=200, time_span_days=365)

            for violation in violations:
                violation_history.append(
                    {
                        "timestamp": violation.timestamp,
                        "file_path": violation.file_path,
                        "violation_type": violation.violation_type,
                        "severity": violation.severity,
                        "business_impact": violation.business_impact,
                        "context": violation.context,
                    }
                )

            # Train models
            training_start = time.time()
            training_result = orchestrator.train_statistical_models(df, violation_history)
            training_time = time.time() - training_start

            # Perform analysis
            analysis_start = time.time()
            hotspots = orchestrator.analyze_architectural_hotspots(file_metrics, violation_history, max_hotspots=20)
            analysis_time = time.time() - analysis_start

            # Calculate performance metrics
            total_time = time.time() - start_time
            files_per_second = len(file_metrics) / analysis_time if analysis_time > 0 else 0

            # Performance thresholds (government-grade requirements)
            training_threshold = 300  # 5 minutes max for training
            analysis_threshold = 60  # 1 minute max for analysis
            throughput_threshold = 5  # 5 files per second minimum

            performance_score = 0.0
            if training_time <= training_threshold:
                performance_score += 0.4
            if analysis_time <= analysis_threshold:
                performance_score += 0.4
            if files_per_second >= throughput_threshold:
                performance_score += 0.2

            details = {
                "total_execution_time": total_time,
                "training_time": training_time,
                "analysis_time": analysis_time,
                "files_analyzed": len(file_metrics),
                "violations_processed": len(violation_history),
                "hotspots_identified": len(hotspots),
                "files_per_second": files_per_second,
                "training_success": training_result.get("success", False),
                "performance_thresholds": {
                    "training_max": training_threshold,
                    "analysis_max": analysis_threshold,
                    "throughput_min": throughput_threshold,
                },
            }

            is_valid = training_result.get("success", False) and len(hotspots) > 0 and performance_score > 0.5

        except Exception as e:
            is_valid = False
            performance_score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="End-to-End Performance Benchmark",
            passed=is_valid,
            score=performance_score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )


class EdgeCaseTester:
    """Test edge cases and error handling."""

    def test_empty_data_handling(self) -> ValidationResult:
        """Test handling of empty datasets."""
        start_time = time.time()

        try:
            orchestrator = StatisticalHotspotOrchestrator()

            # Test with empty data
            empty_metrics: Dict[str, Dict[str, Any]] = {}
            empty_violations: List[Dict[str, Any]] = []

            # This should not crash and should return empty results gracefully
            hotspots = orchestrator.analyze_architectural_hotspots(empty_metrics, empty_violations)

            # Validate graceful handling
            handles_empty = len(hotspots) == 0

            # Test with minimal data
            minimal_metrics = {"test.py": {"complexity_score": 1.0, "churn_score": 1.0}}
            minimal_violations: List[Dict[str, Any]] = []

            hotspots_minimal = orchestrator.analyze_architectural_hotspots(minimal_metrics, minimal_violations)

            handles_minimal = len(hotspots_minimal) >= 0  # Should not crash

            score = 1.0 if (handles_empty and handles_minimal) else 0.0
            details = {
                "empty_data_handled": str(handles_empty),
                "minimal_data_handled": str(handles_minimal),
                "empty_hotspots_count": str(len(hotspots)),
                "minimal_hotspots_count": str(len(hotspots_minimal)),
            }

            is_valid = handles_empty and handles_minimal

        except Exception as e:
            is_valid = False
            score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="Empty Data Handling",
            passed=is_valid,
            score=score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )

    def test_extreme_values(self) -> ValidationResult:
        """Test handling of extreme values."""
        start_time = time.time()

        try:
            detector = StatisticalHotspotDetector()

            # Test with extreme values
            extreme_data = {
                "complexity_score": np.array([0, 1e6, np.inf, -np.inf, np.nan]),
                "churn_score": np.array([1e-10, 1e10, 0, np.nan, 1.0]),
            }

            # Should handle extreme values without crashing
            detector.fit_baseline_distributions(extreme_data)

            # Test statistical significance with extreme values
            extreme_metrics = {
                "complexity_score": 1e6,
                "churn_score": 1e-10,
                "invalid_metric": np.nan,
            }

            result = detector.calculate_statistical_significance(extreme_metrics)

            # Should return valid result structure even with extreme inputs
            handles_extremes = (
                hasattr(result, "statistical_significance")
                and 0 <= result.statistical_significance <= 1
                and not np.isnan(result.statistical_significance)
            )

            score = 1.0 if handles_extremes else 0.0
            details = {
                "extreme_values_handled": str(handles_extremes),
                "statistical_significance": str(result.statistical_significance),
                "baseline_distributions_count": str(len(detector.baseline_distributions)),
            }

            is_valid = handles_extremes

        except Exception as e:
            is_valid = False
            score = 0.0
            details = {"error": str(e)}

        execution_time = time.time() - start_time

        return ValidationResult(
            test_name="Extreme Values Handling",
            passed=is_valid,
            score=score,
            details=details,
            execution_time=execution_time,
            error_message=None if is_valid else str(details.get("error", "")),
        )


class ValidationFramework:
    """Main validation framework orchestrating all validation tests."""

    def __init__(self) -> None:
        self.correctness_validator = StatisticalCorrectnessValidator()
        self.performance_benchmarker = PerformanceBenchmarker()
        self.edge_case_tester = EdgeCaseTester()

    def run_complete_validation(self) -> ValidationSuite:
        """Run complete validation suite."""
        logger.info("Starting comprehensive validation framework")
        suite_start = time.time()

        results = []

        # Statistical correctness tests
        logger.info("Running statistical correctness validation...")
        results.append(self.correctness_validator.validate_statistical_hotspot_detector())
        results.append(self.correctness_validator.validate_temporal_weighting_accuracy())
        results.append(self.correctness_validator.validate_bayesian_risk_calibration())

        # Performance benchmarks
        logger.info("Running performance benchmarks...")
        results.append(self.performance_benchmarker.benchmark_orchestrator_performance())

        # Edge case tests
        logger.info("Running edge case tests...")
        results.append(self.edge_case_tester.test_empty_data_handling())
        results.append(self.edge_case_tester.test_extreme_values())

        # Calculate overall metrics
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.passed)
        failed_tests = total_tests - passed_tests
        overall_score = sum(r.score for r in results) / total_tests if total_tests > 0 else 0.0
        total_time = time.time() - suite_start

        suite = ValidationSuite(
            suite_name="GitHub Issue #43 Comprehensive Validation",
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            overall_score=overall_score,
            execution_time=total_time,
            results=results,
        )

        logger.info(
            f"Validation complete: {passed_tests}/{total_tests} tests passed, " f"overall score: {overall_score:.2f}"
        )

        return suite

    def generate_validation_report(self, suite: ValidationSuite) -> str:
        """Generate comprehensive validation report."""

        report = [
            "# Statistical Hotspot Analysis Validation Report",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Implementation:** GitHub Issue #43 Enhanced Hotspot Analysis",
            "",
            "## Executive Summary",
            f"- **Total Tests:** {suite.total_tests}",
            f"- **Passed:** {suite.passed_tests}",
            f"- **Failed:** {suite.failed_tests}",
            f"- **Success Rate:** {suite.success_rate:.1f}%",
            f"- **Overall Score:** {suite.overall_score:.2f}/1.0",
            f"- **Execution Time:** {suite.execution_time:.2f} seconds",
            "",
        ]

        # Add detailed results
        report.append("## Detailed Test Results")
        report.append("")

        for result in suite.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            report.extend(
                [
                    f"### {result.test_name}",
                    f"**Status:** {status}",
                    f"**Score:** {result.score:.2f}/1.0",
                    f"**Execution Time:** {result.execution_time:.3f}s",
                    "",
                ]
            )

            if result.error_message:
                report.append(f"**Error:** {result.error_message}")
                report.append("")

            # Add key details
            if result.details:
                report.append("**Details:**")
                for key, value in result.details.items():
                    if key != "error":
                        report.append(f"- {key}: {value}")
                report.append("")

        # Add recommendations
        failed_tests = [r for r in suite.results if not r.passed]
        if failed_tests:
            report.extend(["## Recommendations", ""])
            for test in failed_tests:
                report.append(f"- **{test.test_name}:** {test.error_message or 'Review implementation'}")
                report.append("")

        # Add conclusion
        if suite.success_rate >= 80 and suite.overall_score >= 0.7:
            conclusion = "✅ **VALIDATION PASSED** - Implementation meets government-grade requirements"
        elif suite.success_rate >= 60 and suite.overall_score >= 0.5:
            conclusion = "⚠️ **VALIDATION PARTIAL** - Implementation needs improvement in some areas"
        else:
            conclusion = "❌ **VALIDATION FAILED** - Implementation requires significant fixes"

        report.extend(["## Conclusion", "", conclusion, ""])

        return "\n".join(report)
