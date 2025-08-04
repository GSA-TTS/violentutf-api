"""
Statistical Hotspot Orchestrator for GitHub Issue #43.

Comprehensive orchestrator integrating all statistical components to replace inadequate hotspot analysis.

This module replaces the current inadequate implementation:
- Line 1835: hotspots.sort(key=lambda h: h.churn_score * h.complexity_score, reverse=True)
- Lines 1920-1927: Hard-coded thresholds in _assess_hotspot_risk_level

Implements government-grade statistical hotspot analysis with proper:
- Statistical significance testing
- Temporal weighting with exponential decay
- Bayesian risk assessment with uncertainty quantification
- Comprehensive feature engineering with domain knowledge
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Scientific computing dependencies with graceful degradation
try:
    import numpy as np
    import pandas as pd

    HAS_SCIENTIFIC_DEPS = True
except ImportError:
    HAS_SCIENTIFIC_DEPS = False
    # Create dummy modules for type checking
    np = None
    pd = None

import yaml

from .adaptive_threshold_learner import AdaptiveThresholdLearner, ThresholdOptimizationResult
from .advanced_feature_engineer import AdvancedFeatureEngineer, FeatureEngineeringResult
from .bayesian_risk_engine import BayesianRiskAssessment, BayesianRiskEngine
from .git_temporal_integration import GitTemporalAnalysisResult, GitTemporalIntegrator

# Import all statistical components
from .statistical_hotspot_detector import StatisticalHotspotDetector, StatisticalHotspotResult
from .statistical_normalizer import NormalizationParams, StatisticalNormalizer
from .temporal_weighting_engine import (
    TemporalViolation,
    TemporalWeightingEngine,
    TemporalWeightingResult,
)
from .time_series_trend_analyzer import TimeSeriesTrendAnalyzer, TrendAnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class EnhancedArchitecturalHotspot:
    """
    Enhanced architectural hotspot with comprehensive statistical assessment.

    Replaces the simple ArchitecturalHotspot with government-grade analysis.
    """

    file_path: str

    # Statistical assessment results
    statistical_significance: StatisticalHotspotResult
    temporal_assessment: TemporalWeightingResult
    bayesian_risk: BayesianRiskAssessment

    # Traditional metrics (for compatibility)
    churn_score: float
    complexity_score: float

    # Enhanced risk assessment
    integrated_risk_probability: float
    risk_confidence_interval: Tuple[float, float]
    risk_evidence_strength: str

    # Feature contributions for interpretability
    feature_contributions: Dict[str, float]

    # Temporal context
    violation_history: List[str]
    temporal_patterns: Dict[str, Any]

    # Metadata
    analysis_timestamp: datetime
    model_version: str

    # Git temporal analysis (optional)
    git_temporal_analysis: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "statistical_significance": self.statistical_significance.to_dict(),
            "temporal_assessment": self.temporal_assessment.to_dict(),
            "bayesian_risk": self.bayesian_risk.to_dict(),
            "churn_score": self.churn_score,
            "complexity_score": self.complexity_score,
            "integrated_risk_probability": self.integrated_risk_probability,
            "risk_confidence_interval": list(self.risk_confidence_interval),
            "risk_evidence_strength": self.risk_evidence_strength,
            "feature_contributions": self.feature_contributions,
            "violation_history": self.violation_history,
            "temporal_patterns": self.temporal_patterns,
            "git_temporal_analysis": (self.git_temporal_analysis.to_dict() if self.git_temporal_analysis else None),
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "model_version": self.model_version,
        }


class StatisticalHotspotOrchestrator:
    """
    Comprehensive statistical hotspot orchestrator implementing GitHub issue #43 requirements.

    Orchestrates all statistical components to provide government-grade hotspot analysis:
    1. Statistical significance testing (Phase 1)
    2. Temporal weighting with exponential decay (Phase 2)
    3. Bayesian risk assessment with uncertainty quantification (Phase 3)
    4. Comprehensive validation and testing (Phase 4)

    Replaces inadequate current implementation with statistically rigorous analysis.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize statistical hotspot orchestrator.

        Args:
            config_path: Path to YAML configuration file
        """
        # Load configuration
        self.config = self._load_configuration(config_path)

        # Initialize statistical components
        self.statistical_detector = StatisticalHotspotDetector(
            significance_level=self.config["statistical_detection"]["significance_level"],
            confidence_level=self.config["statistical_detection"]["confidence_level"],
            bootstrap_samples=self.config["statistical_detection"]["bootstrap_samples"],
        )

        self.threshold_learner = AdaptiveThresholdLearner(
            cross_validation_folds=self.config["statistical_detection"]["cross_validation_folds"]
        )

        self.normalizer = StatisticalNormalizer(default_method=self.config["normalization"]["default_method"])

        self.temporal_engine = TemporalWeightingEngine(
            default_half_life_days=self.config["temporal_weighting"]["default_half_life_days"],
            max_age_days=self.config["temporal_weighting"]["max_age_days"],
            business_multipliers=self.config["temporal_weighting"]["business_multipliers"],
        )

        self.trend_analyzer = TimeSeriesTrendAnalyzer(
            anomaly_threshold=self.config["temporal_weighting"]["anomaly_detection"]["threshold_sigma"],
            min_observations=self.config["temporal_weighting"]["anomaly_detection"]["min_observations"],
        )

        self.bayesian_engine = BayesianRiskEngine(
            n_mcmc_samples=self.config["bayesian_risk"]["mcmc_samples"],
            credible_interval_level=self.config["bayesian_risk"]["credible_interval_level"],
            calibration_threshold=self.config["bayesian_risk"]["calibration_threshold"],
        )

        self.feature_engineer = AdvancedFeatureEngineer(
            enable_domain_features=self.config["feature_engineering"]["enable_domain_features"],
            enable_interaction_features=self.config["feature_engineering"]["enable_interaction_features"],
            enable_temporal_features=self.config["feature_engineering"]["enable_temporal_features"],
        )

        # Initialize git temporal integrator (optional based on repository availability)
        self.git_integrator: Optional[GitTemporalIntegrator] = None
        try:
            repo_path = self.config.get("git_integration", {}).get("repo_path", ".")
            self.git_integrator = GitTemporalIntegrator(
                repo_path=repo_path,
                half_life_days=self.config["temporal_weighting"]["default_half_life_days"],
                min_confidence_threshold=self.config.get("git_integration", {}).get("min_confidence", 0.6),
                max_history_months=self.config.get("git_integration", {}).get("max_history_months", 12),
            )
            self.git_integration_available = True
        except Exception as e:
            logger.info(f"Git integration not available: {e}")
            self.git_integrator = None
            self.git_integration_available = False

        # Model state
        self.is_trained = False
        self.model_version = "1.0.0"
        self.training_history: List[Dict[str, Any]] = []

        logger.info("Initialized StatisticalHotspotOrchestrator with comprehensive statistical analysis")

    def _load_configuration(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            # Use default configuration path
            current_dir = Path(__file__).parent
            config_path = str(current_dir / "../config/hotspot_analysis_config.yaml")

        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config or {}
        except Exception as e:
            logger.warning(f"Failed to load configuration from {config_path}: {str(e)}")
            # Return minimal default configuration
            return self._get_default_configuration()

    def _get_default_configuration(self) -> Dict[str, Any]:
        """Get default configuration if YAML loading fails."""
        return {
            "statistical_detection": {
                "significance_level": 0.05,
                "confidence_level": 0.95,
                "bootstrap_samples": 1000,
                "cross_validation_folds": 5,
            },
            "temporal_weighting": {
                "default_half_life_days": 30,
                "max_age_days": 365,
                "business_multipliers": {
                    "critical": 2.0,
                    "high": 1.5,
                    "security": 1.3,
                    "medium": 1.0,
                    "low": 0.7,
                },
                "anomaly_detection": {"threshold_sigma": 2.5, "min_observations": 30},
            },
            "bayesian_risk": {
                "mcmc_samples": 10000,
                "credible_interval_level": 0.95,
                "calibration_threshold": 0.1,
            },
            "feature_engineering": {
                "enable_domain_features": True,
                "enable_interaction_features": True,
                "enable_temporal_features": True,
            },
            "normalization": {"default_method": "robust_z_score"},
        }

    def train_statistical_models(
        self, historical_data: pd.DataFrame, violation_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Train all statistical models using historical data.

        This method must be called before performing hotspot analysis.
        It trains all components to learn from historical patterns.

        Args:
            historical_data: DataFrame with historical file metrics and violations
            violation_history: List of historical violations with timestamps

        Returns:
            Training summary with performance metrics
        """
        logger.info("Training comprehensive statistical models for hotspot analysis")

        training_start = datetime.now()
        training_results = {}

        try:
            # 1. Train statistical hotspot detector
            logger.info("Training statistical hotspot detector...")
            self.statistical_detector.fit_baseline_distributions(
                {
                    col: historical_data[col].dropna().values
                    for col in historical_data.select_dtypes(include=[np.number]).columns
                    if col not in ["is_violation", "timestamp"]
                }
            )
            training_results["statistical_detector"] = {"status": "success"}

            # 2. Train adaptive threshold learner
            logger.info("Training adaptive threshold learner...")
            if "is_violation" in historical_data.columns:
                threshold_results = self.threshold_learner.learn_optimal_thresholds(
                    historical_data, target_column="is_violation"
                )
                training_results["threshold_learner"] = {
                    "status": "success",
                    "n_thresholds_learned": str(len(threshold_results)),
                }

            # 3. Train statistical normalizer
            logger.info("Training statistical normalizer...")
            normalization_results = self.normalizer.fit_normalization_parameters(historical_data)
            training_results["normalizer"] = {
                "status": "success",
                "n_features_normalized": str(len(normalization_results)),
            }

            # 4. Train temporal weighting engine
            logger.info("Training temporal weighting engine...")
            if violation_history:
                temporal_violations = [
                    TemporalViolation(
                        timestamp=(
                            datetime.fromisoformat(v["timestamp"])
                            if isinstance(v["timestamp"], str)
                            else v["timestamp"]
                        ),
                        file_path=v["file_path"],
                        violation_type=v.get("violation_type", "unknown"),
                        severity=float(v.get("severity", 1.0)),
                        context=v.get("context", {}),
                        business_impact=v.get("business_impact", "medium"),
                    )
                    for v in violation_history
                ]

                optimization_results = self.temporal_engine.optimize_decay_parameters(temporal_violations)
                training_results["temporal_engine"] = {
                    "status": "success",
                    "optimal_half_life": str(optimization_results["optimal_half_life"]),
                    "optimization_score": str(optimization_results["optimization_score"]),
                }

            # 5. Train Bayesian risk engine
            logger.info("Training Bayesian risk engine...")
            if "is_violation" in historical_data.columns:
                # Fit prior distributions
                self.bayesian_engine.fit_prior_distributions(historical_data)

                # Train likelihood models
                self.bayesian_engine.train_likelihood_models(historical_data, target_column="is_violation")

                # Validate calibration
                calibration_results = self.bayesian_engine.validate_model_calibration(historical_data)

                training_results["bayesian_engine"] = {
                    "status": "success",
                    "cv_auc_mean": str(self.bayesian_engine.validation_scores.get("cv_auc_mean", 0.0)),
                    "expected_calibration_error": str(calibration_results.get("expected_calibration_error", 1.0)),
                    "is_well_calibrated": str(calibration_results.get("is_well_calibrated", False)),
                }

            self.is_trained = True
            training_duration = (datetime.now() - training_start).total_seconds()

            # Record training history
            training_record = {
                "timestamp": training_start,
                "duration_seconds": training_duration,
                "n_training_samples": len(historical_data),
                "n_violation_history": len(violation_history),
                "training_results": training_results,
                "model_version": self.model_version,
            }
            self.training_history.append(training_record)

            logger.info(f"Statistical model training completed in {training_duration:.1f} seconds")

            return {
                "success": True,
                "training_duration": training_duration,
                "training_results": training_results,
                "model_version": self.model_version,
            }

        except Exception as e:
            logger.error(f"Statistical model training failed: {str(e)}")
            return {"success": False, "error": str(e), "training_results": training_results}

    def analyze_architectural_hotspots(
        self,
        file_metrics: Dict[str, Dict[str, Any]],
        violation_history: List[Dict[str, Any]],
        max_hotspots: int = 10,
    ) -> List[EnhancedArchitecturalHotspot]:
        """
        Comprehensive statistical hotspot analysis replacing inadequate current implementation.

        This method replaces:
        - hotspots.sort(key=lambda h: h.churn_score * h.complexity_score, reverse=True)
        - Hard-coded thresholds in _assess_hotspot_risk_level

        Args:
            file_metrics: Dictionary mapping file paths to their metrics
            violation_history: Historical violation data with timestamps
            max_hotspots: Maximum number of hotspots to return

        Returns:
            List of EnhancedArchitecturalHotspot with comprehensive statistical assessment
        """
        if not self.is_trained:
            raise ValueError(
                "Statistical models must be trained before analysis. Call train_statistical_models() first."
            )

        logger.info(f"Performing comprehensive statistical hotspot analysis for {len(file_metrics)} files")

        enhanced_hotspots = []

        # Convert violation history to temporal violations
        temporal_violations = self._convert_to_temporal_violations(violation_history)

        # Group violations by file path for temporal analysis
        file_violations: Dict[str, List[TemporalViolation]] = {}
        for violation in temporal_violations:
            if violation.file_path not in file_violations:
                file_violations[violation.file_path] = []
            file_violations[violation.file_path].append(violation)

        # Analyze each file
        for file_path, metrics in file_metrics.items():
            try:
                enhanced_hotspot = self._analyze_single_file_comprehensive(
                    file_path, metrics, file_violations.get(file_path, [])
                )
                enhanced_hotspots.append(enhanced_hotspot)

            except Exception as e:
                logger.warning(f"Failed to analyze {file_path}: {str(e)}")
                continue

        # Sort by integrated risk probability (replacing simple multiplication)
        enhanced_hotspots.sort(key=lambda h: h.integrated_risk_probability, reverse=True)

        # Return top hotspots
        top_hotspots = enhanced_hotspots[:max_hotspots]

        logger.info(f"Identified {len(top_hotspots)} top architectural hotspots using statistical analysis")

        return top_hotspots

    def _convert_to_temporal_violations(self, violation_history: List[Dict[str, Any]]) -> List[TemporalViolation]:
        """Convert raw violation history to TemporalViolation objects."""
        temporal_violations = []

        for violation in violation_history:
            try:
                # Parse timestamp
                if isinstance(violation.get("timestamp"), str):
                    timestamp = datetime.fromisoformat(violation["timestamp"])
                elif isinstance(violation.get("timestamp"), datetime):
                    timestamp = violation["timestamp"]
                else:
                    timestamp = datetime.now()  # Fallback

                temporal_violation = TemporalViolation(
                    timestamp=timestamp,
                    file_path=violation.get("file_path", "unknown"),
                    violation_type=violation.get("violation_type", "unknown"),
                    severity=float(violation.get("severity", 1.0)),
                    context=violation.get("context", {}),
                    business_impact=violation.get("business_impact", "medium"),
                )

                temporal_violations.append(temporal_violation)

            except Exception as e:
                logger.debug(f"Failed to convert violation to temporal format: {str(e)}")
                continue

        return temporal_violations

    def _analyze_single_file_comprehensive(
        self, file_path: str, metrics: Dict[str, Any], file_violations: List[TemporalViolation]
    ) -> EnhancedArchitecturalHotspot:
        """
        Comprehensive statistical analysis for a single file.

        Integrates all statistical components to provide government-grade assessment.
        """
        analysis_timestamp = datetime.now()

        # 1. Statistical significance testing
        file_metrics_with_path = {**metrics, "file_path": file_path}
        statistical_result = self.statistical_detector.calculate_statistical_significance(file_metrics_with_path)

        # 2. Temporal weighting analysis
        if file_violations:
            temporal_results = self.temporal_engine.calculate_temporal_weighted_risk(
                file_violations, current_time=analysis_timestamp
            )
            temporal_assessment = temporal_results.get(file_path)
        else:
            # Create default temporal assessment for files without violations
            temporal_assessment = TemporalWeightingResult(
                file_path=file_path,
                weighted_risk_score=0.0,
                violation_count=0,
                age_range_days=0,
                temporal_concentration=0.0,
                recent_violations=0,
                decay_parameters={"method": "exponential", "half_life": 30.0},
                metadata={},
            )

        # 3. Advanced feature engineering
        # Ensure temporal_assessment is not None (should always be set by this point)
        assert temporal_assessment is not None
        temporal_context = {
            "violation_count": temporal_assessment.violation_count,
            "temporal_concentration": temporal_assessment.temporal_concentration,
            "recent_violations": temporal_assessment.recent_violations,
            "age_range_days": temporal_assessment.age_range_days,
        }

        business_context = metrics.get("business_context", {})

        feature_result = self.feature_engineer.engineer_comprehensive_features(
            raw_metrics=metrics,
            temporal_context=temporal_context,
            business_context=business_context,
        )

        # 4. Git temporal analysis (if available)
        git_temporal_analysis = None
        if self.git_integration_available and self.git_integrator:
            try:
                # Convert file violations to violation history format for git integrator
                violation_history_data = []
                for violation in file_violations:
                    violation_history_data.append(
                        {
                            "timestamp": violation.timestamp,
                            "severity": violation.severity,
                            "type": violation.violation_type,
                            "message": violation.context.get("message", ""),
                            "business_impact": violation.business_impact,
                            "context": violation.context,
                        }
                    )

                git_temporal_analysis = self.git_integrator.analyze_file_temporal_patterns(
                    file_path, violation_history_data
                )
            except Exception as e:
                logger.debug(f"Git temporal analysis failed for {file_path}: {e}")

        # 5. Bayesian risk assessment
        # Ensure the features dict has the right type
        features_dict: Dict[str, Union[float, str]] = {k: v for k, v in feature_result.engineered_features.items()}
        bayesian_assessment = self.bayesian_engine.calculate_bayesian_risk(
            features_dict,
            historical_context={"temporal_assessment": temporal_assessment},
        )

        # 6. Integrate all assessments into final risk probability
        integrated_risk_probability = self._integrate_risk_assessments(
            statistical_result, temporal_assessment, bayesian_assessment, git_temporal_analysis
        )

        # 7. Determine risk confidence interval
        risk_confidence_interval = self._calculate_integrated_confidence_interval(
            statistical_result, bayesian_assessment
        )

        # 8. Assess overall evidence strength
        evidence_strength = self._assess_integrated_evidence_strength(statistical_result, bayesian_assessment)

        # Extract traditional metrics for compatibility
        churn_score = float(metrics.get("churn_score", 0.0))
        complexity_score = float(metrics.get("complexity_score", 0.0))

        # Create violation history summary (temporal_assessment already asserted to not be None)
        violation_history = [
            f"Temporal violations: {temporal_assessment.violation_count}",
            f"Recent violations (30d): {temporal_assessment.recent_violations}",
            f"Weighted risk score: {temporal_assessment.weighted_risk_score:.2f}",
            f"Statistical significance: {statistical_result.statistical_significance}",
        ]

        # Temporal patterns summary
        temporal_patterns = {
            "temporal_concentration": temporal_assessment.temporal_concentration,
            "age_range_days": temporal_assessment.age_range_days,
            "statistical_significance": statistical_result.statistical_significance,
            "trend_detected": statistical_result.z_score > 2.0,
        }

        return EnhancedArchitecturalHotspot(
            file_path=file_path,
            statistical_significance=statistical_result,
            temporal_assessment=temporal_assessment,
            bayesian_risk=bayesian_assessment,
            churn_score=churn_score,
            complexity_score=complexity_score,
            integrated_risk_probability=integrated_risk_probability,
            risk_confidence_interval=risk_confidence_interval,
            risk_evidence_strength=evidence_strength,
            feature_contributions=bayesian_assessment.feature_contributions,
            violation_history=violation_history,
            temporal_patterns=temporal_patterns,
            git_temporal_analysis=git_temporal_analysis,
            analysis_timestamp=analysis_timestamp,
            model_version=self.model_version,
        )

    def _integrate_risk_assessments(
        self,
        statistical_result: StatisticalHotspotResult,
        temporal_result: TemporalWeightingResult,
        bayesian_result: BayesianRiskAssessment,
        git_temporal_result: Optional[GitTemporalAnalysisResult] = None,
    ) -> float:
        """
        Integrate multiple risk assessments into final risk probability.

        Uses weighted combination of all assessment methods including git temporal analysis.
        """
        # Base weights for core components
        if git_temporal_result:
            # Adjust weights when git temporal analysis is available
            weights = {
                "statistical": 0.25,  # Statistical significance testing
                "temporal": 0.25,  # Temporal weighting (GitHub issue #43 requirement)
                "bayesian": 0.35,  # Bayesian assessment (most comprehensive)
                "git_temporal": 0.15,  # Git temporal analysis (historical context)
            }
        else:
            weights = {
                "statistical": 0.3,  # Statistical significance testing
                "temporal": 0.3,  # Temporal weighting (GitHub issue #43 requirement)
                "bayesian": 0.4,  # Bayesian assessment (most comprehensive)
            }

        # Convert statistical result to probability
        statistical_prob = statistical_result.risk_probability

        # Convert temporal result to probability (normalize weighted score)
        max_temporal_score = 100.0  # Reasonable maximum for normalization
        temporal_prob = min(temporal_result.weighted_risk_score / max_temporal_score, 1.0)

        # Bayesian probability is already in [0,1]
        bayesian_prob = bayesian_result.risk_probability

        # Git temporal probability (if available)
        git_temporal_prob = 0.0
        if git_temporal_result:
            git_temporal_prob = git_temporal_result.risk_score

        # Weighted combination
        if git_temporal_result:
            integrated_probability = (
                weights["statistical"] * statistical_prob
                + weights["temporal"] * temporal_prob
                + weights["bayesian"] * bayesian_prob
                + weights["git_temporal"] * git_temporal_prob
            )
        else:
            integrated_probability = (
                weights["statistical"] * statistical_prob
                + weights["temporal"] * temporal_prob
                + weights["bayesian"] * bayesian_prob
            )

        # Ensure valid probability range
        return max(0.0, min(1.0, integrated_probability))

    def _calculate_integrated_confidence_interval(
        self, statistical_result: StatisticalHotspotResult, bayesian_result: BayesianRiskAssessment
    ) -> Tuple[float, float]:
        """Calculate integrated confidence interval from multiple sources."""
        # Use the more conservative (wider) interval
        stat_interval = statistical_result.confidence_interval
        bayesian_interval = bayesian_result.credible_interval

        # Take the minimum lower bound and maximum upper bound for conservative estimate
        lower_bound = min(stat_interval[0], bayesian_interval[0])
        upper_bound = max(stat_interval[1], bayesian_interval[1])

        return (lower_bound, upper_bound)

    def _assess_integrated_evidence_strength(
        self, statistical_result: StatisticalHotspotResult, bayesian_result: BayesianRiskAssessment
    ) -> str:
        """Assess overall evidence strength from multiple analyses."""
        # Map evidence strengths to numerical values
        strength_mapping = {
            "insufficient": 0,
            "weak": 1,
            "moderate": 2,
            "strong": 3,
            "very_strong": 4,
        }

        stat_strength = strength_mapping.get(statistical_result.evidence_strength, 0)
        bayesian_strength = strength_mapping.get(bayesian_result.evidence_strength, 0)

        # Take the average and map back to categorical
        avg_strength = (stat_strength + bayesian_strength) / 2

        strength_labels = ["insufficient", "weak", "moderate", "strong", "very_strong"]
        return strength_labels[min(int(round(avg_strength)), 4)]

    def get_orchestrator_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of orchestrator state and capabilities."""
        return {
            "model_state": {
                "is_trained": self.is_trained,
                "model_version": self.model_version,
                "training_sessions": len(self.training_history),
            },
            "component_summaries": {
                "statistical_detector": self.statistical_detector.get_model_summary(),
                "threshold_learner": self.threshold_learner.get_performance_summary(),
                "normalizer": self.normalizer.get_normalization_summary(),
                "temporal_engine": self.temporal_engine.get_temporal_analysis_summary(),
                "trend_analyzer": self.trend_analyzer.get_analysis_summary(),
                "bayesian_engine": self.bayesian_engine.get_model_summary(),
                "feature_engineer": self.feature_engineer.get_feature_engineering_summary(),
            },
            "configuration": self.config,
            "training_history": self.training_history,
        }

    def _prepare_training_data(
        self, file_metrics: Dict[str, Dict[str, Any]], violation_history: List[Dict[str, Any]]
    ) -> pd.DataFrame:
        """
        Prepare training data from file metrics and violation history.

        Args:
            file_metrics: Dictionary mapping file paths to their metrics
            violation_history: List of historical violations with timestamps

        Returns:
            DataFrame with training data including violation counts and labels
        """
        # Convert file metrics to DataFrame
        training_records = []

        # Count violations by file path
        violation_counts = {}
        for violation in violation_history:
            file_path = violation.get("file_path", "unknown")
            if file_path not in violation_counts:
                violation_counts[file_path] = 0
            violation_counts[file_path] += 1

        # Create training records
        for file_path, metrics in file_metrics.items():
            record = {
                "file_path": file_path,
                "churn_score": float(metrics.get("churn_score", 0.0)),
                "complexity_score": float(metrics.get("complexity_score", 0.0)),
                "change_frequency": float(metrics.get("change_frequency", 0.0)),
                "file_size": int(metrics.get("file_size", 0)),
                "violation_count": violation_counts.get(file_path, 0),
                "is_violation": violation_counts.get(file_path, 0) > 0,
            }

            # Add business context if available
            business_context = metrics.get("business_context", {})
            if business_context:
                record.update(
                    {
                        "test_coverage_percent": float(business_context.get("test_coverage_percent", 0.0)),
                        "team_experience_years": float(business_context.get("team_experience_years", 0.0)),
                    }
                )

            training_records.append(record)

        return pd.DataFrame(training_records)

    def _assess_business_impact_from_path(self, file_path: str) -> str:
        """
        Assess business impact based on file path patterns.

        Args:
            file_path: Path to the file

        Returns:
            Business impact level: critical, high, medium, low
        """
        file_path_lower = file_path.lower()

        # Critical components - security, authentication, core business logic
        critical_patterns = [
            "core/security",
            "core/auth",
            "core/authentication",
            "security/",
            "auth/",
            "authentication/",
            "core/payment",
            "payment/",
            "billing/",
            "core/database",
            "database/connection",
            "db/connection",
        ]

        # High impact - API endpoints, user management, core services
        high_patterns = [
            "api/",
            "endpoints/",
            "services/",
            "models/user",
            "user",
            "admin",
            "core/",
            "middleware/",
        ]

        # Low impact - tests, documentation, utilities
        low_patterns = [
            "test",
            "spec",
            "doc",
            "readme",
            "license",
            "example",
            "sample",
            "demo",
            "fixture",
        ]

        # Check patterns in order of criticality
        for pattern in critical_patterns:
            if pattern in file_path_lower:
                return "critical"

        for pattern in high_patterns:
            if pattern in file_path_lower:
                return "high"

        for pattern in low_patterns:
            if pattern in file_path_lower:
                return "low"

        # Default to medium for everything else
        return "medium"

    def _assess_component_criticality(self, file_path: str) -> str:
        """
        Assess component criticality based on file path and type.

        Args:
            file_path: Path to the file

        Returns:
            Component criticality: critical, high, medium, low
        """
        file_path_lower = file_path.lower()

        # Critical components - core system files
        critical_patterns = [
            "core/security",
            "core/auth",
            "main.py",
            "app.py",
            "security.py",
            "authentication.py",
            "auth.py",
            "database.py",
            "config.py",
            "settings.py",
        ]

        # Medium criticality - supporting components (check first for specificity)
        medium_patterns = ["utils/", "helpers/", "common/", "shared/", "lib/", "tools/", "scripts/"]

        # High criticality - important application components
        high_patterns = ["api/", "endpoints/", "services/", "models/", "middleware/", "app/"]

        # Low criticality - tests, docs, examples
        low_patterns = ["test", "spec", "doc", "example", "sample", "demo", "fixture", "mock"]

        # Check patterns in order of criticality (most specific first)
        for pattern in critical_patterns:
            if pattern in file_path_lower:
                return "critical"

        for pattern in low_patterns:
            if pattern in file_path_lower:
                return "low"

        for pattern in medium_patterns:
            if pattern in file_path_lower:
                return "medium"

        for pattern in high_patterns:
            if pattern in file_path_lower:
                return "high"

        # Default to medium for unrecognized patterns
        return "medium"

    def _assess_usage_frequency(self, file_path: str) -> str:
        """
        Assess usage frequency based on file path patterns.

        Args:
            file_path: Path to the file

        Returns:
            Usage frequency: very_high, high, medium, low
        """
        file_path_lower = file_path.lower()

        # Very high usage - entry points and core files
        very_high_patterns = [
            "main.py",
            "app.py",
            "__init__.py",
            "index.",
            "server.py",
            "wsgi.py",
            "asgi.py",
        ]

        # High usage - frequently accessed components
        high_patterns = [
            "config",
            "settings",
            "auth",
            "security",
            "api/",
            "endpoints/",
            "middleware/",
            "models/user",
            "services/auth",
        ]

        # Low usage - tests, docs, utilities (check first for specificity)
        low_patterns = [
            "test",
            "spec",
            "doc",
            "readme",
            "example",
            "sample",
            "demo",
            "fixture",
            "conftest",
            "migration",
            "script",
            "tool",
        ]

        # Medium usage - supporting components
        medium_patterns = [
            "services/",
            "models/",
            "utils/",
            "helpers/",
            "middleware/logging",
            "lib/",
        ]

        # Check patterns in order of frequency (most specific first)
        for pattern in very_high_patterns:
            if pattern in file_path_lower:
                return "very_high"

        for pattern in low_patterns:
            if pattern in file_path_lower:
                return "low"

        for pattern in medium_patterns:
            if pattern in file_path_lower:
                return "medium"

        for pattern in high_patterns:
            if pattern in file_path_lower:
                return "high"

        # Default to medium for unrecognized patterns
        return "medium"
