"""
Advanced Feature Engineer for GitHub Issue #43
Implements sophisticated feature engineering incorporating domain knowledge for
government-grade software quality assessment.

Combines statistical transformations with software engineering domain expertise
to create meaningful features for Bayesian risk assessment.

Based on:
- Software engineering best practices for risk assessment
- Domain-driven feature engineering principles
- Statistical feature construction methodologies
"""

import logging
import re
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class FeatureEngineeringResult:
    """
    Result of feature engineering process.

    Attributes:
        engineered_features: Dictionary of engineered features
        feature_metadata: Metadata about feature construction
        domain_knowledge_applied: Domain knowledge rules applied
        statistical_transformations: Statistical transformations performed
        feature_importance_hints: Hints about expected feature importance
    """

    engineered_features: Dict[str, float]
    feature_metadata: Dict[str, Any]
    domain_knowledge_applied: List[str]
    statistical_transformations: List[str]
    feature_importance_hints: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "engineered_features": self.engineered_features,
            "feature_metadata": self.feature_metadata,
            "domain_knowledge_applied": self.domain_knowledge_applied,
            "statistical_transformations": self.statistical_transformations,
            "feature_importance_hints": self.feature_importance_hints,
        }


class AdvancedFeatureEngineer:
    """
    Advanced feature engineering incorporating software engineering domain knowledge.

    Creates sophisticated features from raw metrics by combining:
    - Statistical transformations (log, sqrt, polynomial)
    - Domain knowledge (file types, architectural patterns)
    - Interaction features (multiplicative, ratio-based)
    - Temporal features (trends, seasonality, recency)
    - Business context (team expertise, testing coverage)

    Designed for government-grade software quality assessment where
    interpretability and domain expertise integration are critical.
    """

    def __init__(
        self,
        enable_domain_features: bool = True,
        enable_interaction_features: bool = True,
        enable_temporal_features: bool = True,
        enable_statistical_transforms: bool = True,
        max_interaction_order: int = 2,
    ):
        """
        Initialize advanced feature engineer.

        Args:
            enable_domain_features: Enable domain knowledge features
            enable_interaction_features: Enable feature interactions
            enable_temporal_features: Enable temporal pattern features
            enable_statistical_transforms: Enable statistical transformations
            max_interaction_order: Maximum order for interaction features
        """
        self.enable_domain_features = enable_domain_features
        self.enable_interaction_features = enable_interaction_features
        self.enable_temporal_features = enable_temporal_features
        self.enable_statistical_transforms = enable_statistical_transforms
        self.max_interaction_order = max_interaction_order

        # Domain knowledge patterns
        self.domain_patterns = self._initialize_domain_patterns()

        # Feature importance hints based on domain knowledge
        self.feature_importance_hints: Dict[str, float] = {}

        # Engineering history for reproducibility
        self.engineering_history: List[Dict[str, Any]] = []

        logger.info("Initialized AdvancedFeatureEngineer with domain knowledge integration")

    def _initialize_domain_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize domain knowledge patterns for software engineering."""
        return {
            "security_patterns": {
                "indicators": [
                    "auth",
                    "security",
                    "login",
                    "password",
                    "token",
                    "crypto",
                    "session",
                    "jwt",
                    "oauth",
                    "ssl",
                    "tls",
                    "cert",
                    "key",
                ],
                "risk_multiplier": 1.5,
                "description": "Security-related components have higher inherent risk",
            },
            "core_system_patterns": {
                "indicators": [
                    "core",
                    "base",
                    "foundation",
                    "engine",
                    "kernel",
                    "main",
                    "framework",
                    "infrastructure",
                    "platform",
                ],
                "risk_multiplier": 1.3,
                "description": "Core system components affect entire system stability",
            },
            "api_interface_patterns": {
                "indicators": [
                    "api",
                    "endpoint",
                    "route",
                    "controller",
                    "interface",
                    "service",
                    "handler",
                    "rest",
                    "graphql",
                    "rpc",
                ],
                "risk_multiplier": 1.2,
                "description": "External interfaces have higher exposure risk",
            },
            "database_patterns": {
                "indicators": [
                    "db",
                    "database",
                    "model",
                    "schema",
                    "migration",
                    "repository",
                    "dao",
                    "orm",
                    "sql",
                    "query",
                ],
                "risk_multiplier": 1.25,
                "description": "Database components affect data integrity",
            },
            "configuration_patterns": {
                "indicators": [
                    "config",
                    "setting",
                    "env",
                    "properties",
                    "yaml",
                    "json",
                    "xml",
                    "ini",
                    "conf",
                ],
                "risk_multiplier": 1.1,
                "description": "Configuration changes can have wide system impact",
            },
            "testing_patterns": {
                "indicators": ["test", "spec", "mock", "stub", "fixture"],
                "risk_multiplier": 0.7,
                "description": "Test files have lower operational risk",
            },
            "documentation_patterns": {
                "indicators": ["doc", "readme", "md", "txt", "comment"],
                "risk_multiplier": 0.5,
                "description": "Documentation changes have minimal operational risk",
            },
        }

    def engineer_comprehensive_features(
        self,
        raw_metrics: Dict[str, Any],
        temporal_context: Optional[Dict[str, Any]] = None,
        business_context: Optional[Dict[str, Any]] = None,
    ) -> FeatureEngineeringResult:
        """
        Engineer comprehensive features from raw metrics with domain knowledge.

        Creates sophisticated feature set combining statistical transformations
        with software engineering domain expertise.

        Args:
            raw_metrics: Raw metrics from code analysis
            temporal_context: Temporal violation patterns and trends
            business_context: Business context (team, testing, usage)

        Returns:
            FeatureEngineeringResult with engineered features and metadata
        """
        logger.info("Engineering comprehensive features with domain knowledge")

        engineered_features = {}
        applied_transformations = []
        applied_domain_knowledge = []
        feature_metadata = {}

        # 1. Basic statistical transformations
        if self.enable_statistical_transforms:
            basic_features = self._apply_statistical_transformations(raw_metrics)
            engineered_features.update(basic_features)
            applied_transformations.extend(["log_transform", "sqrt_transform", "polynomial_features"])

        # 2. Domain knowledge features
        if self.enable_domain_features:
            domain_features = self._apply_domain_knowledge_features(raw_metrics)
            engineered_features.update(domain_features["features"])
            applied_domain_knowledge.extend(domain_features["applied_patterns"])
            feature_metadata.update(domain_features["metadata"])

        # 3. Interaction features
        if self.enable_interaction_features:
            interaction_features = self._create_interaction_features(engineered_features)
            engineered_features.update(interaction_features)
            applied_transformations.append("interaction_features")

        # 4. Temporal features
        if self.enable_temporal_features and temporal_context:
            temporal_features = self._engineer_temporal_features(temporal_context)
            engineered_features.update(temporal_features)
            applied_transformations.append("temporal_features")

        # 5. Business context features
        if business_context:
            business_features = self._engineer_business_context_features(business_context)
            engineered_features.update(business_features)
            applied_transformations.append("business_context_features")

        # 6. Advanced composite features
        composite_features = self._create_composite_features(engineered_features, raw_metrics)
        engineered_features.update(composite_features)
        applied_transformations.append("composite_features")

        # Generate importance hints based on domain knowledge
        importance_hints = self._generate_feature_importance_hints(engineered_features, raw_metrics)

        # Record engineering history
        self.engineering_history.append(
            {
                "timestamp": datetime.now(),
                "n_input_metrics": len(raw_metrics),
                "n_output_features": len(engineered_features),
                "applied_transformations": applied_transformations,
                "applied_domain_knowledge": applied_domain_knowledge,
            }
        )

        result = FeatureEngineeringResult(
            engineered_features=engineered_features,
            feature_metadata=feature_metadata,
            domain_knowledge_applied=applied_domain_knowledge,
            statistical_transformations=applied_transformations,
            feature_importance_hints=importance_hints,
        )

        logger.info(f"Engineered {len(engineered_features)} features from {len(raw_metrics)} raw metrics")

        return result

    def _apply_statistical_transformations(self, raw_metrics: Dict[str, Any]) -> Dict[str, float]:
        """Apply statistical transformations to numerical metrics."""
        transformed = {}

        for metric_name, value in raw_metrics.items():
            if isinstance(value, (int, float)) and np.isfinite(value):
                # Original value
                transformed[metric_name] = float(value)

                # Log transformation for skewed metrics
                if value > 0:
                    transformed[f"{metric_name}_log"] = np.log(value + 1)
                    transformed[f"{metric_name}_log10"] = np.log10(value + 1)

                # Square root transformation
                if value >= 0:
                    transformed[f"{metric_name}_sqrt"] = np.sqrt(value)

                # Square transformation for non-linear relationships
                transformed[f"{metric_name}_squared"] = value**2

                # Cube root for heavy-tailed distributions
                if value >= 0:
                    transformed[f"{metric_name}_cbrt"] = np.cbrt(value)
                elif value < 0:
                    transformed[f"{metric_name}_cbrt"] = -np.cbrt(abs(value))

                # Inverse transformation (with regularization)
                if abs(value) > 1e-10:
                    transformed[f"{metric_name}_inv"] = 1.0 / (value + np.sign(value) * 1e-10)

                # Sigmoid transformation for bounded features
                transformed[f"{metric_name}_sigmoid"] = 1.0 / (1.0 + np.exp(-value))

                # Normalization indicators
                if value != 0:
                    transformed[f"{metric_name}_sign"] = np.sign(value)
                    transformed[f"{metric_name}_abs"] = abs(value)

        return transformed

    def _apply_domain_knowledge_features(self, raw_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Apply software engineering domain knowledge to create meaningful features."""
        domain_features = {}
        applied_patterns = []
        metadata = {}

        file_path = raw_metrics.get("file_path", "").lower()

        # File path analysis
        path_obj = Path(file_path)
        file_extension = path_obj.suffix.lower()
        file_name = path_obj.name.lower()
        directory_parts = [part.lower() for part in path_obj.parts]

        # Apply domain patterns
        for pattern_name, pattern_info in self.domain_patterns.items():
            indicators = pattern_info["indicators"]
            risk_multiplier = pattern_info["risk_multiplier"]

            # Check if any indicators match file path
            matches = []
            for indicator in indicators:
                if (
                    indicator in file_path
                    or indicator in file_name
                    or any(indicator in part for part in directory_parts)
                ):
                    matches.append(indicator)

            if matches:
                # Create binary indicator feature
                feature_name = f"is_{pattern_name.replace('_patterns', '')}"
                domain_features[feature_name] = 1.0
                applied_patterns.append(pattern_name)

                # Create match count feature
                domain_features[f"{feature_name}_match_count"] = float(len(matches))

                # Create weighted feature based on risk multiplier
                domain_features[f"{feature_name}_risk_weight"] = risk_multiplier

                metadata[feature_name] = {
                    "pattern": pattern_name,
                    "matches": matches,
                    "risk_multiplier": risk_multiplier,
                    "description": pattern_info["description"],
                }
            else:
                # Create zero feature for consistency
                feature_name = f"is_{pattern_name.replace('_patterns', '')}"
                domain_features[feature_name] = 0.0
                domain_features[f"{feature_name}_match_count"] = 0.0
                domain_features[f"{feature_name}_risk_weight"] = 1.0

        # File type features
        common_extensions = [".py", ".js", ".java", ".cpp", ".c", ".go", ".rs", ".rb", ".php"]
        for ext in common_extensions:
            domain_features[f"is_filetype_{ext.replace('.', '')}"] = float(file_extension == ext)

        # Directory depth feature
        domain_features["directory_depth"] = float(len(directory_parts))

        # File size category (if available)
        if "file_size" in raw_metrics:
            file_size = raw_metrics["file_size"]
            if isinstance(file_size, (int, float)):
                domain_features["is_large_file"] = float(file_size > 10000)  # > 10KB
                domain_features["is_very_large_file"] = float(file_size > 100000)  # > 100KB
                domain_features["file_size_category"] = self._categorize_file_size(file_size)

        # Complexity categorization
        if "complexity_score" in raw_metrics:
            complexity = raw_metrics["complexity_score"]
            if isinstance(complexity, (int, float)):
                domain_features["is_high_complexity"] = float(complexity > 75)
                domain_features["is_very_high_complexity"] = float(complexity > 100)
                domain_features["complexity_category"] = self._categorize_complexity(complexity)

        # Churn categorization
        if "churn_score" in raw_metrics:
            churn = raw_metrics["churn_score"]
            if isinstance(churn, (int, float)):
                domain_features["is_high_churn"] = float(churn > 500)
                domain_features["is_very_high_churn"] = float(churn > 1000)
                domain_features["churn_category"] = self._categorize_churn(churn)

        return {
            "features": domain_features,
            "applied_patterns": applied_patterns,
            "metadata": metadata,
        }

    def _categorize_file_size(self, file_size: float) -> float:
        """Categorize file size into discrete categories."""
        if file_size < 1000:
            return 1.0  # Small
        elif file_size < 10000:
            return 2.0  # Medium
        elif file_size < 100000:
            return 3.0  # Large
        else:
            return 4.0  # Very large

    def _categorize_complexity(self, complexity: float) -> float:
        """Categorize complexity score into discrete levels."""
        if complexity < 25:
            return 1.0  # Low
        elif complexity < 50:
            return 2.0  # Medium
        elif complexity < 75:
            return 3.0  # High
        else:
            return 4.0  # Very high

    def _categorize_churn(self, churn: float) -> float:
        """Categorize churn score into discrete levels."""
        if churn < 100:
            return 1.0  # Low
        elif churn < 500:
            return 2.0  # Medium
        elif churn < 1000:
            return 3.0  # High
        else:
            return 4.0  # Very high

    def _create_interaction_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Create interaction features between important metrics."""
        interactions = {}

        # Multiplicative interactions (2nd order)
        interaction_pairs = [
            ("churn_score", "complexity_score"),
            ("churn_score", "is_security"),
            ("complexity_score", "is_core_system"),
            ("churn_score", "is_api_interface"),
            ("complexity_score", "is_api_interface"),
        ]

        for feature1, feature2 in interaction_pairs:
            if feature1 in features and feature2 in features:
                interaction_name = f"{feature1}_x_{feature2}"
                interactions[interaction_name] = features[feature1] * features[feature2]

        # Ratio interactions
        ratio_pairs = [
            ("churn_score", "complexity_score"),
            ("complexity_score", "file_size"),
            ("churn_score", "file_size"),
        ]

        for numerator, denominator in ratio_pairs:
            if numerator in features and denominator in features and features[denominator] != 0:
                ratio_name = f"{numerator}_ratio_{denominator}"
                interactions[ratio_name] = features[numerator] / features[denominator]

        # Polynomial interactions (for non-linear relationships)
        poly_features = ["churn_score", "complexity_score"]
        for feature in poly_features:
            if feature in features:
                interactions[f"{feature}_poly2"] = features[feature] ** 2
                if features[feature] > 0:
                    interactions[f"{feature}_poly3"] = features[feature] ** 3

        return interactions

    def _engineer_temporal_features(self, temporal_context: Dict[str, Any]) -> Dict[str, float]:
        """Engineer features from temporal violation patterns."""
        temporal_features = {}

        # Violation recency features
        if "oldest_violation_age_days" in temporal_context:
            age = temporal_context["oldest_violation_age_days"]
            temporal_features["violation_age_days"] = float(age)
            temporal_features["violation_age_log"] = np.log(age + 1)
            temporal_features["violation_age_sqrt"] = np.sqrt(age)
            temporal_features["violation_recency_weight"] = np.exp(-age / 30)  # 30-day decay

        # Violation frequency features
        if "violation_frequency_per_month" in temporal_context:
            freq = temporal_context["violation_frequency_per_month"]
            temporal_features["violation_frequency"] = float(freq)
            temporal_features["violation_frequency_log"] = np.log(freq + 1)
            temporal_features["is_frequent_violations"] = float(freq > 2)  # > 2 per month

        # Temporal pattern features
        if "violation_timestamps" in temporal_context:
            timestamps = temporal_context["violation_timestamps"]
            if len(timestamps) > 1:
                # Time gaps analysis
                gaps = np.diff(sorted(timestamps))
                temporal_features["avg_violation_gap_days"] = float(np.mean(gaps))
                temporal_features["violation_gap_std"] = float(np.std(gaps))
                temporal_features["violation_gap_cv"] = (
                    float(np.std(gaps) / np.mean(gaps)) if np.mean(gaps) > 0 else 0.0
                )

                # Burst detection
                short_gaps = [gap for gap in gaps if gap < 7]  # Within a week
                temporal_features["violation_burst_ratio"] = float(len(short_gaps) / len(gaps))
                temporal_features["has_violation_bursts"] = float(len(short_gaps) > 0)

        # Seasonal patterns
        if "seasonal_strength" in temporal_context:
            temporal_features["seasonal_strength"] = float(temporal_context["seasonal_strength"])
            temporal_features["has_seasonal_pattern"] = float(temporal_context["seasonal_strength"] > 0.1)

        # Trend features
        if "trend_direction" in temporal_context:
            trend = temporal_context["trend_direction"]
            temporal_features["trend_increasing"] = float(trend == "increasing")
            temporal_features["trend_decreasing"] = float(trend == "decreasing")
            temporal_features["trend_stable"] = float(trend == "no_trend")

        if "trend_slope" in temporal_context:
            slope = temporal_context["trend_slope"]
            temporal_features["trend_slope"] = float(slope)
            temporal_features["trend_slope_abs"] = float(abs(slope))

        return temporal_features

    def _engineer_business_context_features(self, business_context: Dict[str, Any]) -> Dict[str, float]:
        """Engineer features from business and organizational context."""
        business_features = {}

        # Team experience features
        if "team_experience_years" in business_context:
            experience = business_context["team_experience_years"]
            business_features["team_experience"] = float(experience)
            business_features["team_experience_normalized"] = min(float(experience) / 10.0, 1.0)
            business_features["is_experienced_team"] = float(experience >= 3)
            business_features["is_senior_team"] = float(experience >= 5)

        # Testing coverage features
        if "test_coverage_percent" in business_context:
            coverage = business_context["test_coverage_percent"]
            business_features["test_coverage"] = float(coverage) / 100.0
            business_features["test_coverage_deficit"] = 1.0 - (float(coverage) / 100.0)
            business_features["is_well_tested"] = float(coverage >= 80)
            business_features["is_poorly_tested"] = float(coverage < 50)

        # Component criticality
        criticality_map = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "none": 0.0}
        if "component_criticality" in business_context:
            criticality = business_context["component_criticality"].lower()
            business_features["criticality_score"] = criticality_map.get(criticality, 0.6)
            business_features["is_critical_component"] = float(criticality == "critical")

        # Usage frequency
        usage_map = {"very_high": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "very_low": 0.2}
        if "usage_frequency" in business_context:
            usage = business_context["usage_frequency"].lower()
            business_features["usage_score"] = usage_map.get(usage, 0.6)
            business_features["is_high_usage"] = float(usage in ["high", "very_high"])

        # Documentation quality
        if "documentation_quality" in business_context:
            quality = business_context["documentation_quality"]
            business_features["documentation_quality"] = float(quality) / 100.0
            business_features["is_well_documented"] = float(quality >= 70)

        # Code review coverage
        if "code_review_coverage" in business_context:
            review_coverage = business_context["code_review_coverage"]
            business_features["code_review_coverage"] = float(review_coverage) / 100.0
            business_features["has_code_review"] = float(review_coverage > 0)

        return business_features

    def _create_composite_features(
        self, engineered_features: Dict[str, float], raw_metrics: Dict[str, Any]
    ) -> Dict[str, float]:
        """Create advanced composite features combining multiple dimensions."""
        composite = {}

        # Risk concentration index
        risk_components = []
        if "churn_score" in engineered_features:
            risk_components.append(engineered_features["churn_score"])
        if "complexity_score" in engineered_features:
            risk_components.append(engineered_features["complexity_score"])
        if "violation_frequency" in engineered_features:
            risk_components.append(engineered_features["violation_frequency"])

        if risk_components:
            composite["risk_concentration_index"] = float(np.mean(risk_components))
            composite["risk_variance"] = float(np.var(risk_components))

        # Domain risk score (weighted combination of domain indicators)
        domain_weights = {
            "is_security": 0.3,
            "is_core_system": 0.25,
            "is_api_interface": 0.2,
            "is_database": 0.15,
            "is_configuration": 0.1,
        }

        domain_risk_score = 0.0
        for feature, weight in domain_weights.items():
            if feature in engineered_features:
                domain_risk_score += engineered_features[feature] * weight

        composite["domain_risk_score"] = domain_risk_score

        # Technical debt indicator
        tech_debt_factors = []
        if "complexity_score" in engineered_features:
            tech_debt_factors.append(min(engineered_features["complexity_score"] / 100.0, 1.0))
        if "test_coverage_deficit" in engineered_features:
            tech_debt_factors.append(engineered_features["test_coverage_deficit"])
        if "churn_score" in engineered_features:
            tech_debt_factors.append(min(engineered_features["churn_score"] / 1000.0, 1.0))

        if tech_debt_factors:
            composite["technical_debt_indicator"] = float(np.mean(tech_debt_factors))

        # Stability score (inverse of change frequency)
        if "violation_frequency" in engineered_features and engineered_features["violation_frequency"] > 0:
            composite["stability_score"] = 1.0 / (1.0 + engineered_features["violation_frequency"])
        else:
            composite["stability_score"] = 1.0

        # Maintenance burden score
        maintenance_factors = []
        if "complexity_score" in engineered_features:
            maintenance_factors.append(min(engineered_features["complexity_score"] / 75.0, 1.0))
        if "churn_score" in engineered_features:
            maintenance_factors.append(min(engineered_features["churn_score"] / 500.0, 1.0))
        if "team_experience_normalized" in engineered_features:
            # Less experienced teams have higher maintenance burden
            maintenance_factors.append(1.0 - engineered_features["team_experience_normalized"])

        if maintenance_factors:
            composite["maintenance_burden_score"] = float(np.mean(maintenance_factors))

        return composite

    def _generate_feature_importance_hints(
        self, engineered_features: Dict[str, float], raw_metrics: Dict[str, Any]
    ) -> Dict[str, float]:
        """Generate hints about expected feature importance based on domain knowledge."""
        importance_hints = {}

        # High importance features
        high_importance = [
            "churn_score",
            "complexity_score",
            "violation_frequency",
            "is_security",
            "is_core_system",
            "domain_risk_score",
            "technical_debt_indicator",
            "risk_concentration_index",
        ]

        # Medium importance features
        medium_importance = [
            "is_api_interface",
            "is_database",
            "test_coverage_deficit",
            "team_experience",
            "criticality_score",
            "usage_score",
        ]

        # Interaction features (generally important)
        interaction_importance = [
            "churn_score_x_complexity_score",
            "churn_score_x_is_security",
            "complexity_score_x_is_core_system",
        ]

        # Assign importance hints
        for feature in engineered_features:
            if feature in high_importance:
                importance_hints[feature] = 0.9
            elif feature in medium_importance:
                importance_hints[feature] = 0.7
            elif any(interaction in feature for interaction in interaction_importance):
                importance_hints[feature] = 0.8
            elif feature.endswith("_log") or feature.endswith("_sqrt"):
                importance_hints[feature] = 0.6  # Transformed features
            elif feature.startswith("is_"):
                importance_hints[feature] = 0.5  # Binary indicators
            else:
                importance_hints[feature] = 0.4  # Default lower importance

        return importance_hints

    def get_feature_engineering_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of feature engineering capabilities and history."""
        return {
            "configuration": {
                "enable_domain_features": self.enable_domain_features,
                "enable_interaction_features": self.enable_interaction_features,
                "enable_temporal_features": self.enable_temporal_features,
                "enable_statistical_transforms": self.enable_statistical_transforms,
                "max_interaction_order": self.max_interaction_order,
            },
            "domain_patterns": {
                name: {
                    "n_indicators": len(pattern["indicators"]),
                    "risk_multiplier": pattern["risk_multiplier"],
                    "description": pattern["description"],
                }
                for name, pattern in self.domain_patterns.items()
            },
            "engineering_history": self.engineering_history,
            "total_engineering_sessions": len(self.engineering_history),
        }
