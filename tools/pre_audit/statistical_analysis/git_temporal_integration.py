"""
Git Temporal Integration for GitHub Issue #43.

Integrates git history parsing with temporal weighting analysis for enhanced hotspot detection.

This module bridges the gap between historical git data and statistical temporal analysis,
providing comprehensive temporal violation patterns for government-grade risk assessment.

Based on:
- Git history analysis patterns
- Temporal weighting algorithms
- Statistical significance testing for temporal patterns
"""

import logging
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Scientific computing dependencies with graceful degradation
try:
    import numpy as np
    import pandas as pd
    from scipy import stats

    HAS_SCIENTIFIC_DEPS = True
except ImportError:
    HAS_SCIENTIFIC_DEPS = False
    # Create dummy modules for type checking
    np = None
    pd = None
    stats = None

# Import git history parser
try:
    from tools.pre_audit.git_history_parser import ArchitecturalFix, GitHistoryParser
    from tools.pre_audit.git_pattern_matcher import FixType

    HAS_GIT_HISTORY = True
except ImportError:
    HAS_GIT_HISTORY = False

    # Define dummy enum-like class for type annotations when git history is not available
    class FixType:  # type: ignore
        EXPLICIT_ADR_FIX = "explicit_adr_fix"
        ARCHITECTURAL_FIX = "architectural_fix"
        BOUNDARY_FIX = "boundary_fix"
        DEPENDENCY_FIX = "dependency_fix"
        REFACTORING_FIX = "refactoring_fix"
        IMPLICIT_FIX = "implicit_fix"
        UNKNOWN = "unknown"


# Import our temporal analysis components
from .temporal_weighting_engine import (
    TemporalViolation,
    TemporalWeightingEngine,
    TemporalWeightingResult,
)

warnings.filterwarnings("ignore", category=RuntimeWarning)

logger = logging.getLogger(__name__)


@dataclass
class GitTemporalAnalysisResult:
    """
    Result of integrated git temporal analysis.

    Attributes:
        file_path: Path to analyzed file
        temporal_violations: List of temporal violations from git history
        weighting_result: Result from temporal weighting analysis
        git_fixes: List of architectural fixes from git history
        temporal_patterns: Identified temporal patterns
        risk_score: Integrated temporal risk score
        trend_analysis: Temporal trend information
        hotspot_indicators: Statistical indicators for hotspot classification
    """

    file_path: str
    temporal_violations: List[TemporalViolation]
    weighting_result: Optional[TemporalWeightingResult]
    git_fixes: List[ArchitecturalFix]
    temporal_patterns: Dict[str, Any]
    risk_score: float
    trend_analysis: Dict[str, Any]
    hotspot_indicators: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "temporal_violations": [v.to_dict() for v in self.temporal_violations],
            "weighting_result": self.weighting_result.to_dict() if self.weighting_result else None,
            "git_fixes": [f.to_dict() for f in self.git_fixes],
            "temporal_patterns": self.temporal_patterns,
            "risk_score": self.risk_score,
            "trend_analysis": self.trend_analysis,
            "hotspot_indicators": self.hotspot_indicators,
        }


class GitTemporalIntegrator:
    """
    Integrates git history analysis with temporal weighting for comprehensive hotspot detection.

    This class combines historical git data with statistical temporal analysis to provide
    enhanced violation pattern detection and risk assessment capabilities.

    Key Features:
    - Converts git fixes to temporal violations for statistical analysis
    - Applies exponential decay weighting to historical fixes
    - Identifies temporal patterns in architectural violations
    - Provides integrated risk assessment combining git history and statistical analysis
    """

    def __init__(
        self,
        repo_path: Union[str, Path],
        half_life_days: float = 30.0,
        min_confidence_threshold: float = 0.6,
        max_history_months: int = 12,
    ):
        """
        Initialize git temporal integrator.

        Args:
            repo_path: Path to git repository
            half_life_days: Half-life for exponential decay weighting
            min_confidence_threshold: Minimum confidence for including git fixes
            max_history_months: Maximum months of history to analyze

        Raises:
            ImportError: If required scientific computing dependencies are not available
        """
        if not HAS_SCIENTIFIC_DEPS:
            raise ImportError(
                "Scientific computing dependencies (numpy, pandas, scipy) are required "
                "for GitTemporalIntegrator. Please install them with: "
                "pip install numpy pandas scipy"
            )
        self.repo_path = Path(repo_path)
        self.half_life_days = half_life_days
        self.min_confidence_threshold = min_confidence_threshold
        self.max_history_months = max_history_months

        # Initialize components
        self.temporal_engine = TemporalWeightingEngine(default_half_life_days=half_life_days)

        # Initialize git history parser if available
        if HAS_GIT_HISTORY:
            try:
                self.git_parser: Optional[GitHistoryParser] = GitHistoryParser(self.repo_path)
                self.git_available = True
            except Exception as e:
                logger.warning(f"Could not initialize git parser: {e}")
                self.git_parser = None
                self.git_available = False
        else:
            logger.warning("Git history parsing not available - install GitPython")
            self.git_available = False

        # Analysis cache
        self.analysis_cache: Dict[str, GitTemporalAnalysisResult] = {}

        logger.info(f"Initialized GitTemporalIntegrator with {half_life_days}-day half-life")

    def analyze_file_temporal_patterns(
        self,
        file_path: str,
        violation_history: Optional[List[Dict[str, Any]]] = None,
    ) -> GitTemporalAnalysisResult:
        """
        Analyze temporal patterns for a specific file combining git history and violations.

        Args:
            file_path: Path to file to analyze
            violation_history: Optional external violation history

        Returns:
            GitTemporalAnalysisResult with comprehensive temporal analysis
        """
        logger.info(f"Analyzing temporal patterns for {file_path}")

        # Check cache
        cache_key = f"{file_path}_{hash(str(violation_history))}"
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        # Initialize result components
        temporal_violations = []
        git_fixes = []
        weighting_result = None
        temporal_patterns = {}
        trend_analysis = {}
        hotspot_indicators = {}

        try:
            # 1. Extract git fixes for this file
            if self.git_available and self.git_parser:
                git_fixes = self._get_git_fixes_for_file(file_path)
                logger.info(f"Found {len(git_fixes)} git fixes for {file_path}")

            # 2. Convert git fixes to temporal violations
            git_violations = self._convert_git_fixes_to_violations(git_fixes)

            # 3. Combine with external violation history
            if violation_history:
                external_violations = self._convert_violation_history_to_temporal(violation_history, file_path)
                temporal_violations = git_violations + external_violations
            else:
                temporal_violations = git_violations

            # 4. Apply temporal weighting analysis
            if temporal_violations:
                weighting_results = self.temporal_engine.calculate_temporal_weighted_risk(temporal_violations)
                # Get the weighting result for this specific file
                weighting_result = weighting_results.get(file_path)

                # 5. Analyze temporal patterns
                temporal_patterns = self._analyze_temporal_patterns(temporal_violations)

                # 6. Perform trend analysis
                trend_analysis = self._analyze_temporal_trends(temporal_violations)

            # 7. Calculate hotspot indicators (always calculate, even without weighting result)
            hotspot_indicators = self._calculate_hotspot_indicators(temporal_violations, weighting_result)

            # 8. Calculate integrated risk score
            risk_score = self._calculate_integrated_risk_score(temporal_violations, weighting_result, git_fixes)

        except Exception as e:
            logger.error(f"Error in temporal analysis for {file_path}: {e}")
            risk_score = 0.0
            # Ensure we have default values for all components
            if not temporal_patterns:
                temporal_patterns = {"pattern_detected": False}
            if not trend_analysis:
                trend_analysis = {"trend_detected": False}
            if not hotspot_indicators:
                hotspot_indicators = {"hotspot_score": 0.0}

        # Create result
        result = GitTemporalAnalysisResult(
            file_path=file_path,
            temporal_violations=temporal_violations,
            weighting_result=weighting_result,
            git_fixes=git_fixes,
            temporal_patterns=temporal_patterns,
            risk_score=risk_score,
            trend_analysis=trend_analysis,
            hotspot_indicators=hotspot_indicators,
        )

        # Cache result
        self.analysis_cache[cache_key] = result

        return result

    def _get_git_fixes_for_file(self, file_path: str) -> List[ArchitecturalFix]:
        """Get architectural fixes from git history that affected the given file."""
        if not self.git_parser:
            return []

        try:
            # Get all architectural fixes
            all_fixes = self.git_parser.find_architectural_fixes(since_months=self.max_history_months, max_commits=1000)

            # Filter for fixes that affected this file
            file_fixes = []
            for fix in all_fixes:
                if fix.confidence >= self.min_confidence_threshold:
                    # Check if this file was changed in the fix
                    if any(
                        file_path in changed_file or changed_file in file_path for changed_file in fix.files_changed
                    ):
                        file_fixes.append(fix)

            return file_fixes

        except Exception as e:
            logger.warning(f"Error getting git fixes for {file_path}: {e}")
            return []

    def _convert_git_fixes_to_violations(self, git_fixes: List[ArchitecturalFix]) -> List[TemporalViolation]:
        """Convert git architectural fixes to temporal violations."""
        violations = []

        for fix in git_fixes:
            # Map FixType to business impact
            business_impact = self._map_fix_type_to_impact(fix.fix_type)

            # Calculate severity based on fix confidence and type
            severity = min(fix.confidence * self._get_fix_type_severity_multiplier(fix.fix_type), 1.0)

            violation = TemporalViolation(
                file_path=fix.files_changed[0] if fix.files_changed else "unknown",
                timestamp=fix.date,
                severity=severity,
                violation_type=f"architectural_fix_{fix.fix_type.value}",
                business_impact=business_impact,
                context={
                    "commit_hash": fix.commit_hash,
                    "author": fix.author,
                    "pattern_matched": fix.pattern_matched,
                    "adr_references": fix.adr_references,
                    "lines_added": fix.lines_added,
                    "lines_deleted": fix.lines_deleted,
                    "confidence": fix.confidence,
                    "message": fix.commit_message[:200],  # Store message in context
                },
            )

            violations.append(violation)

        return violations

    def _convert_violation_history_to_temporal(
        self, violation_history: List[Dict[str, Any]], file_path: str
    ) -> List[TemporalViolation]:
        """Convert external violation history to temporal violations."""
        violations = []

        for violation_data in violation_history:
            try:
                # Extract timestamp
                timestamp_str = violation_data.get("timestamp")
                if isinstance(timestamp_str, str):
                    timestamp = pd.to_datetime(timestamp_str)
                elif isinstance(timestamp_str, datetime):
                    timestamp = timestamp_str
                else:
                    continue  # Skip invalid timestamps

                # Extract other fields with defaults
                severity = float(violation_data.get("severity", 1.0))
                violation_type = violation_data.get("type", "unknown")
                message = violation_data.get("message", "")[:200]  # Truncate
                business_impact = violation_data.get("business_impact", "medium")

                # Prepare context with message
                context = violation_data.get("context", {})
                if message:
                    context["message"] = message

                violation = TemporalViolation(
                    file_path=file_path,
                    timestamp=timestamp,
                    severity=severity,
                    violation_type=violation_type,
                    business_impact=business_impact,
                    context=context,
                )

                violations.append(violation)

            except Exception as e:
                logger.debug(f"Error converting violation data: {e}")
                continue

        return violations

    def _map_fix_type_to_impact(self, fix_type: "FixType") -> str:
        """Map git fix type to business impact level."""
        if not HAS_GIT_HISTORY:
            return "medium"

        try:
            # Map actual FixType enum values to business impact levels
            mapping = {
                FixType.EXPLICIT_ADR_FIX: "critical",  # Explicit architectural fixes are high priority
                FixType.ARCHITECTURAL_FIX: "high",  # General architectural improvements
                FixType.BOUNDARY_FIX: "high",  # Boundary violations are important
                FixType.DEPENDENCY_FIX: "medium",  # Dependency issues are moderate
                FixType.REFACTORING_FIX: "low",  # Refactoring is maintenance
                FixType.IMPLICIT_FIX: "medium",  # Implicit fixes are moderate
                FixType.UNKNOWN: "low",  # Unknown types get low priority
            }
            return mapping.get(fix_type, "medium")
        except Exception:
            return "medium"

    def _get_fix_type_severity_multiplier(self, fix_type: "FixType") -> float:
        """Get severity multiplier for different fix types."""
        if not HAS_GIT_HISTORY:
            return 1.0

        try:
            # Map actual FixType enum values to severity multipliers
            multipliers = {
                FixType.EXPLICIT_ADR_FIX: 1.5,  # Highest severity - explicit arch fixes
                FixType.ARCHITECTURAL_FIX: 1.3,  # High severity - general arch improvements
                FixType.BOUNDARY_FIX: 1.4,  # High severity - boundary violations
                FixType.DEPENDENCY_FIX: 1.1,  # Moderate severity - dependency issues
                FixType.REFACTORING_FIX: 0.8,  # Lower severity - maintenance refactoring
                FixType.IMPLICIT_FIX: 1.0,  # Normal severity - implicit improvements
                FixType.UNKNOWN: 0.9,  # Slightly below normal - unknown type
            }
            return multipliers.get(fix_type, 1.0)
        except Exception:
            return 1.0

    def _analyze_temporal_patterns(self, violations: List[TemporalViolation]) -> Dict[str, Any]:
        """Analyze temporal patterns in violations."""
        if not violations:
            return {"pattern_detected": False}

        timestamps = [v.timestamp for v in violations]
        severities = [v.severity for v in violations]

        patterns = {
            "pattern_detected": True,
            "total_violations": len(violations),
            "time_span_days": ((max(timestamps) - min(timestamps)).days if len(timestamps) > 1 else 0),
            "average_severity": float(np.mean(severities)),
            "severity_trend": "stable",
        }

        # Add clustering analysis
        if len(violations) >= 3:
            clustering_data = self._analyze_violation_clustering(violations)
            patterns.update(clustering_data)

        # Add severity trend analysis
        if len(severities) >= 3:
            trend_data = self._analyze_severity_trends(severities)
            patterns.update(trend_data)

        return patterns

    def _analyze_violation_clustering(self, violations: List[TemporalViolation]) -> Dict[str, Any]:
        """Analyze clustering patterns in violations."""
        clusters = []
        current_cluster = [violations[0]]

        for i in range(1, len(violations)):
            time_diff = abs((violations[i].timestamp - violations[i - 1].timestamp).days)
            if time_diff <= 7:  # Within a week
                current_cluster.append(violations[i])
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [violations[i]]

        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        clustered_violations = sum(len(cluster) for cluster in clusters)
        return {
            "violation_clusters": len(clusters),
            "clustered_violations": clustered_violations,
            "clustering_ratio": clustered_violations / len(violations),
        }

    def _analyze_severity_trends(self, severities: List[float]) -> Dict[str, Any]:
        """Analyze severity trends over time."""
        try:
            x = np.arange(len(severities))
            slope, _, r_value, p_value, _ = stats.linregress(x, severities)

            trend_data: Dict[str, Union[float, str]] = {
                "trend_slope": float(slope),
                "trend_r_squared": float(r_value**2),
                "trend_p_value": float(p_value),
            }

            if p_value < 0.05:  # Significant trend
                if float(slope) > 0.01:
                    trend_data["severity_trend"] = "increasing"
                elif float(slope) < -0.01:
                    trend_data["severity_trend"] = "decreasing"

            return trend_data
        except Exception:
            return {"severity_trend": "stable"}

    def _analyze_temporal_trends(self, violations: List[TemporalViolation]) -> Dict[str, Any]:
        """Perform comprehensive temporal trend analysis."""
        if len(violations) < 2:
            return {"trend_detected": False}

        # Sort by timestamp
        sorted_violations = sorted(violations, key=lambda v: v.timestamp)

        trend_analysis: Dict[str, Any] = {
            "trend_detected": True,
            "analysis_period_days": (sorted_violations[-1].timestamp - sorted_violations[0].timestamp).days,
            "violation_frequency": len(violations),
        }

        # Monthly aggregation
        try:
            df = pd.DataFrame(
                [
                    {
                        "timestamp": v.timestamp,
                        "severity": v.severity,
                        "business_impact": v.business_impact,
                    }
                    for v in sorted_violations
                ]
            )

            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df.set_index("timestamp", inplace=True)

            # Monthly aggregation
            monthly_agg = (
                df.resample("ME")
                .agg(
                    {
                        "severity": ["count", "mean", "sum"],
                    }
                )
                .fillna(0)
            )

            if len(monthly_agg) >= 2:
                # Trend in violation count
                counts = monthly_agg[("severity", "count")].values
                if len(counts) >= 3:
                    x = np.arange(len(counts))
                    slope, _, r_value, p_value, _ = stats.linregress(x, counts)

                    trend_analysis.update(
                        {
                            "monthly_trend_slope": float(slope),
                            "monthly_trend_r_squared": float(r_value**2),
                            "monthly_trend_significant": bool(p_value < 0.05),
                            "monthly_trend_direction": (
                                "increasing" if slope > 0 else "decreasing" if slope < 0 else "stable"
                            ),
                        }
                    )

                # Recent vs. historical comparison
                if len(monthly_agg) >= 4:
                    recent_months = monthly_agg.tail(2)[("severity", "count")].mean()
                    historical_months = monthly_agg.head(-2)[("severity", "count")].mean()

                    trend_analysis.update(
                        {
                            "recent_vs_historical_ratio": float(recent_months / (historical_months + 1e-10)),
                            "recent_activity_increase": bool(recent_months > historical_months * 1.5),
                        }
                    )

        except Exception as e:
            logger.debug(f"Error in trend analysis: {e}")

        return trend_analysis

    def _calculate_hotspot_indicators(
        self,
        violations: List[TemporalViolation],
        weighting_result: Optional[TemporalWeightingResult],
    ) -> Dict[str, float]:
        """Calculate statistical indicators for hotspot classification."""
        if not violations:
            return {"hotspot_score": 0.0}

        indicators = {}

        # Basic frequency indicators
        indicators["violation_frequency"] = float(len(violations))
        indicators["average_severity"] = float(np.mean([v.severity for v in violations]))

        # Temporal weighting indicators
        if weighting_result:
            indicators["weighted_score"] = weighting_result.weighted_risk_score
            indicators["recent_activity_score"] = weighting_result.recent_violations
            indicators["decay_rate"] = weighting_result.decay_parameters.get("half_life", 30.0)

        # Business impact distribution
        impact_weights = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}
        weighted_impact = sum(impact_weights.get(v.business_impact, 0.6) for v in violations) / len(violations)
        indicators["business_impact_score"] = weighted_impact

        # Recency factor
        now = datetime.now()
        if violations:
            most_recent = max(v.timestamp for v in violations)
            days_since_recent = (now - most_recent).days
            indicators["recency_factor"] = np.exp(-days_since_recent / 30.0)  # 30-day decay
        else:
            indicators["recency_factor"] = 0.0

        # Combined hotspot score
        base_score = indicators["violation_frequency"] * indicators["average_severity"]
        temporal_multiplier = indicators.get("weighted_score", 1.0) / max(indicators["violation_frequency"], 1.0)
        business_multiplier = indicators["business_impact_score"]
        recency_multiplier = indicators["recency_factor"]

        indicators["hotspot_score"] = base_score * temporal_multiplier * business_multiplier * recency_multiplier

        return indicators

    def _calculate_integrated_risk_score(
        self,
        violations: List[TemporalViolation],
        weighting_result: Optional[TemporalWeightingResult],
        git_fixes: List[ArchitecturalFix],
    ) -> float:
        """Calculate integrated risk score combining all temporal factors."""
        if not violations and not git_fixes:
            return 0.0

        risk_components = []

        # Base violation risk
        if violations:
            violation_risk = np.mean([v.severity for v in violations]) * len(violations) / 10.0
            risk_components.append(min(violation_risk, 1.0))

        # Temporal weighting risk
        if weighting_result:
            weighted_risk = weighting_result.weighted_risk_score / 10.0  # Normalize to 0-1
            risk_components.append(min(weighted_risk, 1.0))

        # Git history risk
        if git_fixes:
            git_risk = np.mean([f.confidence for f in git_fixes]) * len(git_fixes) / 5.0
            risk_components.append(min(git_risk, 1.0))

        # Combined risk (weighted average)
        if risk_components:
            weights = [0.4, 0.4, 0.2][: len(risk_components)]  # Temporal gets higher weight
            normalized_weights = np.array(weights) / sum(weights)
            integrated_risk = np.average(risk_components, weights=normalized_weights)
        else:
            integrated_risk = 0.0

        return float(min(integrated_risk, 1.0))

    def get_integration_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of integration capabilities and cache status."""
        return {
            "git_integration": {
                "git_available": self.git_available,
                "repo_path": str(self.repo_path),
                "max_history_months": self.max_history_months,
                "min_confidence_threshold": self.min_confidence_threshold,
            },
            "temporal_analysis": {
                "half_life_days": self.half_life_days,
                "engine_available": self.temporal_engine is not None,
            },
            "cache_status": {
                "cached_analyses": len(self.analysis_cache),
            },
            "capabilities": {
                "git_history_parsing": HAS_GIT_HISTORY and self.git_available,
                "temporal_weighting": True,
                "pattern_analysis": True,
                "trend_analysis": True,
                "hotspot_indicators": True,
            },
        }
