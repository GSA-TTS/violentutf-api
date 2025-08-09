"""
Validation rules and constraints for report data.

This module defines validation rules for different types of data
used in the reporting system.
"""

import re
from typing import Any, Dict, Optional, Tuple


class ValidationRules:
    """Define validation rules and constraints."""

    # Numeric ranges
    COMPLIANCE_SCORE_RANGE = (0.0, 100.0)
    RISK_SCORE_RANGE = (0.0, 100.0)
    CONFIDENCE_RANGE = (0.0, 1.0)
    LINE_NUMBER_RANGE = (1, 1000000)
    TECHNICAL_DEBT_RANGE = (0.0, 10000.0)  # In hours

    # String lengths
    MAX_FILE_PATH_LENGTH = 1024
    MAX_ADR_ID_LENGTH = 100
    MAX_MESSAGE_LENGTH = 5000
    MAX_DESCRIPTION_LENGTH = 10000
    MAX_TITLE_LENGTH = 500

    # Collection sizes
    MAX_VIOLATIONS_COUNT = 10000
    MAX_HOTSPOTS_COUNT = 1000
    MAX_RECOMMENDATIONS_COUNT = 100

    # Risk levels
    VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "minimal"}

    # Analysis modes
    VALID_ANALYSIS_MODES = {"audit", "coach", "debug", "comprehensive"}

    # Patterns
    ADR_ID_PATTERN = re.compile(r"^ADR-[\w\-_]{1,50}$")
    SAFE_PATH_PATTERN = re.compile(r"^[\w\-_./\\]+$")

    @staticmethod
    def validate_numeric_range(value: Any, range_tuple: Tuple[float, float], field_name: str) -> float:
        """Validate numeric value is within range."""
        try:
            num_value = float(value)
            min_val, max_val = range_tuple
            if not (min_val <= num_value <= max_val):
                raise ValueError(f"{field_name} must be between {min_val} and {max_val}, got {num_value}")
            return num_value
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid numeric value for {field_name}: {str(e)}")

    @staticmethod
    def validate_compliance_score(value: Any) -> float:
        """Validate compliance score is 0-100."""
        return ValidationRules.validate_numeric_range(value, ValidationRules.COMPLIANCE_SCORE_RANGE, "compliance_score")

    @staticmethod
    def validate_risk_score(value: Any) -> float:
        """Validate risk score is 0-100."""
        return ValidationRules.validate_numeric_range(value, ValidationRules.RISK_SCORE_RANGE, "risk_score")

    @staticmethod
    def validate_confidence(value: Any) -> float:
        """Validate confidence is 0-1."""
        return ValidationRules.validate_numeric_range(value, ValidationRules.CONFIDENCE_RANGE, "confidence")

    @staticmethod
    def validate_line_number(value: Any) -> int:
        """Validate line number is positive integer."""
        try:
            int_value = int(value)
            if int_value < 1:
                raise ValueError("Line number must be positive")
            if int_value > ValidationRules.LINE_NUMBER_RANGE[1]:
                raise ValueError(f"Line number too large: {int_value}")
            return int_value
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid line number: {str(e)}")

    @staticmethod
    def validate_risk_level(value: str) -> str:
        """Validate risk level is valid."""
        lower_value = str(value).lower()
        if lower_value not in ValidationRules.VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk level '{value}'. Must be one of: {', '.join(ValidationRules.VALID_RISK_LEVELS)}"
            )
        return lower_value

    @staticmethod
    def validate_adr_id(value: str) -> str:
        """Validate ADR ID format."""
        str_value = str(value)
        if len(str_value) > ValidationRules.MAX_ADR_ID_LENGTH:
            raise ValueError(f"ADR ID too long: {len(str_value)} > {ValidationRules.MAX_ADR_ID_LENGTH}")

        if not ValidationRules.ADR_ID_PATTERN.match(str_value):
            # Allow legacy formats but sanitize them
            sanitized = re.sub(r"[^\w\-_]", "_", str_value)
            if len(sanitized) > ValidationRules.MAX_ADR_ID_LENGTH:
                sanitized = sanitized[: ValidationRules.MAX_ADR_ID_LENGTH]
            return f"ADR-{sanitized}"

        return str_value

    @staticmethod
    def validate_analysis_mode(value: str) -> str:
        """Validate analysis mode."""
        lower_value = str(value).lower()
        if lower_value not in ValidationRules.VALID_ANALYSIS_MODES:
            raise ValueError(
                f"Invalid analysis mode '{value}'. Must be one of: {', '.join(ValidationRules.VALID_ANALYSIS_MODES)}"
            )
        return lower_value

    @staticmethod
    def validate_collection_size(collection: Any, max_size: int, name: str) -> None:
        """Validate collection size is within limits."""
        if hasattr(collection, "__len__"):
            size = len(collection)
            if size > max_size:
                raise ValueError(f"{name} exceeds maximum size: {size} > {max_size}")

    @staticmethod
    def validate_violation(violation: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize a violation entry."""
        validated = {}

        # Required fields
        if "file_path" in violation:
            validated["file_path"] = str(violation["file_path"])[: ValidationRules.MAX_FILE_PATH_LENGTH]

        if "adr_id" in violation:
            validated["adr_id"] = ValidationRules.validate_adr_id(violation["adr_id"])

        # Optional fields with validation
        if "line_number" in violation:
            try:
                validated["line_number"] = ValidationRules.validate_line_number(violation["line_number"])
            except ValueError:
                validated["line_number"] = 0  # Default for invalid

        if "risk_level" in violation:
            try:
                validated["risk_level"] = ValidationRules.validate_risk_level(violation["risk_level"])
            except ValueError:
                validated["risk_level"] = "medium"  # Default

        if "message" in violation and violation["message"]:
            validated["message"] = str(violation["message"])[: ValidationRules.MAX_MESSAGE_LENGTH]

        if "technical_debt_hours" in violation:
            try:
                validated["technical_debt_hours"] = ValidationRules.validate_numeric_range(
                    violation["technical_debt_hours"], ValidationRules.TECHNICAL_DEBT_RANGE, "technical_debt_hours"
                )
            except ValueError:
                validated["technical_debt_hours"] = 0.0

        return validated

    @staticmethod
    def validate_hotspot(hotspot: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize a hotspot entry."""
        validated = {}

        # Required fields
        if "file_path" in hotspot:
            validated["file_path"] = str(hotspot["file_path"])[: ValidationRules.MAX_FILE_PATH_LENGTH]

        # Risk scores
        if "risk_score" in hotspot:
            try:
                validated["risk_score"] = ValidationRules.validate_risk_score(hotspot["risk_score"])
            except ValueError:
                validated["risk_score"] = 50.0  # Default medium risk

        # Optional scores
        for score_field in ["churn_score", "complexity_score"]:
            if score_field in hotspot:
                try:
                    validated[score_field] = ValidationRules.validate_numeric_range(
                        hotspot[score_field], (0.0, 100.0), score_field
                    )
                except ValueError:
                    validated[score_field] = 0.0

        # Risk category
        if "risk_category" in hotspot:
            validated["risk_category"] = str(hotspot["risk_category"])[:50]

        return validated
