"""
Input validation module for secure report generation.

This module provides comprehensive input validation to prevent security
vulnerabilities such as path traversal, XSS, and injection attacks.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .validation_rules import ValidationRules

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom exception for validation failures."""

    pass


class InputValidator:
    """
    Validates input data for report generation.

    Implements defense-in-depth validation strategy with multiple
    security checks for all input types.
    """

    # Safe characters for file paths (alphanumeric, dots, dashes, underscores, slashes)
    PATH_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9._\-/]+$")

    # Maximum lengths to prevent DoS
    MAX_PATH_LENGTH = 4096
    MAX_STRING_LENGTH = 65536
    MAX_ARRAY_SIZE = 10000
    MAX_DICT_DEPTH = 10

    # Dangerous patterns to block - using safe detection instead of HTML parsing
    DANGEROUS_PATTERNS = [
        # Block any HTML-like tags entirely for security
        re.compile(r"<[^>]*>", re.IGNORECASE),  # Any HTML tags
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # onclick, onerror, etc.
        re.compile(r"@import", re.IGNORECASE),
        re.compile(r"expression\s*\(", re.IGNORECASE),  # CSS expression
        re.compile(r"vbscript:", re.IGNORECASE),
        re.compile(r"data:text/html", re.IGNORECASE),
    ]

    # SQL injection patterns - more targeted to avoid false positives
    SQL_PATTERNS = [
        # Match SQL keywords only when they appear to be actual SQL statements
        re.compile(r";\s*(union|select|insert|update|delete|drop|create)\s+", re.IGNORECASE),
        re.compile(r"(union\s+all\s+select|union\s+select)", re.IGNORECASE),
        re.compile(r"--\s*$"),  # SQL comment at end of line
        re.compile(r"/\*.*\*/"),  # SQL block comment
        re.compile(r"'\s*(or|and)\s*'?\d*'?\s*=", re.IGNORECASE),  # Common SQL injection
        re.compile(r"(drop\s+table|create\s+table|alter\s+table)", re.IGNORECASE),
        re.compile(r"(exec\s*\(|execute\s+immediate)", re.IGNORECASE),
    ]

    def __init__(self, strict_mode: bool = True):
        """
        Initialize the validator.

        Args:
            strict_mode: If True, applies strictest validation rules
        """
        self.strict_mode = strict_mode
        self._validation_stats = {
            "total_validations": 0,
            "passed": 0,
            "failed": 0,
            "blocked_patterns": [],
            "fields_removed": 0,
        }

    def validate_audit_data(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate complete audit data structure.

        Args:
            audit_data: Raw audit data from claude_code_auditor

        Returns:
            Validated and sanitized audit data

        Raises:
            ValidationError: If validation fails
        """
        self._validation_stats["total_validations"] += 1

        try:
            # Check data size first
            self._validate_data_size(audit_data)

            # Start with empty validated data
            validated = {}

            # Specific validation for known fields (which handle sanitization)
            if "all_violations" in audit_data:
                validated["all_violations"] = self._validate_violations(audit_data["all_violations"])

            if "architectural_hotspots" in audit_data:
                validated["architectural_hotspots"] = self._validate_hotspots(audit_data["architectural_hotspots"])

            if "audit_metadata" in audit_data:
                validated["audit_metadata"] = self._validate_metadata(audit_data["audit_metadata"])

            # For any other fields, use generic validation
            for key, value in audit_data.items():
                if key not in ["all_violations", "architectural_hotspots", "audit_metadata"]:
                    try:
                        validated[key] = self._validate_dict({key: value}, depth=0)[key]
                    except ValidationError as e:
                        # Skip fields that fail validation but log the issue
                        logger.debug(f"Skipping field '{key}' due to validation error: {str(e)}")
                        self._validation_stats["fields_removed"] += 1

            # Check if we have any recognizable audit data at all
            if not any(key in validated for key in ["all_violations", "architectural_hotspots", "audit_metadata"]):
                raise ValidationError(
                    "Audit data must contain at least one of: all_violations, architectural_hotspots, audit_metadata"
                )

            self._validation_stats["passed"] += 1
            return validated

        except ValidationError:
            # Re-raise validation errors as-is (they're safe to expose)
            self._validation_stats["failed"] += 1
            raise
        except Exception as e:
            self._validation_stats["failed"] += 1
            # Log detailed error internally without exposing to user
            logger.error(f"Validation failed: {e}", exc_info=True)
            # Return generic error message to prevent information disclosure
            raise ValidationError("Audit data validation failed: Invalid or malformed audit data")

    def validate_file_path(self, path: Union[str, Path]) -> Path:
        """
        Validate file path for security.

        Args:
            path: File path to validate

        Returns:
            Validated Path object

        Raises:
            ValidationError: If path is invalid or dangerous
        """
        if not path:
            raise ValidationError("Path cannot be empty")

        path_str = str(path)

        # Check length
        if len(path_str) > self.MAX_PATH_LENGTH:
            raise ValidationError(f"Path too long: {len(path_str)} > {self.MAX_PATH_LENGTH}")

        # Check for directory traversal and absolute paths
        if ".." in path_str:
            raise ValidationError("Path traversal detected")

        # Block absolute paths (security risk)
        if path_str.startswith("/") or (len(path_str) > 2 and path_str[1] == ":"):
            raise ValidationError("Absolute paths not allowed")

        # Check for null bytes
        if "\x00" in path_str:
            raise ValidationError("Null byte in path")

        # In strict mode, only allow safe characters
        if self.strict_mode and not self.PATH_SAFE_PATTERN.match(path_str):
            raise ValidationError("Path contains unsafe characters")

        # Convert to Path but don't resolve to keep relative paths
        try:
            validated_path = Path(path_str)

            return validated_path

        except Exception as e:
            # Log detailed error internally without exposing to user
            logger.error("Path validation failed", path=path_str, error=str(e))
            raise ValidationError("Invalid file path")

    def validate_string(self, value: str, field_name: str = "string") -> str:
        """
        Validate string for XSS and injection attacks.

        Args:
            value: String to validate
            field_name: Name of field for error messages

        Returns:
            Validated string

        Raises:
            ValidationError: If string contains dangerous content
        """
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")

        # Check length
        if len(value) > self.MAX_STRING_LENGTH:
            raise ValidationError(f"{field_name} too long: {len(value)} > {self.MAX_STRING_LENGTH}")

        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(value):
                self._validation_stats["blocked_patterns"].append(pattern.pattern)
                raise ValidationError(f"{field_name} contains dangerous pattern: {pattern.pattern}")

        # Check for SQL injection patterns in strict mode
        if self.strict_mode:
            for pattern in self.SQL_PATTERNS:
                if pattern.search(value):
                    self._validation_stats["blocked_patterns"].append(pattern.pattern)
                    raise ValidationError(f"{field_name} contains SQL pattern: {pattern.pattern}")

        # Check for control characters
        if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
            raise ValidationError(f"{field_name} contains control characters")

        return value

    def validate_json_data(self, data: Union[str, Dict, List]) -> Union[Dict, List]:
        """
        Validate JSON data structure.

        Args:
            data: JSON string or parsed data

        Returns:
            Validated data structure

        Raises:
            ValidationError: If JSON is invalid or contains dangerous content
        """
        # Parse if string
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError as e:
                # Log detailed error internally without exposing to user
                logger.error("JSON parsing failed", error=str(e), data_length=len(data))
                raise ValidationError("Invalid JSON format")
        else:
            parsed = data

        # Validate the structure
        if isinstance(parsed, dict):
            return self._validate_dict(parsed, depth=0)
        elif isinstance(parsed, list):
            return self._validate_list(parsed, depth=0)
        else:
            raise ValidationError("JSON must be object or array")

    def _validate_dict(self, data: Dict[str, Any], depth: int) -> Dict[str, Any]:
        """Recursively validate dictionary."""
        if depth > self.MAX_DICT_DEPTH:
            raise ValidationError(f"Dictionary too deep: {depth} > {self.MAX_DICT_DEPTH}")

        validated = {}
        for key, value in data.items():
            # Validate key
            if not isinstance(key, str):
                raise ValidationError(f"Dictionary key must be string: {type(key)}")

            # Keys don't need full validation - just basic safety check
            if len(key) > 256 or "\x00" in key:
                raise ValidationError(f"Invalid dictionary key: {key}")
            validated_key = key

            # Validate value based on type
            if isinstance(value, str):
                validated[validated_key] = self.validate_string(value, f"value:{key}")
            elif isinstance(value, dict):
                validated[validated_key] = self._validate_dict(value, depth + 1)
            elif isinstance(value, list):
                validated[validated_key] = self._validate_list(value, depth + 1)
            elif isinstance(value, (int, float, bool, type(None))):
                validated[validated_key] = value
            else:
                # Convert other types to string and validate
                validated[validated_key] = self.validate_string(str(value), f"value:{key}")

        return validated

    def _validate_list(self, data: List[Any], depth: int) -> List[Any]:
        """Recursively validate list."""
        if len(data) > self.MAX_ARRAY_SIZE:
            raise ValidationError(f"Array too large: {len(data)} > {self.MAX_ARRAY_SIZE}")

        validated = []
        for i, item in enumerate(data):
            if isinstance(item, str):
                validated.append(self.validate_string(item, f"item[{i}]"))
            elif isinstance(item, dict):
                validated.append(self._validate_dict(item, depth + 1))
            elif isinstance(item, list):
                validated.append(self._validate_list(item, depth + 1))
            elif isinstance(item, (int, float, bool, type(None))):
                validated.append(item)
            else:
                validated.append(self.validate_string(str(item), f"item[{i}]"))

        return validated

    def _validate_violations(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate violation entries."""
        # First validate that violations is actually a list
        if not isinstance(violations, list):
            raise ValidationError(f"violations must be a list, got {type(violations).__name__}")

        # Check collection size
        ValidationRules.validate_collection_size(violations, ValidationRules.MAX_VIOLATIONS_COUNT, "violations")

        validated = []
        for violation in violations:
            if not isinstance(violation, dict):
                continue

            try:
                # Use comprehensive validation from rules
                validated_violation = ValidationRules.validate_violation(violation)

                # Additional file path validation with our security checks
                if "file_path" in validated_violation:
                    try:
                        validated_violation["file_path"] = str(
                            self.validate_file_path(validated_violation["file_path"])
                        )
                    except ValidationError:
                        validated_violation["file_path"] = "unknown"

                # Validate additional string fields
                string_fields = ["message", "adr_title", "evidence", "remediation_guidance"]
                for field in string_fields:
                    if field in violation and violation[field]:
                        try:
                            validated_violation[field] = self.validate_string(str(violation[field]), field)
                        except ValidationError:
                            validated_violation[field] = "[Content sanitized]"

                validated.append(validated_violation)

            except Exception as e:
                logger.warning(f"Skipping invalid violation: {str(e)}")
                continue

        return validated

    def _validate_hotspots(self, hotspots: List[Any]) -> List[Dict[str, Any]]:
        """Validate hotspot entries."""
        # Check collection size
        ValidationRules.validate_collection_size(hotspots, ValidationRules.MAX_HOTSPOTS_COUNT, "hotspots")

        validated = []

        for hotspot in hotspots:
            if isinstance(hotspot, dict):
                try:
                    # Use comprehensive validation from rules
                    validated_hotspot = ValidationRules.validate_hotspot(hotspot)

                    # Additional file path validation with our security checks
                    if "file_path" in validated_hotspot:
                        try:
                            validated_hotspot["file_path"] = str(
                                self.validate_file_path(validated_hotspot["file_path"])
                            )
                        except ValidationError:
                            validated_hotspot["file_path"] = "unknown"

                    # Copy additional numeric fields not in basic validation
                    numeric_fields = ["integrated_risk_probability", "temporal_weight"]
                    for field in numeric_fields:
                        if field in hotspot and isinstance(hotspot[field], (int, float)):
                            validated_hotspot[field] = float(hotspot[field])

                    # Validate arrays
                    if "violation_history" in hotspot and isinstance(hotspot["violation_history"], list):
                        validated_hotspot["violation_history"] = self._validate_list(
                            hotspot["violation_history"][:10], depth=1  # Limit size
                        )

                    validated.append(validated_hotspot)

                except Exception as e:
                    logger.warning(f"Skipping invalid hotspot: {str(e)}")
                    # Handle as basic hotspot
                    validated.append({"file_path": str(hotspot), "type": "basic"})
            else:
                # Handle other hotspot types
                validated.append({"file_path": str(hotspot), "type": "basic"})

        return validated

    def _validate_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Validate audit metadata."""
        validated = {}

        # Numeric fields with validation
        numeric_validations = {
            "total_files_analyzed": (0, 1000000),
            "execution_time_seconds": (0.0, 86400.0),  # Max 24 hours
            "cache_hits": (0, 1000000),
            "cache_misses": (0, 1000000),
            "total_adrs_analyzed": (0, 10000),
        }

        for field, (min_val, max_val) in numeric_validations.items():
            if field in metadata:
                try:
                    value = float(metadata[field])
                    if min_val <= value <= max_val:
                        validated[field] = value
                    else:
                        logger.warning(f"Metadata field '{field}' out of range: {value}")
                        validated[field] = min(max(value, min_val), max_val)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid numeric metadata field '{field}': {metadata[field]}")

        # String fields that need validation
        string_fields = ["repository_path", "analysis_timestamp", "git_branch"]
        for field in string_fields:
            if field in metadata and metadata[field]:
                try:
                    validated[field] = self.validate_string(str(metadata[field]), field)
                except ValidationError:
                    validated[field] = "[Sanitized]"

        # Analysis mode validation
        if "mode" in metadata:
            try:
                validated["mode"] = ValidationRules.validate_analysis_mode(metadata["mode"])
            except ValueError:
                validated["mode"] = "audit"  # Default

        # ADR ID validation
        if "selected_adr" in metadata and metadata["selected_adr"]:
            try:
                validated["selected_adr"] = ValidationRules.validate_adr_id(metadata["selected_adr"])
            except ValueError:
                validated["selected_adr"] = None

        # Version string
        if "audit_version" in metadata:
            version = str(metadata["audit_version"])[:20]  # Limit length
            validated["audit_version"] = re.sub(r"[^\w\.\-]", "", version)

        return validated

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return self._validation_stats.copy()

    def _validate_data_size(self, data: Any, max_size_mb: int = 50) -> None:
        """
        Check if data size is within acceptable limits.

        Args:
            data: Data to check
            max_size_mb: Maximum allowed size in MB

        Raises:
            ValidationError: If data is too large
        """
        import sys

        try:
            # Get size of object in bytes
            size_bytes = sys.getsizeof(json.dumps(data))
            size_mb = size_bytes / (1024 * 1024)

            if size_mb > max_size_mb:
                raise ValidationError(f"Data size ({size_mb:.2f} MB) exceeds maximum allowed size ({max_size_mb} MB)")

            logger.debug(f"Data size validation passed: {size_mb:.2f} MB")

        except (TypeError, ValueError) as e:
            # If we can't serialize to JSON, estimate size differently
            logger.warning(f"Could not determine exact data size: {str(e)}")
            # Fall back to basic object size check
            size_bytes = sys.getsizeof(data)
            size_mb = size_bytes / (1024 * 1024)

            # Be more conservative with the estimate
            if size_mb > max_size_mb / 2:
                raise ValidationError(f"Estimated data size ({size_mb:.2f} MB) may exceed limits")
