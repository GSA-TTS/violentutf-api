"""
JSON report generator with schema validation.

This module enhances the basic JSON output from claude_code_auditor.py
with schema validation, proper structure, and security features.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# JSON Schema validation
try:
    import jsonschema
    from jsonschema import ValidationError as JSONSchemaError
    from jsonschema import validate

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    JSONSchemaError = Exception

from ..base import ReportConfig, ReportDataProcessor, ReportGenerator
from ..hotspot_integration import HotspotDataTransformer
from ..security import HotspotSanitizer, InputValidator, OutputEncoder

logger = logging.getLogger(__name__)


class JSONReportGenerator(ReportGenerator):
    """
    Generates secure JSON reports with schema validation.

    Enhances the basic JSON output from claude_code_auditor.py
    with proper validation, structure, and different detail levels.
    """

    # JSON Schema for report validation
    REPORT_SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["metadata", "summary", "violations"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["report_id", "timestamp", "audit_version"],
                "properties": {
                    "report_id": {"type": "string", "format": "uuid"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "audit_version": {"type": "string"},
                    "repository_path": {"type": "string"},
                    "total_files_analyzed": {"type": "integer", "minimum": 0},
                    "analysis_duration": {"type": "number", "minimum": 0},
                },
            },
            "summary": {
                "type": "object",
                "required": ["compliance_score", "total_violations"],
                "properties": {
                    "compliance_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 100,
                    },
                    "total_violations": {"type": "integer", "minimum": 0},
                    "critical_violations": {"type": "integer", "minimum": 0},
                    "high_violations": {"type": "integer", "minimum": 0},
                    "medium_violations": {"type": "integer", "minimum": 0},
                    "low_violations": {"type": "integer", "minimum": 0},
                    "technical_debt_hours": {"type": "number", "minimum": 0},
                    "technical_debt_days": {"type": "number", "minimum": 0},
                    "risk_assessment": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    },
                },
            },
            "violations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["file_path", "adr_id"],
                    "properties": {
                        "file_path": {"type": "string"},
                        "line_number": {"type": ["integer", "null"]},
                        "adr_id": {"type": "string"},
                        "risk_level": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "unknown"],
                        },
                        "message": {"type": "string"},
                        "category": {"type": "string"},
                        "impact_assessment": {"type": "string"},
                        "fix_complexity": {"type": "string"},
                    },
                },
            },
            "hotspot_analysis": {
                "type": "object",
                "properties": {
                    "hotspots": {"type": "array"},
                    "statistics": {"type": "object"},
                    "temporal_trends": {"type": "object"},
                    "risk_distribution": {"type": "object"},
                },
            },
            "recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "description": {"type": "string"},
                        "priority": {"type": "string"},
                        "category": {"type": "string"},
                        "estimated_effort": {"type": "string"},
                    },
                },
            },
        },
    }

    def __init__(self, config: ReportConfig):
        """Initialize JSON generator."""
        super().__init__(config)

        # Security components
        self.validator = InputValidator()
        self.encoder = OutputEncoder()
        self.hotspot_sanitizer = HotspotSanitizer(security_level=config.security_level.value)

        # Override hotspot sanitizer to use JSON-safe encoding instead of HTML encoding
        self.hotspot_sanitizer.encoder.encode_for_html = lambda x: str(x)  # No HTML encoding for JSON

        # Data processors
        self.data_processor = ReportDataProcessor()
        self.hotspot_transformer = HotspotDataTransformer()

        # Check schema validation availability
        if not HAS_JSONSCHEMA:
            logger.warning("jsonschema not available - schema validation disabled")

    def generate(self, audit_data: Dict[str, Any]) -> Path:
        """
        Generate JSON report from audit data.

        Args:
            audit_data: Validated audit data

        Returns:
            Path to generated JSON report
        """
        try:
            # Validate data size
            self.validator._validate_data_size(audit_data, self.config.max_input_size_mb)

            # Validate input data
            validated_data = self.validator.validate_audit_data(audit_data)

            # Process data for reporting
            report_data = self.data_processor.prepare_report_data(validated_data)

            # Add hotspot analysis if available
            if self.config.include_hotspots and "architectural_hotspots" in validated_data:
                hotspot_analysis = self.hotspot_transformer.create_hotspot_analysis_result(
                    validated_data,
                    {
                        "security_level": self.config.security_level.value,
                        "max_hotspots_display": self.config.max_hotspots_display,
                    },
                )

                # Sanitize hotspot data
                report_data["hotspot_analysis"] = {
                    "hotspots": self.hotspot_sanitizer.sanitize_hotspot_list(hotspot_analysis.hotspots),
                    "statistics": hotspot_analysis.statistical_summary,
                    "temporal_trends": hotspot_analysis.temporal_trends,
                    "risk_distribution": hotspot_analysis.risk_distribution,
                    "metadata": hotspot_analysis.analysis_metadata,
                }

            # Filter data based on security level
            filtered_data = self._filter_by_security_level(report_data)

            # Add report metadata
            filtered_data["_report_metadata"] = {
                "generator": "JSONReportGenerator",
                "version": "2.0.0",
                "security_level": self.config.security_level.value,
                "schema_version": "1.0.0",
            }

            # Validate against schema if available
            if HAS_JSONSCHEMA:
                try:
                    validate(instance=filtered_data, schema=self.REPORT_SCHEMA)
                except JSONSchemaError as e:
                    logger.warning(f"Schema validation failed: {str(e)}")
                    # Continue anyway - validation is informative

            # Generate output with proper formatting
            output_path = self._get_output_path("json")

            with open(output_path, "w", encoding="utf-8") as f:
                if self.config.security_level == "public":
                    # Minimal output for public
                    json.dump(filtered_data, f, indent=2, ensure_ascii=True)
                else:
                    # Pretty print for internal use - still use ensure_ascii for security
                    json.dump(
                        filtered_data,
                        f,
                        indent=2,
                        ensure_ascii=True,
                        sort_keys=True,
                        default=self._json_serializer,
                    )

            logger.info(f"JSON report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"JSON generation failed: {str(e)}")
            raise

    def validate_data(self, audit_data: Dict[str, Any]) -> bool:
        """Validate audit data structure."""
        try:
            self.validator.validate_audit_data(audit_data)

            # Additional JSON-specific validation
            json.dumps(audit_data, default=self._json_serializer)

            return True
        except Exception:
            return False

    def _generate_hotspot_section(self, hotspot_data: Any) -> Dict[str, Any]:
        """Generate hotspot analysis section for JSON."""
        if not hotspot_data:
            return {}

        return {
            "summary": hotspot_data.get("temporal_trends", {}).get("summary", ""),
            "total_hotspots": len(hotspot_data.get("hotspots", [])),
            "risk_distribution": hotspot_data.get("risk_distribution", {}),
            "top_hotspots": hotspot_data.get("hotspots", [])[:10],
        }

    def _filter_by_security_level(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter report data based on security level.

        Args:
            data: Complete report data

        Returns:
            Filtered data appropriate for security level
        """
        if self.config.security_level.value == "full":
            # Return everything for administrators
            return data

        filtered = data.copy()

        if self.config.security_level.value == "public":
            # Minimal data for public consumption

            # Redact sensitive paths
            if "violations" in filtered:
                for violation in filtered["violations"]:
                    if "file_path" in violation:
                        violation["file_path"] = self._redact_path(violation["file_path"])
                    # Remove detailed messages
                    if "message" in violation:
                        violation["message"] = "Details redacted"
                    if "evidence" in violation:
                        del violation["evidence"]

            # Simplify hotspot data
            if "hotspot_analysis" in filtered:
                filtered["hotspot_analysis"] = {
                    "summary": filtered["hotspot_analysis"].get("statistics", {}),
                    "risk_distribution": filtered["hotspot_analysis"].get("risk_distribution", {}),
                    "total_count": len(filtered["hotspot_analysis"].get("hotspots", [])),
                }

            # Remove detailed recommendations
            if "recommendations" in filtered:
                filtered["recommendations"] = [
                    {
                        "priority": rec.get("priority", "medium"),
                        "category": rec.get("category", "general"),
                    }
                    for rec in filtered["recommendations"][:5]
                ]

            # Remove trends details
            if "trends" in filtered:
                filtered["trends"] = {
                    "total_unique_adrs": filtered["trends"].get("total_unique_adrs", 0),
                    "total_affected_files": filtered["trends"].get("total_affected_files", 0),
                }

        elif self.config.security_level.value == "internal":
            # Internal use - some details hidden

            # Truncate violation messages
            if "violations" in filtered:
                for violation in filtered["violations"]:
                    if "message" in violation and len(violation["message"]) > 200:
                        violation["message"] = violation["message"][:200] + "..."

            # Limit hotspots
            if "hotspot_analysis" in filtered and "hotspots" in filtered["hotspot_analysis"]:
                filtered["hotspot_analysis"]["hotspots"] = filtered["hotspot_analysis"]["hotspots"][:50]

        return filtered

    def _redact_path(self, path: str) -> str:
        """Redact sensitive path information."""
        parts = Path(path).parts
        if len(parts) <= 2:
            return f"[{len(parts)}-level-path]"

        # Show only depth and extension
        ext = Path(path).suffix
        return f"[{len(parts)}-level-path]{ext}"

    def _json_serializer(self, obj: Any) -> Any:
        """
        Custom JSON serializer for non-standard types.

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, "to_dict"):
            return obj.to_dict()
        elif hasattr(obj, "__dict__"):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
        else:
            # Fallback to string representation
            return str(obj)

    def generate_streaming(self, audit_data: Dict[str, Any]) -> Path:
        """
        Generate JSON report with streaming for large datasets.

        Args:
            audit_data: Validated audit data

        Returns:
            Path to generated JSON report
        """
        output_path = self._get_output_path("json")

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("{\n")

                # Write metadata
                f.write('  "metadata": ')
                json.dump(
                    self.data_processor._generate_metadata(audit_data),
                    f,
                    indent=2,
                    default=self._json_serializer,
                )
                f.write(",\n")

                # Write summary
                f.write('  "summary": ')
                json.dump(
                    self.data_processor._generate_summary(audit_data),
                    f,
                    indent=2,
                    default=self._json_serializer,
                )
                f.write(",\n")

                # Stream violations
                f.write('  "violations": [\n')
                violations = audit_data.get("all_violations", [])
                for i, violation in enumerate(violations):
                    validated_violation = self.validator._validate_violations([violation])[0]
                    f.write("    ")
                    json.dump(validated_violation, f, default=self._json_serializer)
                    if i < len(violations) - 1:
                        f.write(",")
                    f.write("\n")
                f.write("  ]\n")

                f.write("}\n")

            logger.info(f"Streaming JSON report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Streaming JSON generation failed: {str(e)}")
            # Clean up partial file
            if output_path.exists():
                output_path.unlink()
            raise
