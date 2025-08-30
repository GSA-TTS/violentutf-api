"""
HTML report generator with enhanced security and visualization.

This module replaces the basic HTML generation in claude_code_auditor.py
with a secure, template-based approach using Jinja2 sandboxed environment.
"""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Jinja2 with sandboxed environment for security
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from ..base import ReportConfig, ReportDataProcessor, ReportGenerator
from ..hotspot_integration import HotspotDataTransformer
from ..security import HotspotSanitizer, InputValidator, OutputEncoder, ValidationError

logger = logging.getLogger(__name__)


class HTMLReportGenerator(ReportGenerator):
    """
    Generates secure HTML reports with visualizations.

    Replaces the unsafe string concatenation in claude_code_auditor.py
    with a template-based approach using Jinja2's sandboxed environment.
    """

    def __init__(self, config: ReportConfig):
        """Initialize HTML generator with templates."""
        super().__init__(config)

        # Security components
        self.validator = InputValidator()
        self.encoder = OutputEncoder()
        self.hotspot_sanitizer = HotspotSanitizer(security_level=config.security_level.value)

        # Data processors
        self.data_processor = ReportDataProcessor()
        self.hotspot_transformer = HotspotDataTransformer()

        # Setup Jinja2 sandboxed environment
        self._setup_template_environment()

        # Note: Statistics removed for thread safety
        # Each generate() call is stateless

    def _setup_template_environment(self):
        """Setup Jinja2 sandboxed environment for secure templating."""
        # Determine template directory
        template_dir = Path(__file__).parent.parent / "templates"
        if not template_dir.exists():
            # Create basic template directory
            template_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_templates(template_dir)

        # Use sandboxed environment for security
        self.env = SandboxedEnvironment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Add custom filters
        self.env.filters["format_timestamp"] = self._format_timestamp
        self.env.filters["format_number"] = self._format_number
        self.env.filters["format_percentage"] = self._format_percentage
        self.env.filters["risk_color"] = self._get_risk_color
        self.env.filters["risk_icon"] = self._get_risk_icon

        # Add custom functions
        self.env.globals["static_url"] = self._static_url

    def generate(self, audit_data: Dict[str, Any]) -> Path:
        """
        Generate HTML report from audit data.

        Args:
            audit_data: Validated audit data

        Returns:
            Path to generated HTML report
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

            # Add configuration context
            report_data["config"] = {
                "security_level": self.config.security_level.value,
                "include_charts": self.config.enable_charts,
                "include_recommendations": self.config.include_recommendations,
                "include_executive_summary": self.config.include_executive_summary,
                "max_violations_per_page": getattr(self.config, "max_violations_per_page", 100),
            }

            # Generate visualizations if enabled
            if self.config.enable_charts:
                report_data["charts"] = self._generate_chart_data(report_data)

            # Render template
            template = self.env.get_template("audit_report.html")
            html_content = template.render(**report_data)

            # Save report with secure permissions
            output_path = self._get_output_path("html")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Set secure file permissions (owner read/write only)
            os.chmod(output_path, 0o600)

            # Copy static files to output directory
            self._copy_static_files(output_path.parent)

            logger.info(f"HTML report generated: {output_path}")

            return output_path

        except Exception as e:
            logger.error(f"HTML generation failed: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def validate_data(self, audit_data: Dict[str, Any]) -> bool:
        """Validate audit data structure."""
        try:
            self.validator.validate_audit_data(audit_data)
            return True
        except ValidationError:
            return False

    def _generate_hotspot_section(self, hotspot_data: Any) -> str:
        """Generate hotspot analysis section."""
        if not hotspot_data:
            return ""

        # Use template for hotspot section
        template = self.env.get_template("sections/hotspot_analysis.html")
        return template.render(hotspot_data=hotspot_data)

    def _generate_chart_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data for client-side charts."""
        charts = {}

        # Compliance score gauge
        charts["compliance_gauge"] = {
            "type": "gauge",
            "data": {
                "value": report_data["summary"]["compliance_score"],
                "min": 0,
                "max": 100,
                "thresholds": {"critical": 60, "warning": 80, "good": 90},
            },
        }

        # Violation distribution pie chart
        risk_counts = {
            "Critical": report_data["summary"]["critical_violations"],
            "High": report_data["summary"]["high_violations"],
            "Medium": report_data["summary"]["medium_violations"],
            "Low": report_data["summary"]["low_violations"],
        }

        charts["violation_pie"] = {
            "type": "pie",
            "data": {
                "labels": list(risk_counts.keys()),
                "values": list(risk_counts.values()),
                "colors": ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c"],
            },
        }

        # Top violated files bar chart
        if "trends" in report_data and "violations_by_file" in report_data["trends"]:
            files = list(report_data["trends"]["violations_by_file"].keys())[:10]
            counts = [report_data["trends"]["violations_by_file"][f] for f in files]

            charts["top_files_bar"] = {
                "type": "bar",
                "data": {
                    "labels": [self._truncate_path(f) for f in files],
                    "values": counts,
                    "color": "#1976d2",
                },
            }

        # Hotspot risk heatmap
        if "hotspot_analysis" in report_data:
            hotspots = report_data["hotspot_analysis"]["hotspots"][:20]

            charts["hotspot_heatmap"] = {
                "type": "heatmap",
                "data": {
                    "labels": [self._truncate_path(h["file_path"]) for h in hotspots],
                    "values": [h["risk_score"] for h in hotspots],
                    "colorScale": "Reds",
                },
            }

            # Temporal trends
            trends = report_data["hotspot_analysis"]["temporal_trends"]["percentages"]
            charts["temporal_trends"] = {
                "type": "doughnut",
                "data": {
                    "labels": ["Improving", "Stable", "Degrading"],
                    "values": [
                        trends.get("improving", 0),
                        trends.get("stable", 0),
                        trends.get("degrading", 0),
                    ],
                    "colors": ["#4caf50", "#ff9800", "#f44336"],
                },
            }

        # Charts created: len(charts)

        # Encode chart data for safe embedding
        for chart_id, chart_data in charts.items():
            # Create a copy without the json field to avoid circular reference
            clean_data = {k: v for k, v in chart_data.items() if k != "json"}
            # Store the JSON serialization of the clean data
            charts[chart_id]["json"] = json.dumps(clean_data, ensure_ascii=True)

        return charts

    def _create_default_templates(self, template_dir: Path):
        """Create default HTML templates if they don't exist."""
        # Main report template
        main_template = template_dir / "audit_report.html"
        if not main_template.exists():
            main_template.write_text(self._get_default_main_template())

        # Create sections directory
        sections_dir = template_dir / "sections"
        sections_dir.mkdir(exist_ok=True)

        # Executive summary section
        exec_summary = sections_dir / "executive_summary.html"
        if not exec_summary.exists():
            exec_summary.write_text(self._get_default_executive_summary_template())

        # Hotspot analysis section
        hotspot_section = sections_dir / "hotspot_analysis.html"
        if not hotspot_section.exists():
            hotspot_section.write_text(self._get_default_hotspot_template())

        # Violations section
        violations_section = sections_dir / "violations.html"
        if not violations_section.exists():
            violations_section.write_text(self._get_default_violations_template())

    def _get_default_main_template(self) -> str:
        """Get default main report template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Security Headers -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">

    <title>Architectural Audit Report - {{ metadata.timestamp|format_timestamp }}</title>
    <style>
        :root {
            --primary-color: #1976d2;
            --success-color: #4caf50;
            --warning-color: #ff9800;
            --danger-color: #f44336;
            --text-color: #333;
            --bg-color: #f5f5f5;
            --card-bg: #ffffff;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background: var(--bg-color);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: var(--card-bg);
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .header h1 {
            color: var(--primary-color);
            margin-bottom: 10px;
        }

        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .metadata-item {
            background: var(--bg-color);
            padding: 10px 15px;
            border-radius: 4px;
        }

        .metadata-item label {
            font-weight: 600;
            color: #666;
            font-size: 0.9em;
        }

        .compliance-score {
            font-size: 3em;
            font-weight: 700;
            color: {{ summary.compliance_score|risk_color }};
            text-align: center;
            margin: 20px 0;
        }

        .section {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 25px;
        }

        .section h2 {
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--bg-color);
        }

        .chart-container {
            height: 400px;
            margin: 20px 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background: var(--bg-color);
            font-weight: 600;
            color: #666;
        }

        tr:hover {
            background: var(--bg-color);
        }

        .risk-critical { color: var(--danger-color); }
        .risk-high { color: #ff5722; }
        .risk-medium { color: var(--warning-color); }
        .risk-low { color: var(--success-color); }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge-critical { background: #ffebee; color: var(--danger-color); }
        .badge-high { background: #fff3e0; color: #ff5722; }
        .badge-medium { background: #fff8e1; color: var(--warning-color); }
        .badge-low { background: #e8f5e9; color: var(--success-color); }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            .section {
                padding: 15px;
            }
        }

        @media print {
            body {
                background: white;
            }
            .section {
                box-shadow: none;
                page-break-inside: avoid;
            }
        }
    </style>
    <script src="static/js/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Architectural Audit Report</h1>
            <div class="compliance-score">
                {{ summary.compliance_score|format_percentage }}
            </div>
            <div class="metadata">
                <div class="metadata-item">
                    <label>Generated</label>
                    <div>{{ metadata.timestamp|format_timestamp }}</div>
                </div>
                <div class="metadata-item">
                    <label>Repository</label>
                    <div>{{ metadata.repository_path }}</div>
                </div>
                <div class="metadata-item">
                    <label>Files Analyzed</label>
                    <div>{{ metadata.total_files_analyzed|format_number }}</div>
                </div>
                <div class="metadata-item">
                    <label>Analysis Time</label>
                    <div>{{ metadata.analysis_duration|format_number }}s</div>
                </div>
            </div>
        </div>

        {% if config.include_executive_summary %}
            {% include 'sections/executive_summary.html' %}
        {% endif %}

        {% if hotspot_analysis %}
            {% include 'sections/hotspot_analysis.html' %}
        {% endif %}

        {% include 'sections/violations.html' %}

        {% if config.include_recommendations and recommendations %}
        <section class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                {% for rec in recommendations[:10] %}
                <div class="recommendation">
                    <h4>{{ rec.id }}: {{ rec.description }}</h4>
                    <p><strong>Priority:</strong> <span class="badge badge-{{ rec.priority }}">{{ rec.priority|upper }}</span></p>
                    <p><strong>Category:</strong> {{ rec.category }}</p>
                    <p><strong>Estimated Effort:</strong> {{ rec.estimated_effort }}</p>
                </div>
                {% endfor %}
            </div>
        </section>
        {% endif %}
    </div>

    {% if config.include_charts and charts %}
    <script>
        // Render charts
        document.addEventListener('DOMContentLoaded', function() {
            {% for chart_id, chart in charts.items() %}
            try {
                const {{ chart_id }}_data = JSON.parse({{ chart.json|tojson }});
                // Chart rendering code would go here
            } catch (e) {
                console.error('Chart rendering error:', e);
            }
            {% endfor %}
        });
    </script>
    {% endif %}
</body>
</html>"""

    def _get_default_executive_summary_template(self) -> str:
        """Get default executive summary template."""
        return """<section class="section executive-summary">
    <h2>Executive Summary</h2>

    <div class="key-findings">
        <h3>Key Findings</h3>
        <ul>
        {% for finding in summary.key_findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </div>

    <div class="risk-summary">
        <h3>Risk Assessment: <span class="risk-{{ summary.risk_assessment|lower }}">{{ summary.risk_assessment }}</span></h3>

        <table>
            <thead>
                <tr>
                    <th>Risk Level</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="risk-critical">Critical</td>
                    <td>{{ summary.critical_violations|format_number }}</td>
                    <td>{{ (summary.critical_violations / summary.total_violations * 100)|format_percentage if summary.total_violations > 0 else '0%' }}</td>
                </tr>
                <tr>
                    <td class="risk-high">High</td>
                    <td>{{ summary.high_violations|format_number }}</td>
                    <td>{{ (summary.high_violations / summary.total_violations * 100)|format_percentage if summary.total_violations > 0 else '0%' }}</td>
                </tr>
                <tr>
                    <td class="risk-medium">Medium</td>
                    <td>{{ summary.medium_violations|format_number }}</td>
                    <td>{{ (summary.medium_violations / summary.total_violations * 100)|format_percentage if summary.total_violations > 0 else '0%' }}</td>
                </tr>
                <tr>
                    <td class="risk-low">Low</td>
                    <td>{{ summary.low_violations|format_number }}</td>
                    <td>{{ (summary.low_violations / summary.total_violations * 100)|format_percentage if summary.total_violations > 0 else '0%' }}</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="technical-debt">
        <h3>Technical Debt</h3>
        <p>Estimated effort to resolve all violations: <strong>{{ summary.technical_debt_days|format_number }} days</strong></p>
    </div>
</section>"""

    def _get_default_hotspot_template(self) -> str:
        """Get default hotspot analysis template."""
        return """<section class="section hotspot-analysis">
    <h2>Architectural Hotspots</h2>

    <div class="hotspot-summary">
        <h3>Summary</h3>
        <p>{{ hotspot_analysis.temporal_trends.summary }}</p>

        <div class="stats-grid">
            <div class="stat">
                <label>Total Hotspots</label>
                <div class="value">{{ hotspot_analysis.statistics.total_hotspots }}</div>
            </div>
            <div class="stat">
                <label>Critical Risk</label>
                <div class="value risk-critical">{{ hotspot_analysis.statistics.critical_count }}</div>
            </div>
            <div class="stat">
                <label>Average Risk</label>
                <div class="value">{{ (hotspot_analysis.statistics.average_risk * 100)|format_percentage }}</div>
            </div>
        </div>
    </div>

    {% if hotspot_analysis.hotspots %}
    <div class="hotspot-list">
        <h3>Top Risk Areas</h3>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Risk Score</th>
                    <th>Confidence</th>
                    <th>Violations</th>
                    <th>Category</th>
                </tr>
            </thead>
            <tbody>
                {% for hotspot in hotspot_analysis.hotspots[:20] %}
                <tr>
                    <td>{{ hotspot.file_path }}</td>
                    <td class="risk-{{ hotspot.risk_category|lower }}">
                        {{ (hotspot.risk_score * 100)|format_percentage }}
                    </td>
                    <td>{{ hotspot.confidence|default('N/A') }}</td>
                    <td>{{ hotspot.violation_count|format_number }}</td>
                    <td>
                        <span class="badge badge-{{ hotspot.risk_category|lower }}">
                            {{ hotspot.risk_category }}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if config.include_charts %}
    <div class="chart-container" id="temporal-trends-chart"></div>
    <div class="chart-container" id="hotspot-heatmap"></div>
    {% endif %}
</section>"""

    def _get_default_violations_template(self) -> str:
        """Get default violations template."""
        return """<section class="section violations">
    <h2>ADR Violations</h2>

    <div class="violations-summary">
        <p>Total violations found: <strong>{{ summary.total_violations|format_number }}</strong></p>
    </div>

    {% if violations %}
    <div class="violations-table">
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Line</th>
                    <th>ADR</th>
                    <th>Risk</th>
                    <th>Message</th>
                    <th>Impact</th>
                </tr>
            </thead>
            <tbody>
                {% for violation in violations[:config.max_violations_per_page] %}
                <tr>
                    <td>{{ violation.file_path }}</td>
                    <td>{{ violation.line_number|default('N/A') }}</td>
                    <td>{{ violation.adr_id }}</td>
                    <td>
                        <span class="badge badge-{{ violation.risk_level }}">
                            {{ violation.risk_level|upper }}
                        </span>
                    </td>
                    <td>{{ violation.message|default('') }}</td>
                    <td>{{ violation.impact_assessment }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if violations|length > config.max_violations_per_page %}
        <p class="note">Showing {{ config.max_violations_per_page }} of {{ violations|length }} violations.
           See JSON report for complete list.</p>
        {% endif %}
    </div>
    {% else %}
    <p>No violations found. Excellent compliance!</p>
    {% endif %}
</section>"""

    # Template filters
    def _format_timestamp(self, timestamp: str) -> str:
        """Format ISO timestamp for display."""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError) as e:
            logger.debug(f"Could not format timestamp '{timestamp}': {str(e)}")
            return timestamp

    def _format_number(self, value: Any) -> str:
        """Format number with thousands separator."""
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not format number '{value}': {str(e)}")
            return str(value)

    def _format_percentage(self, value: Any) -> str:
        """Format as percentage."""
        try:
            return f"{float(value):.1f}%"
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not format percentage '{value}': {str(e)}")
            return str(value)

    def _get_risk_color(self, value: Any) -> str:
        """Get color based on risk value."""
        try:
            score = float(value)
            if score >= 90:
                return "#4caf50"  # Green
            elif score >= 80:
                return "#8bc34a"  # Light green
            elif score >= 70:
                return "#ff9800"  # Orange
            elif score >= 60:
                return "#ff5722"  # Deep orange
            else:
                return "#f44336"  # Red
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not determine risk color for '{value}': {str(e)}")
            return "#666"  # Gray

    def _get_risk_icon(self, risk_level: str) -> str:
        """Get icon for risk level."""
        icons = {"critical": "⚠️", "high": "⚡", "medium": "⚪", "low": "✓"}
        return icons.get(risk_level.lower(), "•")

    def _truncate_path(self, path: str, max_length: int = 50) -> str:
        """Truncate long file paths for display."""
        if len(path) <= max_length:
            return path

        parts = Path(path).parts
        if len(parts) <= 2:
            return path[: max_length - 3] + "..."

        # Show first and last parts
        return f"{parts[0]}/.../{parts[-1]}"

    def _static_url(self, path: str) -> str:
        """Generate URL for static files."""
        # For now, return relative path to static files
        # In production, this could be a CDN URL or absolute path
        return f"static/{path}"

    def _copy_static_files(self, output_dir: Path) -> None:
        """Copy static files to output directory."""
        try:
            # Validate output directory
            output_dir = Path(output_dir).resolve()

            # Ensure we're not writing outside allowed directories
            allowed_base = self.config.output_dir.resolve()
            if not str(output_dir).startswith(str(allowed_base)):
                raise ValueError(f"Output directory {output_dir} is outside allowed path {allowed_base}")

            # Create static directory in output location
            static_output = output_dir / "static"
            static_output.mkdir(exist_ok=True, mode=0o755)

            # Copy JS files
            js_output = static_output / "js"
            js_output.mkdir(exist_ok=True, mode=0o755)

            # Source static directory
            static_source = Path(__file__).parent.parent / "static"

            # Copy Chart.js if it exists
            chart_source = static_source / "js" / "chart.min.js"
            if chart_source.exists():
                import shutil

                shutil.copy2(chart_source, js_output / "chart.min.js")
                logger.debug(f"Copied Chart.js to {js_output}")
            else:
                # Fallback: embed Chart.js inline (not recommended for production)
                logger.warning("Chart.js not found locally, using inline fallback")
                self._create_inline_chartjs(js_output)

        except Exception as e:
            logger.warning(f"Could not copy static files: {str(e)}")
            # Reports will still work, just without local Chart.js

    def _create_inline_chartjs(self, js_dir: Path) -> None:
        """Create a minimal Chart.js file as fallback."""
        fallback_content = """// Chart.js not available locally
// Add Chart.js manually or update from CDN
console.warn('Chart.js not loaded. Charts will not be displayed.');"""

        (js_dir / "chart.min.js").write_text(fallback_content)
