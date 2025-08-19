"""Architectural Report Generator Service.

This service generates comprehensive PDF and HTML reports for architectural metrics,
ROI tracking, and audit results using the existing reporting infrastructure.
"""

import base64
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.report import Report, ReportFormat, ReportStatus
from app.services.architectural_metrics_service import ArchitecturalMetricsService

# Use non-interactive backend for matplotlib
matplotlib.use("Agg")

logger = logging.getLogger(__name__)


class ArchitecturalReportGenerator:
    """Service for generating architectural audit reports."""

    def __init__(self, db_session: AsyncSession):
        """Initialize the report generator.

        Args:
            db_session: AsyncSQL database session
        """
        self.db = db_session
        self.metrics_service = ArchitecturalMetricsService(db_session)
        self.template_dir = Path(__file__).parent.parent / "templates" / "reports"
        self._ensure_template_dir()

    def _ensure_template_dir(self) -> None:
        """Ensure template directory exists."""
        self.template_dir.mkdir(parents=True, exist_ok=True)

        # Create default templates if they don't exist
        self._create_default_templates()

    def _create_default_templates(self) -> None:
        """Create default report templates."""
        # HTML template for architectural metrics report
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .subtitle {
            opacity: 0.9;
            margin-top: 10px;
        }
        .section {
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .metric-label {
            color: #666;
            margin-top: 5px;
        }
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        .chart-container img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
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
            background-color: #667eea;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .positive {
            color: #28a745;
            font-weight: bold;
        }
        .negative {
            color: #dc3545;
            font-weight: bold;
        }
        .neutral {
            color: #ffc107;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        .summary-box {
            background: linear-gradient(135deg, #f5f3ff 0%, #e9e7ff 100%);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge-success {
            background-color: #d4edda;
            color: #155724;
        }
        .badge-danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        .badge-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <div class="subtitle">{{ subtitle }}</div>
        <div style="margin-top: 15px;">
            <span>Generated: {{ generated_at }}</span> |
            <span>Period: {{ period_start }} to {{ period_end }}</span>
        </div>
    </div>

    {% if executive_summary %}
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-box">
            {{ executive_summary | safe }}
        </div>
    </div>
    {% endif %}

    {% if leading_indicators %}
    <div class="section">
        <h2>Leading Indicators</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{{ leading_indicators.automation_coverage.automation_percentage }}%</div>
                <div class="metric-label">Automation Coverage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ leading_indicators.detection_time.average_detection_hours }}h</div>
                <div class="metric-label">Avg Detection Time</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ leading_indicators.developer_adoption_rate.adoption_rate }}%</div>
                <div class="metric-label">Developer Adoption</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ leading_indicators.compliance_scores.overall_score }}%</div>
                <div class="metric-label">Compliance Score</div>
            </div>
        </div>

        {% if charts.automation_trend %}
        <div class="chart-container">
            <h3>Automation Coverage Trend</h3>
            <img src="{{ charts.automation_trend }}" alt="Automation Coverage Trend">
        </div>
        {% endif %}

        <h3>Violation Frequency Analysis</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Trend</th>
                </tr>
            </thead>
            <tbody>
                {% for violation in leading_indicators.violation_frequency.top_violations %}
                <tr>
                    <td>{{ violation.category }}</td>
                    <td>{{ violation.count }}</td>
                    <td>{{ violation.percentage }}%</td>
                    <td>
                        {% if violation.trend == 'decreasing' %}
                            <span class="positive">↓ Decreasing</span>
                        {% elif violation.trend == 'increasing' %}
                            <span class="negative">↑ Increasing</span>
                        {% else %}
                            <span class="neutral">→ Stable</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if lagging_indicators %}
    <div class="section">
        <h2>Lagging Indicators</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">
                    {% if lagging_indicators.architectural_debt_velocity.trend == 'improving' %}
                        <span class="positive">{{ lagging_indicators.architectural_debt_velocity.daily_velocity }}</span>
                    {% else %}
                        <span class="negative">{{ lagging_indicators.architectural_debt_velocity.daily_velocity }}</span>
                    {% endif %}
                </div>
                <div class="metric-label">Debt Velocity (daily)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ lagging_indicators.security_incident_reduction.reduction_percentage }}%</div>
                <div class="metric-label">Security Incident Reduction</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ lagging_indicators.maintainability_improvements.improvement_rate }}%</div>
                <div class="metric-label">Maintainability Improvement</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ lagging_indicators.development_velocity_impact.success_rate }}%</div>
                <div class="metric-label">Task Success Rate</div>
            </div>
        </div>

        {% if charts.security_trend %}
        <div class="chart-container">
            <h3>Security Incident Trend</h3>
            <img src="{{ charts.security_trend }}" alt="Security Incident Trend">
        </div>
        {% endif %}
    </div>
    {% endif %}

    {% if roi_analysis %}
    <div class="section">
        <h2>Return on Investment (ROI) Analysis</h2>

        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">${{ "{:,.0f}".format(roi_analysis.total_costs) }}</div>
                <div class="metric-label">Total Investment</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${{ "{:,.0f}".format(roi_analysis.total_benefits) }}</div>
                <div class="metric-label">Total Benefits</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ roi_analysis.roi_percentage }}%</div>
                <div class="metric-label">ROI Percentage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ roi_analysis.payback_period_months }} mo</div>
                <div class="metric-label">Payback Period</div>
            </div>
        </div>

        <h3>Cost Breakdown</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Amount</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                {% for category, amount in roi_analysis.implementation_costs.items() %}
                <tr>
                    <td>{{ category.replace('_', ' ').title() }}</td>
                    <td>${{ "{:,.0f}".format(amount) }}</td>
                    <td>{{ "{:.1f}".format(amount / roi_analysis.total_costs * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h3>Benefits Breakdown</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Amount</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                {% for category, amount in roi_analysis.cost_avoidance.items() %}
                <tr>
                    <td>{{ category.replace('_', ' ').title() }}</td>
                    <td>${{ "{:,.0f}".format(amount) }}</td>
                    <td><span class="badge badge-success">Cost Avoidance</span></td>
                </tr>
                {% endfor %}
                {% for category, amount in roi_analysis.productivity_gains.items() %}
                <tr>
                    <td>{{ category.replace('_', ' ').title() }}</td>
                    <td>${{ "{:,.0f}".format(amount) }}</td>
                    <td><span class="badge badge-warning">Productivity Gain</span></td>
                </tr>
                {% endfor %}
                {% for category, amount in roi_analysis.quality_improvements.items() %}
                <tr>
                    <td>{{ category.replace('_', ' ').title() }}</td>
                    <td>${{ "{:,.0f}".format(amount) }}</td>
                    <td><span class="badge badge-success">Quality Improvement</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if charts.roi_breakdown %}
        <div class="chart-container">
            <h3>ROI Breakdown</h3>
            <img src="{{ charts.roi_breakdown }}" alt="ROI Breakdown">
        </div>
        {% endif %}
    </div>
    {% endif %}

    {% if recommendations %}
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            {% for recommendation in recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="footer">
        <p>Generated by Architectural Audit System | {{ generated_at }}</p>
        <p>🤖 Powered by ViolentUTF API</p>
    </div>
</body>
</html>"""

        # Save HTML template
        html_template_path = self.template_dir / "architectural_metrics.html"
        if not html_template_path.exists():
            html_template_path.write_text(html_template)

    async def generate_architectural_metrics_report(
        self,
        report_id: str,
        format: ReportFormat,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        include_sections: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate comprehensive architectural metrics report.

        Args:
            report_id: Report ID to update
            format: Report format (PDF or HTML)
            start_date: Start date for metrics
            end_date: End date for metrics
            include_sections: Sections to include in report

        Returns:
            Dictionary with report metadata and file path
        """
        try:
            # Default date range
            if not end_date:
                end_date = datetime.now(timezone.utc)
            if not start_date:
                start_date = end_date - timedelta(days=30)

            # Default sections
            if not include_sections:
                include_sections = ["leading", "lagging", "roi", "executive_summary", "recommendations"]

            # Gather metrics data
            metrics_data = await self._gather_metrics_data(start_date, end_date, include_sections)

            # Generate charts
            charts = await self._generate_charts(metrics_data)

            # Generate report based on format
            if format == ReportFormat.PDF:
                file_path = await self._generate_pdf_report(report_id, metrics_data, charts)
            elif format == ReportFormat.HTML:
                file_path = await self._generate_html_report(report_id, metrics_data, charts)
            else:
                raise ValueError(f"Unsupported format: {format}")

            # Update report status
            await self._update_report_status(report_id, ReportStatus.COMPLETED, file_path)

            return {
                "report_id": report_id,
                "file_path": file_path,
                "format": format.value,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "metrics_period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            }

        except Exception as e:
            logger.error(f"Error generating architectural metrics report: {e}")
            await self._update_report_status(report_id, ReportStatus.FAILED, error_message=str(e))
            raise

    async def _gather_metrics_data(
        self, start_date: datetime, end_date: datetime, include_sections: List[str]
    ) -> Dict[str, Any]:
        """Gather all metrics data for the report."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "title": "Architectural Metrics & ROI Report",
            "subtitle": f"Comprehensive analysis of architectural audit initiatives",
        }

        # Gather requested sections
        if "leading" in include_sections:
            data["leading_indicators"] = await self.metrics_service.calculate_leading_indicators(start_date, end_date)

        if "lagging" in include_sections:
            data["lagging_indicators"] = await self.metrics_service.calculate_lagging_indicators(start_date, end_date)

        if "roi" in include_sections:
            data["roi_analysis"] = await self.metrics_service.calculate_roi_analysis(start_date, end_date)

        if "executive_summary" in include_sections:
            data["executive_summary"] = self._generate_executive_summary(data)

        if "recommendations" in include_sections:
            data["recommendations"] = self._generate_recommendations(data)

        return data

    def _generate_executive_summary(self, metrics_data: Dict[str, Any]) -> str:
        """Generate executive summary based on metrics."""
        summary_parts = []

        # Leading indicators summary
        if "leading_indicators" in metrics_data:
            leading = metrics_data["leading_indicators"]
            automation = leading.get("automation_coverage", {}).get("automation_percentage", 0)
            compliance = leading.get("compliance_scores", {}).get("overall_score", 0)

            summary_parts.append(
                f"<p><strong>Current Performance:</strong> The architectural audit system shows "
                f"<strong>{automation:.1f}%</strong> automation coverage with a compliance score of "
                f"<strong>{compliance:.1f}%</strong>.</p>"
            )

        # Lagging indicators summary
        if "lagging_indicators" in metrics_data:
            lagging = metrics_data["lagging_indicators"]
            debt_trend = lagging.get("architectural_debt_velocity", {}).get("trend", "stable")
            security_reduction = lagging.get("security_incident_reduction", {}).get("reduction_percentage", 0)

            trend_text = "improving" if debt_trend == "improving" else "needs attention"
            summary_parts.append(
                f"<p><strong>Historical Trends:</strong> Architectural debt velocity is <strong>{trend_text}</strong>, "
                f"with a <strong>{security_reduction:.1f}%</strong> reduction in security incidents.</p>"
            )

        # ROI summary
        if "roi_analysis" in metrics_data:
            roi = metrics_data["roi_analysis"]
            roi_percentage = roi.get("roi_percentage", 0)
            payback = roi.get("payback_period_months", "N/A")

            summary_parts.append(
                f"<p><strong>Financial Impact:</strong> The initiative shows a <strong>{roi_percentage:.1f}%</strong> ROI "
                f"with a payback period of <strong>{payback} months</strong>.</p>"
            )

        return "\n".join(summary_parts) if summary_parts else "<p>No data available for summary.</p>"

    def _generate_recommendations(self, metrics_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on metrics analysis."""
        recommendations = []

        # Analyze leading indicators
        if "leading_indicators" in metrics_data:
            leading = metrics_data["leading_indicators"]

            # Automation coverage recommendations
            automation_pct = leading.get("automation_coverage", {}).get("automation_percentage", 0)
            if automation_pct < 70:
                recommendations.append(
                    f"Increase automation coverage from {automation_pct:.1f}% to at least 70% by implementing "
                    "scheduled scans and CI/CD integration"
                )

            # Developer adoption recommendations
            adoption_rate = leading.get("developer_adoption_rate", {}).get("adoption_rate", 0)
            if adoption_rate < 80:
                recommendations.append(
                    f"Improve developer adoption rate from {adoption_rate:.1f}% through targeted training "
                    "and simplified tool interfaces"
                )

            # Compliance recommendations
            compliance_score = leading.get("compliance_scores", {}).get("overall_score", 0)
            if compliance_score < 90:
                recommendations.append(
                    f"Focus on improving compliance score from {compliance_score:.1f}% by addressing "
                    "critical and high-severity violations first"
                )

        # Analyze lagging indicators
        if "lagging_indicators" in metrics_data:
            lagging = metrics_data["lagging_indicators"]

            # Debt velocity recommendations
            debt_velocity = lagging.get("architectural_debt_velocity", {}).get("daily_velocity", 0)
            if debt_velocity > 0:
                recommendations.append(
                    "Prioritize debt reduction by allocating dedicated resources to resolve "
                    f"{abs(debt_velocity):.1f} violations per day"
                )

            # Quality metrics recommendations
            quality = lagging.get("quality_metrics", {})
            critical_rate = quality.get("critical_rate", 0)
            if critical_rate > 5:
                recommendations.append(
                    f"Reduce critical defect rate from {critical_rate:.1f}% through enhanced "
                    "code review processes and automated security scanning"
                )

        # ROI recommendations
        if "roi_analysis" in metrics_data:
            roi = metrics_data["roi_analysis"]
            roi_percentage = roi.get("roi_percentage", 0)

            if roi_percentage < 100:
                recommendations.append(
                    "Optimize ROI by focusing on high-impact automation opportunities and "
                    "reducing manual intervention requirements"
                )

            # Cost optimization
            costs = roi.get("implementation_costs", {})
            if costs.get("developer_time", 0) > costs.get("tool_licensing", 0) * 2:
                recommendations.append(
                    "Consider additional tool investments to reduce developer time requirements "
                    "and improve overall efficiency"
                )

        # General recommendations if none specific
        if not recommendations:
            recommendations = [
                "Continue monitoring architectural metrics regularly",
                "Maintain current automation and compliance levels",
                "Consider expanding audit coverage to additional systems",
            ]

        return recommendations

    async def _generate_charts(self, metrics_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for the report."""
        charts = {}

        try:
            # Automation coverage trend chart
            if "leading_indicators" in metrics_data:
                charts["automation_trend"] = self._create_automation_trend_chart(metrics_data["leading_indicators"])

            # Security incident trend chart
            if "lagging_indicators" in metrics_data:
                charts["security_trend"] = self._create_security_trend_chart(metrics_data["lagging_indicators"])

            # ROI breakdown chart
            if "roi_analysis" in metrics_data:
                charts["roi_breakdown"] = self._create_roi_breakdown_chart(metrics_data["roi_analysis"])

        except Exception as e:
            logger.warning(f"Error generating charts: {e}")

        return charts

    def _create_automation_trend_chart(self, leading_indicators: Dict[str, Any]) -> str:
        """Create automation coverage trend chart."""
        try:
            fig, ax = plt.subplots(figsize=(10, 6))

            # Sample data for demonstration
            automation_data = leading_indicators.get("automation_coverage", {})
            automated = automation_data.get("automated_scans", 0)
            manual = automation_data.get("manual_scans", 0)

            categories = ["Automated", "Manual"]
            values = [automated, manual]
            colors = ["#667eea", "#dc3545"]

            ax.bar(categories, values, color=colors)
            ax.set_ylabel("Number of Scans")
            ax.set_title("Automation Coverage Distribution")

            # Add percentage labels
            total = sum(values)
            for i, (cat, val) in enumerate(zip(categories, values)):
                percentage = (val / total * 100) if total > 0 else 0
                ax.text(i, val + 1, f"{percentage:.1f}%", ha="center")

            plt.tight_layout()

            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format="png", dpi=100)
            buffer.seek(0)
            chart_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            logger.error(f"Error creating automation trend chart: {e}")
            return ""

    def _create_security_trend_chart(self, lagging_indicators: Dict[str, Any]) -> str:
        """Create security incident trend chart."""
        try:
            fig, ax = plt.subplots(figsize=(10, 6))

            # Get monthly data
            security_data = lagging_indicators.get("security_incident_reduction", {})
            monthly_data = security_data.get("monthly_data", {})

            if monthly_data:
                months = list(monthly_data.keys())
                incidents = list(monthly_data.values())

                ax.plot(months, incidents, marker="o", color="#dc3545", linewidth=2)
                ax.fill_between(range(len(months)), incidents, alpha=0.3, color="#dc3545")
                ax.set_xlabel("Month")
                ax.set_ylabel("Number of Incidents")
                ax.set_title("Security Incidents Over Time")
                ax.grid(True, alpha=0.3)

                # Rotate x-axis labels
                plt.xticks(rotation=45)

            plt.tight_layout()

            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format="png", dpi=100)
            buffer.seek(0)
            chart_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            logger.error(f"Error creating security trend chart: {e}")
            return ""

    def _create_roi_breakdown_chart(self, roi_analysis: Dict[str, Any]) -> str:
        """Create ROI breakdown pie chart."""
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

            # Costs pie chart
            costs = roi_analysis.get("implementation_costs", {})
            if costs:
                cost_labels = [k.replace("_", " ").title() for k in costs.keys()]
                cost_values = list(costs.values())
                colors1 = plt.cm.Reds(range(50, 250, 50))[: len(cost_labels)]

                ax1.pie(cost_values, labels=cost_labels, autopct="%1.1f%%", colors=colors1)
                ax1.set_title("Cost Distribution")

            # Benefits pie chart
            benefits = {}
            benefits.update(roi_analysis.get("cost_avoidance", {}))
            benefits.update(roi_analysis.get("productivity_gains", {}))
            benefits.update(roi_analysis.get("quality_improvements", {}))

            if benefits:
                benefit_labels = [k.replace("_", " ").title() for k in benefits.keys()]
                benefit_values = list(benefits.values())
                colors2 = plt.cm.Greens(range(50, 250, 25))[: len(benefit_labels)]

                ax2.pie(benefit_values, labels=benefit_labels, autopct="%1.1f%%", colors=colors2)
                ax2.set_title("Benefits Distribution")

            plt.suptitle("ROI Analysis Breakdown", fontsize=16)
            plt.tight_layout()

            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format="png", dpi=100)
            buffer.seek(0)
            chart_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()

            return f"data:image/png;base64,{chart_base64}"

        except Exception as e:
            logger.error(f"Error creating ROI breakdown chart: {e}")
            return ""

    async def _generate_pdf_report(self, report_id: str, metrics_data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Generate PDF report."""
        try:
            # Create output directory using tempfile for secure temp directory
            import tempfile

            output_dir = (
                Path(settings.REPORT_OUTPUT_DIR)
                if hasattr(settings, "REPORT_OUTPUT_DIR")
                else Path(tempfile.gettempdir()) / "reports"
            )
            output_dir.mkdir(parents=True, exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"architectural_metrics_{report_id}_{timestamp}.pdf"
            file_path = output_dir / filename

            # Create PDF document
            doc = SimpleDocTemplate(
                str(file_path),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18,
            )

            # Build content
            story = []
            styles = getSampleStyleSheet()

            # Title
            title_style = ParagraphStyle(
                "CustomTitle", parent=styles["Title"], fontSize=24, textColor=colors.HexColor("#667eea"), spaceAfter=30
            )
            story.append(Paragraph(metrics_data["title"], title_style))
            story.append(Spacer(1, 12))

            # Subtitle
            story.append(Paragraph(metrics_data["subtitle"], styles["Heading2"]))
            story.append(Spacer(1, 12))

            # Period info
            period_text = f"<b>Report Period:</b> {metrics_data['period_start']} to {metrics_data['period_end']}"
            story.append(Paragraph(period_text, styles["Normal"]))
            story.append(Spacer(1, 24))

            # Executive Summary
            if "executive_summary" in metrics_data:
                story.append(Paragraph("Executive Summary", styles["Heading1"]))
                story.append(Paragraph(metrics_data["executive_summary"], styles["Normal"]))
                story.append(Spacer(1, 24))

            # Leading Indicators
            if "leading_indicators" in metrics_data:
                story.append(PageBreak())
                story.append(Paragraph("Leading Indicators", styles["Heading1"]))
                story.append(Spacer(1, 12))

                # Create metrics table
                leading = metrics_data["leading_indicators"]
                metrics_table_data = [
                    ["Metric", "Value", "Status"],
                    ["Automation Coverage", f"{leading['automation_coverage']['automation_percentage']:.1f}%", "✓"],
                    ["Avg Detection Time", f"{leading['detection_time']['average_detection_hours']:.1f}h", "✓"],
                    ["Developer Adoption", f"{leading['developer_adoption_rate']['adoption_rate']:.1f}%", "✓"],
                    ["Compliance Score", f"{leading['compliance_scores']['overall_score']:.1f}%", "✓"],
                ]

                metrics_table = Table(metrics_table_data)
                metrics_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 12),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                story.append(metrics_table)
                story.append(Spacer(1, 24))

            # Lagging Indicators
            if "lagging_indicators" in metrics_data:
                story.append(PageBreak())
                story.append(Paragraph("Lagging Indicators", styles["Heading1"]))
                story.append(Spacer(1, 12))

                lagging = metrics_data["lagging_indicators"]
                lagging_table_data = [
                    ["Metric", "Value", "Trend"],
                    [
                        "Debt Velocity",
                        f"{lagging['architectural_debt_velocity']['daily_velocity']:.2f}/day",
                        lagging["architectural_debt_velocity"]["trend"],
                    ],
                    [
                        "Security Reduction",
                        f"{lagging['security_incident_reduction']['reduction_percentage']:.1f}%",
                        lagging["security_incident_reduction"]["trend"],
                    ],
                    ["Maintainability", f"{lagging['maintainability_improvements']['improvement_rate']:.1f}%", "↑"],
                    ["Success Rate", f"{lagging['development_velocity_impact']['success_rate']:.1f}%", "→"],
                ]

                lagging_table = Table(lagging_table_data)
                lagging_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 12),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.lightgrey),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                story.append(lagging_table)
                story.append(Spacer(1, 24))

            # ROI Analysis
            if "roi_analysis" in metrics_data:
                story.append(PageBreak())
                story.append(Paragraph("Return on Investment Analysis", styles["Heading1"]))
                story.append(Spacer(1, 12))

                roi = metrics_data["roi_analysis"]
                roi_summary = f"""
                <b>Total Investment:</b> ${roi['total_costs']:,.0f}<br/>
                <b>Total Benefits:</b> ${roi['total_benefits']:,.0f}<br/>
                <b>Net Benefit:</b> ${roi['net_benefit']:,.0f}<br/>
                <b>ROI Percentage:</b> {roi['roi_percentage']:.1f}%<br/>
                <b>Payback Period:</b> {roi.get('payback_period_months', 'N/A')} months
                """
                story.append(Paragraph(roi_summary, styles["Normal"]))
                story.append(Spacer(1, 24))

            # Recommendations
            if "recommendations" in metrics_data:
                story.append(PageBreak())
                story.append(Paragraph("Recommendations", styles["Heading1"]))
                story.append(Spacer(1, 12))

                for i, rec in enumerate(metrics_data["recommendations"], 1):
                    story.append(Paragraph(f"{i}. {rec}", styles["Normal"]))
                    story.append(Spacer(1, 6))

            # Build PDF
            doc.build(story)

            return str(file_path)

        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise

    async def _generate_html_report(self, report_id: str, metrics_data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Generate HTML report."""
        try:
            # Create output directory using tempfile for secure temp directory
            import tempfile

            output_dir = (
                Path(settings.REPORT_OUTPUT_DIR)
                if hasattr(settings, "REPORT_OUTPUT_DIR")
                else Path(tempfile.gettempdir()) / "reports"
            )
            output_dir.mkdir(parents=True, exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"architectural_metrics_{report_id}_{timestamp}.html"
            file_path = output_dir / filename

            # Load template with autoescape enabled for security
            env = Environment(
                loader=FileSystemLoader(str(self.template_dir)), autoescape=select_autoescape(["html", "xml"])
            )
            template = env.get_template("architectural_metrics.html")

            # Add charts to context
            metrics_data["charts"] = charts

            # Render template
            html_content = template.render(**metrics_data)

            # Save file
            file_path.write_text(html_content)

            return str(file_path)

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise

    async def _update_report_status(
        self, report_id: str, status: ReportStatus, file_path: Optional[str] = None, error_message: Optional[str] = None
    ) -> None:
        """Update report status in database."""
        try:
            query = select(Report).where(Report.id == report_id)
            result = await self.db.execute(query)
            report = result.scalar_one_or_none()

            if report:
                report.status = status
                report.generated_at = datetime.now(timezone.utc)

                if file_path:
                    report.file_path = file_path
                    report.file_size = Path(file_path).stat().st_size

                    # Determine MIME type
                    if file_path.endswith(".pdf"):
                        report.mime_type = "application/pdf"
                    elif file_path.endswith(".html"):
                        report.mime_type = "text/html"

                if error_message:
                    report.error_message = error_message

                await self.db.commit()

        except Exception as e:
            logger.error(f"Error updating report status: {e}")
            await self.db.rollback()
