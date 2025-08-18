"""
PDF report generator using ReportLab.

This module provides PDF generation capabilities for architectural
audit reports with charts, tables, and formatted content.
"""

import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ReportLab imports
try:
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        FrameBreak,
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.tableofcontents import TableOfContents

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    # Create dummy classes to prevent NameError during class definition
    ParagraphStyle = type("ParagraphStyle", (), {"__init__": lambda *args, **kwargs: None})
    TableStyle = type("TableStyle", (), {})
    Paragraph = type("Paragraph", (), {})
    Table = type("Table", (), {})

    # Create dummy colors module with HexColor class
    class DummyColors:
        @staticmethod
        def HexColor(color_str):
            return color_str

    colors = DummyColors()
    A4 = (595.27, 841.89)  # A4 dimensions in points
    # Dummy enums
    TA_CENTER = 1
    TA_JUSTIFY = 2
    TA_RIGHT = 3

    # Dummy function to return styles
    def getSampleStyleSheet():
        class DummyStyleSheet:
            def __getitem__(self, key):
                return ParagraphStyle()

            def add(self, style):
                pass

        return DummyStyleSheet()

    logger = logging.getLogger(__name__)
    logger.warning("ReportLab not available - PDF generation disabled")

from ..base import ReportConfig, ReportDataProcessor, ReportGenerator
from ..hotspot_integration import HotspotDataTransformer
from ..security import HotspotSanitizer, InputValidator, OutputEncoder

logger = logging.getLogger(__name__)


class PDFReportGenerator(ReportGenerator):
    """
    Generates professional PDF reports using ReportLab.

    Creates structured PDF documents with executive summary,
    charts, tables, and detailed findings suitable for
    stakeholder distribution.
    """

    def __init__(self, config: ReportConfig):
        """Initialize PDF generator."""
        super().__init__(config)

        if not HAS_REPORTLAB:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")

        # Security components
        self.validator = InputValidator()
        self.encoder = OutputEncoder()
        self.hotspot_sanitizer = HotspotSanitizer(security_level=config.security_level.value)

        # Data processors
        self.data_processor = ReportDataProcessor()
        self.hotspot_transformer = HotspotDataTransformer()

        # PDF settings
        self.page_size = A4

        # Color scheme (must be set before styles)
        self.colors = {
            "primary": colors.HexColor("#1976d2"),
            "success": colors.HexColor("#4caf50"),
            "warning": colors.HexColor("#ff9800"),
            "danger": colors.HexColor("#f44336"),
            "text": colors.HexColor("#333333"),
            "light_gray": colors.HexColor("#f5f5f5"),
            "medium_gray": colors.HexColor("#666666"),
        }

        # Create styles after colors are set
        self.styles = self._create_custom_styles()

    def generate(self, audit_data: Dict[str, Any]) -> Path:
        """
        Generate PDF report from audit data.

        Args:
            audit_data: Validated audit data

        Returns:
            Path to generated PDF report
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

            # Generate PDF
            output_path = self._get_output_path("pdf")

            # Create document
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=self.page_size,
                topMargin=1 * inch,
                bottomMargin=1 * inch,
                leftMargin=1 * inch,
                rightMargin=1 * inch,
            )

            # Build story (content)
            story = []

            # Title page
            story.extend(self._create_title_page(report_data))
            story.append(PageBreak())

            # Table of contents
            if self.config.include_executive_summary:
                story.extend(self._create_table_of_contents())
                story.append(PageBreak())

            # Executive summary
            if self.config.include_executive_summary:
                story.extend(self._create_executive_summary(report_data))
                story.append(PageBreak())

            # Risk overview with charts
            if self.config.enable_charts:
                story.extend(self._create_risk_overview(report_data))
                story.append(PageBreak())

            # Hotspot analysis
            if report_data.get("hotspot_analysis"):
                story.extend(self._create_hotspot_section(report_data["hotspot_analysis"]))
                story.append(PageBreak())

            # Violation details
            story.extend(self._create_violations_section(report_data))

            # Recommendations
            if self.config.include_recommendations and report_data.get("recommendations"):
                story.append(PageBreak())
                story.extend(self._create_recommendations_section(report_data))

            # Build PDF
            doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

            logger.info(f"PDF report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            raise

    def validate_data(self, audit_data: Dict[str, Any]) -> bool:
        """Validate audit data structure."""
        try:
            self.validator.validate_audit_data(audit_data)
            return True
        except Exception:
            return False

    def _generate_hotspot_section(self, hotspot_data: Any) -> List[Any]:
        """Generate hotspot analysis section for PDF."""
        story = []

        story.append(Paragraph("Architectural Hotspots", self.styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        if hotspot_data:
            # Summary
            summary = hotspot_data.get("temporal_trends", {}).get("summary", "")
            story.append(Paragraph(summary, self.styles["Normal"]))
            story.append(Spacer(1, 0.1 * inch))

            # Statistics table
            stats = hotspot_data.get("statistics", {})
            stats_data = [
                ["Metric", "Value"],
                ["Total Hotspots", str(stats.get("total_hotspots", 0))],
                ["Critical Risk", str(stats.get("critical_count", 0))],
                ["Average Risk", f"{stats.get('average_risk', 0)*100:.1f}%"],
                [
                    "High Confidence",
                    f"{stats.get('confidence_statistics', {}).get('high_confidence_percentage', 0):.1f}%",
                ],
            ]

            stats_table = Table(stats_data, colWidths=[3 * inch, 2 * inch])
            stats_table.setStyle(self._get_table_style())
            story.append(stats_table)
            story.append(Spacer(1, 0.2 * inch))

            # Top hotspots table
            if hotspot_data.get("hotspots"):
                story.append(Paragraph("Top Risk Areas", self.styles["Heading2"]))
                story.append(Spacer(1, 0.1 * inch))

                hotspot_table_data = [["File", "Risk Score", "Category", "Violations"]]

                for hotspot in hotspot_data["hotspots"][:10]:
                    hotspot_table_data.append(
                        [
                            self._truncate_text(hotspot.get("file_path", ""), 40),
                            f"{hotspot.get('risk_score', 0)*100:.1f}%",
                            hotspot.get("risk_category", "Unknown"),
                            str(hotspot.get("violation_count", 0)),
                        ]
                    )

                hotspot_table = Table(hotspot_table_data, colWidths=[3 * inch, 1.5 * inch, 1.5 * inch, 1 * inch])
                hotspot_table.setStyle(self._get_table_style(highlight_header=True))
                story.append(hotspot_table)

        return story

    def _create_custom_styles(self) -> Dict[str, ParagraphStyle]:
        """Create custom paragraph styles."""
        styles = getSampleStyleSheet()

        # Custom title style
        styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=styles["Title"],
                fontSize=24,
                textColor=self.colors["primary"],
                spaceAfter=30,
                alignment=TA_CENTER,
            )
        )

        # Custom heading styles - use unique names to avoid conflicts
        styles.add(
            ParagraphStyle(
                name="CustomHeading1",
                parent=styles["Heading1"],
                fontSize=18,
                textColor=self.colors["primary"],
                spaceAfter=12,
            )
        )

        styles.add(
            ParagraphStyle(
                name="CustomHeading2",
                parent=styles["Heading2"],
                fontSize=14,
                textColor=self.colors["text"],
                spaceAfter=8,
            )
        )

        # Custom body text
        styles.add(
            ParagraphStyle(
                name="CustomBodyText", parent=styles["Normal"], fontSize=10, alignment=TA_JUSTIFY, spaceAfter=6
            )
        )

        # Risk level styles
        for level, color in [
            ("Critical", self.colors["danger"]),
            ("High", colors.HexColor("#ff5722")),
            ("Medium", self.colors["warning"]),
            ("Low", self.colors["success"]),
        ]:
            styles.add(
                ParagraphStyle(
                    name=f"Risk{level}",
                    parent=styles["Normal"],
                    fontSize=10,
                    textColor=color,
                    fontName="Helvetica-Bold",
                )
            )

        return styles

    def _create_title_page(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create title page content."""
        story = []

        # Add logo space
        story.append(Spacer(1, 2 * inch))

        # Title
        story.append(Paragraph("Architectural Audit Report", self.styles["CustomTitle"]))

        story.append(Spacer(1, 0.5 * inch))

        # Compliance score
        score = report_data["summary"]["compliance_score"]
        score_color = self._get_score_color(score)

        score_style = ParagraphStyle(
            "ScoreStyle",
            parent=self.styles["Normal"],
            fontSize=36,
            textColor=score_color,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        story.append(Paragraph(f"{score:.1f}%", score_style))
        story.append(Paragraph("Compliance Score", self.styles["Normal"]))

        story.append(Spacer(1, 1 * inch))

        # Metadata
        metadata = report_data["metadata"]
        info_data = [
            ["Repository:", metadata.get("repository_path", "Unknown")],
            ["Generated:", self._format_timestamp(metadata.get("timestamp", ""))],
            ["Files Analyzed:", str(metadata.get("total_files_analyzed", 0))],
            ["Analysis Duration:", f"{metadata.get('analysis_duration', 0):.1f} seconds"],
        ]

        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TEXTCOLOR", (0, 0), (-1, -1), self.colors["text"]),
                ]
            )
        )

        story.append(info_table)

        return story

    def _create_table_of_contents(self) -> List[Any]:
        """Create table of contents."""
        story = []

        story.append(Paragraph("Table of Contents", self.styles["Heading1"]))
        story.append(Spacer(1, 0.3 * inch))

        toc_data = [
            ["1. Executive Summary", "3"],
            ["2. Risk Overview", "4"],
            ["3. Architectural Hotspots", "6"],
            ["4. ADR Violations", "8"],
            ["5. Recommendations", "12"],
        ]

        toc = Table(toc_data, colWidths=[5 * inch, 1 * inch])
        toc.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, -1), "LEFT"),
                    ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("TEXTCOLOR", (0, 0), (-1, -1), self.colors["text"]),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, self.colors["light_gray"]),
                ]
            )
        )

        story.append(toc)

        return story

    def _create_executive_summary(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create executive summary section."""
        story = []

        story.append(Paragraph("Executive Summary", self.styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        # Key findings
        story.append(Paragraph("Key Findings", self.styles["Heading2"]))
        for finding in report_data["summary"]["key_findings"]:
            story.append(Paragraph(f"• {finding}", self.styles["BodyText"]))

        story.append(Spacer(1, 0.2 * inch))

        # Risk assessment
        risk_level = report_data["summary"]["risk_assessment"]
        risk_style = self.styles.get(f"Risk{risk_level.title()}", self.styles["Normal"])

        story.append(Paragraph("Overall Risk Assessment", self.styles["Heading2"]))
        story.append(Paragraph(risk_level, risk_style))

        story.append(Spacer(1, 0.2 * inch))

        # Summary table
        summary_data = [
            ["Metric", "Count", "Percentage"],
            ["Total Violations", str(report_data["summary"]["total_violations"]), "100%"],
            [
                "Critical",
                str(report_data["summary"]["critical_violations"]),
                self._calculate_percentage(
                    report_data["summary"]["critical_violations"], report_data["summary"]["total_violations"]
                ),
            ],
            [
                "High",
                str(report_data["summary"]["high_violations"]),
                self._calculate_percentage(
                    report_data["summary"]["high_violations"], report_data["summary"]["total_violations"]
                ),
            ],
            [
                "Medium",
                str(report_data["summary"]["medium_violations"]),
                self._calculate_percentage(
                    report_data["summary"]["medium_violations"], report_data["summary"]["total_violations"]
                ),
            ],
            [
                "Low",
                str(report_data["summary"]["low_violations"]),
                self._calculate_percentage(
                    report_data["summary"]["low_violations"], report_data["summary"]["total_violations"]
                ),
            ],
        ]

        summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        summary_table.setStyle(self._get_table_style(highlight_header=True))
        story.append(summary_table)

        story.append(Spacer(1, 0.2 * inch))

        # Technical debt
        story.append(Paragraph("Technical Debt", self.styles["Heading2"]))
        debt_days = report_data["summary"]["technical_debt_days"]
        story.append(
            Paragraph(f"Estimated effort to resolve all violations: {debt_days:.1f} days", self.styles["BodyText"])
        )

        return story

    def _create_risk_overview(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create risk overview with charts."""
        story = []

        story.append(Paragraph("Risk Overview", self.styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        # Create pie chart
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100

        # Data
        data = [
            report_data["summary"]["critical_violations"],
            report_data["summary"]["high_violations"],
            report_data["summary"]["medium_violations"],
            report_data["summary"]["low_violations"],
        ]

        pie.data = data
        pie.labels = ["Critical", "High", "Medium", "Low"]
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = self.colors["danger"]
        pie.slices[1].fillColor = colors.HexColor("#ff5722")
        pie.slices[2].fillColor = self.colors["warning"]
        pie.slices[3].fillColor = self.colors["success"]

        drawing.add(pie)

        # Add legend
        legend = Legend()
        legend.x = 280
        legend.y = 80
        legend.dx = 8
        legend.dy = 8
        legend.fontName = "Helvetica"
        legend.fontSize = 10
        legend.boxAnchor = "w"
        legend.columnMaximum = 1
        legend.strokeWidth = 1
        legend.strokeColor = colors.black
        legend.deltax = 75
        legend.deltay = 10
        legend.autoXPadding = 5
        legend.yGap = 0
        legend.colorNamePairs = [
            (self.colors["danger"], "Critical"),
            (colors.HexColor("#ff5722"), "High"),
            (self.colors["warning"], "Medium"),
            (self.colors["success"], "Low"),
        ]

        drawing.add(legend)
        story.append(drawing)

        return story

    def _create_violations_section(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create violations detail section."""
        story = []

        story.append(Paragraph("ADR Violations", self.styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        violations = report_data.get("violations", [])

        if not violations:
            story.append(Paragraph("No violations found.", self.styles["Normal"]))
            return story

        # Group by risk level
        by_risk = {}
        for violation in violations:
            risk = violation.get("risk_level", "unknown")
            if risk not in by_risk:
                by_risk[risk] = []
            by_risk[risk].append(violation)

        # Display by risk level
        for risk_level in ["critical", "high", "medium", "low"]:
            if risk_level not in by_risk:
                continue

            risk_violations = by_risk[risk_level]

            story.append(
                Paragraph(f"{risk_level.title()} Risk Violations ({len(risk_violations)})", self.styles["Heading2"])
            )
            story.append(Spacer(1, 0.1 * inch))

            # Create table for this risk level
            table_data = [["File", "Line", "ADR", "Message"]]

            for v in risk_violations[:20]:  # Limit to 20 per level
                table_data.append(
                    [
                        self._truncate_text(v.get("file_path", ""), 30),
                        str(v.get("line_number", "N/A")),
                        v.get("adr_id", ""),
                        self._truncate_text(v.get("message", ""), 40),
                    ]
                )

            table = Table(table_data, colWidths=[2.5 * inch, 0.7 * inch, 1 * inch, 2.8 * inch])
            table.setStyle(self._get_table_style(highlight_header=True, risk_level=risk_level))

            story.append(KeepTogether(table))
            story.append(Spacer(1, 0.2 * inch))

        return story

    def _create_recommendations_section(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create recommendations section."""
        story = []

        story.append(Paragraph("Recommendations", self.styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        recommendations = report_data.get("recommendations", [])

        # Group by priority
        by_priority = {}
        for rec in recommendations:
            priority = rec.get("priority", "medium")
            if priority not in by_priority:
                by_priority[priority] = []
            by_priority[priority].append(rec)

        # Display by priority
        for priority in ["critical", "high", "medium", "low"]:
            if priority not in by_priority:
                continue

            priority_recs = by_priority[priority]

            story.append(Paragraph(f"{priority.title()} Priority ({len(priority_recs)})", self.styles["Heading2"]))
            story.append(Spacer(1, 0.1 * inch))

            for rec in priority_recs[:5]:  # Limit to 5 per priority
                story.append(
                    Paragraph(f"<b>{rec.get('id', '')}</b>: {rec.get('description', '')}", self.styles["BodyText"])
                )
                story.append(
                    Paragraph(
                        f"Category: {rec.get('category', '')} | " f"Effort: {rec.get('estimated_effort', '')}",
                        self.styles["Normal"],
                    )
                )
                story.append(Spacer(1, 0.1 * inch))

        return story

    def _get_table_style(self, highlight_header: bool = True, risk_level: Optional[str] = None) -> TableStyle:
        """Get table style configuration."""
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), self.colors["light_gray"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), self.colors["text"]),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, self.colors["medium_gray"]),
        ]

        # Add risk-specific coloring
        if risk_level:
            risk_colors = {
                "critical": self.colors["danger"],
                "high": colors.HexColor("#ff5722"),
                "medium": self.colors["warning"],
                "low": self.colors["success"],
            }
            if risk_level in risk_colors:
                style_commands.append(("TEXTCOLOR", (0, 1), (-1, -1), risk_colors[risk_level]))

        return TableStyle(style_commands)

    def _add_header_footer(self, canvas, doc):
        """Add header and footer to pages."""
        canvas.saveState()

        # Header
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(self.colors["medium_gray"])
        canvas.drawString(inch, self.page_size[1] - 0.5 * inch, "Architectural Audit Report")
        canvas.drawRightString(
            self.page_size[0] - inch, self.page_size[1] - 0.5 * inch, datetime.now().strftime("%Y-%m-%d")
        )

        # Footer
        page_num = canvas.getPageNumber()
        canvas.drawCentredString(self.page_size[0] / 2.0, 0.5 * inch, f"Page {page_num}")

        # Line separators
        canvas.setStrokeColor(self.colors["light_gray"])
        canvas.line(inch, self.page_size[1] - 0.6 * inch, self.page_size[0] - inch, self.page_size[1] - 0.6 * inch)
        canvas.line(inch, 0.7 * inch, self.page_size[0] - inch, 0.7 * inch)

        canvas.restoreState()

    # Helper methods
    def _get_score_color(self, score: float) -> Any:
        """Get color based on score value."""
        if score >= 90:
            return self.colors["success"]
        elif score >= 80:
            return colors.HexColor("#8bc34a")
        elif score >= 70:
            return self.colors["warning"]
        elif score >= 60:
            return colors.HexColor("#ff5722")
        else:
            return self.colors["danger"]

    def _format_timestamp(self, timestamp: str) -> str:
        """Format ISO timestamp for display."""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError) as e:
            logger.debug(f"Could not format timestamp '{timestamp}': {str(e)}")
            return timestamp

    def _calculate_percentage(self, part: int, total: int) -> str:
        """Calculate percentage string."""
        if total == 0:
            return "0%"
        return f"{(part / total * 100):.1f}%"

    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to maximum length."""
        if len(text) <= max_length:
            return text
        return text[: max_length - 3] + "..."
