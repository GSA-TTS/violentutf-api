"""
Enhanced reporting module for architectural audit results.

This module provides comprehensive report generation capabilities with:
- Multiple export formats (HTML, PDF, JSON)
- Security-by-design with XSS prevention
- Statistical hotspot integration (Issue #43)
- Parallel export processing
- Customizable visualizations
- Executive summaries for stakeholders
"""

from .base import ReportConfig, ReportDataProcessor, ReportGenerator, SecurityLevel
from .export_manager import ExportManager
from .exporters import HTMLReportGenerator, JSONReportGenerator, PDFReportGenerator
from .hotspot_integration import HotspotAnalysisResult, HotspotDataTransformer
from .security import EncodingType, HotspotSanitizer, InputValidator, OutputEncoder, ValidationError

__version__ = "2.0.0"

__all__ = [
    # Base classes
    "ReportConfig",
    "ReportGenerator",
    "ReportDataProcessor",
    "SecurityLevel",
    # Exporters
    "HTMLReportGenerator",
    "JSONReportGenerator",
    "PDFReportGenerator",
    # Security
    "InputValidator",
    "OutputEncoder",
    "HotspotSanitizer",
    "ValidationError",
    "EncodingType",
    # Hotspot integration
    "HotspotDataTransformer",
    "HotspotAnalysisResult",
    # Export management
    "ExportManager",
]
