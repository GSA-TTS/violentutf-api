"""
Security modules for the reporting system.

This package provides security components to prevent common vulnerabilities
in report generation, including XSS, path traversal, and content injection.
"""

from .hotspot_sanitizer import HotspotSanitizer
from .input_validator import InputValidator, ValidationError
from .output_encoder import EncodingType, OutputEncoder

__all__ = ["InputValidator", "ValidationError", "OutputEncoder", "EncodingType", "HotspotSanitizer"]
