"""
Output encoding module for secure report generation.

This module provides encoding functions to prevent XSS and other
injection attacks in generated reports.
"""

import html
import json
import logging
import re
from enum import Enum
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)


class EncodingType(Enum):
    """Types of encoding supported."""

    HTML = "html"
    JSON = "json"
    XML = "xml"
    URL = "url"
    JAVASCRIPT = "javascript"
    CSS = "css"


class OutputEncoder:
    """
    Provides secure encoding for various output formats.

    Implements context-aware encoding to prevent XSS and injection
    attacks in different output contexts.
    """

    # HTML entities that must always be encoded
    HTML_ENTITIES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "/": "&#x2F;"}

    # Additional characters to encode in attributes
    ATTR_ENTITIES = {"\n": "&#10;", "\r": "&#13;", "\t": "&#9;", "=": "&#x3D;", "\x00": ""}  # Remove null bytes

    # CSS dangerous patterns
    CSS_DANGEROUS = [
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"expression\s*\(", re.IGNORECASE),
        re.compile(r"@import", re.IGNORECASE),
        re.compile(r"</style", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        """Initialize the encoder."""
        self._encoding_stats = {"html_encoded": 0, "json_encoded": 0, "css_encoded": 0, "dangerous_blocked": 0}

    def encode_for_html(self, value: Any) -> str:
        """
        Encode value for safe HTML output.

        Args:
            value: Value to encode

        Returns:
            HTML-safe encoded string
        """
        if value is None:
            return ""

        # Convert to string
        text = str(value)

        # Use Python's html.escape for basic encoding
        encoded = html.escape(text, quote=True)

        # Additional encoding for forward slash (defense in depth)
        encoded = encoded.replace("/", "&#x2F;")

        # Remove any null bytes
        encoded = encoded.replace("\x00", "")

        self._encoding_stats["html_encoded"] += 1
        return encoded

    def encode_for_html_attribute(self, value: Any) -> str:
        """
        Encode value for HTML attribute context.

        More strict than general HTML encoding.

        Args:
            value: Value to encode

        Returns:
            Attribute-safe encoded string
        """
        if value is None:
            return ""

        text = str(value)

        # First apply HTML encoding
        encoded = self.encode_for_html(text)

        # Then encode additional characters for attributes
        for char, entity in self.ATTR_ENTITIES.items():
            encoded = encoded.replace(char, entity)

        # Encode non-alphanumeric characters
        def encode_char(match: re.Match[str]) -> str:
            char = match.group(0)
            return f"&#x{ord(char):X};"

        # Encode characters outside basic ASCII
        encoded = re.sub(r"[^\x20-\x7E]", encode_char, encoded)

        return encoded

    def encode_for_javascript(self, value: Any) -> str:
        """
        Encode value for JavaScript string context.

        Args:
            value: Value to encode

        Returns:
            JavaScript-safe encoded string
        """
        if value is None:
            return ""

        text = str(value)

        # JavaScript string escape mapping
        js_escapes = {
            "\\": "\\\\",
            '"': '\\"',
            "'": "\\'",
            "\n": "\\n",
            "\r": "\\r",
            "\t": "\\t",
            "\b": "\\b",
            "\f": "\\f",
            "\v": "\\v",
            "\x00": "\\u0000",
            "<": "\\u003C",  # Prevent </script>
            ">": "\\u003E",
            "&": "\\u0026",
            "=": "\\u003D",
            "/": "\\u002F",  # Prevent closing tags
        }

        result = ""
        for char in text:
            if char in js_escapes:
                result += js_escapes[char]
            elif ord(char) < 32 or ord(char) > 126:
                # Encode as Unicode escape
                result += f"\\u{ord(char):04X}"
            else:
                result += char

        return result

    def encode_for_css(self, value: Any) -> str:
        """
        Encode value for CSS context.

        Args:
            value: Value to encode

        Returns:
            CSS-safe encoded string
        """
        if value is None:
            return ""

        text = str(value)

        # Check for dangerous patterns
        for pattern in self.CSS_DANGEROUS:
            if pattern.search(text):
                self._encoding_stats["dangerous_blocked"] += 1
                self._encoding_stats["css_encoded"] += 1  # Count as encoded
                logger.warning(f"Blocked dangerous CSS pattern: {pattern.pattern}")
                return ""  # Return empty string for dangerous content

        # CSS encoding
        result = ""
        for char in text:
            if char.isalnum() or char in "-_":
                result += char
            else:
                # Encode as CSS hex escape
                result += f"\\{ord(char):06X} "

        self._encoding_stats["css_encoded"] += 1
        return result

    def encode_for_json(self, value: Any) -> str:
        """
        Encode value for JSON output.

        Args:
            value: Value to encode

        Returns:
            JSON-safe string
        """
        try:
            # Use json.dumps with ensure_ascii for safety
            encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
            self._encoding_stats["json_encoded"] += 1
            return encoded
        except (TypeError, ValueError) as e:
            logger.error(f"JSON encoding error: {str(e)}")
            return json.dumps(str(value), ensure_ascii=True)

    def encode_for_url(self, value: Any) -> str:
        """
        Encode value for URL context.

        Args:
            value: Value to encode

        Returns:
            URL-safe encoded string
        """
        if value is None:
            return ""

        from urllib.parse import quote

        return quote(str(value), safe="")

    def encode_dict_values(
        self, data: Dict[str, Any], encoding_type: EncodingType = EncodingType.HTML
    ) -> Dict[str, Any]:
        """
        Recursively encode all string values in a dictionary.

        Args:
            data: Dictionary to encode
            encoding_type: Type of encoding to apply

        Returns:
            Dictionary with encoded values
        """
        encoded: Dict[str, Any] = {}

        for key, value in data.items():
            if isinstance(value, str):
                encoded[key] = self._encode_by_type(value, encoding_type)
            elif isinstance(value, dict):
                encoded[key] = self.encode_dict_values(value, encoding_type)
            elif isinstance(value, list):
                encoded[key] = self.encode_list_values(value, encoding_type)
            else:
                encoded[key] = value

        return encoded

    def encode_list_values(self, data: List[Any], encoding_type: EncodingType = EncodingType.HTML) -> List[Any]:
        """
        Recursively encode all string values in a list.

        Args:
            data: List to encode
            encoding_type: Type of encoding to apply

        Returns:
            List with encoded values
        """
        encoded: List[Any] = []

        for item in data:
            if isinstance(item, str):
                encoded.append(self._encode_by_type(item, encoding_type))
            elif isinstance(item, dict):
                encoded.append(self.encode_dict_values(item, encoding_type))
            elif isinstance(item, list):
                encoded.append(self.encode_list_values(item, encoding_type))
            else:
                encoded.append(item)

        return encoded

    def _encode_by_type(self, value: str, encoding_type: EncodingType) -> str:
        """Apply encoding based on type."""
        if encoding_type == EncodingType.HTML:
            return self.encode_for_html(value)
        elif encoding_type == EncodingType.JSON:
            return self.encode_for_json(value)
        elif encoding_type == EncodingType.JAVASCRIPT:
            return self.encode_for_javascript(value)
        elif encoding_type == EncodingType.CSS:
            return self.encode_for_css(value)
        elif encoding_type == EncodingType.URL:
            return self.encode_for_url(value)
        else:
            return self.encode_for_html(value)  # Default to HTML

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe file operations.

        Args:
            filename: Original filename

        Returns:
            Safe filename
        """
        # Remove directory separators and dangerous characters
        safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", filename)

        # Remove leading dots
        safe = safe.lstrip(".")

        # Limit length
        if len(safe) > 255:
            name, ext = safe[:250], safe[-5:] if "." in safe[-5:] else ""
            safe = name + ext

        # Ensure non-empty
        if not safe:
            safe = "report"

        return safe

    def create_safe_id(self, text: str) -> str:
        """
        Create safe HTML ID from text.

        Args:
            text: Source text

        Returns:
            Safe ID string
        """
        # Convert to lowercase and replace non-alphanumeric with dashes
        safe_id = re.sub(r"[^a-z0-9]+", "-", text.lower())

        # Remove leading/trailing dashes
        safe_id = safe_id.strip("-")

        # Ensure starts with letter
        if safe_id and not safe_id[0].isalpha():
            safe_id = "id-" + safe_id

        # Limit length
        if len(safe_id) > 50:
            safe_id = safe_id[:50].rstrip("-")

        return safe_id or "id"

    def get_encoding_stats(self) -> Dict[str, int]:
        """Get encoding statistics."""
        return self._encoding_stats.copy()
