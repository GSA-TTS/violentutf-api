"""
Unit tests for output encoding security module.

Tests context-aware encoding to prevent XSS and injection attacks
in different output contexts.
"""

import json

import pytest

from tools.pre_audit.reporting.security import EncodingType, OutputEncoder


class TestOutputEncoder:
    """Test suite for OutputEncoder class."""

    @pytest.fixture
    def encoder(self):
        """Create OutputEncoder instance."""
        return OutputEncoder()

    # Test HTML Encoding
    def test_encode_for_html_basic(self, encoder):
        """Test basic HTML encoding."""
        test_cases = [
            ("<script>alert('XSS')</script>", "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;&#x2F;script&gt;"),
            ("Hello & World", "Hello &amp; World"),
            ("<div>Test</div>", "&lt;div&gt;Test&lt;&#x2F;div&gt;"),
            ("'Single' and \"Double\" quotes", "&#x27;Single&#x27; and &quot;Double&quot; quotes"),
            ("Forward / slash", "Forward &#x2F; slash"),
        ]

        for input_str, expected in test_cases:
            result = encoder.encode_for_html(input_str)
            assert result == expected

    def test_encode_for_html_null_bytes(self, encoder):
        """Test that null bytes are removed."""
        input_str = "Test\x00String"
        result = encoder.encode_for_html(input_str)
        assert "\x00" not in result
        assert "TestString" in result

    def test_encode_for_html_none(self, encoder):
        """Test encoding None value."""
        result = encoder.encode_for_html(None)
        assert result == ""

    # Test HTML Attribute Encoding
    def test_encode_for_html_attribute(self, encoder):
        """Test HTML attribute encoding with additional restrictions."""
        test_cases = [
            ("onclick='alert(1)'", "onclick&#x3D;&#x27;alert(1)&#x27;"),
            ("Line\nBreak", "Line&#10;Break"),
            ("Tab\tCharacter", "Tab&#9;Character"),
            ("Carriage\rReturn", "Carriage&#13;Return"),
        ]

        for input_str, expected in test_cases:
            result = encoder.encode_for_html_attribute(input_str)
            assert expected in result

    def test_encode_for_html_attribute_non_ascii(self, encoder):
        """Test that non-ASCII characters are encoded."""
        input_str = "Émoji 😀"
        result = encoder.encode_for_html_attribute(input_str)
        # Should encode the emoji
        assert "&#x" in result
        assert "😀" not in result

    # Test JavaScript Encoding
    def test_encode_for_javascript_basic(self, encoder):
        """Test basic JavaScript encoding."""
        test_cases = [
            ("alert('XSS')", "alert(\\'XSS\\')"),
            ('say "hello"', 'say \\"hello\\"'),
            ("Line\nBreak", "Line\\nBreak"),
            ("Tab\tChar", "Tab\\tChar"),
            ("Backslash\\", "Backslash\\\\"),
            ("</script>", "\\u003C\\u002Fscript\\u003E"),
        ]

        for input_str, expected in test_cases:
            result = encoder.encode_for_javascript(input_str)
            assert result == expected

    def test_encode_for_javascript_special_chars(self, encoder):
        """Test JavaScript encoding of special characters."""
        test_cases = [
            ("\x00", "\\u0000"),  # Null byte
            ("<", "\\u003C"),  # Less than
            (">", "\\u003E"),  # Greater than
            ("&", "\\u0026"),  # Ampersand
            ("=", "\\u003D"),  # Equals
            ("/", "\\u002F"),  # Forward slash
        ]

        for input_str, expected in test_cases:
            result = encoder.encode_for_javascript(input_str)
            assert result == expected

    def test_encode_for_javascript_unicode(self, encoder):
        """Test JavaScript encoding of Unicode characters."""
        input_str = "Unicode: 你好"
        result = encoder.encode_for_javascript(input_str)
        # Chinese characters should be encoded
        assert "\\u" in result
        assert "你" not in result

    # Test CSS Encoding
    def test_encode_for_css_basic(self, encoder):
        """Test basic CSS encoding."""
        input_str = "background-image"
        result = encoder.encode_for_css(input_str)
        assert result == "background-image"  # Alphanumeric and dash are safe

    def test_encode_for_css_special_chars(self, encoder):
        """Test CSS encoding of special characters."""
        input_str = "url('image.jpg')"
        result = encoder.encode_for_css(input_str)
        # Should encode parentheses, quotes, etc.
        assert "\\000028" in result or "\\28" in result  # (
        assert "\\000029" in result or "\\29" in result  # )

    def test_encode_for_css_blocks_dangerous(self, encoder):
        """Test that dangerous CSS patterns are blocked."""
        dangerous_patterns = [
            "javascript:alert(1)",
            "expression(alert(1))",
            "@import url('evil.css')",
            "</style><script>alert(1)</script>",
        ]

        for pattern in dangerous_patterns:
            result = encoder.encode_for_css(pattern)
            assert result == ""  # Should return empty string

    # Test JSON Encoding
    def test_encode_for_json_basic(self, encoder):
        """Test basic JSON encoding."""
        test_cases = [
            ("Hello World", '"Hello World"'),
            ({"key": "value"}, '{"key":"value"}'),
            ([1, 2, 3], "[1,2,3]"),
            (None, "null"),
            (True, "true"),
            (False, "false"),
        ]

        for input_val, expected in test_cases:
            result = encoder.encode_for_json(input_val)
            assert result == expected

    def test_encode_for_json_unicode(self, encoder):
        """Test JSON encoding with Unicode."""
        input_str = "Unicode: 你好"
        result = encoder.encode_for_json(input_str)
        # Should use ASCII encoding
        assert "\\u" in result
        decoded = json.loads(result)
        assert decoded == input_str

    def test_encode_for_json_invalid_type(self, encoder):
        """Test JSON encoding with non-serializable type."""

        class CustomObject:
            def __str__(self):
                return "CustomObject"

        obj = CustomObject()
        result = encoder.encode_for_json(obj)
        assert result == '"CustomObject"'

    # Test URL Encoding
    def test_encode_for_url(self, encoder):
        """Test URL encoding."""
        test_cases = [
            ("hello world", "hello%20world"),
            ("param=value&other=test", "param%3Dvalue%26other%3Dtest"),
            ("special!@#$%", "special%21%40%23%24%25"),
        ]

        for input_str, expected in test_cases:
            result = encoder.encode_for_url(input_str)
            assert result == expected

    # Test Dictionary Encoding
    def test_encode_dict_values(self, encoder):
        """Test recursive dictionary encoding."""
        input_dict = {
            "html": "<script>alert(1)</script>",
            "nested": {"value": "<div>Test</div>", "list": ["<b>Bold</b>", "Normal"]},
            "number": 42,
        }

        result = encoder.encode_dict_values(input_dict, EncodingType.HTML)

        assert "&lt;script&gt;" in result["html"]
        assert "&lt;div&gt;" in result["nested"]["value"]
        assert "&lt;b&gt;" in result["nested"]["list"][0]
        assert result["nested"]["list"][1] == "Normal"
        assert result["number"] == 42

    # Test List Encoding
    def test_encode_list_values(self, encoder):
        """Test recursive list encoding."""
        input_list = ["<script>alert(1)</script>", {"key": "<value>"}, ["<nested>", "safe"], 42]

        result = encoder.encode_list_values(input_list, EncodingType.HTML)

        assert "&lt;script&gt;" in result[0]
        assert "&lt;value&gt;" in result[1]["key"]
        assert "&lt;nested&gt;" in result[2][0]
        assert result[2][1] == "safe"
        assert result[3] == 42

    # Test Filename Sanitization
    def test_sanitize_filename_basic(self, encoder):
        """Test basic filename sanitization."""
        test_cases = [
            ("report.pdf", "report.pdf"),
            ("my report.pdf", "my_report.pdf"),
            ("../../../etc/passwd", "_.._.._.._etc_passwd"),
            ("file<script>.pdf", "file_script_.pdf"),
            (".hidden", "hidden"),  # Remove leading dots
            ("very" + "long" * 100 + ".pdf", "very" + "long" * 62 + ".pdf"),  # Length limit
        ]

        for input_name, expected in test_cases:
            result = encoder.sanitize_filename(input_name)
            assert len(result) <= 255
            if expected.endswith(".pdf"):
                assert result.endswith(".pdf") or result.endswith("_.pdf")

    def test_sanitize_filename_empty(self, encoder):
        """Test filename sanitization with empty input."""
        test_cases = ["", ".", "..", "..."]

        for input_name in test_cases:
            result = encoder.sanitize_filename(input_name)
            assert result == "report"  # Default name

    # Test Safe ID Creation
    def test_create_safe_id(self, encoder):
        """Test creation of safe HTML IDs."""
        test_cases = [
            ("Section Title", "section-title"),
            ("123-start", "id-123-start"),  # Ensure starts with letter
            ("Special!@#$%Chars", "special-chars"),
            ("  Trim  Spaces  ", "trim-spaces"),
            ("very-" + "long-" * 20 + "id", "very-" + "long-" * 9 + "long"),  # Length limit
        ]

        for input_text, expected in test_cases:
            result = encoder.create_safe_id(input_text)
            assert result[0].isalpha()  # Must start with letter
            assert len(result) <= 50
            assert all(c.isalnum() or c == "-" for c in result)

    def test_create_safe_id_empty(self, encoder):
        """Test safe ID creation with empty input."""
        result = encoder.create_safe_id("")
        assert result == "id"

    # Test Statistics
    def test_get_encoding_stats(self, encoder):
        """Test encoding statistics tracking."""
        # Perform various encodings
        encoder.encode_for_html("Test")
        encoder.encode_for_html("Test2")
        encoder.encode_for_json({"key": "value"})
        encoder.encode_for_css("javascript:alert(1)")  # Dangerous, will be blocked

        stats = encoder.get_encoding_stats()

        assert stats["html_encoded"] == 2
        assert stats["json_encoded"] == 1
        assert stats["css_encoded"] == 1
        assert stats["dangerous_blocked"] == 1
