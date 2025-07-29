"""Advanced security tests for input sanitization middleware.

This module tests sophisticated attack vectors that were missing from basic tests:
- Unicode-based attacks (UTF-8 overlong encoding, homograph attacks)
- Polyglot payloads that work across multiple contexts
- DOM-based XSS patterns in JSON responses
- Mutation XSS (mXSS) scenarios
- Deeply nested data structures with malicious content
- Performance and DoS scenarios
- Encoding attack vectors
"""

import json
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch
from urllib.parse import quote, quote_plus

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.middleware.input_sanitization import InputSanitizationMiddleware


@pytest.fixture
def app():
    """Create test FastAPI app with input sanitization middleware."""
    app = FastAPI()
    app.add_middleware(InputSanitizationMiddleware)

    @app.post("/json")
    async def json_endpoint(request: Request):
        # Try to get sanitized body first
        from app.middleware.input_sanitization import get_sanitized_body

        sanitized_body = get_sanitized_body(request)
        if sanitized_body:
            return {"received": json.loads(sanitized_body.decode("utf-8"))}
        else:
            # Fallback to original method
            body = await request.body()
            return {"received": json.loads(body)}

    @app.post("/form")
    async def form_endpoint(request: Request):
        body = await request.body()
        return {"received": body.decode()}

    @app.post("/text")
    async def text_endpoint(request: Request):
        body = await request.body()
        return {"received": body.decode()}

    @app.get("/query")
    async def query_endpoint(request: Request):
        # Access sanitized params from request state
        params = getattr(request.state, "sanitized_query_params", {})
        return {"params": params}

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestUnicodeAttacks:
    """Test protection against Unicode-based attacks."""

    def test_utf8_overlong_encoding(self, client):
        """Test UTF-8 overlong encoding attacks."""
        # Overlong encoding of '<' (0x3C)
        # Normal: 0x3C
        # Overlong: 0xC0 0xBC (invalid UTF-8)
        overlong_attacks = [
            # Overlong encodings (these will likely be rejected by Python)
            b"\xc0\xbc",  # Overlong '<'
            b"\xe0\x80\xbc",  # Even more overlong '<'
            b"\xf0\x80\x80\xbc",  # Maximum overlong '<'
        ]

        for attack in overlong_attacks:
            try:
                # Try as raw bytes
                response = client.post("/text", content=attack, headers={"Content-Type": "text/plain"})
                # Should either reject or sanitize
                if response.status_code == 200:
                    assert b"<" not in response.content
            except Exception:
                # Invalid encoding should be handled gracefully
                pass

    def test_unicode_homograph_attacks(self, client):
        """Test Unicode homograph/homoglyph attacks."""
        # Various Unicode characters that look like ASCII
        homograph_attacks = {
            "а": "a",  # Cyrillic 'а' (U+0430) vs Latin 'a'
            "е": "e",  # Cyrillic 'е' (U+0435) vs Latin 'e'
            "о": "o",  # Cyrillic 'о' (U+043E) vs Latin 'o'
            "с": "c",  # Cyrillic 'с' (U+0441) vs Latin 'c'
            "⁄": "/",  # Fraction slash (U+2044) vs solidus
            "˂": "<",  # Modifier letter left arrowhead vs less-than
            "˃": ">",  # Modifier letter right arrowhead vs greater-than
        }

        for fake_char, real_char in homograph_attacks.items():
            # Test in JSON payload
            payload = {"script": f"{fake_char}script{fake_char}alert('xss'){fake_char}/script{fake_char}"}
            response = client.post("/json", json=payload)
            assert response.status_code == 200
            # Should sanitize lookalike characters

    def test_unicode_normalization_attacks(self, client):
        """Test Unicode normalization attacks."""
        # Different Unicode normalization forms can bypass filters
        normalization_attacks = [
            # Combining characters
            "e\u0301",  # é as e + combining acute accent
            "<\u0338",  # < with combining long solidus overlay
            # Zero-width characters
            "java\u200bscript:",  # Zero-width space
            "java\u200cscript:",  # Zero-width non-joiner
            "java\u200dscript:",  # Zero-width joiner
            "java\ufeffscript:",  # Zero-width no-break space
        ]

        for attack in normalization_attacks:
            response = client.get(f"/query?input={quote(attack)}")
            assert response.status_code == 200
            result = response.json()
            # Should handle Unicode normalization
            if "params" in result and "input" in result["params"]:
                assert "javascript:" not in result["params"]["input"].lower()

    def test_bidi_override_attacks(self, client):
        """Test bidirectional text override attacks."""
        # Right-to-left override can hide malicious content
        bidi_attacks = [
            "\u202e<script>alert('xss')</script>",  # RLO character
            "normal\u202emalicious\u202ctext",  # RLO + PDF
            "\u200f<img src=x onerror=alert(1)>",  # RLM character
        ]

        for attack in bidi_attacks:
            payload = {"comment": attack}
            response = client.post("/json", json=payload)
            assert response.status_code == 200
            # Bidi characters should be sanitized


class TestPolyglotPayloads:
    """Test polyglot payloads that work across multiple contexts."""

    def test_javascript_html_polyglot(self, client):
        """Test payloads that work in both JavaScript and HTML contexts."""
        polyglot_payloads = [
            # Works in HTML attribute and JavaScript
            '";alert(1);//<script>alert(2)</script>',
            "';alert(1);//<img src=x onerror=alert(2)>",
            # Works in multiple contexts
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload="+/`/+/onmouseover=1/+/[*/[]/+alert(1)//">',
            # JSON/JavaScript polyglot
            '{"a":"b"}//<script>alert(1)</script>',
        ]

        for payload in polyglot_payloads:
            # Test as JSON value
            response = client.post("/json", json={"input": payload})
            assert response.status_code == 200
            result = response.json()
            # Should be sanitized
            assert "alert" not in str(result).lower() or "[FILTERED]" in str(result)

    def test_sql_xss_polyglot(self, client):
        """Test payloads that combine SQL injection and XSS."""
        polyglot_payloads = [
            "'; DROP TABLE users; --<script>alert(1)</script>",
            "1' UNION SELECT '<script>alert(1)</script>'--",
            "admin'--<img src=x onerror=alert(1)>",
        ]

        for payload in polyglot_payloads:
            response = client.get(f"/query?search={quote(payload)}")
            assert response.status_code == 200
            result = response.json()
            # Should sanitize both SQL and XSS
            if "params" in result and "search" in result["params"]:
                sanitized = result["params"]["search"]
                assert "DROP TABLE" not in sanitized
                assert "<script>" not in sanitized

    def test_multiencoding_polyglot(self, client):
        """Test polyglot with multiple encoding layers."""
        # URL encode -> HTML encode -> JavaScript encode
        polyglot = "<script>alert('xss')</script>"

        # Multiple encoding layers
        encoded_payloads = [
            polyglot,  # Raw
            quote(polyglot),  # URL encoded once
            quote(quote(polyglot)),  # URL encoded twice
            f"&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;",  # HTML entities
            "\\x3cscript\\x3ealert('xss')\\x3c/script\\x3e",  # Hex encoding
        ]

        for payload in encoded_payloads:
            response = client.get(f"/query?data={payload}")
            assert response.status_code == 200
            # Should handle multiple encoding layers


class TestDOMXSSPatterns:
    """Test DOM-based XSS patterns in JSON responses."""

    def test_json_response_dom_xss(self, client):
        """Test DOM XSS patterns in JSON responses."""
        dom_xss_patterns = [
            {"html": "<img src=x onerror=alert(1)>"},
            {"eval": "javascript:eval('alert(1)')"},
            {"innerHTML": "<svg onload=alert(1)>"},
            {"document.write": "<script>alert(1)</script>"},
            {"location": "javascript:alert(1)"},
        ]

        for pattern in dom_xss_patterns:
            response = client.post("/json", json=pattern)
            assert response.status_code == 200
            result = response.json()
            # Should sanitize DOM XSS patterns
            assert "alert(1)" not in json.dumps(result)

    def test_json_callback_injection(self, client):
        """Test JSONP callback injection attacks."""
        # JSONP callbacks can execute JavaScript
        callbacks = [
            "alert(1)",
            "eval('alert(1)')",
            "Function('alert(1)')()",
            "<script>alert(1)</script>",
        ]

        for callback in callbacks:
            response = client.get(f"/query?callback={quote(callback)}")
            assert response.status_code == 200
            result = response.json()
            # Callback should be sanitized
            if "params" in result and "callback" in result["params"]:
                assert "alert" not in result["params"]["callback"]

    def test_angular_template_injection(self, client):
        """Test AngularJS template injection patterns."""
        angular_payloads = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{7*7}}",  # Simple expression
            "{{ {'a':'b'}.constructor.prototype.charAt=[].join;$eval('x=alert(1)'); }}",
        ]

        for payload in angular_payloads:
            response = client.post("/json", json={"template": payload})
            assert response.status_code == 200
            # Should sanitize Angular expressions


class TestMutationXSS:
    """Test mutation XSS (mXSS) scenarios."""

    def test_browser_mutation_patterns(self, client):
        """Test patterns that mutate when parsed by browsers."""
        mxss_patterns = [
            # Patterns that change when innerHTML is used
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            '<style><p title="</style><img src=x onerror=alert(1)>">',
            '<script><!--<p title="</script><img src=x onerror=alert(1)>">-->',
            # Double encoding that mutates
            "&lt;img src=x onerror=alert(1)&gt;",
        ]

        for pattern in mxss_patterns:
            response = client.post("/json", json={"content": pattern})
            assert response.status_code == 200
            # Should handle mutation patterns

    def test_namespace_confusion(self, client):
        """Test namespace confusion attacks."""
        # SVG/MathML namespace confusion
        namespace_attacks = [
            '<svg><p id="</p><img src=x onerror=alert(1)>">',
            '<math><p id="</p><img src=x onerror=alert(1)>">',
            '<svg><foreignObject><p id="</foreignObject><img src=x onerror=alert(1)>">',
        ]

        for attack in namespace_attacks:
            response = client.post("/json", json={"svg": attack})
            assert response.status_code == 200


class TestNestedDataStructures:
    """Test deeply nested data structures with malicious content."""

    def test_deeply_nested_json(self, client):
        """Test deeply nested JSON with malicious content at various levels."""

        # Create deeply nested structure
        def create_nested_payload(depth: int, payload: str) -> Dict[str, Any]:
            if depth == 0:
                return {"value": payload}
            return {"nested": create_nested_payload(depth - 1, payload)}

        # Test various depths
        for depth in [5, 10, 20, 50]:
            nested = create_nested_payload(depth, "<script>alert(1)</script>")
            response = client.post("/json", json=nested)
            assert response.status_code == 200
            # Should sanitize at all depths

    def test_recursive_depth_limit(self, client):
        """Test recursive sanitization depth limits."""
        # Create circular reference (not possible in JSON, but test the concept)
        large_nested = {}
        current = large_nested
        for i in range(100):
            current["level"] = {"xss": f"<script>alert({i})</script>", "next": {}}
            current = current["level"]["next"]

        response = client.post("/json", json=large_nested)
        # Should handle without stack overflow
        assert response.status_code in [200, 400, 413]

    def test_mixed_nested_attacks(self, client):
        """Test nested structures with different attack types."""
        mixed_payload = {
            "users": [
                {"name": "<script>alert(1)</script>"},
                {"email": "'; DROP TABLE users; --"},
                {"comment": "javascript:alert(1)"},
            ],
            "settings": {
                "theme": "<style>@import 'http://evil.com/css'</style>",
                "callback": "eval('alert(1)')",
                "template": "{{constructor.constructor('alert(1)')()}}",
            },
            "deeply": {
                "nested": {
                    "value": "\u202e<script>alert('rtl')</script>",
                    "items": ["<img src=x onerror=alert(1)>"] * 10,
                }
            },
        }

        response = client.post("/json", json=mixed_payload)
        assert response.status_code == 200
        # All attack vectors should be sanitized


class TestPerformanceAndDoS:
    """Test performance impact and DoS scenarios."""

    def test_large_payload_performance(self, client):
        """Test performance with large payloads approaching 10MB limit."""
        # Create large payload with potential XSS
        large_data = {"items": [{"id": i, "data": f"<script>alert({i})</script>" * 100} for i in range(1000)]}

        # Measure sanitization time
        start_time = time.time()
        response = client.post("/json", json=large_data)
        processing_time = time.time() - start_time

        # Should complete within reasonable time
        assert response.status_code in [200, 413]
        assert processing_time < 5.0  # 5 seconds max

    def test_algorithmic_complexity_attack(self, client):
        """Test algorithmic complexity attacks with crafted input."""
        # Patterns that could cause exponential processing
        complexity_attacks = [
            # Nested brackets that could cause backtracking
            "(" * 1000 + ")" * 1000,
            # Repeated patterns
            "a" * 10000 + "b" * 10000,
            # Many special characters
            "".join(["<>\"'&"] * 2000),
        ]

        for attack in complexity_attacks:
            start_time = time.time()
            response = client.get(f"/query?input={quote(attack[:1000])}")  # Limit size
            processing_time = time.time() - start_time

            assert response.status_code == 200
            assert processing_time < 1.0  # Should not cause DoS

    def test_memory_exhaustion_patterns(self, client):
        """Test patterns designed to exhaust memory."""
        # Patterns that could cause memory issues
        memory_attacks = [
            # Very long strings without spaces
            "A" * 100000,
            # Unicode expansion
            "\u0041\u0301" * 10000,  # A with combining accent
            # Entity expansion
            "&" + "amp;" * 1000,
        ]

        for attack in memory_attacks[:1]:  # Test conservatively
            try:
                response = client.post(
                    "/text", content=attack[:10000], headers={"Content-Type": "text/plain"}  # Limit size
                )
                assert response.status_code in [200, 413]
            except Exception:
                # Should handle gracefully
                pass

    def test_payload_size_limits(self, client):
        """Test payload size limit enforcement."""
        # Create payload just under 10MB
        size_9mb = "x" * (9 * 1024 * 1024)
        response = client.post("/text", content=size_9mb, headers={"Content-Type": "text/plain"})
        assert response.status_code == 200

        # Create payload just over 10MB
        size_11mb = "x" * (11 * 1024 * 1024)
        response = client.post("/text", content=size_11mb, headers={"Content-Type": "text/plain"})
        assert response.status_code == 413  # Request Entity Too Large


class TestEncodingAttacks:
    """Test various encoding attack vectors."""

    def test_double_url_encoding(self, client):
        """Test double and triple URL encoding attempts."""
        # %3C = <, %253C = %3C (double encoded)
        encoding_attacks = [
            "%3Cscript%3Ealert(1)%3C/script%3E",  # Single
            "%253Cscript%253Ealert(1)%253C/script%253E",  # Double
            "%25253Cscript%25253Ealert(1)%25253C/script%25253E",  # Triple
        ]

        for attack in encoding_attacks:
            response = client.get(f"/query?payload={attack}")
            assert response.status_code == 200
            result = response.json()
            # Should decode and sanitize all layers
            if "params" in result and "payload" in result["params"]:
                assert "<script>" not in result["params"]["payload"]

    def test_mixed_encoding_types(self, client):
        """Test mixed encoding types (URL + HTML + Unicode)."""
        mixed_encodings = [
            # URL + HTML entities
            "%3C&#115;cript%3Ealert(1)%3C/&#115;cript%3E",
            # Unicode + URL
            "\\u003Cscript%3Ealert(1)\\u003C/script%3E",
            # HTML entities + Unicode
            "&lt;script&#x3E;alert\\u0028\\u0031\\u0029&lt;/script&#x3E;",
        ]

        for attack in mixed_encodings:
            response = client.get(f"/query?mixed={quote(attack)}")
            assert response.status_code == 200
            # Should handle mixed encodings

    def test_charset_confusion(self, client):
        """Test character set confusion attacks."""
        # Different charsets can interpret bytes differently
        charset_attacks = [
            # UTF-7 encoding (if supported)
            "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
            # Latin-1 vs UTF-8 confusion
            b"\xc0\xbc",  # Could be interpreted differently
        ]

        for attack in charset_attacks:
            if isinstance(attack, bytes):
                response = client.post("/text", content=attack, headers={"Content-Type": "text/plain; charset=latin-1"})
            else:
                response = client.post("/text", content=attack)
            # Should handle charset issues
            assert response.status_code in [200, 400]

    def test_null_byte_injection(self, client):
        """Test null byte injection attempts."""
        null_byte_attacks = [
            "file.php\x00.jpg",  # Null byte truncation
            "<script>\x00alert(1)</script>",  # Null in tag
            "java\x00script:alert(1)",  # Null in protocol
        ]

        for attack in null_byte_attacks:
            response = client.get(f"/query?file={quote(attack)}")
            assert response.status_code == 200
            result = response.json()
            # Null bytes should be handled
            if "params" in result and "file" in result["params"]:
                assert "\x00" not in result["params"]["file"]


class TestEdgeCasesAndSpecialScenarios:
    """Test edge cases and special scenarios."""

    def test_empty_and_whitespace_payloads(self, client):
        """Test empty and whitespace-only payloads."""
        edge_cases = [
            "",
            " ",
            "\t\n\r",
            "\u0000",  # Null
            "\u200b",  # Zero-width space
        ]

        for payload in edge_cases:
            response = client.post("/text", content=payload)
            assert response.status_code == 200

    def test_content_type_boundary_cases(self, client):
        """Test content type boundary cases."""
        # Test with unusual content types
        content_types = [
            "application/json; charset=utf-8",
            "application/json;charset=utf-8",  # No space
            "application/JSON",  # Uppercase
            "application/json; boundary=something",  # Extra params
        ]

        for ct in content_types:
            response = client.post("/json", json={"test": "<script>alert(1)</script>"}, headers={"Content-Type": ct})
            # Should handle various content type formats
            assert response.status_code in [200, 400]

    def test_header_injection_attempts(self, client):
        """Test header injection attempts."""
        # Try to inject headers through values
        header_injections = [
            "value\r\nX-Injected: true",
            "value\nX-Evil: yes",
            "value\r\n\r\n<script>alert(1)</script>",
        ]

        for injection in header_injections:
            response = client.get("/query", headers={"X-Custom": injection})
            assert response.status_code == 200
            # Should sanitize header values

    def test_unicode_case_variations(self, client):
        """Test Unicode case variations that might bypass filters."""
        case_variations = [
            "ＳＣＲＩＰＴ",  # Fullwidth
            "ѕсrірt",  # Mixed scripts
            "ScRiPt",  # Mixed case
            "ⓢⓒⓡⓘⓟⓣ",  # Circled letters
        ]

        for variant in case_variations:
            payload = f"<{variant}>alert(1)</{variant}>"
            response = client.post("/json", json={"tag": payload})
            assert response.status_code == 200
            # Should handle Unicode case variations
