"""HTML sanitization and input cleaning utilities."""

import html
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import unquote, urlparse

import bleach
from structlog.stdlib import get_logger

logger = get_logger(__name__)

# Default allowed HTML tags for basic formatting
DEFAULT_ALLOWED_TAGS = {
    "p",
    "br",
    "strong",
    "em",
    "u",
    "ol",
    "ul",
    "li",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
}

# Default allowed attributes
DEFAULT_ALLOWED_ATTRIBUTES = {
    "*": ["class"],
    "a": ["href", "title"],
    "img": ["src", "alt", "title", "width", "height"],
}

# Dangerous HTML tags that should never be allowed
DANGEROUS_TAGS = {
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "applet",
    "form",
    "input",
    "textarea",
    "select",
    "option",
    "button",
    "link",
    "meta",
    "base",
    "frame",
    "frameset",
}

# Dangerous attributes that could contain JavaScript
DANGEROUS_ATTRIBUTES = {
    "onclick",
    "onload",
    "onerror",
    "onmouseover",
    "onmouseout",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
    "onreset",
    "onselect",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "onabort",
    "oncanplay",
    "oncanplaythrough",
    "ondurationchange",
    "onemptied",
    "onended",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onpause",
    "onplay",
    "onplaying",
    "onprogress",
    "onratechange",
    "onseeked",
    "onseeking",
    "onstalled",
    "onsuspend",
    "ontimeupdate",
    "onvolumechange",
    "onwaiting",
}

# Common XSS patterns to remove
XSS_PATTERNS = [
    r"javascript:",
    r"vbscript:",
    r"data:text/html",
    r"data:image/svg\+xml",
    r"on\w+\s*=",
    r"expression\s*\(",
    r"@import",
    r"behaviour\s*:",
    r"-moz-binding",
]


def sanitize_html(
    html_content: str,
    allowed_tags: Optional[Set[str]] = None,
    allowed_attributes: Optional[Dict[str, List[str]]] = None,
    strip_dangerous: bool = True,
) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.

    Args:
        html_content: HTML content to sanitize
        allowed_tags: Set of allowed HTML tags (default: basic formatting tags)
        allowed_attributes: Dict of allowed attributes per tag
        strip_dangerous: Whether to strip dangerous tags/attributes

    Returns:
        Sanitized HTML content
    """
    if not html_content or not isinstance(html_content, str):
        return ""

    if allowed_tags is None:
        allowed_tags = DEFAULT_ALLOWED_TAGS.copy()

    if allowed_attributes is None:
        allowed_attributes = DEFAULT_ALLOWED_ATTRIBUTES.copy()

    # Remove dangerous tags if strip_dangerous is True
    if strip_dangerous:
        allowed_tags = allowed_tags - DANGEROUS_TAGS

        # Remove dangerous attributes
        cleaned_attributes = {}
        for tag, attrs in allowed_attributes.items():
            cleaned_attrs = [attr for attr in attrs if attr.lower() not in DANGEROUS_ATTRIBUTES]
            if cleaned_attrs:
                cleaned_attributes[tag] = cleaned_attrs
        allowed_attributes = cleaned_attributes

    try:
        # Use bleach to sanitize HTML
        sanitized: str = bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True,  # Strip disallowed tags instead of escaping
            strip_comments=True,
        )

        # Additional XSS pattern removal
        for pattern in XSS_PATTERNS:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        logger.debug("HTML sanitized", original_length=len(html_content), sanitized_length=len(sanitized))
        return sanitized

    except Exception as e:
        logger.error("HTML sanitization failed", error=str(e))
        # Fallback to aggressive escaping
        return html.escape(html_content)


def sanitize_url(url: str, allowed_schemes: Optional[List[str]] = None) -> Optional[str]:
    """
    Sanitize URL to prevent malicious schemes.

    Args:
        url: URL to sanitize
        allowed_schemes: List of allowed URL schemes

    Returns:
        Sanitized URL or None if dangerous
    """
    if not url or not isinstance(url, str):
        return None

    if allowed_schemes is None:
        allowed_schemes = ["http", "https", "mailto"]

    try:
        # Check for null bytes
        if "\x00" in url:
            logger.warning("URL contains null byte", url=url[:100])
            return None

        url = url.strip()

        # Check if URL is empty after stripping
        if not url:
            return None

        parsed = urlparse(url)

        # Validate port if present
        try:
            if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
                logger.warning("Invalid port number", port=parsed.port, url=url[:100])
                return None
        except ValueError:
            # urlparse raises ValueError for invalid ports
            logger.warning("Invalid port in URL", url=url[:100])
            return None

        # Check scheme
        if parsed.scheme and parsed.scheme.lower() not in allowed_schemes:
            logger.warning("Dangerous URL scheme blocked", scheme=parsed.scheme, url=url[:100])
            return None

        # Check for dangerous patterns in the original URL and decoded URL
        url_lower = url.lower()
        decoded_url_lower = unquote(url).lower()

        # Remove whitespace and control characters for better detection
        clean_url = re.sub(r"[\s\t\r\n]", "", decoded_url_lower)

        dangerous_patterns = ["javascript:", "vbscript:", "data:text/html"]

        # Check both original and cleaned versions
        for pattern in dangerous_patterns:
            if pattern in url_lower or pattern in clean_url:
                logger.warning("Dangerous URL pattern blocked", url=url[:100])
                return None

        return url

    except Exception as e:
        logger.error("URL sanitization failed", error=str(e), url=url[:100])
        return None


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename to prevent directory traversal and other attacks.

    Args:
        filename: Filename to sanitize
        max_length: Maximum allowed filename length

    Returns:
        Sanitized filename
    """
    if not filename or not isinstance(filename, str):
        return "unnamed_file"

    # Handle special cases first
    if filename == ".":
        return "unnamed_file"
    elif filename == "..":
        return "unnamed_file"
    elif filename == "...":
        return "unnamed_file"
    elif filename.startswith("...") and len(filename) > 3:
        # Remove all leading dots for triple-dot files like "...hidden"
        filename = filename.lstrip(".")

    # Remove directory traversal attempts
    filename = filename.replace("..", "").replace("/", "").replace("\\", "")

    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*\x00-\x1f]', "", filename)

    # Remove leading/trailing whitespace
    filename = filename.strip()

    # Remove trailing dots
    filename = filename.rstrip(".")

    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
        if ext:
            max_name_length = max_length - len(ext) - 1
            filename = f"{name[:max_name_length]}.{ext}"
        else:
            filename = filename[:max_length]

    # Ensure not empty
    if not filename:
        filename = "unnamed_file"

    return filename


def sanitize_sql_input(input_text: str) -> str:
    """
    Sanitize input to prevent SQL injection.

    Args:
        input_text: Input text to sanitize

    Returns:
        Sanitized input text
    """
    if not input_text or not isinstance(input_text, str):
        return ""

    # More comprehensive SQL injection patterns
    dangerous_patterns = [
        r"';\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\s+",
        r"(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\s+(TABLE|DATABASE|INDEX|VIEW)",
        r"UNION\s+(ALL\s+)?SELECT",
        r"OR\s+1\s*=\s*1",
        r"AND\s+1\s*=\s*1",
        r"'\s*OR\s*'.*'\s*=\s*'",
        r"'\s*OR\s+1\s*=\s*1",
        r"'\s*AND\s+1\s*=\s*1",
        r"--\s*",
        r"/\*.*\*/",
        r"xp_cmdshell",
        r"sp_executesql",
        r"exec\s*\(",
        r"execute\s*\(",
        r"information_schema",
        r"sysobjects",
        r"syscolumns",
        r"@@version",
        r"@@user",
        r"@@servername",
        r"waitfor\s+delay",
        r"convert\s*\(",
        r"cast\s*\(",
        r"char\s*\(",
        r"ascii\s*\(",
        r"substring\s*\(",
        r"having\s+1\s*=\s*1",
        r"group\s+by\s+.*having",
        r"order\s+by\s+.*--",
        r"into\s+outfile",
        r"load_file\s*\(",
        r"benchmark\s*\(",
        r"sleep\s*\(",
        r"pg_sleep\s*\(",
    ]

    sanitized = input_text
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.MULTILINE)

    # Additional aggressive filtering for standalone dangerous keywords
    dangerous_keywords = [
        r"\bDROP\s+TABLE\b",
        r"\bDELETE\s+FROM\b",
        r"\bINSERT\s+INTO\b",
        r"\bUPDATE\s+SET\b",
        r"\bCREATE\s+TABLE\b",
        r"\bALTER\s+TABLE\b",
        r"\bTRUNCATE\s+TABLE\b",
    ]

    for keyword in dangerous_keywords:
        sanitized = re.sub(keyword, "", sanitized, flags=re.IGNORECASE)

    # Escape remaining single quotes
    sanitized = sanitized.replace("'", "''")

    return sanitized.strip()


def sanitize_log_output(log_data: str, max_length: int = 1000) -> str:
    """
    Sanitize log output to prevent log injection and limit size.

    Args:
        log_data: Log data to sanitize
        max_length: Maximum log entry length

    Returns:
        Sanitized log data
    """
    if not log_data or not isinstance(log_data, str):
        return ""

    # Remove ANSI escape sequences
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    sanitized = ansi_escape.sub("", log_data)

    # Remove control characters except tab, newline, carriage return
    sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", sanitized)

    # Replace multiple whitespace with single space
    sanitized = re.sub(r"\s+", " ", sanitized)

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"

    return sanitized.strip()


def sanitize_json_keys(data: object, allowed_keys: Optional[Set[str]] = None) -> Dict[str, Any]:
    """
    Sanitize JSON object keys to only allow specified keys.

    Args:
        data: Dictionary to sanitize
        allowed_keys: Set of allowed keys (if None, allows all)

    Returns:
        Sanitized dictionary
    """
    if not isinstance(data, dict):
        return {}

    if allowed_keys is None:
        return data

    return {k: v for k, v in data.items() if k in allowed_keys}


def remove_sensitive_data(text: str, patterns: Optional[List[str]] = None) -> str:
    """
    Remove sensitive data patterns from text.

    Args:
        text: Text to clean
        patterns: List of regex patterns to remove (default: common sensitive patterns)

    Returns:
        Text with sensitive data removed
    """
    if not text or not isinstance(text, str):
        return ""

    if patterns is None:
        patterns = [
            r"\b\d{4}[-\s]*\d{4}[-\s]*\d{4}[-\s]*\d{4}\b",  # Credit card numbers
            r"\b\d{3}[-\s.]?\d{2}[-\s.]?\d{4}\b",  # SSN
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email addresses
            r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",  # Phone numbers
            r"\b[A-Z0-9]{20,}\b",  # Long alphanumeric strings (potential API keys)
            r'password[\'"\s]*[:=][\'"\s]*\S+',  # Password fields
            r'token[\'"\s]*[:=][\'"\s]*\S+',  # Token fields
            r'key[\'"\s]*[:=][\'"\s]*\S+',  # Key fields
        ]

    cleaned_text = text
    for pattern in patterns:
        cleaned_text = re.sub(pattern, "[REDACTED]", cleaned_text, flags=re.IGNORECASE)

    return cleaned_text


def sanitize_ai_prompt(prompt: str, max_length: int = 50000) -> str:
    """
    Sanitize AI prompt input for safety.

    Args:
        prompt: AI prompt text to sanitize
        max_length: Maximum prompt length

    Returns:
        Sanitized prompt text
    """
    if not prompt or not isinstance(prompt, str):
        return ""

    # Remove potential prompt injection attempts
    dangerous_patterns = [
        r"ignore\s+(all\s+)?(previous|above|system)\s+(instructions?|prompts?)",
        r"forget\s+(all\s+)?(previous|above|system)\s+(instructions?|prompts?)",
        r"act\s+as\s+(admin|administrator|root|developer|system)",
        r"developer\s+mode",
        r"jailbreak",
        r"system:\s*",
        r"assistant:\s*",
        r"human:\s*",
        r"\[SYSTEM\]",
        r"\[ASSISTANT\]",
        r"\[HUMAN\]",
    ]

    sanitized = prompt
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE)

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated for safety]"

    # Remove excessive whitespace
    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    return sanitized


def _sanitize_javascript_patterns(text: str) -> str:
    """
    Remove JavaScript execution patterns from text.

    Args:
        text: Text to sanitize

    Returns:
        Text with JavaScript patterns removed/filtered
    """
    # JavaScript execution patterns and dangerous HTML/SQL patterns that should be filtered
    js_patterns = [
        # JavaScript execution patterns
        r"alert\s*\([^)]*\)",  # alert() calls
        r"eval\s*\([^)]*\)",  # eval() calls
        r"setTimeout\s*\([^)]*\)",  # setTimeout calls
        r"setInterval\s*\([^)]*\)",  # setInterval calls
        r"Function\s*\([^)]*\)",  # Function constructor
        r"constructor\s*\.\s*constructor",  # Constructor escape
        r"document\s*\.\s*write",  # document.write
        r"document\s*\.\s*cookie",  # document.cookie access
        r"window\s*\.\s*location",  # window.location
        r"location\s*\.\s*href",  # location.href
        r"innerHTML\s*=",  # innerHTML assignment
        r"outerHTML\s*=",  # outerHTML assignment
        r"on\w+\s*=\s*['\"]?[^'\"]*['\"]?",  # Event handlers (onclick, onerror, etc.)
        r"javascript\s*:",  # javascript: protocol
        r"vbscript\s*:",  # vbscript: protocol
        r"data\s*:\s*text/html",  # data:text/html protocol
        r"expression\s*\(",  # CSS expression()
        r"@import",  # CSS @import
        r"behaviour\s*:",  # CSS behavior
        r"-moz-binding",  # Mozilla binding
        # HTML tags that can execute JavaScript or are generally dangerous
        r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",  # Full script blocks
        r"<\s*script[^>]*>",  # Opening script tags
        r"<\s*/\s*script\s*>",  # Closing script tags
        r"<\s*iframe[^>]*>",  # iframe tags
        r"<\s*object[^>]*>",  # object tags
        r"<\s*embed[^>]*>",  # embed tags
        r"<\s*applet[^>]*>",  # applet tags
        r"<\s*form[^>]*>",  # form tags
        r"<\s*img[^>]*onerror[^>]*>",  # img with onerror
        r"<\s*svg[^>]*onload[^>]*>",  # svg with onload
        # SQL injection patterns that should be completely filtered
        r"'\s*OR\s*'",  # Simple quote-OR-quote pattern (covers 1' OR '1'='1)
        r"'\s*OR\s+\d+\s*=\s*\d+",  # OR with numbers
        r"\w*'\s*OR\s*\w+",  # General OR patterns after quotes
        r"UNION\s+SELECT",  # UNION SELECT
        r"DROP\s+TABLE",  # DROP TABLE
        r"DELETE\s+FROM",  # DELETE FROM
        r"INSERT\s+INTO",  # INSERT INTO
        r"UPDATE\s+SET",  # UPDATE SET
    ]

    sanitized = text
    for pattern in js_patterns:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE | re.MULTILINE)

    return sanitized


def sanitize_string(
    text: str, max_length: int = 1000, allow_html: bool = False, strip_sql: bool = True, strip_js: bool = False
) -> str:
    """
    Sanitize a string for general use.

    Args:
        text: String to sanitize
        max_length: Maximum allowed string length
        allow_html: Whether to allow HTML content
        strip_sql: Whether to strip SQL injection patterns
        strip_js: Whether to strip JavaScript execution patterns

    Returns:
        Sanitized string
    """
    if not text or not isinstance(text, str):
        return ""

    # Limit length first
    if len(text) > max_length:
        text = text[:max_length]

    # Remove control characters except tab, newline, carriage return
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)

    # Remove JavaScript execution patterns first (before HTML escaping)
    if strip_js:
        text = _sanitize_javascript_patterns(text)

    # Handle HTML content
    if allow_html:
        text = sanitize_html(text)
    else:
        # Escape HTML if not allowing it
        text = html.escape(text)

    # Handle SQL injection patterns if requested
    if strip_sql:
        text = sanitize_sql_input(text)

    # Clean up whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def sanitize_dict(
    data: Any, max_key_length: int = 100, max_value_length: int = 1000, allow_html: bool = False  # noqa: ANN401
) -> Dict[str, Any]:  # noqa: C901
    """
    Sanitize all string values in a dictionary.

    Args:
        data: Dictionary to sanitize
        max_key_length: Maximum length for keys
        max_value_length: Maximum length for string values
        allow_html: Whether to allow HTML in values

    Returns:
        Dictionary with sanitized string values
    """
    if not isinstance(data, dict):
        return {}

    sanitized: Dict[str, Any] = {}

    for key, value in data.items():
        # Sanitize key
        if isinstance(key, str):
            clean_key = sanitize_string(key, max_length=max_key_length, allow_html=False)
            if not clean_key:  # Skip empty keys
                continue
        else:
            clean_key = str(key)[:max_key_length]

        # Sanitize value based on type
        if isinstance(value, str):
            clean_value = sanitize_string(value, max_length=max_value_length, allow_html=allow_html)
            sanitized[clean_key] = clean_value
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized[clean_key] = sanitize_dict(value, max_key_length, max_value_length, allow_html)
        elif isinstance(value, list):
            # Sanitize list items
            clean_list: List[Any] = []
            for item in value:
                if isinstance(item, str):
                    clean_item = sanitize_string(item, max_length=max_value_length, allow_html=allow_html)
                    clean_list.append(clean_item)
                elif isinstance(item, dict):
                    clean_list.append(sanitize_dict(item, max_key_length, max_value_length, allow_html))
                else:
                    clean_list.append(item)
            sanitized[clean_key] = clean_list
        else:
            # Keep non-string values as-is
            sanitized[clean_key] = value

    return sanitized
