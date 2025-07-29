# Field Sanitization Guide

## Overview

The ViolentUTF API includes a comprehensive field sanitization framework that automatically cleans and validates input data to prevent security vulnerabilities such as:

- Cross-Site Scripting (XSS)
- SQL Injection
- Path Traversal
- Command Injection
- AI Prompt Injection

## Architecture

The sanitization framework consists of:

1. **Core Module** (`app/core/field_sanitization.py`): Main sanitization logic
2. **Utilities** (`app/utils/sanitization.py`): Low-level sanitization functions using bleach
3. **Decorators** (`app/core/decorators/sanitization.py`): Easy-to-use endpoint decorators
4. **Middleware** (`app/middleware/input_sanitization.py`): Automatic sanitization for all requests

## Sanitization Types

### Available Types

- **HTML**: Removes dangerous HTML tags and attributes
- **SQL**: Prevents SQL injection patterns
- **FILENAME**: Sanitizes file names to prevent path traversal
- **URL**: Validates and sanitizes URLs
- **EMAIL**: Ensures valid email format
- **PHONE**: Formats and validates phone numbers
- **LOG**: Prevents log injection
- **JSON_KEYS**: Filters allowed JSON keys
- **AI_PROMPT**: Prevents prompt injection attacks
- **GENERAL**: General-purpose text sanitization

### Sanitization Levels

- **STRICT**: Maximum sanitization, may remove legitimate content
- **MODERATE**: Balanced approach (default)
- **LENIENT**: Minimal sanitization
- **NONE**: No sanitization applied

## Usage Examples

### Using Predefined Rules

```python
from app.core.field_sanitization import (
    USERNAME_SANITIZATION,
    EMAIL_SANITIZATION,
    sanitize_request_data
)

# Sanitize a request
data = {
    "username": "user<script>alert('xss')</script>",
    "email": "TEST@EXAMPLE.COM"
}

rules = [USERNAME_SANITIZATION, EMAIL_SANITIZATION]
sanitized = sanitize_request_data(data, rules)
# Result: {"username": "user", "email": "test@example.com"}
```

### Custom Sanitization Rules

```python
from app.core.field_sanitization import (
    FieldSanitizationRule,
    SanitizationType,
    SanitizationLevel
)

# Create custom rule
bio_rule = FieldSanitizationRule(
    field_name="bio",
    sanitization_types=[
        SanitizationType.HTML,
        SanitizationType.SQL
    ],
    level=SanitizationLevel.MODERATE,
    max_length=1000,
    allow_html_tags={"p", "br", "strong", "em"}
)
```

### Using Decorators

#### Basic Sanitization

```python
from app.core.decorators import sanitize_request
from app.core.field_sanitization import USERNAME_SANITIZATION, EMAIL_SANITIZATION

@router.post("/users")
@sanitize_request([USERNAME_SANITIZATION, EMAIL_SANITIZATION])
async def create_user(user_data: UserCreate):
    # user_data is automatically sanitized
    return {"user_id": "123"}
```

#### Field-Specific Sanitization

```python
from app.core.decorators import sanitize_fields
from app.core.field_sanitization import SanitizationType

@router.post("/contact")
@sanitize_fields(
    name=[SanitizationType.GENERAL],
    email=[SanitizationType.EMAIL],
    message=[SanitizationType.HTML, SanitizationType.SQL]
)
async def contact_form(data: ContactForm):
    return {"success": True}
```

#### Auto-Sanitization

```python
from app.core.decorators import auto_sanitize

@router.post("/data")
@auto_sanitize(level="moderate", exclude_fields=["password", "api_key"])
async def process_data(data: DataModel):
    # All string fields except password and api_key are sanitized
    return {"processed": True}
```

## Common Patterns

### User Registration

```python
REGISTRATION_RULES = [
    USERNAME_SANITIZATION,
    EMAIL_SANITIZATION,
    FieldSanitizationRule(
        field_name="full_name",
        sanitization_types=[SanitizationType.GENERAL],
        max_length=100,
        strip_html=True
    ),
    # Don't sanitize password!
    FieldSanitizationRule(
        field_name="password",
        level=SanitizationLevel.NONE
    )
]
```

### Blog Comments

```python
COMMENT_RULES = [
    FieldSanitizationRule(
        field_name="author",
        sanitization_types=[SanitizationType.GENERAL],
        max_length=50,
        strip_html=True
    ),
    COMMENT_SANITIZATION  # Allows limited HTML
]
```

### File Uploads

```python
UPLOAD_RULES = [
    FILENAME_SANITIZATION,
    FieldSanitizationRule(
        field_name="description",
        sanitization_types=[SanitizationType.GENERAL],
        max_length=500
    )
]
```

## Best Practices

### 1. Never Sanitize Passwords

Passwords should never be sanitized as it can weaken them:

```python
FieldSanitizationRule(
    field_name="password",
    level=SanitizationLevel.NONE
)
```

### 2. Use Appropriate Levels

- **STRICT**: For usernames, file names, identifiers
- **MODERATE**: For user content, comments, descriptions
- **LENIENT**: For rich text content where formatting is important

### 3. Combine with Validation

Sanitization should complement, not replace, validation:

```python
# First validate with Pydantic
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr

# Then sanitize
@sanitize_request([USERNAME_SANITIZATION, EMAIL_SANITIZATION])
async def create_user(user: UserCreate):
    pass
```

### 4. Log Sanitization Events

The framework automatically logs when fields are sanitized. Monitor these logs to detect attack attempts.

### 5. Test Thoroughly

Always test sanitization rules with malicious input:

```python
def test_xss_prevention():
    rule = COMMENT_SANITIZATION
    result = sanitize_field("<script>alert('xss')</script>", rule)
    assert "<script>" not in result.sanitized_value
```

## Security Considerations

1. **Defense in Depth**: Sanitization is one layer of security. Also use:
   - Parameterized queries for database access
   - Content Security Policy headers
   - Input validation
   - Output encoding

2. **Context-Aware Sanitization**: Different contexts require different sanitization:
   - HTML content vs plain text
   - SQL queries vs NoSQL queries
   - File system paths vs URLs

3. **Performance**: Sanitization adds overhead. For high-performance endpoints, consider:
   - Caching sanitized values
   - Async sanitization for large payloads
   - Selective field sanitization

4. **Monitoring**: Track sanitization metrics:
   - Fields most often sanitized
   - Common attack patterns
   - Performance impact

## Troubleshooting

### Issue: Over-sanitization

**Symptom**: Legitimate content is being removed

**Solution**: Adjust sanitization level or allowed tags:

```python
rule = FieldSanitizationRule(
    field_name="content",
    sanitization_types=[SanitizationType.HTML],
    level=SanitizationLevel.LENIENT,  # Less aggressive
    allow_html_tags={"p", "br", "a", "img"}  # Allow more tags
)
```

### Issue: Sanitization Not Applied

**Symptom**: Dangerous content passes through

**Solution**: Check decorator order and middleware configuration:

```python
# Correct order: rate limit -> sanitize -> process
@router.post("/endpoint")
@rate_limit("api")
@sanitize_request(rules)
async def endpoint(data: Model):
    pass
```

### Issue: Performance Impact

**Symptom**: Slow request processing

**Solution**: Optimize sanitization rules:

```python
# Only sanitize necessary fields
@sanitize_fields(
    # Don't sanitize every field
    name=[SanitizationType.GENERAL],
    comment=[SanitizationType.HTML]
)
```

## Integration with Other Features

### With Rate Limiting

```python
@router.post("/api/endpoint")
@rate_limit("api")
@sanitize_request(rules)
async def endpoint(data: Model):
    pass
```

### With Input Validation

```python
from app.core.input_validation import validate_request

@router.post("/api/endpoint")
@validate_request(validation_rules)
@sanitize_request(sanitization_rules)
async def endpoint(data: Model):
    pass
```

### With Request Signing

```python
@router.post("/api/secure")
@require_request_signature()
@sanitize_request(rules)
async def secure_endpoint(data: Model):
    pass
```

## Conclusion

The field sanitization framework provides a robust defense against injection attacks while maintaining flexibility for different use cases. By combining predefined rules, custom configurations, and convenient decorators, you can ensure all user input is properly sanitized before processing.
