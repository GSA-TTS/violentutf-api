# Security Middleware Implementation

## Overview

This document describes the implementation of four critical security middleware components for the ViolentUTF API:

1. **SEC-001: CSRF Protection** - Cross-Site Request Forgery protection
2. **SEC-002: Input Sanitization** - Comprehensive input validation and sanitization
3. **SEC-003: Secure Session Management** - Redis-backed secure session handling
4. **SEC-004: Request Signing** - HMAC-based request authentication

## Architecture

### Middleware Stack Order
```
Request → RequestID → Logging → Metrics → Session → CSRF → InputSanitization → RequestSigning → CORS → GZip → SecurityHeaders → Application
```

### Components

#### 1. Session Management (`app/core/session.py`, `app/middleware/session.py`)
- **Purpose**: Secure session handling with Redis backend
- **Features**:
  - Cryptographically secure session ID generation (32 bytes)
  - Redis-backed storage with TTL
  - Session rotation to prevent fixation attacks
  - IP address and User-Agent validation
  - Secure cookie attributes (HttpOnly, Secure, SameSite=strict)

#### 2. CSRF Protection (`app/middleware/csrf.py`)
- **Purpose**: Prevent Cross-Site Request Forgery attacks
- **Features**:
  - Double-submit cookie pattern
  - HMAC-signed tokens using application secret
  - Safe method exemption (GET, HEAD, OPTIONS, TRACE)
  - Configurable exempt paths
  - Form and header token validation

#### 3. Input Sanitization (`app/middleware/input_sanitization.py`)
- **Purpose**: Sanitize all user inputs to prevent injection attacks
- **Features**:
  - Query parameter sanitization with URL decoding
  - Recursive JSON body sanitization
  - Form data validation
  - XSS and SQL injection pattern detection
  - Request size limits (10MB maximum)
  - Content-type specific handling

#### 4. Request Signing (`app/middleware/request_signing.py`)
- **Purpose**: HMAC-based request authentication for high-security endpoints
- **Features**:
  - HMAC-SHA256 signature validation
  - Canonical request string creation
  - Timestamp validation (5-minute window)
  - Nonce replay attack prevention
  - API key/secret management

## Security Features

### CSRF Protection
- **Token Generation**: HMAC-signed tokens using `SECRET_KEY`
- **Validation**: Double-submit pattern with constant-time comparison
- **Cookie Settings**: HttpOnly=false (readable by JS), Secure=true, SameSite=strict
- **Exempt Paths**: Health endpoints, documentation, metrics

### Session Security
- **Session IDs**: 32-byte cryptographically secure random tokens
- **Storage**: Redis with automatic TTL expiration
- **Rotation**: Automatic rotation on suspicious activity
- **Validation**: IP and User-Agent consistency checks

### Input Validation
- **XSS Prevention**: Script tag removal, event handler detection
- **SQL Injection**: Pattern-based detection and sanitization
- **Size Limits**: 10MB request body, 1000 char query params
- **Content Types**: JSON, form-encoded, multipart, plain text

### Request Authentication
- **Algorithm**: HMAC-SHA256
- **Components**: Method + Path + Query + Headers + Body + Timestamp + Nonce
- **Replay Protection**: Nonce tracking in Redis
- **Time Window**: 5-minute maximum request age

## Configuration

### Environment Variables
```bash
SECRET_KEY=<32+ character secret>  # Required for CSRF and sessions
REDIS_URL=redis://localhost:6379  # Required for sessions and nonces
CSRF_PROTECTION=true              # Enable CSRF protection
SECURE_COOKIES=true               # Enable secure cookie attributes
ACCESS_TOKEN_EXPIRE_MINUTES=30    # Session lifetime
```

### Settings
All middleware respects configuration from `app/core/config.py`:
- `CSRF_PROTECTION`: Enable/disable CSRF protection
- `SECURE_COOKIES`: Control cookie security attributes
- `ALLOWED_ORIGINS`: CORS configuration affects session cookies

## Usage Examples

### Creating Signed Requests
```python
from app.middleware.request_signing import RequestSigner

signer = RequestSigner("api_key", "api_secret")
headers = signer.sign_request(
    method="POST",
    path="/api/v1/admin/users",
    body=b'{"name": "john"}',
    headers={"content-type": "application/json"}
)

# Use headers in HTTP request
```

### CSRF Token Handling
```javascript
// Get CSRF token from cookie
const csrfToken = getCookie('csrf_token');

// Include in POST request
fetch('/api/v1/data', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
});
```

### Session Management
```python
from app.middleware.session import create_session_for_user

# In authentication endpoint
async def login(request: Request):
    # ... validate credentials ...
    create_session_for_user(request, user_id, {"role": "admin"})
    return {"status": "authenticated"}
```

## Testing

### Test Coverage
- **Session Middleware**: 12 test cases covering creation, validation, rotation
- **CSRF Middleware**: 15 test cases covering token generation, validation, exemptions
- **Input Sanitization**: 20 test cases covering XSS, SQL injection, size limits
- **Request Signing**: 15 test cases covering signature validation, replay protection

### Running Tests
```bash
# Run all middleware tests
pytest tests/unit/middleware/ -v

# Run with coverage
pytest tests/unit/middleware/ --cov=app.middleware --cov-report=html

# Test specific middleware
pytest tests/unit/middleware/test_csrf_middleware.py -v
```

## Security Considerations

### Production Deployment
1. **Always enable CSRF protection** in production
2. **Use HTTPS** to ensure secure cookies work properly
3. **Configure Redis** with authentication and encryption
4. **Monitor** session creation and CSRF validation failures
5. **Rotate secrets** regularly using secure key management

### Performance Impact
- **Session**: Redis lookup on each request with session
- **CSRF**: Token validation on state-changing requests
- **Input Sanitization**: Pattern matching on all input data
- **Request Signing**: HMAC computation on signed endpoints

### Monitoring
Monitor these metrics:
- CSRF validation failures (potential attacks)
- Session creation/rotation rate
- Input sanitization rejections
- Request signing failures
- Redis connection health

## Troubleshooting

### Common Issues
1. **CSRF Token Mismatch**: Check cookie domain and SameSite settings
2. **Session Not Found**: Verify Redis connectivity and TTL settings
3. **Input Rejected**: Check sanitization patterns and size limits
4. **Signature Invalid**: Verify canonical request string creation

### Debug Logging
Enable debug logging to troubleshoot:
```python
import logging
logging.getLogger("app.middleware").setLevel(logging.DEBUG)
```

## Future Enhancements

### Planned Improvements
1. **Rate Limiting**: Per-user request rate limits
2. **Anomaly Detection**: Behavioral analysis for sessions
3. **WAF Integration**: Web Application Firewall rules
4. **Advanced Signing**: Support for different signing algorithms
5. **Session Analytics**: User session behavior tracking

### Security Audits
Regular security reviews should focus on:
- Signature validation logic
- Session fixation prevention
- Input sanitization coverage
- CSRF token entropy
- Timing attack resistance

## Compliance

This implementation addresses:
- **OWASP Top 10**: Injection, broken authentication, XSS, CSRF
- **NIST Guidelines**: Session management, input validation
- **GSA Requirements**: Secure coding practices, audit logging

---

**Document Version**: 1.0
**Last Updated**: 2025-07-26
**Status**: Production Ready
