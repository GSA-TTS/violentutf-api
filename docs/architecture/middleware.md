# Middleware Documentation

## Table of Contents
- [Overview](#overview)
- [Middleware Stack](#middleware-stack)
- [Request Flow](#request-flow)
- [Built-in Middleware](#built-in-middleware)
  - [RequestIDMiddleware](#requestidmiddleware)
  - [LoggingMiddleware](#loggingmiddleware)
  - [MetricsMiddleware](#metricsmiddleware)
  - [SecurityHeadersMiddleware](#securityheadersmiddleware)
  - [CORS Middleware](#cors-middleware)
  - [GZip Middleware](#gzip-middleware)
  - [Rate Limiting](#rate-limiting)
  - [TrustedHost Middleware](#trustedhost-middleware)
- [Custom Middleware Guide](#custom-middleware-guide)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The ViolentUTF API uses a layered middleware architecture to handle cross-cutting concerns like security, logging, metrics, and request processing. Middleware components process requests before they reach route handlers and can modify responses before they're sent to clients.

## Middleware Stack

The middleware stack is ordered specifically for optimal security and performance. Here's the complete stack from outermost to innermost:

```
Client Request
    ↓
[Rate Limiter] - Request rate limiting per IP
    ↓
[RequestIDMiddleware] - Generate/extract request ID
    ↓
[LoggingMiddleware] - Log requests and responses
    ↓
[MetricsMiddleware] - Collect performance metrics
    ↓
[CORS Middleware] - Handle cross-origin requests
    ↓
[GZip Middleware] - Compress responses
    ↓
[SecurityHeadersMiddleware] - Add security headers
    ↓
[TrustedHostMiddleware] - Validate host headers (production only)
    ↓
Route Handler (your endpoint)
    ↑
Response flows back through middleware in reverse order
```

## Request Flow

### 1. Incoming Request Flow

```python
# 1. Rate limiting check
# 2. Request ID assignment
# 3. Request logging
# 4. Metrics start timer
# 5. CORS preflight handling
# 6. Security validations
# 7. Route handler execution
```

### 2. Outgoing Response Flow

```python
# 1. Route handler response
# 2. Security headers added
# 3. Response compression
# 4. CORS headers added
# 5. Metrics recording
# 6. Response logging
# 7. Request ID in response
# 8. Send to client
```

## Built-in Middleware

### RequestIDMiddleware

**Location:** `app/middleware/request_id.py`

**Purpose:** Generates unique request IDs for tracking requests across services and logs.

**Configuration:** None required

**Headers:**
- Reads: `X-Request-ID` (optional client-provided ID)
- Sets: `X-Request-ID` (in response)

**Features:**
- Generates UUID v4 if no ID provided
- Stores ID in `request.state.request_id`
- Adds ID to all log entries via context
- Returns ID in response headers

**Example:**
```bash
# Client provides ID
curl -H "X-Request-ID: custom-id-123" http://localhost:8000/api/v1/health

# Server generates ID
curl -v http://localhost:8000/api/v1/health
# Response includes: X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

**Performance Impact:** <0.1ms

### LoggingMiddleware

**Location:** `app/middleware/logging.py`

**Purpose:** Structured logging of all HTTP requests and responses with timing information.

**Configuration:**
```env
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json  # json or console
ENABLE_ACCESS_LOGS=true
```

**Logged Information:**
- Request: method, path, client IP, user agent
- Response: status code, response time
- Context: request ID, user ID (if authenticated)
- Errors: Full exception traces

**Example Log Entry:**
```json
{
  "timestamp": "2024-01-20T10:30:45.123Z",
  "level": "info",
  "event": "http_request_completed",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "GET",
  "path": "/api/v1/users",
  "status_code": 200,
  "response_time_ms": 45.2,
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

**Performance Impact:** 1-2ms

**Privacy Considerations:**
- Passwords are never logged
- Sensitive headers are redacted
- Request bodies are not logged by default

### MetricsMiddleware

**Location:** `app/middleware/metrics.py`

**Purpose:** Collects Prometheus metrics for monitoring and alerting.

**Configuration:**
```env
ENABLE_METRICS=true
METRICS_PORT=9090  # Metrics endpoint port
```

**Metrics Collected:**
- `http_requests_total`: Counter of requests by method, endpoint, status
- `http_request_duration_seconds`: Histogram of response times
- `http_requests_in_progress`: Gauge of active requests
- `http_request_size_bytes`: Histogram of request sizes
- `http_response_size_bytes`: Histogram of response sizes

**Example Metrics:**
```prometheus
# Total requests
http_requests_total{method="GET",endpoint="/api/v1/users",status="200"} 1543

# Response time histogram
http_request_duration_seconds_bucket{le="0.1",method="GET",endpoint="/api/v1/users"} 1200
http_request_duration_seconds_bucket{le="0.5",method="GET",endpoint="/api/v1/users"} 1500
```

**Access Metrics:**
```bash
curl http://localhost:9090/metrics
```

**Performance Impact:** <1ms

### SecurityHeadersMiddleware

**Location:** `app/middleware/security.py`

**Purpose:** Adds comprehensive security headers to all responses.

**Configuration:**
```env
HSTS_MAX_AGE=31536000  # HTTP Strict Transport Security
CSP_POLICY="default-src 'self'"  # Content Security Policy
SECURE_COOKIES=true
```

**Headers Added:**

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS protection (legacy) |
| `Content-Security-Policy` | Configurable | Control resource loading |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Disable features |

**Removed Headers:**
- `Server` - Hide server technology
- `X-Powered-By` - Hide framework info

**Production vs Development:**
- Production adds `preload` to HSTS
- Production uses stricter CSP
- Development allows unsafe-inline scripts

**Performance Impact:** <0.5ms

### CORS Middleware

**Location:** FastAPI built-in (`CORSMiddleware`)

**Purpose:** Handle Cross-Origin Resource Sharing for browser-based clients.

**Configuration:**
```env
ALLOWED_ORIGINS=["https://app.example.com"]
ALLOWED_METHODS=["GET", "POST", "PUT", "DELETE"]
ALLOWED_HEADERS=["*"]
ALLOW_CREDENTIALS=true
```

**Features:**
- Preflight request handling (OPTIONS)
- Origin validation
- Credentials support
- Configurable methods and headers

**Example CORS Headers:**
```
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: *
```

**Performance Impact:** <0.5ms (1-2ms for preflight)

### GZip Middleware

**Location:** FastAPI built-in (`GZipMiddleware`)

**Purpose:** Compress responses to reduce bandwidth usage.

**Configuration:**
- Minimum size: 1000 bytes (hardcoded)
- Compression level: 6 (balanced)

**Features:**
- Automatic for text/JSON responses
- Skips already compressed content
- Honors `Accept-Encoding` header

**Example:**
```bash
# Request with compression
curl -H "Accept-Encoding: gzip" http://localhost:8000/api/v1/large-response

# Response headers include:
# Content-Encoding: gzip
# Vary: Accept-Encoding
```

**Performance Impact:**
- CPU: 2-5ms for compression
- Bandwidth: 60-80% reduction for JSON

### Rate Limiting

**Location:** Uses `slowapi` (wrapper around `limits`)

**Purpose:** Prevent abuse and ensure fair usage.

**Configuration:**
```env
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60  # Default limit
```

**Features:**
- Per-IP rate limiting
- Configurable limits per endpoint
- Clear error messages
- Headers indicate limit status

**Rate Limit Headers:**
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1614556800
```

**Custom Limits Example:**
```python
from slowapi import Limiter

@app.get("/api/v1/expensive-operation")
@limiter.limit("5 per minute")  # Override default
async def expensive_operation():
    pass
```

**Performance Impact:** <1ms

### TrustedHost Middleware

**Location:** FastAPI built-in (enabled in production only)

**Purpose:** Prevent host header injection attacks.

**Configuration:**
Automatically configured based on `ALLOWED_ORIGINS` in production.

**Features:**
- Validates `Host` header
- Returns 400 for invalid hosts
- Extracted from ALLOWED_ORIGINS

**Example:**
```python
# If ALLOWED_ORIGINS = ["https://app.example.com"]
# Then allowed hosts = ["app.example.com"]
```

**Performance Impact:** <0.1ms

## Custom Middleware Guide

### Creating Custom Middleware

**Basic Structure:**

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, Awaitable

class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Pre-processing
        print(f"Before request: {request.url}")

        # Call the next middleware or route handler
        response = await call_next(request)

        # Post-processing
        response.headers["X-Custom-Header"] = "value"

        return response
```

### Adding Middleware to Application

```python
# In app/main.py

from app.middleware.custom import CustomMiddleware

def create_application() -> FastAPI:
    app = FastAPI()

    # Add middleware (order matters!)
    app.add_middleware(CustomMiddleware)

    return app
```

### Middleware Best Practices

1. **Keep it lightweight** - Middleware runs for every request
2. **Handle exceptions** - Don't let middleware crashes kill requests
3. **Use request.state** - For passing data between middleware
4. **Avoid blocking I/O** - Use async operations
5. **Log sparingly** - Avoid verbose logging in middleware

### Advanced Example: API Key Authentication

```python
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class APIKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_keys: set):
        super().__init__(app)
        self.api_keys = api_keys

    async def dispatch(self, request: Request, call_next):
        # Skip auth for health checks
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)

        # Check API key
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key not in self.api_keys:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or missing API key"}
            )

        # Add user info to request state
        request.state.api_key = api_key

        return await call_next(request)
```

## Performance Considerations

### Middleware Performance Impact

| Middleware | Typical Impact | Notes |
|------------|---------------|-------|
| RequestID | <0.1ms | UUID generation |
| Logging | 1-2ms | I/O for log writing |
| Metrics | <1ms | In-memory operations |
| Security Headers | <0.5ms | Header manipulation |
| CORS | <0.5ms | Header checks |
| GZip | 2-5ms | CPU for compression |
| Rate Limiting | <1ms | Redis lookup |

### Total Overhead

Typical total middleware overhead: 5-10ms

### Optimization Tips

1. **Order matters** - Put selective middleware first
2. **Skip when possible** - Bypass middleware for health checks
3. **Cache computed values** - Don't recalculate per request
4. **Use streaming** - For large responses
5. **Profile regularly** - Monitor middleware performance

## Troubleshooting

### Debug Middleware Execution

Enable debug logging:
```env
LOG_LEVEL=DEBUG
```

### Common Issues

**1. Middleware Not Executing**
- Check middleware registration order
- Verify middleware is added to app
- Ensure no early returns

**2. Headers Not Set**
- Some headers may be overridden by other middleware
- Check middleware order
- Response headers must be set before streaming

**3. Performance Degradation**
- Profile individual middleware
- Check for blocking I/O
- Monitor external service calls

**4. CORS Issues**
- Verify origin is in allowed list
- Check preflight responses
- Ensure credentials settings match

### Debugging Tools

**Request Flow Logging:**
```python
import time
from fastapi import Request

class DebugMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        print(f"[{self.__class__.__name__}] Start: {request.url}")

        response = await call_next(request)

        duration = time.time() - start
        print(f"[{self.__class__.__name__}] End: {duration:.3f}s")

        return response
```

**Middleware Stack Visualization:**
```python
def print_middleware_stack(app: FastAPI):
    print("Middleware Stack (execution order):")
    for i, middleware in enumerate(app.middleware):
        print(f"{i+1}. {middleware.__class__.__name__}")
```

## Related Documentation

- [Security Configuration](../security/configuration-guide.md) - Security settings
- [Performance Tuning](../deployment/performance-tuning.md) - Performance optimization
- [API Documentation](../api/README.md) - API endpoints
- [Logging Guide](../development/logging.md) - Logging configuration
