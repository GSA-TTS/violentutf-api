# Security Configuration Guide

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [JWT Configuration](#jwt-configuration)
- [CORS Configuration](#cors-configuration)
- [Security Headers](#security-headers)
- [Rate Limiting](#rate-limiting)
- [Environment-Specific Security](#environment-specific-security)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The ViolentUTF API implements multiple layers of security through configuration settings. This guide covers all security-related configuration options available in the application.

All security settings are configured through environment variables or the `.env` file. The application uses Pydantic for validation, ensuring that invalid configurations are caught at startup.

## Quick Start

Create a `.env` file with these essential security settings:

```env
# Minimum secure configuration
SECRET_KEY=your-very-long-random-secret-key-at-least-32-characters-long
ENVIRONMENT=production
DEBUG=false
ALLOWED_ORIGINS=["https://your-app.example.com"]
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
```

## JWT Configuration

### SECRET_KEY

The most critical security setting. Used for signing JWT tokens and other cryptographic operations.

**Requirements:**
- Minimum length: 32 characters
- Must be random and unpredictable
- Different for each environment
- Never commit to version control

**Generation example:**
```python
import secrets
# Generate a secure secret key
secret_key = secrets.token_urlsafe(32)
print(f"SECRET_KEY={secret_key}")
```

**Configuration:**
```env
SECRET_KEY=your-very-long-random-secret-key-at-least-32-characters-long
```

### Token Expiration

Control how long tokens remain valid:

```env
# Access token expires in 30 minutes (default)
ACCESS_TOKEN_EXPIRE_MINUTES=30  # Range: 5-1440 (5 minutes to 24 hours)

# Refresh token expires in 7 days (default)
REFRESH_TOKEN_EXPIRE_DAYS=7     # Range: 1-30 days
```

**Best practices:**
- Shorter access tokens (15-60 minutes) for higher security
- Longer refresh tokens (7-30 days) for better user experience
- Consider your application's security requirements

### JWT Algorithm

```env
# Default is HS256 (HMAC with SHA-256)
ALGORITHM=HS256
```

**Supported algorithms:**
- HS256: Symmetric signing (uses SECRET_KEY)
- RS256: Asymmetric signing (requires public/private key pair)

For most applications, HS256 is sufficient and simpler to manage.

### Password Hashing

Uses Argon2, the winner of the Password Hashing Competition:

```env
# Number of hashing rounds (default: 12)
BCRYPT_ROUNDS=12  # Range: 10-15
```

**Tuning guide:**
- 10-11: Faster, suitable for development
- 12-13: Balanced security/performance (recommended)
- 14-15: Maximum security, slower authentication

## CORS Configuration

Cross-Origin Resource Sharing controls which domains can access your API:

### Allowed Origins

```env
# Development
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]

# Production - be specific!
ALLOWED_ORIGINS=["https://app.example.com", "https://www.example.com"]
```

**Important notes:**
- Empty list `[]` defaults to `["http://localhost:3000", "http://localhost:8000"]`
- Never use `["*"]` in production
- Include protocol (http/https) in origins
- Validated at startup for proper URL format

### CORS Methods and Headers

```env
# Allowed HTTP methods (default: most common methods)
ALLOWED_METHODS=["GET", "POST", "PUT", "DELETE"]

# Allowed headers (default: all headers)
ALLOWED_HEADERS=["*"]

# Allow credentials (cookies, authorization headers)
ALLOW_CREDENTIALS=true
```

**Security considerations:**
- Limit methods to what your API actually uses
- Consider restricting headers in production
- Set `ALLOW_CREDENTIALS=false` if not using cookies

## Security Headers

### HSTS (HTTP Strict Transport Security)

Forces browsers to use HTTPS:

```env
# Max age in seconds (default: 1 year)
HSTS_MAX_AGE=31536000    # 1 year
# HSTS_MAX_AGE=63072000  # 2 years (recommended for production)
```

**Production note:** The application automatically adds `includeSubDomains` and `preload` directives in production mode.

### Content Security Policy (CSP)

Controls which resources can be loaded:

```env
# Default CSP policy
CSP_POLICY="default-src 'self'"
```

**Applied CSP directives:**
- `default-src 'self'`: Only allow resources from same origin
- `script-src 'self' 'strict-dynamic'`: (production) Strict script loading
- `script-src 'self' 'unsafe-inline'`: (development) Allow inline scripts
- `frame-ancestors 'none'`: Prevent clickjacking
- `base-uri 'self'`: Prevent base tag injection

### Cookie Security

```env
# Secure cookie settings (default: true)
SECURE_COOKIES=true

# CSRF protection (default: true)
CSRF_PROTECTION=true
```

**Applied settings:**
- `Secure`: Cookies only sent over HTTPS
- `HttpOnly`: Cookies not accessible via JavaScript
- `SameSite=Strict`: CSRF protection

### Additional Security Headers

The following headers are automatically applied:
- `X-Content-Type-Options: nosniff` - Prevent MIME sniffing
- `X-Frame-Options: DENY` - Prevent clickjacking
- `X-XSS-Protection: 1; mode=block` - XSS protection (legacy browsers)
- `Referrer-Policy: strict-origin-when-cross-origin` - Control referrer info
- Permissions Policy - Disable unnecessary browser features

## Rate Limiting

Protect against abuse and DDoS:

```env
# Enable rate limiting (default: true)
RATE_LIMIT_ENABLED=true

# Requests per minute per IP (default: 60)
RATE_LIMIT_PER_MINUTE=60  # Range: 10-1000
```

**Recommended limits:**
- Public API: 30-60 requests/minute
- Authenticated API: 100-200 requests/minute
- Admin endpoints: 10-30 requests/minute

**Rate limit response:**
```json
{
  "detail": "Rate limit exceeded: 60 per 1 minute"
}
```

## Environment-Specific Security

### Development Environment

```env
ENVIRONMENT=development
DEBUG=true  # Allowed in development
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]
SERVER_HOST=127.0.0.1  # Localhost only
SECURE_COOKIES=false  # For HTTP development
RATE_LIMIT_PER_MINUTE=1000  # Higher limit for testing
```

### Staging Environment

```env
ENVIRONMENT=staging
DEBUG=false
ALLOWED_ORIGINS=["https://staging.example.com"]
SERVER_HOST=0.0.0.0  # Required for containers
SECURE_COOKIES=true
RATE_LIMIT_PER_MINUTE=100
```

### Production Environment

```env
ENVIRONMENT=production
DEBUG=false  # MUST be false (validated)
ALLOWED_ORIGINS=["https://app.example.com"]
SERVER_HOST=0.0.0.0  # Behind load balancer
SECURE_COOKIES=true
CSRF_PROTECTION=true
HSTS_MAX_AGE=63072000  # 2 years
RATE_LIMIT_PER_MINUTE=60

# Production validations:
# - SECRET_KEY strength is validated
# - DEBUG=true will cause startup failure
# - Weak SECRET_KEY patterns are rejected
```

## Security Best Practices

### 1. Secret Management

**DO:**
- Use a secret management service (AWS Secrets Manager, HashiCorp Vault)
- Generate different secrets for each environment
- Rotate secrets regularly
- Use strong, random values

**DON'T:**
- Commit secrets to git (use `.env.example` instead)
- Use predictable secrets like "test", "development"
- Share secrets between environments
- Log secret values

### 2. HTTPS Configuration

Always use HTTPS in production:
- Configure your reverse proxy (nginx, Apache) for SSL
- Use strong cipher suites
- Enable HTTP/2
- Redirect HTTP to HTTPS

### 3. Host Security

In production with multiple domains:
```python
# The app automatically configures TrustedHostMiddleware
# based on your ALLOWED_ORIGINS in production
```

### 4. Monitoring

Monitor these security events:
- Failed authentication attempts
- Rate limit violations
- Invalid CORS requests
- Malformed JWT tokens

## Troubleshooting

### Common Issues

**1. "SECRET_KEY must be at least 32 characters"**
- Generate a longer secret key
- Don't use simple strings

**2. "DEBUG must be False in production"**
- Ensure `ENVIRONMENT=production` and `DEBUG=false`

**3. "Invalid database URL"**
- Check URL format: `postgresql://user:pass@host/db`
- Ensure special characters are URL-encoded

**4. CORS errors in browser**
- Verify origin is in ALLOWED_ORIGINS
- Include protocol (https://)
- Check browser console for specific error

**5. Rate limit hit during testing**
- Increase RATE_LIMIT_PER_MINUTE
- Disable with RATE_LIMIT_ENABLED=false (dev only)

### Security Validation

The application performs these validations at startup:
- SECRET_KEY length and complexity
- Production environment checks
- URL format validation
- Configuration consistency

### Debug Security Issues

Enable debug logging:
```env
LOG_LEVEL=DEBUG
```

Check security middleware behavior:
```python
# Logs will show:
# - Security header application
# - Rate limit decisions
# - CORS validations
# - JWT token validation
```

## Related Documentation

- [Security Notes](./SECURITY_NOTES.md) - Current security status
- [API Authentication](../api/authentication.md) - Using JWT tokens
- [Deployment Guide](../deployment/README.md) - Production deployment
- [Middleware Documentation](../architecture/middleware.md) - Security middleware details
