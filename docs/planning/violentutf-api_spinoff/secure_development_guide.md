# Secure Development Guide for ViolentUTF API

## Overview

This guide provides security-first development practices for the ViolentUTF API extraction, focusing on using the most secure and reliable packages.

## Secure Package Installation

### 1. Use Hash Verification

Always install packages with hash verification in production:

```bash
# Generate requirements with hashes
pip-compile --generate-hashes requirements.in -o requirements.txt

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

### 2. Use Virtual Environments

```bash
# Create isolated environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Upgrade pip itself
python -m pip install --upgrade pip
```

### 3. Verify Package Authenticity

```bash
# Check package signatures
pip install --verify-signatures package-name

# Use trusted index only
pip install --index-url https://pypi.org/simple/ --trusted-host pypi.org
```

## Authentication Implementation

### Use PyJWT Instead of Python-Jose

```python
# Secure JWT implementation with PyJWT
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Optional, Dict, Any

class SecureJWTManager:
    """Secure JWT implementation using PyJWT"""

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT with secure defaults"""
        to_encode = data.copy()

        # Use UTC timezone
        now = datetime.now(timezone.utc)
        expire = now + (expires_delta or timedelta(minutes=15))

        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": now,
            "nbf": now,  # Not before
            "jti": str(uuid.uuid4()),  # Unique ID
        })

        # Encode with algorithm
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm
        )

        return encoded_jwt

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT"""
        try:
            # Decode with verification
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "nbf", "jti"]
                }
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
```

### Secure Password Hashing with Argon2

```python
from passlib.context import CryptContext
from passlib.hash import argon2

# Configure Argon2 with secure parameters
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__rounds=4,  # Time cost
    argon2__memory_cost=65536,  # Memory cost (64MB)
    argon2__parallelism=2,  # Parallelism
    argon2__hash_len=32,  # Hash length
    argon2__salt_len=16  # Salt length
)

def hash_password(password: str) -> str:
    """Hash password using Argon2"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)
```

## Database Security

### Use Psycopg3 with Secure Defaults

```python
import psycopg
from psycopg.rows import dict_row
from contextlib import asynccontextmanager

class SecureDatabase:
    """Secure database connection management"""

    def __init__(self, database_url: str):
        # Parse and validate URL
        self.conn_params = psycopg.conninfo.conninfo_to_dict(database_url)

        # Force SSL in production
        if not self.conn_params.get("sslmode"):
            self.conn_params["sslmode"] = "require"

        # Set secure defaults
        self.conn_params.update({
            "connect_timeout": 10,
            "options": "-c statement_timeout=30000",  # 30s timeout
            "application_name": "violentutf_api",
        })

    @asynccontextmanager
    async def get_connection(self):
        """Get secure database connection"""
        async with await psycopg.AsyncConnection.connect(
            **self.conn_params,
            row_factory=dict_row
        ) as conn:
            # Set secure session parameters
            await conn.execute("SET search_path TO public")
            await conn.execute("SET lock_timeout = '10s'")

            yield conn
```

### Prevent SQL Injection

```python
from typing import List, Any
import re

class SecureQueryBuilder:
    """Build secure parameterized queries"""

    @staticmethod
    def validate_identifier(identifier: str) -> str:
        """Validate table/column names"""
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            raise ValueError(f"Invalid identifier: {identifier}")
        return identifier

    @staticmethod
    def build_insert(table: str, data: dict) -> tuple[str, list]:
        """Build secure INSERT query"""
        table = SecureQueryBuilder.validate_identifier(table)

        columns = []
        placeholders = []
        values = []

        for col, val in data.items():
            col = SecureQueryBuilder.validate_identifier(col)
            columns.append(col)
            placeholders.append("%s")
            values.append(val)

        query = f"""
            INSERT INTO {table} ({', '.join(columns)})
            VALUES ({', '.join(placeholders)})
            RETURNING *
        """

        return query, values
```

## Input Validation and Sanitization

### Use Pydantic V2 with Strict Mode

```python
from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Optional
import re
import bleach

class StrictBaseModel(BaseModel):
    """Base model with strict validation"""
    model_config = ConfigDict(
        str_strip_whitespace=True,  # Auto strip whitespace
        str_min_length=1,  # No empty strings
        validate_assignment=True,  # Validate on assignment
        validate_default=True,  # Validate defaults
        extra='forbid',  # No extra fields allowed
        use_enum_values=True,
        arbitrary_types_allowed=False,
    )

class SecureItemCreate(StrictBaseModel):
    """Item creation with comprehensive validation"""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Item name"
    )
    description: Optional[str] = Field(
        None,
        max_length=1000,
        description="Item description"
    )
    price: float = Field(
        ...,
        gt=0,
        le=1000000,
        description="Item price"
    )

    @validator('name')
    def validate_name(cls, v: str) -> str:
        """Validate and sanitize name"""
        # Check for SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(--|#|/\*|\*/)",
            r"(\x00|\x1a)",  # Null bytes
        ]

        for pattern in sql_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Invalid characters in name")

        # Sanitize HTML
        v = bleach.clean(v, tags=[], strip=True)

        return v

    @validator('description')
    def sanitize_description(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize HTML in description"""
        if v:
            # Allow only safe HTML tags
            v = bleach.clean(
                v,
                tags=['p', 'br', 'strong', 'em', 'u'],
                attributes={},
                strip=True
            )
        return v
```

## Secure Middleware Configuration

### Rate Limiting with SlowAPI

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Create limiter with secure key function
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/minute"],  # Global limit
    storage_uri="redis://localhost:6379",  # Use Redis for distributed apps
    strategy="fixed-window-elastic-expiry",
    headers_enabled=True,  # Return rate limit headers
)

# Add to FastAPI
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Use on endpoints
@app.post("/api/v1/items/")
@limiter.limit("10/minute")  # Stricter limit for POST
async def create_item(request: Request, item: ItemCreate):
    return {"status": "created"}
```

### Security Headers with Secure

```python
from secure import Secure

# Configure security headers
secure_headers = Secure(
    server="",  # Don't reveal server
    hsts=Secure.HSTS(max_age=31536000, include_subdomains=True, preload=True),
    xfo=Secure.XFrameOptions.DENY,
    xss=Secure.XXSSProtection.BLOCK,
    content=Secure.XContentTypeOptions.NOSNIFF,
    csp=Secure.ContentSecurityPolicy(
        default_src="'self'",
        script_src="'self' 'unsafe-inline'",  # Adjust as needed
        style_src="'self' 'unsafe-inline'",
        img_src="'self' data: https:",
        connect_src="'self'",
        font_src="'self'",
        object_src="'none'",
        media_src="'self'",
        frame_src="'none'",
        base_uri="'self'",
        form_action="'self'",
        frame_ancestors="'none'",
        upgrade_insecure_requests=True,
    ),
    referrer=Secure.Referrer.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
    permissions_policy={
        "geolocation": [],
        "microphone": [],
        "camera": [],
        "payment": [],
        "usb": [],
    },
    cache_control="no-store, max-age=0",
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response
```

## Secure Logging

### Use Structlog with PII Filtering

```python
import structlog
from structlog.processors import CallsiteParameter, TimeStamper
import re

def filter_sensitive_data(_, __, event_dict):
    """Remove sensitive data from logs"""
    sensitive_patterns = [
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),  # SSN
        (r'\b\d{16}\b', '[CARD]'),  # Credit card
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        (r'["\']?password["\']?\s*[:=]\s*["\']?[^"\']+["\']?', '"password": "[REDACTED]"'),
        (r'["\']?token["\']?\s*[:=]\s*["\']?[^"\']+["\']?', '"token": "[REDACTED]"'),
    ]

    # Convert to string for filtering
    str_dict = str(event_dict)

    for pattern, replacement in sensitive_patterns:
        str_dict = re.sub(pattern, replacement, str_dict, flags=re.IGNORECASE)

    # Parse back if changed
    if str_dict != str(event_dict):
        # Log that filtering occurred
        event_dict['_filtered'] = True

    return event_dict

# Configure secure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        CallsiteParameter(
            parameters=[CallsiteParameter.FILENAME, CallsiteParameter.LINENO]
        ),
        filter_sensitive_data,  # Custom filter
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()
```

## Development Security Checklist

### Before Each Commit

```bash
#!/bin/bash
# pre-commit-security.sh

echo "Running security checks..."

# 1. Check for secrets
echo "Checking for secrets..."
detect-secrets scan --baseline .secrets.baseline

# 2. Run security linters
echo "Running bandit..."
bandit -r app/ -ll -f json -o bandit_report.json

echo "Running semgrep..."
semgrep --config=auto app/ --json -o semgrep_report.json

# 3. Check dependencies
echo "Checking dependencies..."
pip-audit --desc --fix

# 4. Type checking
echo "Running mypy..."
mypy app/ --strict

# 5. Run security tests
echo "Running security tests..."
pytest tests/security/ -v

echo "Security checks complete!"
```

### Security-First CI/CD

```yaml
# .github/workflows/security.yml
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'

    - name: Upload Trivy results to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/python
          p/owasp-top-ten

    - name: Python Security Check
      run: |
        pip install bandit[toml] pip-audit
        bandit -r app/ -ll
        pip-audit --desc
```

## Security Resources

1. **OWASP Python Security**: https://owasp.org/www-project-python-security/
2. **Python Security Best Practices**: https://python.plainenglish.io/python-security-best-practices-d33b1d5f3f28
3. **NIST Secure Software Development**: https://csrc.nist.gov/Projects/ssdf
4. **CWE Top 25**: https://cwe.mitre.org/top25/

## Regular Security Maintenance

### Weekly Tasks
- Run `pip-audit` to check for new vulnerabilities
- Review Dependabot alerts
- Check for security advisories

### Monthly Tasks
- Update all dependencies to latest secure versions
- Run full security scan with multiple tools
- Review and update security policies

### Quarterly Tasks
- Conduct security code review
- Update threat model
- Perform penetration testing
- Review access controls and permissions

Remember: **Security is not a one-time task but a continuous process!**
