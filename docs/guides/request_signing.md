# Request Signing Guide

Request signing protects sensitive API operations from tampering and replay attacks using HMAC-based signatures.

## Overview

The request signing framework provides:

- **HMAC-based signatures** using SHA256 or SHA512
- **Replay attack prevention** with nonces and timestamps
- **Flexible configuration** for different security levels
- **Multiple verification methods** (decorators, middleware)
- **Admin and webhook signature support**

## Basic Usage

### 1. Requiring Signatures on Endpoints

```python
from app.core.decorators.request_signing import require_request_signature

@router.delete("/users/{user_id}")
@require_request_signature()
async def delete_user(user_id: int, request: Request):
    # This endpoint now requires a valid signature
    return {"deleted": user_id}
```

### 2. Signing a Request (Client Side)

```python
from app.core.request_signing import sign_request, format_authorization_header

# Sign the request
signature = sign_request(
    secret_key="your_secret_key",
    method="DELETE",
    path="/api/v1/users/123",
    headers={
        "host": "api.example.com",
        "content-type": "application/json"
    },
    body=b'{"reason": "User requested"}',
    key_id="your_key_id"
)

# Add to Authorization header
headers["Authorization"] = format_authorization_header(signature)
```

### 3. Authorization Header Format

```
Authorization: Signature keyId="test_key_1",algorithm="HMAC-SHA256",headers="host content-type",timestamp="1234567890",nonce="abc123",signature="def456..."
```

## Advanced Features

### Admin-Only Endpoints

Require signatures from admin keys (key IDs starting with `admin_`):

```python
from app.core.decorators.request_signing import require_admin_signature

@router.post("/admin/dangerous-operation")
@require_admin_signature()
async def admin_operation(request: Request, data: DangerousOperation):
    # Only admin keys can access this
    return {"status": "executed"}
```

### Webhook Signature Verification

Verify signatures from external services:

```python
from app.core.decorators.request_signing import verify_webhook_signature

@router.post("/webhooks/payment")
@verify_webhook_signature(
    secret_key=settings.PAYMENT_WEBHOOK_SECRET,
    signature_header="X-Payment-Signature",
    timestamp_header="X-Payment-Timestamp",
    max_age_seconds=300
)
async def payment_webhook(request: Request, data: PaymentWebhook):
    # Webhook signature is verified
    return {"received": True}
```

### Restricting to Specific Keys

```python
@require_request_signature(
    allowed_key_ids=["key1", "key2"],
    custom_error_message="This operation requires special authorization"
)
async def restricted_operation(request: Request):
    # Only key1 or key2 can access
    return {"status": "ok"}
```

## Configuration Options

### SignatureConfig

```python
from app.core.request_signing import SignatureConfig, SignatureAlgorithm

config = SignatureConfig(
    algorithm=SignatureAlgorithm.HMAC_SHA512,  # Use SHA512
    max_age_seconds=600,                       # 10 minute validity
    require_nonce=True,                        # Prevent replay attacks
    require_timestamp=True,                    # Enforce time window
    include_headers=["host", "date"],         # Headers to sign
    include_query_params=True,                 # Include query string
    include_body=True,                         # Include body hash
)
```

### Key Management

```python
from app.core.request_signing import signature_key_store

# Add a key
signature_key_store.add_key(
    key_id="api_key_123",
    secret_key="very_secret_key_value",
    metadata={"user_id": "123", "created_at": "2024-01-01"}
)

# List keys
keys = signature_key_store.list_keys()

# Remove a key
signature_key_store.remove_key("api_key_123")
```

## Security Best Practices

### 1. Key Management

- Use strong, randomly generated secret keys (at least 32 bytes)
- Rotate keys regularly
- Store keys securely (environment variables, secrets manager)
- Use different keys for different purposes (API vs webhooks)

### 2. Signature Configuration

- Always require timestamps and nonces for replay protection
- Use appropriate max age (5-10 minutes for most operations)
- Include critical headers in signature (host, content-type)
- Sign request body for POST/PUT/PATCH operations

### 3. Implementation Guidelines

```python
# Good: Specific error handling
@require_request_signature(
    custom_error_message="Payment operations require merchant signature"
)

# Good: Restrict to known keys
@require_request_signature(
    allowed_key_ids=["merchant_key_1", "merchant_key_2"]
)

# Good: Admin operations with admin keys
@require_admin_signature(admin_key_prefix="admin_")
```

## Example: Complete Flow

### Server Setup

```python
# app/api/endpoints/sensitive.py
from fastapi import APIRouter, Request
from app.core.decorators.request_signing import require_request_signature

router = APIRouter()

@router.post("/transfer-funds")
@require_request_signature()
async def transfer_funds(
    request: Request,
    transfer: FundTransfer
):
    # Access signature info
    key_id = request.state.signature_key_id

    # Process transfer
    result = await process_transfer(transfer, authorized_by=key_id)

    return {
        "transfer_id": result.id,
        "status": "completed",
        "authorized_by": key_id
    }
```

### Client Implementation

```python
import httpx
from app.core.request_signing import sign_request, format_authorization_header

# Prepare request
method = "POST"
url = "https://api.example.com/api/v1/transfer-funds"
body = {"from_account": "123", "to_account": "456", "amount": 100.00}
body_bytes = json.dumps(body).encode()

# Sign request
signature = sign_request(
    secret_key=os.environ["API_SECRET"],
    method=method,
    path="/api/v1/transfer-funds",
    headers={
        "host": "api.example.com",
        "content-type": "application/json",
        "content-length": str(len(body_bytes))
    },
    body=body_bytes,
    key_id=os.environ["API_KEY_ID"]
)

# Make request
response = httpx.post(
    url,
    json=body,
    headers={
        "Authorization": format_authorization_header(signature),
        "Content-Type": "application/json"
    }
)
```

### cURL Example

```bash
# The signature would be calculated by your application
curl -X POST https://api.example.com/api/v1/transfer-funds \
  -H 'Authorization: Signature keyId="api_key_123",algorithm="HMAC-SHA256",headers="host content-type",timestamp="1234567890",nonce="abc123",signature="calculated_signature_here"' \
  -H 'Content-Type: application/json' \
  -d '{"from_account": "123", "to_account": "456", "amount": 100.00}'
```

## Troubleshooting

### Common Issues

1. **"Request signature required"**
   - Ensure Authorization header is present
   - Check header format starts with "Signature "

2. **"Invalid signature"**
   - Verify secret key matches
   - Check all signed components match (method, path, headers, body)
   - Ensure headers are lowercase in signing string

3. **"Signature expired"**
   - Check timestamp is current (within max_age_seconds)
   - Synchronize client/server clocks

4. **"Nonce already used"**
   - Generate unique nonce for each request
   - Don't retry requests with same signature

### Debug Mode

```python
import logging
logging.getLogger("app.core.request_signing").setLevel(logging.DEBUG)
```

This will log detailed information about signature verification.

## Integration with Existing Systems

### Using with API Keys

```python
# Store API key -> secret mapping
api_keys = {
    "api_key_123": {
        "secret": "secret_123",
        "user_id": "user_123",
        "permissions": ["read", "write"]
    }
}

# Verify both API key and signature
@require_request_signature()
async def protected_endpoint(request: Request):
    key_id = request.state.signature_key_id
    if key_id not in api_keys:
        raise HTTPException(status_code=401)

    # Check permissions
    if "write" not in api_keys[key_id]["permissions"]:
        raise HTTPException(status_code=403)

    return {"status": "ok"}
```

### Middleware Integration

For automatic signature verification on multiple endpoints:

```python
from app.middleware.request_signing import RequestSigningMiddleware

app.add_middleware(
    RequestSigningMiddleware,
    signed_paths=["/api/v1/admin/", "/api/v1/sensitive/"]
)
```

## Performance Considerations

1. **Caching**: Signature verification is fast (microseconds)
2. **Nonce Storage**: Use Redis for distributed systems
3. **Key Lookup**: Cache key lookups for frequent requests
4. **Body Reading**: Body is only read once and cached

## See Also

- [API Security Best Practices](./api_security.md)
- [Authentication Guide](./authentication.md)
- [Rate Limiting Guide](./rate_limiting.md)
