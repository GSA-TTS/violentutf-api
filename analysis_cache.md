# Unit Test Failure Analysis

## Problem Summary
API tests in `test_api_keys.py` are failing due to middleware authentication/security requirements:

1. **Request Signing Middleware (401 Unauthorized)**
   - Missing X-Signature header
   - Missing X-Timestamp header
   - Missing X-Nonce header
   - Has API key but missing signing headers

2. **CSRF Middleware (403 Forbidden)**
   - Missing CSRF token for POST requests
   - `csrf_validation_failed` with `has_submitted: false`

## Failure Patterns
- GET requests: 401 due to request signing
- POST requests: 403 due to CSRF validation
- All API key endpoint tests affected

## Root Cause
The test environment is using the full application stack with all middleware enabled, but the tests are not providing the required security headers/tokens that the middleware expects.

## Middleware Analysis

### Request Signing Middleware
- **Paths requiring signing**: `/api/v1/admin/`, `/api/v1/users/`, `/api/v1/api-keys/`
- **Required headers**: X-Signature, X-Timestamp, X-API-Key, X-Nonce
- **Algorithm**: HMAC-SHA256 with canonical request string
- **API Secret Logic**: `test_` prefix → `test_secret`, `admin_` prefix → `admin_secret`

### CSRF Middleware
- **Configuration**: `CSRF_PROTECTION = True` by default
- **Exempt paths**: `/api/v1/auth` and others, but NOT `/api/v1/api-keys/`
- **Safe methods**: GET, HEAD, OPTIONS, TRACE (no CSRF needed)
- **Required**: Cookie token + header token (double-submit pattern)

## Solution Implementation Status

### ✅ Completed
- Added `REQUEST_SIGNING_ENABLED` configuration option
- Updated `main.py` to conditionally add middleware based on settings
- Updated test configuration to set `CSRF_PROTECTION=False` and `REQUEST_SIGNING_ENABLED=False`

### ❌ Current Issue
**Settings Override Problem**: The test application is created before the settings override is applied. The `settings` global in `main.py` is imported at module level, so test overrides don't affect it.

**Evidence**: Test logs still show request signing middleware being triggered despite configuration.

### Next Steps
1. Fix settings dependency injection in test application creation
2. Either use dependency override for settings or modify main.py to accept settings parameter
3. Validate middleware is actually disabled in test environment

## Technical Analysis
The `create_application()` function in main.py uses the global `settings` import, which gets evaluated at import time. The test fixture pattern of creating `test_settings` and then calling `create_application()` doesn't override the already-imported global settings.

**Solution Options**:
1. Modify `create_application()` to accept settings parameter
2. Use dependency override pattern for settings in conftest
3. Monkey-patch the settings module before app creation
