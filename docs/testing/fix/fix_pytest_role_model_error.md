# Fix Documentation: pytest_role_model_error.json

## Fix Applied
**Type**: LOGIC_ERROR Resolution
**Date**: 2025-08-25
**Original NFO**: pytest_role_model_error.json

## Problem Summary
Integration tests were failing with TypeError because test code was trying to instantiate Role objects with a `hierarchy_level` parameter that doesn't exist in the actual Role model schema.

## Root Cause Analysis
The Role model uses a JSON field called `role_metadata` with a nested `level` key, but test fixtures were using a non-existent `hierarchy_level` constructor parameter. This mismatch between test expectations and actual model schema caused SQLAlchemy constructor failures.

## Solution Applied
**Selected Hypothesis**: PRIMARY - Update test data to use correct Role model constructor with `role_metadata`

### Changes Made
1. **File**: `/Users/tamnguyen/Documents/GitHub/violentutf-api/tests/integration/test_auth_integration.py`
   - **Lines Updated**: 189-193, 196-200, 474-478, 481-485
   - **Action**: Replaced all `hierarchy_level=X` with `role_metadata={"level": X}`

### Specific Fixes
```python
# BEFORE (causing TypeError):
admin_role = Role(
    name="admin",
    display_name="Administrator",
    hierarchy_level=100,  # ❌ Invalid parameter
)

# AFTER (correct schema):
admin_role = Role(
    name="admin",
    display_name="Administrator",
    role_metadata={"level": 100},  # ✅ Valid parameter
)
```

### Validation in Sandbox
- ✅ Confirmed Role constructor accepts `role_metadata` parameter
- ✅ Schema matches actual model definition in `app/models/role.py`
- ✅ All four Role instantiations updated consistently

## Expected Outcome
- All affected integration tests should now pass without TypeError
- Role objects will be created with proper metadata structure
- RBAC functionality will work correctly with level-based hierarchy

## Affected Tests
- test_api_key_authentication_flow
- test_rbac_authorization_flow
- test_oauth2_flow
- test_audit_logging_integration
- test_permission_middleware_integration

## Risk Assessment
- **Risk Level**: LOW
- **Impact**: Positive - aligns test code with actual model schema
- **Rollback**: Simple - revert to previous hierarchy_level parameters

## Testing Recommendation
Run the affected integration test to verify fix:
```bash
python -m pytest tests/integration/test_auth_integration.py::TestAuthIntegration::test_rbac_authorization_flow -v
```
