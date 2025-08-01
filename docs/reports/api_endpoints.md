# ViolentUTF API Endpoints Documentation

**Generated on:** 2025-07-27 19:03:12
**Status:** ✅ GitHub Issue #18 COMPLETED
**Total Endpoints:** 50 endpoints across 7 categories

## Executive Summary

The ViolentUTF API is a comprehensive, production-ready REST API that implements all requirements from GitHub Issue #18. The API provides complete CRUD operations with enterprise-grade features including authentication, authorization, audit logging, and comprehensive security controls.

### Issue #18 Requirements Verification

✅ **Extract basic CRUD endpoints** - 50 CRUD endpoints implemented
✅ **Remove APISIX routing dependencies** - Direct FastAPI routing only
✅ **Implement direct API access** - RESTful endpoints at `/api/v1/*`
✅ **Add comprehensive input validation** - Pydantic v2 + sanitization middleware
✅ **Implement idempotency support** - Redis-backed idempotency middleware
✅ **Add proper error responses** - Standardized BaseResponse format
✅ **Ensure stateless operation** - JWT authentication, external Redis cache
✅ **Add OpenAPI documentation** - Interactive docs at `/api/v1/docs`

## API Overview

### Base URL
- **Development**: `http://localhost:8000`
- **API Base Path**: `/api/v1`
- **Documentation**: `/api/v1/docs`
- **OpenAPI Schema**: `/api/v1/openapi.json`

### Authentication
- **Method**: JWT Bearer tokens
- **Header**: `Authorization: Bearer <token>`
- **Endpoints**: `/api/v1/auth/login`, `/api/v1/auth/register`

### Features
- **Idempotency**: Use `Idempotency-Key` header for safe retries
- **Pagination**: `page` and `per_page` parameters for list endpoints
- **Filtering**: Advanced filtering capabilities on list endpoints
- **Audit Trail**: All operations logged to audit system
- **Rate Limiting**: Per-endpoint rate limiting with `slowapi`
- **Input Validation**: Multi-layer validation and sanitization
- **Error Handling**: Consistent error responses with trace IDs

## Endpoint Categories

### 1. Health & Monitoring (3 endpoints)

Essential endpoints for service health monitoring and system status.

- `GET /api/v1/health`: Basic health check - returns 200 if service is running
- `GET /api/v1/ready`: Readiness check - verifies all dependencies (database, cache)
- `GET /api/v1/live`: Liveness check - kubernetes-style liveness probe

**Use Cases:**
- Load balancer health checks
- Kubernetes readiness/liveness probes
- Monitoring system integration

### 2. Authentication (2 endpoints)

Secure authentication system with JWT tokens.

- `POST /api/v1/auth/login`: Authenticate user and receive JWT tokens
- `POST /api/v1/auth/register`: Register new user account

**Features:**
- Argon2 password hashing
- JWT access and refresh tokens
- Account verification workflow
- MFA support preparation

### 3. User Management (13 endpoints)

Comprehensive user lifecycle management with role-based access control.

#### Core CRUD Operations
- `GET /api/v1/users/`: List users with pagination and filtering
- `POST /api/v1/users/`: Create new user (admin required)
- `GET /api/v1/users/{item_id}`: Get user details by ID
- `PUT /api/v1/users/{item_id}`: Update user (full update)
- `PATCH /api/v1/users/{item_id}`: Partially update user
- `DELETE /api/v1/users/{item_id}`: Soft delete user

#### Self-Service Operations
- `GET /api/v1/users/me`: Get current user profile
- `PUT /api/v1/users/me`: Update current user profile
- `POST /api/v1/users/me/change-password`: Change own password

#### Lookup Operations
- `GET /api/v1/users/username/{username}`: Find user by username

#### Administrative Operations
- `POST /api/v1/users/{user_id}/verify`: Verify user email (admin only)
- `POST /api/v1/users/{user_id}/activate`: Activate user account (admin only)
- `POST /api/v1/users/{user_id}/deactivate`: Deactivate user account (admin only)

**Security Features:**
- Role-based access control (RBAC)
- Password complexity requirements
- Email verification workflow
- Account activation/deactivation

### 4. API Key Management (11 endpoints)

Secure API key management for programmatic access.

#### Core CRUD Operations
- `GET /api/v1/api-keys/`: List API keys with filtering
- `POST /api/v1/api-keys/`: Create new API key
- `GET /api/v1/api-keys/{item_id}`: Get API key details
- `PUT /api/v1/api-keys/{item_id}`: Update API key
- `PATCH /api/v1/api-keys/{item_id}`: Partially update API key
- `DELETE /api/v1/api-keys/{item_id}`: Delete API key

#### Self-Service Operations
- `GET /api/v1/api-keys/my-keys`: Get current user's API keys

#### Management Operations
- `POST /api/v1/api-keys/{key_id}/revoke`: Revoke API key immediately
- `POST /api/v1/api-keys/{key_id}/validate`: Validate API key status

#### Configuration Operations
- `GET /api/v1/api-keys/permission-templates`: Get available permission templates
- `GET /api/v1/api-keys/usage-stats`: Get API key usage statistics

**Security Features:**
- SHA256 key hashing
- Permission-based access control
- Usage tracking and analytics
- Immediate revocation capability
- Expiration date support

### 5. Session Management (12 endpoints)

Comprehensive session lifecycle management and security monitoring.

#### Core CRUD Operations
- `GET /api/v1/sessions/`: List sessions with filtering
- `POST /api/v1/sessions/`: Create new session
- `GET /api/v1/sessions/{item_id}`: Get session details
- `PUT /api/v1/sessions/{item_id}`: Update session
- `PATCH /api/v1/sessions/{item_id}`: Partially update session
- `DELETE /api/v1/sessions/{item_id}`: Delete session

#### Self-Service Operations
- `GET /api/v1/sessions/my-sessions`: Get current user's sessions

#### Security Operations
- `POST /api/v1/sessions/{session_id}/revoke`: Revoke specific session
- `POST /api/v1/sessions/revoke-all`: Revoke all user sessions
- `POST /api/v1/sessions/{session_id}/extend`: Extend session lifetime

#### Monitoring Operations
- `GET /api/v1/sessions/active`: Get currently active sessions
- `GET /api/v1/sessions/statistics`: Get session usage statistics

**Security Features:**
- Session tracking and monitoring
- Device fingerprinting
- Geographic location tracking
- Suspicious activity detection
- Bulk session revocation

### 6. Audit Logging (8 endpoints)

Comprehensive audit trail for compliance and security monitoring.

#### Core Operations
- `GET /api/v1/audit-logs/`: List audit logs with filtering
- `GET /api/v1/audit-logs/{log_id}`: Get specific audit log details

#### Search and Filter Operations
- `GET /api/v1/audit-logs/search`: Advanced search across audit logs
- `GET /api/v1/audit-logs/user/{user_id}`: Get audit logs for specific user
- `GET /api/v1/audit-logs/resource/{resource_type}/{resource_id}`: Get audit logs for specific resource

#### Analytics Operations
- `GET /api/v1/audit-logs/statistics`: Get audit log statistics and metrics
- `GET /api/v1/audit-logs/summary/{resource_type}/{resource_id}`: Get audit summary for resource

#### Export Operations
- `POST /api/v1/audit-logs/export`: Export audit logs in various formats

**Compliance Features:**
- Immutable audit records
- Comprehensive event tracking
- Advanced filtering and search
- Export capabilities (CSV, JSON)
- Retention policy support
- Statistical analysis

### 7. General (1 endpoint)

- `GET /`: Root endpoint - API information and status

Returns basic API information including service name, version, and documentation links.

## HTTP Methods and Operations

### CRUD Operations Mapping
- **GET**: Read operations (list and retrieve)
- **POST**: Create operations and actions
- **PUT**: Full resource updates
- **PATCH**: Partial resource updates
- **DELETE**: Resource deletion (soft delete)

### Standard Response Codes
- **200 OK**: Successful GET, PUT, PATCH
- **201 Created**: Successful POST (creation)
- **204 No Content**: Successful DELETE
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (duplicate)
- **422 Unprocessable Entity**: Validation error
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

## Security Features

### Authentication & Authorization
- JWT-based stateless authentication
- Role-based access control (RBAC)
- API key authentication for programmatic access
- Multi-factor authentication preparation

### Input Validation & Sanitization
- Pydantic v2 schema validation
- Input sanitization middleware
- SQL injection prevention
- XSS protection
- Prompt injection detection (AI safety)

### Security Headers & Middleware
- CORS protection
- CSRF protection
- Security headers (HSTS, CSP, etc.)
- Request signing for sensitive operations
- Rate limiting per endpoint

### Audit & Monitoring
- Comprehensive audit logging
- Request/response logging
- Metrics collection (Prometheus)
- Correlation ID tracking
- Security event monitoring

## Performance Features

### Caching
- Redis-based response caching
- Configurable TTL policies
- Cache invalidation strategies

### Database Optimization
- Connection pooling
- Query optimization
- Pagination for large datasets
- Database health monitoring

### Request Processing
- GZIP compression
- Request size limits
- Timeout configuration
- Circuit breakers for resilience

## Development Features

### Documentation
- Interactive OpenAPI documentation
- Comprehensive endpoint descriptions
- Request/response examples
- Schema validation documentation

### Testing Support
- Idempotency key support
- Test data isolation
- Mock-friendly design
- Comprehensive error responses

### Monitoring Integration
- Prometheus metrics endpoint
- Health check endpoints
- Structured logging
- Distributed tracing preparation

## Migration Notes

This API is a complete implementation from scratch with no legacy dependencies:

### No Legacy Migration Required
- Built as standalone FastAPI application
- No APISIX gateway dependencies
- Direct HTTP routing
- Independent authentication system

### Original Requirements Fulfilled
All GitHub Issue #18 requirements have been fully implemented:

1. ✅ Basic CRUD endpoints extracted and implemented
2. ✅ APISIX routing dependencies removed (none existed)
3. ✅ Direct API access implemented
4. ✅ Comprehensive input validation added
5. ✅ Idempotency support implemented
6. ✅ Proper error responses added
7. ✅ Stateless operation ensured
8. ✅ OpenAPI documentation added

## Usage Examples

### Authentication
```bash
# Login
curl -X POST /api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "user", "password": "password"}'  # pragma: allowlist secret

# Use token
curl -X GET /api/v1/users/me \\
  -H "Authorization: Bearer <token>"
```

### Idempotency
```bash
# Safe retry with idempotency key
curl -X POST /api/v1/users \\
  -H "Authorization: Bearer <token>" \\
  -H "Idempotency-Key: user-creation-123" \\
  -H "Content-Type: application/json" \\
  -d '{"username": "newuser", "email": "user@example.com"}'
```

### Pagination
```bash
# List with pagination
curl -X GET "/api/v1/users?page=1&per_page=20" \\
  -H "Authorization: Bearer <token>"
```

## Conclusion

The ViolentUTF API successfully implements all requirements from GitHub Issue #18 and provides a production-ready, enterprise-grade REST API with:

- **50 comprehensive endpoints** across 7 categories
- **Complete CRUD operations** for all entities
- **Enterprise security features** including authentication, authorization, and audit
- **Production-ready architecture** with monitoring, caching, and resilience
- **Developer-friendly features** including comprehensive documentation and testing support

The API is ready for immediate production deployment and can serve as the foundation for building AI red-teaming applications with robust security and operational capabilities.

---

**Status**: ✅ COMPLETED
**Last Updated**: 2025-07-27
**API Version**: 1.0.0
