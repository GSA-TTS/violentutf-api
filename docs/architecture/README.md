# Architecture Documentation

## Overview

The ViolentUTF API is a standalone FastAPI-based microservice extracted from the mother ViolentUTF repository. It provides a secure, scalable, and maintainable API service for AI red-teaming operations.

## Architecture Principles

1. **Security First**: All design decisions prioritize security
2. **Clean Architecture**: Separation of concerns with clear boundaries
3. **Dependency Injection**: Loose coupling between components
4. **Async by Default**: Leveraging Python's async capabilities
5. **Observable**: Comprehensive logging, metrics, and tracing

## Directory Structure

```
violentutf-api/
├── app/
│   ├── api/          # API layer (routes, endpoints)
│   ├── core/         # Core business logic
│   ├── middleware/   # Cross-cutting concerns
│   ├── models/       # Data models
│   ├── services/     # Business services
│   └── main.py       # Application entry point
├── tests/
│   ├── unit/         # Unit tests
│   ├── integration/  # Integration tests
│   └── contract/     # API contract tests
└── docs/             # Documentation
```

## Key Components

### API Layer
- FastAPI application
- Route definitions
- Request/response validation
- OpenAPI documentation

### Core Layer
- Configuration management
- Security utilities
- Error handling
- Logging setup

### Middleware Stack
1. **RequestIDMiddleware**: Trace requests across services
2. **LoggingMiddleware**: Structured request/response logging
3. **MetricsMiddleware**: Prometheus metrics collection
4. **SecurityMiddleware**: Security headers (HSTS, CSP, etc.)
5. **CompressionMiddleware**: GZip response compression

### Security Architecture
- JWT-based authentication
- Argon2 password hashing
- Rate limiting per endpoint
- Security headers on all responses
- Input validation and sanitization

## Data Flow

```
Client Request
    ↓
Nginx/Load Balancer
    ↓
FastAPI Application
    ↓
Middleware Pipeline
    ├── Request ID Assignment
    ├── Security Headers
    ├── Request Logging
    ├── Metrics Collection
    └── Rate Limiting
    ↓
Route Handler
    ↓
Business Logic
    ↓
Database/Cache
    ↓
Response Pipeline
    ├── Response Compression
    ├── Response Logging
    └── Metrics Update
    ↓
Client Response
```

## Deployment Architecture

### Development
- Single instance
- SQLite database
- In-memory caching
- Debug logging

### Production
- Multiple instances behind load balancer
- PostgreSQL database
- Redis cache
- Structured JSON logging
- Prometheus metrics
- Distributed tracing

## External Dependencies

### Required
- PostgreSQL or SQLite (database)
- Redis (caching) - optional

### Removed Dependencies
- APISIX (API Gateway) - removed
- Keycloak (SSO) - removed
- Mother repo components - standalone

## Scaling Considerations

1. **Horizontal Scaling**: Stateless design allows multiple instances
2. **Database Pooling**: Connection pooling for efficiency
3. **Caching Strategy**: Redis for session and response caching
4. **Async Operations**: Non-blocking I/O for better concurrency

## Monitoring & Observability

1. **Logging**: Structured JSON logs with correlation IDs
2. **Metrics**: Prometheus-compatible metrics
3. **Health Checks**: Comprehensive health endpoints
4. **Tracing**: OpenTelemetry support (future)

## Security Considerations

1. **Authentication**: JWT with refresh token rotation
2. **Authorization**: Role-based access control (RBAC)
3. **Encryption**: TLS 1.3+ for transport, Argon2 for passwords
4. **Input Validation**: Pydantic models with strict validation
5. **Rate Limiting**: Per-endpoint and per-user limits
6. **Security Headers**: CSP, HSTS, X-Frame-Options, etc.

## Future Enhancements

1. OpenTelemetry integration
2. GraphQL support
3. WebSocket endpoints
4. Event-driven architecture
5. Multi-tenancy support
