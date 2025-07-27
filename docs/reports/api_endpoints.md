# API Endpoints Comparison Report

**Generated on:** 2025-07-26 20:41:22

## Executive Summary

- **Original ViolentUTF API:** 18 versioned endpoints across 7 categories
- **Spinoff ViolentUTF-API:** 80 endpoints across 12 categories
- **New Endpoints Added:** 61
- **Enhanced Endpoints:** 2
- **Legacy Endpoints Replaced:** 18 (replaced with versioned equivalents)

## Feature Completeness Analysis

✅ **All original API features are preserved in the spinoff**

The spinoff API maintains complete backward compatibility through versioned endpoints while adding significant enhancements.

## Legacy Endpoint Migration

The following non-versioned endpoints from the original API have been replaced with versioned equivalents:

### Authentication

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `POST /api/auth/login` | `POST /api/v1/auth/login` | API versioning standardization |
| `POST /api/auth/logout` | `POST /api/v1/auth/logout` | API versioning standardization |
| `POST /api/auth/refresh` | `POST /api/v1/auth/refresh` | API versioning standardization |

### Configuration

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `GET /api/config/converters` | `GET /api/v1/config/converters` | API versioning standardization |
| `GET /api/config/orchestrators` | `GET /api/v1/config/orchestrators` | API versioning standardization |

### Health/Status

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `GET /api/status` | `GET /api/v1/status` | API versioning standardization |

### Memory/History

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `GET /api/memory/conversations` | `GET /api/v1/memory/conversations` | API versioning standardization |
| `GET /api/memory/conversations/{id}` | `GET /api/v1/memory/conversations/{id}` | API versioning standardization |

### Prompt Management

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `GET /api/prompts` | `GET /api/v1/prompts` | API versioning standardization |
| `POST /api/prompts` | `POST /api/v1/prompts` | API versioning standardization |
| `PUT /api/prompts/{id}` | `PUT /api/v1/prompts/{id}` | API versioning standardization |
| `DELETE /api/prompts/{id}` | `DELETE /api/v1/prompts/{id}` | API versioning standardization |

### Red Team Operations

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `POST /api/redteam/attack` | `POST /api/v1/redteam/attack` | API versioning standardization |
| `GET /api/redteam/targets` | `GET /api/v1/redteam/targets` | API versioning standardization |
| `POST /api/redteam/targets` | `POST /api/v1/redteam/targets` | API versioning standardization |
| `GET /api/redteam/results/{id}` | `GET /api/v1/redteam/results/{id}` | API versioning standardization |

### Scoring

| Original Endpoint | Replaced By | Reason |
|-------------------|-------------|---------|
| `GET /api/scoring/metrics` | `GET /api/v1/scoring/metrics` | API versioning standardization |
| `POST /api/scoring/evaluate` | `POST /api/v1/scoring/evaluate` | API versioning standardization |

## New Feature Categories

### User Management

Added 13 endpoints for user management:

- `GET /api/v1/users`: List users
- `GET /api/v1/users/{id}`: Get user details
- `POST /api/v1/users`: Create user
- `PUT /api/v1/users/{id}`: Update user
- `PATCH /api/v1/users/{id}`: Partial update
- `DELETE /api/v1/users/{id}`: Soft delete
- `GET /api/v1/users/me`: Get own profile
- `PUT /api/v1/users/me`: Update own profile
- `POST /api/v1/users/me/change-password`: Change password
- `GET /api/v1/users/username/{username}`: Get by username
- `POST /api/v1/users/{id}/verify`: Verify email
- `POST /api/v1/users/{id}/activate`: Activate user
- `POST /api/v1/users/{id}/deactivate`: Deactivate user

### API Key Management

Added 12 endpoints for api key management:

- `GET /api/v1/api-keys`: List API keys
- `GET /api/v1/api-keys/{id}`: Get API key
- `POST /api/v1/api-keys`: Create API key
- `PUT /api/v1/api-keys/{id}`: Update API key
- `PATCH /api/v1/api-keys/{id}`: Partial update
- `DELETE /api/v1/api-keys/{id}`: Delete API key
- `GET /api/v1/api-keys/my-keys`: Get own keys
- `POST /api/v1/api-keys/{id}/revoke`: Revoke key
- `POST /api/v1/api-keys/{id}/validate`: Validate key
- `GET /api/v1/api-keys/permission-templates`: Get templates
- `GET /api/v1/api-keys/usage-stats`: Usage stats
- `POST /api/v1/api-keys/{id}/record-usage`: Record usage

### Session Management

Added 13 endpoints for session management:

- `GET /api/v1/sessions`: List sessions
- `GET /api/v1/sessions/{id}`: Get session
- `POST /api/v1/sessions`: Create session
- `PUT /api/v1/sessions/{id}`: Update session
- `PATCH /api/v1/sessions/{id}`: Partial update
- `DELETE /api/v1/sessions/{id}`: Delete session
- `GET /api/v1/sessions/my-sessions`: Get own sessions
- `POST /api/v1/sessions/{id}/revoke`: Revoke session
- `POST /api/v1/sessions/revoke-all`: Revoke all
- `POST /api/v1/sessions/{id}/extend`: Extend session
- `GET /api/v1/sessions/active`: Active sessions
- `GET /api/v1/sessions/statistics`: Session stats
- `POST /api/v1/sessions/cleanup-expired`: Cleanup expired

### Audit Logging

Added 7 endpoints for audit logging:

- `GET /api/v1/audit-logs`: List logs
- `GET /api/v1/audit-logs/{id}`: Get log
- `GET /api/v1/audit-logs/user/{user_id}`: User logs
- `GET /api/v1/audit-logs/resource/{type}/{id}`: Resource logs
- `GET /api/v1/audit-logs/statistics`: Log stats
- `GET /api/v1/audit-logs/summary/{type}/{id}`: Log summary
- `POST /api/v1/audit-logs/export`: Export logs

### MCP Integration

Added 3 endpoints for mcp integration:

- `GET /api/v1/mcp/tools`: List MCP tools
- `POST /api/v1/mcp/execute`: Execute MCP tool
- `GET /api/v1/mcp/sse`: SSE stream

## Enhanced Endpoints

### POST /api/v1/auth/login

**Category:** Authentication

**Enhancements:**
- MFA support
- Session tracking

### POST /api/v1/redteam/attack

**Category:** Red Team Operations

**Enhancements:**
- PyRIT
- Idempotency
- Enhanced error handling

## New Endpoints Analysis

### Rationale for New Endpoints

#### API key creation

- `POST /api/v1/api-keys` (API Key Management): Api Keys

#### Analytics and monitoring

- `GET /api/v1/audit-logs/statistics` (Audit Logging): Statistics

#### Comparative analysis

- `POST /api/v1/scoring/compare` (Scoring): Compare

#### Compliance and security monitoring

- `GET /api/v1/audit-logs` (Audit Logging): Audit Logs

#### Data export capabilities

- `POST /api/v1/audit-logs/export` (Audit Logging): Export

#### Data management and compliance

- `DELETE /api/v1/redteam/attacks/{id}` (Red Team Operations):

#### Data retention policies

- `DELETE /api/v1/memory/conversations/{id}` (Memory/History):

#### Email verification workflow

- `POST /api/v1/users/{id}/verify` (User Management): Verify

#### Enhanced functionality

- `DELETE /api/v1/api-keys/{id}` (API Key Management):

#### Enhanced memory retrieval

- `POST /api/v1/memory/search` (Memory/History): Search

#### Extended functionality via MCP

- `POST /api/v1/mcp/execute` (MCP Integration): Execute

#### Historical analysis and reporting

- `GET /api/v1/redteam/attacks` (Red Team Operations): Attacks

#### Model Context Protocol integration

- `GET /api/v1/mcp/tools` (MCP Integration): Tools

#### Monitoring integration

- `GET /api/v1/metrics` (Health/Status): Metrics

#### Performance tracking over time

- `GET /api/v1/scoring/history` (Scoring): History

#### Programmatic access management

- `GET /api/v1/api-keys` (API Key Management): Api Keys

#### Real-time MCP communication

- `GET /api/v1/mcp/sse` (MCP Integration): Sse

#### Runtime configuration changes

- `PUT /api/v1/config/settings` (Configuration): Settings

#### Security control

- `POST /api/v1/api-keys/{id}/revoke` (API Key Management): Revoke

#### Security monitoring and session control

- `GET /api/v1/sessions` (Session Management): Sessions

#### Self-service capabilities

- `GET /api/v1/api-keys/my-keys` (API Key Management): My Keys

#### Self-service user registration for scalability

- `POST /api/v1/auth/register` (Authentication): Register

#### Session creation

- `POST /api/v1/sessions` (Session Management): Sessions

#### Session management

- `POST /api/v1/sessions/{id}/extend` (Session Management): Extend

#### System configuration management

- `GET /api/v1/config/settings` (Configuration): Settings

#### Template version control

- `GET /api/v1/prompts/{id}/versions` (Prompt Management): Versions

#### User administration and management

- `GET /api/v1/users` (User Management): Users

#### User creation

- `POST /api/v1/users` (User Management): Users

#### User lifecycle management

- `POST /api/v1/users/{id}/activate` (User Management): Activate

#### Validation capabilities

- `POST /api/v1/api-keys/{id}/validate` (API Key Management): Validate

## Detailed Endpoint Comparison

### API Key Management

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/v1/api-keys/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/api-keys` | - | ✓ | ✨ New | Programmatic access management |
| `GET /api/v1/api-keys/my-keys` | - | ✓ | ✨ New | Self-service capabilities |
| `GET /api/v1/api-keys/permission-templates` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/api-keys/usage-stats` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/api-keys/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `PATCH /api/v1/api-keys/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/api-keys` | - | ✓ | ✨ New | API key creation |
| `POST /api/v1/api-keys/{id}/record-usage` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/api-keys/{id}/revoke` | - | ✓ | ✨ New | Security control |
| `POST /api/v1/api-keys/{id}/validate` | - | ✓ | ✨ New | Validation capabilities |
| `PUT /api/v1/api-keys/{id}` | - | ✓ | ✨ New | Enhanced functionality |

### Audit Logging

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `GET /api/v1/audit-logs` | - | ✓ | ✨ New | Compliance and security monitoring |
| `GET /api/v1/audit-logs/resource/{type}/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/audit-logs/statistics` | - | ✓ | ✨ New | Analytics and monitoring |
| `GET /api/v1/audit-logs/summary/{type}/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/audit-logs/user/{user_id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/audit-logs/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/audit-logs/export` | - | ✓ | ✨ New | Data export capabilities |

### Authentication

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `POST /api/auth/login` | ✓ | - | 🔄 Replaced | Use `/api/v1/auth/login` instead |
| `POST /api/auth/logout` | ✓ | - | 🔄 Replaced | Use `/api/v1/auth/logout` instead |
| `POST /api/auth/refresh` | ✓ | - | 🔄 Replaced | Use `/api/v1/auth/refresh` instead |
| `POST /api/v1/auth/login` | ✓ | ✓ | ⚡ Enhanced | Enhanced with new features |
| `POST /api/v1/auth/logout` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/v1/auth/refresh` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/v1/auth/register` | - | ✓ | ✨ New | Self-service user registration for scalability |

### Configuration

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `GET /api/config/converters` | ✓ | - | 🔄 Replaced | Use `/api/v1/config/converters` instead |
| `GET /api/config/orchestrators` | ✓ | - | 🔄 Replaced | Use `/api/v1/config/orchestrators` instead |
| `GET /api/v1/config/converters` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/v1/config/orchestrators` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/v1/config/settings` | - | ✓ | ✨ New | System configuration management |
| `PUT /api/v1/config/settings` | - | ✓ | ✨ New | Runtime configuration changes |

### Health/Status

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `GET /api/status` | ✓ | - | 🔄 Replaced | Use `/api/v1/status` instead |
| `GET /api/v1/health` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/metrics` | - | ✓ | ✨ New | Monitoring integration |
| `GET /api/v1/status` | ✓ | ✓ | ✅ Preserved |  |
| `GET /health` | ✓ | ✓ | ✅ Preserved |  |

### MCP Integration

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `GET /api/v1/mcp/sse` | - | ✓ | ✨ New | Real-time MCP communication |
| `GET /api/v1/mcp/tools` | - | ✓ | ✨ New | Model Context Protocol integration |
| `POST /api/v1/mcp/execute` | - | ✓ | ✨ New | Extended functionality via MCP |

### Memory/History

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/v1/memory/conversations/{id}` | - | ✓ | ✨ New | Data retention policies |
| `GET /api/memory/conversations` | ✓ | - | 🔄 Replaced | Use `/api/v1/memory/conversations` instead |
| `GET /api/memory/conversations/{id}` | ✓ | - | 🔄 Replaced | Use `/api/v1/memory/conversations/{id}` instead |
| `GET /api/v1/memory/conversations` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/v1/memory/conversations/{id}` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/v1/memory/search` | - | ✓ | ✨ New | Enhanced memory retrieval |

### Prompt Management

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/prompts/{id}` | ✓ | - | 🔄 Replaced | Use `/api/v1/prompts/{id}` instead |
| `DELETE /api/v1/prompts/{id}` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/prompts` | ✓ | - | 🔄 Replaced | Use `/api/v1/prompts` instead |
| `GET /api/v1/prompts` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/v1/prompts/{id}/versions` | - | ✓ | ✨ New | Template version control |
| `POST /api/prompts` | ✓ | - | 🔄 Replaced | Use `/api/v1/prompts` instead |
| `POST /api/v1/prompts` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/v1/prompts/{id}/clone` | - | ✓ | ✨ New | Template version control |
| `PUT /api/prompts/{id}` | ✓ | - | 🔄 Replaced | Use `/api/v1/prompts/{id}` instead |
| `PUT /api/v1/prompts/{id}` | ✓ | ✓ | ✅ Preserved |  |

### Red Team Operations

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/v1/redteam/attacks/{id}` | - | ✓ | ✨ New | Data management and compliance |
| `GET /api/redteam/results/{id}` | ✓ | - | 🔄 Replaced | Use `/api/v1/redteam/results/{id}` instead |
| `GET /api/redteam/targets` | ✓ | - | 🔄 Replaced | Use `/api/v1/redteam/targets` instead |
| `GET /api/v1/redteam/attacks` | - | ✓ | ✨ New | Historical analysis and reporting |
| `GET /api/v1/redteam/results/{id}` | ✓ | ✓ | ✅ Preserved |  |
| `GET /api/v1/redteam/targets` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/redteam/attack` | ✓ | - | 🔄 Replaced | Use `/api/v1/redteam/attack` instead |
| `POST /api/redteam/targets` | ✓ | - | 🔄 Replaced | Use `/api/v1/redteam/targets` instead |
| `POST /api/v1/redteam/attack` | ✓ | ✓ | ⚡ Enhanced | Enhanced with new features |
| `POST /api/v1/redteam/targets` | ✓ | ✓ | ✅ Preserved |  |

### Scoring

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `GET /api/scoring/metrics` | ✓ | - | 🔄 Replaced | Use `/api/v1/scoring/metrics` instead |
| `GET /api/v1/scoring/history` | - | ✓ | ✨ New | Performance tracking over time |
| `GET /api/v1/scoring/metrics` | ✓ | ✓ | ✅ Preserved |  |
| `POST /api/scoring/evaluate` | ✓ | - | 🔄 Replaced | Use `/api/v1/scoring/evaluate` instead |
| `POST /api/v1/scoring/compare` | - | ✓ | ✨ New | Comparative analysis |
| `POST /api/v1/scoring/evaluate` | ✓ | ✓ | ✅ Preserved |  |

### Session Management

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/v1/sessions/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/sessions` | - | ✓ | ✨ New | Security monitoring and session control |
| `GET /api/v1/sessions/active` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/sessions/my-sessions` | - | ✓ | ✨ New | Self-service capabilities |
| `GET /api/v1/sessions/statistics` | - | ✓ | ✨ New | Analytics and monitoring |
| `GET /api/v1/sessions/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `PATCH /api/v1/sessions/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/sessions` | - | ✓ | ✨ New | Session creation |
| `POST /api/v1/sessions/cleanup-expired` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/sessions/revoke-all` | - | ✓ | ✨ New | Security control |
| `POST /api/v1/sessions/{id}/extend` | - | ✓ | ✨ New | Session management |
| `POST /api/v1/sessions/{id}/revoke` | - | ✓ | ✨ New | Security control |
| `PUT /api/v1/sessions/{id}` | - | ✓ | ✨ New | Enhanced functionality |

### User Management

| Endpoint | Original | Spinoff | Status | Notes |
|----------|----------|---------|--------|-------|
| `DELETE /api/v1/users/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/users` | - | ✓ | ✨ New | User administration and management |
| `GET /api/v1/users/me` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/users/username/{username}` | - | ✓ | ✨ New | Enhanced functionality |
| `GET /api/v1/users/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `PATCH /api/v1/users/{id}` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/users` | - | ✓ | ✨ New | User creation |
| `POST /api/v1/users/me/change-password` | - | ✓ | ✨ New | Enhanced functionality |
| `POST /api/v1/users/{id}/activate` | - | ✓ | ✨ New | User lifecycle management |
| `POST /api/v1/users/{id}/deactivate` | - | ✓ | ✨ New | User lifecycle management |
| `POST /api/v1/users/{id}/verify` | - | ✓ | ✨ New | Email verification workflow |
| `PUT /api/v1/users/me` | - | ✓ | ✨ New | Enhanced functionality |
| `PUT /api/v1/users/{id}` | - | ✓ | ✨ New | Enhanced functionality |

## Architecture Improvements

### 1. API Versioning

- All endpoints now use consistent `/api/v1/` prefix
- Legacy non-versioned endpoints replaced with versioned equivalents
- Enables future API version management
- Backward compatibility through versioning

### 2. Enhanced Security

- Comprehensive user management endpoints
- API key management with SHA256 hashing
- Session management and monitoring
- Detailed audit logging for compliance

### 3. Operational Excellence

- Idempotency support for non-idempotent operations
- Advanced pagination and filtering
- Comprehensive error responses (RFC 7807)
- Prometheus metrics endpoint

### 4. Developer Experience

- OpenAPI/Swagger documentation
- Consistent RESTful patterns
- Self-service endpoints (/me)
- Permission templates

## Recommendations

### High Priority

1. **Complete MCP Integration**: The MCP endpoints provide extended functionality
2. **Implement Batch Operations**: Add batch endpoints for bulk operations
3. **Add WebSocket Support**: Real-time updates for attack progress

### Medium Priority

1. **Rate Limiting Endpoints**: Add endpoints to view/manage rate limits
2. **Backup/Restore API**: System backup and restore capabilities
3. **Plugin Management**: If plugin system is implemented

## Conclusion

The spinoff ViolentUTF-API successfully preserves all core functionality from the original ViolentUTF API while adding significant enhancements:

1. **Complete Feature Parity**: All red team operations are preserved
2. **API Standardization**: Legacy endpoints replaced with versioned equivalents
3. **Enhanced Security**: Comprehensive auth, session, and audit systems
4. **Better Operations**: Monitoring, metrics, and management capabilities
5. **Improved Developer Experience**: Consistent patterns and documentation
6. **Future-Ready**: Versioned API with extensibility in mind

The architectural improvements and new endpoints are principled additions that address real operational needs while maintaining the core red teaming functionality.
