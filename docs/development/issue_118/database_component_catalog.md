# ViolentUTF API Database Component Catalog
## Comprehensive Inventory and Configuration Details

**Document Version**: 1.0
**Analysis Date**: September 19, 2025
**Issue**: #118 - Phase 0: Architecture Identification and Documentation

---

## Database Systems Inventory

### Primary Database Systems

| Component | Version | Role | Configuration File | Connection String | Pool Configuration |
|-----------|---------|------|-------------------|-------------------|-------------------|
| **PostgreSQL** | 15-alpine | Primary Database | docker-compose.yml | `postgresql+asyncpg://violentutf:***@db:5432/violentutf` | Pool: 5, Overflow: 10 |
| **Redis** | 7-alpine | Cache/Broker | docker-compose.yml | `redis://:***@redis:6379/{0,1,2}` | Connection pooling |
| **SQLite** | aiosqlite | Testing/Dev | N/A | `sqlite+aiosqlite:///./test.db` | No pooling |

---

## PostgreSQL Configuration

### Connection Parameters

```yaml
# From app/core/config.py
Database Configuration:
  URL: "postgresql+asyncpg://violentutf:violentutf@db:5432/violentutf"
  Pool Size: 5 (configurable via DATABASE_POOL_SIZE)
  Max Overflow: 10 (configurable via DATABASE_MAX_OVERFLOW)
  Pool Timeout: 30 seconds
  Pool Recycle: 3600 seconds (1 hour)
  Pre-ping: Enabled
  Echo: Controlled by DEBUG setting
```

### Docker Configuration

```yaml
# From docker-compose.yml
Service: violentutf-db
Image: postgres:15-alpine
Environment:
  POSTGRES_USER: violentutf (configurable via DB_USER)
  POSTGRES_PASSWORD: violentutf (configurable via DB_PASSWORD)
  POSTGRES_DB: violentutf (configurable via DB_NAME)
  POSTGRES_INITDB_ARGS: "--encoding=UTF-8"
Volumes:
  - postgres_data:/var/lib/postgresql/data
  - ./backups/postgres:/backups
Health Check:
  Command: pg_isready -U violentutf
  Interval: 10s
  Timeout: 5s
  Retries: 5
```

### Performance Settings

| Parameter | Value | Purpose | Tunable |
|-----------|-------|---------|---------|
| **Pool Size** | 5 | Base connections | Yes (DATABASE_POOL_SIZE) |
| **Max Overflow** | 10 | Additional connections | Yes (DATABASE_MAX_OVERFLOW) |
| **Pool Timeout** | 30s | Connection wait time | No (hardcoded) |
| **Pool Recycle** | 3600s | Connection lifetime | No (hardcoded) |
| **Pre-ping** | True | Connection validation | No (hardcoded) |

---

## Redis Configuration

### Database Allocation

| Redis DB | Purpose | Used By | Configuration |
|----------|---------|---------|---------------|
| **DB 0** | Sessions & API Cache | API Service | `REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0` |
| **DB 1** | Celery Message Broker | Celery Worker, Flower | `CELERY_BROKER_URL=redis://:${REDIS_PASSWORD}@redis:6379/1` |
| **DB 2** | Celery Result Backend | Celery Worker, Flower | `CELERY_RESULT_BACKEND=redis://:${REDIS_PASSWORD}@redis:6379/2` |

### Docker Configuration

```yaml
# From docker-compose.yml
Service: violentutf-redis
Image: redis:7-alpine
Command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
Volumes:
  - redis_data:/data
Health Check:
  Command: redis-cli ping
  Interval: 10s
  Timeout: 5s
  Retries: 5
```

### Cache Manager Settings

```python
# From app/core/cache.py
Cache Configuration:
  Default TTL: 300 seconds (configurable via CACHE_TTL)
  Connection Timeout: 5 seconds
  Socket Timeout: 5 seconds
  Retry on Timeout: True
  Health Check Interval: 30 seconds
  Max Connection Failures: 3
  Connection Retry Delay: 30 seconds
  Fallback Cache Max Size: 10,000 entries
```

---

## SQLAlchemy Models Catalog

### Core Authentication Models (6 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **User** | users | User management | UserRole, APIKey, Session | Yes |
| **Role** | roles | RBAC roles | UserRole, Permission | Yes |
| **Permission** | permissions | Granular permissions | Role associations | Yes |
| **UserRole** | user_roles | User-role mapping | User, Role | Yes |
| **APIKey** | api_keys | API authentication | User | Yes |
| **Session** | sessions | Session management | User | Yes |

### Multi-Factor Authentication Models (4 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **MFADevice** | mfa_devices | MFA device registration | User, MFAChallenge | Yes |
| **MFABackupCode** | mfa_backup_codes | Backup authentication | User | Yes |
| **MFAChallenge** | mfa_challenges | Active MFA challenges | User, MFADevice | Yes |
| **MFAEvent** | mfa_events | MFA audit events | User | Yes |

### OAuth Integration Models (4 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **OAuthApplication** | oauth_applications | OAuth client apps | User, Tokens | Yes |
| **OAuthAccessToken** | oauth_access_tokens | Access tokens | OAuthApplication | Yes |
| **OAuthRefreshToken** | oauth_refresh_tokens | Refresh tokens | OAuthApplication | Yes |
| **OAuthAuthorizationCode** | oauth_authorization_codes | Auth codes | OAuthApplication | Yes |

### Security & Scanning Models (6 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **SecurityScan** | security_scans | Scan definitions | User, ScanFinding | Yes |
| **Scan** | scans | Scan execution | User, ScanReport | Yes |
| **ScanFinding** | scan_findings | Individual results | SecurityScan | Yes |
| **ScanReport** | scan_reports | Result reports | Scan | Yes |
| **VulnerabilityFinding** | vulnerability_findings | Vulnerability records | VulnerabilityTaxonomy | Yes |
| **VulnerabilityTaxonomy** | vulnerability_taxonomy | Vuln classification | VulnerabilityFinding | Yes |

### Task Management Models (6 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **Task** | tasks | Async task definitions | User, TaskResult | Yes |
| **TaskResult** | task_results | Task execution results | Task | Yes |
| **Plugin** | plugins | Plugin management | PluginExecution | Yes |
| **PluginConfiguration** | plugin_configurations | Plugin settings | Plugin | Yes |
| **PluginExecution** | plugin_executions | Plugin execution history | Plugin | Yes |
| **PluginRegistry** | plugin_registry | Plugin catalog | Plugin | Yes |

### Orchestration Models (4 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **OrchestratorConfiguration** | orchestrator_configurations | Orchestrator settings | OrchestratorExecution | Yes |
| **OrchestratorExecution** | orchestrator_executions | Execution tracking | OrchestratorConfiguration | Yes |
| **OrchestratorScore** | orchestrator_scores | Performance metrics | OrchestratorExecution | Yes |
| **OrchestratorTemplate** | orchestrator_templates | Execution templates | OrchestratorExecution | Yes |

### Reporting Models (3 models)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **Report** | reports | Report definitions | User, ReportTemplate | Yes |
| **ReportTemplate** | report_templates | Report templates | Report | Yes |
| **ReportSchedule** | report_schedules | Scheduled reporting | Report | Yes |

### Audit Model (1 model)

| Model | Table | Purpose | Key Relationships | Audit Enabled |
|-------|-------|---------|------------------|---------------|
| **AuditLog** | audit_logs | Comprehensive audit trail | User, All entities | N/A (is audit) |

---

## Repository Catalog

### Base Repository Classes

| Repository | File | Purpose | Generic Type |
|------------|------|---------|-------------|
| **BaseRepository** | `repositories/base.py` | Generic CRUD operations | `Generic[T]` |
| **EnhancedRepository** | `repositories/enhanced.py` | Advanced query capabilities | `BaseRepository` extension |

### Specialized Repositories (31+ repositories)

#### Authentication Repositories

| Repository | Model | File | Key Methods |
|------------|-------|------|-------------|
| **UserRepository** | User | `repositories/user.py` | `get_by_username`, `get_by_email`, `update_last_login` |
| **RoleRepository** | Role | `repositories/role.py` | `get_by_name`, `get_permissions`, `assign_permissions` |
| **APIKeyRepository** | APIKey | `repositories/api_key.py` | `get_by_key`, `validate_key`, `revoke_key` |
| **SessionRepository** | Session | `repositories/session.py` | `get_active_session`, `invalidate_user_sessions` |

#### MFA Repositories

| Repository | Model | File | Key Methods |
|------------|-------|------|-------------|
| **MFADeviceRepository** | MFADevice | `repositories/mfa_device.py` | `get_user_devices`, `register_device`, `verify_device` |
| **MFABackupCodeRepository** | MFABackupCode | `repositories/mfa_backup_code.py` | `generate_codes`, `validate_code`, `mark_used` |
| **MFAChallengeRepository** | MFAChallenge | `repositories/mfa_challenge.py` | `create_challenge`, `verify_challenge` |
| **MFAEventRepository** | MFAEvent | `repositories/mfa_event.py` | `log_event`, `get_user_events` |

#### OAuth Repositories

| Repository | Model | File | Key Methods |
|------------|-------|------|-------------|
| **OAuthApplicationRepository** | OAuthApplication | `repositories/oauth_application.py` | `get_by_client_id`, `validate_client` |
| **OAuthAccessTokenRepository** | OAuthAccessToken | `repositories/oauth_access_token.py` | `create_token`, `validate_token`, `revoke_token` |
| **OAuthRefreshTokenRepository** | OAuthRefreshToken | `repositories/oauth_refresh_token.py` | `create_refresh_token`, `exchange_token` |
| **OAuthAuthorizationCodeRepository** | OAuthAuthorizationCode | `repositories/oauth_authorization_code.py` | `create_code`, `exchange_code` |

#### Security Repositories

| Repository | Model | File | Key Methods |
|------------|-------|------|-------------|
| **SecurityScanRepository** | SecurityScan | `repositories/security_scan.py` | `get_by_user`, `update_status`, `get_statistics` |
| **ScanRepository** | Scan | `repositories/scan.py` | `get_active_scans`, `update_progress` |
| **VulnerabilityFindingRepository** | VulnerabilityFinding | `repositories/vulnerability_finding.py` | `get_by_severity`, `get_by_taxonomy` |
| **VulnerabilityTaxonomyRepository** | VulnerabilityTaxonomy | `repositories/vulnerability_taxonomy.py` | `get_by_category`, `search_taxonomy` |

#### System Repositories

| Repository | Model | File | Key Methods |
|------------|-------|------|-------------|
| **TaskRepository** | Task | `repositories/task.py` | `get_pending_tasks`, `update_status` |
| **PluginRepository** | Plugin | `repositories/plugin.py` | `get_available_plugins`, `enable_plugin` |
| **ReportRepository** | Report | `repositories/report.py` | `generate_report`, `schedule_report` |
| **AuditLogRepository** | AuditLog | `repositories/audit_log.py` | `create_audit_entry`, `search_by_criteria` |
| **HealthRepository** | N/A | `repositories/health.py` | `check_database_health`, `get_system_metrics` |

---

## Middleware Database Interactions

### Authentication & Authorization Middleware

| Middleware | Database Tables | Purpose | Repository Used |
|------------|-----------------|---------|-----------------|
| **Authentication** | users, api_keys, sessions | User authentication | UserRepository, APIKeyRepository, SessionRepository |
| **Permissions** | roles, permissions, user_roles | RBAC authorization | RoleRepository |
| **OAuth** | oauth_applications, oauth_access_tokens | OAuth flow management | OAuth repositories |
| **Session** | sessions | Session lifecycle | SessionRepository |

### Security & Monitoring Middleware

| Middleware | Database Tables | Purpose | Repository Used |
|------------|-----------------|---------|-----------------|
| **Audit** | audit_logs | Request/response logging | AuditLogRepository |
| **Rate Limiting** | Redis DB 0 | Request rate tracking | Cache directly |
| **Idempotency** | Redis DB 0 | Duplicate prevention | Cache directly |
| **CSRF** | Redis DB 0 | CSRF token storage | Cache directly |

### Performance & Caching Middleware

| Middleware | Database Tables | Purpose | Repository Used |
|------------|-----------------|---------|-----------------|
| **Response Cache** | Redis DB 0 | Response caching | Cache directly |
| **Body Cache** | Redis DB 0 | Request body caching | Cache directly |

---

## Alembic Migration Catalog

### Migration History

| Migration File | Revision | Description | Tables Affected | Date |
|----------------|----------|-------------|-----------------|------|
| `0d9d1d5fbe10_initial_database_models_with_*.py` | 0d9d1d5fbe10 | Initial schema creation | All core tables | 2025-08-30 |
| `41eb10f48a60_add_last_login_at_and_last_login_ip_*.py` | 41eb10f48a60 | User login tracking | users | 2025-08-30 |
| `add_async_task_management_models.py` | N/A | Task management system | tasks, task_results, plugins | 2025-08-30 |
| `add_roles_field_rbac.py` | N/A | RBAC enhancements | roles, permissions | 2025-07-28 |
| `add_vulnerability_management_tables.py` | N/A | Vulnerability tracking | vulnerability_findings, vulnerability_taxonomy | 2025-08-30 |

### Migration Commands

```bash
# Check current migration status
alembic current

# View migration history
alembic history --verbose

# Upgrade to latest
alembic upgrade head

# Generate new migration
alembic revision --autogenerate -m "description"

# Downgrade to specific revision
alembic downgrade <revision>
```

---

## Connection Pool Configuration

### Repository-Specific Pool Sizes

```python
# From app/core/config.py
Repository Pool Configurations:
  USER_POOL_SIZE: 5 (default)
  API_KEY_POOL_SIZE: 3
  SESSION_POOL_SIZE: 10
  AUDIT_POOL_SIZE: 8
  SECURITY_SCAN_POOL_SIZE: 5
  VULNERABILITY_POOL_SIZE: 3
  ROLE_POOL_SIZE: 2
  HEALTH_POOL_SIZE: 2
```

### Timeout Configurations

```python
Repository Timeout Settings:
  CONNECTION_TIMEOUT: 30 seconds
  QUERY_TIMEOUT: 60 seconds
  HEALTH_CHECK_TIMEOUT: 10 seconds
```

### Retry Policies

```python
Repository Retry Configuration:
  MAX_RETRIES: 3
  RETRY_DELAY_BASE: 1.0 seconds
  RETRY_DELAY_MAX: 30.0 seconds
  EXPONENTIAL_BACKOFF: True
```

---

## Health Check Configuration

### Database Health Checks

| Component | Check Type | Interval | Timeout | Command |
|-----------|------------|----------|---------|---------|
| **PostgreSQL** | SQL Query | 10s | 5s | `pg_isready -U violentutf` |
| **Redis** | Ping Command | 10s | 5s | `redis-cli ping` |
| **API Health** | HTTP Endpoint | 30s | 10s | `curl -f http://localhost:8000/api/v1/health` |

### Circuit Breaker Configuration

```python
# From app/db/session.py
Circuit Breaker Settings:
  Name: "database_operations"
  Failure Threshold: 5
  Recovery Timeout: 30.0 seconds
  State Monitoring: Enabled
```

---

## Backup and Recovery Configuration

### PostgreSQL Backups

```yaml
Backup Configuration:
  Type: Docker volume mount
  Location: ./backups/postgres
  Frequency: Manual (no automated backups configured)
  Retention: Not specified
  Recovery: Manual restore from backup files
```

### Redis Persistence

```yaml
Redis Persistence:
  Type: AOF (Append Only File)
  Configuration: --appendonly yes
  Volume: redis_data
  Persistence: All write operations logged
```

---

## Performance Monitoring

### Available Metrics

| Metric Category | Source | Method | Purpose |
|-----------------|--------|--------|---------|
| **Connection Pool** | SQLAlchemy Engine | `get_connection_pool_stats()` | Pool utilization monitoring |
| **Cache Performance** | Cache Manager | `health_check()` | Cache hit/miss rates |
| **Circuit Breaker** | Circuit Breaker | State monitoring | Failure tracking |
| **Health Checks** | Health endpoints | HTTP status | Service availability |

### Pool Statistics Available

```python
Pool Statistics:
  pool_size: Number of base connections
  checked_in: Available connections
  checked_out: Active connections
  overflow: Additional connections
  invalid: Failed connections
  total: Total connections
  usage_percent: Pool utilization percentage
```

---

## Configuration Management

### Environment Variables

| Variable | Default | Purpose | Required |
|----------|---------|---------|----------|
| `DATABASE_URL` | None | PostgreSQL connection | Yes |
| `REDIS_URL` | None | Redis connection | Yes |
| `DATABASE_POOL_SIZE` | 5 | Base pool size | No |
| `DATABASE_MAX_OVERFLOW` | 10 | Additional connections | No |
| `CACHE_TTL` | 300 | Default cache TTL | No |

### Security Configuration

```python
Security Settings:
  Password Hashing: bcrypt with 12 rounds
  Session Security: Secure cookies enabled
  Connection Security: SSL/TLS configurable
  Credential Masking: Automatic in logs
  Secret Management: Environment variables only
```

---

## Summary

This comprehensive catalog documents:

- **3 database systems** with detailed configurations
- **35+ SQLAlchemy models** with relationships
- **31+ repository classes** with specialized methods
- **18 middleware layers** with database interactions
- **5 Alembic migrations** with change history
- **Comprehensive monitoring** and health check systems
- **Detailed configuration** for all components

The catalog serves as a complete reference for database architecture understanding and provides the foundation for subsequent audit phases.

---

*This catalog provides detailed technical specifications for all database components in the ViolentUTF API system.*
