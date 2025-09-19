# Database Audit Phase 1: Discovery & Inventory Plan
## ViolentUTF API - September 2025

---

## YAML Metadata
```yaml
schema_version: "1.0"
issue_type: "database_audit"
phase: "1_discovery_and_inventory"
status: "planning"
priority: "high"
created_date: "2025-09-19"
estimated_completion: "2025-10-03"
task_description: "Build comprehensive inventory of all ViolentUTF API data assets with automated discovery"
technical_requirements:
  - Automated asset discovery scripts
  - Living inventory registry system
  - Risk assessment integration
  - Gap identification mechanisms
affected_systems:
  - PostgreSQL (primary database)
  - Redis (caching/sessions)
  - SQLite (testing/development)
  - File storage systems
  - 31 repository implementations
  - 21 database models
  - 24 API endpoints
  - 16+ middleware components
required_permissions:
  - Database read access
  - Configuration file access
  - Code repository analysis access
  - Docker service introspection
completion_criteria:
  - Complete asset inventory registry
  - Automated discovery tools implemented
  - Risk assessment framework established
  - Gap identification completed
  - Living documentation system operational
```

---

## 🎯 **Objective**
Build and maintain a comprehensive, automated inventory of all ViolentUTF API data assets, leveraging existing repository patterns, configuration systems, and analysis tools to identify gaps, assess risks, and establish continuous monitoring.

---

## 📋 **Implementation Phases**

### **Phase 1.1: Existing Asset Documentation Review** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **Inventory Current Documentation**
  - [ ] Analyze existing `/docs/` directory for asset documentation
  - [ ] Review migration history in `/alembic/versions/` (5 migration files)
  - [ ] Extract asset information from Docker Compose configurations
  - [ ] Document existing monitoring and health check capabilities

- [ ] **Catalog Repository Pattern Implementation**
  - [ ] Map all 31 repositories in `/app/repositories/` to their data models
  - [ ] Document repository inheritance from BaseRepository
  - [ ] Identify common CRUD patterns and specialized operations
  - [ ] Map repository-to-API endpoint relationships

- [ ] **Configuration Asset Discovery**
  - [ ] Extract data store configurations from `/app/core/config.py` Settings class
  - [ ] Document connection parameters, pool sizes, and timeouts
  - [ ] Map environment-specific configurations
  - [ ] Identify security-related configuration assets

#### 📊 **Completion Criteria:**
- Existing asset documentation summary created
- Repository pattern mapping completed
- Configuration asset baseline established

---

### **Phase 1.2: Automated Discovery Tool Development** ⏱️ *4-5 days*

#### ✅ **Tasks:**
- [ ] **Database Schema Discovery Tool**
  ```python
  # Leverage existing SQLAlchemy models and database introspection
  python3 tools/inventory/schema_discovery.py
  ```
  - [ ] Use existing 21 models in `/app/models/` for schema mapping
  - [ ] Introspect PostgreSQL database using existing session management
  - [ ] Document table relationships, indexes, and constraints
  - [ ] Map foreign key relationships and cascade behaviors

- [ ] **Repository Usage Analysis Tool**
  ```python
  # Analyze repository patterns for data access mapping
  python3 tools/inventory/repository_analyzer.py
  ```
  - [ ] Parse all 31 repositories for CRUD operation patterns
  - [ ] Map repository method usage across API endpoints
  - [ ] Document transaction patterns and connection usage
  - [ ] Identify repository-specific configurations and optimizations

- [ ] **API Data Flow Discovery Tool**
  ```python
  # Map API endpoints to database operations
  python3 tools/inventory/api_flow_analyzer.py
  ```
  - [ ] Analyze 24 API endpoint files for database interactions
  - [ ] Map HTTP operations to repository method calls
  - [ ] Document middleware data interactions (16+ middleware layers)
  - [ ] Identify background task data operations (Celery workers)

- [ ] **Configuration Discovery Tool**
  ```python
  # Automated configuration asset discovery
  python3 tools/inventory/config_discovery.py
  ```
  - [ ] Extract all database-related configurations from Settings class
  - [ ] Parse Docker Compose service definitions
  - [ ] Map environment variable dependencies
  - [ ] Document connection pool and circuit breaker configurations

#### 📊 **Completion Criteria:**
- 4 automated discovery tools implemented and tested
- Tools integrate with existing codebase infrastructure
- Discovery output in structured format (JSON/YAML)

---

### **Phase 1.3: Physical Data Store Inventory** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **PostgreSQL Database Inventory**
  ```python
  # Using existing database session management
  from app.db.session import get_db, check_database_health
  ```
  - [ ] Catalog all tables using SQLAlchemy metadata introspection
  - [ ] Document indexes, constraints, and triggers
  - [ ] Map table relationships and foreign key dependencies
  - [ ] Record table sizes, row counts, and growth patterns

- [ ] **Redis Cache Inventory**
  ```python
  # Using existing Redis configuration
  from app.core.config import settings  # REDIS_URL configuration
  ```
  - [ ] Document Redis key patterns for sessions, caching, and Celery
  - [ ] Map cache TTL configurations and usage patterns
  - [ ] Inventory Redis databases (0: cache, 1: Celery broker, 2: results)
  - [ ] Document persistence and backup configurations

- [ ] **SQLite Development Database Inventory**
  - [ ] Catalog test database configurations in testing environment
  - [ ] Document development database schemas and test data
  - [ ] Map testing-specific database configurations
  - [ ] Identify test database lifecycle patterns

- [ ] **File Storage Inventory**
  - [ ] Document log file storage patterns (`./logs` volume mount)
  - [ ] Catalog backup storage (`./backups/postgres` volume mount)
  - [ ] Map configuration file storage locations
  - [ ] Identify temporary and cache file storage

#### 📊 **Completion Criteria:**
- Complete physical data store catalog
- Storage capacity and usage documentation
- Backup and recovery strategy documentation

---

### **Phase 1.4: Logical Data Asset Inventory** ⏱️ *3-4 days*

#### ✅ **Tasks:**
- [ ] **Database Schema Asset Inventory**
  - [ ] Document all tables from 21 SQLAlchemy models:
    - [ ] User management (User, Role, Permission models)
    - [ ] API security (APIKey, Session models)
    - [ ] MFA system (MFA Policy, Device, Challenge, Backup Code, Event models)
    - [ ] OAuth system (Application, Access Token, Refresh Token, Authorization Code, Scope models)
    - [ ] Security scanning (Vulnerability Taxonomy, Finding, Security Scan models)
    - [ ] Audit system (Audit Log model)
    - [ ] Task management (Task, Orchestrator models)
    - [ ] Plugin system (Plugin model)

- [ ] **Data Relationship Mapping**
  - [ ] Document foreign key relationships between models
  - [ ] Map one-to-many and many-to-many relationships
  - [ ] Identify circular dependencies and cascade behaviors
  - [ ] Document polymorphic relationships and inheritance

- [ ] **Index and Performance Asset Inventory**
  - [ ] Document all database indexes (primary, unique, composite)
  - [ ] Map query performance optimization assets
  - [ ] Identify missing indexes for common query patterns
  - [ ] Document database-level performance configurations

- [ ] **Data Lifecycle Asset Inventory**
  - [ ] Map data creation patterns through repository methods
  - [ ] Document update and deletion workflows
  - [ ] Identify soft delete vs hard delete patterns
  - [ ] Map data archival and retention policies

#### 📊 **Completion Criteria:**
- Complete logical asset catalog with relationships
- Data lifecycle documentation
- Performance optimization asset inventory

---

### **Phase 1.5: Access Pattern and Security Asset Inventory** ⏱️ *3-4 days*

#### ✅ **Tasks:**
- [ ] **Repository Access Pattern Analysis**
  - [ ] Map 31 repositories to their usage patterns:
    - [ ] UserRepository → Authentication, user management
    - [ ] APIKeyRepository → API authentication
    - [ ] SessionRepository → Session management
    - [ ] AuditLogRepository → Security auditing
    - [ ] SecurityScanRepository → Vulnerability management
    - [ ] MFA repositories (5 types) → Multi-factor authentication
    - [ ] OAuth repositories (5 types) → External authentication
    - [ ] Vulnerability repositories (2 types) → Security scanning

- [ ] **API Endpoint Data Access Inventory**
  - [ ] Map 24 API endpoint files to repository usage
  - [ ] Document HTTP method to database operation mappings
  - [ ] Identify read-heavy vs write-heavy endpoints
  - [ ] Map endpoint-specific authorization requirements

- [ ] **Middleware Data Interaction Inventory**
  - [ ] Document data interactions in 16+ middleware layers:
    - [ ] Authentication middleware → User and session data
    - [ ] Authorization middleware → Role and permission data
    - [ ] Audit middleware → Audit log data
    - [ ] Session middleware → Session storage
    - [ ] CSRF middleware → Token storage
    - [ ] Rate limiting middleware → Rate limit data

- [ ] **Security Asset Inventory**
  - [ ] User and Role Management Assets:
    - [ ] User accounts and authentication data
    - [ ] Role-based access control (RBAC) configurations
    - [ ] Permission assignments and inheritance
  - [ ] API Security Assets:
    - [ ] API key lifecycle and usage tracking
    - [ ] OAuth token management (access, refresh, authorization codes)
    - [ ] JWT token configurations and signing keys
  - [ ] MFA Security Assets:
    - [ ] MFA device registrations and configurations
    - [ ] Backup codes and recovery mechanisms
    - [ ] Challenge-response data and event logs
  - [ ] Audit and Monitoring Assets:
    - [ ] Comprehensive audit log data
    - [ ] Security event tracking
    - [ ] Session monitoring and analysis

#### 📊 **Completion Criteria:**
- Complete access pattern documentation
- Security asset catalog with lifecycle tracking
- Authorization and authentication asset mapping

---

### **Phase 1.6: Gap Identification and Risk Assessment** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **Asset Documentation Gap Analysis**
  - [ ] Compare discovered assets with existing documentation
  - [ ] Identify undocumented databases, tables, or configurations
  - [ ] Flag orphaned resources not referenced in code
  - [ ] Document assets missing proper ownership

- [ ] **Security Gap Assessment**
  - [ ] Identify assets without proper access controls
  - [ ] Flag databases without backup strategies
  - [ ] Document assets missing audit logging
  - [ ] Identify configuration drift from security standards

- [ ] **Compliance Gap Analysis**
  - [ ] Map assets to regulatory requirements (if applicable)
  - [ ] Identify data retention policy gaps
  - [ ] Document missing encryption configurations
  - [ ] Flag assets without proper monitoring

- [ ] **Operational Gap Assessment**
  - [ ] Identify assets without monitoring/alerting
  - [ ] Flag databases without performance optimization
  - [ ] Document missing disaster recovery procedures
  - [ ] Identify capacity planning gaps

#### 📊 **Completion Criteria:**
- Comprehensive gap analysis report
- Risk-prioritized remediation recommendations
- Security and compliance assessment

---

## 🛠️ **Tools and Implementation Strategy**

### **Existing Tool Leverage (Reuse Principle)**

#### **1. Database Infrastructure Tools**
```python
# Leverage existing session management
from app.db.session import (
    get_connection_pool_stats,
    check_database_health,
    get_db,
    validate_database_connection
)

# Use existing configuration system
from app.core.config import settings
database_config = settings.get_database_config()
redis_config = settings.get_redis_config()
```

#### **2. Repository Pattern Analysis**
```python
# Leverage existing repository implementations
from app.repositories import *  # All 31 repositories
from app.repositories.base import BaseRepository, Page

# Analyze common patterns
def analyze_repository_patterns():
    # Map CRUD operations across repositories
    # Document pagination and query patterns
    # Identify transaction management patterns
```

#### **3. Model Introspection**
```python
# Use existing SQLAlchemy models
from app.models import *  # All 21 models
from app.db.base import Base

# Schema introspection
def introspect_database_schema():
    # Use SQLAlchemy metadata for schema discovery
    # Map model relationships automatically
    # Extract constraints and indexes
```

#### **4. Configuration Analysis**
```python
# Leverage existing configuration validation
from app.core.config import Settings, get_settings

def analyze_configuration_assets():
    config = get_settings()
    validation_result = config.validate_configuration()
    # Extract data store configurations
    # Map security settings
    # Document environment variations
```

### **New Discovery Tools (Minimal Development)**

#### **1. Schema Discovery Tool**
```bash
# tools/inventory/schema_discovery.py
python3 -c "
import asyncio
from app.db.session import get_db
from app.db.base import Base
from sqlalchemy import inspect

async def discover_schema():
    async with get_db() as db:
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()
        # Generate comprehensive schema inventory
"
```

#### **2. Repository Usage Analyzer**
```bash
# tools/inventory/repository_analyzer.py
# Static code analysis of repository usage patterns
find app/api/endpoints -name "*.py" -exec grep -l "Repository" {} \;
# Map endpoint-to-repository relationships
```

#### **3. Configuration Discovery Tool**
```bash
# tools/inventory/config_discovery.py
python3 -c "
from app.core.config import settings
import json

config_inventory = {
    'database': settings.get_database_config(),
    'redis': settings.get_redis_config(),
    'security': settings.get_security_config(),
    'repository': settings.get_repository_config()
}
print(json.dumps(config_inventory, indent=2))
"
```

#### **4. Integration with Existing Pre-Audit Tools**
```python
# Leverage tools/pre_audit/ infrastructure
from tools.pre_audit.cache_manager import CacheManager
from tools.pre_audit.smart_analyzer import SmartAnalyzer
from tools.pre_audit.pattern_analyzer import PatternAnalyzer

# Use existing caching for performance
cache = CacheManager()
# Use existing pattern analysis for discovery
analyzer = PatternAnalyzer()
```

---

## 📊 **Inventory Data Structure**

### **Master Inventory Registry**
```yaml
# docs/inventory/master_inventory.yml
database_audit_inventory:
  metadata:
    version: "1.0"
    last_updated: "2025-09-19T10:00:00Z"
    discovery_tools_version: "1.0"

  physical_stores:
    postgresql_primary:
      id: "postgresql_primary"
      type: "postgresql"
      purpose: "primary_transactional"
      connection_url: "[MASKED]"
      configuration:
        pool_size: 5
        max_overflow: 10
        pool_timeout: 30
      health_status:
        available: true
        last_check: "2025-09-19T10:00:00Z"
        circuit_breaker_state: "closed"
      backup_strategy:
        type: "docker_volume"
        location: "./backups/postgres"
        frequency: "continuous"
        retention: "30_days"

    redis_cache:
      id: "redis_cache"
      type: "redis"
      purpose: "caching_sessions_celery"
      configuration:
        databases:
          0: "general_cache"
          1: "celery_broker"
          2: "celery_results"
      health_status:
        available: true
        persistence_enabled: true

  logical_assets:
    user_management:
      tables:
        - name: "users"
          model: "User"
          repository: "UserRepository"
          primary_key: "id"
          relationships:
            - target: "roles"
              type: "many_to_many"
            - target: "sessions"
              type: "one_to_many"
        - name: "roles"
          model: "Role"
          repository: "RoleRepository"

    api_security:
      tables:
        - name: "api_keys"
          model: "APIKey"
          repository: "APIKeyRepository"
          sensitive_data: true

  access_patterns:
    api_endpoints:
      - endpoint: "/api/v1/auth/login"
        methods: ["POST"]
        repositories: ["UserRepository", "SessionRepository"]
        data_operations: ["create_session", "validate_user"]

    repositories:
      - name: "UserRepository"
        model: "User"
        operations: ["create", "read", "update", "delete"]
        specializations: ["authenticate", "update_last_login"]

  security_assets:
    authentication:
      - type: "jwt_tokens"
        configuration:
          algorithm: "HS256"
          expiration: "30_minutes"
      - type: "sessions"
        storage: "database"
        expiration: "24_hours"

    authorization:
      - type: "rbac"
        implementation: "role_based"
        models: ["User", "Role", "Permission"]

  risk_assessment:
    high_risk_assets:
      - asset: "api_keys_table"
        risk_factors: ["sensitive_data", "external_access"]
        mitigation: ["encryption_at_rest", "access_logging"]

    gaps_identified:
      - type: "documentation_gap"
        description: "Missing backup verification procedures"
        priority: "high"
      - type: "security_gap"
        description: "API keys not rotated automatically"
        priority: "medium"
```

---

## 🔄 **Living Inventory Management**

### **Automated Update Mechanisms**

#### **1. Git Hook Integration**
```bash
# .git/hooks/post-commit
#!/bin/bash
# Trigger inventory update on schema changes
if git diff --name-only HEAD~1 | grep -E "(alembic/|app/models/|app/repositories/)"; then
    python3 tools/inventory/update_inventory.py --incremental
fi
```

#### **2. CI/CD Pipeline Integration**
```yaml
# .github/workflows/inventory-update.yml
name: Update Database Inventory
on:
  push:
    paths:
      - 'app/models/**'
      - 'app/repositories/**'
      - 'alembic/versions/**'
      - 'docker-compose.yml'

jobs:
  update_inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Update inventory
        run: python3 tools/inventory/update_inventory.py --full
      - name: Commit inventory updates
        run: |
          git add docs/inventory/
          git commit -m "chore: Update database inventory [automated]"
```

#### **3. Scheduled Discovery**
```python
# tools/inventory/scheduled_discovery.py
import schedule
import time
from datetime import datetime

def daily_inventory_update():
    """Daily inventory update for dynamic assets"""
    print(f"Starting daily inventory update: {datetime.now()}")

    # Update connection pool statistics
    update_connection_metrics()

    # Update health check status
    update_health_status()

    # Update usage patterns
    update_access_patterns()

    # Generate daily inventory report
    generate_daily_report()

# Schedule daily updates
schedule.every().day.at("02:00").do(daily_inventory_update)
```

### **Inventory Validation and Quality Control**

#### **1. Schema Validation**
```python
# tools/inventory/validate_inventory.py
import jsonschema
import yaml

def validate_inventory_schema():
    """Validate inventory against defined schema"""
    with open('docs/inventory/schema.json') as f:
        schema = json.load(f)

    with open('docs/inventory/master_inventory.yml') as f:
        inventory = yaml.safe_load(f)

    jsonschema.validate(inventory, schema)
    print("✓ Inventory schema validation passed")
```

#### **2. Consistency Checks**
```python
# Cross-reference inventory with actual system state
def verify_inventory_consistency():
    """Verify inventory matches actual system state"""

    # Check database connectivity
    verify_database_connections()

    # Verify model-table mappings
    verify_model_mappings()

    # Check repository implementations
    verify_repository_patterns()

    # Validate configuration consistency
    verify_configuration_state()
```

---

## ⚠️ **Risk Mitigation and Quality Assurance**

### **Non-Intrusive Discovery Approach**
- **Read-Only Operations**: All discovery tools use read-only database access
- **Existing Tool Leverage**: Maximum reuse of proven codebase infrastructure
- **Incremental Discovery**: Avoid overwhelming system with full scans
- **Circuit Breaker Respect**: Honor existing circuit breaker patterns

### **Error Handling and Resilience**
```python
# Robust discovery with fallback mechanisms
async def resilient_discovery():
    try:
        # Primary discovery method using live database
        await discover_from_live_database()
    except DatabaseConnectionError:
        # Fallback to static analysis
        await discover_from_code_analysis()
    except CircuitBreakerException:
        # Respect circuit breaker, use cached data
        await load_from_cache()
    finally:
        # Always attempt to save partial results
        await save_partial_inventory()
```

### **Security and Privacy Protection**
- **Credential Masking**: All connection strings and secrets masked in inventory
- **Access Control**: Inventory tools respect existing RBAC patterns
- **Audit Logging**: All discovery operations logged through existing audit system
- **Data Minimization**: Only collect metadata, not actual data content

---

## 📈 **Success Metrics and Validation**

### **Quantitative Metrics**
- **Asset Coverage**: 100% of identifiable database assets cataloged
- **Discovery Accuracy**: >95% accuracy in automated asset identification
- **Update Timeliness**: Inventory updates within 24 hours of changes
- **Tool Reliability**: >99% success rate in discovery tool execution

### **Qualitative Metrics**
- **Gap Identification**: All significant documentation and security gaps identified
- **Risk Assessment**: Comprehensive risk scoring for all assets
- **Stakeholder Validation**: Inventory validated by development and operations teams
- **Integration Quality**: Seamless integration with existing development workflow

### **Validation Procedures**
1. **Cross-Reference Validation**: Compare inventory with running system state
2. **Code Review**: Validate discovery tools follow existing code patterns
3. **Security Review**: Ensure inventory collection respects security boundaries
4. **Performance Impact**: Monitor system performance during discovery operations

---

## 🚀 **Integration with Subsequent Phases**

### **Phase 2 Preparation (Dependency Mapping)**
- **Relationship Data**: Comprehensive relationship mapping for dependency analysis
- **Access Pattern Data**: Detailed access patterns for interaction mapping
- **Performance Data**: Baseline metrics for performance dependency analysis

### **Phase 3 Preparation (Configuration Review)**
- **Configuration Baseline**: Complete configuration state for drift detection
- **Environment Mapping**: Multi-environment configuration comparison data
- **Change Tracking**: Foundation for configuration change monitoring

### **Continuous Improvement Foundation**
- **Living Documentation**: Self-maintaining inventory system
- **Automated Monitoring**: Foundation for continuous asset monitoring
- **Risk Management**: Ongoing risk assessment and gap detection capabilities

---

## 📝 **Implementation Timeline and Dependencies**

### **Week 1: Foundation (Phases 1.1-1.2)**
- Days 1-3: Existing asset documentation review
- Days 4-7: Automated discovery tool development

### **Week 2: Core Inventory (Phases 1.3-1.4)**
- Days 1-3: Physical data store inventory
- Days 4-7: Logical data asset inventory

### **Week 3: Analysis and Documentation (Phases 1.5-1.6)**
- Days 1-4: Access pattern and security asset inventory
- Days 5-7: Gap identification and risk assessment

### **Dependencies**
- **Access Requirements**: Database read access, configuration file access
- **Tool Dependencies**: Existing pre-audit tools, repository patterns, configuration system
- **Team Dependencies**: Development team validation, security team review

---

*This comprehensive Phase 1 plan leverages the robust existing infrastructure of the ViolentUTF API while implementing automated, maintainable inventory management that will serve as the foundation for all subsequent database audit phases.*
