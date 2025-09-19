# Database Audit Phase 0: Architecture Identification Plan
## ViolentUTF API - September 2025

---

## YAML Metadata
```yaml
schema_version: "1.0"
issue_type: "database_audit"
phase: "0_architecture_identification"
status: "planning"
priority: "high"
created_date: "2025-09-19"
estimated_completion: "2025-09-26"
task_description: "Systematically identify and document ViolentUTF API database architecture"
technical_requirements:
  - Database architecture mapping
  - Component interaction analysis
  - Data flow documentation
  - Integration point identification
affected_systems:
  - PostgreSQL (primary database via DATABASE_URL)
  - Redis (caching/sessions via REDIS_URL)
  - SQLite (testing/development fallback)
  - Alembic migrations (/alembic/versions/)
  - SQLAlchemy ORM (/app/models/)
required_permissions:
  - Database read access
  - Configuration file access
  - Migration history review
completion_criteria:
  - Architecture diagrams created
  - Component catalog completed
  - Data flow maps documented
  - Integration points identified
```

---

## 🎯 **Objective**
Capture an accurate, up-to-date blueprint of the ViolentUTF API database architecture, leveraging existing codebase tools and infrastructure to establish a foundation for comprehensive database auditing.

---

## 📋 **Implementation Phases**

### **Phase 0.1: Existing Documentation Analysis** ⏱️ *1-2 days*

#### ✅ **Tasks:**
- [ ] **Review Existing Architecture Documents**
  - [ ] Analyze `/docs/` directory (found `/docs/security/`, `/docs/planning/`)
  - [ ] Review existing audit documentation in `/docs/audits/audit_ADRgeneral.md`
  - [ ] Study planning documents in `/docs/planning/`
  - [ ] Extract insights from `/docs/security/` (SECURITY_NOTES.md, configuration-guide.md)

- [ ] **Examine Codebase Documentation**
  - [ ] Parse README.md and CLAUDE.md for architectural patterns
  - [ ] Review Docker Compose configuration (`docker-compose.yml`, `docker-compose.test.yml`)
  - [ ] Study FastAPI application structure in `/app/main.py`
  - [ ] Analyze existing tools in `/tools/` directory

#### 📊 **Completion Criteria:**
- Architecture documentation summary created
- Existing knowledge gaps identified
- Available tools catalog documented

---

### **Phase 0.2: Database Component Discovery** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **Database Infrastructure Mapping**
  - [ ] Document PostgreSQL configuration from `app.core.config.Settings`
  - [ ] Map Redis usage (caching, sessions, Celery broker/result backend)
  - [ ] Identify SQLite usage (testing, development fallback)
  - [ ] Catalog connection pool settings from `DATABASE_POOL_SIZE`, `DATABASE_MAX_OVERFLOW`

- [ ] **ORM and Migration Analysis**
  - [ ] Inventory SQLAlchemy models: `find app/models -name "*.py" -exec grep -l "class.*Base" {} \;`
  - [ ] Document Alembic migration history: `alembic history --verbose`
  - [ ] Map database schema from existing models (user.py, api_key.py, scan.py, etc.)
  - [ ] Identify custom database types in `/app/db/types.py`

- [ ] **Data Store Analysis** (Using existing tools)
  - [ ] Run connection pool analysis: `python3 -c "from app.db.session import get_connection_pool_stats; print(get_connection_pool_stats())"`
  - [ ] Test database health check: `python3 -c "import asyncio; from app.db.session import check_database_health; print(asyncio.run(check_database_health()))"`
  - [ ] Document circuit breaker patterns in `/app/db/session.py`
  - [ ] Map database session management and connection pooling

#### 📊 **Completion Criteria:**
- Complete database component inventory
- Connection architecture documented
- Schema versioning mapped

---

### **Phase 0.3: Service Integration Mapping** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **Microservice Architecture Analysis**
  - [ ] Map Docker Compose service dependencies (api, db, redis, celery-worker, flower, nginx)
  - [ ] Document API service database interactions via `/app/main.py`
  - [ ] Identify Celery worker database usage patterns
  - [ ] Map Flower monitoring integration

- [ ] **Middleware Database Interactions**
  - [ ] Analyze session middleware database usage (`/app/middleware/session.py`)
  - [ ] Document audit middleware data persistence (`/app/middleware/audit.py`)
  - [ ] Map authentication/authorization database patterns (`/app/middleware/authentication.py`)
  - [ ] Identify caching layers in middleware stack

- [ ] **API Endpoint Database Mapping** (Reuse existing tools)
  - [ ] Document endpoints via running API: `curl http://localhost:8000/api/v1/docs`
  - [ ] Use existing health check: `curl http://localhost:8000/api/v1/health`
  - [ ] Map repository patterns from `/app/api/deps.py`
  - [ ] Analyze endpoint-specific database operations

#### 📊 **Completion Criteria:**
- Service dependency matrix completed
- Database interaction patterns documented
- Middleware database touchpoints mapped

---

### **Phase 0.4: External Integration Assessment** ⏱️ *1-2 days*

#### ✅ **Tasks:**
- [ ] **Third-Party Database Integrations**
  - [ ] Review external database connections (none currently identified)
  - [ ] Map backup strategies from Docker volumes (`postgres_data`, `redis_data`)
  - [ ] Identify external API data persistence patterns
  - [ ] Document existing backup locations (`./backups/postgres`)

- [ ] **Security Integration Points**
  - [ ] Map JWT token storage and validation patterns
  - [ ] Document CSRF protection database dependencies
  - [ ] Analyze request signing database requirements (configurable via `REQUEST_SIGNING_ENABLED`)
  - [ ] Review MFA implementation database patterns (`/app/models/mfa.py`)

#### 📊 **Completion Criteria:**
- External integration inventory completed
- Security database touchpoints documented

---

### **Phase 0.5: Architecture Documentation & Visualization** ⏱️ *2-3 days*

#### ✅ **Tasks:**
- [ ] **Create Architecture Diagrams** (Leveraging existing structure)
  - [ ] Generate component diagram from Docker Compose services
  - [ ] Create data flow diagrams based on middleware stack
  - [ ] Document deployment architecture from existing Docker setup
  - [ ] Build dependency graph using existing FastAPI routing

- [ ] **Data Store Catalog Creation**
  - [ ] Compile comprehensive database inventory table
  - [ ] Document configuration patterns from `/app/core/config.py`
  - [ ] Map backup strategies and retention policies
  - [ ] Create performance baseline from existing monitoring

- [ ] **Risk Assessment Matrix**
  - [ ] Identify single points of failure
  - [ ] Document data sensitivity from model definitions
  - [ ] Map compliance touchpoints
  - [ ] Assess disaster recovery capabilities

#### 📊 **Completion Criteria:**
- Architecture diagrams completed and validated
- Database catalog published
- Risk assessment documented

---

## 🛠️ **Tools and Methods**

### **Existing Codebase Tools (Reuse Principle)**
- **Database Session Management**: `/app/db/session.py` (get_connection_pool_stats, check_database_health)
- **Configuration Management**: `/app/core/config.py` (Settings class with validation)
- **Health Checks**: Existing health endpoints and database connectivity tests
- **Circuit Breaker**: Built-in circuit breaker in session management
- **Repository Patterns**: Existing dependency injection in `/app/api/deps.py`

### **Documentation Tools**
- **FastAPI Documentation**: Auto-generated at `/api/v1/docs`
- **Docker Compose**: Service architecture in `docker-compose.yml`
- **Alembic**: Migration tracking with `alembic history`
- **Existing Analysis Tools**: `/tools/pre_audit/` directory

### **Analysis Scripts** (Verified working)
```bash
# Database connection analysis (using existing tools)
python3 -c "
import sys
sys.path.append('.')
from app.db.session import get_connection_pool_stats, check_database_health
import asyncio
print('Pool Stats:', get_connection_pool_stats())
print('Health Check:', asyncio.run(check_database_health()))
"

# Model discovery (using existing structure)
find app/models -name "*.py" -exec basename {} .py \; | grep -v __

# Migration analysis (using existing Alembic)
alembic history --verbose

# Configuration analysis (using existing settings)
python3 -c "
from app.core.config import settings
print('Database configured:', bool(settings.DATABASE_URL))
print('Redis configured:', bool(settings.REDIS_URL))
print('Pool size:', settings.DATABASE_POOL_SIZE)
"
```

---

## 📊 **Expected Artifacts**

1. **System Architecture Diagrams**
   - Component interaction diagram (API → DB, Redis, Celery)
   - Data flow visualization (Middleware → Repository → Database)
   - Deployment architecture map (Docker Compose services)
   - Database entity relationship diagram (from SQLAlchemy models)

2. **Database Component Catalog**
   ```markdown
   | Database | Type | Purpose | Connection Pool | Health Check | Backup Strategy |
   |----------|------|---------|----------------|--------------|-----------------|
   | PostgreSQL | Primary | Transactional data | 5 (configurable) | Built-in | Docker volume |
   | Redis | Cache | Sessions/Cache/Celery | Connection pool | Built-in | Data persistence |
   | SQLite | Development | Testing fallback | N/A | File check | Not applicable |
   ```

3. **Integration Dependency Matrix**
   - Service-to-database mapping (API, Celery, Flower)
   - Middleware database dependencies (16 middleware layers)
   - Repository pattern usage
   - Critical path identification

4. **Configuration Baseline Documentation**
   - Database connection parameters (from Settings class)
   - Pool configuration settings (pool_size=5, max_overflow=10)
   - Circuit breaker thresholds (failure_threshold=5, recovery_timeout=30s)
   - Repository-specific configurations

---

## 🔄 **Integration with Existing Infrastructure**

### **Leverage Existing Monitoring**
- Use circuit breaker state monitoring from `/app/db/session.py`
- Extend current health check endpoints
- Build on existing structured logging
- Reuse repository monitoring patterns

### **Build on Security Framework**
- Utilize existing JWT authentication patterns
- Extend current audit logging in `/app/middleware/audit.py`
- Leverage session management database patterns
- Build on existing CSRF protection

### **Reuse Development Tools**
- Extend existing Docker Compose setup
- Build on current testing infrastructure (`docker-compose.test.yml`)
- Utilize existing migration management (Alembic)
- Leverage current backup strategies (volume mounts)

---

## ⚠️ **Risk Mitigation**

### **Minimal Disruption Approach**
- **No new API endpoints** - Use existing internal tools and introspection
- **Read-only analysis** - No database modifications during discovery
- **Non-production first** - Begin analysis in development environment
- **Existing tool reuse** - Leverage verified working infrastructure

### **Fallback Strategies**
- Manual documentation if automated tools fail
- Code analysis as backup to runtime discovery
- Stakeholder interviews for missing context
- Incremental discovery if full analysis exceeds resources

---

## 📈 **Success Metrics**

- **Documentation Coverage**: 100% of identified database components documented
- **Architecture Accuracy**: Validated against running system
- **Tool Verification**: All referenced tools confirmed working
- **Completeness**: All service dependencies mapped
- **Maintainability**: Documentation integrates with existing project structure

---

## 🚀 **Next Steps**

Upon completion of Phase 0, subsequent phases will be informed by:
1. **Phase 1**: Discovery & Inventory (detailed data asset cataloging)
2. **Phase 2**: Dependency Mapping (deep interaction analysis)
3. **Phase 3**: Configuration Review (drift detection and validation)

---

## 📝 **Notes and Considerations**

- **Verified Tools**: All referenced database tools tested and confirmed working
- **Security Boundaries**: All analysis respects existing security patterns
- **Minimal New Code**: Focus on using existing infrastructure over creating new tools
- **Configuration Driven**: Leverage comprehensive Settings class for configuration analysis
- **Docker Native**: Built around existing containerized architecture

---

*This plan prioritizes accuracy and reuse of the existing, well-architected ViolentUTF API infrastructure while maintaining the rigor required for comprehensive database architecture identification.*
