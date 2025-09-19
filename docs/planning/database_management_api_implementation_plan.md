# Database Management API Implementation Plan
## ViolentUTF-API PyRIT Memory Integration Strategy

**Created**: January 2025
**Status**: Design Phase
**Priority**: High
**Epic Issue**: [To be created as follow-up to Issue #107]

---

## Executive Summary

This document provides a comprehensive implementation plan for database management API endpoints in violentutf-api, designed to support PyRIT integration while maintaining enterprise-grade security and multi-tenant architecture. The plan addresses the gap identified where violentutf-api lacks the database management capabilities present in the original ViolentUTF implementation.

**Key Goal**: Create database management APIs that bridge PyRIT's DuckDB memory requirements with violentutf-api's PostgreSQL-based enterprise architecture.

---

## 1. Background Analysis

### 1.1 PyRIT Memory System Requirements

Based on analysis of PyRIT API documentation and ViolentUTF implementation:

**PyRIT Memory Interface Pattern**:
- **Core Interface**: `MemoryInterface` (abstract base class)
- **Implementation Options**: `DuckDBMemory`, `AzureSQLMemory`, `InMemoryMemory`
- **Initialization**: `initialize_pyrit(memory_db_type="DuckDB", **kwargs)`
- **Central Memory**: `CentralMemory.set_memory_instance(memory)` for framework-wide access

**PyRIT Database Schema (DuckDB)**:
```sql
-- Core PyRIT tables (from DuckDBMemory)
CREATE TABLE prompt_memory_entries (
    id UUID PRIMARY KEY,
    conversation_id TEXT,
    role TEXT,
    content TEXT,
    timestamp TIMESTAMP,
    user_id TEXT,
    memory_type TEXT
);

CREATE TABLE embedding_data (
    id UUID FOREIGN KEY REFERENCES prompt_memory_entries(id),
    embedding ARRAY(FLOAT),
    embedding_type_name TEXT
);

CREATE TABLE scores (
    id UUID PRIMARY KEY,
    prompt_id UUID,
    scorer_name TEXT,
    score_value REAL,
    score_metadata TEXT
);
```

**PyRIT Dataset Types**:
- `SeedPromptDataset` - Collection of initial prompts for red teaming
- `QuestionAnsweringDataset` - Q&A pairs for evaluation
- `ChatMessagesDataset` - Conversational data for memory operations

### 1.2 Original ViolentUTF Database Architecture

**User Isolation Model**:
- Per-user DuckDB files: `pyrit_memory_{hash(salt+username)}.db`
- File-based isolation in `/app/app_data/violentutf/` directory
- Direct user control over database operations (initialize, reset, backup)

**Integration Points**:
- ViolentUTF FastAPI creates user-specific DuckDB instances
- PyRIT orchestrators use `DuckDBMemory(db_path=user_db_path)`
- Database endpoints provide status, statistics, and management operations

### 1.3 ViolentUTF-API Current Architecture

**Enterprise Multi-tenant Model**:
- Shared PostgreSQL database with RBAC isolation
- SQLAlchemy 2.x with repository pattern and service layers
- Existing models: User, Task, Scan, Report, Orchestrator
- No PyRIT dependency in requirements.txt
- No database management endpoints

**Key Differences Requiring Adaptation**:
1. **Database Technology**: PostgreSQL/SQLite vs DuckDB
2. **Isolation Strategy**: RBAC/row-level security vs file-based
3. **Memory Management**: Shared instance vs per-user instances
4. **Integration Pattern**: Enterprise services vs direct PyRIT integration

---

## 2. Implementation Strategy

### 2.1 Hybrid Architecture Approach

**Recommended Strategy**: Implement a **dual-database architecture** that maintains enterprise PostgreSQL for application data while supporting PyRIT's DuckDB requirements for memory operations.

**Architecture Components**:
1. **Primary Database** (PostgreSQL): Application entities, user management, audit trails
2. **PyRIT Memory Layer** (DuckDB): User-specific PyRIT memory instances
3. **Database Management Service**: Bridges both layers with enterprise security
4. **API Layer**: RESTful endpoints for database operations

### 2.2 PyRIT Integration Pattern

**PyRIT Memory Management Service**:
```python
class PyRITMemoryService:
    """Manages PyRIT DuckDB instances within enterprise architecture."""

    def __init__(self, user_service: UserService, audit_service: AuditService):
        self.user_service = user_service
        self.audit_service = audit_service
        self.memory_cache: Dict[str, DuckDBMemory] = {}

    async def get_user_memory_instance(self, user_id: str) -> DuckDBMemory:
        """Get or create user-specific PyRIT memory instance."""
        if user_id not in self.memory_cache:
            # Create user-specific DuckDB file with RBAC validation
            db_path = self._generate_secure_db_path(user_id)
            memory = DuckDBMemory(db_path=db_path)
            self.memory_cache[user_id] = memory

            # Audit memory instance creation
            await self.audit_service.log_database_event(
                user_id=user_id,
                event="pyrit_memory_created",
                metadata={"db_path": db_path}
            )

        return self.memory_cache[user_id]
```

---

## 3. Database Management API Design

### 3.1 Endpoint Architecture

**Base Path**: `/api/v1/database`
**Authentication**: JWT + RBAC (existing middleware stack)
**Authorization**: User can only access their own database resources

### 3.2 Core Endpoints

#### 3.2.1 Database Status Endpoint
```
GET /api/v1/database/status
```

**Purpose**: Get user's database connection status and health metrics

**Response Schema**:
```python
class DatabaseStatusResponse(BaseModel):
    """User database status information."""

    # Primary database (PostgreSQL)
    primary_database: DatabaseInfo = Field(description="Main application database")

    # PyRIT memory database (DuckDB)
    pyrit_memory: Optional[PyRITMemoryInfo] = Field(description="User's PyRIT memory instance")

    # Overall status
    health_status: Literal["healthy", "degraded", "error"]
    last_accessed: Optional[datetime]

class DatabaseInfo(BaseModel):
    status: Literal["connected", "disconnected", "error"]
    database_type: str  # "postgresql", "sqlite"
    size_mb: Optional[float]

class PyRITMemoryInfo(BaseModel):
    is_initialized: bool
    database_path: str
    file_size_mb: Optional[float]
    table_count: int
    memory_entries_count: int
    last_backup: Optional[datetime]
```

**Implementation Notes**:
- Validates user access to their own resources only
- Checks both PostgreSQL connection and PyRIT DuckDB instance
- Returns aggregated health status

#### 3.2.2 PyRIT Memory Initialization
```
POST /api/v1/database/pyrit/initialize
```

**Purpose**: Initialize user's PyRIT memory database instance

**Request Schema**:
```python
class InitializePyRITMemoryRequest(BaseModel):
    force_recreate: bool = False
    backup_existing: bool = True
    memory_config: Optional[Dict[str, Any]] = None
```

**Response Schema**:
```python
class InitializePyRITMemoryResponse(BaseModel):
    memory_instance_id: str
    database_path: str
    initialization_status: Literal["created", "already_exists", "recreated"]
    tables_created: List[str]
    backup_path: Optional[str]
    initialized_at: datetime
```

#### 3.2.3 Database Statistics
```
GET /api/v1/database/stats
```

**Purpose**: Get comprehensive database usage statistics

**Response Schema**:
```python
class DatabaseStatsResponse(BaseModel):
    """User database statistics."""

    primary_database_usage: PrimaryDBStats
    pyrit_memory_stats: Optional[PyRITMemoryStats]
    total_storage_mb: float

class PyRITMemoryStats(BaseModel):
    table_statistics: List[TableStats]
    memory_entries_count: int
    conversations_count: int
    scores_count: int
    embeddings_count: int
    date_range: DateRange

class TableStats(BaseModel):
    table_name: str
    row_count: int
    size_mb: float
```

#### 3.2.4 PyRIT Memory Management
```
POST /api/v1/database/pyrit/reset
POST /api/v1/database/pyrit/backup
POST /api/v1/database/pyrit/export
```

**Purpose**: PyRIT memory lifecycle management operations

### 3.3 Dataset Management Extensions

#### 3.3.1 Dataset Integration Endpoints
```
GET /api/v1/database/datasets
POST /api/v1/database/datasets/import
GET /api/v1/database/datasets/{dataset_id}/export
```

**Purpose**: Bridge PyRIT datasets with enterprise data management

**Integration Pattern**:
- Import PyRIT datasets (SeedPromptDataset, etc.) into user's memory instance
- Export user's prompt/conversation data as PyRIT-compatible datasets
- Manage dataset metadata in PostgreSQL, actual data in PyRIT DuckDB

---

## 4. Technical Implementation Plan

### 4.1 Phase 1: Foundation (Weeks 1-3)

#### 4.1.1 PyRIT Integration Setup
**Tasks**:
- [ ] Add PyRIT dependency to requirements.txt
- [ ] Create PyRIT memory service layer
- [ ] Implement secure DuckDB file management
- [ ] Extend audit logging for database operations

**Deliverables**:
- `app/services/pyrit_memory_service.py`
- `app/core/pyrit_integration.py`
- `app/utils/secure_file_manager.py`

#### 4.1.2 Database Models Extension
**Tasks**:
- [ ] Create PyRIT memory metadata models
- [ ] Extend User model with PyRIT memory references
- [ ] Create database management audit models
- [ ] Implement Alembic migrations

**Deliverables**:
- `app/models/pyrit_memory.py`
- `app/models/database_management.py`
- Migration files for new tables

#### 4.1.3 Security Framework
**Tasks**:
- [ ] Implement RBAC for database operations
- [ ] Create secure file path validation
- [ ] Extend existing middleware for database endpoints
- [ ] Implement resource quotas and limits

**Deliverables**:
- Enhanced RBAC permissions
- File system security validation
- Database operation rate limiting

### 4.2 Phase 2: Core API Development (Weeks 4-7)

#### 4.2.1 Database Management Endpoints
**Tasks**:
- [ ] Implement database status endpoint
- [ ] Create PyRIT memory initialization endpoint
- [ ] Build database statistics endpoint
- [ ] Add memory management operations (reset, backup)

**Deliverables**:
- `app/api/endpoints/database.py`
- `app/schemas/database.py`
- Complete endpoint implementation with OpenAPI docs

#### 4.2.2 Repository and Service Layer
**Tasks**:
- [ ] Create database management repository
- [ ] Implement database statistics service
- [ ] Build PyRIT memory bridge service
- [ ] Add background task support for long operations

**Deliverables**:
- `app/repositories/database_management.py`
- `app/services/database_stats_service.py`
- Celery task integration for async operations

#### 4.2.3 Testing Framework
**Tasks**:
- [ ] Unit tests for all services and repositories
- [ ] Integration tests with PyRIT memory
- [ ] API endpoint testing with authentication
- [ ] Performance testing with concurrent users

**Deliverables**:
- Comprehensive test suite (>85% coverage)
- Performance benchmarks
- Security testing validation

### 4.3 Phase 3: Dataset Integration (Weeks 8-10)

#### 4.3.1 PyRIT Dataset Support
**Tasks**:
- [ ] Implement SeedPromptDataset import/export
- [ ] Add QuestionAnsweringDataset support
- [ ] Create ChatMessagesDataset integration
- [ ] Build dataset validation framework

**Deliverables**:
- Dataset import/export endpoints
- Dataset validation services
- PyRIT format compatibility layer

#### 4.3.2 Advanced Features
**Tasks**:
- [ ] Implement dataset search and filtering
- [ ] Add dataset versioning support
- [ ] Create dataset sharing mechanisms
- [ ] Build dataset analytics dashboard

**Deliverables**:
- Advanced dataset management features
- Analytics and reporting capabilities

### 4.4 Phase 4: Production Readiness (Weeks 11-12)

#### 4.4.1 Monitoring and Observability
**Tasks**:
- [ ] Add Prometheus metrics for database operations
- [ ] Implement structured logging for all operations
- [ ] Create health check endpoints
- [ ] Build operational dashboards

**Deliverables**:
- Production monitoring setup
- Comprehensive logging and alerting

#### 4.4.2 Documentation and Training
**Tasks**:
- [ ] Complete API documentation
- [ ] Create user guides and tutorials
- [ ] Build administrative documentation
- [ ] Prepare deployment guides

**Deliverables**:
- Complete documentation set
- User training materials

---

## 5. Integration Patterns

### 5.1 PyRIT Orchestrator Integration

**Pattern**: Extend existing `OrchestratorExecution` model to support PyRIT memory management

```python
class OrchestratorExecution(BaseModelMixin, Base):
    """Extended orchestrator execution with PyRIT memory support."""

    # Existing fields...

    # PyRIT-specific fields
    pyrit_memory_session: Optional[str] = mapped_column(String(255), nullable=True)
    memory_instance_path: Optional[str] = mapped_column(String(500), nullable=True)

    async def initialize_pyrit_memory(self, user_id: str) -> DuckDBMemory:
        """Initialize PyRIT memory for this execution."""
        memory_service = get_pyrit_memory_service()
        memory = await memory_service.get_user_memory_instance(user_id)

        # Store memory session reference
        self.pyrit_memory_session = str(memory.get_session_id())
        self.memory_instance_path = memory.db_path

        return memory
```

### 5.2 Task Integration Pattern

**Pattern**: Extend existing `Task` model for PyRIT-related background operations

```python
class DatabaseManagementTask(Task):
    """Specialized task for database operations."""

    operation_type: str  # "backup", "reset", "export", "import"
    target_database: str  # "primary", "pyrit_memory"
    operation_metadata: Dict[str, Any]

    async def execute_database_operation(self):
        """Execute database management operation."""
        if self.operation_type == "backup":
            return await self._backup_pyrit_memory()
        elif self.operation_type == "reset":
            return await self._reset_pyrit_memory()
        # ... other operations
```

### 5.3 Audit Trail Integration

**Pattern**: Extend existing audit system for database operations

```python
class DatabaseAuditEvent:
    """Database-specific audit event types."""

    PYRIT_MEMORY_CREATED = "pyrit_memory_created"
    PYRIT_MEMORY_RESET = "pyrit_memory_reset"
    PYRIT_MEMORY_BACKUP = "pyrit_memory_backup"
    DATASET_IMPORTED = "dataset_imported"
    DATASET_EXPORTED = "dataset_exported"
    MEMORY_ACCESSED = "memory_accessed"
```

---

## 6. Security Considerations

### 6.1 File System Security

**User Isolation**:
- PyRIT DuckDB files stored in user-specific directories
- Hash-based file naming: `pyrit_memory_{hash(user_id+salt)}.db`
- Strict file permission validation (600 permissions)
- Regular security audits of file access patterns

**Path Traversal Prevention**:
```python
def validate_db_path(user_id: str, provided_path: str) -> bool:
    """Validate that database path belongs to user."""
    expected_path = generate_secure_db_path(user_id)
    return os.path.normpath(provided_path) == expected_path
```

### 6.2 Resource Management

**Quotas and Limits**:
- Maximum PyRIT database size per user (configurable)
- Rate limiting on database operations
- Concurrent operation limits
- Automatic cleanup of old backup files

**Monitoring**:
- Database operation audit trails
- Resource usage tracking
- Anomaly detection for unusual database access patterns

---

## 7. Performance Considerations

### 7.1 Scalability Design

**Connection Management**:
- Connection pooling for PostgreSQL operations
- PyRIT DuckDB instance caching with LRU eviction
- Background cleanup of unused memory instances

**Async Operations**:
- All database operations use async/await patterns
- Background tasks for long-running operations (backup, reset)
- Progress tracking for async operations

### 7.2 Performance Targets

**Response Time Targets**:
- Database status endpoint: <500ms
- Database statistics: <2 seconds
- PyRIT memory initialization: <5 seconds
- Backup operations: <30 seconds (background)

**Concurrent User Support**:
- Target: 100+ concurrent users
- Each user maintains independent PyRIT memory instance
- Shared PostgreSQL connection pool optimization

---

## 8. Testing Strategy

### 8.1 Unit Testing

**Test Coverage Requirements**: >85%

**Key Test Areas**:
- PyRIT memory service operations
- Database management service logic
- Security validation functions
- File path validation and sanitization
- RBAC permission enforcement

### 8.2 Integration Testing

**PyRIT Integration Tests**:
- DuckDB memory instance creation and management
- PyRIT dataset import/export workflows
- Memory persistence across service restarts
- Multi-user isolation validation

**Database Integration Tests**:
- PostgreSQL + DuckDB dual database operations
- Transaction consistency across databases
- Audit trail completeness
- Performance under concurrent load

### 8.3 Security Testing

**Security Test Requirements**:
- Path traversal attack prevention
- RBAC bypass attempt detection
- Resource exhaustion testing
- File permission validation
- SQL injection prevention (both PostgreSQL and DuckDB)

### 8.4 Performance Testing

**Load Testing Scenarios**:
- 100 concurrent users with database operations
- Large dataset import/export operations
- Memory instance creation under load
- Background task queue performance

---

## 9. Deployment Considerations

### 9.1 Environment Configuration

**Environment Variables**:
```bash
# PyRIT Configuration
PYRIT_MEMORY_DIR=/app/data/pyrit_memory
PYRIT_DB_SALT=secure_random_salt_for_hashing
PYRIT_MEMORY_QUOTA_MB=1024

# Database Management
DB_BACKUP_RETENTION_DAYS=30
DB_OPERATION_TIMEOUT_SECONDS=300
ENABLE_PYRIT_MEMORY_CLEANUP=true
```

**Directory Structure**:
```
/app/data/
├── pyrit_memory/
│   ├── user_{hash1}/
│   │   ├── pyrit_memory_{hash}.db
│   │   └── backups/
│   └── user_{hash2}/
└── postgresql/  (existing)
```

### 9.2 Migration Strategy

**Phase 1**: Deploy database management APIs without PyRIT dependency
**Phase 2**: Add PyRIT integration and memory management
**Phase 3**: Enable dataset import/export features
**Phase 4**: Full production rollout with monitoring

### 9.3 Monitoring and Alerting

**Key Metrics**:
- PyRIT memory instance count and sizes
- Database operation success/failure rates
- Response time percentiles for all endpoints
- Resource usage (disk space, memory consumption)
- User adoption metrics

**Alerting Rules**:
- PyRIT memory database corruption detection
- Disk space exhaustion warnings
- Unusual database access patterns
- Performance degradation alerts

---

## 10. Success Criteria

### 10.1 Functional Requirements

- [ ] All database management endpoints implemented and tested
- [ ] PyRIT memory integration working with user isolation
- [ ] Dataset import/export functionality operational
- [ ] Comprehensive audit trail for all database operations
- [ ] Background task processing for long operations

### 10.2 Non-Functional Requirements

- [ ] API response times meet performance targets
- [ ] Security validation passes penetration testing
- [ ] System handles 100+ concurrent users
- [ ] Database operations maintain ACID properties
- [ ] Complete monitoring and alerting implementation

### 10.3 Integration Requirements

- [ ] Seamless integration with existing authentication/authorization
- [ ] PyRIT orchestrator execution uses database management APIs
- [ ] Audit system captures all database events
- [ ] Task queue handles database operations efficiently
- [ ] Documentation and training materials complete

---

## 11. Risk Assessment and Mitigation

### 11.1 Technical Risks

**Risk**: PyRIT version compatibility issues
**Mitigation**: Pin specific PyRIT version, comprehensive integration testing

**Risk**: DuckDB file corruption or loss
**Mitigation**: Automated backup system, file integrity monitoring

**Risk**: Performance degradation with many concurrent users
**Mitigation**: Connection pooling, caching strategies, load testing

**Risk**: Security vulnerabilities in file access patterns
**Mitigation**: Security review, penetration testing, access auditing

### 11.2 Operational Risks

**Risk**: Increased system complexity
**Mitigation**: Comprehensive documentation, monitoring, gradual rollout

**Risk**: Storage cost increase from PyRIT databases
**Mitigation**: Storage quotas, cleanup policies, cost monitoring

**Risk**: Backup and disaster recovery complexity
**Mitigation**: Automated backup testing, recovery procedures documentation

---

## 12. Future Enhancements

### 12.1 Advanced Features (Post-MVP)

**PyRIT Analytics Integration**:
- ConversationAnalytics API integration
- Embedding similarity search endpoints
- Advanced prompt analysis features

**Enterprise Features**:
- Multi-tenant organization support
- Dataset sharing between users
- Advanced RBAC for dataset access
- Integration with external dataset repositories

**Performance Optimizations**:
- Database sharding strategies
- Caching layer for frequently accessed data
- Async processing pipeline optimization

### 12.2 Integration Opportunities

**External System Integration**:
- Integration with existing data lakes/warehouses
- ETL pipelines for dataset processing
- ML pipeline integration for automated analysis
- Integration with security orchestration platforms

---

## 13. Conclusion

This implementation plan provides a comprehensive strategy for adding database management API endpoints to violentutf-api while maintaining enterprise-grade security and performance. The hybrid architecture approach preserves the benefits of both PostgreSQL for application data and DuckDB for PyRIT memory requirements.

**Key Success Factors**:
1. Maintaining security and isolation in multi-tenant environment
2. Seamless PyRIT integration without compromising existing architecture
3. Comprehensive testing and validation of all components
4. Gradual rollout with monitoring and feedback integration

**Next Steps**:
1. Review and approve implementation plan
2. Create GitHub issues for each phase
3. Begin Phase 1 development work
4. Establish monitoring and testing infrastructure

This plan enables violentutf-api to support PyRIT operations while maintaining its enterprise architecture principles and security requirements.
