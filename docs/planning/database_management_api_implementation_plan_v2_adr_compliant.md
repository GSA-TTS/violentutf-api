# Database Management API Implementation Plan v2.0
## ViolentUTF-API PyRIT Memory Integration Strategy - ADR Compliant

**Created**: January 2025
**Version**: 2.0 (ADR Compliant)
**Status**: Design Phase - Enhanced for ADR Compliance
**Priority**: High
**Epic Issue**: [To be created as follow-up to Issue #107]

---

## Executive Summary

This document provides a comprehensive, **ADR-compliant** implementation plan for database management API endpoints in violentutf-api. The plan has been enhanced to align with all existing Architecture Decision Records while supporting PyRIT integration and maintaining enterprise-grade security and multi-tenant architecture.

**Key Enhancement**: Full alignment with **ADR-F2.2 Polyglot Persistence Strategy**, **ADR-003 Hybrid RBAC+ABAC**, **ADR-007 Async Task Processing**, and **ADR-010 Dependency Management** while enabling PyRIT engine compatibility.

**Architectural Decision**: Implement PyRIT memory management as a **specialized evidence storage layer** within the existing polyglot persistence strategy, rather than introducing a separate database architecture.

---

## 1. ADR Compliance Analysis

### 1.1 ADR-F2.2: Polyglot Persistence Strategy Compliance

**REQUIRED ALIGNMENT**: PyRIT memory integration must fit within the established three-tier storage strategy:

1. **PostgreSQL (Relational)**: Highly structured metadata, user accounts, configurations
2. **MongoDB/Document DB**: High-volume, semi-structured test evidence
3. **Blob Storage (S3)**: Long-term archival of large artifacts

**PyRIT Integration Pattern**:
- **PyRIT Memory Metadata** → PostgreSQL (`pyrit_memory_sessions`, `pyrit_datasets`)
- **PyRIT Conversation Evidence** → Document DB (as specialized evidence documents)
- **PyRIT DuckDB Archives** → Blob Storage (compressed archives for compliance)

**Key Constraint**: PyRIT's DuckDB requirement becomes a **temporary processing layer** rather than persistent primary storage, with data lifecycle managed according to ADR-F2.2 data lifecycle policy.

### 1.2 ADR-003: Hybrid RBAC+ABAC Authorization

**REQUIRED CONSTRAINTS**:
- All PyRIT memory operations must enforce `organization_id` isolation
- Database management endpoints require appropriate role-based permissions
- Every PyRIT dataset/memory resource must include `organization_id` foreign key

**Implementation Requirements**:
```python
# All PyRIT memory operations must include ABAC checks
def get_user_pyrit_memory(user_id: str, current_user: User) -> PyRITMemoryInstance:
    # RBAC Check
    require_role("tester")(current_user)

    # ABAC Check - organization_id isolation
    memory_metadata = db.execute(
        "SELECT * FROM pyrit_memory_sessions WHERE user_id = :user_id AND organization_id = :org_id",
        {"user_id": user_id, "org_id": current_user.organization_id}
    )
    if not memory_metadata:
        raise HTTPException(404, "Memory session not found")
```

### 1.3 ADR-007: Async Task Processing Compliance

**REQUIRED PATTERN**: All long-running PyRIT operations must use Celery task queue with HTTP polling

**Affected Operations**:
- PyRIT memory initialization (may take minutes for large datasets)
- Dataset import/export operations
- Memory backup and archival operations
- Large dataset conversion processes

**Implementation Pattern**:
```python
@router.post("/pyrit/initialize", status_code=202)
async def initialize_pyrit_memory(request: InitRequest) -> TaskResponse:
    # Immediate response with task URL
    task = create_pyrit_initialization_task.delay(user_id, request.dict())
    return TaskResponse(
        task_id=task.id,
        status_url=f"/api/v1/tasks/{task.id}",
        status="PENDING"
    )
```

### 1.4 ADR-010: Software Dependency Management

**REQUIRED COMPLIANCE**:
- PyRIT dependency must pass vulnerability scanning (`pip-audit`)
- License compatibility verification required
- Automated Dependabot monitoring for PyRIT updates
- SCA scans must include PyRIT transitive dependencies

**Implementation Requirements**:
- Add PyRIT to `requirements.txt` with version pinning
- Configure Dependabot for PyRIT monitoring
- Document PyRIT license compatibility (likely MIT/Apache compatible)
- Include PyRIT security scanning in CI/CD pipeline

### 1.5 ADR-006: JSON Data Serialization

**CONSTRAINT**: All database management endpoints must use JSON exclusively
- PyRIT memory statistics → JSON response format
- Dataset import/export → JSON-based API (not binary formats)
- Configuration and metadata → JSON serialization only

---

## 2. Enhanced Architecture Strategy

### 2.1 ADR-Compliant Polyglot Persistence Integration

**Revised Architecture**: PyRIT integration as **Evidence Storage Extension** within existing polyglot strategy:

```
PostgreSQL (System of Record):
├── Users, Organizations (existing)
├── PyRIT Memory Sessions (NEW)
├── PyRIT Dataset Metadata (NEW)
└── PyRIT Operation Audit Trail (NEW)

Document Database (Evidence Store):
├── Security Scan Evidence (existing)
├── PyRIT Conversation Evidence (NEW)
├── PyRIT Prompt/Response Pairs (NEW)
└── PyRIT Scoring Results (NEW)

Blob Storage (Archival):
├── Generated Reports (existing)
├── PyRIT Memory Archives (NEW)
├── PyRIT Dataset Backups (NEW)
└── Exported PyRIT Data (NEW)

Temporary Processing Layer:
└── PyRIT DuckDB instances (ephemeral, for active processing only)
```

### 2.2 Data Lifecycle Integration

**Compliance with ADR-F2.2 Data Lifecycle**:
- **Hot Storage (0-90 days)**: Active PyRIT conversations in Document DB
- **Warm Processing**: PyRIT DuckDB instances for active orchestrator sessions
- **Cold Storage (90+ days)**: Compressed PyRIT archives in Blob Storage
- **Cleanup**: Automated deletion of temporary DuckDB files after evidence migration

### 2.3 Multi-Tenant Security Model

**Organization-Level Isolation**:
```sql
-- All PyRIT tables must include organization_id
CREATE TABLE pyrit_memory_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL,  -- MANDATORY per ADR-003
    session_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(50),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE pyrit_datasets (
    id UUID PRIMARY KEY,
    name VARCHAR(255),
    organization_id UUID NOT NULL,  -- MANDATORY per ADR-003
    dataset_type VARCHAR(100),
    storage_location TEXT,
    created_by UUID,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
```

---

## 3. ADR-Compliant Database Management API Design

### 3.1 Endpoint Architecture (ADR-007 Compliant)

**Base Path**: `/api/v1/database`
**Authentication**: JWT with RBAC+ABAC (ADR-003)
**Serialization**: JSON exclusively (ADR-006)
**Long Operations**: Async with HTTP polling (ADR-007)

### 3.2 Core Endpoints with ADR Compliance

#### 3.2.1 Database Status Endpoint
```
GET /api/v1/database/status
```

**ADR-003 Compliance**: Filtered by `organization_id`
**ADR-006 Compliance**: JSON response only

```python
class DatabaseStatusResponse(BaseModel):
    """ADR-F2.2 Compliant: Status across all storage layers."""

    # PostgreSQL status (structured metadata)
    metadata_database: DatabaseInfo

    # Document DB status (evidence storage)
    evidence_database: DocumentDBInfo

    # Blob storage status (archival)
    archival_storage: BlobStorageInfo

    # PyRIT processing status (per organization)
    pyrit_processing: PyRITProcessingInfo

    # Overall health (organization-scoped)
    health_status: Literal["healthy", "degraded", "error"]
    last_accessed: Optional[datetime]
```

#### 3.2.2 PyRIT Memory Initialization (Async)
```
POST /api/v1/database/pyrit/initialize
```

**ADR-007 Compliance**: Returns `202 Accepted` with task URL
**ADR-003 Compliance**: Organization-scoped operation

```python
@router.post("/pyrit/initialize", status_code=202)
async def initialize_pyrit_memory(
    request: InitializePyRITMemoryRequest,
    current_user: User = Depends(get_current_user_with_org)
) -> TaskResponse:
    """ADR-007 Compliant: Async initialization with polling."""

    # RBAC Check (ADR-003)
    require_role("tester")(current_user)

    # Create async task
    task = initialize_pyrit_memory_task.delay(
        user_id=current_user.id,
        organization_id=current_user.organization_id,  # ADR-003 ABAC
        config=request.dict()
    )

    return TaskResponse(
        task_id=task.id,
        status_url=f"/api/v1/tasks/{task.id}",
        status="PENDING"
    )
```

#### 3.2.3 Dataset Operations (Polyglot Compliant)
```
POST /api/v1/database/datasets/import  (Async)
GET /api/v1/database/datasets          (Paginated, Org-scoped)
POST /api/v1/database/datasets/export  (Async, Blob Storage)
```

**ADR-F2.2 Compliance**: Metadata in PostgreSQL, Evidence in Document DB, Archives in Blob

---

## 4. Technical Implementation Plan (ADR Enhanced)

### 4.1 Phase 1: ADR-Compliant Foundation (Weeks 1-4)

#### 4.1.1 Dependency Management (ADR-010)
**Tasks**:
- [ ] Add PyRIT to `requirements.txt` with version constraints
- [ ] Configure Dependabot for PyRIT dependency monitoring
- [ ] Run `pip-audit` scans including PyRIT transitive dependencies
- [ ] Verify PyRIT license compatibility (MIT/Apache)
- [ ] Update CI/CD pipeline for PyRIT security scanning

**Deliverables**:
- PyRIT dependency properly managed per ADR-010
- Security scanning compliance for all PyRIT dependencies
- License compliance documentation

#### 4.1.2 Polyglot Persistence Extension (ADR-F2.2)
**Tasks**:
- [ ] Create PostgreSQL models for PyRIT metadata (with `organization_id`)
- [ ] Design Document DB schema for PyRIT evidence storage
- [ ] Implement Blob Storage integration for PyRIT archives
- [ ] Create data lifecycle management for PyRIT data
- [ ] Implement automated archival processes (90-day lifecycle)

**Deliverables**:
- `app/models/pyrit_memory.py` (PostgreSQL metadata)
- `app/services/pyrit_evidence_service.py` (Document DB integration)
- `app/services/pyrit_archival_service.py` (Blob Storage)
- Alembic migrations for PyRIT metadata tables

#### 4.1.3 Security Framework Enhancement (ADR-003)
**Tasks**:
- [ ] Extend RBAC with PyRIT-specific roles (`pyrit_user`, `pyrit_admin`)
- [ ] Implement organization-scoped ABAC for all PyRIT operations
- [ ] Create security validation for PyRIT file operations
- [ ] Extend audit logging for PyRIT database events

**Deliverables**:
- Enhanced RBAC/ABAC middleware for PyRIT operations
- Organization-isolated PyRIT resource access
- Comprehensive audit trail for PyRIT operations

### 4.2 Phase 2: Async API Development (Weeks 5-8)

#### 4.2.1 Task Queue Integration (ADR-007)
**Tasks**:
- [ ] Create Celery tasks for PyRIT memory initialization
- [ ] Implement async dataset import/export operations
- [ ] Build task progress tracking with status URLs
- [ ] Add webhook support for advanced clients

**Deliverables**:
- `app/celery/pyrit_tasks.py` (all PyRIT async operations)
- Task status tracking with HTTP polling
- Optional webhook notifications

#### 4.2.2 Database Management Endpoints (JSON-only, ADR-006)
**Tasks**:
- [ ] Implement database status endpoint (org-scoped)
- [ ] Create PyRIT memory management endpoints
- [ ] Build dataset import/export APIs
- [ ] Add comprehensive statistics endpoints

**Deliverables**:
- `app/api/endpoints/database.py` (full endpoint suite)
- `app/schemas/database.py` (JSON-only schemas)
- OpenAPI documentation compliance

### 4.3 Phase 3: Evidence Integration (Weeks 9-12)

#### 4.3.1 Document Database Integration (ADR-F2.2)
**Tasks**:
- [ ] Implement PyRIT evidence storage in Document DB
- [ ] Create conversation/prompt storage services
- [ ] Build evidence querying and analytics
- [ ] Add evidence lifecycle management

**Deliverables**:
- PyRIT evidence properly stored in Document DB layer
- Evidence querying APIs with organization isolation
- Automated evidence archival to Blob Storage

#### 4.3.2 Data Lifecycle Automation (ADR-F2.2)
**Tasks**:
- [ ] Implement 90-day evidence migration to cold storage
- [ ] Create automated cleanup of temporary DuckDB files
- [ ] Build archival monitoring and reporting
- [ ] Add data retention policy enforcement

**Deliverables**:
- Automated data lifecycle management
- Cold storage archival processes
- Compliance-ready data retention

### 4.4 Phase 4: Production & Compliance (Weeks 13-16)

#### 4.4.1 Monitoring and Security
**Tasks**:
- [ ] Implement comprehensive security monitoring
- [ ] Add PyRIT-specific Prometheus metrics
- [ ] Create compliance reporting dashboards
- [ ] Build security incident response procedures

#### 4.4.2 Documentation and Training
**Tasks**:
- [ ] Complete API documentation (JSON schemas)
- [ ] Create PyRIT integration guides
- [ ] Build operational runbooks
- [ ] Prepare compliance documentation

---

## 5. PyRIT Engine Compatibility Strategy

### 5.1 PyRIT Memory Bridge Pattern

**Challenge**: PyRIT expects DuckDB, but ADR-F2.2 mandates polyglot persistence.

**Solution**: Create a **PyRIT Memory Bridge** that presents DuckDB interface while storing data in compliance with polyglot strategy:

```python
class ADRCompliantPyRITMemory(MemoryInterface):
    """PyRIT Memory implementation compliant with ADR-F2.2."""

    def __init__(self, organization_id: str, user_id: str):
        self.organization_id = organization_id  # ADR-003 compliance
        self.user_id = user_id

        # Temporary DuckDB for PyRIT compatibility (processing only)
        self.temp_duckdb = DuckDBMemory(db_path=f"/tmp/pyrit_{user_id}.db")

        # Polyglot storage services (ADR-F2.2 compliance)
        self.metadata_service = PyRITMetadataService()  # PostgreSQL
        self.evidence_service = PyRITEvidenceService()  # Document DB
        self.archival_service = PyRITArchivalService()  # Blob Storage

    async def add_request_pieces_to_memory(self, request_pieces):
        """Store in temp DuckDB + sync to polyglot storage."""

        # 1. Store in temporary DuckDB (PyRIT compatibility)
        await self.temp_duckdb.add_request_pieces_to_memory(request_pieces)

        # 2. Sync to Document DB (ADR-F2.2 compliance)
        evidence_docs = self._convert_to_evidence_documents(request_pieces)
        await self.evidence_service.store_evidence(
            organization_id=self.organization_id,
            evidence_docs=evidence_docs
        )

        # 3. Update metadata in PostgreSQL
        await self.metadata_service.update_session_stats(
            organization_id=self.organization_id,
            user_id=self.user_id,
            new_entries_count=len(request_pieces)
        )
```

### 5.2 Temporary Processing Layer

**Temporary DuckDB Usage**:
- Created on-demand for active PyRIT orchestrator sessions
- Automatically synced to polyglot storage layers
- Cleaned up after session completion (24-48 hour TTL)
- Used ONLY for PyRIT engine compatibility, not as system of record

**Data Flow**:
1. **PyRIT Operation Start** → Create temporary DuckDB instance
2. **PyRIT Processing** → PyRIT engine uses DuckDB normally
3. **Background Sync** → Continuous sync to Document DB + PostgreSQL
4. **Session Complete** → Final sync + DuckDB cleanup
5. **Long-term Storage** → Evidence in Document DB, metadata in PostgreSQL

---

## 6. Security Model Enhancement

### 6.1 Multi-Layered Security (ADR-003 Enhanced)

**Security Layers**:
1. **Authentication**: JWT tokens with user identity
2. **RBAC**: Role-based function access (`viewer`, `tester`, `admin`, `pyrit_user`)
3. **ABAC**: Organization-based data isolation (`organization_id` on all resources)
4. **File System Security**: Secure temporary file management
5. **Network Security**: TLS for all PyRIT communication

**PyRIT-Specific RBAC Roles**:
```python
class PyRITRole:
    PYRIT_USER = "pyrit_user"      # Can use PyRIT memory, import datasets
    PYRIT_ADMIN = "pyrit_admin"    # Can manage PyRIT for organization
    PYRIT_ANALYST = "pyrit_analyst" # Can analyze PyRIT results
```

### 6.2 Organization Isolation

**Mandatory Organization Scoping**:
```python
# Every PyRIT operation MUST include organization check
@require_role("pyrit_user")
async def get_pyrit_memory_stats(
    current_user: User = Depends(get_current_user)
) -> PyRITMemoryStats:

    # ABAC: Only access own organization's PyRIT data
    stats = await pyrit_service.get_memory_stats(
        organization_id=current_user.organization_id  # MANDATORY
    )

    return stats
```

---

## 7. Compliance and Audit Framework

### 7.1 ADR Compliance Matrix

| ADR | Requirement | Implementation Status |
|-----|------------|----------------------|
| ADR-F2.2 | Polyglot Persistence | ✅ PyRIT integrated as evidence layer |
| ADR-003 | RBAC+ABAC | ✅ Organization isolation enforced |
| ADR-007 | Async Processing | ✅ All long operations use Celery |
| ADR-006 | JSON Serialization | ✅ All APIs use JSON exclusively |
| ADR-010 | Dependency Management | ✅ PyRIT dependency managed per policy |

### 7.2 Audit Requirements

**Audit Events**:
```python
class PyRITAuditEvent:
    PYRIT_MEMORY_CREATED = "pyrit_memory_created"
    PYRIT_DATASET_IMPORTED = "pyrit_dataset_imported"
    PYRIT_EVIDENCE_ARCHIVED = "pyrit_evidence_archived"
    PYRIT_MEMORY_ACCESSED = "pyrit_memory_accessed"
    PYRIT_DATA_EXPORTED = "pyrit_data_exported"
```

**Compliance Reporting**:
- Data lifecycle compliance (90-day archival rule)
- Organization isolation validation
- Security event monitoring
- Resource usage tracking per organization

---

## 8. Risk Assessment and Mitigation (ADR Enhanced)

### 8.1 Technical Risks

**Risk**: PyRIT DuckDB compatibility vs ADR-F2.2 polyglot requirement
**Mitigation**: Temporary processing layer with automatic sync to compliant storage

**Risk**: Performance impact of dual storage (DuckDB + Document DB)
**Mitigation**: Async background sync, intelligent caching, temporary DuckDB cleanup

**Risk**: Organization isolation complexity with PyRIT sessions
**Mitigation**: Mandatory `organization_id` checks, comprehensive audit trails

### 8.2 Compliance Risks

**Risk**: Data lifecycle policy violations (ADR-F2.2)
**Mitigation**: Automated archival processes, compliance monitoring, retention policies

**Risk**: RBAC/ABAC bypass in PyRIT operations (ADR-003)
**Mitigation**: Mandatory security checks, comprehensive testing, security reviews

---

## 9. Implementation Validation

### 9.1 ADR Compliance Testing

**Required Test Coverage**:
- [ ] PyRIT data properly flows through polyglot storage layers (ADR-F2.2)
- [ ] All PyRIT operations enforce organization isolation (ADR-003)
- [ ] Long PyRIT operations use async task pattern (ADR-007)
- [ ] All PyRIT APIs use JSON exclusively (ADR-006)
- [ ] PyRIT dependency passes security scans (ADR-010)

### 9.2 Integration Testing

**PyRIT Engine Compatibility**:
- [ ] PyRIT orchestrators function normally with memory bridge
- [ ] Dataset import/export maintains PyRIT format compatibility
- [ ] Memory operations transparent to PyRIT engine
- [ ] Performance acceptable for PyRIT use cases

### 9.3 Security Validation

**Multi-Tenant Security**:
- [ ] Organization A cannot access Organization B's PyRIT data
- [ ] Role-based access properly enforced for PyRIT operations
- [ ] File system security prevents unauthorized access
- [ ] Audit trails complete for all PyRIT operations

---

## 10. Success Criteria (ADR Compliant)

### 10.1 Functional Requirements

- [ ] All database management endpoints implemented with ADR compliance
- [ ] PyRIT memory integration working with polyglot storage
- [ ] Organization-isolated PyRIT operations
- [ ] Async task processing for all long operations
- [ ] JSON-only API responses

### 10.2 ADR Compliance Requirements

- [ ] **ADR-F2.2**: PyRIT data flows through PostgreSQL → Document DB → Blob Storage
- [ ] **ADR-003**: All PyRIT resources include `organization_id` and enforce RBAC+ABAC
- [ ] **ADR-007**: All long PyRIT operations return `202 Accepted` with status URLs
- [ ] **ADR-006**: All PyRIT APIs use `application/json` exclusively
- [ ] **ADR-010**: PyRIT dependency passes security scans and license compliance

### 10.3 PyRIT Engine Compatibility

- [ ] PyRIT orchestrators function normally with memory bridge
- [ ] PyRIT dataset types (SeedPrompt, QA, ChatMessages) fully supported
- [ ] Memory operations transparent to PyRIT engine
- [ ] Performance meets PyRIT engine requirements

---

## 11. Conclusion

This enhanced implementation plan ensures full compliance with all existing ADRs while maintaining PyRIT engine compatibility. The key innovation is treating PyRIT integration as a **specialized evidence layer** within the existing polyglot persistence strategy rather than introducing conflicting architecture patterns.

**Key ADR Compliance Achievements**:
1. **ADR-F2.2**: PyRIT integrated as evidence storage extension, not separate database architecture
2. **ADR-003**: Complete organization isolation with RBAC+ABAC for all PyRIT operations
3. **ADR-007**: All long PyRIT operations use standard async task processing
4. **ADR-006**: JSON-exclusive API design maintained throughout
5. **ADR-010**: PyRIT dependency managed per security and compliance policies

**PyRIT Compatibility**: Maintained through intelligent memory bridge pattern that presents DuckDB interface while storing data in compliance with established architectural decisions.

This approach ensures that violentutf-api can support PyRIT operations while maintaining its enterprise architecture integrity and compliance posture.

---

## Appendix: ADR Reference Summary

### ADR-F2.2: Polyglot Persistence Strategy
- **PostgreSQL**: Structured metadata (users, organizations, PyRIT sessions)
- **Document DB**: Semi-structured evidence (PyRIT conversations, scores)
- **Blob Storage**: Archival data (PyRIT backups, exports)
- **Data Lifecycle**: 90-day hot→cold migration policy

### ADR-003: Hybrid RBAC+ABAC Authorization
- **RBAC**: Function-level access control via roles
- **ABAC**: Resource-level access control via `organization_id`
- **Requirement**: All tenant resources MUST include `organization_id`

### ADR-007: Async Task Processing
- **Pattern**: `202 Accepted` response with status URL
- **Tools**: Celery task queue with Redis broker
- **Requirement**: All long operations (>30 seconds) must be async

### ADR-006: JSON Data Serialization
- **Exclusive Format**: `application/json` for all API operations
- **No Exceptions**: XML, Protobuf, or other formats prohibited
- **Integration**: OpenAPI/Swagger documentation alignment

### ADR-010: Software Dependency Management
- **Security**: All dependencies must pass `pip-audit` scans
- **Monitoring**: Dependabot for continuous vulnerability tracking
- **Policy**: Critical/High vulnerabilities block deployment
