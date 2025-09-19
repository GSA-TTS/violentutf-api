# ViolentUTF API Architecture Diagrams
## Visual Database Architecture Documentation

**Document Version**: 1.0
**Created**: September 19, 2025
**Issue**: #118 - Phase 0: Architecture Identification and Documentation

---

## System Context Diagram

```mermaid
C4Context
    title ViolentUTF API System Context

    Person(user, "API Users", "Developers and applications consuming the ViolentUTF API")
    Person(admin, "System Administrators", "DevOps and security teams managing the platform")

    System(violentutf, "ViolentUTF API", "AI red-teaming platform providing security scanning and vulnerability assessment")

    System_Ext(client_apps, "Client Applications", "External applications using the API")
    System_Ext(monitoring, "Monitoring Systems", "External monitoring and alerting platforms")

    Rel(user, violentutf, "Uses", "HTTPS/REST API")
    Rel(admin, violentutf, "Manages", "Admin API, Docker")
    Rel(client_apps, violentutf, "Consumes", "REST API")
    Rel(violentutf, monitoring, "Sends metrics", "HTTP/HTTPS")
```

---

## Container Architecture Diagram

```mermaid
C4Container
    title ViolentUTF API Container Architecture

    Person(user, "API Users")
    Person(admin, "Administrators")

    System_Boundary(violentutf, "ViolentUTF API System") {
        Container(nginx, "Nginx Proxy", "Nginx", "Reverse proxy and load balancer")
        Container(api, "API Service", "FastAPI/Python", "Main API application with authentication and business logic")
        Container(worker, "Celery Worker", "Celery/Python", "Async task processing and background jobs")
        Container(flower, "Flower Monitor", "Flower/Python", "Celery task monitoring and management")

        ContainerDb(postgres, "PostgreSQL", "PostgreSQL 15", "Primary database for persistent data storage")
        ContainerDb(redis, "Redis Cache", "Redis 7", "Caching, session storage, and message broker")
    }

    Rel(user, nginx, "Uses", "HTTPS")
    Rel(admin, flower, "Monitors", "HTTPS")

    Rel(nginx, api, "Forwards requests", "HTTP")
    Rel(api, postgres, "Reads/Writes", "PostgreSQL Protocol")
    Rel(api, redis, "Caches/Sessions", "Redis Protocol")

    Rel(worker, postgres, "Reads/Writes", "PostgreSQL Protocol")
    Rel(worker, redis, "Task Queue", "Redis Protocol")
    Rel(flower, redis, "Monitors", "Redis Protocol")
```

---

## Database Component Diagram

```mermaid
C4Component
    title Database Components and Interactions

    Container_Boundary(api, "API Service") {
        Component(auth, "Authentication", "FastAPI/Middleware", "User authentication and session management")
        Component(rbac, "RBAC Engine", "Middleware", "Role-based access control")
        Component(repos, "Repository Layer", "SQLAlchemy", "Data access abstraction")
        Component(models, "ORM Models", "SQLAlchemy", "35+ database models")
        Component(cache, "Cache Manager", "Redis Client", "Caching and session management")
    }

    Container_Boundary(worker, "Celery Worker") {
        Component(tasks, "Task Executor", "Celery", "Async task processing")
        Component(scans, "Scan Engine", "Python", "Security scanning logic")
    }

    ContainerDb(postgres, "PostgreSQL", "Database", "Primary data store")
    ContainerDb(redis_db0, "Redis DB 0", "Cache", "Sessions & API cache")
    ContainerDb(redis_db1, "Redis DB 1", "Broker", "Celery message broker")
    ContainerDb(redis_db2, "Redis DB 2", "Results", "Celery result backend")

    Rel(auth, repos, "Uses")
    Rel(rbac, repos, "Uses")
    Rel(repos, models, "Uses")
    Rel(models, postgres, "Queries")

    Rel(cache, redis_db0, "Stores/Retrieves")
    Rel(auth, cache, "Session mgmt")

    Rel(tasks, redis_db1, "Receives tasks")
    Rel(tasks, redis_db2, "Stores results")
    Rel(scans, repos, "Saves results")
```

---

## Data Flow Diagram

```mermaid
flowchart TD
    A[API Request] --> B[Nginx Proxy]
    B --> C[FastAPI Router]
    C --> D[Authentication Middleware]
    D --> E[RBAC Middleware]
    E --> F[API Endpoint]
    F --> G[Repository Layer]
    G --> H[(PostgreSQL)]

    D --> I[Session Cache]
    I --> J[(Redis DB 0)]

    F --> K[Background Task]
    K --> L[Celery Queue]
    L --> M[(Redis DB 1)]

    N[Celery Worker] --> M
    N --> O[Task Execution]
    O --> P[Results Storage]
    P --> Q[(Redis DB 2)]
    P --> G

    R[Audit Middleware] --> S[Audit Log]
    S --> H

    C --> R
    E --> R
    F --> R
```

---

## Database Schema Overview

```mermaid
erDiagram
    %% Core Authentication
    User ||--o{ UserRole : has
    Role ||--o{ UserRole : grants
    User ||--o{ APIKey : owns
    User ||--o{ Session : active

    %% MFA System
    User ||--o{ MFADevice : registers
    MFADevice ||--o{ MFAChallenge : generates
    User ||--o{ MFABackupCode : has

    %% OAuth Integration
    User ||--o{ OAuthApplication : owns
    OAuthApplication ||--o{ OAuthAccessToken : issues
    OAuthApplication ||--o{ OAuthRefreshToken : issues
    OAuthApplication ||--o{ OAuthAuthorizationCode : generates

    %% Security Scanning
    User ||--o{ SecurityScan : creates
    SecurityScan ||--o{ ScanFinding : contains
    SecurityScan ||--o{ ScanReport : generates
    ScanFinding ||--o{ VulnerabilityFinding : links

    %% Task Management
    User ||--o{ Task : submits
    Task ||--o{ TaskResult : produces
    Plugin ||--o{ PluginExecution : runs

    %% Audit Trail
    User ||--o{ AuditLog : generates

    User {
        uuid id PK
        string username
        string email
        string password_hash
        datetime created_at
        datetime last_login_at
        string last_login_ip
        boolean is_active
        boolean is_verified
    }

    Role {
        uuid id PK
        string name
        string description
        jsonb permissions
        datetime created_at
    }

    SecurityScan {
        uuid id PK
        string name
        string scan_type
        jsonb configuration
        string status
        datetime started_at
        datetime completed_at
        uuid user_id FK
    }

    AuditLog {
        uuid id PK
        string action
        string resource_type
        uuid resource_id
        jsonb metadata
        datetime timestamp
        uuid user_id FK
    }
```

---

## Service Dependency Graph

```mermaid
graph TB
    subgraph "External Access"
        CLIENT[Client Applications]
        ADMIN[Administrators]
    end

    subgraph "ViolentUTF Platform"
        subgraph "Proxy Layer"
            NGINX[Nginx Proxy<br/>Port 80]
        end

        subgraph "Application Layer"
            API[API Service<br/>Port 8000<br/>FastAPI]
            WORKER[Celery Worker<br/>Background Tasks]
            FLOWER[Flower Monitor<br/>Port 5555<br/>Task Monitoring]
        end

        subgraph "Data Layer"
            POSTGRES[(PostgreSQL<br/>Port 5432<br/>Primary DB)]
            REDIS[(Redis<br/>Port 6379<br/>Cache/Broker)]
        end

        subgraph "Redis Databases"
            REDIS_0[(DB 0: Sessions)]
            REDIS_1[(DB 1: Celery Broker)]
            REDIS_2[(DB 2: Celery Results)]
        end
    end

    CLIENT --> NGINX
    ADMIN --> FLOWER

    NGINX --> API
    API --> POSTGRES
    API --> REDIS_0

    WORKER --> POSTGRES
    WORKER --> REDIS_1
    WORKER --> REDIS_2

    FLOWER --> REDIS_1
    FLOWER --> REDIS_2

    REDIS --> REDIS_0
    REDIS --> REDIS_1
    REDIS --> REDIS_2

    %% Dependencies
    API -.->|depends_on| POSTGRES
    API -.->|depends_on| REDIS
    WORKER -.->|depends_on| POSTGRES
    WORKER -.->|depends_on| REDIS
    FLOWER -.->|depends_on| REDIS
    NGINX -.->|depends_on| API
```

---

## Repository Pattern Architecture

```mermaid
classDiagram
    class BaseRepository {
        +session: AsyncSession
        +model: Type[T]
        +get_by_id(id): Optional[T]
        +create(data): T
        +update(id, data): Optional[T]
        +delete(id): bool
        +list(filters): Page[T]
        +count(filters): int
    }

    class UserRepository {
        +get_by_username(username): Optional[User]
        +get_by_email(email): Optional[User]
        +update_last_login(id, ip): bool
        +list_active_users(): List[User]
    }

    class SecurityScanRepository {
        +get_by_user(user_id): List[SecurityScan]
        +get_active_scans(): List[SecurityScan]
        +update_status(id, status): bool
        +get_scan_statistics(): Dict
    }

    class AuditLogRepository {
        +create_audit_entry(action, resource): AuditLog
        +get_user_activities(user_id): List[AuditLog]
        +search_by_criteria(filters): List[AuditLog]
    }

    class SessionRepository {
        +get_active_session(token): Optional[Session]
        +invalidate_user_sessions(user_id): int
        +cleanup_expired_sessions(): int
    }

    BaseRepository <|-- UserRepository
    BaseRepository <|-- SecurityScanRepository
    BaseRepository <|-- AuditLogRepository
    BaseRepository <|-- SessionRepository

    UserRepository --> User
    SecurityScanRepository --> SecurityScan
    AuditLogRepository --> AuditLog
    SessionRepository --> Session
```

---

## Middleware Stack Diagram

```mermaid
flowchart TD
    A[Incoming Request] --> B[Request ID Middleware]
    B --> C[Logging Middleware]
    C --> D[Security Headers Middleware]
    D --> E[CORS Middleware]
    E --> F[Rate Limiting Middleware]
    F --> G[Request Size Middleware]
    G --> H[Input Sanitization Middleware]
    H --> I[CSRF Protection Middleware]
    I --> J[Authentication Middleware]
    J --> K[Session Middleware]
    K --> L[Permissions Middleware]
    L --> M[Audit Middleware]
    M --> N[Cache Middleware]
    N --> O[Idempotency Middleware]
    O --> P[API Endpoint]

    %% Database interactions
    J -.-> Q[(User/APIKey Tables)]
    K -.-> R[(Session Table)]
    L -.-> S[(Role/Permission Tables)]
    M -.-> T[(AuditLog Table)]
    N -.-> U[(Redis Cache)]
    O -.-> V[(Redis Idempotency)]

    %% Response path
    P --> W[Response Processing]
    W --> X[Response Cache]
    X --> Y[Audit Response]
    Y --> Z[Final Response]
```

---

## Connection Pool Architecture

```mermaid
graph TB
    subgraph "Application Layer"
        API1[API Process 1]
        API2[API Process 2]
        WORKER1[Worker Process 1]
        WORKER2[Worker Process 2]
    end

    subgraph "Connection Pool"
        POOL[SQLAlchemy Pool<br/>Size: 5<br/>Max Overflow: 10]
        CONN1[Connection 1]
        CONN2[Connection 2]
        CONN3[Connection 3]
        CONN4[Connection 4]
        CONN5[Connection 5]
        OVERFLOW[Overflow Connections<br/>Up to 10 additional]
    end

    subgraph "Database"
        POSTGRES[(PostgreSQL<br/>Primary Database)]
    end

    subgraph "Monitoring"
        CIRCUIT[Circuit Breaker<br/>Failure Threshold: 5<br/>Recovery: 30s]
        HEALTH[Health Checks<br/>SELECT 1 queries]
        STATS[Pool Statistics<br/>Real-time metrics]
    end

    API1 --> POOL
    API2 --> POOL
    WORKER1 --> POOL
    WORKER2 --> POOL

    POOL --> CONN1
    POOL --> CONN2
    POOL --> CONN3
    POOL --> CONN4
    POOL --> CONN5
    POOL --> OVERFLOW

    CONN1 --> POSTGRES
    CONN2 --> POSTGRES
    CONN3 --> POSTGRES
    CONN4 --> POSTGRES
    CONN5 --> POSTGRES
    OVERFLOW --> POSTGRES

    CIRCUIT -.-> POOL
    HEALTH -.-> POSTGRES
    STATS -.-> POOL
```

---

## Cache Architecture Diagram

```mermaid
graph TB
    subgraph "Application Layer"
        API[API Service]
        MIDDLEWARE[Cache Middleware]
        SESSIONS[Session Manager]
    end

    subgraph "Cache Layer"
        CACHE_MGR[Cache Manager<br/>Fallback Support]
        PRIMARY[Redis Primary]
        FALLBACK[In-Memory Fallback]
    end

    subgraph "Redis Cluster"
        REDIS[(Redis Server)]
        DB0[(DB 0: Sessions & API Cache)]
        DB1[(DB 1: Celery Broker)]
        DB2[(DB 2: Celery Results)]
    end

    subgraph "Celery System"
        WORKER[Celery Worker]
        FLOWER[Flower Monitor]
        BROKER[Message Broker]
        BACKEND[Result Backend]
    end

    API --> MIDDLEWARE
    API --> SESSIONS
    MIDDLEWARE --> CACHE_MGR
    SESSIONS --> CACHE_MGR

    CACHE_MGR --> PRIMARY
    CACHE_MGR --> FALLBACK

    PRIMARY --> DB0
    BROKER --> DB1
    BACKEND --> DB2

    REDIS --> DB0
    REDIS --> DB1
    REDIS --> DB2

    WORKER --> BROKER
    WORKER --> BACKEND
    FLOWER --> DB1
    FLOWER --> DB2

    %% Fallback mechanism
    PRIMARY -.->|Connection Failed| FALLBACK
```

---

## Deployment Architecture

```mermaid
deployment
    node "Docker Host" {

        node "violentutf-network" {

            component "nginx" [
                Nginx Proxy
                --
                Image: nginx:alpine
                Port: 80
                Volume: nginx.conf
            ]

            component "api" [
                ViolentUTF API
                --
                Image: violentutf-api:latest
                Port: 8000
                Volumes: ./app, ./logs
            ]

            component "celery-worker" [
                Celery Worker
                --
                Image: violentutf-api:latest
                Command: celery worker
                Volumes: ./app, ./logs
            ]

            component "flower" [
                Flower Monitor
                --
                Image: violentutf-api:latest
                Port: 5555
                Command: celery flower
            ]

            database "postgres" [
                PostgreSQL 15
                --
                Image: postgres:15-alpine
                Volume: postgres_data
                Backup: ./backups/postgres
            ]

            database "redis" [
                Redis 7
                --
                Image: redis:7-alpine
                Volume: redis_data
                Command: redis-server --appendonly yes
            ]
        }
    }

    nginx --> api
    api --> postgres
    api --> redis
    celery-worker --> postgres
    celery-worker --> redis
    flower --> redis
```

---

## Summary

These diagrams provide a comprehensive visual representation of the ViolentUTF API database architecture, including:

1. **System Context** - High-level system interactions
2. **Container Architecture** - Service-level decomposition
3. **Database Components** - Internal component relationships
4. **Data Flow** - Request/response processing patterns
5. **Schema Overview** - Entity relationships and key tables
6. **Service Dependencies** - Inter-service communication
7. **Repository Pattern** - Data access layer architecture
8. **Middleware Stack** - Request processing pipeline
9. **Connection Pooling** - Database connection management
10. **Cache Architecture** - Caching and session management
11. **Deployment View** - Docker container orchestration

These visual representations complement the detailed analysis document and provide clear architectural understanding for stakeholders across all technical levels.

---

*Diagrams generated using Mermaid syntax for consistent rendering across documentation platforms.*
