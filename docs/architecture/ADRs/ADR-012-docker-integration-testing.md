# ADR-012: Implement Docker-Based Integration Testing Infrastructure

## ADR Number
012

## Title
Implement Docker-Based Integration Testing Infrastructure

## Status
Proposed

## Date
2025-01-11

## Author(s)
[Author Name]

## Stakeholders
- Development Team (primary implementers and users)
- QA Team (test strategy and automation)
- DevOps Team (CI/CD pipeline integration)
- Security Team (container security and secrets management)
- Product Management (delivery timeline impact)
- SRE Team (production incident reduction)

## Context

The ViolentUTF API system currently lacks a comprehensive integration testing strategy. While the API can be run locally for development and testing, we need to establish clear patterns for integration testing in different environments.

**Important Note**: For local development, the ViolentUTF API can be run directly (e.g., `uvicorn app.main:app --reload`) and integration tests can be executed against these local endpoints without requiring Docker. This is often the simplest and fastest approach for development and debugging.

However, Docker-based integration testing infrastructure becomes necessary for specific scenarios:

Key architectural challenges that necessitate Docker-based testing in certain situations:

1. **CI/CD Pipeline Testing**: GitHub Actions and other CI/CD systems need a consistent, reproducible environment that doesn't depend on local development setup.

2. **Database Integration Testing**: When tests need a fresh PostgreSQL or Redis instance to avoid data pollution between test runs, especially for destructive tests.

3. **Multi-Service Dependencies**: When testing interactions with external services (e.g., Keycloak for auth, message queues, etc.) that are complex to set up locally.

4. **Team Collaboration**: Ensuring all team members have identical test environments regardless of their local machine configuration.

5. **Performance Testing**: When you need to simulate production-like resource constraints and network conditions.

6. **Pre-Production Validation**: Testing the actual Docker images that will be deployed to production.

The identified Architecturally Significant Requirements (ASRs) that must be addressed:

**ASR-1:** Implement containerized testing infrastructure using Docker Compose that isolates test dependencies from production.

**ASR-2:** Support parallel test execution without test interference or data corruption.

**ASR-3:** Establish automated performance baselines through a dedicated performance test suite.

**ASR-4:** Integrate CI/CD pipeline with Docker-based testing infrastructure for automated quality gates.

**ASR-5:** Implement proper service health checking and startup orchestration.

**ASR-6:** Ensure complete test isolation and repeatability through proper fixture and cleanup mechanisms.

## Testing Strategy Guidelines

### When to Use Local Testing (Recommended for Development)

For most development scenarios with ViolentUTF API, running tests against local endpoints is sufficient and preferred:

```bash
# Start the API locally
uvicorn app.main:app --reload --port 8000

# In another terminal, run integration tests
pytest tests/integration/ --base-url http://localhost:8000
```

**Use local testing when:**
- Developing and debugging features
- Running quick integration tests during development
- Testing API endpoints without complex dependencies
- Working with in-memory databases or test databases
- Needing fast feedback loops

**Advantages:**
- Fastest test execution
- Easiest debugging (direct access to logs and debugger)
- No Docker overhead
- Immediate code changes reflection with --reload

### When to Use Docker-Based Testing

**Use Docker-based testing when:**
- Running in CI/CD pipelines
- Testing with multiple service dependencies (PostgreSQL, Redis, Keycloak)
- Needing guaranteed clean state for each test run
- Testing Docker image builds before deployment
- Simulating production environment
- Running performance or load tests
- Ensuring consistency across team members

**Example Docker-based test execution:**
```bash
# Using docker-compose for full integration testing
docker-compose -f docker-compose.test.yml up -d
pytest tests/integration/ --base-url http://localhost:8000
docker-compose -f docker-compose.test.yml down -v
```

## Assumptions & Constraints

**Assumptions:**
- Docker is available and approved for use in all development and CI/CD environments
- The team has basic Docker knowledge or can acquire it through training
- Current system architecture supports containerization without major refactoring
- CI/CD infrastructure has sufficient resources to run containerized tests

**Constraints:**
- **Budget**: Limited budget for cloud resources constrains the complexity of test environments
- **Timeline**: Solution must be implemented within Q1 2025 to support upcoming release cycles
- **Team Expertise**: Limited Kubernetes experience on the team constrains orchestration options
- **Technology Standards**: Must align with existing enterprise standards for containerization
- **Resource Limits**: CI/CD agents have memory and CPU constraints that limit parallel container execution
- **Security Policies**: Container images must pass security scanning and comply with CVE policies
- **Legacy Dependencies**: Some services may have dependencies that complicate containerization

## Considered Options

### Option 1: Docker Compose with Dedicated Test Containers

This approach uses Docker Compose to orchestrate separate container instances specifically for testing, with isolated databases and caches.

**Implementation Details:**
- Create `docker-compose.test.yml` with test-specific service definitions
- Use separate PostgreSQL and Redis containers with ephemeral storage
- Implement health checks using Docker's native healthcheck capability
- Use environment variables to configure test-specific settings
- Leverage Docker networks for service isolation

**Pros:**
- **Addresses ASR-1**: Provides complete isolation from production through containerization, eliminating any risk of test data pollution in production systems
- **Addresses ASR-2**: Each test run can spawn its own isolated container set, enabling true parallel execution without database lock conflicts
- **Addresses ASR-4**: Docker Compose integrates seamlessly with CI/CD systems (GitHub Actions, GitLab CI, Jenkins) through simple commands
- **Addresses ASR-5**: Docker Compose's `depends_on` with health checks ensures proper service startup sequencing
- **Industry Standard**: Docker Compose is widely adopted, well-documented, and has extensive community support
- **Developer Experience**: Developers can run the exact same tests locally as in CI/CD, reducing "works on my machine" issues
- **Resource Efficiency**: Containers share the host kernel, making them lighter than VMs while maintaining isolation

**Cons:**
- **Learning Curve**: Requires team members to understand Docker concepts and debugging containerized applications
- **ASR-3 Complexity**: Performance testing in containers may not perfectly reflect production performance due to resource constraints and network virtualization overhead
- **Initial Setup Cost**: Significant upfront investment to containerize all services and write Docker Compose configurations
- **Docker Dependency**: Introduces hard dependency on Docker runtime availability in all environments
- **Resource Overhead**: Running multiple containers simultaneously requires adequate system resources, potentially limiting local development on lower-spec machines
- **Debugging Complexity**: Debugging failing tests inside containers can be more challenging than native processes

### Option 2: Kubernetes-Based Testing Infrastructure

This approach uses Kubernetes to orchestrate test environments with more sophisticated orchestration capabilities.

**Implementation Details:**
- Deploy test environments as Kubernetes namespaces
- Use Helm charts for parameterized deployments
- Implement Jobs for test execution
- Leverage Kubernetes Services for inter-service communication
- Use InitContainers for setup and ConfigMaps for configuration

**Pros:**
- **Addresses ASR-1**: Kubernetes namespaces provide strong isolation boundaries with network policies and resource quotas
- **Addresses ASR-2**: Kubernetes can dynamically scale test environments and provides better resource management for parallel execution
- **Addresses ASR-3**: More production-like environment for performance testing, especially if production uses Kubernetes
- **Addresses ASR-5**: Kubernetes provides sophisticated health checking, liveness probes, and readiness probes
- **Scalability**: Can easily scale to hundreds of parallel test executions
- **Production Parity**: If production uses Kubernetes, tests run in identical orchestration environment
- **Advanced Features**: Built-in service discovery, load balancing, and secret management

**Cons:**
- **Complexity Overhead**: Kubernetes has a steep learning curve and requires significant expertise to manage effectively
- **ASR-4 Friction**: More complex CI/CD integration requiring either cloud Kubernetes or local alternatives like Minikube/Kind
- **ASR-6 Challenges**: Test cleanup becomes more complex with persistent volumes and stateful sets
- **Infrastructure Requirements**: Requires either cloud Kubernetes cluster (ongoing cost) or complex local setup
- **Development Experience**: Local development becomes significantly more complex, requiring Kubernetes knowledge for debugging
- **Slower Iteration**: Container image builds and Kubernetes deployments are slower than Docker Compose
- **Overkill for Current Scale**: The system's current testing needs don't justify Kubernetes' complexity

### Option 3: Hybrid Testcontainers Approach

This approach uses the Testcontainers library to programmatically manage Docker containers from within test code.

**Implementation Details:**
- Use Testcontainers Python library to spawn containers on-demand
- Define container configurations in test code
- Implement custom wait strategies for service readiness
- Use Testcontainers' automatic cleanup mechanisms
- Leverage Testcontainers modules for common services (PostgreSQL, Redis)

**Pros:**
- **Addresses ASR-1**: Provides container isolation with fine-grained programmatic control
- **Addresses ASR-2**: Each test can spawn its own containers, ensuring perfect isolation for parallel execution
- **Addresses ASR-6**: Automatic cleanup is built into the framework, reducing test pollution risks
- **Developer Friendly**: Tests are self-contained with their infrastructure requirements defined in code
- **Flexibility**: Can mix containerized and non-containerized components as needed
- **Test-Centric**: Designed specifically for testing, not general orchestration
- **Language Integration**: Deep integration with pytest and Python testing frameworks

**Cons:**
- **ASR-4 Limitations**: Less straightforward CI/CD integration as containers are managed by test code rather than orchestration files
- **ASR-3 Challenges**: Not well-suited for comprehensive performance testing that requires stable, long-running environments
- **ASR-5 Gaps**: Health checking must be implemented in test code rather than using standard orchestration patterns
- **Docker Dependency**: Still requires Docker but adds another abstraction layer that can fail
- **Debugging Difficulty**: When tests fail, understanding container state requires debugging through Testcontainers API
- **Resource Management**: Harder to control overall resource usage when each test manages its own containers
- **Limited Orchestration**: Complex multi-service scenarios with specific networking requirements are harder to implement

## Decision & Rationale

**Decision**: Adopt a hybrid testing strategy that uses local testing for development and Docker Compose with dedicated test containers (Option 1) for CI/CD and complex integration scenarios.

### Rationale

After careful evaluation, we recognize that ViolentUTF API's architecture as a FastAPI application allows for flexible testing approaches. We will adopt a pragmatic hybrid strategy:

1. **Local Testing First**: For development and simple integration tests, developers should run the API locally and test against local endpoints. This provides the fastest feedback loop and easiest debugging experience.

2. **Docker Compose for Complex Scenarios**: Docker Compose will be used when containerization provides clear value - primarily in CI/CD pipelines, multi-service integration tests, and production validation scenarios.

**Primary Decision Drivers:**

1. **Optimal ASR Coverage**: Docker Compose adequately addresses 5 out of 6 ASRs with production-ready solutions. While it has some limitations for ASR-3 (performance testing), these can be mitigated through careful configuration and supplementary tools.

2. **Complexity-to-Value Ratio**: Docker Compose provides the right balance of sophistication and simplicity. Unlike Kubernetes (Option 2), which would introduce unnecessary complexity for our current scale, Docker Compose offers sufficient orchestration capabilities without overwhelming the team. The learning curve is manageable, and most developers already have Docker experience.

3. **CI/CD Integration Excellence**: Docker Compose's straightforward CLI interface (`docker-compose up`, `docker-compose down`) makes it trivial to integrate with any CI/CD system. This directly addresses ASR-4 with minimal configuration overhead. Both GitHub Actions and GitLab CI have first-class support for Docker Compose.

4. **Developer Experience Optimization**: The ability to run the exact same test environment locally and in CI/CD is invaluable. Developers can reproduce CI failures locally with a single command, dramatically reducing debugging time. This isn't possible with Testcontainers (Option 3), where container management is buried in test code.

5. **Proven Industry Pattern**: Docker Compose for integration testing is a well-established pattern with extensive documentation, community support, and tooling. This reduces implementation risk and provides a clear upgrade path to Kubernetes if needed in the future.

**Addressing the Trade-offs:**

While Docker Compose has limitations for performance testing (ASR-3), we can mitigate this through:
- Running performance tests against a separate, more production-like environment
- Using resource limits in Docker Compose to simulate constrained environments
- Supplementing with targeted performance testing tools when needed

The initial setup cost and Docker dependency are acceptable trade-offs given that:
- The investment pays dividends through prevented production issues
- Docker is already part of our technology stack
- The alternative (no integration testing) poses unacceptable business risk

**Why Not the Alternatives:**

**Kubernetes (Option 2)** was rejected because:
- The complexity overhead would delay implementation by months
- Our current scale doesn't justify the operational burden
- Local development would become significantly more difficult
- The team lacks Kubernetes expertise, creating knowledge risk

**Testcontainers (Option 3)** was rejected because:
- Poor fit for comprehensive integration testing scenarios
- Harder to standardize across different test types
- Less suitable for performance testing requirements
- More difficult to debug when infrastructure issues arise

### Strategic Alignment

This decision aligns with our broader architectural principles:
- **Simplicity First**: Choose the simplest solution that meets requirements
- **Developer Productivity**: Optimize for developer experience and fast feedback loops
- **Incremental Evolution**: Start with Docker Compose, potentially migrate to Kubernetes later
- **Risk Management**: Reduce production risks through comprehensive testing

## Consequences

### Technical Impact

**Positive:**
- **Standardized Testing Environment**: All developers and CI/CD systems will use identical test configurations, eliminating environment-specific test failures
- **Improved Test Reliability**: Isolated containers prevent test pollution and enable truly independent test execution
- **Faster Feedback Loops**: Developers can run integration tests locally before pushing code, catching issues earlier
- **Version Control for Infrastructure**: Test environment configuration becomes code in `docker-compose.test.yml`, enabling reviews and versioning
- **Service Health Validation**: Standardized health checks will prevent race conditions and intermittent failures

**Negative:**
- **Increased Maintenance Burden**: Docker Compose files, Dockerfiles, and health check scripts require ongoing maintenance
- **Technical Debt**: We're committing to Docker as a core technology, which will require continued investment and updates
- **Performance Testing Limitations**: Container overhead and resource constraints may mask or create performance issues not present in production
- **Debugging Complexity**: Developers must learn to debug applications running inside containers, including network and volume issues

### Operational Impact

**Positive:**
- **Reduced Production Incidents**: Comprehensive integration testing will catch issues before deployment
- **Simplified Onboarding**: New team members can spin up the entire test environment with one command
- **Consistent CI/CD Pipeline**: Automated testing becomes reliable and reproducible
- **Environment Parity**: Test environment closely mirrors production architecture

**Negative:**
- **Resource Requirements**: CI/CD agents need sufficient resources to run multiple containers
- **Docker Dependency**: All development machines and CI/CD agents must have Docker installed and maintained
- **Increased CI/CD Time**: Running containerized tests adds overhead to build times (estimated 2-3 minutes per pipeline)
- **Storage Management**: Docker images and volumes require periodic cleanup to prevent disk space issues

### Security Impact

**Positive:**
- **Isolated Test Data**: Test credentials and data are completely separated from production
- **Secrets Management**: Docker Compose secrets provide a secure way to handle test credentials
- **Network Isolation**: Docker networks prevent test traffic from affecting other systems

**Negative:**
- **Container Security**: Requires ongoing attention to container security updates and vulnerability scanning
- **Secret Sprawl**: Test secrets must be managed carefully to prevent exposure in version control
- **Attack Surface**: Docker daemon becomes a critical security component requiring hardening

### Future Decisions

This decision necessitates several follow-up architectural decisions:

1. **Test Data Management Strategy** (Required within 1 month)
   - How to generate, manage, and version test fixtures
   - Data privacy considerations for test data
   - Backup and restore strategies for complex test scenarios

2. **Performance Testing Framework** (Required within 2 months)
   - Selection of performance testing tools compatible with Docker
   - Metrics collection and storage strategy
   - Performance baseline establishment methodology

3. **Container Registry Strategy** (Required within 2 months)
   - Whether to use public or private registries for test images
   - Image versioning and tagging conventions
   - Image scanning and security policies

4. **CI/CD Resource Scaling** (Required within 3 months)
   - Determining optimal resource allocation for test containers
   - Parallel test execution strategies
   - Cost optimization for cloud-based CI/CD

5. **Migration Path to Kubernetes** (Evaluation in 12 months)
   - Criteria for determining when to migrate to Kubernetes
   - Ensuring Docker Compose configuration remains Kubernetes-compatible
   - Knowledge transfer and training requirements

### Risk Assessment

**New Risks Introduced:**
- **Single Point of Failure**: Docker daemon issues could block all testing
- **Version Compatibility**: Docker Compose file format versions may cause compatibility issues
- **Resource Exhaustion**: Improperly configured tests could consume excessive resources
- **Learning Curve Impact**: Initial productivity may decrease while team learns Docker

**Mitigated Risks:**
- **Production Data Corruption**: Eliminated through complete isolation
- **Deployment Failures**: Reduced through comprehensive pre-deployment testing
- **Integration Issues**: Caught early through automated testing
- **Performance Regressions**: Detected through automated performance baselines

## Implementation Examples

### Local Testing Setup

```python
# tests/integration/conftest.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    """Provide test client for local testing"""
    return TestClient(app)

@pytest.fixture
def base_url(request):
    """Allow overriding base URL via command line"""
    return request.config.getoption("--base-url", default="http://localhost:8000")
```

### Local Integration Test Example

```python
# tests/integration/test_api_endpoints.py
def test_health_check_local(client):
    """Test health endpoint using local test client"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_create_resource_local(client, test_db):
    """Test resource creation with local test database"""
    response = client.post("/api/resources", json={"name": "test"})
    assert response.status_code == 201
```

### Docker-Based Testing Configuration

```yaml
# docker-compose.test.yml
version: '3.8'
services:
  api:
    build: .
    environment:
      - DATABASE_URL=postgresql://test:test@db/testdb
      - REDIS_URL=redis://redis:6379
      - TESTING=true
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "8000:8000"

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=test
      - POSTGRES_PASSWORD=test
      - POSTGRES_DB=testdb
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U test"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
```

### CI/CD Integration Test Script

```bash
#!/bin/bash
# scripts/run-integration-tests.sh

# For local development (no Docker)
if [ "$1" == "local" ]; then
    echo "Running tests against local API..."
    uvicorn app.main:app --port 8000 &
    API_PID=$!
    sleep 2
    pytest tests/integration/ --base-url http://localhost:8000
    TEST_EXIT_CODE=$?
    kill $API_PID
    exit $TEST_EXIT_CODE
fi

# For CI/CD (with Docker)
echo "Starting Docker test environment..."
docker-compose -f docker-compose.test.yml up -d
echo "Waiting for services to be healthy..."
sleep 10
pytest tests/integration/ --base-url http://localhost:8000
TEST_EXIT_CODE=$?
docker-compose -f docker-compose.test.yml down -v
exit $TEST_EXIT_CODE
```

## Related Artifacts/Decisions

- GitHub Issue #23: Docker-based integration testing infrastructure requirements
- ADR-007: Async Task Processing (impacts test environment requirements)
- ADR-008: Logging and Auditing (test environment must support log aggregation)
- ADR-010: Software Dependencies (containerization strategy for dependencies)
- Future ADR: Test Data Management Strategy
- Future ADR: Performance Testing Framework
- Future ADR: Container Registry Strategy
