# Docker Test Environment Documentation

## Overview

This document describes the Docker-based integration testing infrastructure implemented according to ADR-012. The infrastructure supports both local development and CI/CD pipeline testing with complete isolation from production environments.

## Quick Start

### Running Tests with Docker

```bash
# Run integration tests (default)
./scripts/run_docker_tests.sh

# Run specific test suites
./scripts/run_docker_tests.sh unit
./scripts/run_docker_tests.sh integration
./scripts/run_docker_tests.sh bdd
./scripts/run_docker_tests.sh performance
./scripts/run_docker_tests.sh architecture

# Run all tests
./scripts/run_docker_tests.sh all

# Run tests with additional pytest arguments
./scripts/run_docker_tests.sh integration -v --tb=short

# Clean up Docker containers
./scripts/run_docker_tests.sh cleanup
```

### Running Tests Locally (Without Docker)

For rapid development feedback, you can run tests against a local API instance:

```bash
# Start the API locally
uvicorn app.main:app --reload --port 8000

# In another terminal, run tests
./scripts/run_docker_tests.sh local

# Or directly with pytest
pytest tests/integration/ --base-url http://localhost:8000
```

## Architecture

### Service Components

The Docker test environment consists of the following services:

1. **PostgreSQL Database (`db`)**
   - Image: `postgres:15-alpine`
   - Database: `testdb`
   - Port: 5433 (to avoid conflicts)
   - Storage: Ephemeral (tmpfs)
   - Memory: 512MB limit

2. **Redis Cache (`redis`)**
   - Image: `redis:7-alpine`
   - Port: 6380 (to avoid conflicts)
   - Database: 1 (test-specific)
   - Storage: Ephemeral (no persistence)
   - Memory: 256MB limit

3. **API Service (`api`)**
   - Built from Dockerfile
   - Port: 8000
   - Environment: Test mode enabled
   - Memory: 1GB limit
   - Auto-runs migrations

4. **Celery Worker (`celery_worker`)**
   - For async task processing (ADR-007)
   - Concurrency: 2 workers
   - Memory: 512MB limit

5. **Celery Beat (`celery_beat`)**
   - For scheduled tasks
   - Memory: 256MB limit

### Network Isolation

All services run on an isolated `test_network` to prevent interference with production or development environments.

### Health Checks

Each service implements health checks according to ADR-012 ASR-5:

- **PostgreSQL**: Uses `pg_isready` command
- **Redis**: Uses `redis-cli ping`
- **API**: HTTP health endpoint check
- **Celery**: Uses `celery inspect ping`

Services are configured with dependencies to ensure proper startup order.

## Configuration

### Environment Variables

Test-specific environment variables are defined in `.env.test`:

```bash
# Core settings
TESTING=true
ENV=test

# Database
DATABASE_URL=postgresql://test:test@localhost:5433/testdb

# Redis
REDIS_URL=redis://localhost:6380/1

# Test credentials
TEST_API_KEY=test_api_key_123456789
TEST_ADMIN_API_KEY=test_admin_key_987654321

# Parallel test support
TEST_RUN_ID=${TEST_RUN_ID:-default}
PARALLEL_TEST_WORKER=${PARALLEL_TEST_WORKER:-1}
```

### Resource Limits

Resource limits are configured for CI/CD sustainability:

| Service | Memory | CPU |
|---------|--------|-----|
| API | 1GB | 1.0 |
| PostgreSQL | 512MB | 0.5 |
| Redis | 256MB | 0.25 |
| Celery Worker | 512MB | 0.5 |
| Celery Beat | 256MB | 0.25 |

Total: <2.5GB RAM, 2.5 CPUs (within CI/CD limits)

## Test Organization

### Test Structure

```
tests/
├── unit/              # Unit tests
├── integration/       # Integration tests
│   └── docker/       # Docker-specific tests
├── bdd/              # BDD/Gherkin tests
│   ├── features/     # Feature files
│   └── steps/        # Step definitions
├── performance/      # Performance tests
├── security/         # Security tests
└── architecture/     # Architecture compliance tests
```

### Test Types

1. **Unit Tests**: Fast, isolated tests of individual components
2. **Integration Tests**: Test service interactions
3. **BDD Tests**: Business-driven acceptance tests
4. **Performance Tests**: Load and stress testing
5. **Architecture Tests**: ADR compliance validation

## Parallel Test Execution

The infrastructure supports parallel test execution (ADR-012 ASR-2):

```bash
# Run tests in parallel with pytest-xdist
pytest tests/integration/ -n 4

# Each worker gets a unique TEST_RUN_ID
export TEST_RUN_ID="test_$(date +%s)_$$"
```

## CI/CD Integration

The Docker test environment is designed for CI/CD pipelines (ADR-012 ASR-4):

### GitHub Actions Example

```yaml
name: Integration Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Docker Tests
        run: |
          ./scripts/run_docker_tests.sh integration

      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: test-results/
```

## Performance Baselines

According to ADR-012 requirements:

- **Startup**: All services must start within 30 seconds
- **Health Checks**: All services must be healthy within 60 seconds
- **API Response**: 95% of requests must complete within 500ms
- **Total Pipeline**: Must complete within 15 minutes

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Check for port usage
   lsof -i :5433  # PostgreSQL
   lsof -i :6380  # Redis
   lsof -i :8000  # API
   ```

2. **Container Cleanup**
   ```bash
   # Force cleanup
   docker-compose -f docker-compose.test.yml down -v --remove-orphans
   docker system prune -f
   ```

3. **View Logs**
   ```bash
   # View all service logs
   docker-compose -f docker-compose.test.yml logs

   # View specific service logs
   docker-compose -f docker-compose.test.yml logs api
   ```

4. **Debug Failed Tests**
   ```bash
   # Run with verbose output
   ./scripts/run_docker_tests.sh integration -v --tb=long

   # Keep containers running after tests
   docker-compose -f docker-compose.test.yml up -d
   pytest tests/integration/ --base-url http://localhost:8000
   ```

## Security Considerations

1. **Test Credentials**: All test credentials are clearly marked and different from production
2. **No Production Data**: Test environment cannot access production databases
3. **Ephemeral Storage**: No data persists between test runs
4. **Network Isolation**: Test network is isolated from other Docker networks

## Best Practices

1. **Clean State**: Always start tests with a clean environment
2. **Isolation**: Each test should be independent and not rely on others
3. **Fixtures**: Use pytest fixtures for test data management
4. **Cleanup**: Always clean up resources after tests
5. **Logging**: Use structured logging with correlation IDs

## Related Documentation

- [ADR-012: Docker Integration Testing](../architecture/ADRs/ADR-012-docker-integration-testing.md)
- [Integration Test Infrastructure](./INTEGRATION_TEST_INFRASTRUCTURE.md)
- [CI/CD Multi-Layer Testing](../CI_CD_MULTI_LAYER_TESTING.md)

## Future Enhancements

1. **Kubernetes Support**: Migration path for K8s-based testing
2. **Test Data Management**: Advanced fixture management system
3. **Performance Monitoring**: Real-time performance metrics dashboard
4. **Container Registry**: Private registry for test images
5. **Distributed Testing**: Support for distributed test execution
