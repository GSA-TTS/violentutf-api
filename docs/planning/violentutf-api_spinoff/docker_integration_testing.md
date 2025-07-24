# Docker-Based Integration Testing Strategy

## Overview

Instead of using testcontainers, we'll run the actual ViolentUTF API in Docker for more realistic integration testing. This approach tests the real application as it would run in production.

## Docker Compose Test Environment

### docker-compose.test.yml

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  test-db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: testuser
      POSTGRES_PASSWORD: testpass
      POSTGRES_DB: violentutf_test
      POSTGRES_HOST_AUTH_METHOD: md5
    ports:
      - "5433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U testuser -d violentutf_test"]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - test-db-data:/var/lib/postgresql/data

  # Redis Cache
  test-redis:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  # ViolentUTF API
  test-api:
    build:
      context: .
      dockerfile: Dockerfile
      target: test  # Use test stage if multi-stage
    environment:
      DATABASE_URL: postgresql://testuser:testpass@test-db:5432/violentutf_test  # pragma: allowlist secret
      REDIS_URL: redis://test-redis:6379/0
      SECRET_KEY: test-secret-key-for-testing-only
      ENVIRONMENT: testing
      LOG_LEVEL: DEBUG
      # Disable external services for testing
      USE_EXTERNAL_SERVICES: "false"
      # Test-specific settings
      RATE_LIMIT_ENABLED: "false"  # Disable for testing
      ALLOW_TEST_ROUTES: "true"    # Enable test endpoints
    ports:
      - "8001:8000"
    depends_on:
      test-db:
        condition: service_healthy
      test-redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      # Mount source code for development
      - ./app:/app/app:ro
      - ./tests:/app/tests:ro
    command: >
      sh -c "
        echo 'Waiting for database...' &&
        alembic upgrade head &&
        echo 'Database ready, starting API...' &&
        uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
      "

  # Test Runner Service
  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.test
    environment:
      TEST_API_URL: http://test-api:8000
      TEST_DATABASE_URL: postgresql://testuser:testpass@test-db:5432/violentutf_test  # pragma: allowlist secret
      TEST_REDIS_URL: redis://test-redis:6379/0
      PYTHONPATH: /app
    depends_on:
      test-api:
        condition: service_healthy
    volumes:
      - ./tests:/app/tests
      - ./test-results:/app/test-results
      - ./coverage:/app/coverage
    command: >
      sh -c "
        echo 'Waiting for API to be ready...' &&
        sleep 5 &&
        pytest tests/integration -v --cov=app --cov-report=html:/app/coverage --junit-xml=/app/test-results/junit.xml
      "

volumes:
  test-db-data:

networks:
  default:
    name: violentutf-test-network
```

### Dockerfile.test

```dockerfile
# Test runner Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements-test.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-test.txt

# Copy test files
COPY tests/ tests/
COPY pyproject.toml pytest.ini ./

# Set Python path
ENV PYTHONPATH=/app

CMD ["pytest"]
```

## Integration Test Structure

### Base Integration Test Class

```python
# tests/integration/conftest.py
import pytest
import httpx
import asyncio
import os
from typing import Generator
import time

@pytest.fixture(scope="session")
def api_base_url() -> str:
    """Get API base URL from environment or default"""
    return os.getenv("TEST_API_URL", "http://localhost:8001")

@pytest.fixture(scope="session")
def api_client(api_base_url: str) -> Generator[httpx.Client, None, None]:
    """Create HTTP client for API testing"""
    with httpx.Client(base_url=api_base_url, timeout=30.0) as client:
        # Wait for API to be ready
        max_retries = 30
        for i in range(max_retries):
            try:
                response = client.get("/api/v1/health")
                if response.status_code == 200:
                    print(f"API ready after {i+1} attempts")
                    break
            except Exception as e:
                if i == max_retries - 1:
                    raise RuntimeError(f"API not ready after {max_retries} attempts: {e}")
            time.sleep(1)

        yield client

@pytest.fixture(scope="session")
async def async_api_client(api_base_url: str) -> Generator[httpx.AsyncClient, None, None]:
    """Create async HTTP client for API testing"""
    async with httpx.AsyncClient(base_url=api_base_url, timeout=30.0) as client:
        # Wait for API to be ready
        max_retries = 30
        for i in range(max_retries):
            try:
                response = await client.get("/api/v1/health")
                if response.status_code == 200:
                    break
            except Exception:
                if i == max_retries - 1:
                    raise RuntimeError("API not ready")
            await asyncio.sleep(1)

        yield client

@pytest.fixture(scope="function")
def auth_headers(api_client: httpx.Client) -> dict:
    """Get authentication headers for testing"""
    # Create test user and get token
    response = api_client.post(
        "/api/v1/auth/test-token",  # Test-only endpoint
        json={"username": "testuser", "scopes": ["read", "write"]}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def admin_headers(api_client: httpx.Client) -> dict:
    """Get admin authentication headers"""
    response = api_client.post(
        "/api/v1/auth/test-token",
        json={"username": "admin", "scopes": ["read", "write", "admin"]}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    return {"Authorization": f"Bearer {token}"}
```

### Integration Test Examples

```python
# tests/integration/test_api_flow.py
import pytest
import httpx
from typing import Dict, Any

class TestCompleteAPIFlow:
    """Test complete API workflows with real services"""

    @pytest.mark.integration
    def test_item_crud_flow(self, api_client: httpx.Client, auth_headers: dict):
        """Test complete CRUD flow for items"""
        # Create item
        create_data = {
            "name": "Integration Test Item",
            "description": "Created during integration test",
            "price": 99.99
        }

        create_response = api_client.post(
            "/api/v1/items/",
            json=create_data,
            headers=auth_headers
        )
        assert create_response.status_code == 201
        item = create_response.json()
        item_id = item["id"]

        # Verify item was created
        assert item["name"] == create_data["name"]
        assert item["price"] == create_data["price"]

        # List items
        list_response = api_client.get(
            "/api/v1/items/",
            headers=auth_headers
        )
        assert list_response.status_code == 200
        items = list_response.json()
        assert any(i["id"] == item_id for i in items["items"])

        # Get specific item
        get_response = api_client.get(
            f"/api/v1/items/{item_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 200
        retrieved_item = get_response.json()
        assert retrieved_item["id"] == item_id

        # Update item
        update_data = {"name": "Updated Item", "price": 149.99}
        update_response = api_client.put(
            f"/api/v1/items/{item_id}",
            json=update_data,
            headers=auth_headers
        )
        assert update_response.status_code == 200
        updated_item = update_response.json()
        assert updated_item["name"] == update_data["name"]
        assert updated_item["price"] == update_data["price"]

        # Delete item
        delete_response = api_client.delete(
            f"/api/v1/items/{item_id}",
            headers=auth_headers
        )
        assert delete_response.status_code == 204

        # Verify deletion
        get_deleted_response = api_client.get(
            f"/api/v1/items/{item_id}",
            headers=auth_headers
        )
        assert get_deleted_response.status_code == 404

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_concurrent_operations(
        self,
        async_api_client: httpx.AsyncClient,
        auth_headers: dict
    ):
        """Test API handles concurrent operations correctly"""
        import asyncio

        async def create_item(index: int) -> Dict[str, Any]:
            response = await async_api_client.post(
                "/api/v1/items/",
                json={
                    "name": f"Concurrent Item {index}",
                    "price": float(index * 10)
                },
                headers=auth_headers
            )
            assert response.status_code == 201
            return response.json()

        # Create 10 items concurrently
        tasks = [create_item(i) for i in range(10)]
        items = await asyncio.gather(*tasks)

        # Verify all items were created
        assert len(items) == 10
        assert all(item["id"] for item in items)

        # Clean up
        delete_tasks = [
            async_api_client.delete(
                f"/api/v1/items/{item['id']}",
                headers=auth_headers
            )
            for item in items
        ]
        await asyncio.gather(*delete_tasks)

    @pytest.mark.integration
    def test_database_transaction_rollback(
        self,
        api_client: httpx.Client,
        auth_headers: dict
    ):
        """Test that failed operations rollback properly"""
        # Try to create item with invalid data that will fail after partial processing
        invalid_data = {
            "name": "Test Item",
            "price": 100.0,
            "force_error": True  # Special flag to trigger error in processing
        }

        response = api_client.post(
            "/api/v1/items/",
            json=invalid_data,
            headers=auth_headers
        )

        # Should fail
        assert response.status_code >= 400

        # Verify no partial data was saved
        list_response = api_client.get(
            "/api/v1/items/",
            params={"search": "Test Item"},
            headers=auth_headers
        )
        items = list_response.json()["items"]
        assert not any(item["name"] == "Test Item" for item in items)
```

### Performance Integration Tests

```python
# tests/integration/test_performance.py
import pytest
import httpx
import time
from concurrent.futures import ThreadPoolExecutor
import statistics

class TestAPIPerformance:
    """Test API performance with real infrastructure"""

    @pytest.mark.integration
    @pytest.mark.performance
    def test_endpoint_latency(self, api_client: httpx.Client):
        """Test API endpoint latency"""
        latencies = []

        # Warm up
        for _ in range(5):
            api_client.get("/api/v1/health")

        # Measure latencies
        for _ in range(100):
            start = time.time()
            response = api_client.get("/api/v1/health")
            latency = (time.time() - start) * 1000  # Convert to ms

            assert response.status_code == 200
            latencies.append(latency)

        # Calculate statistics
        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile

        print(f"\nLatency Stats (ms):")
        print(f"  P50: {p50:.2f}")
        print(f"  P95: {p95:.2f}")
        print(f"  P99: {p99:.2f}")

        # Assert performance requirements
        assert p50 < 50, f"P50 latency {p50}ms exceeds 50ms target"
        assert p95 < 200, f"P95 latency {p95}ms exceeds 200ms target"
        assert p99 < 500, f"P99 latency {p99}ms exceeds 500ms target"

    @pytest.mark.integration
    @pytest.mark.performance
    def test_concurrent_load(self, api_client: httpx.Client, auth_headers: dict):
        """Test API under concurrent load"""
        def make_request(i: int) -> tuple[int, float]:
            start = time.time()
            response = api_client.get(
                f"/api/v1/items/",
                params={"page": i % 10},
                headers=auth_headers
            )
            duration = time.time() - start
            return response.status_code, duration

        # Run concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(make_request, range(100)))

        # Analyze results
        status_codes = [r[0] for r in results]
        durations = [r[1] for r in results]

        # All requests should succeed
        assert all(code == 200 for code in status_codes), \
            f"Failed requests: {status_codes.count(500)}"

        # Check performance under load
        avg_duration = statistics.mean(durations)
        max_duration = max(durations)

        print(f"\nLoad Test Results:")
        print(f"  Average response time: {avg_duration*1000:.2f}ms")
        print(f"  Max response time: {max_duration*1000:.2f}ms")

        assert avg_duration < 0.5, f"Average response time {avg_duration}s exceeds 500ms"
        assert max_duration < 2.0, f"Max response time {max_duration}s exceeds 2s"
```

## Running Integration Tests

### Local Development

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d test-db test-redis test-api

# Wait for services to be ready
docker-compose -f docker-compose.test.yml ps

# Run integration tests locally
TEST_API_URL=http://localhost:8001 pytest tests/integration -v

# Or run tests in Docker
docker-compose -f docker-compose.test.yml run --rm test-runner

# View logs
docker-compose -f docker-compose.test.yml logs -f test-api

# Stop services
docker-compose -f docker-compose.test.yml down -v
```

### CI/CD Pipeline

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Build test images
      run: docker-compose -f docker-compose.test.yml build

    - name: Start test environment
      run: docker-compose -f docker-compose.test.yml up -d test-db test-redis test-api

    - name: Wait for services
      run: |
        timeout 60 bash -c 'until docker-compose -f docker-compose.test.yml ps | grep -q "healthy"; do sleep 1; done'

    - name: Run integration tests
      run: docker-compose -f docker-compose.test.yml run --rm test-runner

    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: |
          test-results/
          coverage/

    - name: Stop services
      if: always()
      run: docker-compose -f docker-compose.test.yml down -v
```

### Makefile for Convenience

```makefile
# Makefile
.PHONY: test-integration test-integration-local test-integration-docker

# Run integration tests locally (requires services running)
test-integration-local:
	TEST_API_URL=http://localhost:8001 pytest tests/integration -v

# Run integration tests in Docker
test-integration-docker:
	docker-compose -f docker-compose.test.yml run --rm test-runner

# Full integration test (start services, run tests, cleanup)
test-integration:
	@echo "Starting test environment..."
	docker-compose -f docker-compose.test.yml up -d test-db test-redis test-api
	@echo "Waiting for services to be ready..."
	@timeout 60 bash -c 'until docker-compose -f docker-compose.test.yml ps | grep -q "healthy"; do sleep 1; done'
	@echo "Running integration tests..."
	docker-compose -f docker-compose.test.yml run --rm test-runner
	@echo "Cleaning up..."
	docker-compose -f docker-compose.test.yml down -v

# View test logs
test-logs:
	docker-compose -f docker-compose.test.yml logs -f

# Clean up test environment
test-clean:
	docker-compose -f docker-compose.test.yml down -v
	rm -rf test-results/ coverage/
```

## Best Practices

1. **Use Health Checks**: Always wait for services to be healthy before running tests
2. **Isolate Test Data**: Use separate test database that can be reset
3. **Clean Up**: Always clean up test data after tests
4. **Parallel Safety**: Design tests to run in parallel when possible
5. **Realistic Testing**: Test with real service configurations
6. **Performance Baselines**: Include performance tests to catch regressions
7. **Error Scenarios**: Test failure cases and error handling

## Advantages Over Testcontainers

1. **More Realistic**: Tests the actual Docker image that will be deployed
2. **Simpler Setup**: No need for additional test container libraries
3. **Better Debugging**: Can inspect running containers during test failures
4. **Shared Environment**: Multiple test runners can use same services
5. **Production-Like**: Uses same docker-compose patterns as production
6. **Better Performance**: Services stay running between test runs in development

This approach provides comprehensive integration testing that closely mimics production behavior while being simple to set up and maintain.
