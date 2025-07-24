# Testing Guide for Specific Improvements

## Overview

This guide provides concrete test examples for each type of improvement being made during the extraction process. Each improvement should be validated through specific tests before being considered complete.

## Security Improvements Testing

### 1. Input Validation Testing

```python
# tests/unit/test_input_validation.py
import pytest
from pydantic import ValidationError
from app.schemas.item import ItemCreate

class TestInputValidation:
    """Test input validation improvements"""

    @pytest.mark.parametrize("invalid_name", [
        "",  # Empty string
        " ",  # Whitespace only
        "a" * 256,  # Too long
        "<script>alert('xss')</script>",  # XSS attempt
        "'; DROP TABLE items; --",  # SQL injection
        None,  # Null value
    ])
    def test_invalid_item_name(self, invalid_name):
        """Test that invalid names are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            ItemCreate(name=invalid_name, price=10.0)

        errors = exc_info.value.errors()
        assert any(error["loc"] == ("name",) for error in errors)

    @pytest.mark.parametrize("invalid_price", [
        -1.0,  # Negative price
        0.0,   # Zero price
        float('inf'),  # Infinity
        "not_a_number",  # String
        None,  # Null
    ])
    def test_invalid_item_price(self, invalid_price):
        """Test that invalid prices are rejected"""
        with pytest.raises(ValidationError):
            ItemCreate(name="Valid Name", price=invalid_price)

    def test_sanitization_of_html_content(self):
        """Test HTML content is properly sanitized"""
        from app.utils.sanitization import sanitize_html

        dangerous_input = '<script>alert("xss")</script><p>Safe content</p>'
        sanitized = sanitize_html(dangerous_input)

        assert '<script>' not in sanitized
        assert '<p>Safe content</p>' in sanitized
```

### 2. Authentication Testing

```python
# tests/unit/test_jwt_auth.py
import pytest
from datetime import datetime, timedelta
from jose import jwt
from app.core.auth import (
    create_access_token,
    create_refresh_token,
    verify_access_token,
    verify_refresh_token
)

class TestJWTAuthentication:
    """Test JWT implementation replacing Keycloak"""

    def test_access_token_creation_and_validation(self):
        """Test access token lifecycle"""
        user_data = {
            "sub": "user-123",
            "email": "user@example.com",
            "roles": ["user", "admin"]
        }

        # Create token
        access_token = create_access_token(user_data)

        # Verify token
        decoded = verify_access_token(access_token)
        assert decoded["sub"] == user_data["sub"]
        assert decoded["email"] == user_data["email"]
        assert decoded["roles"] == user_data["roles"]
        assert decoded["type"] == "access"

    def test_refresh_token_rotation(self):
        """Test refresh token rotation for security"""
        user_id = "user-123"

        # Create initial refresh token
        refresh_token_1 = create_refresh_token(user_id)

        # Use refresh token to get new tokens
        decoded = verify_refresh_token(refresh_token_1)
        assert decoded["sub"] == user_id

        # Create new refresh token (rotation)
        refresh_token_2 = create_refresh_token(user_id)

        # Old refresh token should be invalidated
        with pytest.raises(Exception):
            verify_refresh_token(refresh_token_1)

    def test_token_expiration_enforcement(self):
        """Test that expired tokens are rejected"""
        # Create token that expires in 1 second
        token = create_access_token(
            {"sub": "user-123"},
            expires_delta=timedelta(seconds=1)
        )

        # Token should be valid immediately
        assert verify_access_token(token) is not None

        # Wait for expiration
        import time
        time.sleep(2)

        # Token should now be invalid
        with pytest.raises(Exception):
            verify_access_token(token)
```

### 3. Security Headers Testing

```python
# tests/integration/test_security_headers.py
import pytest
from fastapi.testclient import TestClient

class TestSecurityHeaders:
    """Test security headers implementation"""

    def test_all_security_headers_present(self, client):
        """Test that all required security headers are present"""
        response = client.get("/api/v1/health")

        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }

        for header, expected_value in required_headers.items():
            assert header in response.headers
            assert expected_value in response.headers[header]

    def test_cors_configuration(self, client):
        """Test CORS is properly configured"""
        # Test preflight request
        response = client.options(
            "/api/v1/items",
            headers={
                "Origin": "https://allowed-origin.com",
                "Access-Control-Request-Method": "POST"
            }
        )

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
```

## Reliability Improvements Testing

### 1. Circuit Breaker Testing

```python
# tests/unit/test_circuit_breaker.py
import pytest
from unittest.mock import Mock, patch
import asyncio
from app.utils.circuit_breaker import CircuitBreaker

class TestCircuitBreaker:
    """Test circuit breaker implementation"""

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures"""
        breaker = CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=5,
            expected_exception=Exception
        )

        # Mock failing service
        async def failing_service():
            raise Exception("Service unavailable")

        # First 3 calls should fail normally
        for i in range(3):
            with pytest.raises(Exception):
                await breaker.call(failing_service)

        # Circuit should now be open
        assert breaker.state == "open"

        # Next call should fail immediately without calling service
        with pytest.raises(Exception) as exc_info:
            await breaker.call(failing_service)

        assert "Circuit breaker is open" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery after timeout"""
        breaker = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1  # 100ms for testing
        )

        # Open the circuit
        async def failing_service():
            raise Exception("Fail")

        with pytest.raises(Exception):
            await breaker.call(failing_service)

        assert breaker.state == "open"

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Circuit should be half-open
        assert breaker.state == "half-open"

        # Successful call should close circuit
        async def working_service():
            return "Success"

        result = await breaker.call(working_service)
        assert result == "Success"
        assert breaker.state == "closed"
```

### 2. Retry Logic Testing

```python
# tests/unit/test_retry_logic.py
import pytest
from unittest.mock import Mock, AsyncMock
import asyncio
from app.utils.retry import retry_async

class TestRetryLogic:
    """Test retry logic with exponential backoff"""

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self):
        """Test retry succeeds after transient failures"""
        call_count = 0

        @retry_async(max_attempts=3, backoff_factor=0.1)
        async def flaky_operation():
            nonlocal call_count
            call_count += 1

            if call_count < 3:
                raise ConnectionError("Transient error")

            return "Success"

        result = await flaky_operation()
        assert result == "Success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exponential_backoff_timing(self):
        """Test exponential backoff increases wait time"""
        attempt_times = []

        @retry_async(max_attempts=4, backoff_factor=0.1)
        async def failing_operation():
            attempt_times.append(asyncio.get_event_loop().time())
            raise ConnectionError("Fail")

        with pytest.raises(ConnectionError):
            await failing_operation()

        # Verify exponential backoff
        assert len(attempt_times) == 4

        # Calculate delays between attempts
        delays = [
            attempt_times[i] - attempt_times[i-1]
            for i in range(1, len(attempt_times))
        ]

        # Each delay should be roughly double the previous
        for i in range(1, len(delays)):
            assert delays[i] > delays[i-1] * 1.5
```

### 3. Health Check Testing

```python
# tests/integration/test_health_checks.py
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

class TestHealthChecks:
    """Test comprehensive health check implementation"""

    @pytest.mark.integration
    def test_liveness_always_returns_200(self, client):
        """Test liveness probe always returns 200 when app is running"""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    @pytest.mark.integration
    def test_readiness_checks_all_dependencies(self, client):
        """Test readiness checks all critical dependencies"""
        with patch('app.api.endpoints.health.check_database') as mock_db:
            with patch('app.api.endpoints.health.check_cache') as mock_cache:
                with patch('app.api.endpoints.health.check_disk_space') as mock_disk:
                    # All healthy
                    mock_db.return_value = AsyncMock(return_value=True)()
                    mock_cache.return_value = AsyncMock(return_value=True)()
                    mock_disk.return_value = True

                    response = client.get("/api/v1/ready")
                    assert response.status_code == 200
                    data = response.json()
                    assert data["status"] == "ready"
                    assert all(data["checks"].values())

    @pytest.mark.integration
    def test_readiness_fails_when_dependency_down(self, client):
        """Test readiness returns 503 when dependency is down"""
        with patch('app.api.endpoints.health.check_database') as mock_db:
            mock_db.return_value = AsyncMock(return_value=False)()

            response = client.get("/api/v1/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "not ready"
            assert not data["checks"]["database"]
            assert "database" in data["details"]["failed_checks"]
```

## Performance Improvements Testing

### 1. Caching Testing

```python
# tests/unit/test_caching.py
import pytest
from unittest.mock import Mock, patch
import time
from app.utils.cache import cached, cache_client

class TestCaching:
    """Test caching implementation"""

    @pytest.mark.asyncio
    async def test_cache_decorator_prevents_repeated_calls(self):
        """Test that cache decorator prevents repeated function calls"""
        call_count = 0

        @cached(ttl=60)
        async def expensive_operation(param: str):
            nonlocal call_count
            call_count += 1
            return f"Result for {param}"

        # First call should execute function
        result1 = await expensive_operation("test")
        assert result1 == "Result for test"
        assert call_count == 1

        # Second call should use cache
        result2 = await expensive_operation("test")
        assert result2 == "Result for test"
        assert call_count == 1  # No additional calls

        # Different parameter should execute function
        result3 = await expensive_operation("different")
        assert result3 == "Result for different"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_cache_expiration(self):
        """Test cache expiration after TTL"""
        call_count = 0

        @cached(ttl=0.1)  # 100ms TTL for testing
        async def short_ttl_operation():
            nonlocal call_count
            call_count += 1
            return call_count

        # First call
        result1 = await short_ttl_operation()
        assert result1 == 1

        # Call within TTL
        result2 = await short_ttl_operation()
        assert result2 == 1  # Cached result

        # Wait for expiration
        await asyncio.sleep(0.2)

        # Call after TTL
        result3 = await short_ttl_operation()
        assert result3 == 2  # New execution
```

### 2. Pagination Testing

```python
# tests/unit/test_pagination.py
import pytest
from app.schemas.pagination import PaginationParams, paginate_query

class TestPagination:
    """Test pagination implementation"""

    def test_pagination_params_validation(self):
        """Test pagination parameter validation"""
        # Valid params
        params = PaginationParams(page=1, size=20)
        assert params.skip == 0
        assert params.limit == 20

        params = PaginationParams(page=3, size=10)
        assert params.skip == 20  # (3-1) * 10
        assert params.limit == 10

        # Invalid params should use defaults
        params = PaginationParams(page=0, size=1000)
        assert params.page == 1  # Minimum page
        assert params.size == 100  # Maximum size

    def test_cursor_pagination(self):
        """Test cursor-based pagination"""
        from app.utils.pagination import CursorPaginator

        items = [{"id": i, "name": f"Item {i}"} for i in range(100)]
        paginator = CursorPaginator(items, page_size=10)

        # First page
        page1 = paginator.get_page()
        assert len(page1.items) == 10
        assert page1.has_next
        assert not page1.has_previous
        assert page1.next_cursor is not None

        # Next page using cursor
        page2 = paginator.get_page(cursor=page1.next_cursor)
        assert len(page2.items) == 10
        assert page2.items[0]["id"] == 10
        assert page2.has_previous
        assert page2.previous_cursor is not None
```

### 3. Query Optimization Testing

```python
# tests/integration/test_query_optimization.py
import pytest
from sqlalchemy import event
from app.db.session import SessionLocal
from app.models.item import Item

class TestQueryOptimization:
    """Test database query optimizations"""

    @pytest.mark.integration
    def test_query_uses_indexes(self, db_session):
        """Test that queries use proper indexes"""
        queries_executed = []

        # Capture executed queries
        @event.listens_for(db_session.bind, "before_execute")
        def receive_before_execute(conn, clauseelement, multiparams, params):
            queries_executed.append(str(clauseelement))

        # Execute query that should use index
        items = db_session.query(Item).filter(
            Item.is_deleted == False,
            Item.created_at > "2024-01-01"
        ).limit(10).all()

        # Verify index usage (PostgreSQL specific)
        explain_query = f"EXPLAIN {queries_executed[-1]}"
        result = db_session.execute(explain_query).fetchall()

        # Check that index scan is used
        explain_text = " ".join([row[0] for row in result])
        assert "Index Scan" in explain_text or "Bitmap Index Scan" in explain_text

    @pytest.mark.integration
    def test_n_plus_one_prevention(self, db_session):
        """Test that N+1 queries are prevented"""
        from sqlalchemy.orm import joinedload

        queries_executed = []

        @event.listens_for(db_session.bind, "before_execute")
        def count_queries(conn, clauseelement, multiparams, params):
            queries_executed.append(str(clauseelement))

        # Query with eager loading
        items = db_session.query(Item).options(
            joinedload(Item.category),
            joinedload(Item.tags)
        ).limit(10).all()

        # Access related data
        for item in items:
            _ = item.category.name
            _ = [tag.name for tag in item.tags]

        # Should only have 1-3 queries (not 10+)
        assert len(queries_executed) <= 3
```

## Code Quality Testing

### 1. Type Hints Testing

```python
# tests/unit/test_type_hints.py
import pytest
import ast
import inspect
from pathlib import Path

class TestTypeHints:
    """Test that all functions have proper type hints"""

    def test_all_functions_have_type_hints(self):
        """Test 100% type hint coverage"""
        app_path = Path("app")
        files_missing_hints = []

        for py_file in app_path.rglob("*.py"):
            with open(py_file) as f:
                tree = ast.parse(f.read())

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Check return type
                    if node.returns is None and node.name != "__init__":
                        files_missing_hints.append(
                            f"{py_file}:{node.name} missing return type"
                        )

                    # Check argument types
                    for arg in node.args.args:
                        if arg.annotation is None and arg.arg != "self":
                            files_missing_hints.append(
                                f"{py_file}:{node.name} arg '{arg.arg}' missing type"
                            )

        assert not files_missing_hints, \
            f"Missing type hints:\n" + "\n".join(files_missing_hints)

    def test_type_hints_are_runtime_checkable(self):
        """Test that type hints can be validated at runtime"""
        from app.schemas.item import ItemCreate
        from pydantic import ValidationError

        # Should work with correct types
        item = ItemCreate(name="Test", price=10.5)
        assert item.name == "Test"

        # Should fail with incorrect types
        with pytest.raises(ValidationError):
            ItemCreate(name=123, price="not a number")
```

### 2. Documentation Testing

```python
# tests/unit/test_documentation.py
import pytest
import inspect
from pathlib import Path

class TestDocumentation:
    """Test documentation completeness"""

    def test_all_endpoints_have_docstrings(self):
        """Test that all API endpoints have docstrings"""
        from app.api import endpoints

        missing_docs = []

        for module_name in dir(endpoints):
            module = getattr(endpoints, module_name)

            if inspect.ismodule(module):
                for name, obj in inspect.getmembers(module):
                    if name.startswith("router"):
                        # Check all routes in router
                        for route in obj.routes:
                            if not route.endpoint.__doc__:
                                missing_docs.append(
                                    f"{module_name}.{route.endpoint.__name__}"
                                )

        assert not missing_docs, \
            f"Endpoints missing documentation:\n" + "\n".join(missing_docs)

    def test_openapi_documentation_complete(self, client):
        """Test OpenAPI documentation is complete"""
        response = client.get("/api/v1/openapi.json")
        openapi = response.json()

        # Check all endpoints have descriptions
        for path, methods in openapi["paths"].items():
            for method, details in methods.items():
                assert "description" in details, \
                    f"{method.upper()} {path} missing description"

                # Check parameters are documented
                if "parameters" in details:
                    for param in details["parameters"]:
                        assert "description" in param, \
                            f"Parameter {param['name']} missing description"
```

## Testing Checklist for Each Phase

### Phase 1: Core Framework
- [ ] Security middleware tests passing
- [ ] Configuration validation tests passing
- [ ] Error handling tests passing
- [ ] Startup/shutdown tests passing
- [ ] All middleware integration tests passing

### Phase 2: Basic Functionality
- [ ] Health endpoint tests passing
- [ ] Configuration system tests passing
- [ ] Utility function tests passing
- [ ] Logging security tests passing

### Phase 3: Data Layer
- [ ] Model validation tests passing
- [ ] Audit field tests passing
- [ ] Soft delete tests passing
- [ ] Transaction tests passing
- [ ] Query optimization tests passing

### Phase 4-5: API Endpoints
- [ ] Input validation tests passing
- [ ] Pagination tests passing
- [ ] Rate limiting tests passing
- [ ] Idempotency tests passing
- [ ] Cache tests passing

### Phase 6: Security
- [ ] JWT authentication tests passing
- [ ] Authorization tests passing
- [ ] Security header tests passing
- [ ] Penetration tests passing
- [ ] Compliance tests passing

## Continuous Testing Commands

```bash
# Run all tests with coverage
pytest --cov=app --cov-report=html

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m security      # Security tests only
pytest -m performance   # Performance tests only

# Run tests in parallel
pytest -n auto

# Run tests with detailed output
pytest -vvs

# Run tests and stop on first failure
pytest -x

# Run only tests that failed last time
pytest --lf

# Run tests matching pattern
pytest -k "test_security"

# Generate test report
pytest --html=report.html --self-contained-html
```

## Test Report Template

After each phase, generate a test report:

```markdown
# Test Report - Phase X: [Component Name]

## Summary
- Total Tests: XXX
- Passed: XXX
- Failed: X
- Coverage: XX%

## Improvements Validated
- ✅ Security: [List improvements tested]
- ✅ Reliability: [List improvements tested]
- ✅ Performance: [List improvements tested]
- ✅ Quality: [List improvements tested]

## Metrics
- Response Time: XXms (improved from XXXms)
- Memory Usage: XXX MB (reduced from XXX MB)
- Security Issues: 0 (fixed X issues)

## Next Steps
- [ ] Address any failing tests
- [ ] Improve coverage to reach target
- [ ] Document test findings
```
