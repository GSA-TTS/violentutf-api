# Testing Quick Reference for ViolentUTF API Extraction

## Test Execution Flow for Each Component

### Step 1: Pre-Extraction Testing
```bash
# Before extracting any component, establish baseline
cd ../violentutf  # Mother repo
pytest violentutf_api/tests/ --cov=violentutf_api > baseline_test_report.txt
```

### Step 2: Write Tests for Improvements
```bash
# In new repo, write tests for planned improvements FIRST
cd violentutf-api

# Create test for specific improvement
cat > tests/unit/test_security_improvement.py << 'EOF'
def test_jwt_replaces_keycloak():
    """Test that JWT auth works without Keycloak"""
    # This should FAIL initially
    from app.core.auth import create_access_token
    token = create_access_token({"sub": "user-123"})
    assert token is not None
EOF

# Run test - it should fail
pytest tests/unit/test_security_improvement.py
```

### Step 3: Extract Component
```bash
# Copy component from mother repo
cp -r ../violentutf/violentutf_api/fastapi_app/app/core ./app/

# Run tests - most should fail due to missing improvements
pytest tests/unit/test_core.py -v
```

### Step 4: Implement Improvements
```bash
# Implement improvements until tests pass
# Example: Add security middleware
vim app/middleware/security.py

# Run tests continuously while implementing
pytest tests/unit/test_security_improvement.py --watch
```

### Step 5: Validate Improvements
```bash
# Run all tests for the component
pytest tests/unit/test_core.py tests/integration/test_startup.py -v

# Check coverage
pytest tests/unit/test_core.py --cov=app.core --cov-report=term-missing

# Run security tests
bandit -r app/core/
safety check
```

## Component-Specific Test Commands

### Week 1: Core Framework
```bash
# Unit tests
pytest tests/unit/test_app_factory.py -v
pytest tests/unit/test_security_middleware.py -v
pytest tests/unit/test_config.py -v
pytest tests/unit/test_error_handlers.py -v

# Integration tests
pytest tests/integration/test_app_startup.py -v

# Security scan
bandit -r app/ -f json -o security_report.json

# Type checking
mypy app/ --strict

# Coverage check
pytest tests/unit/test_core.py --cov=app.core --cov-fail-under=80
```

### Week 2: Basic Functionality
```bash
# Health endpoints
pytest tests/unit/test_health_endpoints.py -v
pytest tests/integration/test_health_integration.py -v

# Configuration
pytest tests/unit/test_enhanced_config.py -v

# Utilities
pytest tests/unit/test_logging_utils.py -v
pytest tests/unit/test_validation_utils.py -v

# Full test suite
pytest tests/ -m "not slow" --cov=app --cov-report=html
```

### Week 3: Data Layer
```bash
# Models
pytest tests/unit/test_models.py -v
pytest tests/unit/test_audit_mixin.py -v

# Repository pattern
pytest tests/unit/test_repository.py -v

# Database integration
pytest tests/integration/test_database_integration.py -v

# Migration tests
alembic upgrade head
alembic downgrade -1
alembic upgrade head

# Performance tests
pytest tests/performance/test_query_performance.py -v
```

### Week 4-5: API Endpoints
```bash
# Endpoint unit tests
pytest tests/unit/test_*_endpoints.py -v

# Integration tests
pytest tests/integration/test_api_integration.py -v

# Load tests
locust -f tests/load/locustfile.py --headless -u 100 -r 10 -t 60s

# Contract tests
pytest tests/contract/ -v

# Security tests
pytest tests/security/test_endpoint_security.py -v
```

### Week 6: Security Implementation
```bash
# Authentication tests
pytest tests/unit/test_jwt_auth.py -v
pytest tests/unit/test_api_keys.py -v

# Authorization tests
pytest tests/unit/test_rbac.py -v
pytest tests/integration/test_auth_flow.py -v

# Security integration
pytest tests/security/ -v

# Penetration testing
python tests/security/penetration_test.py

# Compliance check
pytest tests/compliance/test_gsa_requirements.py -v
```

## Continuous Testing During Development

### Watch Mode Setup
```bash
# Install pytest-watch
pip install pytest-watch

# Run tests in watch mode
ptw tests/unit/ -- -v

# Watch specific test file
ptw tests/unit/test_specific.py -- -v
```

### Test Categories
```bash
# Run by marker
pytest -m unit          # Fast unit tests
pytest -m integration   # Integration tests (may need services)
pytest -m security      # Security-focused tests
pytest -m performance   # Performance benchmarks
pytest -m slow          # Slow tests (>1s)

# Exclude slow tests for quick feedback
pytest -m "not slow"

# Run failed tests first
pytest --ff
```

### Coverage Commands
```bash
# Generate coverage report
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Show missing lines
pytest --cov=app --cov-report=term-missing

# Fail if coverage below threshold
pytest --cov=app --cov-fail-under=80

# Coverage for specific module
pytest tests/unit/test_auth.py --cov=app.core.auth
```

## Docker Testing Environment

```bash
# Start test environment (API + dependencies)
docker-compose -f docker-compose.test.yml up -d test-db test-redis test-api

# Run integration tests against dockerized API
TEST_API_URL=http://localhost:8001 pytest tests/integration/ -v

# Or run tests inside Docker
docker-compose -f docker-compose.test.yml run --rm test-runner

# View API logs during tests
docker-compose -f docker-compose.test.yml logs -f test-api

# Full test cycle
make test-integration  # Starts services, runs tests, cleans up
```

## Pre-Commit Testing

```bash
# Set up pre-commit hooks
pre-commit install

# Run all pre-commit checks
pre-commit run --all-files

# Run specific hook
pre-commit run mypy --all-files
pre-commit run pytest --all-files
```

## Test Debugging

```bash
# Run with debugger
pytest tests/unit/test_specific.py -v --pdb

# Run with more verbose output
pytest tests/unit/test_specific.py -vvs

# Run with print statements visible
pytest tests/unit/test_specific.py -s

# Run specific test method
pytest tests/unit/test_specific.py::TestClass::test_method -v

# Generate test timing report
pytest --durations=10
```

## Performance Testing

```bash
# Run benchmarks
pytest tests/performance/ --benchmark-only

# Compare benchmarks
pytest tests/performance/ --benchmark-compare

# Profile tests
pytest tests/unit/test_specific.py --profile

# Memory profiling
pytest tests/unit/test_specific.py --memray
```

## CI/CD Test Commands

```yaml
# GitHub Actions example
- name: Run unit tests
  run: pytest tests/unit -v --cov=app --cov-report=xml

- name: Run integration tests
  run: pytest tests/integration -v

- name: Check coverage
  run: pytest --cov=app --cov-fail-under=80

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Test Report Generation

```bash
# HTML report
pytest --html=test_report.html --self-contained-html

# JUnit XML (for CI/CD)
pytest --junitxml=junit.xml

# Coverage XML (for CI/CD)
pytest --cov=app --cov-report=xml

# Combined report
pytest --cov=app --cov-report=html --cov-report=term --html=report.html --junitxml=junit.xml
```

## Quick Validation Checklist

Before marking any component as complete:

```bash
# 1. All tests pass
pytest tests/ -v

# 2. Coverage meets requirement
pytest --cov=app --cov-fail-under=80

# 3. No security issues
bandit -r app/
safety check

# 4. Type hints complete
mypy app/ --strict

# 5. Code quality good
flake8 app/
black --check app/
isort --check app/

# 6. Documentation exists
pytest tests/unit/test_documentation.py -v
```

## Emergency Rollback Testing

If improvements cause issues:

```bash
# Revert to baseline
git checkout baseline-tag

# Run tests to confirm working state
pytest tests/ -v

# Cherry-pick only working improvements
git cherry-pick <commit-hash>

# Re-test
pytest tests/ -v
```

Remember: **Never merge code that doesn't pass all tests!**
