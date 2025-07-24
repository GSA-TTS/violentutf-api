# Comprehensive Testing Strategy for ViolentUTF API Extraction

## Overview

This document outlines the testing strategy for each phase of the ViolentUTF API extraction, ensuring all improvements and objectives are validated through comprehensive unit and integration testing.

## Testing Principles

1. **Test-Driven Enhancement**: Write tests for improvements before implementing them
2. **Progressive Testing**: Build test suites incrementally with each component
3. **Isolation Testing**: Test each component in isolation before integration
4. **Continuous Validation**: Run tests continuously during extraction
5. **Coverage Requirements**: Maintain minimum 80% code coverage, target 95%

## Testing Infrastructure Setup

### Initial Test Framework Configuration

```bash
# Install testing dependencies
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-timeout
pip install httpx  # For FastAPI testing
pip install factory-boy faker  # For test data generation
pip install pytest-benchmark  # For performance testing
pip install pytest-xdist  # For parallel test execution
# Note: For integration tests, we'll run the actual API in Docker
# No need for testcontainers - just docker-compose

# Create pytest configuration
cat > pytest.ini << 'EOF'
[tool:pytest]
minversion = 6.0
addopts =
    -ra
    -q
    --strict-markers
    --cov=app
    --cov-branch
    --cov-report=term-missing:skip-covered
    --cov-fail-under=80
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests (fast, isolated)
    integration: Integration tests (may require external services)
    security: Security-focused tests
    performance: Performance benchmarks
    slow: Tests that take > 1s to run
asyncio_mode = auto
EOF

# Create test structure
mkdir -p tests/{unit,integration,security,performance,fixtures,factories,utils}
touch tests/__init__.py
touch tests/conftest.py
```

## Phase 1: Core Framework Testing (Week 1)

### Unit Tests for Core Framework

#### 1. Application Factory Tests
```python
# tests/unit/test_app_factory.py
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import create_application
from app.core.config import Settings

class TestApplicationFactory:
    """Test the FastAPI application factory"""

    def test_app_creation(self):
        """Test that application is created correctly"""
        app = create_application()
        assert isinstance(app, FastAPI)
        assert app.title == "ViolentUTF API"

    def test_app_has_correct_middleware(self):
        """Test that all required middleware are configured"""
        app = create_application()
        middleware_names = [m.__class__.__name__ for m in app.middleware]

        assert "SecurityHeadersMiddleware" in str(middleware_names)
        assert "CORSMiddleware" in str(middleware_names)
        assert "GZipMiddleware" in str(middleware_names)

    def test_app_routes_configured(self):
        """Test that routes are properly configured"""
        app = create_application()
        routes = [route.path for route in app.routes]

        assert "/api/v1/openapi.json" in routes
        assert "/api/v1/docs" in routes

    @pytest.mark.parametrize("env_name,expected_debug", [
        ("production", False),
        ("development", True),
        ("testing", True),
    ])
    def test_app_debug_mode(self, monkeypatch, env_name, expected_debug):
        """Test debug mode based on environment"""
        monkeypatch.setenv("ENVIRONMENT", env_name)
        app = create_application()
        assert app.debug == expected_debug
```

#### 2. Security Middleware Tests
```python
# tests/unit/test_security_middleware.py
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.middleware.security import SecurityHeadersMiddleware

class TestSecurityMiddleware:
    """Test security headers middleware"""

    @pytest.fixture
    def app_with_security(self):
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/test")
        def test_endpoint():
            return {"message": "test"}

        return app

    def test_security_headers_present(self, app_with_security):
        """Test that security headers are added to responses"""
        client = TestClient(app_with_security)
        response = client.get("/test")

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert "Strict-Transport-Security" in response.headers

    def test_csp_header_configuration(self, app_with_security):
        """Test Content Security Policy configuration"""
        client = TestClient(app_with_security)
        response = client.get("/test")

        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
```

#### 3. Configuration Tests
```python
# tests/unit/test_config.py
import pytest
from pydantic import ValidationError
from app.core.config import Settings

class TestConfiguration:
    """Test configuration validation and loading"""

    def test_valid_configuration(self, monkeypatch):
        """Test loading valid configuration"""
        monkeypatch.setenv("SECRET_KEY", "test-secret-key")
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")  # pragma: allowlist secret

        settings = Settings()
        assert settings.SECRET_KEY.get_secret_value() == "test-secret-key"
        assert settings.DATABASE_URL == "postgresql://user:pass@localhost/db"  # pragma: allowlist secret

    def test_invalid_database_url(self, monkeypatch):
        """Test that invalid database URLs are rejected"""
        monkeypatch.setenv("SECRET_KEY", "test-secret-key")
        monkeypatch.setenv("DATABASE_URL", "mysql://user:pass@localhost/db")  # pragma: allowlist secret

        with pytest.raises(ValidationError) as exc_info:
            Settings()

        assert "Invalid database URL" in str(exc_info.value)

    def test_missing_required_settings(self):
        """Test that missing required settings raise errors"""
        with pytest.raises(ValidationError) as exc_info:
            Settings()

        assert "SECRET_KEY" in str(exc_info.value)

    @pytest.mark.parametrize("log_level", ["DEBUG", "INFO", "WARNING", "ERROR"])
    def test_log_level_validation(self, monkeypatch, log_level):
        """Test log level validation"""
        monkeypatch.setenv("SECRET_KEY", "test-secret-key")
        monkeypatch.setenv("LOG_LEVEL", log_level)

        settings = Settings()
        assert settings.LOG_LEVEL == log_level
```

#### 4. Error Handler Tests
```python
# tests/unit/test_error_handlers.py
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.core.errors import setup_exception_handlers

class TestErrorHandlers:
    """Test custom error handlers"""

    @pytest.fixture
    def app_with_handlers(self):
        app = FastAPI()
        setup_exception_handlers(app)

        @app.get("/http_error")
        def http_error():
            raise HTTPException(status_code=404, detail="Not found")

        @app.get("/validation_error")
        def validation_error():
            raise ValueError("Invalid input")

        @app.get("/generic_error")
        def generic_error():
            raise Exception("Something went wrong")

        return app

    def test_http_exception_handler(self, app_with_handlers):
        """Test HTTP exception handling"""
        client = TestClient(app_with_handlers)
        response = client.get("/http_error")

        assert response.status_code == 404
        assert response.json()["detail"] == "Not found"
        assert "request_id" in response.json()

    def test_validation_error_handler(self, app_with_handlers):
        """Test validation error handling"""
        client = TestClient(app_with_handlers)
        response = client.get("/validation_error")

        assert response.status_code == 422
        assert "Invalid input" in response.json()["detail"]

    def test_generic_error_handler(self, app_with_handlers):
        """Test generic error handling"""
        client = TestClient(app_with_handlers)
        response = client.get("/generic_error")

        assert response.status_code == 500
        assert response.json()["detail"] == "Internal server error"
```

### Integration Tests for Core Framework

```python
# tests/integration/test_app_startup.py
import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app

class TestApplicationStartup:
    """Test application startup and shutdown"""

    @pytest.mark.integration
    async def test_app_startup_shutdown(self):
        """Test that app starts up and shuts down cleanly"""
        startup_complete = False
        shutdown_complete = False

        @app.on_event("startup")
        async def startup_handler():
            nonlocal startup_complete
            startup_complete = True

        @app.on_event("shutdown")
        async def shutdown_handler():
            nonlocal shutdown_complete
            shutdown_complete = True

        with TestClient(app) as client:
            # Startup should have been called
            assert startup_complete

            # Make a request to ensure app is working
            response = client.get("/")
            assert response.status_code in [200, 404]  # Depends on routes

        # Shutdown should have been called
        assert shutdown_complete

    @pytest.mark.integration
    def test_middleware_integration(self):
        """Test that all middleware work together"""
        with TestClient(app) as client:
            response = client.get("/", headers={"Accept-Encoding": "gzip"})

            # Check compression is working
            assert response.headers.get("Content-Encoding") == "gzip"

            # Check security headers
            assert "X-Content-Type-Options" in response.headers

            # Check CORS headers
            assert "Access-Control-Allow-Origin" in response.headers
```

## Phase 2: Basic Functionality Testing (Week 2)

### Unit Tests for Health Endpoints

```python
# tests/unit/test_health_endpoints.py
import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from app.api.endpoints.health import health_check, readiness_check, check_database

class TestHealthEndpoints:
    """Test health check endpoints"""

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test basic health check returns success"""
        result = await health_check()

        assert result["status"] == "healthy"
        assert "timestamp" in result
        assert "version" in result
        assert datetime.fromisoformat(result["timestamp"])

    @pytest.mark.asyncio
    async def test_readiness_check_all_healthy(self, mocker):
        """Test readiness check when all dependencies are healthy"""
        # Mock all dependency checks to return True
        mocker.patch('app.api.endpoints.health.check_database',
                    return_value=AsyncMock(return_value=True))
        mocker.patch('app.api.endpoints.health.check_cache',
                    return_value=AsyncMock(return_value=True))
        mocker.patch('app.api.endpoints.health.check_disk_space',
                    return_value=True)
        mocker.patch('app.api.endpoints.health.check_memory',
                    return_value=True)

        response = Mock()
        result = await readiness_check(response)

        assert result["status"] == "ready"
        assert all(result["checks"].values())
        assert response.status_code != 503

    @pytest.mark.asyncio
    async def test_readiness_check_database_down(self, mocker):
        """Test readiness check when database is down"""
        mocker.patch('app.api.endpoints.health.check_database',
                    return_value=AsyncMock(return_value=False))
        mocker.patch('app.api.endpoints.health.check_cache',
                    return_value=AsyncMock(return_value=True))
        mocker.patch('app.api.endpoints.health.check_disk_space',
                    return_value=True)
        mocker.patch('app.api.endpoints.health.check_memory',
                    return_value=True)

        response = Mock()
        result = await readiness_check(response)

        assert result["status"] == "not ready"
        assert not result["checks"]["database"]
        assert "database" in result["details"]["failed_checks"]
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_check_database_timeout(self, mocker):
        """Test database check with timeout"""
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=asyncio.TimeoutError())

        mocker.patch('app.api.endpoints.health.get_db',
                    return_value=mock_db)

        result = await check_database()
        assert result is False
```

### Integration Tests for Health Endpoints

```python
# tests/integration/test_health_integration.py
import pytest
from fastapi.testclient import TestClient
# Integration tests will use docker-compose with real services
from app.main import app
from app.core.config import get_settings

class TestHealthIntegration:
    """Integration tests for health endpoints"""

    @pytest.fixture(scope="class")
    def postgres_container(self):
        """Start a PostgreSQL container for testing"""
        with PostgresContainer("postgres:14") as postgres:
            yield postgres

    @pytest.fixture
    def client_with_db(self, postgres_container, monkeypatch):
        """Client with database configured"""
        # Override database URL
        monkeypatch.setattr(
            get_settings(),
            "DATABASE_URL",
            postgres_container.get_connection_url()
        )

        with TestClient(app) as client:
            yield client

    @pytest.mark.integration
    def test_health_endpoint_integration(self, client_with_db):
        """Test health endpoint with real app"""
        response = client_with_db.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ViolentUTF API"

    @pytest.mark.integration
    def test_readiness_endpoint_with_real_db(self, client_with_db):
        """Test readiness with real database"""
        response = client_with_db.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["checks"]["database"] is True
```

## Phase 3: Data Layer Testing (Week 3)

### Unit Tests for Models

```python
# tests/unit/test_models.py
import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import SecureModelBase, AuditMixin
from app.db.base import Base

class TestUser(SecureModelBase):
    """Test model for validation"""
    __tablename__ = "test_users"

    name = Column(String(255))
    email = Column(String(255))

class TestSecureModelBase:
    """Test the secure model base class"""

    @pytest.fixture
    def db_session(self):
        """Create in-memory database session"""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        yield session
        session.close()

    def test_audit_fields_populated(self, db_session):
        """Test that audit fields are automatically populated"""
        user = TestUser(
            name="Test User",
            email="test@example.com",
            created_by="system"
        )
        db_session.add(user)
        db_session.commit()

        assert user.id is not None
        assert isinstance(user.created_at, datetime)
        assert user.updated_at == user.created_at
        assert user.created_by == "system"
        assert user.is_deleted is False
        assert user.version == 1

    def test_soft_delete(self, db_session):
        """Test soft delete functionality"""
        user = TestUser(name="Test User", email="test@example.com")
        db_session.add(user)
        db_session.commit()

        # Soft delete
        user.is_deleted = True
        user.deleted_at = datetime.utcnow()
        user.deleted_by = "admin"
        db_session.commit()

        # Verify soft delete
        assert user.is_deleted is True
        assert user.deleted_at is not None
        assert user.deleted_by == "admin"

    def test_string_validation(self, db_session):
        """Test string length and content validation"""
        # Test overly long string
        with pytest.raises(ValueError, match="String too long"):
            user = TestUser(name="x" * 10001)
            db_session.add(user)
            db_session.commit()

        # Test XSS attempt
        with pytest.raises(ValueError, match="Invalid content"):
            user = TestUser(name="<script>alert('xss')</script>")
            db_session.add(user)
            db_session.commit()

    def test_optimistic_locking(self, db_session):
        """Test optimistic locking with version field"""
        user = TestUser(name="Test User")
        db_session.add(user)
        db_session.commit()

        original_version = user.version

        # Update should increment version
        user.name = "Updated User"
        user.version += 1
        db_session.commit()

        assert user.version == original_version + 1
```

### Unit Tests for Repository Pattern

```python
# tests/unit/test_repository.py
import pytest
from unittest.mock import Mock, MagicMock
from sqlalchemy.orm import Session
from app.crud.base import CRUDBase
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate

class TestCRUDBase:
    """Test base CRUD operations"""

    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        return Mock(spec=Session)

    @pytest.fixture
    def crud_user(self):
        """CRUD instance for user model"""
        return CRUDBase[User, UserCreate, UserUpdate](User)

    def test_get_by_id(self, mock_db, crud_user):
        """Test get by ID operation"""
        mock_user = Mock(spec=User)
        mock_db.query().filter().first.return_value = mock_user

        result = crud_user.get(mock_db, id="test-id")

        assert result == mock_user
        mock_db.query.assert_called_once_with(User)

    def test_get_multi_with_pagination(self, mock_db, crud_user):
        """Test get multiple with pagination"""
        mock_users = [Mock(spec=User) for _ in range(5)]
        mock_db.query().offset().limit().all.return_value = mock_users

        result = crud_user.get_multi(mock_db, skip=10, limit=5)

        assert result == mock_users
        mock_db.query().offset.assert_called_once_with(10)
        mock_db.query().offset().limit.assert_called_once_with(5)

    def test_create_with_audit(self, mock_db, crud_user):
        """Test create with audit fields"""
        user_create = UserCreate(
            email="test@example.com",
            name="Test User"
        )

        result = crud_user.create_with_audit(
            mock_db,
            obj_in=user_create,
            created_by="admin"
        )

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once()

        # Verify audit fields were set
        created_obj = mock_db.add.call_args[0][0]
        assert created_obj.created_by == "admin"
```

### Integration Tests for Data Layer

```python
# tests/integration/test_database_integration.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# Integration tests will use docker-compose with real services
from alembic import command
from alembic.config import Config
from app.db.base import Base
from app.models.user import User
from app.crud.user import crud_user

class TestDatabaseIntegration:
    """Integration tests for database operations"""

    @pytest.fixture(scope="class")
    def postgres_container(self):
        """PostgreSQL container for testing"""
        with PostgresContainer("postgres:14") as postgres:
            yield postgres

    @pytest.fixture
    def db_engine(self, postgres_container):
        """Database engine connected to test container"""
        return create_engine(postgres_container.get_connection_url())

    @pytest.fixture
    def db_session(self, db_engine):
        """Database session for tests"""
        # Run migrations
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option(
            "sqlalchemy.url",
            str(db_engine.url)
        )
        command.upgrade(alembic_cfg, "head")

        SessionLocal = sessionmaker(bind=db_engine)
        session = SessionLocal()
        yield session
        session.close()

        # Clean up
        command.downgrade(alembic_cfg, "base")

    @pytest.mark.integration
    def test_user_crud_operations(self, db_session):
        """Test full CRUD cycle for users"""
        # Create
        user_data = {
            "email": "test@example.com",
            "name": "Test User",
            "hashed_password": "hashed_password"  # pragma: allowlist secret
        }
        user = crud_user.create(db_session, obj_in=user_data)

        assert user.id is not None
        assert user.email == user_data["email"]

        # Read
        retrieved_user = crud_user.get(db_session, id=user.id)
        assert retrieved_user.id == user.id

        # Update
        update_data = {"name": "Updated User"}
        updated_user = crud_user.update(
            db_session,
            db_obj=user,
            obj_in=update_data
        )
        assert updated_user.name == "Updated User"

        # Soft Delete
        deleted_user = crud_user.remove_soft(
            db_session,
            id=user.id,
            deleted_by="admin"
        )
        assert deleted_user.is_deleted is True
        assert deleted_user.deleted_by == "admin"

    @pytest.mark.integration
    def test_transaction_rollback(self, db_session):
        """Test transaction rollback on error"""
        try:
            with db_session.begin():
                user = User(email="test@example.com")
                db_session.add(user)

                # Force an error
                raise ValueError("Simulated error")
        except ValueError:
            pass

        # Verify user was not saved
        count = db_session.query(User).filter_by(
            email="test@example.com"
        ).count()
        assert count == 0
```

## Phase 4-5: API Endpoints Testing (Weeks 4-5)

### Unit Tests for Endpoints

```python
# tests/unit/test_item_endpoints.py
import pytest
from unittest.mock import Mock, patch
from fastapi import HTTPException
from app.api.endpoints.items import read_items, create_item
from app.schemas.item import ItemCreate, ItemResponse

class TestItemEndpoints:
    """Test item endpoints"""

    @pytest.mark.asyncio
    async def test_read_items_with_filters(self, mocker):
        """Test reading items with filters"""
        mock_items = [
            Mock(id=1, name="Item 1"),
            Mock(id=2, name="Item 2")
        ]

        mock_crud = mocker.patch('app.api.endpoints.items.crud_item')
        mock_crud.get_multi_with_filters.return_value = mock_items

        mock_db = Mock()
        mock_user = Mock(id="user-123")

        result = await read_items(
            db=mock_db,
            skip=0,
            limit=10,
            filter_name="Item",
            sort_by="created_at",
            sort_order="desc",
            current_user=mock_user
        )

        assert len(result) == 2
        mock_crud.get_multi_with_filters.assert_called_once_with(
            mock_db,
            skip=0,
            limit=10,
            filter_name="Item",
            sort_by="created_at",
            sort_order="desc",
            user_id="user-123"
        )

    @pytest.mark.asyncio
    async def test_create_item_with_validation(self, mocker):
        """Test creating item with validation"""
        item_create = ItemCreate(
            name="New Item",
            description="Test description",
            idempotency_key="unique-key-123"
        )

        mock_crud = mocker.patch('app.api.endpoints.items.crud_item')
        mock_crud.get_by_idempotency_key.return_value = None
        mock_crud.create_with_owner.return_value = Mock(
            id=1,
            name=item_create.name
        )

        mock_db = Mock()
        mock_user = Mock(id="user-123", email="user@example.com")

        result = await create_item(
            db=mock_db,
            item_in=item_create,
            current_user=mock_user,
            signature=None
        )

        assert result.id == 1
        mock_crud.create_with_owner.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_item_idempotency(self, mocker):
        """Test idempotency handling"""
        existing_item = Mock(id=1, name="Existing Item")

        mock_crud = mocker.patch('app.api.endpoints.items.crud_item')
        mock_crud.get_by_idempotency_key.return_value = existing_item

        item_create = ItemCreate(
            name="New Item",
            idempotency_key="duplicate-key"
        )

        result = await create_item(
            db=Mock(),
            item_in=item_create,
            current_user=Mock(),
            signature=None
        )

        assert result == existing_item
        mock_crud.create_with_owner.assert_not_called()
```

### Integration Tests for Endpoints

```python
# tests/integration/test_api_integration.py
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import create_access_token

class TestAPIIntegration:
    """Integration tests for API endpoints"""

    @pytest.fixture
    def authenticated_client(self):
        """Client with authentication token"""
        token = create_access_token({"sub": "test-user-id"})
        client = TestClient(app)
        client.headers["Authorization"] = f"Bearer {token}"
        return client

    @pytest.mark.integration
    def test_items_crud_flow(self, authenticated_client, db_session):
        """Test complete CRUD flow for items"""
        # Create item
        create_data = {
            "name": "Test Item",
            "description": "Integration test item",
            "price": 99.99
        }
        create_response = authenticated_client.post(
            "/api/v1/items/",
            json=create_data
        )
        assert create_response.status_code == 201
        item = create_response.json()
        item_id = item["id"]

        # Read items
        list_response = authenticated_client.get("/api/v1/items/")
        assert list_response.status_code == 200
        items = list_response.json()
        assert len(items) > 0
        assert any(i["id"] == item_id for i in items)

        # Update item
        update_data = {"name": "Updated Item"}
        update_response = authenticated_client.put(
            f"/api/v1/items/{item_id}",
            json=update_data
        )
        assert update_response.status_code == 200
        updated_item = update_response.json()
        assert updated_item["name"] == "Updated Item"

        # Delete item
        delete_response = authenticated_client.delete(
            f"/api/v1/items/{item_id}"
        )
        assert delete_response.status_code == 204

        # Verify deletion
        get_response = authenticated_client.get(
            f"/api/v1/items/{item_id}"
        )
        assert get_response.status_code == 404

    @pytest.mark.integration
    def test_rate_limiting(self, authenticated_client):
        """Test rate limiting functionality"""
        # Make requests up to the limit
        for i in range(10):
            response = authenticated_client.post(
                "/api/v1/items/",
                json={"name": f"Item {i}"}
            )
            assert response.status_code in [201, 429]

            if response.status_code == 429:
                # Rate limit hit
                assert response.json()["detail"] == "Too many requests"
                assert "Retry-After" in response.headers
                break
        else:
            pytest.fail("Rate limit was not triggered")
```

## Phase 6: Security Testing (Week 6)

### Security Unit Tests

```python
# tests/unit/test_auth.py
import pytest
from datetime import datetime, timedelta
from jose import jwt, JWTError
from app.core.auth import (
    create_access_token,
    verify_token,
    get_password_hash,
    verify_password
)

class TestAuthentication:
    """Test authentication functions"""

    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "SecurePassword123!"  # pragma: allowlist secret
        hashed = get_password_hash(password)

        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("WrongPassword", hashed)

    def test_create_access_token(self):
        """Test JWT token creation"""
        data = {"sub": "user-123", "roles": ["user"]}
        token = create_access_token(data)

        # Decode and verify
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM]
        )

        assert payload["sub"] == "user-123"
        assert payload["roles"] == ["user"]
        assert "exp" in payload
        assert "iat" in payload

    def test_token_expiration(self):
        """Test token expiration"""
        data = {"sub": "user-123"}
        # Create token that expires immediately
        token = create_access_token(
            data,
            expires_delta=timedelta(seconds=-1)
        )

        with pytest.raises(JWTError):
            verify_token(token)

    def test_invalid_token(self):
        """Test invalid token handling"""
        with pytest.raises(JWTError):
            verify_token("invalid.token.here")

    def test_token_with_invalid_signature(self):
        """Test token with tampered signature"""
        data = {"sub": "user-123"}
        token = create_access_token(data)

        # Tamper with the signature
        parts = token.split('.')
        tampered_token = f"{parts[0]}.{parts[1]}.tampered_signature"

        with pytest.raises(JWTError):
            verify_token(tampered_token)
```

### Security Integration Tests

```python
# tests/security/test_security_integration.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

class TestSecurityIntegration:
    """Security-focused integration tests"""

    @pytest.mark.security
    def test_sql_injection_prevention(self, client):
        """Test SQL injection prevention"""
        # Attempt SQL injection in various endpoints
        injection_payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM items WHERE '1'='1"
        ]

        for payload in injection_payloads:
            response = client.get(
                f"/api/v1/items/search?q={payload}"
            )
            # Should not cause server error
            assert response.status_code != 500
            # Should not return unauthorized data
            if response.status_code == 200:
                assert len(response.json()) == 0

    @pytest.mark.security
    def test_xss_prevention(self, authenticated_client):
        """Test XSS prevention"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]

        for payload in xss_payloads:
            response = authenticated_client.post(
                "/api/v1/items/",
                json={"name": payload, "description": "Test"}
            )

            if response.status_code == 201:
                # Verify the payload was sanitized
                item = response.json()
                assert "<script>" not in item["name"]
                assert "javascript:" not in item["name"]

    @pytest.mark.security
    def test_authentication_required(self, client):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            ("/api/v1/items/", "POST"),
            ("/api/v1/items/1", "PUT"),
            ("/api/v1/items/1", "DELETE"),
            ("/api/v1/users/me", "GET")
        ]

        for endpoint, method in protected_endpoints:
            response = client.request(method, endpoint)
            assert response.status_code == 401
            assert response.json()["detail"] == "Not authenticated"

    @pytest.mark.security
    def test_authorization_enforcement(self, authenticated_client):
        """Test role-based access control"""
        # Try to access admin endpoint with user token
        response = authenticated_client.get("/api/v1/admin/users")
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"
```

## Performance Testing

```python
# tests/performance/test_performance.py
import pytest
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
from fastapi.testclient import TestClient
from app.main import app

class TestPerformance:
    """Performance benchmark tests"""

    @pytest.mark.performance
    @pytest.mark.benchmark
    def test_endpoint_response_time(self, benchmark, authenticated_client):
        """Benchmark endpoint response time"""
        def make_request():
            response = authenticated_client.get("/api/v1/items/")
            assert response.status_code == 200
            return response

        # Run benchmark
        result = benchmark(make_request)

        # Assert performance requirements
        assert benchmark.stats["mean"] < 0.2  # 200ms average
        assert benchmark.stats["max"] < 0.5   # 500ms max

    @pytest.mark.performance
    def test_concurrent_requests(self, authenticated_client):
        """Test handling concurrent requests"""
        num_requests = 100
        num_workers = 10

        def make_request(i):
            start = time.time()
            response = authenticated_client.get(f"/api/v1/items/?page={i}")
            duration = time.time() - start
            return response.status_code, duration

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            results = list(executor.map(make_request, range(num_requests)))

        # Verify all requests succeeded
        status_codes = [r[0] for r in results]
        assert all(code == 200 for code in status_codes)

        # Check response times
        durations = [r[1] for r in results]
        avg_duration = sum(durations) / len(durations)
        assert avg_duration < 0.5  # 500ms average under load

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_database_query_performance(self, db_session):
        """Test database query performance"""
        from app.crud.item import crud_item

        # Create test data
        for i in range(1000):
            crud_item.create(db_session, obj_in={
                "name": f"Item {i}",
                "price": i * 10
            })
        db_session.commit()

        # Test query performance
        start = time.time()
        items = crud_item.get_multi(db_session, skip=0, limit=100)
        duration = time.time() - start

        assert len(items) == 100
        assert duration < 0.1  # 100ms for 100 items
```

## Test Utilities and Fixtures

```python
# tests/conftest.py
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.base import Base
from app.api.deps import get_db
from app.core.config import settings

# Test database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

@pytest.fixture(scope="session")
def db_engine():
    """Create test database engine"""
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session(db_engine) -> Generator:
    """Create database session for tests"""
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db_engine
    )
    session = TestingSessionLocal()
    yield session
    session.close()

@pytest.fixture(scope="function")
def client(db_session) -> Generator:
    """Create test client with database override"""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def mock_current_user():
    """Mock current user for tests"""
    from app.models.user import User
    return User(
        id="test-user-id",
        email="test@example.com",
        full_name="Test User",
        is_active=True,
        is_superuser=False
    )

# Test data factories
@pytest.fixture
def item_factory():
    """Factory for creating test items"""
    def _create_item(**kwargs):
        from app.schemas.item import ItemCreate
        defaults = {
            "name": "Test Item",
            "description": "Test Description",
            "price": 99.99
        }
        defaults.update(kwargs)
        return ItemCreate(**defaults)
    return _create_item
```

## Testing Best Practices for Extraction

### 1. Test-Driven Extraction Process

For each component extraction:

1. **Write tests first** for the improvements you plan to make
2. **Extract the component** from mother repo
3. **Run tests** - they should fail
4. **Implement improvements** until tests pass
5. **Add more tests** for edge cases discovered

### 2. Continuous Testing During Extraction

```bash
# Create a test watcher script
cat > watch_tests.sh << 'EOF'
#!/bin/bash
# Continuously run tests as files change

while true; do
    clear
    echo "Running tests..."
    pytest tests/unit -v --tb=short

    echo -e "\n\nWaiting for changes..."
    inotifywait -r -e modify,create,delete \
        --exclude '\.pyc|__pycache__|\.pytest_cache' \
        app/ tests/
done
EOF

chmod +x watch_tests.sh
```

### 3. Test Coverage Enforcement

```bash
# Add pre-commit hook for test coverage
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "Running tests with coverage check..."

pytest --cov=app --cov-fail-under=80 --quiet

if [ $? -ne 0 ]; then
    echo "Tests failed or coverage below 80%. Commit aborted."
    exit 1
fi
EOF

chmod +x .git/hooks/pre-commit
```

### 4. Integration Test Environment

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  test-db:
    image: postgres:14
    environment:
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
      POSTGRES_DB: test_violentutf
    ports:
      - "5433:5432"

  test-redis:
    image: redis:7
    ports:
      - "6380:6379"

  test-app:
    build: .
    environment:
      DATABASE_URL: postgresql://test:test@test-db/test_violentutf  # pragma: allowlist secret
      REDIS_URL: redis://test-redis:6379
      TESTING: "true"
    depends_on:
      - test-db
      - test-redis
    command: pytest -v --cov=app --cov-report=html
```

## Continuous Integration Testing

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt

    - name: Run unit tests
      run: pytest tests/unit -v --cov=app

    - name: Run integration tests
      run: pytest tests/integration -v
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost/postgres  # pragma: allowlist secret

    - name: Run security tests
      run: pytest tests/security -v

    - name: Check coverage
      run: pytest --cov=app --cov-fail-under=80

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
```

## Summary

This comprehensive testing strategy ensures:

1. **Every improvement is validated** through specific tests
2. **Components work in isolation** before integration
3. **Security enhancements are verified** through security tests
4. **Performance improvements are measured** through benchmarks
5. **Quality gates are enforced** through coverage requirements

The key is to treat testing as an integral part of the extraction process, not an afterthought. Each extracted component should have better test coverage than in the mother repository.
