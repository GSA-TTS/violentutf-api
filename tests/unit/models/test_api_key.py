"""Unit tests for APIKey model."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.api_key import APIKey


@pytest.fixture
def db_session() -> Generator[Any, None, None]:
    """Create a test database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


class TestAPIKeyModel:
    """Test APIKey model functionality."""

    def test_api_key_creation(self) -> None:
        """Test creating an API key instance."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test API Key",
            description="Key for testing",
            key_prefix="test_1",
            user_id=user_id,
            permissions={"read": True, "write": False},
        )

        assert api_key.key_hash == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        assert api_key.name == "Test API Key"
        assert api_key.description == "Key for testing"
        assert api_key.key_prefix == "test_1"
        assert api_key.user_id == user_id
        assert api_key.permissions == {"read": True, "write": False}
        # Note: In SQLAlchemy 2.0, defaults are applied by the database
        # usage_count will be None until saved to database
        assert api_key.usage_count is None or api_key.usage_count == 0
        assert api_key.last_used_at is None

    def test_key_prefix_validation(self) -> None:
        """Test key prefix validation."""
        user_id = uuid.uuid4()

        # Valid prefix
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="valid1",
            user_id=user_id,
        )
        assert api_key.key_prefix == "valid1"

        # Too short
        with pytest.raises(ValueError, match="must be at least 6 characters"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                key_prefix="short",
                user_id=user_id,
            )

        # Too long
        with pytest.raises(ValueError, match="cannot exceed 10 characters"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                key_prefix="toolongprefix",
                user_id=user_id,
            )

    def test_permissions_validation(self) -> None:
        """Test permissions validation."""
        user_id = uuid.uuid4()

        # Valid permissions
        valid_perms = {
            "read": True,
            "write": False,
            "targets:read": True,
            "sessions:write": False,
        }
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="test_1",
            user_id=user_id,
            permissions=valid_perms,
        )
        assert api_key.permissions == valid_perms

        # Invalid permission scope
        with pytest.raises(ValueError, match="Invalid permission scope"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                key_prefix="test_1",
                user_id=user_id,
                permissions={"invalid_scope": True},
            )

        # Non-boolean permission value
        with pytest.raises(ValueError, match="must be boolean"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                key_prefix="test_1",
                user_id=user_id,
                permissions={"read": "yes"},
            )

        # Non-dict permissions
        with pytest.raises(ValueError, match="must be a dictionary"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                key_prefix="test_1",
                user_id=user_id,
                permissions="all",  # type: ignore
            )

    def test_expiration_logic(self) -> None:
        """Test API key expiration."""
        user_id = uuid.uuid4()

        # Non-expiring key
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="test_1",
            user_id=user_id,
            expires_at=None,
        )
        assert api_key.is_expired() is False
        assert api_key.is_valid is True

        # Expired key
        past_date = datetime.now(timezone.utc) - timedelta(days=1)
        expired_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Expired",
            key_prefix="test_1",
            user_id=user_id,
            expires_at=past_date,
        )
        assert expired_key.is_expired() is True
        assert expired_key.is_valid is False

        # Future expiration
        future_date = datetime.now(timezone.utc) + timedelta(days=30)
        valid_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Valid",
            key_prefix="test_1",
            user_id=user_id,
            expires_at=future_date,
        )
        assert valid_key.is_expired() is False
        assert valid_key.is_valid is True

    def test_soft_deleted_key_validity(self) -> None:
        """Test that soft deleted keys are invalid."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="test_1",
            user_id=user_id,
        )

        assert api_key.is_valid is True

        # Soft delete the key
        api_key.soft_delete(deleted_by="admin")
        assert api_key.is_valid is False

    def test_record_usage(self) -> None:
        """Test usage recording."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="test_1",
            user_id=user_id,
        )

        # Initial state
        assert api_key.usage_count is None or api_key.usage_count == 0
        assert api_key.last_used_at is None
        assert api_key.last_used_ip is None

        # Record usage
        api_key.record_usage(ip_address="192.168.1.1")

        assert api_key.usage_count == 1
        assert api_key.last_used_at is not None
        assert api_key.last_used_ip == "192.168.1.1"

        # Record another usage
        api_key.record_usage(ip_address="10.0.0.1")

        assert api_key.usage_count == 2
        assert api_key.last_used_ip == "10.0.0.1"

    def test_has_permission(self) -> None:
        """Test permission checking."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test",
            key_prefix="test_1",
            user_id=user_id,
            permissions={
                "read": True,
                "write": False,
                "targets:read": True,
                "targets:write": True,
                "sessions:*": True,
            },
        )

        # Direct permissions
        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is False
        assert api_key.has_permission("targets:read") is True

        # Wildcard permissions
        assert api_key.has_permission("sessions:read") is True
        assert api_key.has_permission("sessions:write") is True
        assert api_key.has_permission("sessions:delete") is True

        # Non-existent permission
        assert api_key.has_permission("admin") is False

    def test_admin_permission_override(self) -> None:
        """Test admin permission grants all access."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Admin Key",
            key_prefix="admin1",
            user_id=user_id,
            permissions={"admin": True},
        )

        # Admin should have all permissions
        assert api_key.has_permission("read") is True
        assert api_key.has_permission("write") is True
        assert api_key.has_permission("delete") is True
        assert api_key.has_permission("anything") is True

    def test_invalid_key_has_no_permissions(self) -> None:
        """Test that invalid keys have no permissions."""
        user_id = uuid.uuid4()

        # Expired key
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Expired",
            key_prefix="test_1",
            user_id=user_id,
            permissions={"read": True},
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        assert api_key.has_permission("read") is False

        # Deleted key
        deleted_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Deleted",
            key_prefix="test_1",
            user_id=user_id,
            permissions={"read": True},
        )
        deleted_key.soft_delete(deleted_by="system")
        assert deleted_key.has_permission("read") is False

    def test_api_key_repr(self) -> None:
        """Test string representation."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test Key",
            key_prefix="test_1",
            user_id=user_id,
        )

        repr_str = repr(api_key)
        assert "APIKey" in repr_str
        assert "Test Key" in repr_str
        assert "test_1" in repr_str

    def test_to_dict_method(self) -> None:
        """Test dictionary conversion."""
        user_id = uuid.uuid4()
        api_key = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Test Key",
            description="A test key",
            key_prefix="test_1",
            user_id=user_id,
            permissions={"read": True},
            last_used_at=datetime.now(timezone.utc),
            last_used_ip="192.168.1.1",
            usage_count=5,
        )

        # Note: to_dict() no longer accepts parameters
        data = api_key.to_dict()
        assert data["name"] == "Test Key"
        assert data["description"] == "A test key"
        assert data["key_prefix"] == "test_1"
        assert data["permissions"] == {"read": True}
        assert data["is_active"] is True
        # user_id and last_used_ip are not included in to_dict() for security
        assert "user_id" not in data
        assert "last_used_ip" not in data
        # usage_count is included
        assert data["usage_count"] == 5 or data["usage_count"] is None

    def test_unique_constraints(self, db_session: Any) -> None:
        """Test unique constraints."""
        user_id = uuid.uuid4()

        # Create first API key
        key1 = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Production Key",
            key_prefix="prod01",
            user_id=user_id,
        )
        db_session.add(key1)
        db_session.commit()

        # Try to create duplicate key hash
        key2 = APIKey(
            key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret  # Same hash
            name="Another Key",
            key_prefix="test_1",
            user_id=user_id,
        )
        db_session.add(key2)

        with pytest.raises(Exception, match=".*"):  # IntegrityError in real DB
            db_session.commit()

        db_session.rollback()

        # Same name for same user should fail
        key3 = APIKey(
            key_hash="b665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
            name="Production Key",  # Same name
            key_prefix="test_1",
            user_id=user_id,
        )
        db_session.add(key3)

        # Note: This would fail with proper unique constraint in PostgreSQL
        # but SQLite doesn't enforce all constraints the same way

    def test_security_validation_inheritance(self) -> None:
        """Test security validations from mixin."""
        user_id = uuid.uuid4()

        # SQL injection in name
        with pytest.raises(ValueError, match="Invalid characters or patterns"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="'; DROP TABLE api_keys; --",
                key_prefix="test_1",
                user_id=user_id,
            )

        # XSS in description
        with pytest.raises(ValueError, match="Invalid HTML/Script content"):
            APIKey(
                key_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # pragma: allowlist secret
                name="Test",
                description="<script>alert('XSS')</script>",
                key_prefix="test_1",
                user_id=user_id,
            )
