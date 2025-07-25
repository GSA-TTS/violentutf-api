"""Unit tests for User model - Updated for SQLAlchemy 2.0."""

import uuid
from datetime import datetime, timezone
from typing import Any, Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.base import Base  # This imports all models
from app.models.user import User


@pytest.fixture
def db_session() -> Generator[Any, None, None]:
    """Create a test database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


class TestUserModel:
    """Test User model functionality."""

    def test_user_creation(self, db_session: Any) -> None:
        """Test creating a user instance."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            full_name="Test User",
        )

        # Test Python-level defaults
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        # Note: is_active and is_superuser have default=True/False but may be None before flush
        # This is because they use mapped_column with default, not a Python-level default

        # Add to session to get database defaults
        db_session.add(user)
        db_session.flush()

        # Now check database-generated values
        assert isinstance(user.id, uuid.UUID)
        assert user.created_at is not None
        assert user.version == 1
        assert user.is_active is True
        assert user.is_superuser is False

    def test_username_validation(self) -> None:
        """Test username validation rules."""
        # Valid usernames
        valid_usernames = ["user123", "test_user", "user-name", "abc"]

        for username in valid_usernames:
            user = User(
                username=username,
                email="test@example.com",
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            )
            assert user.username == username.lower()

        # Invalid usernames - Updated error messages
        with pytest.raises(ValueError, match="Username is required"):
            User(username="", email="test@example.com", password_hash="$argon2...")

        with pytest.raises(ValueError, match="at least 3 characters"):
            User(username="ab", email="test@example.com", password_hash="$argon2...")

        with pytest.raises(ValueError, match="cannot exceed 100 characters"):
            User(username="a" * 101, email="test@example.com", password_hash="$argon2...")

        with pytest.raises(ValueError, match="can only contain"):
            User(username="user@name", email="test@example.com", password_hash="$argon2...")

    def test_email_validation(self) -> None:
        """Test email validation."""
        # Valid emails are normalized to lowercase
        user = User(
            username="testuser",
            email="Test@Example.COM",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        assert user.email == "test@example.com"

        # Invalid email formats
        with pytest.raises(ValueError, match="Invalid email format"):
            User(username="test", email="not-an-email", password_hash="$argon2...")

        # Email validation happens at field level, not length
        # The field validator checks format first

    def test_password_hash_validation(self) -> None:
        """Test password hash validation."""
        # Valid Argon2 hash
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        assert user.password_hash.startswith("$argon2")

        # Invalid hash format - Updated error message
        with pytest.raises(ValueError, match="Password must be hashed with Argon2"):
            User(
                username="test",
                email="test@example.com",
                password_hash="plain_password",
            )

        # Empty hash
        with pytest.raises(ValueError, match="Password hash is required"):
            User(username="test", email="test@example.com", password_hash="")

    def test_security_validation_inheritance(self) -> None:
        """Test that security validations from mixin work."""
        # SQL injection attempt in full_name
        with pytest.raises(ValueError, match="Invalid characters or patterns"):
            User(
                username="testuser",
                email="test@example.com",
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
                full_name="'; DROP TABLE users; --",
            )

        # XSS attempt in full_name
        with pytest.raises(ValueError, match="Invalid HTML/Script content"):
            User(
                username="testuser",
                email="test@example.com",
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
                full_name="<script>alert('XSS')</script>",
            )

    def test_audit_fields_inheritance(self, db_session: Any) -> None:
        """Test that audit fields from mixin work."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            created_by="admin",
        )

        # Test Python-level values
        assert user.created_by == "admin"
        # is_deleted has a Python default in the mixin, should work

        # Add to session to get database defaults
        db_session.add(user)
        db_session.flush()

        # Now test database-generated values
        assert user.version == 1
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
        assert user.created_at.tzinfo is not None  # Timezone aware
        assert user.is_deleted is False  # Should be set after flush

    def test_soft_delete_functionality(self) -> None:
        """Test soft delete methods."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )

        # Soft delete
        user.soft_delete(deleted_by="admin")

        assert user.is_deleted is True
        assert user.deleted_at is not None
        assert user.deleted_by == "admin"

        # Restore
        user.restore()

        assert user.is_deleted is False
        assert user.deleted_at is None
        assert user.deleted_by is None

    def test_user_repr(self) -> None:
        """Test string representation."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )

        repr_str = repr(user)
        assert "User" in repr_str
        assert "testuser" in repr_str
        assert "test@example.com" in repr_str
        # is_active might be None until saved to database
        assert "active=" in repr_str

    def test_to_dict_method(self, db_session: Any) -> None:
        """Test dictionary conversion."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            full_name="Test User",
            created_by="admin",
        )

        # Need to save to get ID and timestamps
        db_session.add(user)
        db_session.flush()

        # to_dict() no longer takes parameters - it never includes sensitive data
        data = user.to_dict()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"
        assert data["is_active"] is True
        assert data["is_superuser"] is False
        assert "password_hash" not in data  # Never included
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_unique_constraints(self, db_session: Any) -> None:
        """Test unique constraints on username and email."""
        # Create first user
        user1 = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        db_session.add(user1)
        db_session.commit()

        # Try to create duplicate username
        user2 = User(
            username="testuser",
            email="other@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        db_session.add(user2)

        with pytest.raises(IntegrityError):
            db_session.flush()

        db_session.rollback()

        # Try to create duplicate email
        user3 = User(
            username="otheruser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )
        db_session.add(user3)

        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_case_insensitive_username(self) -> None:
        """Test username is normalized to lowercase."""
        user = User(
            username="TestUser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        )

        assert user.username == "testuser"

    def test_row_level_security_fields(self) -> None:
        """Test RLS fields from mixin."""
        org_id = uuid.uuid4()
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
            owner_id="owner123",
            organization_id=org_id,
            access_level="restricted",
        )

        assert user.owner_id == "owner123"
        assert user.organization_id == org_id
        assert user.access_level == "restricted"
