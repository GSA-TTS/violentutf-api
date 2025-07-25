# Example: Fixing a Failing Test

Let's walk through fixing an actual failing test to demonstrate the process.

## Original Failing Test

From `tests/unit/models/test_user.py`:

```python
def test_audit_fields_inheritance(self):
    """Test that audit fields from mixin work."""
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        created_by="admin",
    )

    assert user.created_by == "admin"
    assert user.version == 1  # FAILS: AssertionError: assert None == 1
    assert user.is_deleted is False
    assert hasattr(user, "soft_delete")
```

## Why It Fails

The test fails because:
1. `version` has `server_default="1"` which is applied by the database
2. Before saving to database, `version` is `None` in Python
3. The test doesn't use a database session

## Fixed Version

```python
def test_audit_fields_inheritance(self, db_session):
    """Test that audit fields from mixin work."""
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        created_by="admin",
    )

    # Test Python-level defaults
    assert user.created_by == "admin"
    assert user.is_deleted is False
    assert hasattr(user, "soft_delete")

    # Save to database to apply server defaults
    db_session.add(user)
    db_session.flush()

    # Now test database-level defaults
    assert user.version == 1
    assert user.created_at is not None
    assert user.updated_at is not None
```

## Step-by-Step Fix Process

### 1. Add Database Session Fixture

First, ensure the test has access to a database session:

```python
@pytest.fixture
def db_session():
    """Create a test database session."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.base_class import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    session = SessionLocal()
    yield session
    session.close()
```

### 2. Update Test Method Signature

Add the fixture as a parameter:

```python
def test_audit_fields_inheritance(self, db_session):  # Added db_session
```

### 3. Separate Python vs Database Defaults

Test Python-level defaults first (these work without database):
- `created_by` - has Python default
- `is_deleted` - has Python default=False

Then flush to database and test server defaults:
- `version` - has server_default="1"
- `created_at` - has server_default=CURRENT_TIMESTAMP

### 4. Use Flush Instead of Commit

```python
db_session.flush()  # Executes SQL but doesn't commit transaction
```

This applies defaults without committing, keeping tests isolated.

## Another Example: Error Message Test

### Original Failing Test

```python
def test_password_hash_validation(self):
    """Test password hash validation."""
    # Invalid hash format
    with pytest.raises(ValueError, match="properly hashed with Argon2"):
        User(
            username="testuser",
            email="test@example.com",
            password_hash="plain_password",  # pragma: allowlist secret
        )
```

### Why It Fails

```
AssertionError: Regex pattern did not match.
 Regex: 'properly hashed with Argon2'
 Input: 'Password must be hashed with Argon2'
```

### Fixed Version

```python
def test_password_hash_validation(self):
    """Test password hash validation."""
    # Option 1: Match exact message
    with pytest.raises(ValueError, match="Password must be hashed with Argon2"):
        User(
            username="testuser",
            email="test@example.com",
            password_hash="plain_password",  # pragma: allowlist secret
        )

    # Option 2: Partial match (more flexible)
    with pytest.raises(ValueError, match=".*Argon2.*"):
        User(
            username="testuser",
            email="test@example.com",
            password_hash="plain_password",  # pragma: allowlist secret
        )

    # Option 3: Just check exception type (most flexible)
    with pytest.raises(ValueError) as exc_info:
        User(
            username="testuser",
            email="test@example.com",
            password_hash="plain_password",  # pragma: allowlist secret
        )
    assert "Argon2" in str(exc_info.value)
```

## Testing Philosophy

### Before (Brittle)
Tests checked exact implementation details:
- Exact error messages
- Field presence/absence
- Default values without database

### After (Robust)
Tests check behavior:
- Exception raised for invalid input
- Data persists correctly
- Constraints are enforced
- Security validations work

## Common Patterns

### 1. Testing Defaults
```python
# Create object
obj = Model(required_field="value")

# Test Python defaults
assert obj.python_default_field == "default"

# Save and test database defaults
session.add(obj)
session.flush()
assert obj.server_default_field == 1
```

### 2. Testing Validation
```python
# Don't test exact message
with pytest.raises(ValueError):  # Good enough

# Or use partial match
with pytest.raises(ValueError, match=".*invalid.*"):
```

### 3. Testing Relationships
```python
# After creating related objects
session.flush()  # Ensure IDs are assigned

# Convert dynamic relationship to list
api_keys = list(user.api_keys)
assert len(api_keys) == 2
```

### 4. Testing Constraints
```python
try:
    # Create duplicate
    session.flush()
except IntegrityError:
    pass  # Expected
else:
    pytest.fail("Expected IntegrityError")
```

## Summary

The key to fixing tests is understanding the difference between:
1. **Python-level behavior** (instant, no database needed)
2. **Database-level behavior** (requires flush/commit)

Most test failures are due to:
- Not using a database session when needed
- Checking exact error messages that changed
- Not understanding server defaults
- Method signature changes

Fix by:
- Adding database sessions
- Testing behavior not implementation
- Separating Python vs database defaults
- Using partial matches for messages
