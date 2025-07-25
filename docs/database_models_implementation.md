# Database Models Implementation - Issue #16

## Summary

Successfully implemented a comprehensive database model system with audit mixins, soft delete, optimistic locking, and row-level security capabilities for the ViolentUTF API.

## What Was Implemented

### 1. Base Infrastructure

#### Base Class (`app/db/base_class.py`)
- Declarative base for all SQLAlchemy models
- Automatic table name generation from class names
- Foundation for all database models

#### Model Mixins (`app/models/mixins.py`)
Comprehensive mixins providing:

1. **AuditMixin**
   - `id`: UUID primary key with auto-generation
   - `created_at`: Timestamp with timezone
   - `created_by`: User/system identifier
   - `updated_at`: Auto-updating timestamp
   - `updated_by`: Last modifier identifier
   - `version`: For optimistic locking
   - Automatic indexes on audit fields

2. **SoftDeleteMixin**
   - `is_deleted`: Boolean flag
   - `deleted_at`: Deletion timestamp
   - `deleted_by`: Who deleted the record
   - `soft_delete()` method
   - `restore()` method
   - Partial index for active records

3. **SecurityValidationMixin**
   - SQL injection pattern detection
   - XSS pattern detection
   - String length validation
   - Email format validation
   - Automatic validation on all string fields

4. **OptimisticLockMixin**
   - `version` field for concurrent update detection
   - Automatic version increment on updates
   - Event listener for version management

5. **RowLevelSecurityMixin**
   - `owner_id`: Record owner
   - `organization_id`: Organization ownership
   - `access_level`: Access control (private/public/restricted)
   - Indexes for efficient RLS queries

6. **BaseModelMixin**
   - Combines all mixins for easy use
   - Standard base for all models

### 2. Model Implementations

#### User Model (`app/models/user.py`)
- Username with validation (alphanumeric, underscore, hyphen)
- Email with RFC-compliant validation
- Password hash storage (Argon2)
- Active/inactive status
- Superuser flag
- Full audit trail
- Soft delete support
- Unique constraints with soft delete consideration

#### APIKey Model (`app/models/api_key.py`)
- Secure key hash storage
- Key prefix for identification
- Flexible JSON permissions system
- Usage tracking (count, last used, IP)
- Expiration support
- Permission checking methods
- Relationship to User with cascade delete

#### AuditLog Model (`app/models/audit_log.py`)
- Immutable audit trail (no soft delete)
- Comprehensive action tracking
- Resource type and ID tracking
- User and request context
- IP address and user agent logging
- Change tracking with before/after values
- Performance metrics (duration)
- Extensive indexing for queries

### 3. Security Features

#### At Model Level
- SQL injection prevention through pattern matching
- XSS prevention for all text fields
- Length limits enforced
- Input sanitization
- Secure defaults

#### Database Level
- UUID primary keys (harder to enumerate)
- Indexes for performance
- Constraints for data integrity
- Row-level security support

### 4. Performance Optimizations

#### Indexes Created
- Audit field indexes (created_at, updated_at)
- Soft delete partial indexes
- User lookup indexes (username, email)
- API key lookup indexes
- Audit log query indexes
- Composite indexes for common queries

#### Query Optimizations
- Partial indexes for active records
- Strategic composite indexes
- Efficient soft delete filtering

### 5. Testing

#### Unit Tests
- `tests/unit/models/test_mixins.py` - Comprehensive mixin testing
- `tests/unit/models/test_user.py` - User model validation
- `tests/unit/models/test_api_key.py` - API key functionality
- `tests/unit/models/test_audit_log.py` - Audit logging tests

#### Integration Tests
- `tests/integration/test_database_models.py` - Full database operations
- Async SQLAlchemy testing
- Relationship testing
- Cascade operations
- Transaction handling

### 6. Database Migrations

#### Alembic Setup
- Configured for async SQLAlchemy
- Support for both online and offline migrations
- Auto-generation from models
- PostgreSQL and SQLite support

## Usage Examples

### Creating a User
```python
user = User(
    username="john_doe",
    email="john@example.com",
    password_hash=hash_password("secure_password"),
    full_name="John Doe",
    created_by="admin"
)
session.add(user)
await session.commit()
```

### Soft Deleting
```python
user.soft_delete(deleted_by="admin")
await session.commit()

# Query only active users
active_users = await session.execute(
    select(User).filter_by(is_deleted=False)
)
```

### Audit Logging
```python
audit_log = AuditLog.log_action(
    action="login",
    resource_type="user",
    resource_id=str(user.id),
    user_id=str(user.id),
    ip_address=request.client.host,
    status="success"
)
session.add(audit_log)
```

### API Key Permissions
```python
api_key = APIKey(
    key_hash=hash_api_key(raw_key),
    name="Production API Key",
    key_prefix=raw_key[:8],
    user_id=user.id,
    permissions={
        "read": True,
        "write": True,
        "admin": False
    }
)

# Check permissions
if api_key.has_permission("write"):
    # Allow write operation
    pass
```

## Security Considerations

1. **Never store raw passwords** - Always use Argon2 hashing
2. **Never store raw API keys** - Always hash with SHA256
3. **Validate all inputs** - Automatic through SecurityValidationMixin
4. **Use parameterized queries** - SQLAlchemy handles this
5. **Implement row-level security** - Use owner_id and organization_id
6. **Audit everything** - Use AuditLog for all sensitive operations

## Migration Commands

```bash
# Create initial migration
alembic revision --autogenerate -m "Initial models with audit mixins"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1
```

## Future Enhancements

1. **Additional Models** (as needed):
   - Organization model for multi-tenancy
   - RedTeamTarget model for attack targets
   - RedTeamSession model for attack sessions
   - Report model for results

2. **Enhanced Security**:
   - Database encryption at rest
   - Field-level encryption for sensitive data
   - More granular RLS policies

3. **Performance**:
   - Materialized views for complex queries
   - Partitioning for large tables (audit logs)
   - Read replicas for scaling

## Conclusion

The implemented database model system provides a robust, secure, and scalable foundation for the ViolentUTF API. All requirements from issue #16 have been successfully implemented with comprehensive testing and documentation.
