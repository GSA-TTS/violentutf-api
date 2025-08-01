# SQL Injection Prevention Guide

## Overview

The ViolentUTF API includes a comprehensive SQL injection prevention framework that provides multiple layers of protection against SQL injection attacks at the API layer. This guide covers the architecture, usage patterns, and best practices.

## Architecture

The SQL injection prevention framework consists of:

1. **Core Module** (`app/core/sql_injection_prevention.py`): Main prevention logic
2. **Decorators** (`app/core/decorators/sql_injection.py`): Easy-to-use endpoint protection
3. **Pattern Detection**: Configurable SQL injection pattern matching
4. **Query Building**: Safe query construction utilities
5. **Middleware**: Request-level SQL injection detection

## Key Components

### 1. SQL Injection Pattern Detection

The framework detects common SQL injection patterns including:

- **Basic Injections**: `' OR '1'='1`, `admin' --`
- **UNION Attacks**: `' UNION SELECT * FROM users`
- **Time-Based**: `'; WAITFOR DELAY '00:00:05'`
- **Command Execution**: `'; EXEC xp_cmdshell`
- **Information Gathering**: `@@version`, `database()`

### 2. Query Validation Levels

- **STRICT**: Blocks all potentially dangerous queries
- **MODERATE**: Allows parameterized queries only (default)
- **LENIENT**: Allows some dynamic queries with validation
- **NONE**: No validation (dangerous!)

### 3. Safe Query Building

The framework provides multiple approaches for building safe queries:

#### QueryBuilder Class

```python
from app.core.sql_injection_prevention import QueryBuilder

# Build a safe SELECT query
builder = QueryBuilder("users")
query = (
    builder
    .select("id", "name", "email")
    .where("status = :status", status="active")
    .where("created_at > :date", date="2024-01-01")
    .order_by("created_at", "DESC")
    .limit(10)
    .build()
)
```

#### SafeQuery with Validation

```python
from app.core.sql_injection_prevention import build_safe_query

safe_query = build_safe_query(
    query_template="SELECT * FROM users WHERE email = :email",
    parameters={"email": "user@example.com"},
    allowed_tables={"users"},
    allowed_columns={"id", "name", "email"}
)
```

## Usage Examples

### Basic SQL Injection Prevention

```python
from fastapi import APIRouter, Query
from app.core.decorators import prevent_sql_injection

router = APIRouter()

@router.get("/users/search")
@prevent_sql_injection()  # Automatically checks all parameters
async def search_users(
    name: str = Query(None),
    email: str = Query(None)
):
    # Parameters are validated before reaching this point
    # SQL injection attempts will be blocked with 400 error
    return {"users": []}
```

### Strict Validation Mode

```python
@router.post("/admin/query")
@prevent_sql_injection(validation_level=QueryValidationLevel.STRICT)
async def admin_query(query_data: QueryRequest):
    # Only pre-approved query patterns allowed
    # DROP, TRUNCATE, ALTER blocked entirely
    return {"result": []}
```

### Parameter Validation

```python
@router.get("/reports")
@validate_sql_params(
    allowed_tables={"users", "orders", "products"},
    allowed_columns={"id", "name", "status", "created_at"},
    max_length=100
)
async def generate_report(
    table: str,
    columns: List[str],
    filter_by: Optional[str] = None
):
    # Table and column names are validated against whitelist
    return {"report": []}
```

### Using Pre-defined Query Templates

```python
# Define safe templates
SAFE_QUERIES = {
    "user_by_email": SafeQuery(
        query="SELECT * FROM users WHERE email = :email",
        allowed_tables={"users"}
    )
}

@router.get("/users/by-email")
@use_safe_query(template_name="user_by_email")
async def get_user_by_email(email: str):
    # Forces use of pre-validated query template
    return {"user": {}}
```

## Best Practices

### 1. Always Use Parameterized Queries

**Good:**
```python
query = "SELECT * FROM users WHERE id = :user_id"
params = {"user_id": user_id}
result = await db.execute(text(query), params)
```

**Bad:**
```python
# NEVER DO THIS!
query = f"SELECT * FROM users WHERE id = {user_id}"
result = await db.execute(text(query))
```

### 2. Whitelist Table and Column Names

When dynamic table/column names are needed:

```python
ALLOWED_TABLES = {"users", "products", "orders"}
ALLOWED_COLUMNS = {"id", "name", "price", "status"}

def validate_table_column(table: str, column: str):
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table: {table}")
    if column not in ALLOWED_COLUMNS:
        raise ValueError(f"Invalid column: {column}")
```

### 3. Use Appropriate Validation Levels

- **Public APIs**: Use STRICT or MODERATE
- **Internal APIs**: MODERATE is usually sufficient
- **Admin APIs**: Can use MODERATE with additional authentication
- **Never use NONE** in production

### 4. Layer Your Defenses

Combine multiple protection mechanisms:

```python
@router.post("/search")
@rate_limit("api")  # Rate limiting
@prevent_sql_injection()  # SQL injection prevention
@sanitize_request(rules)  # Input sanitization
@validate_request(validation_config)  # Input validation
async def search(search_data: SearchRequest):
    # Multiple layers of protection
    pass
```

### 5. Log and Monitor

The framework automatically logs SQL injection attempts:

```python
# Configure logging
middleware = SQLInjectionPreventionMiddleware(
    log_attempts=True,  # Log all injection attempts
    block_on_detection=True  # Block suspicious requests
)
```

## Common Patterns

### Search Functionality

```python
@router.get("/products/search")
@prevent_sql_injection()
async def search_products(
    query: str = Query(..., min_length=1, max_length=200),
    category: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    db: AsyncSession = Depends(get_session)
):
    # Build safe query
    builder = QueryBuilder("products")

    # Add search condition
    builder.where(
        "(name ILIKE :search OR description ILIKE :search)",
        search=f"%{query}%"
    )

    # Add filters
    if category:
        builder.where("category = :category", category=category)
    if min_price is not None:
        builder.where("price >= :min_price", min_price=min_price)
    if max_price is not None:
        builder.where("price <= :max_price", max_price=max_price)

    # Execute safe query
    safe_query = builder.limit(50).build()
    result = await db.execute(text(safe_query.query), safe_query.parameters)

    return {"products": result.fetchall()}
```

### Dynamic Reporting

```python
@router.post("/reports/custom")
@prevent_sql_injection(validation_level=QueryValidationLevel.STRICT)
async def custom_report(
    report_config: ReportConfig,
    db: AsyncSession = Depends(get_session)
):
    # Validate against whitelist
    if report_config.table not in ALLOWED_REPORT_TABLES:
        raise HTTPException(400, "Invalid table")

    for col in report_config.columns:
        if col not in ALLOWED_COLUMNS[report_config.table]:
            raise HTTPException(400, f"Invalid column: {col}")

    # Build safe query with validated identifiers
    columns = ", ".join(report_config.columns)
    query = f"SELECT {columns} FROM {report_config.table}"

    if report_config.filters:
        conditions = []
        params = {}
        for i, filter in enumerate(report_config.filters):
            conditions.append(f"{filter.column} {filter.operator} :param{i}")
            params[f"param{i}"] = filter.value

        query += " WHERE " + " AND ".join(conditions)
        result = await db.execute(text(query), params)
    else:
        result = await db.execute(text(query))

    return {"data": result.fetchall()}
```

## Testing SQL Injection Prevention

### Unit Tests

```python
def test_sql_injection_detection():
    # Test various injection patterns
    assert detect_sql_injection_patterns("' OR '1'='1")
    assert detect_sql_injection_patterns("admin' --")
    assert detect_sql_injection_patterns("'; DROP TABLE users; --")

    # Test safe inputs
    assert not detect_sql_injection_patterns("john@example.com")
    assert not detect_sql_injection_patterns("Product Name 123")
```

### Integration Tests

```python
async def test_endpoint_blocks_injection():
    # Attempt SQL injection
    response = await client.get(
        "/users/search",
        params={"name": "admin' OR '1'='1"}
    )
    assert response.status_code == 400
    assert "SQL injection attempt detected" in response.json()["detail"]
```

## Troubleshooting

### Issue: False Positives

**Symptom**: Legitimate queries are blocked

**Solution**: Adjust validation level or patterns:

```python
@prevent_sql_injection(
    validation_level=QueryValidationLevel.MODERATE,
    check_query_params=True,
    check_body=False  # Don't check body if it contains code/SQL
)
```

### Issue: Performance Impact

**Symptom**: Slow request processing

**Solution**: Optimize pattern matching:

```python
# Check only critical fields
@prevent_sql_injection(
    check_path_params=False,  # Skip if not user-controlled
    check_query_params=True,
    check_body=True
)
```

### Issue: Complex Queries Blocked

**Symptom**: Legitimate complex queries are rejected

**Solution**: Use pre-defined templates:

```python
# Define complex query as safe template
COMPLEX_QUERY = SafeQuery(
    query="""
    WITH user_stats AS (
        SELECT user_id, COUNT(*) as order_count
        FROM orders
        GROUP BY user_id
    )
    SELECT u.*, us.order_count
    FROM users u
    JOIN user_stats us ON u.id = us.user_id
    WHERE us.order_count > :min_orders
    """,
    query_type=QueryType.SELECT,
    allowed_tables={"users", "orders"}
)
```

## Security Considerations

1. **Defense in Depth**: SQL injection prevention is one layer. Also use:
   - Prepared statements at the database layer
   - Least privilege database users
   - Input validation and sanitization
   - Web Application Firewall (WAF)

2. **Regular Updates**: Keep pattern definitions updated:
   ```python
   # Regularly review and update patterns
   SQL_INJECTION_PATTERNS.append(
       SQLInjectionPattern(
           pattern=r"new_attack_pattern",
           description="Description of new attack",
           severity="high"
       )
   )
   ```

3. **Monitoring**: Set up alerts for injection attempts:
   ```python
   # Log analysis to detect attack patterns
   logger.warning("sql_injection_attempt", {
       "ip": request.client.host,
       "endpoint": request.url.path,
       "patterns": detected_patterns
   })
   ```

4. **Testing**: Regularly test with tools like:
   - SQLMap
   - OWASP ZAP
   - Burp Suite

## Conclusion

The SQL injection prevention framework provides robust protection against SQL injection attacks while maintaining flexibility for legitimate queries. By combining pattern detection, parameter validation, safe query building, and proper logging, you can effectively protect your API from SQL injection vulnerabilities.

Remember: **Never trust user input** and always use parameterized queries!
