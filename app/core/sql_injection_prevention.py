"""SQL injection prevention framework for ViolentUTF API.

This module provides comprehensive SQL injection prevention at the API layer,
including query parameterization, validation, and monitoring.
"""

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.sql import ClauseElement
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class QueryType(str, Enum):
    """Types of SQL queries."""

    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    ALTER = "alter"
    DROP = "drop"
    TRUNCATE = "truncate"
    GRANT = "grant"
    REVOKE = "revoke"


class QueryValidationLevel(str, Enum):
    """Query validation strictness levels."""

    STRICT = "strict"  # Block all dynamic queries
    MODERATE = "moderate"  # Allow parameterized queries only
    LENIENT = "lenient"  # Allow some dynamic queries with validation
    NONE = "none"  # No validation (dangerous!)


class SQLInjectionPattern(BaseModel):
    """SQL injection pattern definition."""

    pattern: str
    description: str
    severity: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    examples: List[str] = Field(default_factory=list)


# Common SQL injection patterns
SQL_INJECTION_PATTERNS = [
    SQLInjectionPattern(
        pattern=r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
        description="SQL keywords that could indicate injection",
        severity="high",
        examples=["' UNION SELECT * FROM users", "'; DROP TABLE users; --"],
    ),
    SQLInjectionPattern(
        pattern=r"(--|#|/\*|\*/)",
        description="SQL comment indicators",
        severity="medium",
        examples=["admin' --", "admin' #", "admin' /* comment */"],
    ),
    SQLInjectionPattern(
        pattern=r"""('|"|`|´|'|'|"|")""",
        description="Quote characters that could break out of strings",
        severity="high",
        examples=["admin'", 'admin"', "admin`"],
    ),
    SQLInjectionPattern(
        pattern=r"(\b(or|and)\b\s*\d+\s*=\s*\d+)",
        description="Always-true conditions",
        severity="critical",
        examples=["' OR 1=1", "' AND 2=2"],
    ),
    SQLInjectionPattern(
        pattern=r"(;|\||&&)",
        description="Command separators and chaining",
        severity="high",
        examples=["'; DELETE FROM users", "admin' | whoami"],
    ),
    SQLInjectionPattern(
        pattern=r"(\b(sleep|benchmark|waitfor|pg_sleep)\b)",
        description="Time-based injection functions",
        severity="high",
        examples=["'; WAITFOR DELAY '00:00:05'", "' OR SLEEP(5)"],
    ),
    SQLInjectionPattern(
        pattern=r"(@@\w+|version\(\)|database\(\)|user\(\))",
        description="Database information functions",
        severity="medium",
        examples=["' UNION SELECT @@version", "' OR user() = 'root'"],
    ),
    SQLInjectionPattern(
        pattern=r"(\b(concat|char|ascii|substring|hex|unhex)\b\s*\()",
        description="String manipulation functions often used in injection",
        severity="medium",
        examples=["' UNION SELECT CONCAT(username, password)", "CHAR(65,66,67)"],
    ),
    SQLInjectionPattern(
        pattern=r"(information_schema|mysql|performance_schema|sys)",
        description="System database names",
        severity="high",
        examples=["' UNION SELECT * FROM information_schema.tables"],
    ),
    SQLInjectionPattern(
        pattern=r"(xp_cmdshell|sp_executesql|sp_makewebtask)",
        description="Dangerous stored procedures",
        severity="critical",
        examples=["'; EXEC xp_cmdshell 'dir'"],
    ),
]


class QueryParameter(BaseModel):
    """Represents a query parameter."""

    name: str
    value: Any
    type: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_parameter_name(cls, v: str) -> str:
        """Validate parameter name doesn't contain dangerous characters."""
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", v):
            raise ValueError(f"Invalid parameter name: {v}")
        return v


class SafeQuery(BaseModel):
    """Represents a validated safe query."""

    query: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    query_type: Optional[QueryType] = None
    validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE
    allowed_tables: Optional[Set[str]] = None
    allowed_columns: Optional[Set[str]] = None
    max_results: Optional[int] = None


def detect_sql_injection_patterns(
    value: str,
    patterns: Optional[List[SQLInjectionPattern]] = None,
    threshold: str = "medium",
) -> List[Tuple[SQLInjectionPattern, List[str]]]:
    """Detect SQL injection patterns in a string.

    Args:
        value: String to check for SQL injection patterns
        patterns: Custom patterns to check (defaults to SQL_INJECTION_PATTERNS)
        threshold: Minimum severity threshold (low, medium, high, critical)

    Returns:
        List of tuples containing matched patterns and their matches
    """
    if not value or not isinstance(value, str):
        return []

    if patterns is None:
        patterns = SQL_INJECTION_PATTERNS

    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity = severity_order.get(threshold, 1)

    detected = []
    for pattern in patterns:
        if severity_order.get(pattern.severity, 2) >= min_severity:
            matches = re.findall(pattern.pattern, value, re.IGNORECASE)
            if matches:
                detected.append((pattern, matches))

    return detected


def validate_query_parameter(
    name: str,
    value: Any,
    allowed_types: Optional[List[type]] = None,
    max_length: Optional[int] = None,
) -> bool:
    """Validate a query parameter.

    Args:
        name: Parameter name
        value: Parameter value
        allowed_types: List of allowed types for the value
        max_length: Maximum length for string values

    Returns:
        True if parameter is valid
    """
    # Validate parameter name
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
        logger.warning("invalid_parameter_name", name=name)
        return False

    # Validate value type
    if allowed_types and type(value) not in allowed_types:
        logger.warning(
            "invalid_parameter_type",
            name=name,
            value_type=type(value).__name__,
            allowed_types=[t.__name__ for t in allowed_types],
        )
        return False

    # Validate string length
    if isinstance(value, str) and max_length and len(value) > max_length:
        logger.warning(
            "parameter_too_long",
            name=name,
            length=len(value),
            max_length=max_length,
        )
        return False

    # Check for SQL injection in string values
    if isinstance(value, str):
        injections = detect_sql_injection_patterns(value, threshold="high")
        if injections:
            logger.warning(
                "sql_injection_in_parameter",
                name=name,
                patterns=[p.description for p, _ in injections],
            )
            return False

    return True


def build_safe_query(
    query_template: str,
    parameters: Dict[str, Any],
    validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE,
    allowed_tables: Optional[Set[str]] = None,
    allowed_columns: Optional[Set[str]] = None,
) -> SafeQuery:
    """Build a safe parameterized query.

    Args:
        query_template: Query template with named parameters
        parameters: Dictionary of parameter values
        validation_level: Validation strictness level
        allowed_tables: Set of allowed table names
        allowed_columns: Set of allowed column names

    Returns:
        SafeQuery object

    Raises:
        ValueError: If query or parameters are invalid
    """
    # Detect query type
    query_lower = query_template.lower().strip()
    query_type = None
    for qtype in QueryType:
        if query_lower.startswith(qtype.value):
            query_type = qtype
            break

    # Create SafeQuery object
    safe_query = SafeQuery(
        query=query_template,
        parameters=parameters,
        query_type=query_type,
        validation_level=validation_level,
        allowed_tables=allowed_tables,
        allowed_columns=allowed_columns,
    )

    # Validate based on level
    if validation_level == QueryValidationLevel.STRICT:
        # In strict mode, only allow specific pre-approved queries
        if query_type in [QueryType.DROP, QueryType.TRUNCATE, QueryType.ALTER]:
            raise ValueError(f"Query type {query_type} not allowed in strict mode")

    elif validation_level == QueryValidationLevel.MODERATE:
        # Validate all parameters
        for name, value in parameters.items():
            if not validate_query_parameter(name, value):
                raise ValueError(f"Invalid parameter: {name}")

        # Check for injection in query template
        injections = detect_sql_injection_patterns(query_template, threshold="medium")
        if injections:
            # Allow only if it's a proper parameterized query
            param_pattern = r":\w+|\$\d+|\?"
            if not re.search(param_pattern, query_template):
                raise ValueError("SQL injection patterns detected in query template")

    # Validate table and column names if provided
    if allowed_tables:
        # Use case-insensitive regex to find table names
        tables_in_query = re.findall(r"\b(?:from|join|into|update)\s+(\w+)", query_template.lower())
        for table in tables_in_query:
            if table not in allowed_tables:
                raise ValueError(f"Table '{table}' not allowed")

    if allowed_columns:
        # Simple column validation (more complex parsing would be needed for production)
        columns_in_query = re.findall(r"\b(\w+)\s*=", query_template)
        for column in columns_in_query:
            if column not in allowed_columns and column not in parameters:
                raise ValueError(f"Column '{column}' not allowed")

    return safe_query


def execute_safe_query(
    engine: Engine,
    safe_query: SafeQuery,
    fetch_one: bool = False,
    fetch_all: bool = True,
) -> Union[List[Dict[str, Any]], Dict[str, Any], None]:
    """Execute a validated safe query.

    Args:
        engine: SQLAlchemy engine
        safe_query: Validated SafeQuery object
        fetch_one: Fetch only one result
        fetch_all: Fetch all results

    Returns:
        Query results as list of dicts or single dict
    """
    try:
        # Log query execution
        logger.info(
            "executing_safe_query",
            query_type=safe_query.query_type,
            parameter_count=len(safe_query.parameters),
        )

        # Create SQLAlchemy text query with bound parameters
        stmt = text(safe_query.query)

        # Execute query
        with engine.connect() as conn:
            result = conn.execute(stmt, safe_query.parameters)

            # Handle different query types
            if safe_query.query_type == QueryType.SELECT:
                if fetch_one:
                    row = result.fetchone()
                    return dict(row._mapping) if row else None
                else:
                    rows = result.fetchall()
                    if safe_query.max_results and len(rows) > safe_query.max_results:
                        rows = rows[: safe_query.max_results]
                    return [dict(row._mapping) for row in rows]
            else:
                # For non-SELECT queries, commit and return affected rows
                conn.commit()
                return {"affected_rows": result.rowcount}

    except Exception as e:
        logger.error(
            "safe_query_execution_failed",
            error=str(e),
            query_type=safe_query.query_type,
        )
        raise


class SQLInjectionPreventionMiddleware:
    """Middleware to prevent SQL injection attacks."""

    def __init__(
        self,
        validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE,
        log_attempts: bool = True,
        block_on_detection: bool = True,
    ):
        """Initialize SQL injection prevention middleware.

        Args:
            validation_level: Default validation level
            log_attempts: Whether to log injection attempts
            block_on_detection: Whether to block requests with SQL injection
        """
        self.validation_level = validation_level
        self.log_attempts = log_attempts
        self.block_on_detection = block_on_detection

    def check_value(self, value: Any, field_name: str = "unknown") -> bool:
        """Check a single value for SQL injection.

        Args:
            value: Value to check
            field_name: Name of the field (for logging)

        Returns:
            True if value is safe, False if injection detected
        """
        if not isinstance(value, str):
            return True

        injections = detect_sql_injection_patterns(value, threshold="medium")
        if injections:
            if self.log_attempts:
                logger.warning(
                    "sql_injection_attempt_detected",
                    field=field_name,
                    patterns=[p.description for p, _ in injections],
                    severity=[p.severity for p, _ in injections],
                )
            return False

        return True

    def check_request_data(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Check request data for SQL injection.

        Args:
            data: Request data dictionary

        Returns:
            Tuple of (is_safe, list_of_unsafe_fields)
        """
        unsafe_fields = []

        for field_name, value in data.items():
            if isinstance(value, str):
                if not self.check_value(value, field_name):
                    unsafe_fields.append(field_name)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if not self.check_value(item, f"{field_name}[{i}]"):
                        unsafe_fields.append(f"{field_name}[{i}]")
            elif isinstance(value, dict):
                # Recursively check nested objects
                is_safe, nested_unsafe = self.check_request_data(value)
                if not is_safe:
                    unsafe_fields.extend([f"{field_name}.{f}" for f in nested_unsafe])

        return len(unsafe_fields) == 0, unsafe_fields


# Pre-defined safe query templates
SAFE_QUERY_TEMPLATES = {
    "get_user_by_id": SafeQuery(
        query="SELECT * FROM users WHERE id = :user_id",
        query_type=QueryType.SELECT,
        allowed_tables={"users"},
    ),
    "get_users_by_status": SafeQuery(
        query="SELECT * FROM users WHERE status = :status ORDER BY created_at DESC",
        query_type=QueryType.SELECT,
        allowed_tables={"users"},
    ),
    "update_user_email": SafeQuery(
        query="UPDATE users SET email = :email, updated_at = CURRENT_TIMESTAMP WHERE id = :user_id",
        query_type=QueryType.UPDATE,
        allowed_tables={"users"},
        allowed_columns={"email", "updated_at", "id"},
    ),
    "search_products": SafeQuery(
        query="""
        SELECT * FROM products
        WHERE (name ILIKE :search_term OR description ILIKE :search_term)
        AND status = 'active'
        ORDER BY relevance DESC
        LIMIT :limit OFFSET :offset
        """,
        query_type=QueryType.SELECT,
        allowed_tables={"products"},
        max_results=100,
    ),
}


def get_safe_query_template(template_name: str) -> SafeQuery:
    """Get a pre-defined safe query template.

    Args:
        template_name: Name of the template

    Returns:
        SafeQuery template

    Raises:
        KeyError: If template not found
    """
    if template_name not in SAFE_QUERY_TEMPLATES:
        raise KeyError(f"Query template '{template_name}' not found")
    # Deep copy to ensure immutability
    return SAFE_QUERY_TEMPLATES[template_name].model_copy(deep=True)


class QueryBuilder:
    """Safe query builder for dynamic queries."""

    def __init__(
        self,
        base_table: str,
        validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE,
    ):
        """Initialize query builder.

        Args:
            base_table: Base table name
            validation_level: Validation level for the query
        """
        self.base_table = base_table
        self.validation_level = validation_level
        self.select_columns: List[str] = []
        self.where_conditions: List[str] = []
        self.join_clauses: List[str] = []
        self.order_by: List[str] = []
        self.parameters: Dict[str, Any] = {}
        self.limit_value: Optional[int] = None
        self.offset_value: Optional[int] = None

    def select(self, *columns: str) -> "QueryBuilder":
        """Add columns to select."""
        for col in columns:
            if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", col):
                self.select_columns.append(col)
            else:
                raise ValueError(f"Invalid column name: {col}")
        return self

    def where(self, condition: str, **params: Any) -> "QueryBuilder":
        """Add WHERE condition with parameters."""
        # Validate condition doesn't contain injection
        if detect_sql_injection_patterns(condition, threshold="high"):
            raise ValueError("SQL injection pattern detected in WHERE condition")

        self.where_conditions.append(condition)
        self.parameters.update(params)
        return self

    def order_by_column(self, column: str, direction: str = "ASC") -> "QueryBuilder":
        """Add ORDER BY clause."""
        if direction.upper() not in ["ASC", "DESC"]:
            raise ValueError("Invalid sort direction")
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", column):
            self.order_by.append(f"{column} {direction}")
        else:
            raise ValueError(f"Invalid column name: {column}")
        return self

    def limit(self, limit: int) -> "QueryBuilder":
        """Set result limit."""
        if not isinstance(limit, int) or limit < 1:
            raise ValueError("Limit must be a positive integer")
        self.limit_value = limit
        return self

    def offset(self, offset: int) -> "QueryBuilder":
        """Set result offset."""
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("Offset must be a non-negative integer")
        self.offset_value = offset
        return self

    def build(self) -> SafeQuery:
        """Build the final SafeQuery."""
        # Build SELECT clause
        select_clause = "*" if not self.select_columns else ", ".join(self.select_columns)

        # Build query
        query_parts = [f"SELECT {select_clause}", f"FROM {self.base_table}"]

        # Add WHERE clause
        if self.where_conditions:
            query_parts.append("WHERE " + " AND ".join(self.where_conditions))

        # Add ORDER BY
        if self.order_by:
            query_parts.append("ORDER BY " + ", ".join(self.order_by))

        # Add LIMIT/OFFSET
        if self.limit_value:
            query_parts.append(f"LIMIT {self.limit_value}")
        if self.offset_value:
            query_parts.append(f"OFFSET {self.offset_value}")

        query = " ".join(query_parts)

        return SafeQuery(
            query=query,
            parameters=self.parameters,
            query_type=QueryType.SELECT,
            validation_level=self.validation_level,
            max_results=self.limit_value,
        )
