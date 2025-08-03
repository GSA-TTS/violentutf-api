"""Example endpoints demonstrating SQL injection prevention."""

from typing import Any, Dict, List, Optional

from appcore.decorators import prevent_sql_injection, use_safe_query, validate_sql_params
from appcore.rate_limiting import rate_limit
from appcore.sql_injection_prevention import (
    QueryBuilder,
    QueryValidationLevel,
    SafeQuery,
    build_safe_query,
    execute_safe_query,
    get_safe_query_template,
)
from appdb.session import get_db
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

logger = get_logger(__name__)

router = APIRouter()


class UserSearchRequest(BaseModel):
    """User search request model."""

    name: Optional[str] = Field(None, max_length=100)
    email: Optional[str] = Field(None, max_length=254)
    status: Optional[str] = Field(None, pattern="^(active|inactive|suspended)$")
    sort_by: str = Field(default="created_at", pattern="^(name|email|created_at|updated_at)$")
    sort_order: str = Field(default="DESC", pattern="^(ASC|DESC)$")
    limit: int = Field(default=10, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class ProductSearchRequest(BaseModel):
    """Product search request model."""

    query: str = Field(..., min_length=1, max_length=200)
    category: Optional[str] = Field(None, max_length=50)
    min_price: Optional[float] = Field(None, ge=0)
    max_price: Optional[float] = Field(None, ge=0)


@router.get("/users/search/unsafe")
@rate_limit("api")
async def unsafe_user_search(
    name: Optional[str] = Query(None, description="User name to search"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """UNSAFE example - demonstrates SQL injection vulnerability.

    ⚠️ WARNING: This endpoint is intentionally vulnerable for demonstration.
    DO NOT USE IN PRODUCTION!

    Try these injection attempts:
    - /users/search/unsafe?name=admin' OR '1'='1
    - /users/search/unsafe?name=admin'; DROP TABLE users; --
    """
    try:
        # UNSAFE: Direct string concatenation
        query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"  # nosec B608

        logger.warning(
            "unsafe_query_example",
            query=query,
            name=name,
        )

        # This would execute the unsafe query (commented out for safety)
        # result = await db.execute(text(query))
        # users = result.fetchall()

        return {
            "warning": "This is an UNSAFE example endpoint",
            "query": query,
            "injection_risk": "HIGH",
            "message": "In a real scenario, this could expose or delete your data!",
        }

    except Exception as e:
        logger.error("unsafe_search_error", error=str(e))
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Search failed",
        )


@router.get("/users/search/basic")
@rate_limit("api")
@prevent_sql_injection()  # Basic SQL injection prevention
async def basic_safe_user_search(
    name: Optional[str] = Query(None, description="User name to search"),
    email: Optional[str] = Query(None, description="Email to search"),
    status: Optional[str] = Query(None, description="User status"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Basic safe search with SQL injection prevention.

    This endpoint uses the @prevent_sql_injection decorator to automatically
    check all parameters for SQL injection patterns before processing.

    Try these (they will be blocked):
    - /users/search/basic?name=admin' OR '1'='1
    - /users/search/basic?email=test@example.com'; DROP TABLE users; --
    """
    try:
        # Build parameterized query
        query = """
        SELECT id, name, email, status, created_at
        FROM users
        WHERE 1=1
        """
        params = {}

        if name:
            query += " AND name ILIKE :name"
            params["name"] = f"%{name}%"

        if email:
            query += " AND email ILIKE :email"
            params["email"] = f"%{email}%"

        if status:
            query += " AND status = :status"
            params["status"] = status

        query += " ORDER BY created_at DESC LIMIT 20"

        # Execute safe parameterized query
        result = await db.execute(text(query), params)
        users = result.fetchall()

        return {
            "users": [
                {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "status": user.status,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                }
                for user in users
            ],
            "count": len(users),
            "query_type": "parameterized",
        }

    except Exception as e:
        logger.error("basic_search_error", error=str(e))
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Search failed",
        )


@router.post("/users/search/advanced")
@rate_limit("api")
@prevent_sql_injection(validation_level=QueryValidationLevel.STRICT)
async def advanced_safe_user_search(
    search_request: UserSearchRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Advanced safe search using SafeQuery builder.

    This endpoint demonstrates:
    1. Strict SQL injection prevention
    2. SafeQuery builder for dynamic queries
    3. Allowed tables and columns validation
    """
    try:
        # Use QueryBuilder for safe dynamic query construction
        builder = QueryBuilder("users", validation_level=QueryValidationLevel.STRICT)

        # Select specific columns
        builder.select("id", "name", "email", "status", "created_at")

        # Add WHERE conditions safely
        if search_request.name:
            builder.where("name ILIKE :name", name=f"%{search_request.name}%")

        if search_request.email:
            builder.where("email ILIKE :email", email=f"%{search_request.email}%")

        if search_request.status:
            builder.where("status = :status", status=search_request.status)

        # Add ORDER BY safely
        builder.order_by_column(search_request.sort_by, search_request.sort_order)

        # Add pagination
        builder.limit(search_request.limit).offset(search_request.offset)

        # Build the safe query
        safe_query = builder.build()

        # Execute the query
        result = await db.execute(text(safe_query.query), safe_query.parameters)
        users = result.fetchall()

        return {
            "users": [
                {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "status": user.status,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                }
                for user in users
            ],
            "count": len(users),
            "query_type": "safe_query_builder",
            "pagination": {
                "limit": search_request.limit,
                "offset": search_request.offset,
            },
        }

    except ValueError as e:
        logger.warning("invalid_query_construction", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid query: {str(e)}",
        )
    except Exception as e:
        logger.error("advanced_search_error", error=str(e))
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Search failed",
        )


@router.get("/products/search")
@rate_limit("api")
@validate_sql_params(
    allowed_tables={"products", "categories"},
    allowed_columns={"id", "name", "description", "price", "category_id", "status"},
    max_length=200,
)
@prevent_sql_injection()
async def search_products(
    query: str = Query(..., min_length=1, max_length=200),
    category: Optional[str] = Query(None, max_length=50),
    sort_by: str = Query(default="relevance", pattern="^(name|price|relevance|created_at)$"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Search products with validated parameters.

    This endpoint demonstrates parameter validation combined with
    SQL injection prevention for complex search queries.
    """
    try:
        # Build safe search query
        safe_query = build_safe_query(
            query_template="""
            SELECT p.id, p.name, p.description, p.price, c.name as category
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE (p.name ILIKE :search_term OR p.description ILIKE :search_term)
            AND p.status = 'active'
            """,
            parameters={
                "search_term": f"%{query}%",
            },
            validation_level=QueryValidationLevel.MODERATE,
            allowed_tables={"products", "categories"},
        )

        # Add category filter if provided
        if category:
            safe_query.query += " AND c.name = :category"
            safe_query.parameters["category"] = category

        # Add sorting
        sort_mapping = {
            "name": "p.name",
            "price": "p.price",
            "relevance": "ts_rank(p.search_vector, plainto_tsquery(:search_term))",
            "created_at": "p.created_at",
        }

        order_column = sort_mapping.get(sort_by, "p.created_at")
        safe_query.query += f" ORDER BY {order_column} DESC LIMIT 50"

        # Execute query
        result = await db.execute(text(safe_query.query), safe_query.parameters)
        products = result.fetchall()

        return {
            "products": [
                {
                    "id": product.id,
                    "name": product.name,
                    "description": (
                        product.description[:200] + "..." if len(product.description) > 200 else product.description
                    ),
                    "price": float(product.price),
                    "category": product.category,
                }
                for product in products
            ],
            "count": len(products),
            "search_term": query,
            "filters": {
                "category": category,
                "sort_by": sort_by,
            },
        }

    except ValueError as e:
        logger.warning("invalid_product_search", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid search parameters: {str(e)}",
        )
    except Exception as e:
        logger.error("product_search_error", error=str(e))
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Product search failed",
        )


@router.get("/users/{user_id}")
@rate_limit("api")
@use_safe_query(template_name="get_user_by_id")
async def get_user_by_id(
    user_id: int,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get user by ID using pre-defined safe query template.

    This endpoint uses a pre-defined query template that has been
    validated and tested for safety.
    """
    try:
        # Get the safe query template
        safe_query = get_safe_query_template("get_user_by_id")
        safe_query.parameters = {"user_id": user_id}

        # Execute the safe query
        result = await db.execute(text(safe_query.query), safe_query.parameters)
        user = result.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return {
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "status": user.status,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            },
            "query_type": "pre_defined_template",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_user_error", error=str(e), user_id=user_id)
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Failed to retrieve user",
        )


@router.post("/reports/generate")
@rate_limit("api")
@prevent_sql_injection(validation_level=QueryValidationLevel.STRICT)
async def generate_report(
    table_name: str = Query(..., description="Table to generate report from"),
    columns: List[str] = Query(..., description="Columns to include"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Generate a report with strict validation.

    This endpoint demonstrates how to handle dynamic table/column names
    safely by using strict validation and whitelisting.
    """
    # Whitelist of allowed tables and columns for reporting
    ALLOWED_REPORT_TABLES = {"users", "products", "orders", "audit_logs"}
    ALLOWED_REPORT_COLUMNS = {
        "users": {"id", "name", "email", "status", "created_at"},
        "products": {"id", "name", "price", "category", "stock"},
        "orders": {"id", "user_id", "total", "status", "created_at"},
        "audit_logs": {"id", "user_id", "action", "timestamp"},
    }

    try:
        # Validate table name
        if table_name not in ALLOWED_REPORT_TABLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Table '{table_name}' is not allowed for reporting",
            )

        # Validate columns
        allowed_cols = ALLOWED_REPORT_COLUMNS.get(table_name, set())
        invalid_cols = [col for col in columns if col not in allowed_cols]
        if invalid_cols:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid columns for table '{table_name}': {invalid_cols}",
            )

        # Build safe query with validated identifiers using SQLAlchemy
        # Since table_name and columns are validated against allowlists,
        # we can safely construct identifiers
        from sqlalchemy import column, select, table

        # Create table and column objects safely
        table_obj = table(table_name)
        column_objs = [column(col_name) for col_name in columns]

        # Build query using SQLAlchemy constructs
        query = select(*column_objs).select_from(table_obj).limit(100)

        # Execute query
        result = await db.execute(query)
        rows = result.fetchall()

        return {
            "report": {
                "table": table_name,
                "columns": columns,
                "row_count": len(rows),
                "data": [dict(row._mapping) for row in rows],
            },
            "generated_at": "2024-01-01T00:00:00Z",  # Would use actual timestamp
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("report_generation_error", error=str(e))
        raise HTTPException(
            status_code=500,  # HTTP_500_INTERNAL_SERVER_ERROR
            detail="Failed to generate report",
        )
