"""Unified database session management for audit automation scripts."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

try:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.session import get_db

    SQLALCHEMY_AVAILABLE = True
except ImportError:
    # Fallback for when SQLAlchemy is not available
    AsyncSession = None  # type: ignore
    get_db = None  # type: ignore[assignment]
    SQLALCHEMY_AVAILABLE = False

from audit_utils.exceptions import AuditError
from audit_utils.logging import setup_audit_logger

logger = setup_audit_logger(__name__)


@asynccontextmanager
async def get_audit_session() -> AsyncGenerator[Any, None]:
    """
    Standard async session manager for audit operations.

    Provides consistent error handling and connection management.

    Yields:
        AsyncSession: Database session with automatic transaction management

    Raises:
        AuditError: If database connection fails or SQLAlchemy is not available
    """
    if not SQLALCHEMY_AVAILABLE:
        raise AuditError(
            "Database session not available - SQLAlchemy dependencies not found",
            context={"feature": "database_session", "available": False},
        )

    if get_db is None:
        raise AuditError(
            "Database session factory not available", context={"feature": "database_session", "get_db_available": False}
        )

    session = None
    try:
        async with get_db() as session:
            logger.debug("Database session created for audit operation")
            yield session
            await session.commit()
            logger.debug("Database session committed successfully")
    except Exception as e:
        if session:
            try:
                await session.rollback()
                logger.warning("Database session rolled back due to error")
            except Exception as rollback_error:
                logger.error("Failed to rollback database session", error=str(rollback_error), original_error=str(e))

        logger.error("Database session error", error=str(e), error_type=type(e).__name__)
        raise AuditError(
            f"Database session error: {str(e)}", context={"original_error": str(e), "error_type": type(e).__name__}
        ) from e
    finally:
        if session:
            try:
                await session.close()
                logger.debug("Database session closed")
            except Exception as close_error:
                logger.warning("Error closing database session", error=str(close_error))


class AuditDatabaseMixin:
    """
    Mixin for consistent database access patterns in audit scripts.

    Provides standard CRUD operations with error handling and session management.
    """

    async def execute_query(self, query: Any, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """
        Execute query with standard session management.

        Args:
            query: SQLAlchemy query object or text
            params: Optional parameters for the query

        Returns:
            List of query results

        Raises:
            AuditError: If query execution fails
        """
        try:
            async with get_audit_session() as session:
                logger.debug("Executing audit query", query_type=str(type(query)))
                result = await session.execute(query, params or {})
                data = result.scalars().all()
                logger.debug("Query executed successfully", result_count=len(data))
                return data  # type: ignore[no-any-return]
        except Exception as e:
            logger.error(
                "Query execution failed", error=str(e), error_type=type(e).__name__, has_params=params is not None
            )
            raise AuditError(
                f"Query execution failed: {str(e)}",
                context={"query_type": str(type(query)), "has_params": params is not None, "original_error": str(e)},
            ) from e

    async def bulk_insert(self, model_class: Any, data_list: List[Dict[str, Any]]) -> int:
        """
        Bulk insert with optimized session handling.

        Args:
            model_class: SQLAlchemy model class
            data_list: List of dictionaries containing data to insert

        Returns:
            Number of records inserted

        Raises:
            AuditError: If bulk insert fails
        """
        if not data_list:
            logger.debug("No data provided for bulk insert")
            return 0

        try:
            async with get_audit_session() as session:
                logger.debug("Starting bulk insert", model=str(model_class), record_count=len(data_list))

                # Create model instances
                instances = [model_class(**data) for data in data_list]
                session.add_all(instances)
                await session.flush()

                logger.info(
                    "Bulk insert completed successfully", model=str(model_class), records_inserted=len(data_list)
                )
                return len(data_list)

        except Exception as e:
            logger.error(
                "Bulk insert failed",
                error=str(e),
                error_type=type(e).__name__,
                model=str(model_class),
                record_count=len(data_list),
            )
            raise AuditError(
                f"Bulk insert failed: {str(e)}",
                context={"model": str(model_class), "record_count": len(data_list), "original_error": str(e)},
            ) from e

    async def execute_batch_queries(self, queries: List[tuple[Any, Optional[Dict[str, Any]]]]) -> List[List[Any]]:
        """
        Execute multiple queries in a single transaction.

        Args:
            queries: List of (query, params) tuples

        Returns:
            List of result lists, one for each query

        Raises:
            AuditError: If batch execution fails
        """
        if not queries:
            logger.debug("No queries provided for batch execution")
            return []

        try:
            async with get_audit_session() as session:
                logger.debug("Starting batch query execution", query_count=len(queries))

                results = []
                for i, (query, params) in enumerate(queries):
                    logger.debug(f"Executing batch query {i+1}/{len(queries)}")
                    result = await session.execute(query, params or {})
                    data = result.scalars().all()
                    results.append(data)

                logger.info(
                    "Batch query execution completed",
                    query_count=len(queries),
                    total_results=sum(len(r) for r in results),
                )
                return results

        except Exception as e:
            logger.error(
                "Batch query execution failed", error=str(e), error_type=type(e).__name__, query_count=len(queries)
            )
            raise AuditError(
                f"Batch query execution failed: {str(e)}",
                context={"query_count": len(queries), "original_error": str(e)},
            ) from e


class AuditTransactionManager:
    """
    Advanced transaction manager for complex audit operations.

    Provides nested transaction support and rollback points.
    """

    def __init__(self) -> None:
        self.session = None
        self.savepoint_count = 0

    async def __aenter__(self) -> "AuditTransactionManager":
        """Enter async context and create session."""
        if not SQLALCHEMY_AVAILABLE:
            raise AuditError("Database transactions not available")

        self.session_context = get_audit_session()
        self.session = await self.session_context.__aenter__()
        logger.debug("Audit transaction manager started")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context and handle session cleanup."""
        try:
            if exc_type is not None:
                logger.warning(
                    "Transaction manager exiting with exception", exc_type=str(exc_type), exc_val=str(exc_val)
                )

            await self.session_context.__aexit__(exc_type, exc_val, exc_tb)
            logger.debug("Audit transaction manager completed")
        except Exception as e:
            logger.error("Error in transaction manager cleanup", error=str(e))
            raise
        finally:
            self.session = None

    async def create_savepoint(self) -> str:
        """
        Create a transaction savepoint.

        Returns:
            Savepoint identifier
        """
        if not self.session:
            raise AuditError("No active session for savepoint creation")

        self.savepoint_count += 1  # type: ignore[unreachable]
        savepoint_name = f"audit_sp_{self.savepoint_count}"

        await self.session.execute(f"SAVEPOINT {savepoint_name}")
        logger.debug("Savepoint created", savepoint=savepoint_name)
        return savepoint_name

    async def rollback_to_savepoint(self, savepoint_name: str) -> None:
        """
        Rollback to a specific savepoint.

        Args:
            savepoint_name: Name of the savepoint to rollback to
        """
        if not self.session:
            raise AuditError("No active session for savepoint rollback")

        await self.session.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")  # type: ignore[unreachable]
        logger.info("Rolled back to savepoint", savepoint=savepoint_name)

    async def execute_with_retry(
        self, operation: Any, max_retries: int = 3, *args: Any, **kwargs: Any  # Callable
    ) -> Any:
        """
        Execute operation with automatic retry on transient failures.

        Args:
            operation: Async callable to execute
            max_retries: Maximum number of retry attempts
            *args, **kwargs: Arguments to pass to operation

        Returns:
            Result of the operation

        Raises:
            AuditError: If operation fails after all retries
        """
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    logger.info(f"Retrying operation, attempt {attempt + 1}/{max_retries + 1}")
                    # Brief delay before retry
                    await asyncio.sleep(min(2**attempt, 10))  # Exponential backoff, max 10s

                result = await operation(*args, **kwargs)

                if attempt > 0:
                    logger.info(f"Operation succeeded on attempt {attempt + 1}")

                return result

            except Exception as e:
                last_error = e
                logger.warning(
                    f"Operation failed, attempt {attempt + 1}/{max_retries + 1}",
                    error=str(e),
                    error_type=type(e).__name__,
                )

                if attempt < max_retries:
                    continue
                else:
                    break

        logger.error("Operation failed after all retry attempts", max_retries=max_retries, final_error=str(last_error))
        raise AuditError(
            f"Operation failed after {max_retries + 1} attempts: {str(last_error)}",
            context={
                "max_retries": max_retries,
                "final_error": str(last_error),
                "final_error_type": type(last_error).__name__,
            },
        ) from last_error
