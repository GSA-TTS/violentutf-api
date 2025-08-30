"""Repository test fixtures for comprehensive unit testing."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import Result
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
def mock_session() -> AsyncMock:
    """Provide AsyncSession mock with SQLAlchemy 2.0 compatibility."""
    session = AsyncMock(spec=AsyncSession)

    # Configure standard session methods
    session.execute = AsyncMock()
    session.add = MagicMock()  # add is synchronous
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    session.refresh = AsyncMock()
    session.merge = AsyncMock()
    session.delete = MagicMock()  # delete is synchronous

    # Configure query result methods
    session.scalar = AsyncMock()
    session.scalars = AsyncMock()

    # Configure transaction support
    session.begin = AsyncMock()
    session.in_transaction = MagicMock(return_value=True)

    return session


@pytest.fixture
def query_result_factory() -> callable:
    """Factory for creating mock query results with various data patterns."""

    def _create_result(
        data: Optional[List[Any]] = None,
        scalar_result: Optional[Any] = None,
        count_result: Optional[int] = None,
    ) -> AsyncMock:
        """Create a mock Result object with configured return values."""
        result = AsyncMock(spec=Result)

        # Configure fetchall/fetchone methods
        result.fetchall = AsyncMock(return_value=data or [])
        result.fetchone = AsyncMock(return_value=data[0] if data else None)

        # Configure scalar methods
        result.scalar = MagicMock(return_value=scalar_result)
        result.scalar_one = MagicMock(return_value=scalar_result)
        result.scalar_one_or_none = MagicMock(return_value=scalar_result)

        # Configure scalars for multiple results
        scalars_mock = MagicMock()
        scalars_mock.all = MagicMock(return_value=data or [])
        scalars_mock.first = MagicMock(return_value=data[0] if data else None)
        result.scalars = MagicMock(return_value=scalars_mock)

        # Configure count/unique operations
        if count_result is not None:
            result.scalar.return_value = count_result

        return result

    return _create_result


@pytest.fixture
def database_error_factory() -> callable:
    """Factory for creating various database error scenarios."""

    def _create_error(error_type: str = "connection", message: str = "Database error") -> Exception:
        """Create database error for testing error handling."""
        if error_type == "connection":
            return SQLAlchemyError(message)
        elif error_type == "integrity":
            return IntegrityError(statement="INSERT INTO users...", params={}, orig=Exception(message))
        elif error_type == "timeout":
            return TimeoutError(message)
        else:
            return SQLAlchemyError(message)

    return _create_error


@pytest.fixture
def async_context_factory() -> callable:
    """Factory for creating async context managers for testing."""

    def _create_context(return_value: Any = None, side_effect: Exception = None):
        """Create async context manager mock."""
        context = AsyncMock()

        if side_effect:
            context.__aenter__ = AsyncMock(side_effect=side_effect)
        else:
            context.__aenter__ = AsyncMock(return_value=return_value)

        context.__aexit__ = AsyncMock(return_value=False)
        return context

    return _create_context


@pytest.fixture
def transaction_mock_factory(mock_session: AsyncMock) -> callable:
    """Factory for creating transaction mock scenarios."""

    def _create_transaction_mock(commit_success: bool = True, rollback_on_error: bool = True) -> AsyncMock:
        """Create transaction mock with configurable behavior."""
        transaction = AsyncMock()

        if commit_success:
            transaction.commit = AsyncMock()
        else:
            transaction.commit = AsyncMock(side_effect=SQLAlchemyError("Commit failed"))

        if rollback_on_error:
            transaction.rollback = AsyncMock()
        else:
            transaction.rollback = AsyncMock(side_effect=SQLAlchemyError("Rollback failed"))

        # Configure session to return this transaction
        mock_session.begin.return_value = transaction
        return transaction

    return _create_transaction_mock


@pytest.fixture
def pagination_result_factory() -> callable:
    """Factory for creating paginated query results."""

    def _create_pagination_result(
        total_items: int,
        page_size: int,
        current_page: int,
        items: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Create pagination result data structure."""
        if items is None:
            # Generate mock items based on pagination parameters
            start_idx = (current_page - 1) * page_size
            end_idx = min(start_idx + page_size, total_items)
            items = [f"item_{i}" for i in range(start_idx, end_idx)]

        total_pages = (total_items + page_size - 1) // page_size

        return {
            "items": items,
            "total": total_items,
            "page": current_page,
            "size": page_size,
            "pages": total_pages,
            "has_next": current_page < total_pages,
            "has_prev": current_page > 1,
        }

    return _create_pagination_result


@pytest.fixture
def performance_monitor() -> callable:
    """Performance monitoring utility for test execution."""
    import time

    def _monitor_performance(func_name: str = "test_function"):
        """Context manager for monitoring test performance."""

        class PerformanceMonitor:
            def __init__(self, name: str):
                self.name = name
                self.start_time = None
                self.end_time = None

            def __enter__(self):
                self.start_time = time.time()
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.end_time = time.time()
                duration = self.end_time - self.start_time
                # Log performance metrics for optimization
                if duration > 0.1:  # 100ms threshold for unit tests
                    print(f"WARNING: {self.name} took {duration:.3f}s (>100ms)")

            @property
            def duration(self) -> float:
                if self.start_time and self.end_time:
                    return self.end_time - self.start_time
                return 0.0

        return PerformanceMonitor(func_name)

    return _monitor_performance


@pytest.fixture
def mock_validation_factory() -> callable:
    """Factory for creating input validation test scenarios."""

    def _create_validation_test(
        valid_input: Dict[str, Any], invalid_inputs: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create validation test scenarios."""
        return {"valid": valid_input, "invalid": invalid_inputs or []}

    return _create_validation_test
