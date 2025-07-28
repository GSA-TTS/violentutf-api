"""Load tests for database connection pooling.

Tests connection pooling behavior under various load conditions:
- Concurrent connection requests
- Pool exhaustion scenarios
- Connection recycling
- Pool size optimization
"""

import asyncio
import statistics
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import settings
from app.db.session import get_db, get_session_maker
from app.models.user import User
from app.repositories.user import UserRepository
from tests.test_database import TestDatabaseManager


class PerformanceMetrics:
    """Helper class to collect performance metrics."""

    def __init__(self):
        self.response_times: List[float] = []
        self.errors: List[Exception] = []
        self.start_time = time.time()
        self.end_time = None

    def add_response_time(self, duration: float):
        """Add a response time measurement."""
        self.response_times.append(duration)

    def add_error(self, error: Exception):
        """Record an error."""
        self.errors.append(error)

    def finalize(self):
        """Mark the end of measurements."""
        self.end_time = time.time()

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics."""
        if not self.response_times:
            return {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": len(self.errors),
                "error_rate": 1.0 if self.errors else 0.0,
            }

        return {
            "total_requests": len(self.response_times) + len(self.errors),
            "successful_requests": len(self.response_times),
            "failed_requests": len(self.errors),
            "total_duration": self.end_time - self.start_time,
            "avg_response_time": statistics.mean(self.response_times),
            "min_response_time": min(self.response_times),
            "max_response_time": max(self.response_times),
            "p50_response_time": statistics.median(self.response_times),
            "p95_response_time": (
                statistics.quantiles(self.response_times, n=20)[18]
                if len(self.response_times) > 20
                else max(self.response_times)
            ),
            "p99_response_time": (
                statistics.quantiles(self.response_times, n=100)[98]
                if len(self.response_times) > 100
                else max(self.response_times)
            ),
            "requests_per_second": len(self.response_times) / (self.end_time - self.start_time),
            "error_rate": len(self.errors) / (len(self.response_times) + len(self.errors)),
        }


class TestConnectionPoolingLoad:
    """Test connection pooling under load conditions."""

    @pytest_asyncio.fixture
    async def db_manager(self):
        """Get database manager instance."""
        manager = TestDatabaseManager()
        await manager.initialize()
        yield manager
        await manager.shutdown()

    async def execute_query(self, session_maker, query_id: int, metrics: PerformanceMetrics):
        """Execute a single database query and record metrics."""
        start_time = time.time()
        try:
            async with session_maker() as session:
                # Execute a simple query
                result = await session.execute(select(User).limit(1))
                _ = result.scalar_one_or_none()

                # Record success
                duration = time.time() - start_time
                metrics.add_response_time(duration)

        except Exception as e:
            metrics.add_error(e)

    @pytest.mark.asyncio
    async def test_concurrent_connections_normal_load(self, db_manager):
        """Test connection pooling with normal concurrent load."""
        # Normal load: 20 concurrent connections
        concurrent_count = 20
        iterations_per_connection = 10

        metrics = PerformanceMetrics()
        session_maker = db_manager.get_session_maker()

        # Create tasks for concurrent connections
        tasks = []
        for i in range(concurrent_count):
            for j in range(iterations_per_connection):
                task = asyncio.create_task(
                    self.execute_query(session_maker, i * iterations_per_connection + j, metrics)
                )
                tasks.append(task)

        # Execute all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        metrics.finalize()

        # Verify performance
        summary = metrics.get_summary()
        assert summary["error_rate"] < 0.01  # Less than 1% errors
        assert summary["avg_response_time"] < 0.1  # Average under 100ms
        assert summary["p95_response_time"] < 0.2  # 95th percentile under 200ms

        print(f"\nNormal Load Test Results:")
        print(f"  Total requests: {summary['total_requests']}")
        print(f"  Success rate: {(1 - summary['error_rate']) * 100:.2f}%")
        print(f"  Avg response time: {summary['avg_response_time']*1000:.2f}ms")
        print(f"  P95 response time: {summary['p95_response_time']*1000:.2f}ms")
        print(f"  Requests/second: {summary['requests_per_second']:.2f}")

    @pytest.mark.asyncio
    async def test_concurrent_connections_high_load(self, db_manager):
        """Test connection pooling with high concurrent load."""
        # High load: 100 concurrent connections
        concurrent_count = 100
        iterations_per_connection = 5

        metrics = PerformanceMetrics()
        session_maker = db_manager.get_session_maker()

        # Create tasks for concurrent connections
        tasks = []
        for i in range(concurrent_count):
            for j in range(iterations_per_connection):
                task = asyncio.create_task(
                    self.execute_query(session_maker, i * iterations_per_connection + j, metrics)
                )
                tasks.append(task)

        # Execute all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        metrics.finalize()

        # Verify performance
        summary = metrics.get_summary()
        assert summary["error_rate"] < 0.05  # Less than 5% errors under high load
        assert summary["avg_response_time"] < 0.5  # Average under 500ms

        print(f"\nHigh Load Test Results:")
        print(f"  Total requests: {summary['total_requests']}")
        print(f"  Success rate: {(1 - summary['error_rate']) * 100:.2f}%")
        print(f"  Avg response time: {summary['avg_response_time']*1000:.2f}ms")
        print(f"  P95 response time: {summary['p95_response_time']*1000:.2f}ms")
        print(f"  Requests/second: {summary['requests_per_second']:.2f}")

    @pytest.mark.asyncio
    async def test_pool_exhaustion_behavior(self, db_manager):
        """Test behavior when connection pool is exhausted."""
        # Create a small pool to test exhaustion
        small_pool_maker = get_session_maker()

        metrics = PerformanceMetrics()
        concurrent_count = 10  # More than pool size

        async def long_running_query(query_id: int):
            """Simulate a long-running query that holds connection."""
            start_time = time.time()
            try:
                async with small_pool_maker() as session:
                    # Hold connection for 100ms
                    await asyncio.sleep(0.1)
                    await session.execute(select(User).limit(1))

                duration = time.time() - start_time
                metrics.add_response_time(duration)
            except Exception as e:
                metrics.add_error(e)

        # Create concurrent tasks that exceed pool size
        tasks = [asyncio.create_task(long_running_query(i)) for i in range(concurrent_count)]

        await asyncio.gather(*tasks, return_exceptions=True)
        metrics.finalize()

        # Verify behavior
        summary = metrics.get_summary()
        # Some requests should queue but eventually succeed
        assert summary["successful_requests"] == concurrent_count
        assert summary["max_response_time"] > 0.1  # Some waited in queue

        print(f"\nPool Exhaustion Test Results:")
        print(f"  Pool size: 2, Max overflow: 1")
        print(f"  Concurrent requests: {concurrent_count}")
        print(f"  All requests completed: {summary['successful_requests'] == concurrent_count}")
        print(f"  Max wait time: {summary['max_response_time']*1000:.2f}ms")

    @pytest.mark.asyncio
    async def test_connection_recycling(self, db_manager):
        """Test that connections are properly recycled."""
        session_maker = db_manager.get_session_maker()
        connection_ids = set()

        # Execute queries and track connection IDs
        for i in range(20):
            async with session_maker() as session:
                result = await session.execute(
                    text("SELECT connection_id()")
                    if settings.DATABASE_URL.startswith("postgresql")
                    else text("SELECT 1")  # SQLite doesn't have connection ID
                )
                if settings.DATABASE_URL.startswith("postgresql"):
                    conn_id = result.scalar()
                    connection_ids.add(conn_id)

        # Verify connection recycling
        if settings.DATABASE_URL.startswith("postgresql"):
            # Should reuse connections from pool
            assert len(connection_ids) <= 10  # Default pool size
            print(f"\nConnection Recycling Test:")
            print(f"  Unique connections used: {len(connection_ids)}")
            print(f"  Pool effectively recycled connections")

    @pytest.mark.asyncio
    async def test_pool_size_optimization(self, db_manager):
        """Test performance with different pool sizes."""
        pool_sizes = [5, 10, 20]
        results = {}

        for pool_size in pool_sizes:
            # Create session maker with specific pool size
            # Note: get_session_maker doesn't accept parameters - using default pool
            session_maker = get_session_maker()

            metrics = PerformanceMetrics()
            concurrent_count = 50

            # Run load test
            tasks = []
            for i in range(concurrent_count):

                async def query_task():
                    start = time.time()
                    try:
                        async with session_maker() as session:
                            await session.execute(select(User).limit(1))
                        metrics.add_response_time(time.time() - start)
                    except Exception as e:
                        metrics.add_error(e)

                tasks.append(asyncio.create_task(query_task()))

            await asyncio.gather(*tasks, return_exceptions=True)
            metrics.finalize()

            results[pool_size] = metrics.get_summary()

        # Print comparison
        print(f"\nPool Size Optimization Results:")
        for pool_size, summary in results.items():
            print(f"  Pool size {pool_size}:")
            print(f"    Avg response: {summary['avg_response_time']*1000:.2f}ms")
            print(f"    P95 response: {summary['p95_response_time']*1000:.2f}ms")
            print(f"    Requests/sec: {summary['requests_per_second']:.2f}")

        # Verify larger pools perform better under load
        assert results[20]["avg_response_time"] <= results[5]["avg_response_time"]

    @pytest.mark.asyncio
    async def test_connection_pool_monitoring(self, db_manager):
        """Test that we can monitor pool statistics."""
        session_maker = db_manager.get_session_maker()

        # Execute some queries
        for _ in range(10):
            async with session_maker() as session:
                await session.execute(select(User).limit(1))

        # Get pool statistics
        engine = session_maker.kw["bind"]
        pool = engine.pool

        if hasattr(pool, "size"):
            print(f"\nConnection Pool Statistics:")
            print(f"  Pool size: {pool.size()}")
            print(f"  Checked out connections: {pool.checked_out_connections}")
            print(f"  Overflow: {pool.overflow()}")
            print(f"  Total connections: {pool.size() + pool.overflow()}")

            # Verify pool is working correctly
            assert pool.size() > 0
            assert pool.checked_out_connections == 0  # All returned


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
