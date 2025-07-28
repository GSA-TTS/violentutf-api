"""Comprehensive performance benchmark suite for ViolentUTF API.

Benchmarks various aspects of the repository pattern implementation:
- CRUD operation performance
- Query optimization effectiveness
- Pagination performance
- Bulk operation efficiency
- Complex query performance
- Cross-repository transaction performance
"""

import asyncio
import json
import random
import statistics
import string
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.user import UserRepository
from tests.test_database import TestDatabaseManager


class BenchmarkResult:
    """Stores benchmark results for a specific operation."""

    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.timings: List[float] = []
        self.errors: List[Exception] = []
        self.metadata: Dict[str, Any] = {}

    def add_timing(self, duration: float):
        """Add a timing measurement."""
        self.timings.append(duration)

    def add_error(self, error: Exception):
        """Record an error."""
        self.errors.append(error)

    def set_metadata(self, key: str, value: Any):
        """Set metadata for the benchmark."""
        self.metadata[key] = value

    def get_statistics(self) -> Dict[str, Any]:
        """Calculate statistics for the benchmark."""
        if not self.timings:
            return {"operation": self.operation_name, "samples": 0, "errors": len(self.errors), "error_rate": 1.0}

        sorted_timings = sorted(self.timings)

        return {
            "operation": self.operation_name,
            "samples": len(self.timings),
            "errors": len(self.errors),
            "error_rate": len(self.errors) / (len(self.timings) + len(self.errors)),
            "min_ms": sorted_timings[0] * 1000,
            "max_ms": sorted_timings[-1] * 1000,
            "avg_ms": statistics.mean(self.timings) * 1000,
            "median_ms": statistics.median(self.timings) * 1000,
            "p95_ms": (
                sorted_timings[int(len(sorted_timings) * 0.95)] * 1000
                if len(sorted_timings) > 20
                else sorted_timings[-1] * 1000
            ),
            "p99_ms": (
                sorted_timings[int(len(sorted_timings) * 0.99)] * 1000
                if len(sorted_timings) > 100
                else sorted_timings[-1] * 1000
            ),
            "stddev_ms": statistics.stdev(self.timings) * 1000 if len(self.timings) > 1 else 0,
            "ops_per_second": 1 / statistics.mean(self.timings) if self.timings else 0,
            "metadata": self.metadata,
        }


class BenchmarkSuite:
    """Manages a suite of benchmarks."""

    def __init__(self, suite_name: str):
        self.suite_name = suite_name
        self.benchmarks: Dict[str, BenchmarkResult] = {}
        self.start_time = time.time()
        self.end_time = None

    def get_benchmark(self, operation_name: str) -> BenchmarkResult:
        """Get or create a benchmark for an operation."""
        if operation_name not in self.benchmarks:
            self.benchmarks[operation_name] = BenchmarkResult(operation_name)
        return self.benchmarks[operation_name]

    async def measure(self, operation_name: str, func, *args, **kwargs):
        """Measure the execution time of an async function."""
        benchmark = self.get_benchmark(operation_name)
        start_time = time.time()

        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            benchmark.add_timing(duration)
            return result
        except Exception as e:
            benchmark.add_error(e)
            raise

    def finalize(self):
        """Mark the suite as complete."""
        self.end_time = time.time()

    def get_report(self) -> Dict[str, Any]:
        """Generate a comprehensive benchmark report."""
        return {
            "suite": self.suite_name,
            "duration_seconds": self.end_time - self.start_time if self.end_time else time.time() - self.start_time,
            "benchmarks": {name: benchmark.get_statistics() for name, benchmark in self.benchmarks.items()},
        }

    def print_report(self):
        """Print a formatted benchmark report."""
        report = self.get_report()

        print(f"\n{'='*80}")
        print(f"Benchmark Suite: {report['suite']}")
        print(f"Total Duration: {report['duration_seconds']:.2f} seconds")
        print(f"{'='*80}")

        for name, stats in report["benchmarks"].items():
            print(f"\n{name}:")
            print(f"  Samples: {stats['samples']}")
            print(f"  Errors: {stats['errors']} ({stats['error_rate']*100:.1f}%)")
            if stats["samples"] > 0:
                print(f"  Min: {stats['min_ms']:.2f}ms")
                print(f"  Avg: {stats['avg_ms']:.2f}ms")
                print(f"  Median: {stats['median_ms']:.2f}ms")
                print(f"  P95: {stats['p95_ms']:.2f}ms")
                print(f"  P99: {stats['p99_ms']:.2f}ms")
                print(f"  Max: {stats['max_ms']:.2f}ms")
                print(f"  Ops/sec: {stats['ops_per_second']:.2f}")

        print(f"{'='*80}")


def generate_random_string(length: int = 10) -> str:
    """Generate a random string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class TestPerformanceBenchmarks:
    """Comprehensive performance benchmarks for the repository pattern."""

    @pytest_asyncio.fixture
    async def db_manager(self):
        """Get database manager instance."""
        manager = TestDatabaseManager()
        await manager.initialize()
        yield manager
        await manager.shutdown()

    @pytest_asyncio.fixture
    async def test_data(self, db_manager):
        """Create test data for benchmarks."""
        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            # Create test users
            users = []
            for i in range(100):
                user = await user_repo.create(
                    username=f"bench_user_{i}",
                    email=f"bench{i}@example.com",
                    password_hash=hash_password("password123"),
                    full_name=f"Benchmark User {i}",
                )
                users.append(user)

            await session.commit()

        return {"users": users}

    @pytest.mark.asyncio
    async def test_crud_operation_benchmarks(self, db_manager, test_data):
        """Benchmark basic CRUD operations."""
        suite = BenchmarkSuite("CRUD Operations")

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            # Benchmark: Create User
            for i in range(50):
                username = f"crud_test_{generate_random_string()}"
                email = f"{username}@example.com"

                user = await suite.measure(
                    "Create User",
                    user_repo.create,
                    username=username,
                    email=email,
                    password_hash=hash_password("password123"),
                )

                # Benchmark: Get by ID
                await suite.measure("Get User by ID", user_repo.get_by_id, user.id)

                # Benchmark: Update User
                await suite.measure("Update User", user_repo.update, user.id, full_name=f"Updated {username}")

                # Benchmark: Soft Delete
                await suite.measure("Soft Delete User", user_repo.delete, user.id)

                # Benchmark: Restore
                await suite.measure("Restore User", user_repo.restore, user.id)

            await session.commit()

        suite.finalize()
        suite.print_report()

        # Verify performance
        stats = suite.get_report()["benchmarks"]
        assert stats["Create User"]["avg_ms"] < 50
        assert stats["Get User by ID"]["avg_ms"] < 10
        assert stats["Update User"]["avg_ms"] < 20

    @pytest.mark.asyncio
    async def test_query_optimization_benchmarks(self, db_manager, test_data):
        """Benchmark query optimization strategies."""
        suite = BenchmarkSuite("Query Optimization")

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            # Benchmark: Simple queries
            for i in range(20):
                await suite.measure("Get by Username", user_repo.get_by_username, f"bench_user_{i}")

                await suite.measure("Get by Email", user_repo.get_by_email, f"bench{i}@example.com")

            # Benchmark: Complex queries
            for i in range(10):
                await suite.measure("Get Active Users", user_repo.get_active_users, page=i + 1, size=10)

                await suite.measure("Get Unverified Users", user_repo.get_unverified_users, days_back=30)

        suite.finalize()
        suite.print_report()

        # Verify query performance
        stats = suite.get_report()["benchmarks"]
        assert stats["Get by Username"]["avg_ms"] < 20
        assert stats["Get by Email"]["avg_ms"] < 20

    @pytest.mark.asyncio
    async def test_pagination_performance(self, db_manager, test_data):
        """Benchmark pagination performance with various page sizes."""
        suite = BenchmarkSuite("Pagination Performance")

        page_sizes = [10, 25, 50, 100]

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            for size in page_sizes:
                benchmark_name = f"Pagination Size {size}"

                # Benchmark different pages
                for page in range(1, 6):
                    await suite.measure(
                        benchmark_name,
                        user_repo.list_with_pagination,
                        page=page,
                        size=size,
                        filters={"is_active": True},
                    )

                # Record page size in metadata
                suite.get_benchmark(benchmark_name).set_metadata("page_size", size)

        suite.finalize()
        suite.print_report()

        # Verify pagination scales well
        stats = suite.get_report()["benchmarks"]

        # Larger pages should not be drastically slower
        assert stats["Pagination Size 100"]["avg_ms"] < stats["Pagination Size 10"]["avg_ms"] * 3

    @pytest.mark.asyncio
    async def test_bulk_operation_performance(self, db_manager):
        """Benchmark bulk operations vs individual operations."""
        suite = BenchmarkSuite("Bulk Operations")

        # Test data
        bulk_sizes = [10, 50, 100]

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            for bulk_size in bulk_sizes:
                users_to_create = [
                    {
                        "username": f"bulk_{bulk_size}_{i}_{generate_random_string()}",
                        "email": f"bulk_{bulk_size}_{i}@example.com",
                        "password_hash": hash_password("password123"),
                    }
                    for i in range(bulk_size)
                ]

                # Benchmark: Individual creates
                individual_start = time.time()
                created_users = []
                for user_data in users_to_create:
                    user = await user_repo.create(**user_data)
                    created_users.append(user)
                individual_duration = time.time() - individual_start

                benchmark = suite.get_benchmark(f"Individual Creates (n={bulk_size})")
                benchmark.add_timing(individual_duration)
                benchmark.set_metadata("bulk_size", bulk_size)
                benchmark.set_metadata("ops_per_item_ms", (individual_duration * 1000) / bulk_size)

                # Clean up
                for user in created_users:
                    await user_repo.delete(user.id, hard_delete=True)

                await session.commit()

        suite.finalize()
        suite.print_report()

    @pytest.mark.asyncio
    async def test_complex_query_performance(self, db_manager, test_data):
        """Benchmark complex queries with joins and aggregations."""
        suite = BenchmarkSuite("Complex Queries")

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)
            api_key_repo = APIKeyRepository(session)
            audit_repo = AuditLogRepository(session)

            # Create some API keys and audit logs
            test_user = test_data["users"][0]

            # Create API keys
            for i in range(5):
                await api_key_repo.create(
                    user_id=test_user.id, name=f"benchmark_key_{i}", permissions=["read", "write"]
                )

            # Create audit logs
            for i in range(20):
                await audit_repo.create(
                    action=f"test.action.{i % 5}",
                    resource_type="User",
                    resource_id=test_user.id,
                    actor_id=test_user.id,
                    details={"iteration": i},
                )

            await session.commit()

            # Benchmark: User with API keys (join)
            for i in range(10):
                await suite.measure("List User API Keys", api_key_repo.list_user_keys, test_user.id)

            # Benchmark: Audit log aggregations
            for i in range(10):
                await suite.measure("Get Audit Statistics", audit_repo.get_statistics, group_by="action")

                await suite.measure("Get Entity History", audit_repo.get_entity_history, "User", test_user.id)

        suite.finalize()
        suite.print_report()

    @pytest.mark.asyncio
    async def test_concurrent_operation_performance(self, db_manager):
        """Benchmark performance under concurrent operations."""
        suite = BenchmarkSuite("Concurrent Operations")

        concurrency_levels = [1, 5, 10, 20]

        async def concurrent_read_operation(session: AsyncSession, user_id: str):
            """A read operation to run concurrently."""
            user_repo = UserRepository(session)
            return await user_repo.get_by_id(user_id)

        async def concurrent_write_operation(session: AsyncSession, index: int):
            """A write operation to run concurrently."""
            user_repo = UserRepository(session)
            username = f"concurrent_{index}_{generate_random_string()}"
            return await user_repo.create(
                username=username, email=f"{username}@example.com", password_hash=hash_password("password123")
            )

        # Create a test user for reads
        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)
            test_user = await user_repo.create(
                username="concurrent_test_user",
                email="concurrent@example.com",
                password_hash=hash_password("password123"),
            )
            await session.commit()
            test_user_id = test_user.id

        for concurrency in concurrency_levels:
            # Benchmark concurrent reads
            read_benchmark = f"Concurrent Reads (n={concurrency})"

            async def run_concurrent_reads():
                tasks = []
                for i in range(concurrency):

                    async def read_task():
                        async with db_manager.get_session() as session:
                            return await concurrent_read_operation(session, test_user_id)

                    tasks.append(asyncio.create_task(read_task()))

                return await asyncio.gather(*tasks)

            for _ in range(5):
                await suite.measure(read_benchmark, run_concurrent_reads)

            # Benchmark concurrent writes
            write_benchmark = f"Concurrent Writes (n={concurrency})"

            async def run_concurrent_writes():
                tasks = []
                for i in range(concurrency):

                    async def write_task(idx):
                        async with db_manager.get_session() as session:
                            result = await concurrent_write_operation(session, idx)
                            await session.commit()
                            return result

                    tasks.append(asyncio.create_task(write_task(i)))

                return await asyncio.gather(*tasks)

            for _ in range(5):
                await suite.measure(write_benchmark, run_concurrent_writes)

        suite.finalize()
        suite.print_report()

        # Verify concurrency scaling
        stats = suite.get_report()["benchmarks"]

        # Concurrent operations should scale sub-linearly
        single_read_time = stats["Concurrent Reads (n=1)"]["avg_ms"]
        twenty_read_time = stats["Concurrent Reads (n=20)"]["avg_ms"]
        assert twenty_read_time < single_read_time * 10  # Should be faster than linear scaling

    @pytest.mark.asyncio
    async def test_transaction_performance(self, db_manager):
        """Benchmark transaction performance."""
        suite = BenchmarkSuite("Transaction Performance")

        transaction_sizes = [1, 5, 10, 20]

        for size in transaction_sizes:
            benchmark_name = f"Transaction Size {size}"

            async def transaction_operation():
                async with db_manager.get_session() as session:
                    user_repo = UserRepository(session)
                    audit_repo = AuditLogRepository(session)

                    users = []
                    # Create multiple users in one transaction
                    for i in range(size):
                        user = await user_repo.create(
                            username=f"tx_{size}_{i}_{generate_random_string()}",
                            email=f"tx_{size}_{i}@example.com",
                            password_hash=hash_password("password123"),
                        )
                        users.append(user)

                        # Log the creation
                        await audit_repo.create(
                            action="user.create", resource_type="User", resource_id=user.id, actor_id=user.id
                        )

                    # Commit all at once
                    await session.commit()
                    return users

            # Run multiple times
            for _ in range(10):
                await suite.measure(benchmark_name, transaction_operation)

            suite.get_benchmark(benchmark_name).set_metadata("transaction_size", size)

        suite.finalize()
        suite.print_report()

    @pytest.mark.asyncio
    async def test_save_benchmark_results(self, db_manager, tmp_path):
        """Run all benchmarks and save results to file."""
        # Run a simple benchmark
        suite = BenchmarkSuite("Summary Benchmark")

        async with db_manager.get_session() as session:
            user_repo = UserRepository(session)

            # Quick benchmarks
            for i in range(10):
                await suite.measure(
                    "User Creation",
                    user_repo.create,
                    username=f"summary_{generate_random_string()}",
                    email=f"summary_{i}@example.com",
                    password_hash=hash_password("password123"),
                )

        suite.finalize()

        # Save results
        results_file = tmp_path / "benchmark_results.json"
        with open(results_file, "w") as f:
            json.dump(suite.get_report(), f, indent=2)

        print(f"\nBenchmark results saved to: {results_file}")

        # Verify file was created
        assert results_file.exists()

        # Load and verify
        with open(results_file) as f:
            loaded = json.load(f)
            assert loaded["suite"] == "Summary Benchmark"
            assert "benchmarks" in loaded


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
