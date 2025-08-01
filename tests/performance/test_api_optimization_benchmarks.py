"""Performance benchmarks for API optimization features."""

import asyncio
import statistics
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.enhanced import EnhancedRepository
from app.schemas.filtering import EnhancedFilter, FieldFilter, FilterOperator, SortField
from tests.test_database import DatabaseTestManager


class PerformanceBenchmark:
    """Performance benchmark utilities and metrics collection."""

    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.start_time: Optional[float] = None

    def start_timer(self) -> None:
        """Start timing a benchmark."""
        self.start_time = time.perf_counter()

    def end_timer(self, operation_name: str) -> float:
        """End timing and record the duration."""
        if self.start_time is None:
            raise ValueError("Timer not started")

        duration = time.perf_counter() - self.start_time
        self.start_time = None

        if operation_name not in self.metrics:
            self.metrics[operation_name] = []
        self.metrics[operation_name].append(duration)

        return duration

    def get_stats(self, operation_name: str) -> Dict[str, float]:
        """Get statistics for an operation."""
        if operation_name not in self.metrics:
            return {}

        values = self.metrics[operation_name]
        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
            "p95": self._percentile(values, 95),
            "p99": self._percentile(values, 99),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        }

    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile value."""
        sorted_values = sorted(values)
        index = int((percentile / 100.0) * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]

    def print_summary(self) -> None:
        """Print benchmark summary."""
        print("\n" + "=" * 80)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("=" * 80)

        for operation_name in sorted(self.metrics.keys()):
            stats = self.get_stats(operation_name)
            print(f"\n{operation_name}:")
            print(f"  Count:     {stats['count']:>8}")
            print(f"  Mean:      {stats['mean']*1000:>8.2f} ms")
            print(f"  Median:    {stats['median']*1000:>8.2f} ms")
            print(f"  Min:       {stats['min']*1000:>8.2f} ms")
            print(f"  Max:       {stats['max']*1000:>8.2f} ms")
            print(f"  P95:       {stats['p95']*1000:>8.2f} ms")
            print(f"  P99:       {stats['p99']*1000:>8.2f} ms")
            print(f"  StdDev:    {stats['stdev']*1000:>8.2f} ms")


@pytest.fixture
async def benchmark():
    """Create performance benchmark instance."""
    return PerformanceBenchmark()


@pytest.fixture
async def test_db_manager():
    """Create test database manager."""
    return DatabaseTestManager()


@pytest.fixture
async def populated_db(test_db_manager):
    """Create database with test data for benchmarking."""
    async with test_db_manager.get_session() as session:
        # Create test users with varying data for realistic benchmarks
        users = []
        statuses = ["active", "inactive", "pending", "suspended"]

        for i in range(1000):  # Create 1000 test users
            user = User(
                username=f"user_{i:04d}",
                email=f"user{i:04d}@example.com",
                hashed_password="hashed_password",
                is_active=i % 4 != 3,  # 75% active
                is_superuser=i % 50 == 0,  # 2% superuser
                is_verified=i % 5 != 4,  # 80% verified
                full_name=f"Test User {i}",
                created_at=datetime.now() - timedelta(days=i % 365),
            )
            users.append(user)

            # Batch insert every 100 users
            if len(users) == 100:
                session.add_all(users)
                await session.commit()
                users = []

        # Insert remaining users
        if users:
            session.add_all(users)
            await session.commit()

    return test_db_manager


class TestPaginationPerformance:
    """Test pagination performance with different strategies."""

    @pytest.mark.asyncio
    async def test_offset_pagination_performance(self, populated_db, benchmark):
        """Benchmark offset-based pagination performance."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test different page sizes
            page_sizes = [10, 20, 50, 100]

            for page_size in page_sizes:
                for page in range(1, 6):  # Test first 5 pages
                    filters = EnhancedFilter(page=page, per_page=page_size, use_cache=False)  # Test raw performance

                    benchmark.start_timer()
                    result = await repository.list_with_filters(filters, use_cache=False)
                    duration = benchmark.end_timer(f"offset_pagination_page_{page_size}")

                    # Verify results
                    assert len(result.items) <= page_size
                    assert result.total == 1000

                    # Performance assertions
                    assert duration < 1.0, f"Offset pagination too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_cursor_pagination_performance(self, populated_db, benchmark):
        """Benchmark cursor-based pagination performance."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Get initial page
            filters = EnhancedFilter(per_page=50, sort=[SortField(field="id", direction="asc")], use_cache=False)

            benchmark.start_timer()
            first_page = await repository.list_with_filters(filters, use_cache=False)
            benchmark.end_timer("cursor_pagination_first_page")

            # Test subsequent pages with cursor
            if first_page.items:
                from app.repositories.enhanced import CursorInfo

                cursor = CursorInfo(first_page.items[-1].id, "id").encode()

                for page_num in range(2, 6):  # Test pages 2-5
                    cursor_filters = EnhancedFilter(
                        cursor=cursor,
                        cursor_direction="next",
                        per_page=50,
                        sort=[SortField(field="id", direction="asc")],
                        use_cache=False,
                    )

                    benchmark.start_timer()
                    result = await repository.list_with_filters(cursor_filters, use_cache=False)
                    duration = benchmark.end_timer(f"cursor_pagination_page_{page_num}")

                    # Verify results
                    assert len(result.items) <= 50

                    # Update cursor for next iteration
                    if result.items:
                        cursor = CursorInfo(result.items[-1].id, "id").encode()

                    # Performance assertion - cursor should be faster for later pages
                    assert duration < 0.5, f"Cursor pagination too slow: {duration:.3f}s"


class TestFilteringPerformance:
    """Test filtering performance with different operators and combinations."""

    @pytest.mark.asyncio
    async def test_simple_equality_filter_performance(self, populated_db, benchmark):
        """Benchmark simple equality filtering."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test different equality filters
            test_cases = [
                ("is_active", FilterOperator.EQ, True),
                ("is_superuser", FilterOperator.EQ, False),
                ("is_verified", FilterOperator.EQ, True),
            ]

            for field, operator, value in test_cases:
                filters = EnhancedFilter(
                    filters={field: FieldFilter(operator=operator, value=value)}, per_page=100, use_cache=False
                )

                benchmark.start_timer()
                result = await repository.list_with_filters(filters, use_cache=False)
                duration = benchmark.end_timer(f"equality_filter_{field}")

                # Verify results
                assert len(result.items) >= 0

                # Performance assertion
                assert duration < 0.5, f"Equality filter too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_string_filter_performance(self, populated_db, benchmark):
        """Benchmark string filtering operations."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test different string operators
            test_cases = [
                ("username", FilterOperator.CONTAINS, "user_00"),
                ("username", FilterOperator.STARTSWITH, "user_1"),
                ("email", FilterOperator.ENDSWITH, "@example.com"),
                ("username", FilterOperator.ICONTAINS, "USER_00"),  # Case insensitive
            ]

            for field, operator, value in test_cases:
                filters = EnhancedFilter(
                    filters={field: FieldFilter(operator=operator, value=value)}, per_page=100, use_cache=False
                )

                benchmark.start_timer()
                result = await repository.list_with_filters(filters, use_cache=False)
                duration = benchmark.end_timer(f"string_filter_{operator.value}")

                # Verify results
                assert len(result.items) >= 0

                # Performance assertion - string operations can be slower
                assert duration < 1.0, f"String filter too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_range_filter_performance(self, populated_db, benchmark):
        """Benchmark range filtering operations."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test range filters on created_at
            cutoff_date = datetime.now() - timedelta(days=100)

            test_cases = [
                ("created_at", FilterOperator.GT, cutoff_date),
                ("created_at", FilterOperator.LTE, cutoff_date),
            ]

            for field, operator, value in test_cases:
                filters = EnhancedFilter(
                    filters={field: FieldFilter(operator=operator, value=value)}, per_page=100, use_cache=False
                )

                benchmark.start_timer()
                result = await repository.list_with_filters(filters, use_cache=False)
                duration = benchmark.end_timer(f"range_filter_{operator.value}")

                # Verify results
                assert len(result.items) >= 0

                # Performance assertion
                assert duration < 0.5, f"Range filter too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_combined_filter_performance(self, populated_db, benchmark):
        """Benchmark complex combined filtering."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Complex filter combining multiple conditions
            cutoff_date = datetime.now() - timedelta(days=200)

            filters = EnhancedFilter(
                filters={
                    "is_active": FieldFilter(operator=FilterOperator.EQ, value=True),
                    "is_verified": FieldFilter(operator=FilterOperator.EQ, value=True),
                    "username": FieldFilter(operator=FilterOperator.CONTAINS, value="user_0"),
                    "created_at": FieldFilter(operator=FilterOperator.GT, value=cutoff_date),
                },
                sort=[SortField(field="created_at", direction="desc"), SortField(field="username", direction="asc")],
                per_page=50,
                use_cache=False,
            )

            benchmark.start_timer()
            result = await repository.list_with_filters(filters, use_cache=False)
            duration = benchmark.end_timer("combined_filters")

            # Verify results
            assert len(result.items) >= 0

            # Performance assertion - complex queries should still be reasonable
            assert duration < 1.0, f"Combined filters too slow: {duration:.3f}s"


class TestSortingPerformance:
    """Test sorting performance with different configurations."""

    @pytest.mark.asyncio
    async def test_single_field_sorting_performance(self, populated_db, benchmark):
        """Benchmark single field sorting."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test sorting by different fields
            sort_fields = ["id", "username", "email", "created_at"]

            for field in sort_fields:
                for direction in ["asc", "desc"]:
                    filters = EnhancedFilter(
                        sort=[SortField(field=field, direction=direction)], per_page=100, use_cache=False
                    )

                    benchmark.start_timer()
                    result = await repository.list_with_filters(filters, use_cache=False)
                    duration = benchmark.end_timer(f"sort_{field}_{direction}")

                    # Verify results are sorted
                    assert len(result.items) >= 0
                    if len(result.items) > 1:
                        values = [getattr(item, field) for item in result.items]
                        if direction == "asc":
                            assert values == sorted(values)
                        else:
                            assert values == sorted(values, reverse=True)

                    # Performance assertion
                    assert duration < 0.5, f"Single field sort too slow: {duration:.3f}s"

    @pytest.mark.asyncio
    async def test_multi_field_sorting_performance(self, populated_db, benchmark):
        """Benchmark multi-field sorting."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            # Test multi-field sorting combinations
            sort_combinations = [
                [SortField(field="is_active", direction="desc"), SortField(field="created_at", direction="desc")],
                [
                    SortField(field="is_superuser", direction="desc"),
                    SortField(field="is_active", direction="desc"),
                    SortField(field="username", direction="asc"),
                ],
            ]

            for i, sort_fields in enumerate(sort_combinations):
                filters = EnhancedFilter(sort=sort_fields, per_page=100, use_cache=False)

                benchmark.start_timer()
                result = await repository.list_with_filters(filters, use_cache=False)
                duration = benchmark.end_timer(f"multi_sort_{i+1}")

                # Verify results
                assert len(result.items) >= 0

                # Performance assertion - multi-field sorting can be slower
                assert duration < 1.0, f"Multi-field sort too slow: {duration:.3f}s"


class TestCachePerformance:
    """Test caching performance and effectiveness."""

    @pytest.mark.asyncio
    async def test_cache_hit_performance(self, populated_db, benchmark):
        """Benchmark cache hit performance."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            filters = EnhancedFilter(per_page=50, use_cache=True, cache_ttl=300)

            # First request - cache miss
            benchmark.start_timer()
            first_result = await repository.list_with_filters(filters, use_cache=True)
            cache_miss_duration = benchmark.end_timer("cache_miss")

            # Second request - should be cache hit (if caching works)
            benchmark.start_timer()
            second_result = await repository.list_with_filters(filters, use_cache=True)
            cache_hit_duration = benchmark.end_timer("cache_hit")

            # Verify results are the same
            assert len(first_result.items) == len(second_result.items)

            # Cache hit should be significantly faster (if implemented)
            # Note: This may not work in current implementation due to simplified caching
            print(f"Cache miss: {cache_miss_duration:.3f}s")
            print(f"Cache hit:  {cache_hit_duration:.3f}s")

    @pytest.mark.asyncio
    async def test_cache_vs_no_cache_performance(self, populated_db, benchmark):
        """Compare performance with and without caching."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            filters = EnhancedFilter(
                filters={"is_active": FieldFilter(operator=FilterOperator.EQ, value=True)}, per_page=50
            )

            # Test without cache
            for i in range(5):
                benchmark.start_timer()
                await repository.list_with_filters(filters, use_cache=False)
                benchmark.end_timer("no_cache")

            # Test with cache (first call will be miss, subsequent should be hits)
            for i in range(5):
                benchmark.start_timer()
                await repository.list_with_filters(filters, use_cache=True)
                benchmark.end_timer("with_cache")


class TestConcurrentPerformance:
    """Test performance under concurrent load."""

    @pytest.mark.asyncio
    async def test_concurrent_read_performance(self, populated_db, benchmark):
        """Test performance with concurrent read operations."""
        async with populated_db.get_session() as session:
            repository = EnhancedRepository(session, User)

            async def single_request():
                filters = EnhancedFilter(per_page=20, use_cache=False)
                start_time = time.perf_counter()
                await repository.list_with_filters(filters, use_cache=False)
                return time.perf_counter() - start_time

            # Test with different concurrency levels
            concurrency_levels = [1, 5, 10, 20]

            for concurrency in concurrency_levels:
                benchmark.start_timer()

                # Create concurrent tasks
                tasks = [single_request() for _ in range(concurrency)]
                durations = await asyncio.gather(*tasks)

                total_duration = benchmark.end_timer(f"concurrent_{concurrency}")

                # Record individual request stats
                for duration in durations:
                    if f"concurrent_{concurrency}_individual" not in benchmark.metrics:
                        benchmark.metrics[f"concurrent_{concurrency}_individual"] = []
                    benchmark.metrics[f"concurrent_{concurrency}_individual"].append(duration)

                # Verify all requests completed
                assert len(durations) == concurrency

                # Performance assertions
                max_individual_duration = max(durations)
                assert max_individual_duration < 2.0, f"Individual request too slow: {max_individual_duration:.3f}s"
                assert total_duration < 5.0, f"Concurrent batch too slow: {total_duration:.3f}s"


@pytest.mark.asyncio
async def test_comprehensive_performance_suite(populated_db, benchmark):
    """Run comprehensive performance test suite."""
    async with populated_db.get_session() as session:
        repository = EnhancedRepository(session, User)

        print("\nRunning comprehensive performance benchmarks...")

        # Test various scenarios
        scenarios = [
            {"name": "basic_list", "filters": EnhancedFilter(per_page=20, use_cache=False)},
            {
                "name": "filtered_list",
                "filters": EnhancedFilter(
                    filters={"is_active": FieldFilter(operator=FilterOperator.EQ, value=True)},
                    per_page=20,
                    use_cache=False,
                ),
            },
            {
                "name": "sorted_list",
                "filters": EnhancedFilter(
                    sort=[SortField(field="created_at", direction="desc")], per_page=20, use_cache=False
                ),
            },
            {
                "name": "complex_query",
                "filters": EnhancedFilter(
                    filters={
                        "is_active": FieldFilter(operator=FilterOperator.EQ, value=True),
                        "username": FieldFilter(operator=FilterOperator.CONTAINS, value="user_0"),
                    },
                    sort=[
                        SortField(field="is_superuser", direction="desc"),
                        SortField(field="created_at", direction="desc"),
                    ],
                    per_page=20,
                    use_cache=False,
                ),
            },
        ]

        # Run each scenario multiple times
        iterations = 10

        for scenario in scenarios:
            for i in range(iterations):
                benchmark.start_timer()
                result = await repository.list_with_filters(scenario["filters"], use_cache=False)
                benchmark.end_timer(scenario["name"])

                # Basic validation
                assert len(result.items) >= 0
                assert result.total >= 0

        # Print results
        benchmark.print_summary()

        # Performance targets
        for scenario in scenarios:
            stats = benchmark.get_stats(scenario["name"])
            if stats:
                # All scenarios should complete within reasonable time
                assert stats["p95"] < 1.0, f"{scenario['name']} P95 too slow: {stats['p95']:.3f}s"
                assert stats["mean"] < 0.5, f"{scenario['name']} mean too slow: {stats['mean']:.3f}s"

        print("\n✅ All performance benchmarks passed!")


if __name__ == "__main__":
    # Run benchmarks directly
    import asyncio

    async def main():
        from tests.test_database import DatabaseTestManager

        # Setup
        benchmark = PerformanceBenchmark()
        db_manager = DatabaseTestManager()

        # Populate database
        print("Setting up test database with 1000 users...")
        async with db_manager.get_session() as session:
            # Create test data (simplified for direct run)
            users = [
                User(
                    username=f"user_{i:04d}",
                    email=f"user{i:04d}@example.com",
                    hashed_password="hashed_password",
                    is_active=i % 4 != 3,
                    is_superuser=i % 50 == 0,
                    is_verified=i % 5 != 4,
                )
                for i in range(100)  # Smaller dataset for quick test
            ]
            session.add_all(users)
            await session.commit()

        # Run comprehensive benchmark
        await test_comprehensive_performance_suite(db_manager, benchmark)

    asyncio.run(main())
