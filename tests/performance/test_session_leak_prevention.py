"""Tests for database session leak prevention.

Tests to ensure sessions are properly closed and resources are freed:
- Session cleanup after normal operations
- Session cleanup after exceptions
- Memory usage monitoring
- Connection leak detection
- Resource exhaustion prevention
"""

import asyncio
import gc
import os
import time
import tracemalloc
import weakref
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Set

import psutil
import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.pool import Pool

from app.db.session import get_db, get_session_maker
from app.models.user import User
from app.repositories.user import UserRepository
from tests.test_database import DatabaseTestManager


class SessionTracker:
    """Tracks database sessions for leak detection."""

    def __init__(self):
        self.active_sessions: Set[weakref.ref] = set()
        self.created_count = 0
        self.closed_count = 0
        self.peak_active = 0

    def track_session(self, session: AsyncSession):
        """Track a new session."""
        self.created_count += 1
        # Use weak reference to avoid keeping sessions alive
        ref = weakref.ref(session, self._session_finalized)
        self.active_sessions.add(ref)

        # Update peak
        active_count = len([r for r in self.active_sessions if r() is not None])
        self.peak_active = max(self.peak_active, active_count)

    def _session_finalized(self, ref):
        """Called when a session is garbage collected."""
        self.closed_count += 1
        self.active_sessions.discard(ref)

    def get_active_count(self) -> int:
        """Get count of currently active sessions."""
        # Clean up dead references
        self.active_sessions = {r for r in self.active_sessions if r() is not None}
        return len(self.active_sessions)

    def get_stats(self) -> Dict[str, int]:
        """Get session tracking statistics."""
        return {
            "created": self.created_count,
            "closed": self.closed_count,
            "active": self.get_active_count(),
            "peak_active": self.peak_active,
            "leaked": self.created_count - self.closed_count - self.get_active_count(),
        }


class MemoryMonitor:
    """Monitors memory usage for leak detection."""

    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.snapshots: List[Dict[str, Any]] = []

    def take_snapshot(self, label: str = ""):
        """Take a memory snapshot."""
        gc.collect()  # Force garbage collection

        memory_info = self.process.memory_info()
        snapshot = {
            "timestamp": time.time(),
            "label": label,
            "rss": memory_info.rss,  # Resident Set Size
            "vms": memory_info.vms,  # Virtual Memory Size
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
        }

        self.snapshots.append(snapshot)
        return snapshot

    def get_memory_growth(self) -> Dict[str, float]:
        """Calculate memory growth between first and last snapshot."""
        if len(self.snapshots) < 2:
            return {"rss_growth_mb": 0, "vms_growth_mb": 0}

        first = self.snapshots[0]
        last = self.snapshots[-1]

        return {
            "rss_growth_mb": last["rss_mb"] - first["rss_mb"],
            "vms_growth_mb": last["vms_mb"] - first["vms_mb"],
            "duration_seconds": last["timestamp"] - first["timestamp"],
        }


class TestSessionLeakPrevention:
    """Test database session leak prevention."""

    @pytest_asyncio.fixture
    async def db_manager(self):
        """Get database manager instance."""
        manager = DatabaseTestManager()
        await manager.initialize()
        yield manager
        await manager.shutdown()

    @pytest_asyncio.fixture
    def session_tracker(self):
        """Create session tracker."""
        return SessionTracker()

    @pytest_asyncio.fixture
    def memory_monitor(self):
        """Create memory monitor."""
        return MemoryMonitor()

    @pytest.mark.asyncio
    async def test_session_cleanup_normal_operations(self, db_manager, session_tracker):
        """Test that sessions are properly cleaned up after normal operations."""
        session_maker = db_manager.get_session_maker()

        # Hook into session creation
        original_call = session_maker.__call__

        def tracked_call():
            session = original_call()
            session_tracker.track_session(session)
            return session

        session_maker.__call__ = tracked_call

        # Execute many operations
        operation_count = 100

        for i in range(operation_count):
            async with session_maker() as session:
                result = await session.execute(select(User).limit(1))
                _ = result.scalar_one_or_none()

        # Force garbage collection
        gc.collect()
        await asyncio.sleep(0.1)  # Allow cleanup

        # Check for leaks
        stats = session_tracker.get_stats()

        print(f"\nNormal Operations Session Cleanup:")
        print(f"  Sessions created: {stats['created']}")
        print(f"  Sessions closed: {stats['closed']}")
        print(f"  Currently active: {stats['active']}")
        print(f"  Peak active: {stats['peak_active']}")
        print(f"  Potential leaks: {stats['leaked']}")

        # Verify no leaks
        assert stats["active"] == 0, f"Found {stats['active']} active sessions after operations"
        assert stats["leaked"] <= 0, f"Found {stats['leaked']} leaked sessions"

    @pytest.mark.asyncio
    async def test_session_cleanup_with_exceptions(self, db_manager, session_tracker):
        """Test that sessions are cleaned up even when exceptions occur."""
        session_maker = db_manager.get_session_maker()

        # Track sessions
        original_call = session_maker.__call__

        def tracked_call():
            session = original_call()
            session_tracker.track_session(session)
            return session

        session_maker.__call__ = tracked_call

        # Execute operations that raise exceptions
        exception_count = 0

        for i in range(50):
            try:
                async with session_maker() as session:
                    result = await session.execute(select(User).limit(1))

                    # Simulate various exceptions
                    if i % 3 == 0:
                        raise ValueError("Simulated error")
                    elif i % 5 == 0:
                        raise RuntimeError("Another error")

            except (ValueError, RuntimeError):
                exception_count += 1

        # Force cleanup
        gc.collect()
        await asyncio.sleep(0.1)

        # Check for leaks
        stats = session_tracker.get_stats()

        print(f"\nException Handling Session Cleanup:")
        print(f"  Operations with exceptions: {exception_count}")
        print(f"  Sessions created: {stats['created']}")
        print(f"  Currently active: {stats['active']}")
        print(f"  Potential leaks: {stats['leaked']}")

        # Verify cleanup despite exceptions
        assert stats["active"] == 0, "Sessions leaked after exceptions"

    @pytest.mark.asyncio
    async def test_concurrent_session_management(self, db_manager, session_tracker):
        """Test session management under concurrent load."""
        session_maker = db_manager.get_session_maker()

        # Track sessions
        original_call = session_maker.__call__

        def tracked_call():
            session = original_call()
            session_tracker.track_session(session)
            return session

        session_maker.__call__ = tracked_call

        # Create many concurrent operations
        concurrent_count = 100

        async def db_operation(op_id: int):
            async with session_maker() as session:
                # Simulate varying operation times
                await asyncio.sleep(0.01 * (op_id % 5))

                result = await session.execute(select(User).limit(1))
                _ = result.scalar_one_or_none()

        # Execute concurrently
        tasks = [asyncio.create_task(db_operation(i)) for i in range(concurrent_count)]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Check peak usage
        stats = session_tracker.get_stats()

        print(f"\nConcurrent Session Management:")
        print(f"  Concurrent operations: {concurrent_count}")
        print(f"  Peak active sessions: {stats['peak_active']}")
        print(f"  Currently active: {stats['active']}")

        # Verify reasonable peak usage and cleanup
        assert stats["peak_active"] < concurrent_count, "Too many concurrent sessions"
        assert stats["active"] == 0, "Sessions not cleaned up after concurrent operations"

    @pytest.mark.asyncio
    async def test_memory_usage_stability(self, db_manager, memory_monitor):
        """Test that memory usage remains stable over many operations."""
        session_maker = db_manager.get_session_maker()

        # Take initial snapshot
        memory_monitor.take_snapshot("initial")

        # Run many operations in batches
        batch_size = 100
        batch_count = 10

        for batch in range(batch_count):
            for i in range(batch_size):
                async with session_maker() as session:
                    user_repo = UserRepository(session)
                    users = await user_repo.list_with_pagination(page=1, size=10)

            # Snapshot after each batch
            memory_monitor.take_snapshot(f"batch_{batch + 1}")

            # Force garbage collection
            gc.collect()

        # Final snapshot
        memory_monitor.take_snapshot("final")

        # Analyze memory growth
        growth = memory_monitor.get_memory_growth()

        print(f"\nMemory Usage Stability Test:")
        print(f"  Total operations: {batch_size * batch_count}")
        print(f"  Test duration: {growth['duration_seconds']:.2f}s")
        print(f"  RSS memory growth: {growth['rss_growth_mb']:.2f} MB")
        print(f"  VMS memory growth: {growth['vms_growth_mb']:.2f} MB")

        # Print batch snapshots
        for snapshot in memory_monitor.snapshots:
            if snapshot["label"].startswith("batch_"):
                print(f"  {snapshot['label']}: {snapshot['rss_mb']:.2f} MB")

        # Verify reasonable memory usage
        # Allow some growth but should be minimal
        assert growth["rss_growth_mb"] < 50, f"Excessive memory growth: {growth['rss_growth_mb']} MB"

    @pytest.mark.asyncio
    async def test_connection_pool_leak_prevention(self, db_manager):
        """Test that connection pool doesn't leak connections."""
        engine = db_manager.engine
        pool = engine.pool

        initial_size = pool.size() if hasattr(pool, "size") else 0
        initial_checked_out = pool.checked_out_connections if hasattr(pool, "checked_out_connections") else 0

        print(f"\nConnection Pool Initial State:")
        print(f"  Pool size: {initial_size}")
        print(f"  Checked out: {initial_checked_out}")

        # Execute many operations
        for i in range(100):
            async with db_manager.get_session() as session:
                await session.execute(select(User).limit(1))

                # Simulate some operations holding connections longer
                if i % 10 == 0:
                    await asyncio.sleep(0.1)

        # Check final state
        final_size = pool.size() if hasattr(pool, "size") else 0
        final_checked_out = pool.checked_out_connections if hasattr(pool, "checked_out_connections") else 0

        print(f"\nConnection Pool Final State:")
        print(f"  Pool size: {final_size}")
        print(f"  Checked out: {final_checked_out}")

        # Verify no connection leaks
        assert (
            final_checked_out == initial_checked_out
        ), f"Connections leaked: {final_checked_out - initial_checked_out}"

    @pytest.mark.asyncio
    async def test_session_tracking_with_context_manager(self, db_manager):
        """Test session tracking with custom context manager."""
        sessions_created = []
        sessions_closed = []

        @asynccontextmanager
        async def tracked_session():
            """Context manager that tracks session lifecycle."""
            session = None
            try:
                async with db_manager.get_session() as session:
                    sessions_created.append(id(session))
                    yield session
            finally:
                if session:
                    sessions_closed.append(id(session))

        # Use tracked sessions
        for i in range(20):
            async with tracked_session() as session:
                await session.execute(select(User).limit(1))

        # Verify all sessions were closed
        print(f"\nContext Manager Session Tracking:")
        print(f"  Sessions created: {len(sessions_created)}")
        print(f"  Sessions closed: {len(sessions_closed)}")
        print(f"  Unclosed sessions: {set(sessions_created) - set(sessions_closed)}")

        assert len(sessions_created) == len(sessions_closed), "Not all sessions were closed"
        assert set(sessions_created) == set(sessions_closed), "Session IDs don't match"

    @pytest.mark.asyncio
    async def test_tracemalloc_memory_tracking(self, db_manager):
        """Use tracemalloc to track memory allocations."""
        # Start tracing
        tracemalloc.start()

        # Take initial snapshot
        snapshot1 = tracemalloc.take_snapshot()

        # Execute many database operations
        for i in range(500):
            async with db_manager.get_session() as session:
                repo = UserRepository(session)
                await repo.get_active_users(page=1, size=10)

        # Take final snapshot
        snapshot2 = tracemalloc.take_snapshot()

        # Calculate differences
        top_stats = snapshot2.compare_to(snapshot1, "lineno")

        print(f"\nTop Memory Allocations:")
        for stat in top_stats[:10]:
            if stat.size_diff > 0:
                print(f"  {stat}")

        # Get current memory usage
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"\nMemory Usage:")
        print(f"  Current: {current / 1024 / 1024:.2f} MB")
        print(f"  Peak: {peak / 1024 / 1024:.2f} MB")

        # Verify reasonable memory usage
        assert peak / 1024 / 1024 < 100, f"Peak memory too high: {peak / 1024 / 1024:.2f} MB"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
