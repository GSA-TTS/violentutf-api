"""Database test helpers for consistent test setup."""

import asyncio
import os
from datetime import datetime
from typing import AsyncGenerator, Optional
from uuid import uuid4

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.db.session import get_engine, get_session_maker, reset_engine
from app.models.scan import Scan, ScanFinding, ScanReport, ScanSeverity, ScanStatus, ScanType
from app.models.task import Task, TaskPriority, TaskResult, TaskStatus
from app.models.user import User


@pytest_asyncio.fixture
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Provide a test database engine."""
    # Ensure test environment
    os.environ["TESTING"] = "1"
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

    # Reset any existing engine
    reset_engine()

    # Create test engine
    engine = get_engine()
    if engine is None:
        import pytest

        pytest.fail("Failed to create test database engine")

    yield engine

    # Cleanup
    await engine.dispose()
    reset_engine()


@pytest_asyncio.fixture
async def test_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a test database session."""
    session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    session = session_maker()

    try:
        yield session
    finally:
        await session.close()


async def ensure_test_database():
    """Ensure test database is properly configured."""
    os.environ.setdefault("TESTING", "1")
    os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

    # Reset engine to pick up test configuration
    reset_engine()

    # Verify engine creation
    engine = get_engine()
    if engine is None:
        raise RuntimeError("Failed to configure test database")

    return engine


def reset_test_database():
    """Reset test database state."""
    reset_engine()
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("TESTING", None)


# Test data creation helpers


async def create_test_user(
    db_session: AsyncSession, username: str = "testuser", email: str = "test@example.com", **kwargs
) -> User:
    """Create a test user."""
    user_data = {
        "username": username,
        "email": email,
        "hashed_password": "hashed_password_123",
        "is_active": True,
        "is_verified": True,
        **kwargs,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def create_test_task(
    db_session: AsyncSession,
    name: str = "Test Task",
    task_type: str = "test_task",
    status: TaskStatus = TaskStatus.PENDING,
    created_by: str = "system",
    **kwargs,
) -> Task:
    """Create a test task."""
    task_data = {
        "name": name,
        "task_type": task_type,
        "status": status,
        "description": kwargs.get("description", "Test task description"),
        "priority": kwargs.get("priority", TaskPriority.NORMAL),
        "input_data": kwargs.get("input_data", {"test": "data"}),
        "config": kwargs.get("config", {"timeout": 300}),
        "progress": kwargs.get("progress", 0),
        "created_by": created_by,
        **{
            k: v
            for k, v in (kwargs.items() if hasattr(kwargs, "items") and not callable(kwargs) else [])
            if k not in ["description", "priority", "input_data", "config", "progress"]
        },
    }
    task = Task(**task_data)
    db_session.add(task)
    await db_session.commit()
    await db_session.refresh(task)
    return task


async def create_test_scan(
    db_session: AsyncSession,
    name: str = "Test Security Scan",
    scan_type: ScanType = ScanType.PYRIT_ORCHESTRATOR,
    status: ScanStatus = ScanStatus.PENDING,
    created_by: str = "system",
    findings_count: int = 0,
    critical_findings: int = 0,
    high_findings: int = 0,
    **kwargs,
) -> Scan:
    """Create a test scan."""
    scan_data = {
        "name": name,
        "scan_type": scan_type,
        "status": status,
        "description": kwargs.get("description", "Test security scan"),
        "target_config": kwargs.get("target_config", {"endpoint": "https://api.example.com"}),
        "scan_config": kwargs.get("scan_config", {"max_requests": 100}),
        "parameters": kwargs.get("parameters", {"intensity": "medium"}),
        "tags": kwargs.get("tags", ["test", "security"]),
        "findings_count": findings_count,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": kwargs.get("medium_findings", 0),
        "low_findings": kwargs.get("low_findings", 0),
        "progress": kwargs.get("progress", 0),
        "created_by": created_by,
        **{
            k: v
            for k, v in (kwargs.items() if hasattr(kwargs, "items") and not callable(kwargs) else [])
            if k
            not in [
                "description",
                "target_config",
                "scan_config",
                "parameters",
                "tags",
                "medium_findings",
                "low_findings",
                "progress",
            ]
        },
    }
    scan = Scan(**scan_data)
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return scan


async def create_test_scan_finding(
    db_session: AsyncSession,
    scan_id: str,
    title: str = "Test Security Finding",
    severity: ScanSeverity = ScanSeverity.MEDIUM,
    created_by: str = "system",
    **kwargs,
) -> ScanFinding:
    """Create a test scan finding."""
    finding_data = {
        "scan_id": scan_id,
        "title": title,
        "description": kwargs.get("description", "Test finding description"),
        "severity": severity,
        "category": kwargs.get("category", "injection"),
        "vulnerability_type": kwargs.get("vulnerability_type", "sql_injection"),
        "confidence_score": kwargs.get("confidence_score", 0.8),
        "evidence": kwargs.get("evidence", {"request": "SELECT * FROM users"}),
        "created_by": created_by,
        **{
            k: v
            for k, v in (kwargs.items() if hasattr(kwargs, "items") and not callable(kwargs) else [])
            if k not in ["description", "category", "vulnerability_type", "confidence_score", "evidence"]
        },
    }
    finding = ScanFinding(**finding_data)
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)
    return finding


async def create_test_scan_report(
    db_session: AsyncSession,
    scan_id: str,
    name: str = "Test Report",
    report_type: str = "security_assessment",
    format_type: str = "json",
    created_by: str = "system",
    **kwargs,
) -> ScanReport:
    """Create a test scan report."""
    report_data = {
        "scan_id": scan_id,
        "name": name,
        "report_type": report_type,
        "format": format_type,
        "content": kwargs.get("content", {"summary": "Test report content"}),
        "summary": kwargs.get("summary", {"findings": 0, "severity": "low"}),
        "generated_at": kwargs.get("generated_at", datetime.utcnow()),
        "created_by": created_by,
        **{
            k: v
            for k, v in (kwargs.items() if hasattr(kwargs, "items") and not callable(kwargs) else [])
            if k not in ["content", "summary", "generated_at"]
        },
    }
    report = ScanReport(**report_data)
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)
    return report
