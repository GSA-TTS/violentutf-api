"""Simple model factories without external dependencies."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from app.core.enums import ScanStatus, ScanType
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.security_scan import SecurityScan
from app.models.session import Session
from app.models.user import User


class SimpleUserFactory:
    """Simple factory for creating User test instances."""

    @staticmethod
    def create(**kwargs) -> User:
        """Create a User instance with test data."""
        defaults = {
            "id": str(uuid.uuid4()),
            "username": f"testuser_{random.randint(1000, 9999)}",
            "email": f"test{random.randint(1000, 9999)}@example.com",
            "full_name": "Test User",
            "is_active": True,
            "is_superuser": False,
            "is_verified": True,
            "organization_id": str(uuid.uuid4()),
            "created_by": "system",
            "created_at": datetime.now(timezone.utc),
            "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$test_salt$test_hash_data",
        }
        defaults.update(kwargs)
        return User(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[User]:
        """Create multiple users."""
        return [SimpleUserFactory.create(**kwargs) for _ in range(count)]


class SimpleSessionFactory:
    """Simple factory for creating Session test instances."""

    @staticmethod
    def create(**kwargs) -> Session:
        """Create a Session instance with test data."""
        defaults = {
            "id": str(uuid.uuid4()),
            "user_id": str(uuid.uuid4()),
            "session_token": f"token_{uuid.uuid4().hex}",
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
            "ip_address": "127.0.0.1",
            "device_info": "Test Agent",
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }
        defaults.update(kwargs)
        return Session(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[Session]:
        """Create multiple sessions."""
        return [SimpleSessionFactory.create(**kwargs) for _ in range(count)]


class SimpleAPIKeyFactory:
    """Simple factory for creating API Key test instances."""

    @staticmethod
    def create(**kwargs) -> APIKey:
        """Create an APIKey instance with test data."""
        defaults = {
            "id": str(uuid.uuid4()),
            "user_id": str(uuid.uuid4()),
            "key_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            "name": f"Test API Key {random.randint(1000, 9999)}",
            "description": "Test API Key for unit testing",
            "key_prefix": f"test_{random.randint(100, 999)}",
            "permissions": {"read": True, "write": False},
            "usage_count": 0,
            "created_at": datetime.now(timezone.utc),
        }
        defaults.update(kwargs)
        return APIKey(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[APIKey]:
        """Create multiple API keys."""
        return [SimpleAPIKeyFactory.create(**kwargs) for _ in range(count)]


class SimpleAuditLogFactory:
    """Simple factory for creating AuditLog test instances."""

    @staticmethod
    def create(**kwargs) -> AuditLog:
        """Create an AuditLog instance with test data."""
        defaults = {
            "id": str(uuid.uuid4()),
            "action": "test.action",
            "resource_type": "test_resource",
            "resource_id": str(uuid.uuid4()),
            "user_id": str(uuid.uuid4()),
            "user_email": f"testuser{random.randint(1000, 9999)}@example.com",
            "ip_address": "127.0.0.1",
            "user_agent": "Test User Agent",
            "changes": {"old_value": "test_old", "new_value": "test_new"},
            "action_metadata": {"test": True, "operation": "unit_test"},
            "status": "success",
            "created_at": datetime.now(timezone.utc),
        }
        defaults.update(kwargs)
        return AuditLog(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[AuditLog]:
        """Create multiple audit logs."""
        return [SimpleAuditLogFactory.create(**kwargs) for _ in range(count)]


class SimpleRoleFactory:
    """Simple factory for creating Role test instances."""

    @staticmethod
    def create(**kwargs) -> Role:
        """Create a Role instance with test data."""
        # Extract permissions to put in role_metadata
        permissions = kwargs.pop("permissions", ["users:read", "users:write"])

        defaults = {
            "id": str(uuid.uuid4()),
            "name": f"Test Role {random.randint(1000, 9999)}",
            "display_name": f"Test Display Role {random.randint(1000, 9999)}",
            "description": "Test role for unit testing",
            "role_metadata": {"permissions": permissions},
            "is_system_role": False,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "created_by": "system",
        }
        defaults.update(kwargs)
        return Role(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[Role]:
        """Create multiple roles."""
        return [SimpleRoleFactory.create(**kwargs) for _ in range(count)]


class SimpleSecurityScanFactory:
    """Simple factory for creating SecurityScan test instances."""

    @staticmethod
    def create(**kwargs) -> SecurityScan:
        """Create a SecurityScan instance with test data."""
        # Map user_id to initiated_by if provided
        if "user_id" in kwargs:
            kwargs["initiated_by"] = kwargs.pop("user_id")

        defaults = {
            "id": str(uuid.uuid4()),
            "name": f"Test Security Scan {random.randint(1000, 9999)}",
            "scan_type": ScanType.PYRIT,
            "description": "Test security scan for unit testing",
            "target": "http://test-target.example.com",
            "configuration": {"test_mode": True, "depth": "basic"},
            "scan_parameters": "--test-mode --verbose",
            "initiated_by": f"test_user_{random.randint(100, 999)}",
            "tool_version": "1.0.0",
            "scanner_host": "test-scanner-01",
            "status": ScanStatus.PENDING,
            "timeout_seconds": 3600,
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "info_findings": 0,
            "created_at": datetime.now(timezone.utc),
            "created_by": "system",
        }
        defaults.update(kwargs)
        return SecurityScan(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[SecurityScan]:
        """Create multiple security scans."""
        return [SimpleSecurityScanFactory.create(**kwargs) for _ in range(count)]


@pytest.fixture
def user_factory():
    """Provide simple user factory."""
    return SimpleUserFactory


@pytest.fixture
def session_factory():
    """Provide simple session factory."""
    return SimpleSessionFactory


@pytest.fixture
def api_key_factory():
    """Provide simple API key factory."""
    return SimpleAPIKeyFactory


@pytest.fixture
def audit_log_factory():
    """Provide simple audit log factory."""
    return SimpleAuditLogFactory


@pytest.fixture
def role_factory():
    """Provide simple role factory."""
    return SimpleRoleFactory


@pytest.fixture
def security_scan_factory():
    """Provide simple security scan factory."""
    return SimpleSecurityScanFactory
