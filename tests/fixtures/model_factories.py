"""Model factories for generating test data with realistic patterns."""

from __future__ import annotations

import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.security_scan import SecurityScan
from app.models.session import Session
from app.models.user import User
from app.models.vulnerability_finding import VulnerabilityFinding


def random_string(length: int = 8) -> str:
    """Generate a random string."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


def random_email() -> str:
    """Generate a random email."""
    return f"{random_string()}@example.com"


def random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"


def random_word() -> str:
    """Generate a random word."""
    words = ["test", "example", "demo", "sample", "mock", "fake"]
    return random.choice(words)


class UserFactory:
    """Factory for creating User test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        username: Optional[str] = None,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        is_active: bool = True,
        is_superuser: bool = False,
        is_verified: bool = True,
        organization_id: Optional[str] = None,
        created_by: str = "system",
        **kwargs,
    ) -> User:
        """Create a User instance with realistic test data."""
        return User(
            id=id or str(uuid.uuid4()),
            username=username or f"user_{random_string()}",
            email=email or random_email(),
            full_name=full_name or f"Test {random_word().title()}",
            is_active=is_active,
            is_superuser=is_superuser,
            is_verified=is_verified,
            organization_id=organization_id or str(uuid.uuid4()),
            created_by=created_by,
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            **kwargs,
        )

    @staticmethod
    def create_admin_user(**kwargs) -> User:
        """Create an admin user for testing."""
        defaults = {
            "username": "admin_user",
            "email": "admin@test.com",
            "full_name": "Admin User",
            "is_superuser": True,
            "is_verified": True,
        }
        defaults.update(kwargs)
        return UserFactory.create(**defaults)

    @staticmethod
    def create_regular_user(**kwargs) -> User:
        """Create a regular user for testing."""
        defaults = {
            "username": "regular_user",
            "email": "user@test.com",
            "full_name": "Regular User",
            "is_superuser": False,
            "is_verified": True,
        }
        defaults.update(kwargs)
        return UserFactory.create(**defaults)

    @staticmethod
    def create_inactive_user(**kwargs) -> User:
        """Create an inactive user for testing."""
        defaults = {"is_active": False, "username": "inactive_user", "email": "inactive@test.com"}
        defaults.update(kwargs)
        return UserFactory.create(**defaults)

    @staticmethod
    def create_batch(count: int, **kwargs) -> List[User]:
        """Create multiple users for batch testing."""
        users = []
        for i in range(count):
            user_kwargs = kwargs.copy()
            if "username" not in user_kwargs:
                user_kwargs["username"] = f"user_{i}_{random_string()}"
            if "email" not in user_kwargs:
                user_kwargs["email"] = f"user{i}@test.com"
            users.append(UserFactory.create(**user_kwargs))
        return users


class SessionFactory:
    """Factory for creating Session test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        user_id: Optional[str] = None,
        token: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        is_active: bool = True,
        **kwargs,
    ) -> Session:
        """Create a Session instance with realistic test data."""
        return Session(
            id=id or str(uuid.uuid4()),
            user_id=user_id or str(uuid.uuid4()),
            token=token or f"token_{uuid.uuid4().hex}",
            expires_at=expires_at or (datetime.utcnow() + timedelta(hours=24)),
            ip_address=ip_address or random_ip(),
            user_agent=user_agent or f"TestAgent/{random.randint(1, 10)}.0",
            is_active=is_active,
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            **kwargs,
        )

    @staticmethod
    def create_expired(**kwargs) -> Session:
        """Create an expired session for testing."""
        defaults = {"expires_at": datetime.utcnow() - timedelta(hours=1), "is_active": False}
        defaults.update(kwargs)
        return SessionFactory.create(**defaults)

    @staticmethod
    def create_for_user(user: User, **kwargs) -> Session:
        """Create a session for a specific user."""
        defaults = {"user_id": user.id}
        defaults.update(kwargs)
        return SessionFactory.create(**defaults)


class ApiKeyFactory:
    """Factory for creating ApiKey test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
        key_hash: Optional[str] = None,
        organization_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        is_active: bool = True,
        **kwargs,
    ) -> ApiKey:
        """Create an ApiKey instance with realistic test data."""
        return ApiKey(
            id=id or str(uuid.uuid4()),
            user_id=user_id or str(uuid.uuid4()),
            name=name or f"API Key {random_word()}",
            key_hash=key_hash or uuid.uuid4().hex[:64].ljust(64, "0"),
            organization_id=organization_id or str(uuid.uuid4()),
            expires_at=expires_at,
            is_active=is_active,
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            last_used_at=kwargs.get("last_used_at"),
            **kwargs,
        )

    @staticmethod
    def create_for_user(user: User, **kwargs) -> ApiKey:
        """Create an API key for a specific user."""
        defaults = {"user_id": user.id, "organization_id": user.organization_id}
        defaults.update(kwargs)
        return ApiKeyFactory.create(**defaults)

    @staticmethod
    def create_expired(**kwargs) -> ApiKey:
        """Create an expired API key for testing."""
        defaults = {"expires_at": datetime.utcnow() - timedelta(days=30), "is_active": False}
        defaults.update(kwargs)
        return ApiKeyFactory.create(**defaults)


class AuditLogFactory:
    """Factory for creating AuditLog test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs,
    ) -> AuditLog:
        """Create an AuditLog instance with realistic test data."""
        return AuditLog(
            id=id or str(uuid.uuid4()),
            user_id=user_id,
            action=action or random.choice(["CREATE", "READ", "UPDATE", "DELETE"]),
            resource_type=resource_type or random.choice(["user", "session", "api_key"]),
            resource_id=resource_id or str(uuid.uuid4()),
            details=details or {"test": random_word()},
            ip_address=ip_address or random_ip(),
            user_agent=user_agent or f"TestAgent/{random.randint(1, 10)}.0",
            timestamp=kwargs.get("timestamp", datetime.utcnow()),
            **kwargs,
        )

    @staticmethod
    def create_for_user_action(user: User, action: str, resource_type: str, **kwargs) -> AuditLog:
        """Create an audit log for a specific user action."""
        defaults = {"user_id": user.id, "action": action, "resource_type": resource_type}
        defaults.update(kwargs)
        return AuditLogFactory.create(**defaults)


class SecurityScanFactory:
    """Factory for creating SecurityScan test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        scan_type: Optional[str] = None,
        target: Optional[str] = None,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        status: str = "pending",
        results: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SecurityScan:
        """Create a SecurityScan instance with realistic test data."""
        return SecurityScan(
            id=id or str(uuid.uuid4()),
            scan_type=scan_type or random.choice(["vulnerability", "compliance", "penetration"]),
            target=target or f"https://test{random.randint(1, 999)}.example.com",
            user_id=user_id or str(uuid.uuid4()),
            organization_id=organization_id or str(uuid.uuid4()),
            status=status,
            results=results or {},
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            **kwargs,
        )

    @staticmethod
    def create_completed(**kwargs) -> SecurityScan:
        """Create a completed security scan for testing."""
        defaults = {
            "status": "completed",
            "results": {
                "vulnerabilities_found": random.randint(0, 10),
                "scan_duration": random.randint(30, 300),
                "risk_score": random.randint(1, 10),
            },
        }
        defaults.update(kwargs)
        return SecurityScanFactory.create(**defaults)


class VulnerabilityFindingFactory:
    """Factory for creating VulnerabilityFinding test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        severity: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: str = "open",
        **kwargs,
    ) -> VulnerabilityFinding:
        """Create a VulnerabilityFinding instance with realistic test data."""
        return VulnerabilityFinding(
            id=id or str(uuid.uuid4()),
            scan_id=scan_id or str(uuid.uuid4()),
            vulnerability_id=vulnerability_id or f"CVE-{random.randint(2020, 2024)}-{random.randint(1000, 9999)}",
            severity=severity or random.choice(["critical", "high", "medium", "low"]),
            title=title or f"{random_word().title()} Vulnerability",
            description=description or f"Test vulnerability description for {random_word()} issue",
            status=status,
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            **kwargs,
        )

    @staticmethod
    def create_for_scan(scan: SecurityScan, **kwargs) -> VulnerabilityFinding:
        """Create a vulnerability finding for a specific scan."""
        defaults = {"scan_id": scan.id}
        defaults.update(kwargs)
        return VulnerabilityFindingFactory.create(**defaults)


class RoleFactory:
    """Factory for creating Role test instances."""

    @staticmethod
    def create(
        id: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        **kwargs,
    ) -> Role:
        """Create a Role instance with realistic test data."""
        return Role(
            id=id or str(uuid.uuid4()),
            name=name or f"{random_word()}_role",
            description=description or f"Test role for {random_word()} operations",
            permissions=permissions or [f"{random_word()}:read", f"{random_word()}:write"],
            created_at=kwargs.get("created_at", datetime.utcnow()),
            updated_at=kwargs.get("updated_at"),
            **kwargs,
        )

    @staticmethod
    def create_admin_role(**kwargs) -> Role:
        """Create an admin role for testing."""
        defaults = {
            "name": "admin",
            "description": "Administrator role with full permissions",
            "permissions": ["*:*"],  # All permissions
        }
        defaults.update(kwargs)
        return RoleFactory.create(**defaults)

    @staticmethod
    def create_user_role(**kwargs) -> Role:
        """Create a basic user role for testing."""
        defaults = {
            "name": "user",
            "description": "Basic user role with limited permissions",
            "permissions": ["user:read", "user:update", "session:create"],
        }
        defaults.update(kwargs)
        return RoleFactory.create(**defaults)


@pytest.fixture
def user_factory():
    """Provide UserFactory for test cases."""
    return UserFactory


@pytest.fixture
def session_factory():
    """Provide SessionFactory for test cases."""
    return SessionFactory


@pytest.fixture
def api_key_factory():
    """Provide ApiKeyFactory for test cases."""
    return ApiKeyFactory


@pytest.fixture
def audit_log_factory():
    """Provide AuditLogFactory for test cases."""
    return AuditLogFactory


@pytest.fixture
def security_scan_factory():
    """Provide SecurityScanFactory for test cases."""
    return SecurityScanFactory


@pytest.fixture
def vulnerability_finding_factory():
    """Provide VulnerabilityFindingFactory for test cases."""
    return VulnerabilityFindingFactory


@pytest.fixture
def role_factory():
    """Provide RoleFactory for test cases."""
    return RoleFactory


@pytest.fixture
def all_factories():
    """Provide all factories in a single fixture for convenience."""
    return {
        "user": UserFactory,
        "session": SessionFactory,
        "api_key": ApiKeyFactory,
        "audit_log": AuditLogFactory,
        "security_scan": SecurityScanFactory,
        "vulnerability_finding": VulnerabilityFindingFactory,
        "role": RoleFactory,
    }


class TestDataBuilder:
    """Builder class for creating complex test scenarios with related data."""

    def __init__(self):
        self.users = []
        self.sessions = []
        self.api_keys = []
        self.audit_logs = []
        self.security_scans = []
        self.vulnerability_findings = []
        self.roles = []

    def with_user(self, **kwargs) -> "TestDataBuilder":
        """Add a user to the test scenario."""
        user = UserFactory.create(**kwargs)
        self.users.append(user)
        return self

    def with_admin_user(self, **kwargs) -> "TestDataBuilder":
        """Add an admin user to the test scenario."""
        user = UserFactory.create_admin_user(**kwargs)
        self.users.append(user)
        return self

    def with_session_for_user(self, user_index: int = 0, **kwargs) -> "TestDataBuilder":
        """Add a session for the specified user."""
        if self.users:
            user = self.users[user_index]
            session = SessionFactory.create_for_user(user, **kwargs)
            self.sessions.append(session)
        return self

    def with_api_key_for_user(self, user_index: int = 0, **kwargs) -> "TestDataBuilder":
        """Add an API key for the specified user."""
        if self.users:
            user = self.users[user_index]
            api_key = ApiKeyFactory.create_for_user(user, **kwargs)
            self.api_keys.append(api_key)
        return self

    def with_security_scan(self, **kwargs) -> "TestDataBuilder":
        """Add a security scan to the test scenario."""
        scan = SecurityScanFactory.create(**kwargs)
        self.security_scans.append(scan)
        return self

    def with_vulnerability_for_scan(self, scan_index: int = 0, **kwargs) -> "TestDataBuilder":
        """Add a vulnerability finding for the specified scan."""
        if self.security_scans:
            scan = self.security_scans[scan_index]
            finding = VulnerabilityFindingFactory.create_for_scan(scan, **kwargs)
            self.vulnerability_findings.append(finding)
        return self

    def build(self) -> Dict[str, List[Any]]:
        """Build and return the complete test data scenario."""
        return {
            "users": self.users,
            "sessions": self.sessions,
            "api_keys": self.api_keys,
            "audit_logs": self.audit_logs,
            "security_scans": self.security_scans,
            "vulnerability_findings": self.vulnerability_findings,
            "roles": self.roles,
        }


@pytest.fixture
def test_data_builder():
    """Provide TestDataBuilder for creating complex test scenarios."""
    return TestDataBuilder
