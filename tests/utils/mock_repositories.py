"""Mock repository implementations for service layer unit testing."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import AsyncMock

from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.security_scan import SecurityScan
from app.models.session import Session
from app.models.user import User
from app.models.vulnerability_finding import VulnerabilityFinding
from app.repositories.base import Page
from app.repositories.interfaces import (
    IApiKeyRepository,
    IAuditRepository,
    IHealthRepository,
    IRoleRepository,
    ISecurityScanRepository,
    ISessionRepository,
    IUserRepository,
    IVulnerabilityRepository,
)


class MockUserRepository(AsyncMock):
    """Mock implementation of IUserRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IUserRepository)
        self.users: Dict[str, User] = {}
        self.usernames: Set[str] = set()
        self.emails: Set[str] = set()
        self.call_log: List[tuple] = []

    async def get_by_username(self, username: str, organization_id: Optional[str] = None) -> Optional[User]:
        """Mock user retrieval by username."""
        self.call_log.append(("get_by_username", username, organization_id))

        for user in self.users.values():
            if user.username == username:
                if organization_id is None or user.organization_id == organization_id:
                    return user
        return None

    async def get_by_email(self, email: str) -> Optional[User]:
        """Mock user retrieval by email."""
        self.call_log.append(("get_by_email", email))

        for user in self.users.values():
            if user.email == email:
                return user
        return None

    async def authenticate(self, username: str, password: str, ip_address: Optional[str] = None) -> Optional[User]:
        """Mock user authentication."""
        self.call_log.append(("authenticate", username, "***", ip_address))

        user = await self.get_by_username(username)
        if user and user.is_active and password == "correct_password":
            return user
        return None

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        is_superuser: bool = False,
        created_by: str = "system",
    ) -> User:
        """Mock user creation."""
        self.call_log.append(("create_user", username, email))

        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            username=username,
            email=email,
            full_name=full_name or username,
            is_active=True,
            is_superuser=is_superuser,
            created_by=created_by,
            created_at=datetime.utcnow(),
        )

        self.users[user_id] = user
        self.usernames.add(username)
        self.emails.add(email)
        return user

    async def is_username_available(self, username: str, exclude_user_id: Optional[str] = None) -> bool:
        """Mock username availability check."""
        self.call_log.append(("is_username_available", username, exclude_user_id))

        if exclude_user_id:
            # Check if username exists for other users
            for user_id, user in self.users.items():
                if user_id != exclude_user_id and user.username == username:
                    return False
            return True

        return username not in self.usernames

    async def is_email_available(self, email: str, exclude_user_id: Optional[str] = None) -> bool:
        """Mock email availability check."""
        self.call_log.append(("is_email_available", email, exclude_user_id))

        if exclude_user_id:
            # Check if email exists for other users
            for user_id, user in self.users.items():
                if user_id != exclude_user_id and user.email == email:
                    return False
            return True

        return email not in self.emails

    def add_test_user(self, user: User) -> None:
        """Helper method to add test users to mock repository."""
        self.users[user.id] = user
        self.usernames.add(user.username)
        self.emails.add(user.email)


class MockSessionRepository(AsyncMock):
    """Mock implementation of ISessionRepository for service testing."""

    def __init__(self):
        super().__init__(spec=ISessionRepository)
        self.sessions: Dict[str, Session] = {}
        self.call_log: List[tuple] = []

    async def create_session(
        self,
        user_id: str,
        token: str,
        expires_at: datetime,
        ip_address: Optional[str] = None,
    ) -> Session:
        """Mock session creation."""
        self.call_log.append(("create_session", user_id, token[:10] + "...", expires_at))

        session_id = str(uuid.uuid4())
        session = Session(
            id=session_id,
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            created_at=datetime.utcnow(),
            is_active=True,
        )

        self.sessions[session_id] = session
        return session

    async def get_by_token(self, token: str) -> Optional[Session]:
        """Mock session retrieval by token."""
        self.call_log.append(("get_by_token", token[:10] + "..."))

        for session in self.sessions.values():
            if session.token == token and session.is_active:
                return session
        return None

    async def revoke_session(self, session_id: str) -> bool:
        """Mock session revocation."""
        self.call_log.append(("revoke_session", session_id))

        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
            return True
        return False


class MockApiKeyRepository(AsyncMock):
    """Mock implementation of IApiKeyRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IApiKeyRepository)
        self.api_keys: Dict[str, ApiKey] = {}
        self.call_log: List[tuple] = []

    async def create_api_key(
        self,
        user_id: str,
        name: str,
        key_hash: str,
        organization_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> ApiKey:
        """Mock API key creation."""
        self.call_log.append(("create_api_key", user_id, name))

        key_id = str(uuid.uuid4())
        api_key = ApiKey(
            id=key_id,
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            organization_id=organization_id,
            expires_at=expires_at,
            created_at=datetime.utcnow(),
            is_active=True,
        )

        self.api_keys[key_id] = api_key
        return api_key

    async def get_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        """Mock API key retrieval by hash."""
        self.call_log.append(("get_by_hash", key_hash[:10] + "..."))

        for api_key in self.api_keys.values():
            if api_key.key_hash == key_hash and api_key.is_active:
                return api_key
        return None

    async def revoke_key(self, key_id: str) -> bool:
        """Mock API key revocation."""
        self.call_log.append(("revoke_key", key_id))

        if key_id in self.api_keys:
            self.api_keys[key_id].is_active = False
            return True
        return False


class MockAuditRepository(AsyncMock):
    """Mock implementation of IAuditRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IAuditRepository)
        self.audit_logs: List[AuditLog] = []
        self.call_log: List[tuple] = []

    async def create_audit_log(
        self,
        user_id: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        """Mock audit log creation."""
        self.call_log.append(("create_audit_log", user_id, action, resource_type))

        log_id = str(uuid.uuid4())
        audit_log = AuditLog(
            id=log_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            timestamp=datetime.utcnow(),
        )

        self.audit_logs.append(audit_log)
        return audit_log

    async def get_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        page: int = 1,
        size: int = 50,
    ) -> Page[AuditLog]:
        """Mock audit log retrieval with pagination."""
        self.call_log.append(("get_logs", user_id, action, resource_type, page, size))

        # Filter logs based on criteria
        filtered_logs = self.audit_logs
        if user_id:
            filtered_logs = [log for log in filtered_logs if log.user_id == user_id]
        if action:
            filtered_logs = [log for log in filtered_logs if log.action == action]
        if resource_type:
            filtered_logs = [log for log in filtered_logs if log.resource_type == resource_type]

        # Apply pagination
        total = len(filtered_logs)
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        page_logs = filtered_logs[start_idx:end_idx]

        return Page(
            items=page_logs,
            total=total,
            page=page,
            size=size,
            has_next=end_idx < total,
            has_prev=page > 1,
        )


class MockSecurityScanRepository(AsyncMock):
    """Mock implementation of ISecurityScanRepository for service testing."""

    def __init__(self):
        super().__init__(spec=ISecurityScanRepository)
        self.scans: Dict[str, SecurityScan] = {}
        self.call_log: List[tuple] = []

    async def create_scan(
        self,
        scan_type: str,
        target: str,
        user_id: str,
        organization_id: Optional[str] = None,
    ) -> SecurityScan:
        """Mock security scan creation."""
        self.call_log.append(("create_scan", scan_type, target, user_id))

        scan_id = str(uuid.uuid4())
        scan = SecurityScan(
            id=scan_id,
            scan_type=scan_type,
            target=target,
            user_id=user_id,
            organization_id=organization_id,
            status="pending",
            created_at=datetime.utcnow(),
        )

        self.scans[scan_id] = scan
        return scan

    async def update_scan_status(
        self, scan_id: str, status: str, results: Optional[Dict[str, Any]] = None
    ) -> Optional[SecurityScan]:
        """Mock scan status update."""
        self.call_log.append(("update_scan_status", scan_id, status))

        if scan_id in self.scans:
            scan = self.scans[scan_id]
            scan.status = status
            if results:
                scan.results = results
            scan.updated_at = datetime.utcnow()
            return scan
        return None


class MockVulnerabilityRepository(AsyncMock):
    """Mock implementation of IVulnerabilityRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IVulnerabilityRepository)
        self.vulnerabilities: Dict[str, VulnerabilityFinding] = {}
        self.call_log: List[tuple] = []

    async def create_finding(
        self,
        scan_id: str,
        vulnerability_id: str,
        severity: str,
        title: str,
        description: str,
    ) -> VulnerabilityFinding:
        """Mock vulnerability finding creation."""
        self.call_log.append(("create_finding", scan_id, vulnerability_id, severity))

        finding_id = str(uuid.uuid4())
        finding = VulnerabilityFinding(
            id=finding_id,
            scan_id=scan_id,
            vulnerability_id=vulnerability_id,
            severity=severity,
            title=title,
            description=description,
            status="open",
            created_at=datetime.utcnow(),
        )

        self.vulnerabilities[finding_id] = finding
        return finding


class MockRoleRepository(AsyncMock):
    """Mock implementation of IRoleRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IRoleRepository)
        self.roles: Dict[str, Role] = {}
        self.call_log: List[tuple] = []

    async def create_role(self, name: str, description: str, permissions: List[str]) -> Role:
        """Mock role creation."""
        self.call_log.append(("create_role", name, description))

        role_id = str(uuid.uuid4())
        role = Role(
            id=role_id,
            name=name,
            description=description,
            permissions=permissions,
            created_at=datetime.utcnow(),
        )

        self.roles[role_id] = role
        return role


class MockHealthRepository(AsyncMock):
    """Mock implementation of IHealthRepository for service testing."""

    def __init__(self):
        super().__init__(spec=IHealthRepository)
        self.health_checks: Dict[str, Dict[str, Any]] = {}
        self.call_log: List[tuple] = []

        # Default healthy status
        self.health_checks["database"] = {"status": "healthy", "response_time": 0.01}
        self.health_checks["redis"] = {"status": "healthy", "response_time": 0.005}

    async def check_database_health(self) -> Dict[str, Any]:
        """Mock database health check."""
        self.call_log.append(("check_database_health",))
        return self.health_checks.get("database", {"status": "unhealthy"})

    async def check_redis_health(self) -> Dict[str, Any]:
        """Mock Redis health check."""
        self.call_log.append(("check_redis_health",))
        return self.health_checks.get("redis", {"status": "unhealthy"})

    def set_service_health(self, service: str, health_data: Dict[str, Any]) -> None:
        """Helper to configure service health status for testing."""
        self.health_checks[service] = health_data


class MockRepositoryContainer:
    """Container for all mock repositories for easy service testing."""

    def __init__(self):
        self.user_repository = MockUserRepository()
        self.session_repository = MockSessionRepository()
        self.api_key_repository = MockApiKeyRepository()
        self.audit_repository = MockAuditRepository()
        self.security_scan_repository = MockSecurityScanRepository()
        self.vulnerability_repository = MockVulnerabilityRepository()
        self.role_repository = MockRoleRepository()
        self.health_repository = MockHealthRepository()

    def reset_all(self) -> None:
        """Reset all mock repositories to clean state."""
        self.__init__()

    def get_all_call_logs(self) -> Dict[str, List[tuple]]:
        """Get call logs from all repositories for verification."""
        return {
            "user": self.user_repository.call_log,
            "session": self.session_repository.call_log,
            "api_key": self.api_key_repository.call_log,
            "audit": self.audit_repository.call_log,
            "security_scan": self.security_scan_repository.call_log,
            "vulnerability": self.vulnerability_repository.call_log,
            "role": self.role_repository.call_log,
            "health": self.health_repository.call_log,
        }
