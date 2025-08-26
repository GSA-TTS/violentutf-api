"""Unit tests for dependency injection container."""

from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import (
    DependencyContainer,
    get_api_key_repository,
    get_audit_repository,
    get_container,
    get_health_repository,
    get_role_repository,
    get_security_scan_repository,
    get_session_repository,
    get_user_repository,
    get_vulnerability_repository,
    set_container,
)
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


class TestDependencyContainer:
    """Test cases for DependencyContainer class."""

    def test_container_initialization(self):
        """Test container initializes with empty services and factories."""
        container = DependencyContainer()
        assert container._services == {}
        assert container._factories == {}

    def test_register_service(self):
        """Test service registration."""
        container = DependencyContainer()
        mock_service = Mock()

        container.register_service(IUserRepository, mock_service)

        assert container._services[IUserRepository] == mock_service

    def test_register_factory(self):
        """Test factory registration."""
        container = DependencyContainer()
        mock_factory = Mock(return_value=Mock())

        container.register_factory(IUserRepository, mock_factory)

        assert container._factories[IUserRepository] == mock_factory

    def test_get_service_from_cache(self):
        """Test getting service from cache."""
        container = DependencyContainer()
        mock_service = Mock()
        container.register_service(IUserRepository, mock_service)

        result = container.get_service(IUserRepository)

        assert result == mock_service

    def test_get_service_from_factory(self):
        """Test getting service from factory."""
        container = DependencyContainer()
        mock_service = Mock()
        mock_factory = Mock(return_value=mock_service)
        container.register_factory(IUserRepository, mock_factory)

        result = container.get_service(IUserRepository)

        assert result == mock_service
        mock_factory.assert_called_once()
        # Service should be cached after factory call
        assert container._services[IUserRepository] == mock_service

    def test_get_service_not_found(self):
        """Test getting non-existent service returns None."""
        container = DependencyContainer()

        result = container.get_service(IUserRepository)

        assert result is None

    def test_clear_container(self):
        """Test clearing container removes all services and factories."""
        container = DependencyContainer()
        container.register_service(IUserRepository, Mock())
        container.register_factory(IApiKeyRepository, Mock())

        container.clear()

        assert container._services == {}
        assert container._factories == {}


class TestGlobalContainer:
    """Test cases for global container management."""

    def test_get_container_creates_singleton(self):
        """Test get_container creates singleton instance."""
        # Clear any existing container
        set_container(None)

        container1 = get_container()
        container2 = get_container()

        assert container1 is container2
        assert isinstance(container1, DependencyContainer)

    def test_set_container_updates_global(self):
        """Test set_container updates global instance."""
        custom_container = DependencyContainer()

        set_container(custom_container)

        assert get_container() is custom_container


class TestRepositoryConvenienceFunctions:
    """Test cases for repository convenience functions."""

    def setup_method(self):
        """Set up test container before each test."""
        self.container = DependencyContainer()
        set_container(self.container)

    def test_get_user_repository_success(self):
        """Test successful user repository retrieval."""
        mock_repository = Mock(spec=IUserRepository)
        self.container.register_service(IUserRepository, mock_repository)

        result = get_user_repository()

        assert result == mock_repository

    def test_get_user_repository_not_found(self):
        """Test user repository retrieval returns None when not found."""
        result = get_user_repository()

        assert result is None

    def test_get_user_repository_exception_handled(self):
        """Test user repository retrieval handles exceptions gracefully."""

        # Register a factory that raises an exception
        def failing_factory():
            raise Exception("Database connection failed")

        self.container.register_factory(IUserRepository, failing_factory)

        result = get_user_repository()

        assert result is None

    def test_get_session_repository_success(self):
        """Test successful session repository retrieval."""
        mock_repository = Mock(spec=ISessionRepository)
        self.container.register_service(ISessionRepository, mock_repository)

        result = get_session_repository()

        assert result == mock_repository

    def test_get_api_key_repository_success(self):
        """Test successful API key repository retrieval."""
        mock_repository = Mock(spec=IApiKeyRepository)
        self.container.register_service(IApiKeyRepository, mock_repository)

        result = get_api_key_repository()

        assert result == mock_repository

    def test_get_audit_repository_success(self):
        """Test successful audit repository retrieval."""
        mock_repository = Mock(spec=IAuditRepository)
        self.container.register_service(IAuditRepository, mock_repository)

        result = get_audit_repository()

        assert result == mock_repository

    def test_get_security_scan_repository_success(self):
        """Test successful security scan repository retrieval."""
        mock_repository = Mock(spec=ISecurityScanRepository)
        self.container.register_service(ISecurityScanRepository, mock_repository)

        result = get_security_scan_repository()

        assert result == mock_repository

    def test_get_vulnerability_repository_success(self):
        """Test successful vulnerability repository retrieval."""
        mock_repository = Mock(spec=IVulnerabilityRepository)
        self.container.register_service(IVulnerabilityRepository, mock_repository)

        result = get_vulnerability_repository()

        assert result == mock_repository

    def test_get_role_repository_success(self):
        """Test successful role repository retrieval."""
        mock_repository = Mock(spec=IRoleRepository)
        self.container.register_service(IRoleRepository, mock_repository)

        result = get_role_repository()

        assert result == mock_repository

    def test_get_health_repository_success(self):
        """Test successful health repository retrieval."""
        mock_repository = Mock(spec=IHealthRepository)
        self.container.register_service(IHealthRepository, mock_repository)

        result = get_health_repository()

        assert result == mock_repository

    def test_all_repository_functions_handle_exceptions(self):
        """Test all repository convenience functions handle exceptions gracefully."""

        # Register failing factories for all repository types
        def failing_factory():
            raise Exception("Connection failed")

        repository_functions = [
            (ISessionRepository, get_session_repository),
            (IApiKeyRepository, get_api_key_repository),
            (IAuditRepository, get_audit_repository),
            (ISecurityScanRepository, get_security_scan_repository),
            (IVulnerabilityRepository, get_vulnerability_repository),
            (IRoleRepository, get_role_repository),
            (IHealthRepository, get_health_repository),
        ]

        for interface, func in repository_functions:
            # Clear container and register failing factory
            self.container.clear()
            self.container.register_factory(interface, failing_factory)

            # Function should return None instead of raising exception
            result = func()
            assert result is None


class TestRepositoryFactoryPattern:
    """Test cases for repository factory pattern implementation."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_session = AsyncMock(spec=AsyncSession)
        self.container = DependencyContainer()
        set_container(self.container)

    def test_repository_factory_creates_instance(self):
        """Test repository factory creates proper instance."""
        from app.repositories.user import UserRepository

        def user_repository_factory():
            return UserRepository(self.mock_session)

        self.container.register_factory(IUserRepository, user_repository_factory)

        result = get_user_repository()

        assert isinstance(result, UserRepository)
        assert result.session == self.mock_session

    def test_repository_factory_caching(self):
        """Test repository factory caches instances."""
        call_count = 0

        def counting_factory():
            nonlocal call_count
            call_count += 1
            return Mock(spec=IUserRepository)

        self.container.register_factory(IUserRepository, counting_factory)

        # First call should create instance
        result1 = get_user_repository()
        assert call_count == 1

        # Second call should return cached instance
        result2 = get_user_repository()
        assert call_count == 1
        assert result1 is result2

    def test_repository_factory_error_handling(self):
        """Test repository factory handles initialization errors."""

        def failing_factory():
            raise ConnectionError("Database unavailable")

        self.container.register_factory(IUserRepository, failing_factory)

        # Should not raise exception, should return None
        result = get_user_repository()
        assert result is None


class TestRepositoryRegistrationIntegration:
    """Integration tests for repository registration system."""

    def setup_method(self):
        """Set up test environment."""
        self.container = DependencyContainer()
        set_container(self.container)
        self.mock_session = AsyncMock(spec=AsyncSession)

    def test_register_all_repository_implementations(self):
        """Test registering all 8 repository implementations."""
        from app.repositories import (
            APIKeyRepository,
            AuditLogRepository,
            RoleRepository,
            SecurityScanRepository,
            SessionRepository,
            UserRepository,
            VulnerabilityTaxonomyRepository,
        )
        from app.repositories.health import HealthRepository

        # Create factory functions for all repositories
        factories = {
            IUserRepository: lambda: UserRepository(self.mock_session),
            IApiKeyRepository: lambda: APIKeyRepository(self.mock_session),
            ISessionRepository: lambda: SessionRepository(self.mock_session),
            IAuditRepository: lambda: AuditLogRepository(self.mock_session),
            ISecurityScanRepository: lambda: SecurityScanRepository(self.mock_session),
            IVulnerabilityRepository: lambda: VulnerabilityTaxonomyRepository(self.mock_session),
            IRoleRepository: lambda: RoleRepository(self.mock_session),
            IHealthRepository: lambda: HealthRepository(self.mock_session),
        }

        # Register all factories
        for interface, factory in factories.items():
            self.container.register_factory(interface, factory)

        # Verify all repositories can be retrieved
        repository_getters = [
            get_user_repository,
            get_api_key_repository,
            get_session_repository,
            get_audit_repository,
            get_security_scan_repository,
            get_vulnerability_repository,
            get_role_repository,
            get_health_repository,
        ]

        for getter in repository_getters:
            repository = getter()
            assert repository is not None
            # Verify repository has database session
            assert hasattr(repository, "session") or hasattr(repository, "db")

    def test_repository_registration_with_validation(self):
        """Test repository registration includes connection validation."""
        from app.repositories.user import UserRepository

        def validated_factory():
            repository = UserRepository(self.mock_session)
            # Simulate connection validation
            if not hasattr(repository, "session"):
                raise ConnectionError("Invalid repository configuration")
            return repository

        self.container.register_factory(IUserRepository, validated_factory)

        result = get_user_repository()
        assert isinstance(result, UserRepository)
        assert result.session == self.mock_session
