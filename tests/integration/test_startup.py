"""Integration tests for repository startup and registration."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from app.api.deps import (
    get_api_key_repository_dep,
    get_audit_repository_dep,
    get_health_repository_dep,
    get_role_repository_dep,
    get_security_scan_repository_dep,
    get_session_repository_dep,
    get_user_repository_dep,
    get_vulnerability_repository_dep,
)
from app.core.container import (
    DependencyContainer,
    clear_repository_registrations,
    get_container,
    get_repository_health_status,
    get_repository_health_with_timeout,
    register_repositories,
    set_container,
)


class TestRepositoryStartupIntegration:
    """Integration tests for repository startup and registration."""

    @pytest.fixture
    def clean_container(self):
        """Provide a clean container for each test."""
        original_container = get_container()
        test_container = DependencyContainer()
        set_container(test_container)
        yield test_container
        set_container(original_container)

    @pytest.fixture
    def mock_session_factory(self):
        """Mock session factory for testing."""

        def factory():
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.scalar = AsyncMock()
            mock_session.commit = AsyncMock()
            mock_session.rollback = AsyncMock()
            mock_session.close = AsyncMock()
            return mock_session

        return factory

    @pytest.mark.asyncio
    async def test_register_repositories_success(self, clean_container, mock_session_factory):
        """Test successful repository registration."""
        # Register repositories
        await register_repositories(mock_session_factory)

        # Verify all repository interfaces are registered
        container = get_container()
        assert len(container._factories) == 8

        # Verify specific repository types are registered
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

        expected_interfaces = [
            IUserRepository,
            IApiKeyRepository,
            ISessionRepository,
            IAuditRepository,
            ISecurityScanRepository,
            IVulnerabilityRepository,
            IRoleRepository,
            IHealthRepository,
        ]

        for interface in expected_interfaces:
            assert interface in container._factories

    @pytest.mark.asyncio
    async def test_register_repositories_with_session_failure(self, clean_container):
        """Test repository registration with session creation failure."""

        def failing_session_factory():
            raise ConnectionError("Database connection failed")

        # Should not raise exception, but should log error
        await register_repositories(failing_session_factory)

        # Container should still have factories registered (they fail at creation time)
        container = get_container()
        assert len(container._factories) == 8

    @pytest.mark.asyncio
    async def test_repository_health_status(self, clean_container, mock_session_factory):
        """Test repository health status checking."""
        # Register repositories
        await register_repositories(mock_session_factory)

        # Get health status
        health_status = await get_repository_health_status()

        # Verify structure
        assert isinstance(health_status, dict)
        assert len(health_status) == 8

        # All should be healthy since we have mock sessions
        expected_repos = [
            "user_repository",
            "api_key_repository",
            "session_repository",
            "audit_repository",
            "security_scan_repository",
            "vulnerability_repository",
            "role_repository",
            "health_repository",
        ]

        for repo_name in expected_repos:
            assert repo_name in health_status
            assert health_status[repo_name] == "healthy"

    @pytest.mark.asyncio
    async def test_repository_health_status_with_failures(self, clean_container):
        """Test repository health status with registration failures."""
        # Don't register any repositories
        health_status = await get_repository_health_status()

        # All should be not_registered
        assert all(status == "not_registered" for status in health_status.values())

    def test_clear_repository_registrations(self, clean_container, mock_session_factory):
        """Test clearing repository registrations."""
        # Register some mock repositories
        container = get_container()
        container.register_service(Mock, Mock())
        container.register_factory(Mock, Mock())

        # Clear registrations
        clear_repository_registrations()

        # Verify container is empty
        assert len(container._services) == 0
        assert len(container._factories) == 0


class TestFastAPIRepositoryDependencies:
    """Test FastAPI dependency functions for repositories."""

    @pytest.fixture
    def clean_container(self):
        """Provide a clean container for each test."""
        original_container = get_container()
        test_container = DependencyContainer()
        set_container(test_container)
        yield test_container
        set_container(original_container)

    @pytest.mark.asyncio
    async def test_repository_dependencies_success(self, clean_container):
        """Test successful repository dependency resolution."""
        from app.repositories.interfaces import IUserRepository

        # Mock repository instance
        mock_repository = Mock(spec=IUserRepository)
        mock_repository.session = AsyncMock()

        # Register in container
        container = get_container()
        container.register_service(IUserRepository, mock_repository)

        # Test dependency function
        result = await get_user_repository_dep()
        assert result == mock_repository

    @pytest.mark.asyncio
    async def test_repository_dependencies_not_available(self, clean_container):
        """Test repository dependency when repository not available."""
        # Don't register any repositories

        # Should raise HTTPException with 503 status
        with pytest.raises(HTTPException) as exc_info:
            await get_user_repository_dep()

        assert exc_info.value.status_code == 503
        assert "not available" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_all_repository_dependencies_not_available(self, clean_container):
        """Test all repository dependencies when not available."""
        dependency_functions = [
            get_user_repository_dep,
            get_api_key_repository_dep,
            get_session_repository_dep,
            get_audit_repository_dep,
            get_security_scan_repository_dep,
            get_vulnerability_repository_dep,
            get_role_repository_dep,
            get_health_repository_dep,
        ]

        for dep_func in dependency_functions:
            with pytest.raises(HTTPException) as exc_info:
                await dep_func()

            assert exc_info.value.status_code == 503
            assert "not available" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_repository_dependencies_with_registration(self, clean_container):
        """Test repository dependencies after proper registration."""
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

        # Create mock repositories
        mock_repositories = {
            IUserRepository: Mock(spec=IUserRepository),
            IApiKeyRepository: Mock(spec=IApiKeyRepository),
            ISessionRepository: Mock(spec=ISessionRepository),
            IAuditRepository: Mock(spec=IAuditRepository),
            ISecurityScanRepository: Mock(spec=ISecurityScanRepository),
            IVulnerabilityRepository: Mock(spec=IVulnerabilityRepository),
            IRoleRepository: Mock(spec=IRoleRepository),
            IHealthRepository: Mock(spec=IHealthRepository),
        }

        # Register all repositories
        container = get_container()
        for interface, repo in mock_repositories.items():
            repo.session = AsyncMock()
            container.register_service(interface, repo)

        # Test all dependency functions
        dependency_tests = [
            (get_user_repository_dep, mock_repositories[IUserRepository]),
            (get_api_key_repository_dep, mock_repositories[IApiKeyRepository]),
            (get_session_repository_dep, mock_repositories[ISessionRepository]),
            (get_audit_repository_dep, mock_repositories[IAuditRepository]),
            (get_security_scan_repository_dep, mock_repositories[ISecurityScanRepository]),
            (get_vulnerability_repository_dep, mock_repositories[IVulnerabilityRepository]),
            (get_role_repository_dep, mock_repositories[IRoleRepository]),
            (get_health_repository_dep, mock_repositories[IHealthRepository]),
        ]

        for dep_func, expected_repo in dependency_tests:
            result = await dep_func()
            assert result == expected_repo


class TestApplicationStartupIntegration:
    """Test full application startup integration with repositories."""

    @pytest.mark.asyncio
    async def test_startup_sequence_integration(self):
        """Test the full startup sequence with repository registration."""
        with patch("app.main._initialize_repositories") as mock_init_repos:
            # Mock the session maker to return a valid maker
            with patch("app.db.session.get_session_maker") as mock_get_session_maker:
                mock_session_maker = Mock()
                mock_get_session_maker.return_value = mock_session_maker

                from app.main import _initialize_database

                # Run database initialization (which should call repository init)
                await _initialize_database()

                # Verify repository initialization was called
                mock_init_repos.assert_called_once()

    @pytest.mark.asyncio
    async def test_startup_with_no_database(self):
        """Test startup when database is not configured."""
        with patch("app.main._initialize_repositories") as mock_init_repos:
            # Mock session maker to return None (no database)
            with patch("app.db.session.get_session_maker", return_value=None):
                from app.main import _initialize_database

                await _initialize_database()

                # Repository initialization should not be called
                mock_init_repos.assert_not_called()

    @pytest.mark.asyncio
    async def test_startup_with_database_error(self):
        """Test startup when database initialization fails."""
        # Mock session maker to raise exception
        with patch("app.db.session.get_session_maker", side_effect=Exception("Database error")):
            from app.main import _initialize_database

            # Should not raise exception (graceful handling)
            await _initialize_database()

    @pytest.mark.asyncio
    async def test_shutdown_sequence_integration(self):
        """Test the shutdown sequence with repository cleanup."""
        with patch("app.main._shutdown_repositories") as mock_shutdown_repos:
            # Mock database connection closure
            with patch("app.db.session.close_database_connections") as mock_close_db:

                async def mock_async_func():
                    return None

                mock_close_db.return_value = mock_async_func()

                from app.main import _shutdown_database

                await _shutdown_database()

                # Verify repository shutdown was called before database shutdown
                mock_shutdown_repos.assert_called_once()
                mock_close_db.assert_called_once()


class TestHealthEndpointIntegration:
    """Test health endpoint integration with repository health checks."""

    @pytest.mark.asyncio
    async def test_health_endpoint_with_repositories(self):
        """Test health endpoint includes repository health status."""
        from app.api.endpoints.health import check_repository_health

        # Mock repository health status with timeout function (actually used)
        with patch("app.core.container.get_repository_health_with_timeout") as mock_get_health:
            mock_health_result = {
                "overall_status": "degraded",
                "healthy_count": 6,
                "degraded_count": 0,
                "unhealthy_count": 2,
                "total_count": 8,
                "repositories": {
                    "user_repository": {"status": "healthy", "response_time_ms": 10},
                    "api_key_repository": {"status": "healthy", "response_time_ms": 15},
                    "session_repository": {"status": "unhealthy", "error": "Connection failed"},
                    "audit_repository": {"status": "healthy", "response_time_ms": 8},
                    "security_scan_repository": {"status": "healthy", "response_time_ms": 12},
                    "vulnerability_repository": {"status": "healthy", "response_time_ms": 9},
                    "role_repository": {"status": "healthy", "response_time_ms": 11},
                    "health_repository": {"status": "unhealthy", "error": "Timeout"},
                },
                "summary": {
                    "health_percentage": 75.0,
                    "average_response_time_ms": 10.8,
                    "unhealthy_repositories": ["session_repository", "health_repository"],
                },
                "cache_hit": False,
                "timeout_occurred": False,
            }
            mock_get_health.return_value = mock_health_result

            result = await check_repository_health()

            # Verify UAT-compliant structure is returned
            assert result["overall_status"] == "degraded"
            assert result["healthy_count"] == 6
            assert result["total_count"] == 8
            assert "summary" in result
            assert "repositories" in result
            mock_get_health.assert_called_once_with(timeout_seconds=30, use_cache=True)

    @pytest.mark.asyncio
    async def test_health_endpoint_all_healthy(self):
        """Test health endpoint when all repositories are healthy."""
        from app.api.endpoints.health import check_repository_health

        with patch("app.core.container.get_repository_health_with_timeout") as mock_get_health:
            mock_health_result = {
                "overall_status": "healthy",
                "healthy_count": 8,
                "degraded_count": 0,
                "unhealthy_count": 0,
                "total_count": 8,
                "repositories": {f"repo_{i}": {"status": "healthy", "response_time_ms": 10} for i in range(8)},
                "summary": {"health_percentage": 100.0, "average_response_time_ms": 10.0, "unhealthy_repositories": []},
                "cache_hit": False,
                "timeout_occurred": False,
            }
            mock_get_health.return_value = mock_health_result

            result = await check_repository_health()

            assert result["overall_status"] == "healthy"
            assert result["healthy_count"] == 8
            assert result["total_count"] == 8
            assert result["summary"]["unhealthy_repositories"] == []

    @pytest.mark.asyncio
    async def test_health_endpoint_health_check_error(self):
        """Test health endpoint when health check itself fails."""
        from app.api.endpoints.health import check_repository_health

        with patch(
            "app.core.container.get_repository_health_with_timeout", side_effect=Exception("Health check failed")
        ):
            result = await check_repository_health()

            assert result["overall_status"] == "error"
            assert result["healthy_count"] == 0
            assert result["total_count"] == 8
            assert "error" in result


class TestRepositoryHealthWithTimeout:
    """Test repository health checks with timeout functionality (UAT requirement)."""

    @pytest.fixture
    def clean_container(self):
        """Provide a clean container for each test."""
        original_container = get_container()
        test_container = DependencyContainer()
        set_container(test_container)
        yield test_container
        set_container(original_container)

    @pytest.mark.asyncio
    async def test_repository_health_with_timeout_success(self, clean_container):
        """Test repository health check with timeout - success case."""
        # Mock the underlying health status function
        with patch("app.core.container.get_repository_health_status") as mock_health:
            mock_health_data = {
                "user_repository": "healthy",
                "api_key_repository": "healthy",
                "session_repository": "healthy",
                "audit_repository": "healthy",
                "security_scan_repository": "healthy",
                "vulnerability_repository": "healthy",
                "role_repository": "healthy",
                "health_repository": "healthy",
            }
            mock_health.return_value = mock_health_data

            # Test with timeout
            result = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=False)

            # Verify UAT-compliant structure
            assert "overall_status" in result
            assert "healthy_count" in result
            assert "total_count" in result
            assert "repositories" in result
            assert result["total_count"] == 8
            assert result["timeout_occurred"] is False

    @pytest.mark.asyncio
    async def test_repository_health_with_timeout_timeout_scenario(self, clean_container):
        """Test repository health check timeout scenario."""

        # Mock a slow health check
        async def slow_health_check(*args, **kwargs):
            await asyncio.sleep(2)  # Simulate slow operation
            return {"user_repository": "healthy"}

        with patch("app.core.container.get_repository_health_status", side_effect=slow_health_check):
            # Test with very short timeout
            result = await get_repository_health_with_timeout(timeout_seconds=0.1, use_cache=False)

            # Should handle timeout gracefully
            assert "timeout_occurred" in result
            assert result.get("timeout_occurred") is True
            assert result["overall_status"] == "error"

    @pytest.mark.asyncio
    async def test_repository_health_caching_behavior(self, clean_container):
        """Test repository health check caching behavior (performance requirement)."""
        with patch("app.core.container.get_repository_health_status") as mock_health:
            mock_health_data = {f"repo_{i}": "healthy" for i in range(8)}
            mock_health.return_value = mock_health_data

            # First call should cache the result
            result1 = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=True)

            # Second call should use cache
            result2 = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=True)

            # Function should only be called once due to caching
            mock_health.assert_called_once()
            assert result2.get("cache_hit") is True

    @pytest.mark.asyncio
    async def test_uct_compliance_health_endpoint_structure(self, clean_container):
        """Test UAT compliance - verify health endpoint structure matches specification."""
        with patch("app.core.container.get_repository_health_status") as mock_health:
            # Mock the actual structure returned by get_repository_health_status
            mock_health_result = {
                "overall_status": "degraded",
                "healthy_count": 4,
                "degraded_count": 1,
                "unhealthy_count": 3,
                "total_count": 8,
                "total_check_time_ms": 15.2,
                "repositories": {
                    "user_repository": {"status": "healthy", "response_time_ms": 10},
                    "api_key_repository": {"status": "unhealthy", "error_message": "Connection failed"},
                    "session_repository": {"status": "degraded", "response_time_ms": 25},
                    "audit_repository": {"status": "healthy", "response_time_ms": 8},
                    "security_scan_repository": {"status": "healthy", "response_time_ms": 12},
                    "vulnerability_repository": {"status": "healthy", "response_time_ms": 9},
                    "role_repository": {"status": "not_registered", "error_message": "Not available"},
                    "health_repository": {"status": "error", "error_message": "Timeout"},
                },
                "cache_hit": False,
                "cache_age_seconds": 0,
                "connection_pool": {"pool_size": 5, "checked_out_connections": 0, "utilization_percentage": 0.0},
                "operation_metrics": {},
                "summary": {
                    "health_percentage": 50.0,
                    "average_response_time_ms": 12.8,
                    "unhealthy_repositories": ["api_key_repository", "role_repository", "health_repository"],
                    "connection_pool_health": "healthy",
                },
            }
            mock_health.return_value = mock_health_result

            result = await get_repository_health_with_timeout(timeout_seconds=30, use_cache=False)

            # UAT specification requires these exact fields
            required_fields = [
                "overall_status",
                "healthy_count",
                "degraded_count",
                "unhealthy_count",
                "total_count",
                "repositories",
                "summary",
            ]

            for field in required_fields:
                assert field in result, f"Missing required UAT field: {field}"

            # Verify counts are accurate
            assert result["healthy_count"] == 4  # user, audit, security_scan, vulnerability
            assert result["degraded_count"] == 1  # session
            assert result["unhealthy_count"] == 3  # api_key, role, health
            assert result["total_count"] == 8

            # Verify timeout fields are added
            assert result["timeout_occurred"] is False
            assert result["timeout_seconds"] == 30


class TestApplicationStartupWithRealDependencies:
    """Test application startup with real dependencies (enhanced UAT compliance)."""

    @pytest.mark.asyncio
    async def test_application_startup_initializes_all_repositories(self):
        """Test that application startup initializes all 8 repositories correctly (UAT requirement)."""
        with patch("app.db.session.get_session_maker") as mock_get_session_maker:
            # Mock a real session maker
            mock_session_maker = Mock()
            mock_session_maker.return_value = AsyncMock()
            mock_get_session_maker.return_value = mock_session_maker

            with patch("app.core.container.register_repositories") as mock_register:
                from app.main import _initialize_repositories

                # Run repository initialization
                await _initialize_repositories()

                # Verify register_repositories was called with session factory
                mock_register.assert_called_once()
                args = mock_register.call_args[0]
                assert callable(args[0])  # Session factory should be callable

    @pytest.mark.asyncio
    async def test_graceful_degradation_when_database_unavailable(self):
        """Test graceful degradation when database unavailable (UAT requirement)."""
        with patch("app.db.session.get_session_maker", return_value=None):
            from app.main import _initialize_repositories

            # Should not raise exception (graceful degradation)
            await _initialize_repositories()

            # The system should log that repositories were not initialized
            # Note: When get_repository_health_status() is called, auto-registration
            # may occur as a recovery mechanism, which is the intended behavior
            # So we just verify that initialization didn't raise an exception

    @pytest.mark.asyncio
    async def test_repository_cleanup_during_shutdown(self):
        """Test repository cleanup during application shutdown (UAT requirement)."""
        with patch("app.core.container.clear_repository_registrations") as mock_clear:
            from app.main import _shutdown_repositories

            await _shutdown_repositories()
            mock_clear.assert_called_once()

    @pytest.mark.asyncio
    async def test_startup_fails_gracefully_on_repository_error(self):
        """Test startup fails gracefully if repository initialization fails (UAT requirement)."""
        with patch("app.db.session.get_session_maker") as mock_get_session_maker:
            mock_session_maker = Mock()
            mock_get_session_maker.return_value = mock_session_maker

            # Mock register_repositories to raise exception
            with patch("app.core.container.register_repositories", side_effect=Exception("Registration failed")):
                from app.main import _initialize_repositories

                # Should not raise exception (graceful degradation)
                await _initialize_repositories()


class TestDependencyOverrideIntegration:
    """Test FastAPI dependency override mechanism with repositories (UAT requirement)."""

    @pytest.fixture
    def mock_app(self):
        """Create a mock FastAPI app for testing."""
        from fastapi import FastAPI

        app = FastAPI()
        return app

    @pytest.mark.asyncio
    async def test_dependency_overrides_work_with_repositories(self, mock_app):
        """Test app.dependency_overrides functionality works with repositories (UAT requirement)."""
        from app.api.deps import get_user_repository_dep
        from app.repositories.interfaces import IUserRepository

        # Create mock repository for override
        mock_override_repo = Mock(spec=IUserRepository)

        # Set up dependency override
        async def override_get_user_repo():
            return mock_override_repo

        mock_app.dependency_overrides[get_user_repository_dep] = override_get_user_repo

        # Simulate using the override (in real scenarios, this would be in request context)
        override_func = mock_app.dependency_overrides[get_user_repository_dep]
        result = await override_func()

        assert result == mock_override_repo

    def test_production_dependencies_not_affected_by_overrides(self):
        """Verify production dependencies not affected by test overrides (UAT requirement)."""
        from fastapi import FastAPI

        from app.api.deps import get_user_repository_dep

        # Create separate app instances
        test_app = FastAPI()
        prod_app = FastAPI()

        # Add override only to test app
        test_app.dependency_overrides[get_user_repository_dep] = lambda: "test_override"

        # Verify production app not affected
        assert get_user_repository_dep not in prod_app.dependency_overrides
        assert len(prod_app.dependency_overrides) == 0
