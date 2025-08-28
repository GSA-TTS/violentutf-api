"""
API Dependencies Module.

This module provides common dependency injection functions for FastAPI endpoints.
It consolidates authentication, database access, service layer dependencies, and other shared dependencies.
Follows ADR-013 for API layer separation and service layer integration.
"""

from typing import TYPE_CHECKING, Any, Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

# Import existing authentication functions
from app.core.auth import (
    get_current_active_user,
    get_current_superuser,
    get_current_user,
)

# Import db session dependency for service layer initialization
from app.db.session import get_db_dependency as get_db
from app.repositories.plugin import PluginRepository
from app.repositories.scan import ScanRepository
from app.repositories.security_scan import SecurityScanRepository
from app.repositories.user import UserRepository
from app.repositories.vulnerability_finding import VulnerabilityFindingRepository
from app.repositories.vulnerability_taxonomy import VulnerabilityTaxonomyRepository
from app.services.api_key_service import APIKeyService
from app.services.architectural_metrics_service import ArchitecturalMetricsService
from app.services.audit_service import AuditService
from app.services.health_service import HealthService
from app.services.mfa_policy_service import MFAPolicyService
from app.services.mfa_service import MFAService
from app.services.oauth_service import OAuth2Service
from app.services.plugin_service import PluginService
from app.services.rbac_service import RBACService
from app.services.report_service import ReportService
from app.services.request_validation_service import RequestValidationService
from app.services.scan_service import ScanService
from app.services.security_scan_service import SecurityScanService
from app.services.session_service import SessionService
from app.services.task_service import TaskService
from app.services.template_service import TemplateService

# Import core service layer components that work
from app.services.user_service_impl import UserServiceImpl
from app.services.vulnerability_finding_service import VulnerabilityFindingService
from app.services.vulnerability_taxonomy_service import VulnerabilityTaxonomyService

if TYPE_CHECKING:
    from app.models.user import User
    from app.services.scheduled_report_service import ScheduledReportService
else:
    # Import User for runtime to maintain backward compatibility
    from app.models.user import User


async def get_current_verified_user(current_user: "User" = Depends(get_current_active_user)) -> "User":
    """Get verified user dependency injection.

    Ensures the current user is verified (email verified).

    Args:
        current_user: Current active user

    Returns:
        User: Verified user object

    Raises:
        HTTPException: If user is not verified
    """
    if not getattr(current_user, "is_verified", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unverified user")
    return current_user


async def get_optional_user(request: Request) -> Optional["User"]:
    """Get optional user dependency injection.

    Attempts to get current user but doesn't fail if not authenticated.
    Useful for endpoints that work with or without authentication.

    Args:
        request: FastAPI request object

    Returns:
        Optional[User]: User object if authenticated, None otherwise
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None
    except Exception:
        return None


# Service layer dependency injection functions
# Following ADR-013 API layer separation patterns


async def get_user_service(session: AsyncSession = Depends(get_db)) -> UserServiceImpl:
    """Get user service dependency injection.

    Provides UserService instance with database session for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        UserServiceImpl: Configured user service instance
    """
    user_repo = UserRepository(session)
    return UserServiceImpl(user_repo)


async def get_api_key_service(session: AsyncSession = Depends(get_db)) -> APIKeyService:
    """Get API key service dependency injection.

    Provides APIKeyService instance with database session for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        APIKeyService: Configured API key service instance
    """
    return APIKeyService(session)


async def get_session_service(session: AsyncSession = Depends(get_db)) -> SessionService:
    """Get session service dependency injection.

    Provides SessionService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        SessionService: Configured session service instance
    """
    return SessionService(session)


async def get_architectural_metrics_service(session: AsyncSession = Depends(get_db)) -> ArchitecturalMetricsService:
    """Get architectural metrics service dependency injection.

    Provides ArchitecturalMetricsService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        ArchitecturalMetricsService: Configured metrics service instance
    """
    return ArchitecturalMetricsService(session)


async def get_rbac_service(session: AsyncSession = Depends(get_db)) -> RBACService:
    """Get RBAC service dependency injection.

    Provides RBACService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        RBACService: Configured RBAC service instance
    """
    # For now, we'll pass session directly and fix constructor later
    return RBACService(session)


async def get_vulnerability_taxonomy_service(session: AsyncSession = Depends(get_db)) -> VulnerabilityTaxonomyService:
    """Get VulnerabilityTaxonomyService dependency.

    Provides VulnerabilityTaxonomyService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        VulnerabilityTaxonomyService: Configured vulnerability taxonomy service instance
    """
    vulnerability_taxonomy_repo = VulnerabilityTaxonomyRepository(session)
    return VulnerabilityTaxonomyService(vulnerability_taxonomy_repo)


async def get_oauth_service(session: AsyncSession = Depends(get_db)) -> OAuth2Service:
    """Get OAuth2Service dependency.

    Provides OAuth2Service instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Args:
        session: Database session from dependency injection

    Returns:
        OAuth2Service: Configured OAuth2 service instance
    """
    return OAuth2Service(session)


async def get_audit_service(session: AsyncSession = Depends(get_db)) -> AuditService:
    """Get AuditService dependency."""
    # Service handles its own repository dependencies internally
    return AuditService(session)


async def get_mfa_service(session: AsyncSession = Depends(get_db)) -> MFAService:
    """Get MFAService dependency."""
    # Use service factory to avoid direct repository imports in API layer
    return _create_mfa_service(session)


async def get_mfa_policy_service(session: AsyncSession = Depends(get_db)) -> MFAPolicyService:
    """Get MFAPolicyService dependency."""
    return MFAPolicyService(session)


async def get_scheduled_report_service(session: AsyncSession = Depends(get_db)) -> "ScheduledReportService":
    """Get ScheduledReportService dependency."""
    from app.services.scheduled_report_service import ScheduledReportService

    return ScheduledReportService(session)


async def get_plugin_service(session: AsyncSession = Depends(get_db)) -> PluginService:
    """Get PluginService dependency."""
    plugin_repo = PluginRepository(session)
    return PluginService(plugin_repo)


async def get_report_service(session: AsyncSession = Depends(get_db)) -> ReportService:
    """Get ReportService dependency."""
    return ReportService(session)


async def get_scan_service(session: AsyncSession = Depends(get_db)) -> ScanService:
    """Get ScanService dependency."""
    scan_repo = ScanRepository(session)
    return ScanService(scan_repo)


async def get_security_scan_service(session: AsyncSession = Depends(get_db)) -> SecurityScanService:
    """Get SecurityScanService dependency."""
    security_scan_repo = SecurityScanRepository(session)
    return SecurityScanService(security_scan_repo)


async def get_task_service(session: AsyncSession = Depends(get_db)) -> TaskService:
    """Get TaskService dependency."""
    return TaskService(session)


async def get_template_service(session: AsyncSession = Depends(get_db)) -> TemplateService:
    """Get TemplateService dependency."""
    return TemplateService(session)


async def get_vulnerability_finding_service(session: AsyncSession = Depends(get_db)) -> VulnerabilityFindingService:
    """Get VulnerabilityFindingService dependency."""
    vulnerability_finding_repo = VulnerabilityFindingRepository(session)
    return VulnerabilityFindingService(vulnerability_finding_repo)


async def get_health_service() -> HealthService:
    """Get health service dependency injection.

    Provides HealthService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Returns:
        HealthService: Configured health service instance
    """
    return HealthService()


async def get_request_validation_service() -> RequestValidationService:
    """Get request validation service dependency injection.

    Provides RequestValidationService instance for API endpoints.
    Follows ADR-013 service layer integration patterns.

    Returns:
        RequestValidationService: Configured request validation service instance
    """
    return RequestValidationService()


# Repository dependency functions using container
async def get_user_repository_dep() -> Any:
    """Get user repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_user_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="User repository not available")
    return repository


async def get_api_key_repository_dep() -> Any:
    """Get API key repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_api_key_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="API key repository not available")
    return repository


async def get_session_repository_dep() -> Any:
    """Get session repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_session_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session repository not available")
    return repository


async def get_audit_repository_dep() -> Any:
    """Get audit repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_audit_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Audit repository not available")
    return repository


async def get_security_scan_repository_dep() -> Any:
    """Get security scan repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_security_scan_repository()
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Security scan repository not available"
        )
    return repository


async def get_vulnerability_repository_dep() -> Any:
    """Get vulnerability repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_vulnerability_repository()
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Vulnerability repository not available"
        )
    return repository


async def get_role_repository_dep() -> Any:
    """Get role repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_role_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Role repository not available")
    return repository


async def get_health_repository_dep() -> Any:
    """Get health repository from container for FastAPI dependency injection."""
    from app.core import container
    from app.db.session import get_session_maker

    # Ensure repositories are registered in async context
    try:
        session_maker = get_session_maker()
        if session_maker:

            def session_factory() -> Any:
                return session_maker()

            await container.register_repositories(session_factory)
    except Exception:
        pass  # Continue if registration fails

    repository = container.get_health_repository()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Health repository not available")
    return repository


# UAT-compliant repository dependency functions (without _dep suffix)
async def get_user_repository() -> Any:
    """Get user repository from container for UAT compliance."""
    return await get_user_repository_dep()


async def get_api_key_repository() -> Any:
    """Get API key repository from container for UAT compliance."""
    return await get_api_key_repository_dep()


async def get_session_repository() -> Any:
    """Get session repository from container for UAT compliance."""
    return await get_session_repository_dep()


async def get_audit_repository() -> Any:
    """Get audit repository from container for UAT compliance."""
    return await get_audit_repository_dep()


async def get_security_scan_repository() -> Any:
    """Get security scan repository from container for UAT compliance."""
    return await get_security_scan_repository_dep()


async def get_vulnerability_repository() -> Any:
    """Get vulnerability repository from container for UAT compliance."""
    return await get_vulnerability_repository_dep()


async def get_role_repository() -> Any:
    """Get role repository from container for UAT compliance."""
    return await get_role_repository_dep()


async def get_health_repository() -> Any:
    """Get health repository from container for UAT compliance."""
    return await get_health_repository_dep()


# Legacy aliases for backward compatibility
get_current_user_dep = get_current_user
get_db_dep = get_db


# Internal service factory functions to avoid direct repository imports in API layer
# These functions encapsulate repository creation to maintain architectural boundaries


def _create_mfa_service(session: AsyncSession) -> MFAService:
    """Internal factory for MFAService creation.

    Creates MFAService with session-based dependency injection.
    Repository creation moved to service layer to maintain architectural boundaries.
    """
    # Create audit service (it handles its own repository internally)
    audit_service = AuditService(session)

    # MFAService now creates its own repositories internally
    return MFAService(session=session, audit_service=audit_service)
