"""Service layer for middleware to avoid direct database access."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.api_key import APIKeyRepository
from app.repositories.audit_log import AuditLogRepository
from app.repositories.audit_log_extensions import ExtendedAuditLogRepository
from app.repositories.oauth_access_token import OAuthAccessTokenRepository
from app.repositories.oauth_application import OAuthApplicationRepository
from app.repositories.oauth_authorization_code import OAuthAuthorizationCodeRepository
from app.repositories.oauth_refresh_token import OAuthRefreshTokenRepository
from app.repositories.oauth_scope import OAuthScopeRepository
from app.repositories.role import RoleRepository
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository
from app.services.api_key_service import APIKeyService
from app.services.audit_service import AuditService
from app.services.oauth_service import OAuth2Service


class MiddlewareService:
    """Service layer for middleware operations."""

    def __init__(self, session: AsyncSession):
        """Initialize middleware service.

        Args:
            session: Database session
        """
        self.session = session
        self.audit_repo = AuditLogRepository(session)
        self.api_key_repo = APIKeyRepository(session)
        self.session_repo = SessionRepository(session)
        self.user_repo = UserRepository(session)
        self.role_repo = RoleRepository(session)
        self.audit_service = AuditService(session)

        # OAuth repositories - initialized lazily for performance
        self._oauth_service = None

    async def log_audit_event(
        self,
        action: str,
        resource: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> None:
        """Log an audit event.

        Args:
            action: Action performed
            resource: Resource accessed
            user_id: User ID if authenticated
            details: Additional details
            status: Status of the action
            error_message: Error message if failed
        """
        await self.audit_service.log_event(
            action=action,
            resource=resource,
            user_id=user_id,
            details=details,
            status=status,
            error_message=error_message,
        )

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key.

        Args:
            api_key: API key to validate

        Returns:
            API key data if valid, None otherwise
        """
        return await self.api_key_repo.get_by_key(api_key)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data.

        Args:
            session_id: Session ID

        Returns:
            Session data if exists, None otherwise
        """
        return await self.session_repo.get(session_id)

    async def update_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Update session data.

        Args:
            session_id: Session ID
            data: Session data to update
        """
        await self.session_repo.update(session_id, data)

    async def get_user_permissions(self, user_id: int) -> list[str]:
        """Get user permissions.

        Args:
            user_id: User ID

        Returns:
            List of permission names
        """
        user = await self.user_repo.get(user_id)
        if not user:
            return []

        # Get permissions from user roles
        permissions = []
        if hasattr(user, "roles"):
            for role in user.roles:
                if hasattr(role, "permissions"):
                    permissions.extend([p.name for p in role.permissions])

        return permissions

    async def get_user_by_id(self, user_id: str, organization_id: Optional[str] = None):
        """Get user by ID with organization filtering.

        Args:
            user_id: User ID
            organization_id: Organization ID for multi-tenant isolation

        Returns:
            User object if found, None otherwise
        """
        return await self.user_repo.get_by_id(user_id, organization_id)

    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles.

        Args:
            user_id: User ID

        Returns:
            List of role names
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user or not hasattr(user, "roles"):
            return []
        return [role.name for role in user.roles]

    async def verify_api_key_hash(self, api_key: str, api_key_hash: str) -> bool:
        """Verify API key against stored hash.

        Args:
            api_key: Plain text API key
            api_key_hash: Stored hash

        Returns:
            True if key matches hash
        """
        api_key_service = APIKeyService(self.session)
        return await api_key_service._verify_key_hash(api_key, api_key_hash)

    async def get_api_keys_by_prefix(self, api_key_prefix: str):
        """Get API keys by prefix.

        Args:
            api_key_prefix: API key prefix

        Returns:
            List of matching API key models
        """
        return await self.api_key_repo.get_by_prefix(api_key_prefix)

    async def record_api_key_usage(self, api_key_model) -> None:
        """Record API key usage.

        Args:
            api_key_model: API key model
        """
        api_key_model.record_usage()
        # Note: Transaction management handled by the calling layer

    def _get_oauth_service(self) -> OAuth2Service:
        """Get OAuth2 service instance (lazy initialization).

        Returns:
            OAuth2Service instance
        """
        if self._oauth_service is None:
            # Create repositories
            app_repo = OAuthApplicationRepository(self.session)
            access_token_repo = OAuthAccessTokenRepository(self.session)
            refresh_token_repo = OAuthRefreshTokenRepository(self.session)
            auth_code_repo = OAuthAuthorizationCodeRepository(self.session)
            scope_repo = OAuthScopeRepository(self.session)
            audit_repo = ExtendedAuditLogRepository(self.session)
            audit_service = AuditService(audit_repo)

            self._oauth_service = OAuth2Service(
                app_repo, access_token_repo, refresh_token_repo, auth_code_repo, scope_repo, audit_service
            )

        return self._oauth_service

    async def validate_oauth_access_token(self, token: str) -> Tuple[Optional[Any], Optional[Any], Optional[Any]]:
        """Validate OAuth access token.

        Args:
            token: OAuth access token

        Returns:
            Tuple of (access_token, user, application) or (None, None, None)
        """
        try:
            oauth_service = self._get_oauth_service()
            return await oauth_service.validate_access_token(token)
        except Exception:
            return None, None, None

    async def get_oauth_scopes_for_token(self, access_token_model) -> List[str]:
        """Get scopes for OAuth access token.

        Args:
            access_token_model: OAuth access token model

        Returns:
            List of scope names
        """
        if hasattr(access_token_model, "scopes") and access_token_model.scopes:
            return json.loads(access_token_model.scopes)
        return []
