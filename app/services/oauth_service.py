"""OAuth2 service for managing third-party application access."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from structlog.stdlib import get_logger

from app.core.config import settings
from app.core.errors import AuthenticationError, ForbiddenError, NotFoundError, ValidationError
from app.core.security import create_token, hash_token, verify_password
from app.models.oauth import OAuthAccessToken, OAuthApplication, OAuthAuthorizationCode, OAuthRefreshToken, OAuthScope
from app.models.user import User
from app.repositories.oauth_access_token import OAuthAccessTokenRepository
from app.repositories.oauth_application import OAuthApplicationRepository
from app.repositories.oauth_authorization_code import OAuthAuthorizationCodeRepository
from app.repositories.oauth_refresh_token import OAuthRefreshTokenRepository
from app.repositories.oauth_scope import OAuthScopeRepository
from app.services.audit_service import AuditService

logger = get_logger(__name__)

# OAuth2 token type constants to avoid hardcoded strings flagged by security scanners
REFRESH_TOKEN_TYPE_HINT = "refresh_token"  # nosec B105 - Standard OAuth2 token hint
ACCESS_TOKEN_TYPE_HINT = "access_token"  # nosec B105 - Standard OAuth2 token hint


class OAuth2Service:
    """Service for OAuth2 operations."""

    # Token lifetimes
    ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS = 30  # 30 days
    AUTHORIZATION_CODE_EXPIRE_MINUTES = 10  # 10 minutes

    # Security settings
    MIN_CLIENT_SECRET_LENGTH = 32
    ALLOWED_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"]
    ALLOWED_RESPONSE_TYPES = ["code", "token"]

    def __init__(
        self,
        app_repo: OAuthApplicationRepository,
        access_token_repo: OAuthAccessTokenRepository,
        refresh_token_repo: OAuthRefreshTokenRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        scope_repo: OAuthScopeRepository,
        audit_service: AuditService,
    ):
        """Initialize OAuth2 service.

        Args:
            app_repo: OAuth application repository
            access_token_repo: OAuth access token repository
            refresh_token_repo: OAuth refresh token repository
            auth_code_repo: OAuth authorization code repository
            scope_repo: OAuth scope repository
            audit_service: Audit service
        """
        self.app_repo = app_repo
        self.access_token_repo = access_token_repo
        self.refresh_token_repo = refresh_token_repo
        self.auth_code_repo = auth_code_repo
        self.scope_repo = scope_repo
        self.audit_service = audit_service

    async def create_application(
        self,
        user_id: str,
        name: str,
        description: Optional[str],
        redirect_uris: List[str],
        allowed_scopes: List[str],
        application_type: str = "web",
        is_confidential: bool = True,
        logo_url: Optional[str] = None,
        homepage_url: Optional[str] = None,
        privacy_policy_url: Optional[str] = None,
        terms_of_service_url: Optional[str] = None,
    ) -> Tuple[OAuthApplication, str]:
        """Create new OAuth application.

        Args:
            user_id: Owner user ID
            name: Application name
            description: Application description
            redirect_uris: List of allowed redirect URIs
            allowed_scopes: List of allowed scopes
            application_type: Type of application (web, mobile, spa)
            is_confidential: Whether app can keep secrets
            logo_url: Application logo URL
            homepage_url: Application homepage URL
            privacy_policy_url: Privacy policy URL
            terms_of_service_url: Terms of service URL

        Returns:
            Tuple of (created application, plain text client secret)
        """
        # Validate inputs
        self._validate_application_inputs(name, redirect_uris, allowed_scopes, application_type)

        # Generate client credentials
        client_id = self._generate_client_id()
        client_secret = self._generate_client_secret()
        client_secret_hash = hash_token(client_secret)

        # Determine allowed grant types based on app type
        grant_types = self._get_grant_types_for_app_type(application_type, is_confidential)
        response_types = self._get_response_types_for_app_type(application_type)

        # Create application
        app_data = {
            "name": name,
            "description": description,
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            "redirect_uris": json.dumps(redirect_uris),
            "allowed_scopes": json.dumps(allowed_scopes),
            "grant_types": json.dumps(grant_types),
            "response_types": json.dumps(response_types),
            "application_type": application_type,
            "is_confidential": is_confidential,
            "owner_id": user_id,
            "logo_url": logo_url,
            "homepage_url": homepage_url,
            "privacy_policy_url": privacy_policy_url,
            "terms_of_service_url": terms_of_service_url,
        }

        app = await self.app_repo.create(app_data)

        # Log the creation
        await self.audit_service.log_resource_event(
            action="created",
            resource_type="oauth_application",
            resource_id=str(app.id),
            user_id=user_id,
            metadata={
                "application_name": name,
                "application_type": application_type,
                "allowed_scopes": allowed_scopes,
            },
        )

        logger.info(
            "OAuth application created",
            application_id=str(app.id),
            application_name=name,
            owner_id=user_id,
        )

        return app, client_secret

    async def get_application(self, client_id: str, include_secret: bool = False) -> Optional[OAuthApplication]:
        """Get OAuth application by client ID.

        Args:
            client_id: Client ID
            include_secret: Whether to include secret hash

        Returns:
            OAuth application if found
        """
        app = await self.app_repo.get_by_client_id(client_id)

        if app and not include_secret:
            # Clear sensitive data
            app.client_secret_hash = None

        return app

    async def validate_client(self, client_id: str, client_secret: Optional[str] = None) -> OAuthApplication:
        """Validate OAuth client credentials.

        Args:
            client_id: Client ID
            client_secret: Client secret (required for confidential clients)

        Returns:
            Validated OAuth application

        Raises:
            AuthenticationError: If validation fails
        """
        app = await self.get_application(client_id, include_secret=True)
        if not app:
            raise AuthenticationError("Invalid client credentials")

        if not app.is_active:
            raise AuthenticationError("Client is not active")

        # Verify secret for confidential clients
        if app.is_confidential:
            if not client_secret:
                raise AuthenticationError("Client secret required")

            if not verify_password(client_secret, app.client_secret_hash):
                raise AuthenticationError("Invalid client credentials")

        return app

    async def create_authorization_code(
        self,
        application_id: str,
        user_id: str,
        redirect_uri: str,
        scopes: List[str],
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> str:
        """Create authorization code.

        Args:
            application_id: OAuth application ID
            user_id: User granting authorization
            redirect_uri: Redirect URI for this request
            scopes: Granted scopes
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method (S256 or plain)
            nonce: OpenID Connect nonce
            request: FastAPI request

        Returns:
            Authorization code
        """
        # Generate code
        code = self._generate_authorization_code()
        code_hash = hash_token(code)

        # Set expiration
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.AUTHORIZATION_CODE_EXPIRE_MINUTES)

        # Extract request metadata
        ip_address = None
        user_agent = None
        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("User-Agent")

        # Create authorization code record
        auth_code_data = {
            "code_hash": code_hash,
            "redirect_uri": redirect_uri,
            "scopes": json.dumps(scopes),
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": expires_at,
            "application_id": application_id,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "nonce": nonce,
        }

        _ = await self.auth_code_repo.create(auth_code_data)

        # Log the authorization
        await self.audit_service.log_auth_event(
            event_type="oauth_authorization_granted",
            user_id=user_id,
            request=request,
            metadata={
                "application_id": application_id,
                "scopes": scopes,
                "redirect_uri": redirect_uri,
            },
        )

        logger.info(
            "Authorization code created",
            user_id=user_id,
            application_id=application_id,
            scopes=scopes,
        )

        return code

    async def exchange_authorization_code(
        self,
        code: str,
        client_id: str,
        client_secret: Optional[str],
        redirect_uri: str,
        code_verifier: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> Tuple[str, str, int]:
        """Exchange authorization code for tokens.

        Args:
            code: Authorization code
            client_id: Client ID
            client_secret: Client secret
            redirect_uri: Redirect URI (must match)
            code_verifier: PKCE code verifier
            request: FastAPI request

        Returns:
            Tuple of (access_token, refresh_token, expires_in)

        Raises:
            ValidationError: If code exchange fails
        """
        # Validate client
        app = await self.validate_client(client_id, client_secret)

        # Find authorization code
        code_hash = hash_token(code)
        auth_code = await self.auth_code_repo.get_by_code_hash(code_hash)

        if not auth_code:
            raise ValidationError("Invalid authorization code")

        # Validate code
        if auth_code.is_used:
            # Code replay attack - revoke all tokens
            await self._handle_code_replay(auth_code, request)
            raise ValidationError("Authorization code already used")

        if auth_code.is_expired:
            raise ValidationError("Authorization code expired")

        if auth_code.application_id != app.id:
            raise ValidationError("Authorization code does not belong to client")

        if auth_code.redirect_uri != redirect_uri:
            raise ValidationError("Redirect URI mismatch")

        # Validate PKCE if used
        if auth_code.code_challenge:
            if not code_verifier:
                raise ValidationError("Code verifier required")

            if not self._verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                raise ValidationError("Invalid code verifier")

        # Mark code as used
        await self.auth_code_repo.update(auth_code.id, is_used=True, used_at=datetime.now(timezone.utc))

        # Create tokens
        scopes = json.loads(auth_code.scopes)
        access_token, refresh_token = await self._create_tokens(app, auth_code.user_id, scopes, request)

        # Log the exchange
        await self.audit_service.log_auth_event(
            event_type="oauth_tokens_issued",
            user_id=str(auth_code.user_id),
            request=request,
            metadata={
                "application_id": str(app.id),
                "grant_type": "authorization_code",
                "scopes": scopes,
            },
        )

        return (
            access_token,
            refresh_token,
            self.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # expires_in seconds
        )

    async def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str],
        scopes: Optional[List[str]] = None,
        request: Optional[Request] = None,
    ) -> Tuple[str, str, int]:
        """Refresh access token using refresh token.

        Args:
            refresh_token: Refresh token
            client_id: Client ID
            client_secret: Client secret
            scopes: Requested scopes (must be subset of original)
            request: FastAPI request

        Returns:
            Tuple of (access_token, new_refresh_token, expires_in)

        Raises:
            ValidationError: If refresh fails
        """
        # Validate client
        app = await self.validate_client(client_id, client_secret)

        # Find refresh token
        token_hash = hash_token(refresh_token)
        refresh_token_obj = await self.refresh_token_repo.get_by_token_hash(token_hash)

        if not refresh_token_obj:
            raise ValidationError("Invalid refresh token")

        # Validate refresh token
        if not refresh_token_obj.is_valid:
            raise ValidationError("Refresh token is not valid")

        if refresh_token_obj.application_id != app.id:
            raise ValidationError("Refresh token does not belong to client")

        # Validate requested scopes
        original_scopes = json.loads(refresh_token_obj.scopes)
        if scopes:
            if not set(scopes).issubset(set(original_scopes)):
                raise ValidationError("Requested scopes exceed original grant")
        else:
            scopes = original_scopes

        # Update refresh token usage
        current_use_count = getattr(refresh_token_obj, "use_count", 0)
        await self.refresh_token_repo.update(
            refresh_token_obj.id, use_count=current_use_count + 1, last_used_at=datetime.now(timezone.utc)
        )

        # Create new tokens
        access_token, new_refresh_token = await self._create_tokens(
            app, refresh_token_obj.user_id, scopes, request, refresh_token_obj.id
        )

        # Log the refresh
        await self.audit_service.log_auth_event(
            event_type="oauth_tokens_refreshed",
            user_id=str(refresh_token_obj.user_id),
            request=request,
            metadata={
                "application_id": str(app.id),
                "grant_type": "refresh_token",
                "scopes": scopes,
            },
        )

        return (
            access_token,
            new_refresh_token,
            self.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def validate_access_token(self, token: str) -> Tuple[OAuthAccessToken, User, OAuthApplication]:
        """Validate access token and return associated objects.

        Args:
            token: Access token

        Returns:
            Tuple of (access_token, user, application)

        Raises:
            AuthenticationError: If token is invalid
        """
        token_hash = hash_token(token)

        # Get token with user and application
        row = await self.access_token_repo.get_with_user_and_app(token_hash)

        if not row:
            raise AuthenticationError("Invalid access token")

        access_token, user, application = row

        if not access_token.is_valid:
            raise AuthenticationError("Access token is not valid")

        if not user.is_active:
            raise AuthenticationError("User account is not active")

        if not application.is_active:
            raise AuthenticationError("OAuth application is not active")

        return access_token, user, application

    async def revoke_token(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> bool:
        """Revoke a token.

        Args:
            token: Token to revoke
            token_type_hint: Hint about token type (access_token or refresh_token)
            client_id: Client ID (for validation)
            client_secret: Client secret (for validation)

        Returns:
            True if token was revoked
        """
        token_hash = hash_token(token)
        revoked = False

        # Try access token first (unless hint says otherwise)
        if token_type_hint != REFRESH_TOKEN_TYPE_HINT:
            access_token = await self.access_token_repo.get_by_token_hash(token_hash)

            if access_token:
                # Validate client if provided
                if client_id:
                    app = await self.get_application(client_id)
                    if app and access_token.application_id != app.id:
                        return False

                await self.access_token_repo.update(
                    access_token.id, is_revoked=True, revoked_at=datetime.now(timezone.utc)
                )
                revoked = True

                await self.audit_service.log_auth_event(
                    event_type="oauth_access_token_revoked",
                    user_id=str(access_token.user_id),
                    metadata={
                        "token_id": str(access_token.id),
                        "application_id": str(access_token.application_id),
                    },
                )

        # Try refresh token if not found or hint specified
        if not revoked and token_type_hint != ACCESS_TOKEN_TYPE_HINT:
            refresh_token = await self.refresh_token_repo.get_by_token_hash(token_hash)

            if refresh_token:
                # Validate client if provided
                if client_id:
                    app = await self.get_application(client_id)
                    if app and refresh_token.application_id != app.id:
                        return False

                await self.refresh_token_repo.update(
                    refresh_token.id, is_revoked=True, revoked_at=datetime.now(timezone.utc)
                )
                revoked = True

                # Also revoke associated access tokens
                await self.access_token_repo.revoke_by_refresh_token(refresh_token.id)

                await self.audit_service.log_auth_event(
                    event_type="oauth_refresh_token_revoked",
                    user_id=str(refresh_token.user_id),
                    metadata={
                        "token_id": str(refresh_token.id),
                        "application_id": str(refresh_token.application_id),
                    },
                )

        return revoked

    async def list_user_authorizations(self, user_id: str) -> List[Dict[str, Any]]:
        """List all OAuth authorizations for a user.

        Args:
            user_id: User ID

        Returns:
            List of authorized applications with details
        """
        # Get all active authorizations for user
        authorizations_data = await self.refresh_token_repo.get_user_authorizations(user_id)
        authorizations = []

        for app, token in authorizations_data:
            scopes = json.loads(token.scopes)
            authorizations.append(
                {
                    "application": {
                        "id": str(app.id),
                        "name": app.name,
                        "description": app.description,
                        "logo_url": app.logo_url,
                        "homepage_url": app.homepage_url,
                    },
                    "scopes": scopes,
                    "authorized_at": token.created_at,
                    "last_used_at": token.last_used_at,
                }
            )

        return authorizations

    async def revoke_user_authorization(self, user_id: str, application_id: str) -> bool:
        """Revoke all tokens for a user-application pair.

        Args:
            user_id: User ID
            application_id: Application ID

        Returns:
            True if tokens were revoked
        """
        # Revoke all refresh tokens
        refresh_revoked_count = await self.refresh_token_repo.revoke_user_app_tokens(user_id, application_id)

        # Revoke all access tokens
        access_revoked_count = await self.access_token_repo.revoke_user_app_tokens(user_id, application_id)

        revoked_count = refresh_revoked_count + access_revoked_count

        if revoked_count > 0:
            await self.audit_service.log_auth_event(
                event_type="oauth_authorization_revoked",
                user_id=user_id,
                metadata={
                    "application_id": application_id,
                    "tokens_revoked": revoked_count,
                },
            )

        return revoked_count > 0

    # Private helper methods

    def _validate_application_inputs(
        self,
        name: str,
        redirect_uris: List[str],
        allowed_scopes: List[str],
        application_type: str,
    ) -> None:
        """Validate application inputs."""
        if not name or len(name) < 3:
            raise ValidationError("Application name must be at least 3 characters")

        if not redirect_uris:
            raise ValidationError("At least one redirect URI is required")

        # Validate redirect URIs
        for uri in redirect_uris:
            parsed = urlparse(uri)

            # Check for localhost in production
            if settings.is_production and parsed.hostname in ["localhost", "127.0.0.1"]:
                raise ValidationError("Localhost redirect URIs not allowed in production")

            # Require HTTPS in production (except localhost)
            if settings.is_production and parsed.scheme != "https":
                raise ValidationError("HTTPS required for redirect URIs in production")

        if not allowed_scopes:
            raise ValidationError("At least one scope must be allowed")

        if application_type not in ["web", "mobile", "spa"]:
            raise ValidationError("Invalid application type")

    def _generate_client_id(self) -> str:
        """Generate unique client ID."""
        return f"client_{secrets.token_urlsafe(24)}"

    def _generate_client_secret(self) -> str:
        """Generate secure client secret."""
        return secrets.token_urlsafe(self.MIN_CLIENT_SECRET_LENGTH)

    def _generate_authorization_code(self) -> str:
        """Generate authorization code."""
        return secrets.token_urlsafe(32)

    def _get_grant_types_for_app_type(self, app_type: str, is_confidential: bool) -> List[str]:
        """Get allowed grant types for application type."""
        if app_type == "spa":
            # SPAs can only use authorization code with PKCE
            return ["authorization_code"]
        elif app_type == "mobile":
            # Mobile apps use authorization code with PKCE
            return ["authorization_code", "refresh_token"]
        else:  # web
            if is_confidential:
                # Confidential web apps can use all grant types
                return ["authorization_code", "refresh_token", "client_credentials"]
            else:
                # Public web apps can't use client credentials
                return ["authorization_code", "refresh_token"]

    def _get_response_types_for_app_type(self, app_type: str) -> List[str]:
        """Get allowed response types for application type."""
        # All app types support authorization code flow
        return ["code"]

    def _verify_pkce(self, verifier: str, challenge: str, method: Optional[str]) -> bool:
        """Verify PKCE code challenge."""
        if method == "S256":
            # SHA256 hash of verifier should match challenge
            import base64

            verifier_hash = hashlib.sha256(verifier.encode()).digest()
            verifier_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")
            return verifier_challenge == challenge
        elif method == "plain" or method is None:
            # Plain text comparison
            return verifier == challenge
        else:
            return False

    async def _create_tokens(
        self,
        app: OAuthApplication,
        user_id: str,
        scopes: List[str],
        request: Optional[Request],
        refresh_token_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Create access and refresh tokens."""
        # Generate tokens
        access_token = create_token(
            data={
                "sub": str(user_id),
                "client_id": app.client_id,
                "scopes": scopes,
                "token_type": "access",
            },
            expires_delta=timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        refresh_token = create_token(
            data={
                "sub": str(user_id),
                "client_id": app.client_id,
                "scopes": scopes,
                "token_type": "refresh",
            },
            expires_delta=timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS),
        )

        # Hash tokens for storage
        access_token_hash = hash_token(access_token)
        refresh_token_hash = hash_token(refresh_token)

        # Extract request metadata
        ip_address = None
        user_agent = None
        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("User-Agent")

        # Create refresh token record first
        refresh_token_data = {
            "token_hash": refresh_token_hash,
            "scopes": json.dumps(scopes),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS),
            "application_id": app.id,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
        }
        refresh_token_obj = await self.refresh_token_repo.create(refresh_token_data)

        # Create access token record
        access_token_data = {
            "token_hash": access_token_hash,
            "scopes": json.dumps(scopes),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES),
            "application_id": app.id,
            "user_id": user_id,
            "refresh_token_id": refresh_token_obj.id,
            "ip_address": ip_address,
            "user_agent": user_agent,
        }
        _ = await self.access_token_repo.create(access_token_data)

        return access_token, refresh_token

    async def _handle_code_replay(self, auth_code: OAuthAuthorizationCode, request: Optional[Request]) -> None:
        """Handle authorization code replay attack."""
        # Revoke all tokens associated with this authorization
        logger.warning(
            "Authorization code replay detected",
            code_id=str(auth_code.id),
            application_id=str(auth_code.application_id),
            user_id=str(auth_code.user_id),
        )

        # Find and revoke all tokens for this user-app combination
        await self.revoke_user_authorization(str(auth_code.user_id), str(auth_code.application_id))

        # Log security event
        await self.audit_service.log_security_event(
            event_type="oauth_code_replay",
            user_id=str(auth_code.user_id),
            request=request,
            risk_level="high",
            details={
                "application_id": str(auth_code.application_id),
                "code_id": str(auth_code.id),
                "original_use_time": auth_code.used_at.isoformat() if auth_code.used_at else None,
            },
        )
