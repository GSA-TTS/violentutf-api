"""OAuth repository interface."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.oauth import OAuthAccessToken, OAuthApplication, OAuthAuthorizationCode, OAuthRefreshToken

from .base import IBaseRepository


class IOAuthRepository(IBaseRepository[OAuthApplication]):
    """Interface for OAuth repository operations."""

    @abstractmethod
    async def get_application_by_client_id(
        self, client_id: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[OAuthApplication]:
        """
        Get OAuth application by client ID.

        Args:
            client_id: OAuth client ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            OAuth application if found, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_applications(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> List[OAuthApplication]:
        """
        Get OAuth applications owned by a user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            List of user's OAuth applications
        """
        raise NotImplementedError

    @abstractmethod
    async def create_authorization_code(
        self,
        application_id: Union[str, uuid.UUID],
        user_id: Union[str, uuid.UUID],
        code: str,
        redirect_uri: str,
        scope: str,
        expires_at: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> OAuthAuthorizationCode:
        """
        Create OAuth authorization code.

        Args:
            application_id: OAuth application ID
            user_id: User ID
            code: Authorization code
            redirect_uri: Redirect URI
            scope: Granted scope
            expires_at: Code expiration time
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Created authorization code
        """
        raise NotImplementedError

    @abstractmethod
    async def get_authorization_code(
        self, code: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[OAuthAuthorizationCode]:
        """
        Get OAuth authorization code.

        Args:
            code: Authorization code
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Authorization code if found and not expired, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def consume_authorization_code(
        self, code: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Mark authorization code as consumed.

        Args:
            code: Authorization code
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if code consumed successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def create_access_token(
        self,
        application_id: Union[str, uuid.UUID],
        user_id: Union[str, uuid.UUID],
        token: str,
        scope: str,
        expires_at: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> OAuthAccessToken:
        """
        Create OAuth access token.

        Args:
            application_id: OAuth application ID
            user_id: User ID
            token: Access token
            scope: Granted scope
            expires_at: Token expiration time
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Created access token
        """
        raise NotImplementedError

    @abstractmethod
    async def get_access_token(
        self, token: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[OAuthAccessToken]:
        """
        Get OAuth access token.

        Args:
            token: Access token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Access token if found and not expired, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_access_token(self, token: str, organization_id: Optional[Union[str, uuid.UUID]] = None) -> bool:
        """
        Revoke OAuth access token.

        Args:
            token: Access token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if token revoked successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def create_refresh_token(
        self,
        application_id: Union[str, uuid.UUID],
        user_id: Union[str, uuid.UUID],
        token: str,
        access_token_id: Union[str, uuid.UUID],
        expires_at: datetime,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> OAuthRefreshToken:
        """
        Create OAuth refresh token.

        Args:
            application_id: OAuth application ID
            user_id: User ID
            token: Refresh token
            access_token_id: Associated access token ID
            expires_at: Token expiration time
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Created refresh token
        """
        raise NotImplementedError

    @abstractmethod
    async def get_refresh_token(
        self, token: str, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> Optional[OAuthRefreshToken]:
        """
        Get OAuth refresh token.

        Args:
            token: Refresh token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Refresh token if found and not expired, None otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_refresh_token(self, token: str, organization_id: Optional[Union[str, uuid.UUID]] = None) -> bool:
        """
        Revoke OAuth refresh token.

        Args:
            token: Refresh token
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if token revoked successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_tokens(
        self,
        user_id: Union[str, uuid.UUID],
        application_id: Optional[Union[str, uuid.UUID]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> Dict[str, List[Any]]:
        """
        Get all tokens for a user.

        Args:
            user_id: User ID
            application_id: Optional application ID filter
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Dictionary containing access and refresh tokens
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_all_user_tokens(
        self,
        user_id: Union[str, uuid.UUID],
        application_id: Optional[Union[str, uuid.UUID]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> int:
        """
        Revoke all tokens for a user.

        Args:
            user_id: User ID
            application_id: Optional application ID filter
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of tokens revoked
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_expired_tokens(self, organization_id: Optional[Union[str, uuid.UUID]] = None) -> int:
        """
        Clean up expired OAuth tokens.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of tokens cleaned up
        """
        raise NotImplementedError

    @abstractmethod
    async def get_oauth_statistics(
        self,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get OAuth usage statistics.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dictionary containing OAuth statistics
        """
        raise NotImplementedError
