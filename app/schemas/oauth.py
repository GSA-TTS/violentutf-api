"""OAuth2 schemas for request/response validation."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class OAuthApplicationCreate(BaseModel):
    """Schema for creating OAuth application."""

    name: str = Field(..., min_length=3, max_length=255, description="Application name")
    description: Optional[str] = Field(None, max_length=1000, description="Application description")
    redirect_uris: List[str] = Field(..., description="Allowed redirect URIs")
    allowed_scopes: List[str] = Field(..., description="Allowed OAuth scopes")
    application_type: str = Field("web", description="Application type (web, mobile, spa)")
    is_confidential: bool = Field(True, description="Whether app can keep secrets")
    logo_url: Optional[HttpUrl] = Field(None, description="Application logo URL")
    homepage_url: Optional[HttpUrl] = Field(None, description="Application homepage URL")
    privacy_policy_url: Optional[HttpUrl] = Field(None, description="Privacy policy URL")
    terms_of_service_url: Optional[HttpUrl] = Field(None, description="Terms of service URL")

    @field_validator("application_type")
    @classmethod
    def validate_application_type(cls, v: str) -> str:
        """Validate application type."""
        if v not in ["web", "mobile", "spa"]:
            raise ValueError("Invalid application type")
        return v

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v: List[str]) -> List[str]:
        """Validate redirect URIs list with proper URL parsing."""
        if not v or len(v) == 0:
            raise ValueError("At least one redirect URI is required")

        # Validate each URI with proper URL parsing
        for uri in v:
            if not uri:
                raise ValueError("Empty redirect URI not allowed")

            try:
                parsed = urlparse(uri)

                # Must have a valid scheme
                if not parsed.scheme:
                    raise ValueError(f"Invalid redirect URI - missing scheme: {uri}")

                # Must have a valid netloc (domain)
                if not parsed.netloc:
                    raise ValueError(f"Invalid redirect URI - missing domain: {uri}")

                # Only allow http/https schemes
                if parsed.scheme not in ["http", "https"]:
                    raise ValueError(f"Invalid redirect URI - only http/https allowed: {uri}")

                # Validate domain is not suspicious
                if parsed.netloc.count(".") == 0 and parsed.netloc not in ["localhost"]:
                    raise ValueError(f"Invalid redirect URI - suspicious domain: {uri}")

            except Exception as e:
                raise ValueError(f"Invalid redirect URI format: {uri} - {str(e)}")

        return v

    @field_validator("allowed_scopes")
    @classmethod
    def validate_allowed_scopes(cls, v: List[str]) -> List[str]:
        """Validate allowed scopes list."""
        if not v or len(v) == 0:
            raise ValueError("At least one scope is required")
        return v


class OAuthApplicationUpdate(BaseModel):
    """Schema for updating OAuth application."""

    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    redirect_uris: Optional[List[str]] = Field(None)
    allowed_scopes: Optional[List[str]] = Field(None)
    is_active: Optional[bool] = Field(None)
    logo_url: Optional[HttpUrl] = Field(None)
    homepage_url: Optional[HttpUrl] = Field(None)
    privacy_policy_url: Optional[HttpUrl] = Field(None)
    terms_of_service_url: Optional[HttpUrl] = Field(None)


class OAuthApplicationResponse(BaseModel):
    """Schema for OAuth application response."""

    id: str
    name: str
    description: Optional[str]
    client_id: str
    client_secret: Optional[str] = None  # Only shown on creation
    redirect_uris: List[str]
    allowed_scopes: List[str]
    grant_types: List[str]
    response_types: List[str]
    application_type: str
    is_confidential: bool
    is_active: bool
    is_trusted: bool
    owner_id: str
    logo_url: Optional[str]
    homepage_url: Optional[str]
    privacy_policy_url: Optional[str]
    terms_of_service_url: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
        },
    )

    @classmethod
    def from_orm(cls, obj: Any) -> "OAuthApplicationResponse":
        """Create from ORM object."""
        import json

        return cls(
            id=str(obj.id),
            name=obj.name,
            description=obj.description,
            client_id=obj.client_id,
            redirect_uris=json.loads(obj.redirect_uris),
            allowed_scopes=json.loads(obj.allowed_scopes),
            grant_types=json.loads(obj.grant_types),
            response_types=json.loads(obj.response_types),
            application_type=obj.application_type,
            is_confidential=obj.is_confidential,
            is_active=obj.is_active,
            is_trusted=obj.is_trusted,
            owner_id=str(obj.owner_id),
            logo_url=obj.logo_url,
            homepage_url=obj.homepage_url,
            privacy_policy_url=obj.privacy_policy_url,
            terms_of_service_url=obj.terms_of_service_url,
            created_at=obj.created_at,
            updated_at=obj.updated_at,
        )


class OAuthAuthorizeRequest(BaseModel):
    """Schema for OAuth authorization request."""

    response_type: str = Field(..., description="Response type (code)")
    client_id: str = Field(..., description="Client ID")
    redirect_uri: str = Field(..., description="Redirect URI")
    scope: str = Field(..., description="Requested scopes (space-separated)")
    state: Optional[str] = Field(None, description="State parameter")
    code_challenge: Optional[str] = Field(None, description="PKCE code challenge")
    code_challenge_method: Optional[str] = Field(None, description="PKCE method (S256 or plain)")
    nonce: Optional[str] = Field(None, description="OpenID Connect nonce")

    @field_validator("response_type")
    @classmethod
    def validate_response_type(cls, v: str) -> str:
        """Validate response type."""
        if v not in ["code", "token"]:
            raise ValueError("Invalid response type")
        return v

    @field_validator("code_challenge_method")
    @classmethod
    def validate_code_challenge_method(cls, v: Optional[str]) -> Optional[str]:
        """Validate PKCE method."""
        if v and v not in ["S256", "plain"]:
            raise ValueError("Invalid code challenge method")
        return v


class OAuthTokenRequest(BaseModel):
    """Schema for OAuth token request."""

    grant_type: str = Field(..., description="Grant type")
    code: Optional[str] = Field(None, description="Authorization code")
    redirect_uri: Optional[str] = Field(None, description="Redirect URI")
    client_id: str = Field(..., description="Client ID")
    client_secret: Optional[str] = Field(None, description="Client secret")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    scope: Optional[str] = Field(None, description="Requested scopes")
    code_verifier: Optional[str] = Field(None, description="PKCE code verifier")

    @field_validator("grant_type")
    @classmethod
    def validate_grant_type(cls, v: str) -> str:
        """Validate grant type."""
        if v not in ["authorization_code", "refresh_token", "client_credentials"]:
            raise ValueError("Invalid grant type")
        return v


class OAuthTokenResponse(BaseModel):
    """Schema for OAuth token response."""

    access_token: str = Field(..., description="Access token")
    token_type: str = Field("Bearer", description="Token type")
    expires_in: int = Field(..., description="Token lifetime in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    scope: Optional[str] = Field(None, description="Granted scopes")


class OAuthTokenRevoke(BaseModel):
    """Schema for token revocation request."""

    token: str = Field(..., description="Token to revoke")
    token_type_hint: Optional[str] = Field(None, description="Token type hint")
    client_id: Optional[str] = Field(None, description="Client ID")
    client_secret: Optional[str] = Field(None, description="Client secret")

    @field_validator("token_type_hint")
    @classmethod
    def validate_token_type_hint(cls, v: Optional[str]) -> Optional[str]:
        """Validate token type hint."""
        if v and v not in ["access_token", "refresh_token"]:
            raise ValueError("Invalid token type hint")
        return v


class OAuthScopeResponse(BaseModel):
    """Schema for OAuth scope response."""

    name: str
    display_name: str
    description: str
    category: str
    is_default: bool
    requires_approval: bool
    is_dangerous: bool
    is_active: bool


class UserAuthorizationResponse(BaseModel):
    """Schema for user's OAuth authorization."""

    application: Dict[str, Any] = Field(..., description="Application details")
    scopes: List[str] = Field(..., description="Granted scopes")
    authorized_at: datetime = Field(..., description="Authorization timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat(),
        }
    )
