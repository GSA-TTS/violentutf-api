"""OAuth2 models for third-party application access."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.models.mixins import AuditMixin, SoftDeleteMixin, VersionedMixin


class OAuthApplication(Base, AuditMixin, SoftDeleteMixin, VersionedMixin):
    """Model for OAuth2 applications."""

    __tablename__ = "oauth_applications"

    # Application details
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    client_id = Column(String(255), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(255), nullable=False)

    # Application settings
    redirect_uris = Column(Text, nullable=False)  # JSON array of allowed redirect URIs
    allowed_scopes = Column(Text, nullable=False)  # JSON array of allowed scopes
    grant_types = Column(Text, nullable=False)  # JSON array of allowed grant types
    response_types = Column(Text, nullable=False)  # JSON array of allowed response types

    # Application type and status
    application_type = Column(String(50), nullable=False, default="web")  # web, mobile, spa
    is_confidential = Column(Boolean, default=True)  # Can keep secrets
    is_active = Column(Boolean, default=True)
    is_trusted = Column(Boolean, default=False)  # Skip user consent

    # Owner relationship
    owner_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    owner = relationship("User", back_populates="oauth_applications")

    # Tokens relationship
    access_tokens = relationship("OAuthAccessToken", back_populates="application", cascade="all, delete-orphan")
    refresh_tokens = relationship("OAuthRefreshToken", back_populates="application", cascade="all, delete-orphan")
    authorization_codes = relationship(
        "OAuthAuthorizationCode",
        back_populates="application",
        cascade="all, delete-orphan",
    )

    # Metadata
    logo_url = Column(String(500), nullable=True)
    homepage_url = Column(String(500), nullable=True)
    privacy_policy_url = Column(String(500), nullable=True)
    terms_of_service_url = Column(String(500), nullable=True)

    def __repr__(self) -> str:
        """String representation."""
        return f"<OAuthApplication(name={self.name}, client_id={self.client_id})>"


class OAuthAccessToken(Base, AuditMixin):
    """Model for OAuth2 access tokens."""

    __tablename__ = "oauth_access_tokens"

    # Token details
    token_hash = Column(String(255), unique=True, nullable=False, index=True)
    token_type = Column(String(50), nullable=False, default="Bearer")
    scopes = Column(Text, nullable=False)  # JSON array of granted scopes

    # Expiration
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)

    # Relationships
    application_id = Column(UUID(as_uuid=True), ForeignKey("oauth_applications.id"), nullable=False)
    application = relationship("OAuthApplication", back_populates="access_tokens")

    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="oauth_access_tokens")

    # Associated refresh token
    refresh_token_id = Column(UUID(as_uuid=True), ForeignKey("oauth_refresh_tokens.id"), nullable=True)
    refresh_token = relationship("OAuthRefreshToken", back_populates="access_tokens")

    # Additional metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        """String representation."""
        return f"<OAuthAccessToken(id={self.id}, expires_at={self.expires_at})>"


class OAuthRefreshToken(Base, AuditMixin):
    """Model for OAuth2 refresh tokens."""

    __tablename__ = "oauth_refresh_tokens"

    # Token details
    token_hash = Column(String(255), unique=True, nullable=False, index=True)
    scopes = Column(Text, nullable=False)  # JSON array of granted scopes

    # Expiration
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)

    # Relationships
    application_id = Column(UUID(as_uuid=True), ForeignKey("oauth_applications.id"), nullable=False)
    application = relationship("OAuthApplication", back_populates="refresh_tokens")

    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="oauth_refresh_tokens")

    # Associated access tokens
    access_tokens = relationship("OAuthAccessToken", back_populates="refresh_token")

    # Usage tracking
    use_count = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)

    # Additional metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        """String representation."""
        return f"<OAuthRefreshToken(id={self.id}, expires_at={self.expires_at})>"


class OAuthAuthorizationCode(Base, AuditMixin):
    """Model for OAuth2 authorization codes."""

    __tablename__ = "oauth_authorization_codes"

    # Code details
    code_hash = Column(String(255), unique=True, nullable=False, index=True)
    redirect_uri = Column(String(500), nullable=False)
    scopes = Column(Text, nullable=False)  # JSON array of requested scopes

    # PKCE support
    code_challenge = Column(String(255), nullable=True)
    code_challenge_method = Column(String(50), nullable=True)  # S256 or plain

    # Expiration (codes expire quickly)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)

    # Relationships
    application_id = Column(UUID(as_uuid=True), ForeignKey("oauth_applications.id"), nullable=False)
    application = relationship("OAuthApplication", back_populates="authorization_codes")

    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="oauth_authorization_codes")

    # Additional metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    nonce = Column(String(255), nullable=True)  # For OpenID Connect

    @property
    def is_expired(self) -> bool:
        """Check if code is expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if code is valid."""
        return not self.is_used and not self.is_expired

    def __repr__(self) -> str:
        """String representation."""
        return f"<OAuthAuthorizationCode(id={self.id}, expires_at={self.expires_at})>"


class OAuthScope(Base, AuditMixin):
    """Model for OAuth2 scopes."""

    __tablename__ = "oauth_scopes"

    # Scope details
    name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    # Scope category
    category = Column(String(50), nullable=False)  # read, write, admin, etc.

    # Scope settings
    is_default = Column(Boolean, default=False)  # Granted by default
    requires_approval = Column(Boolean, default=True)  # Requires user consent
    is_dangerous = Column(Boolean, default=False)  # Extra warnings
    is_active = Column(Boolean, default=True)

    # Related permissions (for RBAC integration)
    required_permissions = Column(Text, nullable=True)  # JSON array of permissions

    def __repr__(self) -> str:
        """String representation."""
        return f"<OAuthScope(name={self.name}, category={self.category})>"
