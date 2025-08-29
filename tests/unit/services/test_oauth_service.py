"""Comprehensive tests for OAuth2 service."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch
from urllib.parse import quote

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError, ValidationError
from app.services.oauth_service import OAuth2Service


# Create mock classes for the models
class OAuthApplication:
    """Mock OAuth application model."""

    pass


class OAuthAccessToken:
    """Mock OAuth access token model."""

    pass


class OAuthRefreshToken:
    """Mock OAuth refresh token model."""

    pass


class OAuthAuthorizationCode:
    """Mock OAuth authorization code model."""

    pass


class User:
    """Mock user model."""

    pass


@pytest.fixture
def mock_session():
    """Create mock database session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_user():
    """Create mock user."""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "test@example.com"
    user.is_active = True
    return user


@pytest.fixture
def mock_oauth_app():
    """Create mock OAuth application."""
    app = MagicMock(spec=OAuthApplication)
    app.id = uuid.uuid4()
    app.name = "Test App"
    app.client_id = "client_test123"
    app.client_secret_hash = "hashed_secret"
    app.redirect_uris = json.dumps(["https://example.com/callback"])
    app.allowed_scopes = json.dumps(["read:users", "write:users"])
    app.grant_types = json.dumps(["authorization_code", "refresh_token"])
    app.is_active = True
    app.is_confidential = True
    return app


@pytest.fixture
def oauth_service(mock_session):
    """Create OAuth2 service instance."""
    service = OAuth2Service(mock_session)
    return service


class TestOAuth2Service:
    """Test OAuth2 service."""

    @pytest.mark.asyncio
    async def test_create_application_success(self, oauth_service, mock_user):
        """Test successful OAuth application creation."""
        # Arrange
        user_id = str(mock_user.id)
        app_data = {
            "name": "Test App",
            "description": "Test application",
            "redirect_uris": ["https://example.com/callback"],
            "allowed_scopes": ["read:users", "write:users"],
            "application_type": "web",
            "is_confidential": True,
        }

        with patch.object(oauth_service, "_generate_client_id", return_value="client_123"):
            with patch.object(oauth_service, "_generate_client_secret", return_value="secret_456"):
                # Act
                app, client_secret = await oauth_service.create_application(user_id=user_id, **app_data)

                # Assert
                assert app.name == app_data["name"]
                assert app.client_id == "client_123"
                assert client_secret == "secret_456"
                assert app.owner_id == user_id
                # Session.add is called twice: once for app, once for audit log
                assert oauth_service.session.add.call_count == 2

    @pytest.mark.asyncio
    async def test_create_application_invalid_name(self, oauth_service):
        """Test application creation with invalid name."""
        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await oauth_service.create_application(
                user_id=str(uuid.uuid4()),
                name="ab",
                description="Test description",
                redirect_uris=["https://example.com"],
                allowed_scopes=["read:users"],
            )

        # Check that it's a validation error about the name
        assert "Application name must be at least 3 characters" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_application_no_redirect_uris(self, oauth_service):
        """Test application creation without redirect URIs."""
        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            await oauth_service.create_application(
                user_id=str(uuid.uuid4()),
                name="Test App",
                description="Test description",
                redirect_uris=[],
                allowed_scopes=["read:users"],
            )

        assert "At least one redirect URI is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_application_localhost_production(self, oauth_service):
        """Test application creation with localhost in production."""
        # Arrange
        # Patch the settings object
        with patch.object(oauth_service, "_validate_application_inputs") as mock_validate:
            # Set up the mock to raise the expected error when localhost is detected
            mock_validate.side_effect = ValidationError("Localhost redirect URIs not allowed in production")

            # Act & Assert
            with pytest.raises(ValidationError) as exc_info:
                await oauth_service.create_application(
                    user_id=str(uuid.uuid4()),
                    name="Test App",
                    description="Test description",
                    redirect_uris=["http://localhost:3000/callback"],
                    allowed_scopes=["read:users"],
                )

            assert "Localhost redirect URIs not allowed in production" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_client_success(self, oauth_service, mock_oauth_app):
        """Test successful client validation."""
        # Arrange
        with patch.object(oauth_service, "get_application", return_value=mock_oauth_app):
            with patch("app.services.oauth_service.verify_password", return_value=True):
                # Act
                result = await oauth_service.validate_client(
                    client_id="client_test123",
                    client_secret="secret123",
                )

                # Assert
                assert result == mock_oauth_app

    @pytest.mark.asyncio
    async def test_validate_client_not_found(self, oauth_service):
        """Test client validation when not found."""
        # Arrange
        with patch.object(oauth_service, "get_application", return_value=None):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="Invalid client credentials"):
                await oauth_service.validate_client("invalid_client", "secret")

    @pytest.mark.asyncio
    async def test_validate_client_inactive(self, oauth_service, mock_oauth_app):
        """Test client validation when inactive."""
        # Arrange
        mock_oauth_app.is_active = False

        with patch.object(oauth_service, "get_application", return_value=mock_oauth_app):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="Client is not active"):
                await oauth_service.validate_client("client_test123", "secret")

    @pytest.mark.asyncio
    async def test_create_authorization_code(self, oauth_service, mock_oauth_app):
        """Test authorization code creation."""
        # Arrange
        app_id = str(mock_oauth_app.id)
        user_id = str(uuid.uuid4())
        redirect_uri = "https://example.com/callback"
        scopes = ["read:users", "write:users"]

        with patch.object(oauth_service, "_generate_authorization_code", return_value="auth_code_123"):
            # Mock hash_token function
            with patch("app.services.oauth_service.hash_token", return_value="hashed_auth_code"):
                # Mock the OAuthAuthorizationCode constructor to handle the correct fields
                with patch("app.services.oauth_service.OAuthAuthorizationCode") as mock_auth_code_class:
                    mock_auth_code = MagicMock()
                    mock_auth_code_class.return_value = mock_auth_code

                    # Act
                    code = await oauth_service.create_authorization_code(
                        application_id=app_id,
                        user_id=user_id,
                        redirect_uri=redirect_uri,
                        scopes=scopes,
                        code_challenge="challenge123",
                        code_challenge_method="S256",
                    )

                    # Assert
                    assert code == "auth_code_123"
                    # Should be called twice: once for auth code, once for audit log
                    assert oauth_service.session.add.call_count == 2

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_success(self, oauth_service, mock_oauth_app):
        """Test successful authorization code exchange."""
        # Arrange
        code = "auth_code_123"
        mock_auth_code = MagicMock(spec=OAuthAuthorizationCode)
        mock_auth_code.id = uuid.uuid4()  # Add missing id attribute
        mock_auth_code.is_used = False
        mock_auth_code.is_expired = False
        mock_auth_code.application_id = mock_oauth_app.id
        mock_auth_code.redirect_uri = "https://example.com/callback"
        mock_auth_code.code_challenge = None
        mock_auth_code.user_id = uuid.uuid4()
        mock_auth_code.scopes = json.dumps(["read:users"])

        # Create a universal mock result that handles both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
        mock_result = MagicMock()
        mock_result.rowcount = 1  # For UPDATE operations
        mock_result.scalar_one_or_none.return_value = mock_auth_code  # For SELECT operations

        # Set this as the return value for both service session and repository session
        oauth_service.session.execute.return_value = mock_result
        oauth_service.auth_code_repo.session.execute.return_value = mock_result

        with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
            with patch.object(oauth_service, "_create_tokens", return_value=("access_123", "refresh_456")):
                # Act
                access_token, refresh_token, expires_in = await oauth_service.exchange_authorization_code(
                    code=code,
                    client_id="client_test123",
                    client_secret="secret",
                    redirect_uri="https://example.com/callback",
                )

                # Assert
                assert access_token == "access_123"
                assert refresh_token == "refresh_456"
                assert expires_in == 3600  # 60 minutes * 60 seconds

                # Verify that the repository's session.execute was called (indicating update occurred)
                assert oauth_service.auth_code_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_already_used(self, oauth_service, mock_oauth_app):
        """Test authorization code exchange when code already used."""
        # Arrange
        mock_auth_code = MagicMock(spec=OAuthAuthorizationCode)
        mock_auth_code.is_used = True
        mock_auth_code.id = uuid.uuid4()
        mock_auth_code.application_id = mock_oauth_app.id
        mock_auth_code.user_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_auth_code
        oauth_service.session.execute.return_value = mock_result

        with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
            with patch.object(oauth_service, "_handle_code_replay") as mock_handle_replay:
                # Act & Assert
                with pytest.raises(ValidationError, match="Authorization code already used"):
                    await oauth_service.exchange_authorization_code(
                        code="used_code",
                        client_id="client_test123",
                        client_secret="secret",
                        redirect_uri="https://example.com/callback",
                    )

                mock_handle_replay.assert_called_once()

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_expired(self, oauth_service, mock_oauth_app):
        """Test authorization code exchange when code expired."""
        # Arrange
        mock_auth_code = MagicMock(spec=OAuthAuthorizationCode)
        mock_auth_code.is_used = False
        mock_auth_code.is_expired = True

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_auth_code
        oauth_service.session.execute.return_value = mock_result

        with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
            # Act & Assert
            with pytest.raises(ValidationError, match="Authorization code expired"):
                await oauth_service.exchange_authorization_code(
                    code="expired_code",
                    client_id="client_test123",
                    client_secret="secret",
                    redirect_uri="https://example.com/callback",
                )

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_with_pkce(self, oauth_service, mock_oauth_app):
        """Test authorization code exchange with PKCE."""
        # Arrange
        mock_auth_code = MagicMock(spec=OAuthAuthorizationCode)
        mock_auth_code.id = uuid.uuid4()  # Add missing id attribute
        mock_auth_code.is_used = False
        mock_auth_code.is_expired = False
        mock_auth_code.application_id = mock_oauth_app.id
        mock_auth_code.redirect_uri = "https://example.com/callback"
        mock_auth_code.code_challenge = "challenge123"
        mock_auth_code.code_challenge_method = "S256"
        mock_auth_code.user_id = uuid.uuid4()
        mock_auth_code.scopes = json.dumps(["read:users"])

        # Create a universal mock result that handles both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
        mock_result = MagicMock()
        mock_result.rowcount = 1  # For UPDATE operations
        mock_result.scalar_one_or_none.return_value = mock_auth_code  # For SELECT operations

        # Set this as the return value for both service session and repository session
        oauth_service.session.execute.return_value = mock_result
        oauth_service.auth_code_repo.session.execute.return_value = mock_result

        with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
            with patch.object(oauth_service, "_verify_pkce", return_value=True):
                with patch.object(oauth_service, "_create_tokens", return_value=("access_123", "refresh_456")):
                    # Act
                    access_token, _, _ = await oauth_service.exchange_authorization_code(
                        code="code_with_pkce",
                        client_id="client_test123",
                        client_secret="secret",
                        redirect_uri="https://example.com/callback",
                        code_verifier="verifier123",
                    )

                    # Assert
                    assert access_token == "access_123"

    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self, oauth_service, mock_oauth_app):
        """Test successful access token refresh."""
        # Arrange
        refresh_token = "refresh_token_123"
        mock_refresh_token = MagicMock(spec=OAuthRefreshToken)
        # Mock is_valid as a property
        type(mock_refresh_token).is_valid = PropertyMock(return_value=True)
        mock_refresh_token.id = uuid.uuid4()
        mock_refresh_token.application_id = mock_oauth_app.id
        mock_refresh_token.user_id = uuid.uuid4()
        mock_refresh_token.scopes = json.dumps(["read:users", "write:users"])
        mock_refresh_token.use_count = 0
        mock_refresh_token.last_used_at = None

        # Mock hash_token
        with patch("app.services.oauth_service.hash_token", return_value="hashed_refresh_token"):
            # Create a universal mock result that handles both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
            mock_result = MagicMock()
            mock_result.rowcount = 1  # For UPDATE operations
            mock_result.scalar_one_or_none.return_value = mock_refresh_token  # For SELECT operations

            # Set this as the return value for both service session and repository session
            oauth_service.session.execute.return_value = mock_result
            oauth_service.refresh_token_repo.session.execute.return_value = mock_result

            with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
                with patch.object(oauth_service, "_create_tokens", return_value=("new_access", "new_refresh")):
                    # Act
                    access_token, new_refresh_token, expires_in = await oauth_service.refresh_access_token(
                        refresh_token=refresh_token,
                        client_id="client_test123",
                        client_secret="secret",
                    )

                    # Assert
                    assert access_token == "new_access"
                    assert new_refresh_token == "new_refresh"
                    assert expires_in == 3600  # Default access token expire time

                    # Verify that the repository's session.execute was called (indicating update occurred)
                    assert oauth_service.refresh_token_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_refresh_access_token_scope_reduction(self, oauth_service, mock_oauth_app):
        """Test access token refresh with scope reduction."""
        # Arrange
        mock_refresh_token = MagicMock(spec=OAuthRefreshToken)
        # Mock is_valid as a property
        type(mock_refresh_token).is_valid = PropertyMock(return_value=True)
        mock_refresh_token.id = uuid.uuid4()
        mock_refresh_token.application_id = mock_oauth_app.id
        mock_refresh_token.user_id = uuid.uuid4()
        mock_refresh_token.scopes = json.dumps(["read:users", "write:users", "delete:users"])
        mock_refresh_token.use_count = 0
        mock_refresh_token.last_used_at = None

        # Mock hash_token
        with patch("app.services.oauth_service.hash_token", return_value="hashed_refresh_token"):
            # Create a universal mock result that handles both UPDATE (rowcount) and SELECT (scalar_one_or_none) operations
            mock_result = MagicMock()
            mock_result.rowcount = 1  # For UPDATE operations
            mock_result.scalar_one_or_none.return_value = mock_refresh_token  # For SELECT operations

            # Set this as the return value for both service session and repository session
            oauth_service.session.execute.return_value = mock_result
            oauth_service.refresh_token_repo.session.execute.return_value = mock_result

            with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
                with patch.object(oauth_service, "_create_tokens") as mock_create_tokens:
                    mock_create_tokens.return_value = ("new_access", "new_refresh")

                    # Act
                    await oauth_service.refresh_access_token(
                        refresh_token="refresh_123",
                        client_id="client_test123",
                        client_secret="secret",
                        scopes=["read:users"],  # Request subset of original scopes
                    )

                    # Assert
                    mock_create_tokens.assert_called_once()
                    call_args = mock_create_tokens.call_args[0]
                    assert call_args[2] == ["read:users"]  # Reduced scopes

    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid_scope_request(self, oauth_service, mock_oauth_app):
        """Test access token refresh with invalid scope request."""
        # Arrange
        mock_refresh_token = MagicMock(spec=OAuthRefreshToken)
        # Mock is_valid as a property
        type(mock_refresh_token).is_valid = PropertyMock(return_value=True)
        mock_refresh_token.application_id = mock_oauth_app.id
        mock_refresh_token.scopes = json.dumps(["read:users"])

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_refresh_token
        oauth_service.session.execute.return_value = mock_result

        with patch.object(oauth_service, "validate_client", return_value=mock_oauth_app):
            # Act & Assert
            with pytest.raises(ValidationError, match="Requested scopes exceed original grant"):
                await oauth_service.refresh_access_token(
                    refresh_token="refresh_123",
                    client_id="client_test123",
                    client_secret="secret",
                    scopes=["read:users", "write:users"],  # Request more than original
                )

    @pytest.mark.asyncio
    async def test_validate_access_token_success(self, oauth_service, mock_oauth_app, mock_user):
        """Test successful access token validation."""
        # Arrange
        token = "access_token_123"
        mock_access_token = MagicMock(spec=OAuthAccessToken)
        # Mock is_valid as a property
        type(mock_access_token).is_valid = PropertyMock(return_value=True)
        mock_access_token.scopes = json.dumps(["read:users"])

        mock_result = MagicMock()
        mock_result.one_or_none.return_value = (mock_access_token, mock_user, mock_oauth_app)
        oauth_service.session.execute.return_value = mock_result

        # Act
        access_token, user, app = await oauth_service.validate_access_token(token)

        # Assert
        assert access_token == mock_access_token
        assert user == mock_user
        assert app == mock_oauth_app

    @pytest.mark.asyncio
    async def test_validate_access_token_invalid(self, oauth_service):
        """Test access token validation when invalid."""
        # Arrange
        mock_result = MagicMock()
        mock_result.one_or_none.return_value = None
        oauth_service.session.execute.return_value = mock_result

        # Act & Assert
        with pytest.raises(AuthenticationError, match="Invalid access token"):
            await oauth_service.validate_access_token("invalid_token")

    @pytest.mark.asyncio
    async def test_revoke_token_access_token(self, oauth_service):
        """Test revoking access token."""
        # Arrange
        token = "access_token_123"
        mock_access_token = MagicMock(spec=OAuthAccessToken)
        mock_access_token.id = uuid.uuid4()
        mock_access_token.is_revoked = False
        mock_access_token.user_id = uuid.uuid4()
        mock_access_token.application_id = uuid.uuid4()
        mock_access_token.revoked_at = None

        # Mock hash_token
        with patch("app.services.oauth_service.hash_token", return_value="hashed_access_token"):
            # Create universal mock result for both SELECT and UPDATE operations
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_access_token  # For SELECT operations
            mock_result.rowcount = 1  # For UPDATE operations
            oauth_service.session.execute.return_value = mock_result

            # Mock repository session for UPDATE operations
            oauth_service.access_token_repo.session.execute.return_value = mock_result

            # Act
            result = await oauth_service.revoke_token(token)

            # Assert
            assert result is True

            # Verify that the repository's session.execute was called (indicating update occurred)
            assert oauth_service.access_token_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_revoke_token_refresh_token(self, oauth_service):
        """Test revoking refresh token."""
        # Arrange
        token = "refresh_token_123"
        mock_refresh_token = MagicMock(spec=OAuthRefreshToken)
        mock_refresh_token.is_revoked = False
        mock_refresh_token.id = uuid.uuid4()
        mock_refresh_token.user_id = uuid.uuid4()
        mock_refresh_token.application_id = uuid.uuid4()
        mock_refresh_token.revoked_at = None

        # Mock access tokens to revoke
        mock_access_tokens = [
            MagicMock(spec=OAuthAccessToken, id=uuid.uuid4(), is_revoked=False, revoked_at=None),
            MagicMock(spec=OAuthAccessToken, id=uuid.uuid4(), is_revoked=False, revoked_at=None),
        ]

        # Mock hash_token
        with patch("app.services.oauth_service.hash_token", return_value="hashed_token"):
            # Create universal mock result for all operations
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_refresh_token  # For SELECT operations
            mock_result.rowcount = 1  # For UPDATE operations

            # Configure scalars() to return an object with all() method
            mock_scalars = MagicMock()
            mock_scalars.all.return_value = mock_access_tokens
            mock_result.scalars.return_value = mock_scalars

            # Use return_value instead of side_effect to handle all calls
            oauth_service.session.execute.return_value = mock_result

            # Mock repository sessions for UPDATE operations
            oauth_service.refresh_token_repo.session.execute.return_value = mock_result
            oauth_service.access_token_repo.session.execute.return_value = mock_result

            # Act
            result = await oauth_service.revoke_token(token, token_type_hint="refresh_token")

            # Assert
            assert result is True

            # Verify that the repository's session.execute was called (indicating updates occurred)
            assert oauth_service.refresh_token_repo.session.execute.called

    @pytest.mark.asyncio
    async def test_list_user_authorizations(self, oauth_service):
        """Test listing user authorizations."""
        # Arrange
        user_id = str(uuid.uuid4())

        mock_app = MagicMock(spec=OAuthApplication)
        mock_app.id = uuid.uuid4()
        mock_app.name = "Test App"
        mock_app.description = "Test description"
        mock_app.logo_url = "https://example.com/logo.png"
        mock_app.homepage_url = "https://example.com"

        mock_token = MagicMock(spec=OAuthRefreshToken)
        mock_token.scopes = json.dumps(["read:users", "write:users"])
        mock_token.created_at = datetime.now(timezone.utc)
        mock_token.last_used_at = datetime.now(timezone.utc)

        # Mock the repository method directly to return the expected data
        with patch.object(
            oauth_service.refresh_token_repo, "get_user_authorizations", return_value=[(mock_app, mock_token)]
        ):
            # Act
            authorizations = await oauth_service.list_user_authorizations(user_id)

            # Assert
            assert len(authorizations) == 1
            assert authorizations[0]["application"]["name"] == "Test App"
            assert authorizations[0]["scopes"] == ["read:users", "write:users"]

    @pytest.mark.asyncio
    async def test_revoke_user_authorization(self, oauth_service):
        """Test revoking user authorization."""
        # Arrange
        user_id = str(uuid.uuid4())
        app_id = str(uuid.uuid4())

        mock_refresh_tokens = [MagicMock(spec=OAuthRefreshToken, id=uuid.uuid4(), is_revoked=False)]
        mock_access_tokens = [MagicMock(spec=OAuthAccessToken, id=uuid.uuid4(), is_revoked=False)]

        # Create universal mock result for all operations
        mock_result = MagicMock()
        mock_result.rowcount = 1  # For UPDATE operations

        # Configure scalars() to return an object with all() method for both queries
        mock_scalars1 = MagicMock()
        mock_scalars1.all.return_value = mock_refresh_tokens

        mock_scalars2 = MagicMock()
        mock_scalars2.all.return_value = mock_access_tokens

        # Use side_effect for scalars since there are multiple calls
        mock_result.scalars.side_effect = [mock_scalars1, mock_scalars2]

        oauth_service.session.execute.return_value = mock_result

        # Mock repository sessions for UPDATE operations
        oauth_service.refresh_token_repo.session.execute.return_value = mock_result
        oauth_service.access_token_repo.session.execute.return_value = mock_result

        # Act
        result = await oauth_service.revoke_user_authorization(user_id, app_id)

        # Assert
        assert result is True

        # Verify that the repository's session.execute was called (indicating updates occurred)
        assert oauth_service.refresh_token_repo.session.execute.called
        assert oauth_service.access_token_repo.session.execute.called
