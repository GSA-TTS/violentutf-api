"""Unit tests for MFA service."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.services.mfa_policy_service import MFAPolicyService
from app.services.mfa_service import MFAService


# Create mock classes for the models
class MFADevice:
    """Mock MFA device model."""

    pass


class MFAChallenge:
    """Mock MFA challenge model."""

    pass


class MFAMethod:
    """Mock MFA method enum."""

    TOTP = "totp"  # Changed to lowercase to match actual enum
    BACKUP_CODE = "backup_code"  # Added for other tests


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
    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "test@example.com"
    user.username = "testuser"
    user.is_active = True
    return user


@pytest.fixture
def mfa_service(mock_session):
    """Create MFA service instance."""
    return MFAService(mock_session)


class TestMFAService:
    """Test MFA service methods."""

    @pytest.mark.asyncio
    async def test_setup_totp_success(self, mfa_service, mock_user):
        """Test successful TOTP setup."""
        # Arrange
        device_name = "My Phone"

        # Mock no existing device
        with patch.object(mfa_service, "_get_user_device", return_value=None):
            # Mock the device creation
            mock_device = MagicMock()
            mock_device.id = uuid.uuid4()

            # Act
            with patch.object(pyotp, "random_base32", return_value="TESTBASE32SECRET"):
                # Mock the MFADevice constructor to return our mock
                with patch("app.services.mfa_service.MFADevice", return_value=mock_device):
                    secret, provisioning_uri, qr_code = await mfa_service.setup_totp(
                        user=mock_user, device_name=device_name
                    )

        # Assert
        assert secret == "TESTBASE32SECRET"
        assert "otpauth://totp/" in provisioning_uri
        assert "ViolentUTF%20API" in provisioning_uri
        assert qr_code.startswith("data:image/png;base64,")
        # Should be called 3 times: device, MFA event, and audit log
        assert mfa_service.session.add.call_count == 3

    @pytest.mark.asyncio
    async def test_setup_totp_existing_verified_device(self, mfa_service, mock_user):
        """Test TOTP setup with existing verified device."""
        # Arrange
        existing_device = MagicMock()
        existing_device.verified_at = datetime.now(timezone.utc)

        with patch.object(mfa_service, "_get_user_device", return_value=existing_device):
            # Act & Assert
            with pytest.raises(ValidationError, match="TOTP already configured"):
                await mfa_service.setup_totp(mock_user, "New Device")

    @pytest.mark.asyncio
    async def test_verify_totp_setup_success(self, mfa_service, mock_user):
        """Test successful TOTP verification."""
        # Arrange
        device = MagicMock(spec=MFADevice)
        device.id = uuid.uuid4()
        device.secret = "TESTBASE32SECRET"
        device.verified_at = None

        with patch.object(mfa_service, "_get_user_device", return_value=device):
            # Mock TOTP verification
            with patch.object(pyotp.TOTP, "verify", return_value=True):
                with patch.object(mfa_service, "_generate_backup_codes", return_value=["1234-5678"]):
                    # Act
                    backup_codes = await mfa_service.verify_totp_setup(user=mock_user, token="123456")

        # Assert
        assert backup_codes == ["1234-5678"]
        assert device.verified_at is not None
        assert device.is_active is True
        assert device.is_primary is True

    @pytest.mark.asyncio
    async def test_verify_totp_setup_invalid_token(self, mfa_service, mock_user):
        """Test TOTP verification with invalid token."""
        # Arrange
        device = MagicMock(spec=MFADevice)
        device.id = uuid.uuid4()
        device.secret = "TESTBASE32SECRET"
        device.verified_at = None

        with patch.object(mfa_service, "_get_user_device", return_value=device):
            # Mock TOTP verification failure
            with patch.object(pyotp.TOTP, "verify", return_value=False):
                # Act & Assert
                with pytest.raises(AuthenticationError, match="Invalid TOTP token"):
                    await mfa_service.verify_totp_setup(mock_user, "000000")

    @pytest.mark.asyncio
    async def test_create_mfa_challenge_success(self, mfa_service, mock_user):
        """Test successful MFA challenge creation."""
        # Arrange
        device = MagicMock(spec=MFADevice)
        device.id = uuid.uuid4()
        device.method = MFAMethod.TOTP
        device.is_active = True

        with patch.object(mfa_service, "_get_primary_device", return_value=device):
            # Act
            with patch("secrets.token_urlsafe", return_value="test_challenge_id"):
                # Mock the MFAChallenge constructor
                with patch("app.services.mfa_service.MFAChallenge") as mock_challenge_class:
                    mock_challenge = MagicMock()
                    mock_challenge_class.return_value = mock_challenge
                    challenge_id = await mfa_service.create_mfa_challenge(mock_user)

        # Assert
        assert challenge_id == "test_challenge_id"
        # Should be called 3 times: challenge, MFA event, and audit log
        assert mfa_service.session.add.call_count == 3

    @pytest.mark.asyncio
    async def test_create_mfa_challenge_no_device(self, mfa_service, mock_user):
        """Test MFA challenge creation with no device."""
        # Arrange
        with patch.object(mfa_service, "_get_primary_device", return_value=None):
            # Act & Assert
            with pytest.raises(NotFoundError, match="No active MFA device found"):
                await mfa_service.create_mfa_challenge(mock_user)

    @pytest.mark.asyncio
    async def test_verify_mfa_challenge_totp_success(self, mfa_service):
        """Test successful TOTP challenge verification."""
        # Arrange
        challenge = MagicMock(spec=MFAChallenge)
        challenge.challenge_id = "test_challenge_id"
        challenge.is_valid = True
        challenge.method = MFAMethod.TOTP
        challenge.device_id = uuid.uuid4()
        challenge.user_id = uuid.uuid4()
        challenge.attempt_count = 0
        challenge.max_attempts = 3

        device = MagicMock(spec=MFADevice)
        device.id = challenge.device_id
        device.secret = "TESTBASE32SECRET"
        device.last_used_at = None
        device.use_count = 0

        user = MagicMock(spec=User)
        user.id = challenge.user_id

        # Mock the database query for challenge
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = challenge
        mfa_service.session.execute.return_value = mock_result

        # Mock the method calls
        with patch.object(mfa_service, "_get_device_by_id", return_value=device):
            with patch.object(mfa_service, "_get_user_by_id", return_value=user):
                # Mock TOTP verification
                with patch.object(mfa_service, "_verify_totp", return_value=True):
                    # Act
                    verified, returned_user = await mfa_service.verify_mfa_challenge(
                        challenge_id="test_challenge_id", token="123456", ip_address="127.0.0.1"
                    )

        # Assert
        assert verified is True
        assert returned_user == user
        assert challenge.is_verified is True
        assert device.use_count == 1

    @pytest.mark.asyncio
    async def test_verify_mfa_challenge_max_attempts(self, mfa_service):
        """Test MFA challenge verification with max attempts exceeded."""
        # Arrange
        challenge = MagicMock(spec=MFAChallenge)
        challenge.is_valid = True
        challenge.attempt_count = 2  # One less than max
        challenge.max_attempts = 3
        challenge.method = MFAMethod.TOTP
        challenge.device_id = uuid.uuid4()
        challenge.user_id = uuid.uuid4()

        device = MagicMock(spec=MFADevice)
        device.id = challenge.device_id
        device.secret = "TESTBASE32SECRET"

        user = MagicMock(spec=User)
        user.id = challenge.user_id

        # Mock the database query for challenge
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = challenge
        mfa_service.session.execute.return_value = mock_result

        # Mock the method calls
        with patch.object(mfa_service, "_get_device_by_id", return_value=device):
            with patch.object(mfa_service, "_get_user_by_id", return_value=user):
                # Mock TOTP verification failure
                with patch.object(mfa_service, "_verify_totp", return_value=False):
                    # Act & Assert
                    with pytest.raises(AuthenticationError, match="Maximum attempts exceeded"):
                        await mfa_service.verify_mfa_challenge(challenge_id="test_challenge_id", token="000000")

    @pytest.mark.asyncio
    async def test_remove_mfa_device_success(self, mfa_service, mock_user):
        """Test successful MFA device removal."""
        # Arrange
        device = MagicMock(spec=MFADevice)
        device.id = uuid.uuid4()
        device.user_id = mock_user.id
        device.is_active = True
        device.method = MFAMethod.TOTP

        # Mock the device fetching
        with patch.object(mfa_service, "_get_device_by_id", return_value=device):
            # Mock the user device count query
            mock_result = MagicMock()
            mock_result.scalar.return_value = 2  # User has 2 devices
            mfa_service.session.execute.return_value = mock_result

            # Act
            result = await mfa_service.remove_mfa_device(user=mock_user, device_id=str(device.id))

        # Assert
        assert result is True
        assert device.is_deleted is True
        assert device.is_active is False

    @pytest.mark.asyncio
    async def test_check_mfa_required_with_active_device(self, mfa_service, mock_user):
        """Test MFA requirement check with active device."""
        # Arrange
        # Mock the MFA policy service to return "recommended" enforcement
        with patch("app.services.mfa_policy_service.MFAPolicyService") as mock_policy_service_class:
            mock_policy_service = MagicMock()
            mock_policy_service.check_mfa_requirement = AsyncMock(
                return_value=(False, None, {"enforcement_level": "recommended"})  # is_required  # policy  # details
            )
            mock_policy_service_class.return_value = mock_policy_service

            # Mock the database query for active devices
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [MagicMock()]  # One device
            mfa_service.session.execute.return_value = mock_result

            # Act
            required = await mfa_service.check_mfa_required(mock_user)

            # Assert
            assert required is True

    @pytest.mark.asyncio
    async def test_check_mfa_required_no_device(self, mfa_service, mock_user):
        """Test MFA requirement check with no device."""
        # Arrange
        # Mock the MFA policy service to return no requirement
        with patch("app.services.mfa_policy_service.MFAPolicyService") as mock_policy_service_class:
            mock_policy_service = MagicMock()
            mock_policy_service.check_mfa_requirement = AsyncMock(
                return_value=(False, None, {"enforcement_level": "optional"})  # is_required  # policy  # details
            )
            mock_policy_service_class.return_value = mock_policy_service

            # Act
            required = await mfa_service.check_mfa_required(mock_user)

            # Assert
            assert required is False
