"""Multi-Factor Authentication Service using PyOTP."""

import base64
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import pyotp
import qrcode
from sqlalchemy import and_, select
from structlog.stdlib import get_logger

from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.models.mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent, MFAMethod
from app.models.user import User
from app.repositories.mfa_backup_code import MFABackupCodeRepository
from app.repositories.mfa_challenge import MFAChallengeRepository
from app.repositories.mfa_device import MFADeviceRepository
from app.repositories.mfa_event import MFAEventRepository
from app.repositories.user import UserRepository
from app.services.audit_service import AuditService

logger = get_logger(__name__)


class MFAService:
    """Service for managing multi-factor authentication."""

    # Configuration
    TOTP_ISSUER = "ViolentUTF API"
    TOTP_PERIOD = 30  # seconds
    TOTP_DIGITS = 6
    BACKUP_CODE_COUNT = 10
    CHALLENGE_EXPIRY_MINUTES = 5
    MAX_CHALLENGE_ATTEMPTS = 3

    def __init__(
        self,
        mfa_device_repo: MFADeviceRepository,
        mfa_challenge_repo: MFAChallengeRepository,
        mfa_backup_code_repo: MFABackupCodeRepository,
        mfa_event_repo: MFAEventRepository,
        user_repo: UserRepository,
        audit_service: AuditService,
    ) -> None:
        """Initialize MFA service."""
        self.mfa_device_repo = mfa_device_repo
        self.mfa_challenge_repo = mfa_challenge_repo
        self.mfa_backup_code_repo = mfa_backup_code_repo
        self.mfa_event_repo = mfa_event_repo
        self.user_repo = user_repo
        self.audit_service = audit_service

    async def setup_totp(self, user: User, device_name: str) -> Tuple[str, str, str]:
        """
        Set up TOTP for a user.

        Args:
            user: User setting up TOTP
            device_name: Name for the device

        Returns:
            Tuple of (secret, provisioning_uri, qr_code_data)
        """
        # Check if user already has TOTP set up
        existing = await self._get_user_device(user.id, MFAMethod.TOTP)
        if existing and existing.verified_at:
            raise ValidationError("TOTP already configured. Remove existing device first.")

        # Generate secret
        secret = pyotp.random_base32()

        # Create TOTP instance
        totp = pyotp.TOTP(secret, issuer=self.TOTP_ISSUER, interval=self.TOTP_PERIOD, digits=self.TOTP_DIGITS)

        # Generate provisioning URI
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=self.TOTP_ISSUER)

        # Generate QR code
        qr_code_data = self._generate_qr_code(provisioning_uri)

        # Create or update device record
        if existing:
            device = await self.mfa_device_repo.update(existing.id, secret=secret, name=device_name, verified_at=None)
        else:
            device_data = {
                "user_id": user.id,
                "name": device_name,
                "method": MFAMethod.TOTP,
                "secret": secret,
                "is_active": False,  # Not active until verified
            }
            device = await self.mfa_device_repo.create(device_data)

        # Log event
        await self._log_mfa_event(
            user_id=user.id,
            event_type="setup_initiated",
            event_status="success",
            method=MFAMethod.TOTP,
            device_id=device.id,
        )

        return secret, provisioning_uri, qr_code_data

    async def verify_totp_setup(self, user: User, token: str) -> bool:
        """
        Verify TOTP setup with initial token.

        Args:
            user: User verifying setup
            token: TOTP token to verify

        Returns:
            True if verified successfully
        """
        device = await self._get_user_device(user.id, MFAMethod.TOTP)
        if not device:
            raise NotFoundError("TOTP device not found")

        if device.verified_at:
            raise ValidationError("TOTP already verified")

        # Verify token
        totp = pyotp.TOTP(device.secret, interval=self.TOTP_PERIOD)
        if not totp.verify(token, valid_window=1):
            await self._log_mfa_event(
                user_id=user.id,
                event_type="setup_verification",
                event_status="failure",
                method=MFAMethod.TOTP,
                device_id=device.id,
            )
            raise AuthenticationError("Invalid TOTP token")

        # Mark as verified and active
        device = await self.mfa_device_repo.update(
            device.id,
            verified_at=datetime.now(timezone.utc),
            is_active=True,
            is_primary=True,  # Make primary if first device
        )

        # Generate backup codes
        backup_codes = await self._generate_backup_codes(user.id)

        # Log event
        await self._log_mfa_event(
            user_id=user.id,
            event_type="setup_verification",
            event_status="success",
            method=MFAMethod.TOTP,
            device_id=device.id,
        )

        return backup_codes

    async def create_mfa_challenge(self, user: User, method: Optional[MFAMethod] = None) -> str:
        """
        Create an MFA challenge for authentication.

        Args:
            user: User to challenge
            method: Specific method to use (or primary if None)

        Returns:
            Challenge ID
        """
        # Get device
        if method:
            device = await self._get_user_device(user.id, method)
        else:
            device = await self._get_primary_device(user.id)

        if not device or not device.is_active:
            raise NotFoundError("No active MFA device found")

        # Create challenge
        challenge_id = secrets.token_urlsafe(32)
        challenge_data = {
            "user_id": user.id,
            "device_id": device.id,
            "challenge_id": challenge_id,
            "method": device.method,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=self.CHALLENGE_EXPIRY_MINUTES),
            "max_attempts": self.MAX_CHALLENGE_ATTEMPTS,
        }

        _ = await self.mfa_challenge_repo.create(challenge_data)

        # Log event
        await self._log_mfa_event(
            user_id=user.id,
            event_type="challenge_created",
            event_status="success",
            method=device.method,
            device_id=device.id,
        )

        return challenge_id

    async def verify_mfa_challenge(
        self, challenge_id: str, token: str, ip_address: Optional[str] = None
    ) -> Tuple[bool, Optional[User]]:
        """
        Verify an MFA challenge.

        Args:
            challenge_id: Challenge to verify
            token: Token provided by user
            ip_address: Client IP address

        Returns:
            Tuple of (success, user)
        """
        # Get challenge
        challenge = await self.mfa_challenge_repo.get_by_challenge_id(challenge_id)

        if not challenge or not challenge.is_valid:
            raise AuthenticationError("Invalid or expired challenge")

        # Update attempt count
        current_count = getattr(challenge, "attempt_count", 0)
        await self.mfa_challenge_repo.update(challenge.id, attempt_count=current_count + 1)

        # Get device and user
        device = await self._get_device_by_id(challenge.device_id)
        user = await self._get_user_by_id(challenge.user_id)

        if not device or not user:
            raise NotFoundError("Device or user not found")

        # Verify based on method
        verified = False
        if challenge.method == MFAMethod.TOTP:
            verified = self._verify_totp(device.secret, token)
        elif challenge.method == MFAMethod.BACKUP_CODE:
            verified = await self._verify_backup_code(user.id, token)

        if verified:
            # Mark challenge as verified
            await self.mfa_challenge_repo.update(challenge.id, is_verified=True, verified_at=datetime.now(timezone.utc))

            # Update device usage
            current_use_count = getattr(device, "use_count", 0)
            await self.mfa_device_repo.update(
                device.id, last_used_at=datetime.now(timezone.utc), use_count=current_use_count + 1
            )

            # Log success
            await self._log_mfa_event(
                user_id=user.id,
                event_type="challenge_verified",
                event_status="success",
                method=challenge.method,
                device_id=device.id,
                details={"ip_address": ip_address},
            )

            return True, user
        else:
            # Log failure
            await self._log_mfa_event(
                user_id=user.id,
                event_type="challenge_verified",
                event_status="failure",
                method=challenge.method,
                device_id=device.id,
                details={"ip_address": ip_address, "attempts": challenge.attempt_count},
            )

            # Challenge was already updated above

            if challenge.attempt_count >= challenge.max_attempts:
                raise AuthenticationError("Maximum attempts exceeded")

            return False, None

    async def remove_mfa_device(self, user: User, device_id: str, backup_code: Optional[str] = None) -> bool:
        """
        Remove an MFA device.

        Args:
            user: User removing device
            device_id: Device to remove
            backup_code: Backup code for verification

        Returns:
            True if removed successfully
        """
        # Get device
        device = await self._get_device_by_id(device_id)
        if not device or device.user_id != user.id:
            raise NotFoundError("Device not found")

        # Require backup code verification if removing last active device
        active_devices = await self._count_active_devices(user.id)
        if active_devices == 1 and device.is_active:
            if not backup_code:
                raise ValidationError("Backup code required to remove last device")

            if not await self._verify_backup_code(user.id, backup_code):
                raise AuthenticationError("Invalid backup code")

        # Soft delete device
        await self.mfa_device_repo.delete(device.id)

        # Log event
        await self._log_mfa_event(
            user_id=user.id,
            event_type="device_removed",
            event_status="success",
            method=device.method,
            device_id=device.id,
        )

        return True

    async def list_user_devices(self, user: User) -> List[Dict]:
        """
        List user's MFA devices.

        Args:
            user: User to list devices for

        Returns:
            List of device information
        """
        devices = await self.mfa_device_repo.get_by_user_id(user.id)

        return [
            {
                "id": str(device.id),
                "name": device.name,
                "method": device.method.value,
                "is_active": device.is_active,
                "is_primary": device.is_primary,
                "verified_at": device.verified_at.isoformat() if device.verified_at else None,
                "last_used_at": device.last_used_at.isoformat() if device.last_used_at else None,
                "created_at": device.created_at.isoformat(),
            }
            for device in devices
        ]

    async def regenerate_backup_codes(self, user: User) -> List[str]:
        """
        Regenerate backup codes for a user.

        Args:
            user: User to regenerate codes for

        Returns:
            List of new backup codes
        """
        # Invalidate existing codes
        existing_codes = await self.mfa_backup_code_repo.get_user_codes(user.id, unused_only=True)

        for code in existing_codes:
            await self.mfa_backup_code_repo.mark_code_used(code.id)

        # Generate new codes
        new_codes = await self._generate_backup_codes(user.id)

        # Codes already saved in _generate_backup_codes

        # Log event
        await self._log_mfa_event(
            user_id=user.id, event_type="backup_codes_regenerated", event_status="success", method=MFAMethod.BACKUP_CODE
        )

        return new_codes

    async def check_mfa_required(self, user: User) -> bool:
        """
        Check if MFA is required for a user.

        Args:
            user: User to check

        Returns:
            True if MFA is required
        """
        # First check policy requirements
        from app.services.mfa_policy_service import MFAPolicyService

        policy_service = MFAPolicyService(self.mfa_device_repo.session)
        is_required, policy, details = await policy_service.check_mfa_requirement(user)

        # If policy says MFA is required, return True
        if is_required:
            return True

        # If policy says recommended or user is in grace period,
        # check if user has already set up MFA
        if details.get("enforcement_level") in ["recommended", "grace_period"]:
            # Check if user has any active MFA devices
            device_count = await self.mfa_device_repo.count_active_devices(user.id)

            # If user has configured MFA, require it even if policy doesn't mandate it
            return device_count > 0

        # MFA not required
        return False

    # Private helper methods

    def _generate_qr_code(self, data: str) -> str:
        """Generate QR code as base64 data URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")

        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"

    def _verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token."""
        totp = pyotp.TOTP(secret, interval=self.TOTP_PERIOD)
        return totp.verify(token, valid_window=1)

    async def _verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify and consume backup code."""
        # Hash the code
        import hashlib

        code_hash = hashlib.sha256(code.encode()).hexdigest()

        # Find unused code
        backup_code = await self.mfa_backup_code_repo.get_by_hash(code_hash)

        if backup_code and backup_code.user_id == user_id and not backup_code.is_used:
            # Mark as used
            await self.mfa_backup_code_repo.mark_code_used(backup_code.id)
            return True

        return False

    async def _generate_backup_codes(self, user_id: str) -> List[str]:
        """Generate backup codes for a user."""
        codes = []

        for _ in range(self.BACKUP_CODE_COUNT):
            # Generate code
            code = MFABackupCode.generate_code()
            codes.append(code)

            # Hash and store
            import hashlib

            code_hash = hashlib.sha256(code.encode()).hexdigest()

            backup_code_data = {
                "user_id": user_id,
                "code_hash": code_hash,
            }
            await self.mfa_backup_code_repo.create(backup_code_data)

        return codes

    async def _get_user_device(self, user_id: str, method: MFAMethod) -> Optional[MFADevice]:
        """Get user's device by method."""
        return await self.mfa_device_repo.get_by_user_and_method(user_id, method)

    async def _get_primary_device(self, user_id: str) -> Optional[MFADevice]:
        """Get user's primary MFA device."""
        return await self.mfa_device_repo.get_primary_device(user_id)

    async def _get_device_by_id(self, device_id: str) -> Optional[MFADevice]:
        """Get device by ID."""
        return await self.mfa_device_repo.get_by_id(device_id)

    async def _get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return await self.user_repo.get_by_id(user_id)

    async def _count_active_devices(self, user_id: str) -> int:
        """Count user's active MFA devices."""
        return await self.mfa_device_repo.count_active_devices(user_id)

    async def _log_mfa_event(
        self,
        user_id: str,
        event_type: str,
        event_status: str,
        method: Optional[MFAMethod] = None,
        device_id: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> None:
        """Log MFA event."""
        event_data = {
            "user_id": user_id,
            "event_type": event_type,
            "event_status": event_status,
            "method": method,
            "device_id": device_id,
            "details": json.dumps(details) if details else None,
        }
        await self.mfa_event_repo.create(event_data)

        # Also log to audit service
        await self.audit_service.log_security_event(
            event_type=f"mfa_{event_type}",
            user_id=user_id,
            risk_level="medium" if event_status == "failure" else "low",
            details={
                "method": method.value if hasattr(method, "value") else method,
                "device_id": str(device_id) if device_id else None,
                "status": event_status,
                **(details or {}),
            },
        )
