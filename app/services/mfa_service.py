"""Multi-Factor Authentication Service using PyOTP."""

import base64
import io
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import pyotp
import qrcode
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.models.mfa import MFABackupCode, MFAChallenge, MFADevice, MFAEvent, MFAMethod
from app.models.user import User
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

    def __init__(self, session: AsyncSession) -> None:
        """Initialize MFA service."""
        self.session = session
        self.audit_service = AuditService(session)

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
            existing.secret = secret
            existing.name = device_name
            existing.verified_at = None
            device = existing
        else:
            device = MFADevice(
                user_id=user.id,
                name=device_name,
                method=MFAMethod.TOTP,
                secret=secret,
                is_active=False,  # Not active until verified
            )
            self.session.add(device)

        await self.session.flush()

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
        device.verified_at = datetime.utcnow()
        device.is_active = True
        device.is_primary = True  # Make primary if first device

        await self.session.flush()

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
        challenge = MFAChallenge(
            user_id=user.id,
            device_id=device.id,
            challenge_id=challenge_id,
            method=device.method,
            expires_at=datetime.utcnow() + timedelta(minutes=self.CHALLENGE_EXPIRY_MINUTES),
            max_attempts=self.MAX_CHALLENGE_ATTEMPTS,
        )

        self.session.add(challenge)
        await self.session.flush()

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
        query = select(MFAChallenge).where(MFAChallenge.challenge_id == challenge_id)
        result = await self.session.execute(query)
        challenge = result.scalar_one_or_none()

        if not challenge or not challenge.is_valid:
            raise AuthenticationError("Invalid or expired challenge")

        # Update attempt count
        challenge.attempt_count += 1

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
            challenge.is_verified = True
            challenge.verified_at = datetime.utcnow()

            # Update device usage
            device.last_used_at = datetime.utcnow()
            device.use_count += 1

            await self.session.flush()

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

            await self.session.flush()

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
        device.is_deleted = True
        device.deleted_at = datetime.utcnow()
        device.is_active = False

        await self.session.flush()

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
        query = (
            select(MFADevice)
            .where(MFADevice.user_id == user.id, MFADevice.is_deleted == False)
            .order_by(MFADevice.created_at.desc())
        )

        result = await self.session.execute(query)
        devices = result.scalars().all()

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
        query = select(MFABackupCode).where(MFABackupCode.user_id == user.id, MFABackupCode.is_used == False)
        result = await self.session.execute(query)
        existing_codes = result.scalars().all()

        for code in existing_codes:
            code.is_used = True
            code.used_at = datetime.utcnow()

        # Generate new codes
        new_codes = await self._generate_backup_codes(user.id)

        await self.session.flush()

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

        policy_service = MFAPolicyService(self.session)
        is_required, policy, details = await policy_service.check_mfa_requirement(user)

        # If policy says MFA is required, return True
        if is_required:
            return True

        # If policy says recommended or user is in grace period,
        # check if user has already set up MFA
        if details.get("enforcement_level") in ["recommended", "grace_period"]:
            # Check if user has any active MFA devices
            query = select(MFADevice).where(
                and_(
                    MFADevice.user_id == user.id,
                    MFADevice.is_active == True,
                    MFADevice.is_deleted == False,
                    MFADevice.verified_at.isnot(None),
                )
            )
            result = await self.session.execute(query)
            devices = result.scalars().all()

            # If user has configured MFA, require it even if policy doesn't mandate it
            return len(devices) > 0

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
        query = select(MFABackupCode).where(
            MFABackupCode.user_id == user_id, MFABackupCode.code_hash == code_hash, MFABackupCode.is_used == False
        )
        result = await self.session.execute(query)
        backup_code = result.scalar_one_or_none()

        if backup_code:
            # Mark as used
            backup_code.is_used = True
            backup_code.used_at = datetime.utcnow()
            await self.session.flush()
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

            backup_code = MFABackupCode(user_id=user_id, code_hash=code_hash)
            self.session.add(backup_code)

        await self.session.flush()
        return codes

    async def _get_user_device(self, user_id: str, method: MFAMethod) -> Optional[MFADevice]:
        """Get user's device by method."""
        query = select(MFADevice).where(
            MFADevice.user_id == user_id, MFADevice.method == method, MFADevice.is_deleted == False
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def _get_primary_device(self, user_id: str) -> Optional[MFADevice]:
        """Get user's primary MFA device."""
        query = select(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.is_primary == True,
            MFADevice.is_active == True,
            MFADevice.is_deleted == False,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def _get_device_by_id(self, device_id: str) -> Optional[MFADevice]:
        """Get device by ID."""
        query = select(MFADevice).where(MFADevice.id == device_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        query = select(User).where(User.id == user_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def _count_active_devices(self, user_id: str) -> int:
        """Count user's active MFA devices."""
        query = select(MFADevice).where(
            MFADevice.user_id == user_id, MFADevice.is_active == True, MFADevice.is_deleted == False
        )
        result = await self.session.execute(query)
        return len(result.scalars().all())

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
        event = MFAEvent(
            user_id=user_id,
            event_type=event_type,
            event_status=event_status,
            method=method,
            device_id=device_id,
            details=json.dumps(details) if details else None,
        )
        self.session.add(event)

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
