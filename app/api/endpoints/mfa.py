"""Multi-Factor Authentication endpoints."""

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.auth import get_current_user
from app.core.errors import AuthenticationError, NotFoundError, ValidationError
from app.models.user import User
from app.schemas.base import BaseResponse
from app.schemas.mfa import (
    MFABackupCodesResponse,
    MFAChallengeCreate,
    MFAChallengeResponse,
    MFAChallengeVerify,
    MFADeviceList,
    MFADeviceResponse,
    MFASetupComplete,
    MFASetupResponse,
    MFASetupStart,
)
from app.services.mfa_service import MFAService

from ...db.session import get_db_dependency

logger = get_logger(__name__)

router = APIRouter(prefix="/mfa", tags=["mfa"])


@router.post("/setup/totp", response_model=BaseResponse[MFASetupResponse])
async def setup_totp(
    setup_data: MFASetupStart,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFASetupResponse]:
    """
    Start TOTP setup for the current user.

    Returns secret and QR code for authenticator app setup.
    """
    try:
        mfa_service = MFAService(session)
        secret, provisioning_uri, qr_code = await mfa_service.setup_totp(
            user=current_user, device_name=setup_data.device_name
        )

        await session.commit()

        return BaseResponse(
            status="success",
            message="TOTP setup initiated",
            data=MFASetupResponse(secret=secret, provisioning_uri=provisioning_uri, qr_code=qr_code),
        )
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("TOTP setup failed", error=str(e), user_id=current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to setup TOTP")


@router.post("/setup/verify", response_model=BaseResponse[MFABackupCodesResponse])
async def verify_totp_setup(
    verification_data: MFASetupComplete,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFABackupCodesResponse]:
    """
    Verify TOTP setup with initial token.

    Returns backup codes on successful verification.
    """
    try:
        mfa_service = MFAService(session)
        backup_codes = await mfa_service.verify_totp_setup(user=current_user, token=verification_data.token)

        await session.commit()

        return BaseResponse(
            status="success",
            message="MFA setup completed successfully",
            data=MFABackupCodesResponse(backup_codes=backup_codes),
        )
    except (AuthenticationError, NotFoundError, ValidationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("TOTP verification failed", error=str(e), user_id=current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to verify TOTP setup")


@router.post("/challenge", response_model=BaseResponse[MFAChallengeResponse])
async def create_mfa_challenge(
    challenge_data: MFAChallengeCreate,
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFAChallengeResponse]:
    """
    Create an MFA challenge for authentication.

    This is typically called after username/password verification.
    """
    try:
        # Get user using UserRepository instead of direct database access
        from app.repositories.user import UserRepository

        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(challenge_data.user_id)

        if not user:
            raise NotFoundError("User not found")

        mfa_service = MFAService(session)

        # Check if MFA is required
        if not await mfa_service.check_mfa_required(user):
            raise ValidationError("MFA not configured for this user")

        challenge_id = await mfa_service.create_mfa_challenge(user=user, method=challenge_data.method)

        await session.commit()

        return BaseResponse(
            status="success",
            message="MFA challenge created",
            data=MFAChallengeResponse(challenge_id=challenge_id, expires_in=300),  # 5 minutes
        )
    except (NotFoundError, ValidationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Challenge creation failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create MFA challenge")


@router.post("/challenge/verify", response_model=BaseResponse[Dict[str, str]])
async def verify_mfa_challenge(
    verification_data: MFAChallengeVerify,
    request: Request,
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[Dict[str, str]]:
    """
    Verify an MFA challenge.

    Returns access token on successful verification.
    """
    try:
        mfa_service = MFAService(session)

        # Get client IP
        ip_address = request.client.host if request.client else None

        verified, user = await mfa_service.verify_mfa_challenge(
            challenge_id=verification_data.challenge_id, token=verification_data.token, ip_address=ip_address
        )

        if not verified or not user:
            raise AuthenticationError("Invalid token")

        await session.commit()

        # Generate access token (in real implementation)
        # For now, return a success message
        from app.core.security import create_access_token

        access_token = create_access_token(data={"sub": str(user.id)})

        return BaseResponse(
            status="success", message="MFA verification successful", data={"access_token": access_token}
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error("Challenge verification failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to verify MFA challenge")


@router.get("/devices", response_model=BaseResponse[MFADeviceList])
async def list_mfa_devices(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFADeviceList]:
    """List user's MFA devices."""
    try:
        mfa_service = MFAService(session)
        devices = await mfa_service.list_user_devices(current_user)

        return BaseResponse(
            status="success",
            message="MFA devices retrieved",
            data=MFADeviceList(devices=[MFADeviceResponse(**device) for device in devices]),
        )
    except Exception as e:
        logger.error("Failed to list devices", error=str(e), user_id=current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list MFA devices")


@router.delete("/devices/{device_id}", response_model=BaseResponse[Dict[str, bool]])
async def remove_mfa_device(
    device_id: str,
    backup_code: str = None,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[Dict[str, bool]]:
    """
    Remove an MFA device.

    Requires backup code if removing the last active device.
    """
    try:
        mfa_service = MFAService(session)
        success = await mfa_service.remove_mfa_device(user=current_user, device_id=device_id, backup_code=backup_code)

        await session.commit()

        return BaseResponse(status="success", message="MFA device removed", data={"removed": success})
    except (NotFoundError, ValidationError, AuthenticationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Failed to remove device", error=str(e), user_id=current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to remove MFA device")


@router.post("/backup-codes/regenerate", response_model=BaseResponse[MFABackupCodesResponse])
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFABackupCodesResponse]:
    """Regenerate backup codes for the current user."""
    try:
        mfa_service = MFAService(session)
        backup_codes = await mfa_service.regenerate_backup_codes(current_user)

        await session.commit()

        return BaseResponse(
            status="success", message="Backup codes regenerated", data=MFABackupCodesResponse(backup_codes=backup_codes)
        )
    except Exception as e:
        logger.error("Failed to regenerate codes", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to regenerate backup codes"
        )
