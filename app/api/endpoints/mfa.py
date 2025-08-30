"""Multi-Factor Authentication endpoints."""

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from structlog.stdlib import get_logger

from app.api.deps import get_mfa_service
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

logger = get_logger(__name__)

router = APIRouter(prefix="/mfa", tags=["mfa"])


@router.post("/setup/totp", response_model=BaseResponse[MFASetupResponse])
async def setup_totp(
    setup_data: MFASetupStart,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[MFASetupResponse]:
    """
    Start TOTP setup for the current user.

    Returns secret and QR code for authenticator app setup.
    """
    try:
        secret, provisioning_uri, qr_code = await mfa_service.setup_totp(
            user=current_user, device_name=setup_data.device_name
        )

        return BaseResponse(
            status="success",
            message="TOTP setup initiated",
            data=MFASetupResponse(secret=secret, provisioning_uri=provisioning_uri, qr_code=qr_code),
        )
    except ValidationError as e:
        logger.warning(
            "MFA setup validation failed",
            user_id=current_user.id,
            error_type=type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA setup parameters",
        )
    except Exception as e:
        logger.error("TOTP setup failed", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup TOTP",
        )


@router.post("/setup/verify", response_model=BaseResponse[MFABackupCodesResponse])
async def verify_totp_setup(
    verification_data: MFASetupComplete,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[MFABackupCodesResponse]:
    """
    Verify TOTP setup with initial token.

    Returns backup codes on successful verification.
    """
    try:
        backup_codes = await mfa_service.verify_totp_setup(user=current_user, token=verification_data.token)

        return BaseResponse(
            status="success",
            message="MFA setup completed successfully",
            data=MFABackupCodesResponse(backup_codes=backup_codes),
        )
    except (AuthenticationError, NotFoundError, ValidationError) as e:
        logger.warning(
            "MFA verification failed",
            user_id=current_user.id,
            error_type=type(e).__name__,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA verification failed")
    except Exception as e:
        logger.error("TOTP verification failed", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify TOTP setup",
        )


@router.post("/challenge", response_model=BaseResponse[MFAChallengeResponse])
async def create_mfa_challenge(
    challenge_data: MFAChallengeCreate,
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[MFAChallengeResponse]:
    """
    Create an MFA challenge for authentication.

    This is typically called after username/password verification.
    """
    try:
        # Create MFA challenge using user_id - service layer should handle user lookup
        challenge_id = await mfa_service.create_mfa_challenge_by_user_id(
            user_id=challenge_data.user_id, method=challenge_data.method
        )

        return BaseResponse(
            status="success",
            message="MFA challenge created",
            data=MFAChallengeResponse(challenge_id=challenge_id, expires_in=300),  # 5 minutes
        )
    except (NotFoundError, ValidationError) as e:
        logger.warning("MFA challenge creation failed", error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid challenge parameters",
        )
    except Exception as e:
        logger.error("Challenge creation failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create MFA challenge",
        )


@router.post("/challenge/verify", response_model=BaseResponse[Dict[str, str]])
async def verify_mfa_challenge(
    verification_data: MFAChallengeVerify,
    request: Request,
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[Dict[str, str]]:
    """
    Verify an MFA challenge.

    Returns access token on successful verification.
    """
    try:
        # Get client IP
        ip_address = request.client.host if request.client else None

        verified, user = await mfa_service.verify_mfa_challenge(
            challenge_id=verification_data.challenge_id,
            token=verification_data.token,
            ip_address=ip_address,
        )

        if not verified or not user:
            raise AuthenticationError("Invalid token")

        # Generate access token (in real implementation)
        # For now, return a success message
        from app.core.security import create_access_token

        access_token = create_access_token(data={"sub": str(user.id)})

        return BaseResponse(
            status="success",
            message="MFA verification successful",
            data={"access_token": access_token},
        )
    except AuthenticationError as e:
        logger.warning("MFA challenge verification failed", error_type=type(e).__name__)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    except Exception as e:
        logger.error("Challenge verification failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA challenge",
        )


@router.get("/devices", response_model=BaseResponse[MFADeviceList])
async def list_mfa_devices(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[MFADeviceList]:
    """List user's MFA devices."""
    try:
        devices = await mfa_service.list_user_devices(current_user)

        return BaseResponse(
            status="success",
            message="MFA devices retrieved",
            data=MFADeviceList(devices=[MFADeviceResponse(**device) for device in devices]),
        )
    except Exception as e:
        logger.error("Failed to list devices", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list MFA devices",
        )


@router.delete("/devices/{device_id}", response_model=BaseResponse[Dict[str, bool]])
async def remove_mfa_device(
    device_id: str,
    backup_code: str = None,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[Dict[str, bool]]:
    """
    Remove an MFA device.

    Requires backup code if removing the last active device.
    """
    try:
        success = await mfa_service.remove_mfa_device(user=current_user, device_id=device_id, backup_code=backup_code)

        return BaseResponse(status="success", message="MFA device removed", data={"removed": success})
    except (NotFoundError, ValidationError, AuthenticationError) as e:
        logger.warning(
            "MFA device removal failed",
            user_id=current_user.id,
            error_type=type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to remove MFA device",
        )
    except Exception as e:
        logger.error("Failed to remove device", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove MFA device",
        )


@router.post("/backup-codes/regenerate", response_model=BaseResponse[MFABackupCodesResponse])
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> BaseResponse[MFABackupCodesResponse]:
    """Regenerate backup codes for the current user."""
    try:
        backup_codes = await mfa_service.regenerate_backup_codes(current_user)

        return BaseResponse(
            status="success",
            message="Backup codes regenerated",
            data=MFABackupCodesResponse(backup_codes=backup_codes),
        )
    except Exception as e:
        logger.error("Failed to regenerate codes", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        )
