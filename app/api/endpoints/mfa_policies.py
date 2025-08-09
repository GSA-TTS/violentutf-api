"""MFA Policy management endpoints."""

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.auth import get_current_user
from app.core.errors import NotFoundError, ValidationError
from app.core.permissions import require_permission
from app.models.user import User
from app.schemas.base import BaseResponse
from app.schemas.mfa_policy import (
    MFAPolicyCreate,
    MFAPolicyList,
    MFAPolicyResponse,
    MFAPolicyUpdate,
    UserMFARequirement,
)
from app.services.mfa_policy_service import MFAPolicyService

from ...db.session import get_db_dependency

logger = get_logger(__name__)

router = APIRouter(prefix="/mfa/policies", tags=["mfa-policies"])


@router.post("/", response_model=BaseResponse[MFAPolicyResponse])
async def create_mfa_policy(
    policy_data: MFAPolicyCreate,
    current_user: User = Depends(require_permission("mfa.policy.create")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFAPolicyResponse]:
    """
    Create a new MFA policy.

    Requires permission: mfa.policy.create
    """
    try:
        policy_service = MFAPolicyService(session)
        policy = await policy_service.create_policy(
            name=policy_data.name,
            description=policy_data.description,
            conditions=policy_data.conditions.dict(),
            required_methods=policy_data.required_methods,
            min_methods=policy_data.min_methods,
            grace_period_days=policy_data.grace_period_days,
            enforcement_level=policy_data.enforcement_level,
            bypass_permissions=policy_data.bypass_permissions,
            priority=policy_data.priority,
            created_by=current_user.username,
        )

        await session.commit()

        return BaseResponse(
            status="success",
            message="MFA policy created successfully",
            data=MFAPolicyResponse(
                id=str(policy.id),
                name=policy.name,
                description=policy.description,
                is_active=policy.is_active,
                priority=policy.priority,
                enforcement_level=policy.enforcement_level,
                grace_period_days=policy.grace_period_days,
                min_methods=policy.min_methods,
                conditions=policy_data.conditions,
                required_methods=policy_data.required_methods,
                bypass_permissions=policy_data.bypass_permissions or [],
                created_at=policy.created_at.isoformat(),
                updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
            ),
        )
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Failed to create MFA policy", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create MFA policy")


@router.get("/", response_model=BaseResponse[MFAPolicyList])
async def list_mfa_policies(
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(require_permission("mfa.policy.read")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFAPolicyList]:
    """
    List MFA policies.

    Requires permission: mfa.policy.read
    """
    try:
        policy_service = MFAPolicyService(session)
        policies = await policy_service.list_policies(active_only=active_only, limit=limit, offset=offset)

        return BaseResponse(
            status="success",
            message="MFA policies retrieved",
            data=MFAPolicyList(policies=[MFAPolicyResponse(**policy) for policy in policies]),
        )
    except Exception as e:
        logger.error("Failed to list MFA policies", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list MFA policies")


@router.get("/{policy_id}", response_model=BaseResponse[MFAPolicyResponse])
async def get_mfa_policy(
    policy_id: str,
    current_user: User = Depends(require_permission("mfa.policy.read")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFAPolicyResponse]:
    """
    Get a specific MFA policy.

    Requires permission: mfa.policy.read
    """
    try:
        policy_service = MFAPolicyService(session)
        policies = await policy_service.list_policies(active_only=False)

        policy = next((p for p in policies if p["id"] == policy_id), None)
        if not policy:
            raise NotFoundError("MFA policy not found")

        return BaseResponse(status="success", message="MFA policy retrieved", data=MFAPolicyResponse(**policy))
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("Failed to get MFA policy", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get MFA policy")


@router.put("/{policy_id}", response_model=BaseResponse[MFAPolicyResponse])
async def update_mfa_policy(
    policy_id: str,
    policy_data: MFAPolicyUpdate,
    current_user: User = Depends(require_permission("mfa.policy.update")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[MFAPolicyResponse]:
    """
    Update an MFA policy.

    Requires permission: mfa.policy.update
    """
    try:
        policy_service = MFAPolicyService(session)

        # Build update dict from provided fields
        update_data = {"updated_by": current_user.username}

        if policy_data.name is not None:
            update_data["name"] = policy_data.name
        if policy_data.description is not None:
            update_data["description"] = policy_data.description
        if policy_data.is_active is not None:
            update_data["is_active"] = policy_data.is_active
        if policy_data.priority is not None:
            update_data["priority"] = policy_data.priority
        if policy_data.conditions is not None:
            update_data["conditions"] = policy_data.conditions.dict()
        if policy_data.required_methods is not None:
            update_data["required_methods"] = policy_data.required_methods
        if policy_data.min_methods is not None:
            update_data["min_methods"] = policy_data.min_methods
        if policy_data.grace_period_days is not None:
            update_data["grace_period_days"] = policy_data.grace_period_days
        if policy_data.enforcement_level is not None:
            update_data["enforcement_level"] = policy_data.enforcement_level
        if policy_data.bypass_permissions is not None:
            update_data["bypass_permissions"] = policy_data.bypass_permissions

        await policy_service.update_policy(policy_id, **update_data)

        await session.commit()

        # Get updated policy details
        policies = await policy_service.list_policies(active_only=False)
        policy_dict = next((p for p in policies if p["id"] == policy_id), None)

        return BaseResponse(
            status="success", message="MFA policy updated successfully", data=MFAPolicyResponse(**policy_dict)
        )
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Failed to update MFA policy", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update MFA policy")


@router.delete("/{policy_id}", response_model=BaseResponse[Dict[str, bool]])
async def delete_mfa_policy(
    policy_id: str,
    current_user: User = Depends(require_permission("mfa.policy.delete")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[Dict[str, bool]]:
    """
    Delete an MFA policy.

    Requires permission: mfa.policy.delete
    """
    try:
        policy_service = MFAPolicyService(session)
        success = await policy_service.delete_policy(policy_id=policy_id, deleted_by=current_user.username)

        await session.commit()

        return BaseResponse(
            status="success",
            message="MFA policy deleted" if success else "MFA policy not found",
            data={"deleted": success},
        )
    except Exception as e:
        logger.error("Failed to delete MFA policy", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete MFA policy")


@router.get("/check/{user_id}", response_model=BaseResponse[UserMFARequirement])
async def check_user_mfa_requirement(
    user_id: str,
    current_user: User = Depends(require_permission("mfa.policy.check")),
    session: AsyncSession = Depends(get_db_dependency),
) -> BaseResponse[UserMFARequirement]:
    """
    Check MFA requirements for a specific user.

    Requires permission: mfa.policy.check
    """
    try:
        # Get user
        from sqlalchemy import select

        from app.models.user import User as UserModel

        query = select(UserModel).where(UserModel.id == user_id)
        result = await session.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            raise NotFoundError("User not found")

        policy_service = MFAPolicyService(session)
        is_required, policy, details = await policy_service.check_mfa_requirement(user)

        return BaseResponse(
            status="success",
            message="MFA requirement checked",
            data=UserMFARequirement(
                user_id=user_id,
                username=user.username,
                is_required=details["required"],
                enforcement_level=details["enforcement_level"],
                policy_name=details.get("policy"),
                reason=details.get("reason"),
                grace_period_remaining=details.get("grace_period_remaining"),
                required_methods=details.get("required_methods", []),
                min_methods=details.get("min_methods", 1),
            ),
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("Failed to check MFA requirement", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to check MFA requirement")
