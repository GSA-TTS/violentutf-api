"""Initialize default MFA policies."""

import asyncio
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.services.mfa_policy_service import MFAPolicyService


async def create_default_policies(session: AsyncSession) -> List[str]:
    """Create default MFA policies."""
    policy_service = MFAPolicyService(session)
    created_policies = []

    # Policy 1: Superuser MFA (Required)
    try:
        policy = await policy_service.create_policy(
            name="Superuser MFA Policy",
            description="Require MFA for all superusers with no exceptions",
            conditions={"is_superuser": True},
            required_methods=["totp", "webauthn"],
            min_methods=1,
            grace_period_days=0,  # No grace period for superusers
            enforcement_level="required",
            priority=1000,  # Highest priority
            created_by="system",
        )
        created_policies.append(f"Created: {policy.name}")
    except Exception as e:
        created_policies.append(f"Failed to create Superuser MFA Policy: {e}")

    # Policy 2: Admin Role MFA (Required with grace period)
    try:
        policy = await policy_service.create_policy(
            name="Admin Role MFA Policy",
            description="Require MFA for users with admin role, with 7-day grace period",
            conditions={"roles": ["admin"]},
            required_methods=["totp", "sms", "email"],
            min_methods=1,
            grace_period_days=7,
            enforcement_level="required",
            bypass_permissions=["mfa.bypass.admin"],
            priority=900,
            created_by="system",
        )
        created_policies.append(f"Created: {policy.name}")
    except Exception as e:
        created_policies.append(f"Failed to create Admin Role MFA Policy: {e}")

    # Policy 3: Sensitive Permissions MFA (Required)
    try:
        policy = await policy_service.create_policy(
            name="Sensitive Operations MFA Policy",
            description="Require MFA for users with sensitive permissions",
            conditions={
                "permissions": [
                    "user.delete",
                    "api_key.delete",
                    "organization.delete",
                    "rbac.role.delete",
                    "mfa.policy.delete",
                ]
            },
            required_methods=["totp"],
            min_methods=1,
            grace_period_days=3,
            enforcement_level="required",
            priority=800,
            created_by="system",
        )
        created_policies.append(f"Created: {policy.name}")
    except Exception as e:
        created_policies.append(f"Failed to create Sensitive Operations MFA Policy: {e}")

    # Policy 4: Organization-specific MFA (Recommended)
    try:
        policy = await policy_service.create_policy(
            name="Enterprise Organization MFA Policy",
            description="Recommend MFA for enterprise organization users",
            conditions={"organization_ids": [], "min_account_age_days": 1},  # To be filled with actual org IDs
            required_methods=["totp", "sms", "webauthn"],
            min_methods=1,
            grace_period_days=30,
            enforcement_level="recommended",
            priority=500,
            created_by="system",
        )
        created_policies.append(f"Created: {policy.name}")
    except Exception as e:
        created_policies.append(f"Failed to create Enterprise Organization MFA Policy: {e}")

    # Policy 5: New User MFA (Optional with long grace period)
    try:
        policy = await policy_service.create_policy(
            name="New User MFA Policy",
            description="Optional MFA for new users with 90-day grace period",
            conditions={"min_account_age_days": 0, "roles": ["user"]},
            required_methods=["totp", "sms", "email", "backup_code"],
            min_methods=1,
            grace_period_days=90,
            enforcement_level="optional",
            priority=100,
            created_by="system",
        )
        created_policies.append(f"Created: {policy.name}")
    except Exception as e:
        created_policies.append(f"Failed to create New User MFA Policy: {e}")

    await session.commit()
    return created_policies


async def main() -> None:
    """Main function to create default policies."""
    async with AsyncSessionLocal() as session:
        print("Creating default MFA policies...")
        results = await create_default_policies(session)
        for result in results:
            print(f"  {result}")
        print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
