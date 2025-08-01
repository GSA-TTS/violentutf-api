"""API Key repository with permission and authentication methods."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ..models.api_key import APIKey
from .base import BaseRepository

logger = get_logger(__name__)


class APIKeyRepository(BaseRepository[APIKey]):
    """
    API Key repository with authentication and permission management.

    Extends base repository with API key specific functionality
    following patterns from original ViolentUTF repository.
    """

    def __init__(self, session: AsyncSession):
        """Initialize API key repository."""
        super().__init__(session, APIKey)

    async def get_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """
        Get API key by hash.

        Args:
            key_hash: SHA256 hash of the API key

        Returns:
            APIKey if found and valid, None otherwise
        """
        try:
            query = select(self.model).where(
                and_(self.model.key_hash == key_hash, self.model.is_deleted == False)  # noqa: E712
            )

            result = await self.session.execute(query)
            api_key = result.scalar_one_or_none()

            if api_key:
                # Check if key is expired
                if api_key.is_expired():
                    self.logger.debug("API key found but expired", key_hash=key_hash[:8] + "...")
                    return None

                self.logger.debug("API key found", key_hash=key_hash[:8] + "...")
            else:
                self.logger.debug("API key not found", key_hash=key_hash[:8] + "...")

            return api_key

        except Exception as e:
            self.logger.error("Failed to get API key by hash", key_hash=key_hash[:8] + "...", error=str(e))
            raise

    async def get_by_prefix(self, key_prefix: str) -> List[APIKey]:
        """
        Get API keys by prefix (for identification purposes).

        Args:
            key_prefix: Key prefix to search for

        Returns:
            List of matching API keys
        """
        try:
            query = (
                select(self.model)
                .where(and_(self.model.key_prefix == key_prefix, self.model.is_deleted == False))  # noqa: E712
                .order_by(self.model.created_at.desc())
            )

            result = await self.session.execute(query)
            api_keys = list(result.scalars().all())

            self.logger.debug("API keys found by prefix", key_prefix=key_prefix, count=len(api_keys))
            return api_keys

        except Exception as e:
            self.logger.error("Failed to get API keys by prefix", key_prefix=key_prefix, error=str(e))
            raise

    async def get_by_user_id(self, user_id: str, include_expired: bool = False) -> List[APIKey]:
        """
        Get all API keys for a user.

        Args:
            user_id: User identifier
            include_expired: Whether to include expired keys

        Returns:
            List of user's API keys
        """
        try:
            query = (
                select(self.model)
                .where(and_(self.model.user_id == user_id, self.model.is_deleted == False))  # noqa: E712
                .order_by(self.model.created_at.desc())
            )

            result = await self.session.execute(query)
            api_keys = list(result.scalars().all())

            # Filter out expired keys if requested
            if not include_expired:
                api_keys = [key for key in api_keys if not key.is_expired()]

            self.logger.debug(
                "API keys found for user", user_id=user_id, count=len(api_keys), include_expired=include_expired
            )
            return api_keys

        except Exception as e:
            self.logger.error("Failed to get API keys for user", user_id=user_id, error=str(e))
            raise

    async def create_api_key(
        self,
        user_id: str,
        name: str,
        key_hash: str,
        key_prefix: str,
        permissions: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        created_by: str = "system",
    ) -> APIKey:
        """
        Create a new API key.

        Args:
            user_id: Owner user identifier
            name: Descriptive name for the key
            key_hash: SHA256 hash of the API key
            key_prefix: First few characters of key for identification
            permissions: Optional permission scopes
            description: Optional detailed description
            expires_at: Optional expiration timestamp
            created_by: User who created the key

        Returns:
            Created API key

        Raises:
            ValueError: If name already exists for user or validation fails
        """
        try:
            # Check if name already exists for this user
            existing_key = await self.get_by_name_and_user(name, user_id)
            if existing_key:
                raise ValueError(f"API key name '{name}' already exists for this user")

            # Validate key hash format (should be 64-character SHA256)
            if not key_hash or len(key_hash) != 64:
                raise ValueError("key_hash must be a valid SHA256 hash (64 characters)")

            # Validate key prefix format (should be at least 6 characters)
            if not key_prefix or len(key_prefix) < 6:
                raise ValueError("key_prefix must be at least 6 characters")

            # Create API key
            api_key_data: Dict[str, Any] = {
                "user_id": user_id,
                "name": name,
                "key_hash": key_hash,
                "key_prefix": key_prefix,
                "permissions": permissions or {},
                "description": description,
                "expires_at": expires_at,
                "usage_count": 0,
                "created_by": created_by,
                "updated_by": created_by,
            }

            api_key = await self.create(api_key_data)

            self.logger.info(
                "API key created successfully",
                api_key_id=api_key.id,
                user_id=user_id,
                name=name,
                key_prefix=key_prefix,
                has_expiration=expires_at is not None,
                created_by=created_by,
            )

            return api_key

        except Exception as e:
            self.logger.error("Failed to create API key", user_id=user_id, name=name, error=str(e))
            raise

    async def get_by_name_and_user(self, name: str, user_id: str) -> Optional[APIKey]:
        """
        Get API key by name and user ID.

        Args:
            name: API key name
            user_id: User identifier

        Returns:
            APIKey if found, None otherwise
        """
        try:
            query = select(self.model).where(
                and_(
                    self.model.name == name, self.model.user_id == user_id, self.model.is_deleted == False  # noqa: E712
                )
            )

            result = await self.session.execute(query)
            api_key = result.scalar_one_or_none()

            if api_key:
                self.logger.debug("API key found by name and user", name=name, user_id=user_id)
            else:
                self.logger.debug("API key not found by name and user", name=name, user_id=user_id)

            return api_key

        except Exception as e:
            self.logger.error("Failed to get API key by name and user", name=name, user_id=user_id, error=str(e))
            raise

    async def record_usage(
        self,
        api_key_id: str,
        ip_address: Optional[str] = None,
        usage_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Record API key usage.

        Args:
            api_key_id: API key identifier
            ip_address: Optional IP address of the request
            usage_metadata: Optional metadata about the usage

        Returns:
            True if usage was recorded, False if key not found
        """
        try:
            # Update usage statistics
            update_data = {
                "usage_count": self.model.usage_count + 1,
                "last_used_at": datetime.now(timezone.utc),
                "updated_by": "system",
            }

            if ip_address:
                update_data["last_used_ip"] = ip_address

            # Increment version for optimistic locking
            current_key = await self.get_by_id(api_key_id)
            if current_key:
                update_data["version"] = current_key.version + 1

                updated_key = await self.update(api_key_id, **update_data)
                success = updated_key is not None

                if success:
                    self.logger.debug(
                        "API key usage recorded",
                        api_key_id=api_key_id,
                        usage_count=(current_key.usage_count or 0) + 1,
                        ip_address=ip_address,
                    )
                else:
                    self.logger.warning("API key not found for usage recording", api_key_id=api_key_id)

                return success
            else:
                self.logger.warning("API key not found for usage recording", api_key_id=api_key_id)
                return False

        except Exception as e:
            self.logger.error("Failed to record API key usage", api_key_id=api_key_id, error=str(e))
            raise

    async def check_permission(self, api_key_id: str, permission: str) -> bool:
        """
        Check if API key has a specific permission.

        Args:
            api_key_id: API key identifier
            permission: Permission to check (e.g., "read", "write", "admin")

        Returns:
            True if permission is granted, False otherwise
        """
        try:
            api_key = await self.get_by_id(api_key_id)
            if not api_key:
                self.logger.debug("API key not found for permission check", api_key_id=api_key_id)
                return False

            # Check if key is expired
            if api_key.is_expired():
                self.logger.debug("API key expired for permission check", api_key_id=api_key_id)
                return False

            has_permission = api_key.has_permission(permission)

            self.logger.debug(
                "API key permission checked",
                api_key_id=api_key_id,
                permission=permission,
                has_permission=has_permission,
            )

            return has_permission

        except Exception as e:
            self.logger.error(
                "Failed to check API key permission", api_key_id=api_key_id, permission=permission, error=str(e)
            )
            raise

    async def update_permissions(
        self,
        api_key_id: str,
        permissions: Dict[str, Any],
        updated_by: str = "system",
    ) -> bool:
        """
        Update API key permissions.

        Args:
            api_key_id: API key identifier
            permissions: New permission dictionary
            updated_by: User who updated the permissions

        Returns:
            True if permissions were updated, False if key not found
        """
        try:
            updated_key = await self.update(api_key_id, permissions=permissions, updated_by=updated_by)

            success = updated_key is not None

            if success:
                self.logger.info(
                    "API key permissions updated",
                    api_key_id=api_key_id,
                    permissions=permissions,
                    updated_by=updated_by,
                )
            else:
                self.logger.warning("API key not found for permission update", api_key_id=api_key_id)

            return success

        except Exception as e:
            self.logger.error("Failed to update API key permissions", api_key_id=api_key_id, error=str(e))
            raise

    async def extend_expiration(
        self,
        api_key_id: str,
        new_expires_at: Optional[datetime],
        updated_by: str = "system",
    ) -> bool:
        """
        Update API key expiration date.

        Args:
            api_key_id: API key identifier
            new_expires_at: New expiration timestamp (None for no expiration)
            updated_by: User who updated the expiration

        Returns:
            True if expiration was updated, False if key not found
        """
        try:
            # Special handling for setting expires_at to None (remove expiration)
            # We can't use the base update method because it filters out None values
            if new_expires_at is None:
                from sqlalchemy import update
                from sqlalchemy.sql import func

                update_query = (
                    update(self.model)
                    .where(self.model.id == api_key_id)
                    .values(expires_at=None, updated_by=updated_by, updated_at=func.now())
                )

                result = await self.session.execute(update_query)
                success = result.rowcount > 0

                if success:
                    self.logger.info(
                        "API key expiration removed",
                        api_key_id="***REDACTED***",
                        updated_by=updated_by,
                    )
            else:
                # For non-None values, use the regular update method
                updated_key = await self.update(api_key_id, expires_at=new_expires_at, updated_by=updated_by)
                success = updated_key is not None

            if success:
                self.logger.info(
                    "API key expiration updated",
                    api_key_id=api_key_id,
                    new_expires_at=new_expires_at,
                    updated_by=updated_by,
                )
            else:
                self.logger.warning("API key not found for expiration update", api_key_id=api_key_id)

            return success

        except Exception as e:
            self.logger.error("Failed to update API key expiration", api_key_id=api_key_id, error=str(e))
            raise

    async def get_expired_keys(self, limit: int = 100) -> List[APIKey]:
        """
        Get expired API keys for cleanup.

        Args:
            limit: Maximum number of keys to return

        Returns:
            List of expired API keys
        """
        try:
            current_time = datetime.now(timezone.utc)

            query = (
                select(self.model)
                .where(and_(self.model.expires_at < current_time, self.model.is_deleted == False))  # noqa: E712
                .order_by(self.model.expires_at.asc())
                .limit(limit)
            )

            result = await self.session.execute(query)
            expired_keys = list(result.scalars().all())

            self.logger.debug("Expired API keys found", count=len(expired_keys))
            return expired_keys

        except Exception as e:
            self.logger.error("Failed to get expired API keys", error=str(e))
            raise

    async def validate(self, key: str) -> Optional[APIKey]:
        """
        Validate an API key string and return the APIKey if valid.

        Args:
            key: The raw API key string to validate

        Returns:
            APIKey instance if valid and active, None otherwise
        """
        try:
            # Hash the provided key for lookup
            import hashlib

            key_hash = hashlib.sha256(key.encode()).hexdigest()

            # Find the API key by hash
            query = select(self.model).where(and_(self.model.key_hash == key_hash, self.model.is_deleted == False))

            result = await self.session.execute(query)
            api_key = result.scalar_one_or_none()

            if api_key and api_key.is_active():
                return api_key

            return None

        except Exception as e:
            self.logger.error("Failed to validate API key", error=str(e))
            raise

    async def revoke(self, key_id: str) -> bool:
        """
        Revoke an API key by setting its revoked_at timestamp.

        Args:
            key_id: The ID of the API key to revoke

        Returns:
            True if successfully revoked, False if not found
        """
        try:
            # Find the API key
            api_key = await self.get_by_id(key_id)

            if not api_key:
                self.logger.warning("API key not found for revocation", key_id=key_id)
                return False

            # Set revoked timestamp
            from datetime import datetime, timezone

            api_key.revoked_at = datetime.now(timezone.utc)

            # Save changes
            await self.session.commit()

            self.logger.info("API key revoked successfully", key_id=key_id)
            return True

        except Exception as e:
            self.logger.error("Failed to revoke API key", key_id=key_id, error=str(e))
            await self.session.rollback()
            raise

    async def list_user_keys(self, user_id: str) -> List[APIKey]:
        """
        List all active API keys for a specific user.

        Args:
            user_id: The ID of the user

        Returns:
            List of active APIKey instances for the user
        """
        try:
            # Convert user_id to UUID
            import uuid

            user_uuid = uuid.UUID(user_id)

            # Query user's active API keys
            query = (
                select(self.model)
                .where(
                    and_(
                        self.model.user_id == user_uuid, self.model.is_deleted == False, self.model.revoked_at.is_(None)
                    )
                )
                .order_by(self.model.created_at.desc())
            )

            result = await self.session.execute(query)
            api_keys = result.scalars().all()

            self.logger.debug("Listed user API keys", user_id=str(user_uuid), count=len(api_keys))
            return list(api_keys)

        except Exception as e:
            self.logger.error("Failed to list user API keys", user_id=str(user_id), error=str(e))
            raise

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get API key usage statistics.

        Returns:
            Dictionary containing various statistics
        """
        try:
            # Total keys count
            total_query = select(func.count(self.model.id))
            total_result = await self.session.execute(total_query)
            total_keys = total_result.scalar() or 0

            # Active keys count
            active_query = select(func.count(self.model.id)).where(
                and_(
                    self.model.is_deleted == False,
                    self.model.revoked_at.is_(None),
                    or_(self.model.expires_at.is_(None), self.model.expires_at > datetime.now(timezone.utc)),
                )
            )
            active_result = await self.session.execute(active_query)
            active_keys = active_result.scalar() or 0

            # Expired keys count
            expired_query = select(func.count(self.model.id)).where(
                and_(self.model.expires_at.is_not(None), self.model.expires_at <= datetime.now(timezone.utc))
            )
            expired_result = await self.session.execute(expired_query)
            expired_keys = expired_result.scalar() or 0

            # Revoked keys count
            revoked_query = select(func.count(self.model.id)).where(self.model.revoked_at.is_not(None))
            revoked_result = await self.session.execute(revoked_query)
            revoked_keys = revoked_result.scalar() or 0

            # Keys used today
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            used_today_query = select(func.count(self.model.id)).where(
                and_(self.model.last_used_at.is_not(None), self.model.last_used_at >= today_start)
            )
            used_today_result = await self.session.execute(used_today_query)
            keys_used_today = used_today_result.scalar() or 0

            # Total requests
            total_requests_query = select(func.sum(self.model.usage_count))
            total_requests_result = await self.session.execute(total_requests_query)
            total_requests = total_requests_result.scalar() or 0

            return {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "expired_keys": expired_keys,
                "revoked_keys": revoked_keys,
                "keys_used_today": keys_used_today,
                "total_requests": total_requests,
            }

        except Exception as e:
            self.logger.error("Failed to get API key statistics", error=str(e))
            raise
