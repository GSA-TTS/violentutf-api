"""API Key Service with enhanced security features and business logic."""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from passlib.hash import argon2
from structlog.stdlib import get_logger

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.core.secrets_manager import create_secrets_manager
from app.models.api_key import APIKey
from app.repositories.api_key import APIKeyRepository
from app.schemas.api_key import APIKeyCreate, APIKeyResponse, APIKeyUpdate

logger = get_logger(__name__)


class APIKeyService:
    """Enhanced API key service with security features and business logic."""

    def __init__(self, repository: APIKeyRepository, secrets_manager=None) -> None:
        """Initialize API key service."""
        self.repository = repository
        self.secrets_manager = secrets_manager

    async def create_api_key(
        self,
        user_id: str,
        key_data: APIKeyCreate,
        entropy_bits: int = 256,
        key_format: str = "vutf",
    ) -> Tuple[APIKey, str]:
        """
        Create a new API key with enhanced security features.

        Args:
            user_id: User ID creating the key
            key_data: API key creation data
            entropy_bits: Entropy bits for key generation (default: 256)
            key_format: Key prefix format (default: "vutf")

        Returns:
            Tuple of (APIKey model, full_key_string)
        """
        # Validate key name uniqueness for user
        await self._validate_key_name_uniqueness(user_id, key_data.name)

        # Validate permissions
        self._validate_permissions(key_data.permissions)

        # Generate secure API key
        full_key, key_prefix, key_hash = self._generate_secure_key(entropy_bits, key_format)

        # Prepare API key data - decide hash storage strategy first
        if self.secrets_manager:
            # Use placeholder hash when using secrets manager
            initial_key_hash = key_hash  # Will be moved to secrets manager after creation
        else:
            # Store hash directly in database for fallback/testing
            initial_key_hash = key_hash

        api_key_data: Dict[str, Any] = {
            "name": key_data.name,
            "description": key_data.description,
            "key_hash": initial_key_hash,
            "key_prefix": key_prefix,
            "permissions": key_data.permissions,
            "expires_at": key_data.expires_at,
            "user_id": user_id,
            "created_by": user_id,
            "updated_by": user_id,
        }

        # Create API key
        api_key = await self.repository.create(api_key_data)

        # Store hash in secrets manager (secure storage)
        if self.secrets_manager:
            hash_stored = await self.secrets_manager.store_api_key_hash(str(api_key.id), key_hash)
            if not hash_stored:
                # Rollback API key creation if secrets manager fails
                await self.repository.delete(str(api_key.id))
                raise ValidationError("Failed to securely store API key hash")

            # Clear database hash since it's now in secrets manager
            await self.repository.update(str(api_key.id), key_hash="")
            api_key.key_hash = ""

            # Also store metadata for auditing and lifecycle management
            metadata = {
                "user_id": user_id,
                "name": key_data.name,
                "permissions": key_data.permissions,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": key_data.expires_at.isoformat() if key_data.expires_at else None,
            }
            await self.secrets_manager.store_api_key_metadata(str(api_key.id), metadata)

            logger.info("API key hash stored in secrets manager", api_key_id=str(api_key.id))
        else:
            # Hash is already stored in database during creation
            logger.warning("No secrets manager configured - storing hash in database", api_key_id=str(api_key.id))

        logger.info(
            "api_key_created",
            api_key_id=str(api_key.id),
            name=api_key.name,
            user_id=user_id,
            permissions=list(key_data.permissions.keys()),
            entropy_bits=entropy_bits,
        )

        return api_key, full_key

    async def rotate_api_key(self, key_id: str, user_id: str) -> Tuple[APIKey, str]:
        """
        Rotate an existing API key (generate new key value).

        Args:
            key_id: API key ID to rotate
            user_id: User ID requesting rotation

        Returns:
            Tuple of (updated APIKey model, new_full_key)
        """
        # Get existing key
        api_key = await self.repository.get(key_id)
        if not api_key:
            raise NotFoundError(detail=f"API key with ID {key_id} not found")

        # Check ownership
        if api_key.user_id != user_id:
            raise ForbiddenError(detail="You can only rotate your own API keys")

        # Check if key is active
        if not api_key.is_active():
            raise ValidationError(detail="Cannot rotate an inactive API key")

        # Generate new key
        full_key, key_prefix, key_hash = self._generate_secure_key()

        # Update key with new values
        update_data = {
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "updated_by": user_id,
        }

        updated_key = await self.repository.update(key_id, update_data)

        logger.info(
            "api_key_rotated",
            api_key_id=key_id,
            name=updated_key.name,
            user_id=user_id,
        )

        return updated_key, full_key

    async def rotate_api_key_enhanced(
        self, key_id: str, user_id: str, store_in_secrets_manager: bool = True
    ) -> Tuple[APIKey, str]:
        """
        Enhanced API key rotation with secrets manager integration.

        Args:
            key_id: API key ID to rotate
            user_id: User ID requesting rotation
            store_in_secrets_manager: Whether to store metadata in secrets manager

        Returns:
            Tuple of (updated APIKey model, new_full_key)
        """
        # Get existing key
        api_key = await self.repository.get(key_id)
        if not api_key:
            raise NotFoundError(detail=f"API key with ID {key_id} not found")

        # Check ownership
        if api_key.user_id != user_id:
            raise ForbiddenError(detail="You can only rotate your own API keys")

        # Check if key is active
        if not api_key.is_active():
            raise ValidationError(detail="Cannot rotate an inactive API key")

        # Generate new key with enhanced entropy
        full_key, key_prefix, key_hash = self._generate_secure_key(entropy_bits=512, key_format="vutf")

        # Store old key hash for audit purposes
        old_key_hash = api_key.key_hash

        # Store new hash in secrets manager if available
        if self.secrets_manager:
            # Store hash in secrets manager (secure storage)
            hash_success = await self.secrets_manager.store_api_key_hash(key_id, key_hash)
            if hash_success:
                # Update key with new values (no hash in database)
                update_data = {
                    "key_hash": "",  # Clear database hash for security
                    "key_prefix": key_prefix,
                    "updated_by": user_id,
                }
            else:
                logger.warning(
                    "Failed to store rotated hash in secrets manager, using database fallback", key_id=key_id
                )
                # Fallback to database storage
                update_data = {
                    "key_hash": key_hash,
                    "key_prefix": key_prefix,
                    "updated_by": user_id,
                }
        else:
            # No secrets manager available, store in database (fallback)
            update_data = {
                "key_hash": key_hash,
                "key_prefix": key_prefix,
                "updated_by": user_id,
            }

        updated_key = await self.repository.update(key_id, **update_data)

        # Store metadata in secrets manager if enabled
        if store_in_secrets_manager and self.secrets_manager:
            metadata = {
                "key_id": key_id,
                "user_id": user_id,
                "rotated_at": datetime.now(timezone.utc).isoformat(),
                "previous_hash_preview": old_key_hash[:16] + "..." if old_key_hash else None,
                "permissions": updated_key.permissions,
                "expires_at": updated_key.expires_at.isoformat() if updated_key.expires_at else None,
            }
            await self.secrets_manager.store_api_key_metadata(key_id, metadata)

        logger.info(
            "api_key_rotated_enhanced",
            api_key_id=key_id,
            name=updated_key.name,
            user_id=user_id,
            stored_in_secrets_manager=store_in_secrets_manager and self.secrets_manager is not None,
        )

        return updated_key, full_key

    async def validate_api_key(self, key_value: str) -> Optional[APIKey]:
        """
        Validate an API key using secure Argon2 verification with SHA256 fallback.

        Args:
            key_value: Full API key string to validate

        Returns:
            APIKey model if valid, None if invalid
        """
        if not key_value or not key_value.startswith("vutf_"):
            logger.debug("Invalid API key format", key_format=key_value[:10] if key_value else None)
            return None

        key_prefix = key_value[:10]

        # Get all API keys with matching prefix
        potential_keys = await self.repository.get_by_prefix(key_prefix)

        if not potential_keys:
            logger.debug("No API keys found with prefix", key_prefix=key_prefix)
            return None

        # Try to verify against each potential key
        for api_key in potential_keys:
            stored_hash = None
            hash_source = "database"

            # Priority 1: Try to get hash from secrets manager (more secure)
            if self.secrets_manager:
                try:
                    stored_hash = await self.secrets_manager.get_api_key_hash(str(api_key.id))
                    if stored_hash:
                        hash_source = "secrets_manager"
                        logger.debug("Retrieved hash from secrets manager", key_id=str(api_key.id))
                except Exception as e:
                    logger.warning("Failed to retrieve hash from secrets manager", key_id=str(api_key.id), error=str(e))

            # Priority 2: Fallback to database hash (for backward compatibility)
            if not stored_hash and api_key.key_hash:
                stored_hash = api_key.key_hash
                hash_source = "database"
                logger.debug("Using database hash (fallback)", key_id=str(api_key.id))

            if not stored_hash:
                logger.warning("No hash found for API key", key_id=str(api_key.id))
                continue

            # Verify the hash
            if await self._verify_key_hash(key_value, stored_hash):
                # Found matching key, check if it's active
                if not api_key.is_active():
                    logger.debug("API key found but inactive", key_id=str(api_key.id))
                    return None

                # Migration logic: Move database hashes to secrets manager
                if hash_source == "database" and self.secrets_manager:
                    # Migrate hash to secrets manager for better security
                    import asyncio

                    asyncio.create_task(self._migrate_hash_to_secrets_manager(api_key, stored_hash))

                # Legacy SHA256 migration (if still needed)
                if len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
                    # Schedule Argon2 migration (don't wait for completion)
                    import asyncio

                    asyncio.create_task(self._migrate_legacy_key(api_key, key_value))

                # Log successful validation
                logger.info(
                    "API key validated successfully",
                    key_id=str(api_key.id),
                    user_id=str(api_key.user_id),
                    hash_source=hash_source,
                )
                return api_key

        logger.debug(
            "API key validation failed - no matching hash", key_prefix=key_prefix, candidates=len(potential_keys)
        )
        return None

    async def record_key_usage(self, api_key: APIKey, ip_address: Optional[str] = None) -> None:
        """
        Record usage of an API key.

        Args:
            api_key: API key model
            ip_address: Optional IP address of the request
        """
        api_key.record_usage(ip_address)
        # Repository handles persistence automatically

        logger.debug(
            "api_key_usage_recorded",
            api_key_id=str(api_key.id),
            usage_count=api_key.usage_count,
            ip_address=ip_address,
        )

    async def get_user_keys(
        self,
        user_id: str,
        include_revoked: bool = False,
        include_expired: bool = False,
    ) -> List[APIKey]:
        """
        Get all API keys for a user with optional filtering.

        Args:
            user_id: User ID
            include_revoked: Include revoked keys
            include_expired: Include expired keys

        Returns:
            List of API key models
        """
        keys = await self.repository.list_user_keys(user_id)

        # Filter based on options
        filtered_keys = []
        for key in keys:
            # Skip revoked keys if not requested
            if not include_revoked and key.revoked_at:
                continue

            # Skip expired keys if not requested
            if not include_expired and key.expires_at and key.expires_at < datetime.now(timezone.utc):
                continue

            filtered_keys.append(key)

        return filtered_keys

    async def revoke_api_key(self, key_id: str, user_id: str, admin_override: bool = False) -> bool:
        """
        Revoke an API key.

        Args:
            key_id: API key ID to revoke
            user_id: User ID requesting revocation
            admin_override: Allow admin to revoke any key

        Returns:
            True if key was revoked successfully
        """
        # Get existing key
        api_key = await self.repository.get(key_id)
        if not api_key:
            raise NotFoundError(detail=f"API key with ID {key_id} not found")

        # Check ownership unless admin override
        if not admin_override and api_key.user_id != user_id:
            raise ForbiddenError(detail="You can only revoke your own API keys")

        # Revoke the key
        success = await self.repository.revoke(key_id)

        if success:
            logger.info(
                "api_key_revoked",
                api_key_id=key_id,
                name=api_key.name,
                user_id=user_id,
                admin_override=admin_override,
            )

        return success

    async def get_key_analytics(self, user_id: str) -> Dict[str, Any]:
        """
        Get API key analytics for a user.

        Args:
            user_id: User ID

        Returns:
            Analytics data dictionary
        """
        user_keys = await self.repository.list_user_keys(user_id)

        analytics = {
            "total_keys": len(user_keys),
            "active_keys": len([k for k in user_keys if k.is_active()]),
            "revoked_keys": len([k for k in user_keys if k.revoked_at]),
            "expired_keys": len([k for k in user_keys if k.expires_at and k.expires_at < datetime.now(timezone.utc)]),
            "total_usage": sum(k.usage_count for k in user_keys),
            "keys_by_permissions": self._analyze_permissions(user_keys),
            "recent_usage": self._analyze_recent_usage(user_keys),
        }

        return analytics

    def _generate_secure_key(self, entropy_bits: int = 256, key_format: str = "vutf") -> Tuple[str, str, str]:
        """
        Generate a cryptographically secure API key.

        Args:
            entropy_bits: Number of entropy bits (default: 256)
            key_format: Key prefix format (default: "vutf")

        Returns:
            Tuple of (full_key, key_prefix, key_hash)
        """
        # Calculate required bytes for entropy
        entropy_bytes = entropy_bits // 8

        # Convert to URL-safe base64
        key_base = secrets.token_urlsafe(entropy_bytes)

        # Create full key with prefix
        full_key = f"{key_format}_{key_base}"

        # Create prefix for identification (first 10 chars max, per model validation)
        key_prefix = full_key[:10]

        # Create Argon2 hash (secure against rainbow table attacks)
        # NOTE: New API keys use Argon2, existing keys still use SHA256 for compatibility
        key_hash = argon2.hash(full_key)

        return full_key, key_prefix, key_hash

    async def _verify_key_hash(self, key_value: str, stored_hash: str) -> bool:
        """
        Verify API key against stored hash supporting both Argon2 and SHA256.

        Args:
            key_value: Plain API key value
            stored_hash: Stored hash from database

        Returns:
            True if key matches hash, False otherwise
        """
        try:
            # Detect hash type based on format
            if stored_hash.startswith("$argon2"):
                # Argon2 hash verification
                return argon2.verify(key_value, stored_hash)
            elif len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
                # SHA256 hash verification (legacy support)
                import hashlib

                computed_hash = hashlib.sha256(key_value.encode()).hexdigest()
                return computed_hash == stored_hash
            else:
                # Unknown hash format
                logger.warning("Unknown API key hash format", hash_prefix=stored_hash[:20])
                return False

        except Exception as e:
            # Log verification errors but don't expose them
            logger.error(
                "API key verification error",
                error=str(e),
                hash_type="argon2" if stored_hash.startswith("$argon2") else "sha256",
            )
            return False

    async def _migrate_hash_to_secrets_manager(self, api_key: APIKey, hash_value: str) -> bool:
        """
        Migrate API key hash from database to secrets manager.

        Args:
            api_key: API key model to migrate
            hash_value: Hash value to migrate

        Returns:
            True if migration successful, False otherwise
        """
        try:
            if not self.secrets_manager:
                return False

            # Store hash in secrets manager
            success = await self.secrets_manager.store_api_key_hash(str(api_key.id), hash_value)
            if success:
                # Clear hash from database after successful migration
                await self.repository.update(str(api_key.id), key_hash="")

                logger.info(
                    "Successfully migrated API key hash to secrets manager",
                    key_id=str(api_key.id),
                    algorithm="argon2" if hash_value.startswith("$argon2") else "sha256",
                )
                return True
            else:
                logger.error("Failed to migrate API key hash to secrets manager", key_id=str(api_key.id))
                return False

        except Exception as e:
            logger.error("Exception during hash migration to secrets manager", key_id=str(api_key.id), error=str(e))
            return False

    async def _migrate_legacy_key(self, api_key: APIKey, key_value: str) -> bool:
        """
        Migrate legacy SHA256 key to Argon2 on successful verification.

        Args:
            api_key: API key model to migrate
            key_value: Plain key value for re-hashing

        Returns:
            True if migration successful, False otherwise
        """
        try:
            # Only migrate SHA256 keys
            if not (len(api_key.key_hash) == 64 and all(c in "0123456789abcdef" for c in api_key.key_hash.lower())):
                return False

            # Generate new Argon2 hash
            new_hash = argon2.hash(key_value)

            # Preferred: Store in secrets manager if available
            if self.secrets_manager:
                success = await self.secrets_manager.store_api_key_hash(str(api_key.id), new_hash)
                if success:
                    # Clear hash from database after successful secrets manager storage
                    await self.repository.update(str(api_key.id), key_hash="")
                    logger.info("API key migrated to Argon2 in secrets manager", key_id=str(api_key.id))
                    return True
                else:
                    logger.error("Failed to store migrated Argon2 hash in secrets manager", key_id=str(api_key.id))
                    # Fall through to database storage

            # Fallback: Update the key hash in database
            success = await self.repository.update(str(api_key.id), key_hash=new_hash)

            if success:
                logger.info("API key migrated to Argon2 in database (fallback)", key_id=str(api_key.id))
                return True
            else:
                logger.error("Failed to migrate API key to Argon2", key_id=str(api_key.id))
                return False

        except Exception as e:
            logger.error("API key migration error", key_id=str(api_key.id), error=str(e))
            return False

    async def _validate_key_name_uniqueness(self, user_id: str, key_name: str) -> None:
        """Validate that the API key name is unique for the user."""
        existing_keys = await self.repository.list_user_keys(user_id)
        if any(key.name == key_name for key in existing_keys):
            raise ConflictError(message=f"API key with name '{key_name}' already exists")

    def _validate_permissions(self, permissions: Dict[str, Any]) -> None:
        """
        Validate permission structure and values.

        Args:
            permissions: Permissions dictionary to validate
        """
        if not isinstance(permissions, dict):
            raise ValidationError(detail="Permissions must be a dictionary")

        # Define valid permission scopes
        VALID_SCOPES = {
            # Global permissions
            "read",
            "write",
            "delete",
            "admin",
            "*",
            # Resource-specific permissions
            "users:read",
            "users:write",
            "users:delete",
            "users:*",
            "api_keys:read",
            "api_keys:write",
            "api_keys:delete",
            "api_keys:*",
            "sessions:read",
            "sessions:write",
            "sessions:delete",
            "sessions:*",
            "audit_logs:read",
            "audit_logs:*",
            # Additional resource types
            "projects:read",
            "projects:write",
            "projects:delete",
            "projects:*",
            "reports:read",
            "reports:write",
            "reports:delete",
            "reports:*",
        }

        for scope, enabled in permissions.items():
            # Check if scope is valid or follows pattern
            if scope not in VALID_SCOPES and not scope.endswith(":*"):
                raise ValidationError(detail=f"Invalid permission scope: {scope}")

            # Permissions must be boolean
            if not isinstance(enabled, bool):
                raise ValidationError(detail=f"Permission value for '{scope}' must be boolean")

    def _analyze_permissions(self, keys: List[APIKey]) -> Dict[str, int]:
        """Analyze permission distribution across keys."""
        permission_counts: Dict[str, int] = {}
        for key in keys:
            for permission in key.permissions.keys():
                permission_counts[permission] = permission_counts.get(permission, 0) + 1
        return permission_counts

    def _analyze_recent_usage(self, keys: List[APIKey]) -> Dict[str, Any]:
        """Analyze recent usage patterns."""
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(days=1)
        last_7d = now - timedelta(days=7)

        recent_usage = {
            "keys_used_24h": len([k for k in keys if k.last_used_at and k.last_used_at >= last_24h]),
            "keys_used_7d": len([k for k in keys if k.last_used_at and k.last_used_at >= last_7d]),
            "total_requests_24h": sum(k.usage_count for k in keys if k.last_used_at and k.last_used_at >= last_24h),
            "most_active_key": None,
        }

        # Find most active key
        if keys:
            most_active = max(keys, key=lambda k: k.usage_count)
            recent_usage["most_active_key"] = {
                "name": most_active.name,
                "usage_count": most_active.usage_count,
                "last_used": most_active.last_used_at.isoformat() if most_active.last_used_at else None,
            }

        return recent_usage
