"""Secrets manager abstraction layer with multiple provider support."""

import datetime
import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field
from structlog.stdlib import get_logger

logger = get_logger(__name__)


class SecretData(BaseModel):
    """Secret data model for structured secret storage."""

    value: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


class SecretsManagerProvider(ABC):
    """Abstract base class for secrets manager providers."""

    @abstractmethod
    async def get_secret(self, secret_name: str) -> Optional[SecretData]:
        """Get a secret by name."""
        pass

    @abstractmethod
    async def store_secret(
        self, secret_name: str, secret_value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store a secret."""
        pass

    @abstractmethod
    async def delete_secret(self, secret_name: str) -> bool:
        """Delete a secret."""
        pass

    @abstractmethod
    async def list_secrets(self, prefix: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """List secrets with optional prefix filter."""
        pass

    @abstractmethod
    async def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """Rotate a secret to a new value."""
        pass


class FileSecretsManager(SecretsManagerProvider):
    """File-based secrets manager for development/testing."""

    def __init__(self, secrets_dir: str = "./data/secrets"):
        """Initialize file-based secrets manager."""
        self.secrets_dir = secrets_dir
        os.makedirs(secrets_dir, exist_ok=True)
        # Keep track of original names for reverse mapping
        self._name_mapping: Dict[str, str] = {}  # filename -> original_secret_name
        logger.info("Initialized file-based secrets manager", secrets_dir=secrets_dir)

    def _get_secret_path(self, secret_name: str) -> str:
        """Get file path for secret."""
        safe_name = secret_name.replace("/", "__SLASH__").replace("\\", "__BACKSLASH__")
        filename = f"{safe_name}.json"
        # Store the mapping for reverse lookup
        self._name_mapping[filename] = secret_name
        return os.path.join(self.secrets_dir, filename)

    def _get_secret_name_from_filename(self, filename: str) -> str:
        """Convert filename back to original secret name."""
        # First try to get from mapping
        if filename in self._name_mapping:
            return self._name_mapping[filename]

        # Fallback: reverse the encoding process
        if filename.endswith(".json"):
            base_name = filename[:-5]
        else:
            base_name = filename

        # Reverse the safe encoding
        return base_name.replace("__SLASH__", "/").replace("__BACKSLASH__", "\\")

    def _rebuild_name_mapping(self):
        """Rebuild name mapping by reading existing files (for recovery)."""
        try:
            for filename in os.listdir(self.secrets_dir):
                if filename.endswith(".json") and filename not in self._name_mapping:
                    # Try to guess original name from file content or filename pattern
                    base_name = filename[:-5]
                    guessed_name = base_name.replace("__SLASH__", "/").replace("__BACKSLASH__", "\\")
                    self._name_mapping[filename] = guessed_name
        except (OSError, FileNotFoundError):
            pass

    async def get_secret(self, secret_name: str) -> Optional[SecretData]:
        """Get secret from file."""
        try:
            secret_path = self._get_secret_path(secret_name)
            if not os.path.exists(secret_path):
                return None

            with open(secret_path, "r") as f:
                data = json.load(f)
                return SecretData(**data)

        except Exception as e:
            logger.error("Failed to get secret from file", secret_name=secret_name, error=str(e))
            return None

    async def store_secret(
        self, secret_name: str, secret_value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store secret to file."""
        try:
            import datetime

            secret_data = SecretData(
                value=secret_value,
                metadata=metadata or {},
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                version="1",
            )

            secret_path = self._get_secret_path(secret_name)
            with open(secret_path, "w") as f:
                json.dump(secret_data.model_dump(), f, indent=2)

            logger.info("Secret stored to file", secret_name=secret_name)
            return True

        except Exception as e:
            logger.error("Failed to store secret to file", secret_name=secret_name, error=str(e))
            return False

    async def delete_secret(self, secret_name: str) -> bool:
        """Delete secret file."""
        try:
            secret_path = self._get_secret_path(secret_name)
            if os.path.exists(secret_path):
                os.remove(secret_path)
                logger.info("Secret deleted from file", secret_name=secret_name)
            return True

        except Exception as e:
            logger.error("Failed to delete secret from file", secret_name=secret_name, error=str(e))
            return False

    async def list_secrets(self, prefix: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """List secrets from files."""
        secrets = {}
        try:
            # Rebuild mapping in case we're working with existing files
            self._rebuild_name_mapping()

            for filename in os.listdir(self.secrets_dir):
                if filename.endswith(".json"):
                    secret_name = self._get_secret_name_from_filename(filename)
                    if prefix and not secret_name.startswith(prefix):
                        continue

                    secret_data = await self.get_secret(secret_name)
                    if secret_data:
                        secrets[secret_name] = {
                            "metadata": secret_data.metadata,
                            "version": secret_data.version,
                            "created_at": secret_data.created_at,
                        }

        except Exception as e:
            logger.error("Failed to list secrets from files", error=str(e))

        return secrets

    async def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """Rotate secret in file."""
        # For file-based, rotation is just updating the value
        return await self.store_secret(secret_name, new_value, {"rotated": True})


class VaultSecretsManager(SecretsManagerProvider):
    """HashiCorp Vault secrets manager (stub for future implementation)."""

    def __init__(self, vault_url: str, vault_token: str, mount_path: str = "secret"):
        """Initialize Vault secrets manager."""
        self.vault_url = vault_url
        self.vault_token = vault_token
        self.mount_path = mount_path
        logger.info("Initialized Vault secrets manager", vault_url=vault_url, mount_path=mount_path)

    async def get_secret(self, secret_name: str) -> Optional[SecretData]:
        """Get secret from Vault (to be implemented)."""
        # TODO: Implement HashiCorp Vault integration
        logger.warning("Vault integration not yet implemented")
        return None

    async def store_secret(
        self, secret_name: str, secret_value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store secret in Vault (to be implemented)."""
        # TODO: Implement HashiCorp Vault integration
        logger.warning("Vault integration not yet implemented")
        return False

    async def delete_secret(self, secret_name: str) -> bool:
        """Delete secret from Vault (to be implemented)."""
        logger.warning("Vault integration not yet implemented")
        return False

    async def list_secrets(self, prefix: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """List secrets from Vault (to be implemented)."""
        logger.warning("Vault integration not yet implemented")
        return {}

    async def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """Rotate secret in Vault (to be implemented)."""
        logger.warning("Vault integration not yet implemented")
        return False


class AWSSecretsManager(SecretsManagerProvider):
    """AWS Secrets Manager integration (stub for future implementation)."""

    def __init__(self, region: str, access_key_id: Optional[str] = None, secret_access_key: Optional[str] = None):
        """Initialize AWS Secrets Manager."""
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        logger.info("Initialized AWS Secrets Manager", region=region)

    async def get_secret(self, secret_name: str) -> Optional[SecretData]:
        """Get secret from AWS Secrets Manager (to be implemented)."""
        # TODO: Implement AWS Secrets Manager integration
        logger.warning("AWS Secrets Manager integration not yet implemented")
        return None

    async def store_secret(
        self, secret_name: str, secret_value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store secret in AWS Secrets Manager (to be implemented)."""
        logger.warning("AWS Secrets Manager integration not yet implemented")
        return False

    async def delete_secret(self, secret_name: str) -> bool:
        """Delete secret from AWS Secrets Manager (to be implemented)."""
        logger.warning("AWS Secrets Manager integration not yet implemented")
        return False

    async def list_secrets(self, prefix: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """List secrets from AWS Secrets Manager (to be implemented)."""
        logger.warning("AWS Secrets Manager integration not yet implemented")
        return {}

    async def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """Rotate secret in AWS Secrets Manager (to be implemented)."""
        logger.warning("AWS Secrets Manager integration not yet implemented")
        return False


class SecretsManager:
    """Unified secrets manager with multiple provider support."""

    def __init__(self, provider: SecretsManagerProvider):
        """Initialize secrets manager with chosen provider."""
        self.provider = provider
        logger.info("Secrets manager initialized", provider_type=type(provider).__name__)

    async def get_api_key_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get API key metadata from secrets manager."""
        secret_name = f"api_keys/{key_id}"
        secret_data = await self.provider.get_secret(secret_name)
        return secret_data.metadata if secret_data else None

    async def store_api_key_metadata(self, key_id: str, metadata: Dict[str, Any]) -> bool:
        """Store API key metadata in secrets manager."""
        secret_name = f"api_keys/{key_id}"
        # Store metadata as JSON string
        return await self.provider.store_secret(secret_name, json.dumps(metadata), metadata)

    async def store_api_key_hash(self, key_id: str, key_hash: str) -> bool:
        """Store API key hash securely in secrets manager."""
        secret_name = f"api_keys/{key_id}/hash"
        metadata = {
            "type": "api_key_hash",
            "algorithm": "argon2" if key_hash.startswith("$argon2") else "sha256",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        return await self.provider.store_secret(secret_name, key_hash, metadata)

    async def get_api_key_hash(self, key_id: str) -> Optional[str]:
        """Get API key hash from secrets manager."""
        secret_name = f"api_keys/{key_id}/hash"
        secret_data = await self.provider.get_secret(secret_name)
        return secret_data.value if secret_data else None

    async def rotate_api_key(self, key_id: str, new_key_hash: str) -> bool:
        """Rotate API key in secrets manager."""
        secret_name = f"api_keys/{key_id}/hash"
        return await self.provider.rotate_secret(secret_name, new_key_hash)

    async def cleanup_expired_keys(self) -> int:
        """Clean up expired API keys from secrets manager."""
        secrets = await self.provider.list_secrets("api_keys/")
        cleaned_count = 0

        for secret_name in secrets:
            metadata = secrets[secret_name].get("metadata", {})
            expires_at = metadata.get("expires_at")

            if expires_at:
                import datetime

                expires_dt = datetime.datetime.fromisoformat(expires_at)
                # Ensure timezone awareness for comparison
                if expires_dt.tzinfo is None:
                    expires_dt = expires_dt.replace(tzinfo=datetime.timezone.utc)
                if expires_dt < datetime.datetime.now(datetime.timezone.utc):
                    await self.provider.delete_secret(secret_name)
                    cleaned_count += 1

        logger.info("Cleaned up expired API keys", count=cleaned_count)
        return cleaned_count


def create_secrets_manager(provider_type: str = "file", **kwargs) -> SecretsManager:
    """
    Factory function to create secrets manager with specified provider.

    Args:
        provider_type: Type of provider ("file", "vault", "aws")
        **kwargs: Provider-specific configuration

    Returns:
        Configured SecretsManager instance
    """
    if provider_type.lower() == "file":
        provider = FileSecretsManager(kwargs.get("secrets_dir", "./data/secrets"))
    elif provider_type.lower() == "vault":
        provider = VaultSecretsManager(
            vault_url=kwargs["vault_url"],
            vault_token=kwargs["vault_token"],
            mount_path=kwargs.get("mount_path", "secret"),
        )
    elif provider_type.lower() == "aws":
        provider = AWSSecretsManager(
            region=kwargs["region"],
            access_key_id=kwargs.get("access_key_id"),
            secret_access_key=kwargs.get("secret_access_key"),
        )
    else:
        raise ValueError(f"Unsupported secrets manager provider: {provider_type}")

    return SecretsManager(provider)
