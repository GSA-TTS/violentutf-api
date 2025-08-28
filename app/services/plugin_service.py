"""Plugin management service for handling plugin lifecycle and operations."""

from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from structlog.stdlib import get_logger

from app.core.errors import NotFoundError, ValidationError
from app.models.plugin import Plugin
from app.repositories.base import BaseRepository

logger = get_logger(__name__)


class PluginService:
    """Service for managing plugins with transaction management."""

    def __init__(self, repository: BaseRepository):
        """Initialize plugin service with repository.

        Args:
            repository: Plugin repository for data access
        """
        self.repository = repository

    async def create_plugin(self, plugin_data: Dict[str, Any], user_id: str) -> Plugin:
        """Create a new plugin.

        Args:
            plugin_data: Plugin creation data
            user_id: User creating the plugin

        Returns:
            Plugin: Created plugin instance

        Raises:
            ValidationError: If plugin data is invalid
        """
        try:
            # Add audit fields
            plugin_data.update(
                {
                    "id": str(uuid4()),
                    "created_by": user_id,
                    "updated_by": user_id,
                }
            )

            plugin = await self.repository.create(plugin_data)
            logger.info("plugin_created", plugin_id=plugin.id, name=plugin_data.get("name"))
            return plugin

        except Exception as e:
            logger.error("failed_to_create_plugin", error=str(e))
            raise ValidationError(f"Failed to create plugin: {str(e)}")

    async def get_plugin(self, plugin_id: str) -> Optional[Plugin]:
        """Get plugin by ID.

        Args:
            plugin_id: Plugin identifier

        Returns:
            Plugin: Plugin instance if found

        Raises:
            NotFoundError: If plugin not found
        """
        plugin = await self.repository.get(plugin_id)
        if not plugin:
            raise NotFoundError(f"Plugin with ID {plugin_id} not found")
        return plugin

    async def list_plugins(
        self, skip: int = 0, limit: int = 100, filters: Optional[Dict[str, Any]] = None
    ) -> List[Plugin]:
        """List plugins with pagination and filtering.

        Args:
            skip: Number of plugins to skip
            limit: Maximum number of plugins to return
            filters: Optional filters to apply

        Returns:
            List[Plugin]: List of plugins
        """
        return await self.repository.list(skip=skip, limit=limit, filters=filters)

    async def update_plugin(self, plugin_id: str, update_data: Dict[str, Any], user_id: str) -> Plugin:
        """Update plugin.

        Args:
            plugin_id: Plugin identifier
            update_data: Data to update
            user_id: User performing update

        Returns:
            Plugin: Updated plugin instance

        Raises:
            NotFoundError: If plugin not found
            ValidationError: If update fails
        """
        try:
            await self.get_plugin(plugin_id)  # Validate plugin exists

            # Add audit fields
            update_data["updated_by"] = user_id

            updated_plugin = await self.repository.update(plugin_id, update_data)
            logger.info("plugin_updated", plugin_id=plugin_id, user_id=user_id)
            return updated_plugin

        except Exception as e:
            logger.error("failed_to_update_plugin", plugin_id=plugin_id, error=str(e))
            raise ValidationError(f"Failed to update plugin: {str(e)}")

    async def delete_plugin(self, plugin_id: str, user_id: str) -> bool:
        """Delete plugin.

        Args:
            plugin_id: Plugin identifier
            user_id: User performing deletion

        Returns:
            bool: True if deletion successful

        Raises:
            NotFoundError: If plugin not found
        """
        try:
            # Verify plugin exists before deletion
            await self.get_plugin(plugin_id)

            success = await self.repository.delete(plugin_id)
            if success:
                logger.info("plugin_deleted", plugin_id=plugin_id, user_id=user_id)
            return success

        except Exception as e:
            logger.error("failed_to_delete_plugin", plugin_id=plugin_id, error=str(e))
            raise

    async def activate_plugin(self, plugin_id: str, user_id: str) -> Plugin:
        """Activate a plugin.

        Args:
            plugin_id: Plugin identifier
            user_id: User performing activation

        Returns:
            Plugin: Activated plugin instance
        """
        return await self.update_plugin(plugin_id, {"is_active": True, "status": "active"}, user_id)

    async def deactivate_plugin(self, plugin_id: str, user_id: str) -> Plugin:
        """Deactivate a plugin.

        Args:
            plugin_id: Plugin identifier
            user_id: User performing deactivation

        Returns:
            Plugin: Deactivated plugin instance
        """
        return await self.update_plugin(plugin_id, {"is_active": False, "status": "inactive"}, user_id)
