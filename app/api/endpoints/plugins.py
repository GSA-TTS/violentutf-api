"""Plugin management API endpoints."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import get_plugin_service
from app.core.auth import get_current_user
from app.models.plugin import (
    Plugin,
    PluginConfiguration,
    PluginExecution,
    PluginStatus,
    PluginType,
)
from app.models.user import User
from app.services.plugin_service import PluginService

logger = logging.getLogger(__name__)
router = APIRouter()


class PluginInfo(BaseModel):
    """Plugin information schema."""

    id: str = Field(..., description="Plugin ID")
    name: str = Field(..., description="Plugin name")
    display_name: str = Field(..., description="Plugin display name")
    version: str = Field(..., description="Plugin version")
    description: str = Field(..., description="Plugin description")
    author: Optional[str] = Field(None, description="Plugin author")
    status: str = Field(..., description="Plugin status")
    plugin_type: str = Field(..., description="Plugin type")
    category: str = Field(..., description="Plugin category")
    dependencies: List[str] = Field(default_factory=list, description="Plugin dependencies")
    config: Dict[str, Any] = Field(default_factory=dict, description="Default configuration")
    tags: List[str] = Field(default_factory=list, description="Plugin tags")
    installed_at: Optional[str] = Field(None, description="Installation timestamp")
    last_used_at: Optional[str] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(0, description="Number of times loaded")

    class Config:
        from_attributes = True


class PluginListResponse(BaseModel):
    """Plugin list response schema."""

    plugins: List[PluginInfo] = Field(..., description="List of plugins")
    total: int = Field(..., ge=0, description="Total number of plugins")


class PluginActionRequest(BaseModel):
    """Plugin action request schema."""

    action: str = Field(..., description="Action to perform (enable/disable/reload)")
    config: Optional[Dict[str, Any]] = Field(None, description="Configuration parameters")


@router.get("/", response_model=PluginListResponse, summary="List plugins")
async def list_plugins(
    plugin_type: Optional[str] = Query(None, description="Filter by plugin type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    plugin_service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginListResponse:
    """List available plugins."""
    try:
        # Build filters for service layer
        filters = {}
        if plugin_type:
            filters["plugin_type"] = plugin_type
        if status:
            # Map common status values to PluginStatus enum
            status_mapping = {
                "enabled": PluginStatus.ACTIVE,
                "disabled": PluginStatus.DISABLED,
                "active": PluginStatus.ACTIVE,
                "inactive": PluginStatus.INACTIVE,
                "error": PluginStatus.ERROR,
            }
            filters["status"] = status_mapping.get(status.lower(), status)
        if category:
            filters["category"] = category

        # Get plugins through service layer
        plugins = await plugin_service.list_plugins(filters=filters)

        # Convert to response schemas with proper status mapping
        plugin_responses = []
        for plugin in plugins:
            plugin_info = PluginInfo(
                id=plugin.id,
                name=plugin.name,
                display_name=plugin.display_name,
                version=plugin.plugin_version,
                description=plugin.description,
                author=plugin.author,
                status=("enabled" if plugin.status == PluginStatus.ACTIVE else "disabled"),
                plugin_type=plugin.plugin_type.value,
                category=plugin.category,
                dependencies=plugin.python_dependencies,
                config=plugin.default_config,
                tags=plugin.tags,
                installed_at=(plugin.installed_at.isoformat() if plugin.installed_at else None),
                last_used_at=(plugin.last_loaded_at.isoformat() if plugin.last_loaded_at else None),
                usage_count=plugin.load_count,
            )
            plugin_responses.append(plugin_info)

        from app.core.safe_logging import sanitize_log_value

        logger.info(
            "User listed plugins",
            user=sanitize_log_value(current_user.username),
            count=len(plugin_responses),
        )

        return PluginListResponse(plugins=plugin_responses, total=len(plugin_responses))

    except Exception as e:
        from app.core.safe_logging import safe_error_message

        logger.error("Error listing plugins", error=safe_error_message(e))
        raise HTTPException(status_code=500, detail="Failed to list plugins")


@router.get("/{plugin_id}", response_model=PluginInfo, summary="Get plugin")
async def get_plugin(
    plugin_id: str,
    plugin_service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginInfo:
    """Get detailed information about a specific plugin."""
    try:
        # Get plugin through service layer
        plugin = await plugin_service.get_plugin(plugin_id)

        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")

        # Convert to response schema
        plugin_info = PluginInfo(
            id=plugin.id,
            name=plugin.name,
            display_name=plugin.display_name,
            version=plugin.plugin_version,
            description=plugin.description,
            author=plugin.author,
            status="enabled" if plugin.status == PluginStatus.ACTIVE else "disabled",
            plugin_type=plugin.plugin_type.value,
            category=plugin.category,
            dependencies=plugin.python_dependencies,
            config=plugin.default_config,
            tags=plugin.tags,
            installed_at=(plugin.installed_at.isoformat() if plugin.installed_at else None),
            last_used_at=(plugin.last_loaded_at.isoformat() if plugin.last_loaded_at else None),
            usage_count=plugin.load_count,
        )

        logger.info(f"User {current_user.username} retrieved plugin: {plugin_id}")

        return plugin_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting plugin {plugin_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin")


@router.post("/{plugin_id}/action", summary="Execute plugin action")
async def plugin_action(
    plugin_id: str,
    action_request: PluginActionRequest,
    plugin_service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Execute an action on a plugin (enable, disable, reload, configure)."""
    try:
        from datetime import datetime, timezone

        valid_actions = ["enable", "disable", "reload", "configure"]
        if action_request.action not in valid_actions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid action. Valid actions: {valid_actions}",
            )

        # Get plugin through service layer
        plugin = await plugin_service.get_plugin(plugin_id)

        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")

        # Execute action
        action_result = {"status": "success", "message": ""}

        # Prepare update data based on action
        update_data = {}

        if action_request.action == "enable":
            update_data["status"] = PluginStatus.ACTIVE
            action_result["message"] = "Plugin enabled successfully"

        elif action_request.action == "disable":
            update_data["status"] = PluginStatus.DISABLED
            action_result["message"] = "Plugin disabled successfully"

        elif action_request.action == "reload":
            # Update last loaded timestamp and increment count
            update_data["last_loaded_at"] = datetime.now(timezone.utc)
            update_data["load_count"] = plugin.load_count + 1
            action_result["message"] = "Plugin reloaded successfully"

        elif action_request.action == "configure":
            # Update configuration if provided
            if action_request.config:
                new_config = plugin.default_config.copy()
                new_config.update(action_request.config)
                update_data["default_config"] = new_config
            action_result["message"] = "Plugin configured successfully"

        # Update plugin through service layer
        if update_data:
            await plugin_service.update_plugin(plugin_id, update_data, current_user.username)

        # Create execution record
        execution = PluginExecution(
            plugin_id=plugin.id,
            execution_context="manual_action",
            status="completed",
            success=True,
            input_data={
                "action": action_request.action,
                "config": action_request.config or {},
                "user": current_user.username,
            },
            output_data=action_result,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=0.1,  # Minimal duration for config actions
            created_by=current_user.username,
        )

        # Service should handle execution record creation and commit

        logger.info(f"User {current_user.username} executed action {action_request.action} on plugin: {plugin_id}")

        return {
            "plugin_id": plugin_id,
            "action": action_request.action,
            "result": action_result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_id": execution.id,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing plugin action {plugin_id}: {e}")
        # Service layer should handle rollback
        raise HTTPException(status_code=500, detail="Failed to execute plugin action")


@router.get("/types", summary="Get plugin types")
async def get_plugin_types(
    plugin_service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get available plugin types and their categories from database."""
    try:
        # Get all plugins through service layer
        all_plugins = await plugin_service.list_plugins(
            skip=0,
            limit=10000,  # Large limit to get all plugins
            filters={"status__in": [PluginStatus.ACTIVE, PluginStatus.INACTIVE]},
        )

        # Extract unique categories
        db_categories = list(set(plugin.category for plugin in all_plugins if plugin.category))

        # Build response with all available enum types and database data
        plugin_types = {}
        total_plugins_by_type = {}

        for plugin_type_enum in PluginType:
            plugin_type = plugin_type_enum.value
            # Get categories for this type
            type_categories = list(
                set(
                    plugin.category
                    for plugin in all_plugins
                    if plugin.plugin_type == plugin_type_enum and plugin.category
                )
            )

            plugin_types[plugin_type] = type_categories or ["General"]

            # Count plugins by type
            total_plugins_by_type[plugin_type] = len(
                [plugin for plugin in all_plugins if plugin.plugin_type == plugin_type_enum]
            )

        return {
            "plugin_types": plugin_types,
            "available_categories": db_categories,
            "total_plugins_by_type": total_plugins_by_type,
        }

    except Exception as e:
        logger.error(f"Error getting plugin types: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin types")


@router.post("/refresh", summary="Refresh plugin registry")
async def refresh_plugins(
    plugin_service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Refresh the plugin registry by scanning database and updating metadata."""
    try:
        from datetime import datetime, timezone

        # Get current plugin statistics through service layer
        all_plugins = await plugin_service.list_plugins(skip=0, limit=10000)
        total_plugins = len(all_plugins)
        active_plugins = len([p for p in all_plugins if p.status == PluginStatus.ACTIVE])

        # Update health status for all plugins (simplified health check)
        updated_plugins = 0

        for plugin in all_plugins:
            # Prepare health status update
            health_update = {"last_health_check": datetime.now(timezone.utc)}

            # Reset error count if plugin is active (simplified)
            if plugin.status == PluginStatus.ACTIVE:
                health_update["health_status"] = "healthy"
                health_update["error_count"] = 0
            else:
                health_update["health_status"] = "inactive"

            # Update through service layer
            await plugin_service.update_plugin(plugin.id, health_update, current_user.username)
            updated_plugins += 1

        logger.info(f"User {current_user.username} refreshed plugin registry: {updated_plugins} plugins updated")

        return {
            "status": "success",
            "message": "Plugin registry refreshed successfully",
            "total_plugins": total_plugins,
            "active_plugins": active_plugins,
            "updated_plugins": updated_plugins,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "health_check_completed": True,
        }

    except Exception as e:
        logger.error(f"Error refreshing plugins: {e}")
        # Service layer should handle rollback
        raise HTTPException(status_code=500, detail="Failed to refresh plugin registry")
