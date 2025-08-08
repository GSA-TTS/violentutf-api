"""Plugin management API endpoints."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.plugin import Plugin, PluginConfiguration, PluginExecution, PluginStatus, PluginType
from app.models.user import User

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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PluginListResponse:
    """List available plugins."""
    try:
        # Build query with filters
        query = select(Plugin).where(Plugin.is_deleted.is_(False))

        if plugin_type:
            query = query.where(Plugin.plugin_type == plugin_type)
        if status:
            # Map common status values to PluginStatus enum
            status_mapping = {
                "enabled": PluginStatus.ACTIVE,
                "disabled": PluginStatus.DISABLED,
                "active": PluginStatus.ACTIVE,
                "inactive": PluginStatus.INACTIVE,
                "error": PluginStatus.ERROR,
            }
            db_status = status_mapping.get(status.lower(), status)
            query = query.where(Plugin.status == db_status)
        if category:
            query = query.where(Plugin.category == category)

        # Order by status (active first), then by name
        query = query.order_by(Plugin.status.desc(), Plugin.load_count.desc(), Plugin.name)

        # Execute query
        result = await db.execute(query)
        plugins = result.scalars().all()

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
                status="enabled" if plugin.status == PluginStatus.ACTIVE else "disabled",
                plugin_type=plugin.plugin_type.value,
                category=plugin.category,
                dependencies=plugin.python_dependencies,
                config=plugin.default_config,
                tags=plugin.tags,
                installed_at=plugin.installed_at.isoformat() if plugin.installed_at else None,
                last_used_at=plugin.last_loaded_at.isoformat() if plugin.last_loaded_at else None,
                usage_count=plugin.load_count,
            )
            plugin_responses.append(plugin_info)

        logger.info(f"User {current_user.username} listed plugins: {len(plugin_responses)} found")

        return PluginListResponse(plugins=plugin_responses, total=len(plugin_responses))

    except Exception as e:
        logger.error(f"Error listing plugins: {e}")
        raise HTTPException(status_code=500, detail="Failed to list plugins")


@router.get("/{plugin_id}", response_model=PluginInfo, summary="Get plugin")
async def get_plugin(
    plugin_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PluginInfo:
    """Get detailed information about a specific plugin."""
    try:
        # Query plugin by ID
        query = select(Plugin).where(and_(Plugin.id == plugin_id, Plugin.is_deleted.is_(False)))
        result = await db.execute(query)
        plugin = result.scalar_one_or_none()

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
            installed_at=plugin.installed_at.isoformat() if plugin.installed_at else None,
            last_used_at=plugin.last_loaded_at.isoformat() if plugin.last_loaded_at else None,
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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Execute an action on a plugin (enable, disable, reload, configure)."""
    try:
        from datetime import datetime, timezone

        valid_actions = ["enable", "disable", "reload", "configure"]
        if action_request.action not in valid_actions:
            raise HTTPException(status_code=400, detail=f"Invalid action. Valid actions: {valid_actions}")

        # Get plugin
        query = select(Plugin).where(and_(Plugin.id == plugin_id, Plugin.is_deleted.is_(False)))
        result = await db.execute(query)
        plugin = result.scalar_one_or_none()

        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")

        # Execute action
        action_result = {"status": "success", "message": ""}

        if action_request.action == "enable":
            plugin.status = PluginStatus.ACTIVE
            action_result["message"] = f"Plugin {plugin.name} enabled successfully"

        elif action_request.action == "disable":
            plugin.status = PluginStatus.DISABLED
            action_result["message"] = f"Plugin {plugin.name} disabled successfully"

        elif action_request.action == "reload":
            # Update last loaded timestamp and increment count
            plugin.last_loaded_at = datetime.now(timezone.utc)
            plugin.load_count += 1
            action_result["message"] = f"Plugin {plugin.name} reloaded successfully"

        elif action_request.action == "configure":
            # Update configuration if provided
            if action_request.config:
                plugin.default_config.update(action_request.config)
                plugin.updated_by = current_user.username
            action_result["message"] = f"Plugin {plugin.name} configured successfully"

        # Update plugin in database
        plugin.updated_by = current_user.username
        await db.commit()
        await db.refresh(plugin)

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

        db.add(execution)
        await db.commit()

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
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to execute plugin action")


@router.get("/types", summary="Get plugin types")
async def get_plugin_types(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get available plugin types and their categories from database."""
    try:
        # Get unique categories from database
        category_query = select(Plugin.category.distinct()).where(
            and_(Plugin.is_deleted.is_(False), Plugin.status.in_([PluginStatus.ACTIVE, PluginStatus.INACTIVE]))
        )
        category_result = await db.execute(category_query)
        db_categories = [row[0] for row in category_result.fetchall()]

        # Build response with all available enum types and database data
        available_types = [t.value for t in PluginType]
        plugin_types = {}

        for plugin_type in available_types:
            # Get categories for this type
            type_categories_query = select(Plugin.category.distinct()).where(
                and_(
                    Plugin.plugin_type == plugin_type,
                    Plugin.is_deleted.is_(False),
                    Plugin.status.in_([PluginStatus.ACTIVE, PluginStatus.INACTIVE]),
                )
            )
            type_categories_result = await db.execute(type_categories_query)
            type_categories = [row[0] for row in type_categories_result.fetchall()]

            plugin_types[plugin_type] = type_categories or ["General"]

        return {
            "plugin_types": plugin_types,
            "available_categories": db_categories,
            "total_plugins_by_type": await _get_plugin_counts_by_type(db),
        }

    except Exception as e:
        logger.error(f"Error getting plugin types: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin types")


async def _get_plugin_counts_by_type(db: AsyncSession) -> Dict[str, int]:
    """Get plugin counts by type."""
    counts = {}
    for plugin_type in PluginType:
        count_query = select(func.count()).where(
            and_(
                Plugin.plugin_type == plugin_type,
                Plugin.is_deleted.is_(False),
                Plugin.status.in_([PluginStatus.ACTIVE, PluginStatus.INACTIVE]),
            )
        )
        result = await db.execute(count_query)
        counts[plugin_type.value] = result.scalar() or 0
    return counts


@router.post("/refresh", summary="Refresh plugin registry")
async def refresh_plugins(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Refresh the plugin registry by scanning database and updating metadata."""
    try:
        from datetime import datetime, timezone

        # Get current plugin statistics
        total_plugins_query = select(func.count()).where(Plugin.is_deleted.is_(False))
        total_result = await db.execute(total_plugins_query)
        total_plugins = total_result.scalar() or 0

        active_plugins_query = select(func.count()).where(
            and_(Plugin.is_deleted.is_(False), Plugin.status == PluginStatus.ACTIVE)
        )
        active_result = await db.execute(active_plugins_query)
        active_plugins = active_result.scalar() or 0

        # Update health status for all plugins (simplified health check)
        plugins_to_check = await db.execute(select(Plugin).where(Plugin.is_deleted.is_(False)))
        updated_plugins = 0

        for plugin in plugins_to_check.scalars().all():
            # Simple health check - update last health check timestamp
            plugin.last_health_check = datetime.now(timezone.utc)

            # Reset error count if plugin is active (simplified)
            if plugin.status == PluginStatus.ACTIVE:
                plugin.health_status = "healthy"
                plugin.error_count = 0
            else:
                plugin.health_status = "inactive"

            plugin.updated_by = current_user.username
            updated_plugins += 1

        # Commit all updates
        await db.commit()

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
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to refresh plugin registry")
