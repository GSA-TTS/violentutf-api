"""Plugin management models for extensible functionality."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from app.models.task import Task

from sqlalchemy import JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.models.mixins import BaseModelMixin


class PluginStatus(str, Enum):
    """Plugin status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    ERROR = "error"
    DEPRECATED = "deprecated"


class PluginType(str, Enum):
    """Plugin types."""

    SCANNER = "scanner"
    SCORER = "scorer"
    TARGET = "target"
    GENERATOR = "generator"
    REPORTER = "reporter"
    CONVERTER = "converter"
    MIDDLEWARE = "middleware"
    CUSTOM = "custom"


class PluginLoadingStrategy(str, Enum):
    """Plugin loading strategies."""

    LAZY = "lazy"
    EAGER = "eager"
    ON_DEMAND = "on_demand"


class Plugin(BaseModelMixin, Base):
    """Model for plugin definitions."""

    # Basic plugin information
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Plugin classification
    plugin_type: Mapped[PluginType] = mapped_column(SQLEnum(PluginType), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Version and compatibility
    plugin_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    api_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")
    min_platform_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Plugin status
    status: Mapped[PluginStatus] = mapped_column(
        SQLEnum(PluginStatus), nullable=False, default=PluginStatus.INACTIVE, index=True
    )

    # Loading configuration
    loading_strategy: Mapped[PluginLoadingStrategy] = mapped_column(
        SQLEnum(PluginLoadingStrategy), nullable=False, default=PluginLoadingStrategy.LAZY
    )

    # Implementation details
    entry_point: Mapped[str] = mapped_column(String(500), nullable=False)
    module_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    class_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Configuration
    default_config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    config_schema: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    required_permissions: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Dependencies
    dependencies: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    python_dependencies: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Metadata
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    author_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    homepage: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    license: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Installation tracking
    installed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    last_loaded_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    load_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Health monitoring
    last_health_check: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    health_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    error_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Relationships
    configurations: Mapped[list["PluginConfiguration"]] = relationship(
        "PluginConfiguration", back_populates="plugin", cascade="all, delete-orphan"
    )
    executions: Mapped[list["PluginExecution"]] = relationship(
        "PluginExecution", back_populates="plugin", cascade="all, delete-orphan"
    )

    # Model-specific constraints
    _model_constraints = (
        Index("idx_plugin_type_status", "plugin_type", "status"),
        Index("idx_plugin_category_status", "category", "status"),
        Index("idx_plugin_installed", "installed_at", "status"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<Plugin(id='{self.id}', name='{self.name}', type='{self.plugin_type}', status='{self.status}')>"


class PluginConfiguration(BaseModelMixin, Base):
    """Model for plugin instance configurations."""

    # Relationship to plugin
    plugin_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("plugin.id", ondelete="CASCADE"), nullable=False, index=True
    )
    plugin: Mapped[Plugin] = relationship("Plugin", back_populates="configurations")

    # Configuration information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Configuration data
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    environment: Mapped[Dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    is_default: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Usage tracking
    usage_count: Mapped[int] = mapped_column(nullable=False, default=0)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Validation
    is_valid: Mapped[bool] = mapped_column(nullable=False, default=False)
    validation_errors: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_plugin_config_active", "plugin_id", "is_active"),
        Index("idx_plugin_config_default", "plugin_id", "is_default"),
        Index("idx_plugin_config_name", "name"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<PluginConfiguration(id='{self.id}', plugin_id='{self.plugin_id}', name='{self.name}')>"


class PluginExecution(BaseModelMixin, Base):
    """Model for plugin execution tracking."""

    # Relationship to plugin
    plugin_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("plugin.id", ondelete="CASCADE"), nullable=False, index=True
    )
    plugin: Mapped[Plugin] = relationship("Plugin", back_populates="executions")

    # Configuration used
    configuration_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("plugin_configuration.id", ondelete="SET NULL"), nullable=True, index=True
    )
    configuration: Mapped[Optional[PluginConfiguration]] = relationship("PluginConfiguration")

    # Execution context
    execution_context: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(
        String(255), ForeignKey("task.id", ondelete="SET NULL"), nullable=True, index=True
    )
    task: Mapped[Optional[Task]] = relationship("Task")

    # Execution tracking
    started_at: Mapped[datetime] = mapped_column(nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Status and results
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="running", index=True)
    success: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Input and output
    input_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    output_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    stack_trace: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Performance metrics
    memory_usage_mb: Mapped[Optional[float]] = mapped_column(nullable=True)
    cpu_usage_percent: Mapped[Optional[float]] = mapped_column(nullable=True)
    performance_metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_plugin_execution_plugin_status", "plugin_id", "status"),
        Index("idx_plugin_execution_context", "execution_context", "started_at"),
        Index("idx_plugin_execution_task", "task_id", "status"),
        Index("idx_plugin_execution_success", "success", "started_at"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<PluginExecution(id='{self.id}', plugin_id='{self.plugin_id}', status='{self.status}')>"


class PluginRegistry(BaseModelMixin, Base):
    """Model for plugin registry and marketplace."""

    # Registry information
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Plugin reference
    plugin_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    plugin_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Distribution information
    download_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    # Publishing info
    published_at: Mapped[datetime] = mapped_column(
        nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )
    publisher: Mapped[str] = mapped_column(String(255), nullable=False)

    # Ratings and usage
    download_count: Mapped[int] = mapped_column(nullable=False, default=0)
    rating: Mapped[Optional[float]] = mapped_column(nullable=True)
    rating_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Status
    is_verified: Mapped[bool] = mapped_column(nullable=False, default=False)
    is_featured: Mapped[bool] = mapped_column(nullable=False, default=False)
    is_deprecated: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Model-specific constraints
    _model_constraints = (
        Index("idx_registry_name_version", "plugin_name", "plugin_version"),
        Index("idx_registry_category_published", "category", "published_at"),
        Index("idx_registry_featured", "is_featured", "rating"),
        Index("idx_registry_verified", "is_verified", "published_at"),
    )

    def __repr__(self) -> str:  # noqa: D105
        return f"<PluginRegistry(id='{self.id}', name='{self.plugin_name}', version='{self.plugin_version}')>"
