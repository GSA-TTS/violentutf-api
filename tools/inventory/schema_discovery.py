"""Schema Discovery Tool for Database Audit Phase 1.

This tool discovers and inventories database schema information including:
- Tables and their corresponding SQLAlchemy models
- Column definitions and types
- Relationships and foreign keys
- Indexes and constraints
- Database metadata
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import MetaData, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from app.db.base import Base
from app.db.session import get_db
from app.models import *
from audit_utils.exceptions import audit_error_handler
from audit_utils.file_operations import safe_write_json
from audit_utils.logging import setup_audit_logger

logger = setup_audit_logger(__name__)


class SchemaDiscoveryTool:
    """Tool for discovering and documenting database schema assets."""

    def __init__(self):
        """Initialize the schema discovery tool."""
        self.version = "1.0"
        self.discovery_time = None
        self.fallback_used = False

    @audit_error_handler
    async def discover_schema(self) -> Dict[str, Any]:
        """
        Discover complete database schema information.

        Returns:
            Dict containing schema inventory with tables, relationships, indexes
        """
        self.discovery_time = datetime.now().isoformat() + "Z"

        try:
            return await self._discover_from_live_database()
        except Exception as e:
            logger.warning("Live database discovery failed, falling back to static analysis", error=str(e))
            self.fallback_used = True
            return await self._discover_from_static_analysis()

    @audit_error_handler
    async def _discover_from_live_database(self) -> Dict[str, Any]:
        """Discover schema from live database connection."""
        schema_inventory = {
            "metadata": self._get_metadata(),
            "tables": [],
            "relationships": [],
            "indexes": [],
            "constraints": [],
        }

        try:
            async with get_db() as db:
                # Use run_sync for synchronous inspection operations
                def inspect_database(connection):
                    inspector = inspect(connection)

                    # Discover tables
                    table_names = inspector.get_table_names()
                    logger.info(f"Discovered {len(table_names)} tables")

                    schema_data = {
                        "table_names": table_names,
                        "tables_info": {},
                        "relationships": [],
                        "indexes": [],
                        "constraints": [],
                    }

                    for table_name in table_names:
                        # Analyze table
                        columns = inspector.get_columns(table_name)
                        table_info = {
                            "name": table_name,
                            "model": self._get_model_name_for_table(table_name),
                            "columns": [
                                {
                                    "name": col["name"],
                                    "type": str(col["type"]),
                                    "nullable": col.get("nullable", True),
                                    "primary_key": col.get("primary_key", False),
                                    "unique": col.get("unique", False),
                                    "default": str(col.get("default")) if col.get("default") else None,
                                }
                                for col in columns
                            ],
                            "source": "live_database",
                        }
                        schema_data["tables_info"][table_name] = table_info

                        # Collect relationships for this table
                        relationships = self._get_table_relationships_sync(inspector, table_name)
                        schema_data["relationships"].extend(relationships)

                        # Collect indexes for this table
                        indexes = self._get_table_indexes_sync(inspector, table_name)
                        schema_data["indexes"].extend(indexes)

                        # Collect constraints for this table
                        constraints = self._get_table_constraints_sync(inspector, table_name)
                        schema_data["constraints"].extend(constraints)

                    return schema_data

                # Run the synchronous inspection in sync context
                schema_data = await db.run_sync(inspect_database)

                # Convert to final format
                schema_inventory["tables"] = list(schema_data["tables_info"].values())
                schema_inventory["relationships"] = schema_data["relationships"]
                schema_inventory["indexes"] = schema_data["indexes"]
                schema_inventory["constraints"] = schema_data["constraints"]

        except SQLAlchemyError as e:
            logger.error(f"Database error during schema discovery: {e}")
            raise

        return schema_inventory

    @audit_error_handler
    async def _discover_from_static_analysis(self) -> Dict[str, Any]:
        """Fallback: discover schema from SQLAlchemy models when DB unavailable."""
        schema_inventory = {
            "metadata": self._get_metadata(),
            "tables": [],
            "relationships": [],
            "indexes": [],
            "constraints": [],
            "error": "Database unavailable, using static analysis",
            "fallback_used": True,
        }

        # Use SQLAlchemy metadata from Base
        metadata = Base.metadata

        for table_name, table in metadata.tables.items():
            table_info = {
                "name": table_name,
                "model": self._get_model_name_for_table(table_name),
                "columns": [
                    {
                        "name": col.name,
                        "type": str(col.type),
                        "nullable": col.nullable,
                        "primary_key": col.primary_key,
                        "unique": col.unique,
                    }
                    for col in table.columns
                ],
                "source": "static_analysis",
            }
            schema_inventory["tables"].append(table_info)

            # Extract relationships from foreign keys
            for fk in table.foreign_keys:
                relationship = {
                    "source_table": str(table_name),
                    "source_column": str(fk.parent.name),
                    "target_table": str(fk.column.table.name),
                    "target_column": str(fk.column.name),
                    "constraint_name": str(fk.constraint.name) if fk.constraint else None,
                    "source": "static_analysis",
                }
                schema_inventory["relationships"].append(relationship)

        return schema_inventory

    @audit_error_handler
    async def _analyze_table(self, inspector, table_name: str) -> Dict[str, Any]:
        """Analyze a single table and return its information."""
        columns = inspector.get_columns(table_name)

        table_info = {
            "name": table_name,
            "model": self._get_model_name_for_table(table_name),
            "columns": [
                {
                    "name": col["name"],
                    "type": str(col["type"]),
                    "nullable": col.get("nullable", True),
                    "primary_key": col.get("primary_key", False),
                    "unique": col.get("unique", False),
                    "default": str(col.get("default")) if col.get("default") else None,
                }
                for col in columns
            ],
            "row_count": await self._get_table_row_count(table_name),
            "source": "live_database",
        }

        return table_info

    def _get_table_relationships_sync(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get foreign key relationships for a table (synchronous version)."""
        return self._get_table_relationships(inspector, table_name)

    def _get_table_indexes_sync(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get indexes for a table (synchronous version)."""
        return self._get_table_indexes(inspector, table_name)

    def _get_table_constraints_sync(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get constraints for a table (synchronous version)."""
        return self._get_table_constraints(inspector, table_name)

    @audit_error_handler
    def _get_table_relationships(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get foreign key relationships for a table."""
        relationships = []

        try:
            foreign_keys = inspector.get_foreign_keys(table_name)

            for fk in foreign_keys:
                relationship = {
                    "source_table": table_name,
                    "source_columns": fk["constrained_columns"],
                    "target_table": fk["referred_table"],
                    "target_columns": fk["referred_columns"],
                    "constraint_name": fk["name"],
                    "on_delete": fk.get("options", {}).get("ondelete"),
                    "on_update": fk.get("options", {}).get("onupdate"),
                }
                relationships.append(relationship)

        except Exception as e:
            logger.warning(f"Failed to get relationships for {table_name}: {e}")

        return relationships

    @audit_error_handler
    def _get_table_indexes(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get indexes for a table."""
        indexes = []

        try:
            table_indexes = inspector.get_indexes(table_name)

            for idx in table_indexes:
                index_info = {
                    "table_name": table_name,
                    "name": idx["name"],
                    "columns": idx["column_names"],
                    "unique": idx.get("unique", False),
                    "type": idx.get("type", "btree"),
                }
                indexes.append(index_info)

        except Exception as e:
            logger.warning(f"Failed to get indexes for {table_name}: {e}")

        return indexes

    @audit_error_handler
    def _get_table_constraints(self, inspector, table_name: str) -> List[Dict[str, Any]]:
        """Get constraints for a table."""
        constraints = []

        try:
            # Primary key constraint
            pk_constraint = inspector.get_pk_constraint(table_name)
            if pk_constraint:
                constraints.append(
                    {
                        "table_name": table_name,
                        "type": "primary_key",
                        "name": pk_constraint["name"],
                        "columns": pk_constraint["constrained_columns"],
                    }
                )

            # Unique constraints
            unique_constraints = inspector.get_unique_constraints(table_name)
            for uc in unique_constraints:
                constraints.append(
                    {"table_name": table_name, "type": "unique", "name": uc["name"], "columns": uc["column_names"]}
                )

            # Check constraints
            check_constraints = inspector.get_check_constraints(table_name)
            for cc in check_constraints:
                constraints.append(
                    {"table_name": table_name, "type": "check", "name": cc["name"], "expression": cc.get("sqltext", "")}
                )

        except Exception as e:
            logger.warning(f"Failed to get constraints for {table_name}: {e}")

        return constraints

    @audit_error_handler
    async def _get_table_row_count(self, table_name: str) -> Optional[int]:
        """Get approximate row count for a table."""
        try:
            # Validate table name to prevent SQL injection
            if not table_name.replace("_", "").isalnum():
                logger.warning(f"Invalid table name format: {table_name}")
                return None

            async with get_db() as db:
                # Use text() with validated identifier - table names cannot be parameterized
                result = await db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))  # nosec B608
                count = result.scalar()
                return count
        except Exception as e:
            logger.warning(f"Failed to get row count for {table_name}: {e}")
            return None

    def _get_model_name_for_table(self, table_name: str) -> Optional[str]:
        """Map table name to SQLAlchemy model name."""
        # Common mappings based on naming conventions
        model_mappings = {
            "users": "User",
            "roles": "Role",
            "permissions": "Permission",
            "user_roles": "UserRole",
            "api_keys": "APIKey",
            "sessions": "Session",
            "audit_logs": "AuditLog",
            "oauth_applications": "OAuthApplication",
            "oauth_access_tokens": "OAuthAccessToken",
            "oauth_refresh_tokens": "OAuthRefreshToken",
            "oauth_authorization_codes": "OAuthAuthorizationCode",
            "mfa_devices": "MFADevice",
            "mfa_backup_codes": "MFABackupCode",
            "mfa_challenges": "MFAChallenge",
            "mfa_events": "MFAEvent",
            "vulnerability_taxonomies": "VulnerabilityTaxonomy",
            "vulnerability_findings": "VulnerabilityFinding",
            "security_scans": "SecurityScan",
            "tasks": "Task",
            "task_results": "TaskResult",
            "plugins": "Plugin",
            "plugin_configurations": "PluginConfiguration",
            "plugin_executions": "PluginExecution",
            "plugin_registries": "PluginRegistry",
        }

        return model_mappings.get(table_name)

    def _get_metadata(self) -> Dict[str, Any]:
        """Get discovery metadata."""
        return {
            "discovery_time": self.discovery_time,
            "tool_version": self.version,
            "database_type": "postgresql",
            "fallback_used": self.fallback_used,
        }

    @audit_error_handler
    async def save_inventory(self, inventory: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Save inventory to file using safe JSON operations."""
        if not output_path:
            output_path = f"docs/inventory/schema_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_file = Path(output_path)
        safe_write_json(output_file, inventory)

        logger.info(f"Schema inventory saved to {output_path}")
        return output_path


async def main():
    """Main function for running schema discovery."""
    tool = SchemaDiscoveryTool()

    logger.info("Starting schema discovery...")
    inventory = await tool.discover_schema()

    output_path = await tool.save_inventory(inventory)

    print(f"Schema discovery completed. Results saved to: {output_path}")
    print(f"Discovered {len(inventory['tables'])} tables")
    print(f"Found {len(inventory['relationships'])} relationships")
    print(f"Identified {len(inventory['indexes'])} indexes")


if __name__ == "__main__":
    asyncio.run(main())
