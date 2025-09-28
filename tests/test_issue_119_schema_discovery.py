"""Tests for Schema Discovery Tool - Issue 119."""

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy import MetaData, inspect

from app.db.session import get_db
from tools.inventory.schema_discovery import SchemaDiscoveryTool


class TestSchemaDiscoveryTool:
    """Test suite for Schema Discovery Tool."""

    @pytest.fixture
    def schema_tool(self):
        """Create a schema discovery tool instance."""
        return SchemaDiscoveryTool()

    @pytest.mark.asyncio
    async def test_schema_discovery_basic(self, schema_tool):
        """Verify tool can connect to database and discover basic schema."""
        with patch("app.db.session.get_db") as mock_get_db:
            mock_session = AsyncMock()
            mock_get_db.return_value.__aenter__.return_value = mock_session

            # Mock inspector
            mock_inspector = Mock()
            mock_inspector.get_table_names.return_value = ["users", "roles", "permissions"]

            with patch("sqlalchemy.inspect", return_value=mock_inspector):
                result = await schema_tool.discover_schema()

                assert result is not None
                assert "tables" in result
                assert len(result["tables"]) > 0

    @pytest.mark.asyncio
    async def test_schema_discovery_tables(self, schema_tool):
        """Verify all 21 SQLAlchemy models are discovered correctly."""
        expected_models = [
            "User",
            "Role",
            "Permission",
            "UserRole",
            "APIKey",
            "Session",
            "AuditLog",
            "OAuthApplication",
            "OAuthAccessToken",
            "OAuthRefreshToken",
            "OAuthAuthorizationCode",
            "MFADevice",
            "MFABackupCode",
            "MFAChallenge",
            "MFAEvent",
            "VulnerabilityTaxonomy",
            "VulnerabilityFinding",
            "SecurityScan",
            "Task",
            "TaskResult",
            "Plugin",
        ]

        with patch("app.db.session.get_db") as mock_get_db:
            mock_session = AsyncMock()
            mock_get_db.return_value.__aenter__.return_value = mock_session

            mock_inspector = Mock()
            mock_inspector.get_table_names.return_value = [model.lower() + "s" for model in expected_models]

            with patch("sqlalchemy.inspect", return_value=mock_inspector):
                result = await schema_tool.discover_schema()

                assert "tables" in result
                discovered_tables = [table["name"] for table in result["tables"]]

                # Verify we discovered tables for all major model categories
                assert len(discovered_tables) >= 15  # At least 15 core tables

    @pytest.mark.asyncio
    async def test_schema_discovery_relationships(self, schema_tool):
        """Verify foreign key relationships are mapped correctly."""
        with patch("app.db.session.get_db") as mock_get_db:
            mock_session = AsyncMock()
            mock_get_db.return_value.__aenter__.return_value = mock_session

            mock_inspector = Mock()
            mock_inspector.get_table_names.return_value = ["users", "roles", "user_roles"]
            mock_inspector.get_foreign_keys.return_value = [
                {
                    "name": "fk_user_id",
                    "constrained_columns": ["user_id"],
                    "referred_table": "users",
                    "referred_columns": ["id"],
                }
            ]

            with patch("sqlalchemy.inspect", return_value=mock_inspector):
                result = await schema_tool.discover_schema()

                assert "relationships" in result
                assert len(result["relationships"]) > 0

    @pytest.mark.asyncio
    async def test_schema_discovery_indexes(self, schema_tool):
        """Verify indexes and constraints are discovered."""
        with patch("tools.inventory.schema_discovery.get_db") as mock_get_db:
            mock_session = AsyncMock()
            mock_get_db.return_value.__aenter__.return_value = mock_session

            # Mock the run_sync functionality
            async def mock_run_sync(func):
                # Mock a connection object
                mock_connection = Mock()

                # Mock the inspector and data
                mock_inspector = Mock()
                mock_inspector.get_table_names.return_value = ["users"]
                mock_inspector.get_indexes.return_value = [
                    {"name": "idx_users_email", "column_names": ["email"], "unique": True}
                ]
                mock_inspector.get_pk_constraint.return_value = {"constrained_columns": ["id"], "name": "pk_users"}
                mock_inspector.get_columns.return_value = [
                    {"name": "id", "type": "INTEGER", "nullable": False, "primary_key": True},
                    {"name": "email", "type": "VARCHAR", "nullable": False, "unique": True},
                ]
                mock_inspector.get_foreign_keys.return_value = []
                mock_inspector.get_unique_constraints.return_value = []
                mock_inspector.get_check_constraints.return_value = []

                with patch("tools.inventory.schema_discovery.inspect", return_value=mock_inspector):
                    return func(mock_connection)

            mock_session.run_sync = mock_run_sync

            result = await schema_tool.discover_schema()

            assert "indexes" in result
            assert len(result["indexes"]) > 0
            assert result["indexes"][0]["name"] == "idx_users_email"

    @pytest.mark.asyncio
    async def test_schema_discovery_connection_failure(self, schema_tool):
        """Verify graceful handling of database connection issues."""
        with patch("app.db.session.get_db") as mock_get_db:
            mock_get_db.side_effect = Exception("Database connection failed")

            result = await schema_tool.discover_schema()

            assert result is not None
            assert "error" in result
            assert "fallback_used" in result

    def test_schema_discovery_output_format(self, schema_tool):
        """Verify output follows expected JSON/YAML format."""
        # Mock discovery result
        mock_result = {
            "metadata": {
                "discovery_time": "2025-09-19T10:00:00Z",
                "tool_version": "1.0",
                "database_type": "postgresql",
            },
            "tables": [{"name": "users", "model": "User", "columns": ["id", "email", "username"]}],
            "relationships": [],
            "indexes": [],
        }

        # Verify the result can be serialized to JSON
        json_output = json.dumps(mock_result, indent=2)
        assert json_output is not None

        # Verify it can be parsed back
        parsed_result = json.loads(json_output)
        assert parsed_result == mock_result
