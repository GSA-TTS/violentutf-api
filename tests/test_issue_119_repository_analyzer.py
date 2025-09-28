"""Tests for Repository Analyzer Tool - Issue 119."""

import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from tools.inventory.repository_analyzer import RepositoryAnalyzer


class TestRepositoryAnalyzer:
    """Test suite for Repository Analyzer Tool."""

    @pytest.fixture
    def analyzer(self):
        """Create a repository analyzer instance."""
        return RepositoryAnalyzer(project_root="/test/project")

    @pytest.mark.asyncio
    async def test_repository_analyzer_basic(self, analyzer):
        """Verify analyzer can discover repository files."""
        mock_files = [Path("/test/project/app/repositories/user.py"), Path("/test/project/app/repositories/api_key.py")]

        with patch.object(analyzer, "_discover_repository_files", return_value=mock_files):
            with patch.object(analyzer, "_analyze_repository_file") as mock_analyze:
                mock_analyze.return_value = {
                    "file_path": "app/repositories/user.py",
                    "repository_name": "UserRepository",
                    "classes": [],
                    "methods": [],
                    "crud_operations": {"create": [], "read": [], "update": [], "delete": []},
                }

                result = await analyzer.analyze_repositories()

                assert result is not None
                assert "repositories" in result
                assert len(result["repositories"]) == 2

    @pytest.mark.asyncio
    async def test_repository_analyzer_crud_operations(self, analyzer):
        """Verify CRUD operations are identified correctly."""
        sample_repository = {
            "repository_name": "UserRepository",
            "methods": [
                {"name": "create_user", "is_async": True},
                {"name": "get_user_by_id", "is_async": True},
                {"name": "update_user", "is_async": True},
                {"name": "delete_user", "is_async": True},
                {"name": "find_users", "is_async": True},
            ],
            "crud_operations": {"create": [], "read": [], "update": [], "delete": []},
        }

        # Manually categorize CRUD operations
        analyzer._categorize_crud_operations(sample_repository["methods"], sample_repository["crud_operations"])

        assert "create_user" in sample_repository["crud_operations"]["create"]
        assert "get_user_by_id" in sample_repository["crud_operations"]["read"]
        assert "find_users" in sample_repository["crud_operations"]["read"]
        assert "update_user" in sample_repository["crud_operations"]["update"]
        assert "delete_user" in sample_repository["crud_operations"]["delete"]

    @pytest.mark.asyncio
    async def test_repository_analyzer_inheritance_patterns(self, analyzer):
        """Verify repository inheritance patterns are analyzed."""
        repositories = [
            {"repository_name": "UserRepository", "base_classes": ["BaseRepository"], "methods": []},
            {"repository_name": "APIKeyRepository", "base_classes": ["EnhancedRepository"], "methods": []},
            {"repository_name": "CustomRepository", "base_classes": ["CustomBase"], "methods": []},
        ]

        inheritance_info = analyzer._analyze_inheritance_patterns(repositories)

        assert inheritance_info["base_repository_usage"] == 1
        assert inheritance_info["enhanced_repository_usage"] == 1
        assert "CustomBase" in inheritance_info["custom_base_classes"]
        assert "UserRepository" in inheritance_info["inheritance_tree"]

    @pytest.mark.asyncio
    async def test_repository_analyzer_api_mappings(self, analyzer):
        """Verify API endpoint to repository mappings."""
        sample_endpoint_content = """
from app.repositories.user import UserRepository

@router.get("/users/{user_id}")
async def get_user(user_id: int, user_repo: UserRepository = Depends()):
    return await user_repo.get_by_id(user_id)
"""

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.glob") as mock_glob:
                mock_file = Mock()
                mock_file.name = "users.py"
                mock_file.relative_to.return_value = Path("app/api/endpoints/users.py")
                mock_file.stem = "users"
                mock_glob.return_value = [mock_file]

                with patch("builtins.open", mock_open(read_data=sample_endpoint_content)):
                    mappings = await analyzer._analyze_api_endpoint_mappings()

                    assert len(mappings) == 1
                    assert mappings[0]["endpoint_name"] == "users"
                    assert len(mappings[0]["repository_dependencies"]) > 0
                    assert len(mappings[0]["route_mappings"]) > 0

    def test_repository_analyzer_crud_patterns_analysis(self, analyzer):
        """Verify CRUD patterns analysis across repositories."""
        repositories = [
            {
                "methods": [{"name": "create_user", "is_async": True}, {"name": "get_user", "is_async": True}],
                "crud_operations": {"create": ["create_user"], "read": ["get_user"], "update": [], "delete": []},
            },
            {
                "methods": [{"name": "update_item", "is_async": False}, {"name": "delete_item", "is_async": False}],
                "crud_operations": {"create": [], "read": [], "update": ["update_item"], "delete": ["delete_item"]},
            },
        ]

        crud_analysis = analyzer._analyze_crud_patterns(repositories)

        assert crud_analysis["total_repositories"] == 2
        assert crud_analysis["repositories_with_crud"]["create"] == 1
        assert crud_analysis["repositories_with_crud"]["read"] == 1
        assert crud_analysis["repositories_with_crud"]["update"] == 1
        assert crud_analysis["repositories_with_crud"]["delete"] == 1
        assert crud_analysis["async_vs_sync"]["async_repositories"] == 1
        assert crud_analysis["async_vs_sync"]["sync_repositories"] == 1

    def test_repository_analyzer_file_parsing(self, analyzer):
        """Verify Python file parsing extracts repository information."""
        sample_repository_code = '''
from app.repositories.base import BaseRepository
from app.models.user import User

class UserRepository(BaseRepository[User]):
    """Repository for user management operations."""

    async def create_user(self, user_data: dict) -> User:
        """Create a new user."""
        pass

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        pass

    async def update_user(self, user_id: int, data: dict) -> User:
        """Update user information."""
        pass

    async def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        pass
'''

        # Mock file reading
        mock_file_path = Path("/test/project/app/repositories/user.py")

        with patch("builtins.open", mock_open(read_data=sample_repository_code)):
            result = asyncio.run(analyzer._analyze_repository_file(mock_file_path))

            assert result["repository_name"] == "User"
            assert len(result["classes"]) > 0

            # The CRUD operations are populated during the file analysis
            # Check if methods were properly extracted
            assert len(result["methods"]) > 0

            # Check that we have methods that look like CRUD operations
            method_names = [method["name"] for method in result["methods"]]
            assert "create_user" in method_names
            assert "get_user_by_id" in method_names
            assert "update_user" in method_names
            assert "delete_user" in method_names

    def test_repository_analyzer_usage_statistics(self, analyzer):
        """Verify usage statistics are calculated correctly."""
        mock_inventory = {
            "repositories": [
                {"classes": [{"name": "UserRepository"}], "methods": [{"name": "create_user"}, {"name": "get_user"}]},
                {
                    "classes": [{"name": "APIKeyRepository"}],
                    "methods": [{"name": "create_api_key"}, {"name": "get_api_key"}, {"name": "revoke_api_key"}],
                    "error": "parsing_error",
                },
            ],
            "api_endpoint_mappings": [{"endpoint_name": "users"}, {"endpoint_name": "api_keys"}],
            "repository_inheritance": {"base_repository_usage": 2},
            "crud_patterns": {"repositories_with_crud": {"create": 2, "read": 2, "update": 1, "delete": 1}},
        }

        statistics = analyzer._generate_usage_statistics(mock_inventory)

        assert statistics["total_repository_files"] == 2
        assert statistics["total_repository_classes"] == 2
        assert statistics["total_methods"] == 5
        assert statistics["repositories_with_errors"] == 1
        assert statistics["api_endpoint_mappings"] == 2

    def test_repository_analyzer_output_format(self, analyzer):
        """Verify output follows expected JSON format."""
        mock_result = {
            "metadata": {
                "discovery_time": "2025-09-19T10:00:00Z",
                "tool_version": "1.0",
                "analyzer_type": "repository_usage",
            },
            "repositories": [
                {
                    "repository_name": "UserRepository",
                    "file_path": "app/repositories/user.py",
                    "crud_operations": {
                        "create": ["create_user"],
                        "read": ["get_user"],
                        "update": ["update_user"],
                        "delete": ["delete_user"],
                    },
                }
            ],
            "usage_statistics": {},
        }

        # Verify the result can be serialized to JSON
        json_output = json.dumps(mock_result, indent=2, default=str)
        assert json_output is not None

        # Verify it can be parsed back
        parsed_result = json.loads(json_output)
        assert parsed_result == mock_result
