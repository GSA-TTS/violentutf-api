"""Repository Usage Analyzer for Database Audit Phase 1.

This tool analyzes repository patterns and usage across the codebase including:
- All 31 repositories and their CRUD operations
- Repository method usage across API endpoints
- Repository inheritance from BaseRepository
- Transaction patterns and connection usage
"""

import ast
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from audit_utils.exceptions import audit_error_handler
from audit_utils.file_operations import safe_write_json
from audit_utils.logging import setup_audit_logger

logger = setup_audit_logger(__name__)


class RepositoryAnalyzer:
    """Tool for analyzing repository usage patterns and data access."""

    def __init__(self, project_root: Optional[str] = None):
        """Initialize the repository analyzer."""
        self.version = "1.0"
        self.discovery_time = None
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.repositories_path = self.project_root / "app" / "repositories"
        self.api_endpoints_path = self.project_root / "app" / "api" / "endpoints"

    @audit_error_handler
    async def analyze_repositories(self) -> Dict[str, Any]:
        """
        Analyze complete repository usage patterns.

        Returns:
            Dict containing repository analysis inventory
        """
        self.discovery_time = datetime.now().isoformat() + "Z"

        repository_inventory = {
            "metadata": self._get_metadata(),
            "repositories": [],
            "repository_inheritance": {},
            "api_endpoint_mappings": [],
            "crud_patterns": {},
            "transaction_patterns": [],
            "usage_statistics": {},
        }

        try:
            # Discover all repository files
            repository_files = self._discover_repository_files()
            logger.info(f"Discovered {len(repository_files)} repository files")

            # Analyze each repository
            for repo_file in repository_files:
                repo_analysis = await self._analyze_repository_file(repo_file)
                repository_inventory["repositories"].append(repo_analysis)

            # Analyze repository inheritance patterns
            repository_inventory["repository_inheritance"] = self._analyze_inheritance_patterns(
                repository_inventory["repositories"]
            )

            # Analyze API endpoint to repository mappings
            repository_inventory["api_endpoint_mappings"] = await self._analyze_api_endpoint_mappings()

            # Analyze CRUD patterns
            repository_inventory["crud_patterns"] = self._analyze_crud_patterns(repository_inventory["repositories"])

            # Generate usage statistics
            repository_inventory["usage_statistics"] = self._generate_usage_statistics(repository_inventory)

        except Exception as e:
            logger.error(f"Error during repository analysis: {e}")
            repository_inventory["error"] = str(e)

        return repository_inventory

    @audit_error_handler
    def _discover_repository_files(self) -> List[Path]:
        """Discover all repository Python files."""
        repository_files = []

        if self.repositories_path.exists():
            for file_path in self.repositories_path.glob("*.py"):
                if file_path.name not in ["__init__.py", "__pycache__"]:
                    repository_files.append(file_path)

        # Also check for repositories in subdirectories
        for subdirectory in self.repositories_path.glob("*/"):
            if subdirectory.name not in ["__pycache__", "interfaces"]:
                for file_path in subdirectory.glob("*.py"):
                    if file_path.name != "__init__.py":
                        repository_files.append(file_path)

        return sorted(repository_files)

    @audit_error_handler
    async def _analyze_repository_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a single repository file."""
        repo_analysis = {
            "file_path": str(file_path.relative_to(self.project_root)),
            "repository_name": self._extract_repository_name(file_path),
            "classes": [],
            "methods": [],
            "imports": [],
            "base_classes": [],
            "dependencies": [],
            "crud_operations": {"create": [], "read": [], "update": [], "delete": []},
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse the Python AST
            tree = ast.parse(content)

            # Extract imports
            repo_analysis["imports"] = self._extract_imports(tree)

            # Extract classes and their details
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._analyze_class(node)
                    repo_analysis["classes"].append(class_info)

                    # Check if this is a repository class
                    is_repository = (
                        any("Repository" in str(base) for base in class_info["base_classes"])
                        or "Repository" in class_info["name"]
                    )

                    if is_repository:
                        repo_analysis["base_classes"] = class_info["base_classes"]
                        repo_analysis["methods"] = class_info["methods"]

                        # Categorize CRUD operations
                        self._categorize_crud_operations(class_info["methods"], repo_analysis["crud_operations"])

        except Exception as e:
            logger.warning(f"Failed to analyze repository file {file_path}: {e}")
            repo_analysis["error"] = str(e)

        return repo_analysis

    def _extract_repository_name(self, file_path: Path) -> str:
        """Extract repository name from file path."""
        name = file_path.stem

        # Convert snake_case to PascalCase for class name
        if "_" in name:
            parts = name.split("_")
            return "".join(part.capitalize() for part in parts)
        else:
            return name.capitalize()

    def _extract_imports(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract import statements from AST."""
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({"type": "import", "module": alias.name, "alias": alias.asname})
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imports.append(
                        {"type": "from_import", "module": node.module, "name": alias.name, "alias": alias.asname}
                    )

        return imports

    def _analyze_class(self, class_node: ast.ClassDef) -> Dict[str, Any]:
        """Analyze a class definition."""
        class_info = {
            "name": class_node.name,
            "base_classes": [base.id if isinstance(base, ast.Name) else str(base) for base in class_node.bases],
            "methods": [],
            "decorators": [
                decorator.id if isinstance(decorator, ast.Name) else str(decorator)
                for decorator in class_node.decorator_list
            ],
        }

        # Extract methods (both sync and async)
        for node in class_node.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_info = self._analyze_method(node)
                class_info["methods"].append(method_info)

        return class_info

    def _analyze_method(self, method_node) -> Dict[str, Any]:
        """Analyze a method definition."""
        method_info = {
            "name": method_node.name,
            "arguments": [arg.arg for arg in method_node.args.args],
            "decorators": [
                decorator.id if isinstance(decorator, ast.Name) else str(decorator)
                for decorator in method_node.decorator_list
            ],
            "is_async": isinstance(method_node, ast.AsyncFunctionDef),
            "docstring": ast.get_docstring(method_node),
            "returns_type": None,
        }

        # Try to extract return type annotation
        if method_node.returns:
            method_info["returns_type"] = str(method_node.returns)

        return method_info

    def _categorize_crud_operations(self, methods: List[Dict[str, Any]], crud_operations: Dict[str, List]):
        """Categorize methods into CRUD operations."""
        crud_keywords = {
            "create": ["create", "add", "insert", "save", "register"],
            "read": ["get", "find", "fetch", "list", "search", "query", "retrieve", "select"],
            "update": ["update", "modify", "edit", "change", "patch"],
            "delete": ["delete", "remove", "destroy", "drop"],
        }

        for method in methods:
            method_name = method["name"].lower()

            for operation, keywords in crud_keywords.items():
                if any(keyword in method_name for keyword in keywords):
                    crud_operations[operation].append(method["name"])
                    break

    @audit_error_handler
    def _analyze_inheritance_patterns(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze repository inheritance patterns."""
        inheritance_info = {
            "base_repository_usage": 0,
            "enhanced_repository_usage": 0,
            "custom_base_classes": [],
            "inheritance_tree": {},
        }

        for repo in repositories:
            if repo.get("base_classes"):
                for base_class in repo["base_classes"]:
                    if "BaseRepository" in base_class:
                        inheritance_info["base_repository_usage"] += 1
                    elif "EnhancedRepository" in base_class:
                        inheritance_info["enhanced_repository_usage"] += 1
                    else:
                        inheritance_info["custom_base_classes"].append(base_class)

                inheritance_info["inheritance_tree"][repo["repository_name"]] = repo["base_classes"]

        return inheritance_info

    @audit_error_handler
    async def _analyze_api_endpoint_mappings(self) -> List[Dict[str, Any]]:
        """Analyze API endpoint to repository mappings."""
        mappings = []

        if not self.api_endpoints_path.exists():
            logger.warning("API endpoints path not found")
            return mappings

        try:
            for endpoint_file in self.api_endpoints_path.glob("*.py"):
                if endpoint_file.name == "__init__.py":
                    continue

                mapping = await self._analyze_endpoint_file(endpoint_file)
                if mapping:
                    mappings.append(mapping)

        except Exception as e:
            logger.warning(f"Failed to analyze API endpoints: {e}")

        return mappings

    @audit_error_handler
    async def _analyze_endpoint_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze a single API endpoint file for repository usage."""
        endpoint_mapping = {
            "endpoint_file": str(file_path.relative_to(self.project_root)),
            "endpoint_name": file_path.stem,
            "repository_dependencies": [],
            "route_mappings": [],
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Look for repository imports and usage
            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                stripped_line = line.strip()

                # Check for repository imports
                if "Repository" in line and ("import" in line or "from" in line):
                    endpoint_mapping["repository_dependencies"].append(
                        {"line": line_num, "import_statement": stripped_line}
                    )

                # Check for route definitions
                if "@router." in line or "@app." in line:
                    route_info = {"line": line_num, "route_definition": stripped_line}
                    endpoint_mapping["route_mappings"].append(route_info)

        except Exception as e:
            logger.warning(f"Failed to analyze endpoint file {file_path}: {e}")
            endpoint_mapping["error"] = str(e)

        return endpoint_mapping if endpoint_mapping["repository_dependencies"] else None

    @audit_error_handler
    def _analyze_crud_patterns(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze CRUD patterns across all repositories."""
        crud_analysis = {
            "total_repositories": len(repositories),
            "repositories_with_crud": {"create": 0, "read": 0, "update": 0, "delete": 0},
            "common_method_names": {"create": set(), "read": set(), "update": set(), "delete": set()},
            "async_vs_sync": {"async_repositories": 0, "sync_repositories": 0},
        }

        for repo in repositories:
            crud_ops = repo.get("crud_operations", {})

            # Count repositories with each CRUD operation
            for operation in ["create", "read", "update", "delete"]:
                if crud_ops.get(operation):
                    crud_analysis["repositories_with_crud"][operation] += 1
                    crud_analysis["common_method_names"][operation].update(crud_ops[operation])

            # Check if repository has async methods
            has_async = False
            for method in repo.get("methods", []):
                if method.get("is_async"):
                    has_async = True
                    break

            if has_async:
                crud_analysis["async_vs_sync"]["async_repositories"] += 1
            else:
                crud_analysis["async_vs_sync"]["sync_repositories"] += 1

        # Convert sets to lists for JSON serialization
        for operation in ["create", "read", "update", "delete"]:
            crud_analysis["common_method_names"][operation] = list(crud_analysis["common_method_names"][operation])

        return crud_analysis

    def _generate_usage_statistics(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Generate usage statistics summary."""
        repositories = inventory.get("repositories", [])

        statistics = {
            "total_repository_files": len(repositories),
            "total_repository_classes": sum(len(repo.get("classes", [])) for repo in repositories),
            "total_methods": sum(len(repo.get("methods", [])) for repo in repositories),
            "repositories_with_errors": len([repo for repo in repositories if "error" in repo]),
            "api_endpoint_mappings": len(inventory.get("api_endpoint_mappings", [])),
            "inheritance_patterns": inventory.get("repository_inheritance", {}),
            "crud_coverage": inventory.get("crud_patterns", {}).get("repositories_with_crud", {}),
        }

        return statistics

    def _get_metadata(self) -> Dict[str, Any]:
        """Get analysis metadata."""
        return {
            "discovery_time": self.discovery_time,
            "tool_version": self.version,
            "project_root": str(self.project_root),
            "analyzer_type": "repository_usage",
        }

    @audit_error_handler
    async def save_inventory(self, inventory: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Save inventory to file using safe JSON operations."""
        if not output_path:
            output_path = f"docs/inventory/repository_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_file = Path(output_path)
        safe_write_json(output_file, inventory)

        logger.info(f"Repository analysis saved to {output_path}")
        return output_path


async def main():
    """Main function for running repository analysis."""
    analyzer = RepositoryAnalyzer()

    logger.info("Starting repository analysis...")
    inventory = await analyzer.analyze_repositories()

    output_path = await analyzer.save_inventory(inventory)

    print(f"Repository analysis completed. Results saved to: {output_path}")
    print(f"Analyzed {inventory['usage_statistics']['total_repository_files']} repository files")
    print(f"Found {inventory['usage_statistics']['total_repository_classes']} repository classes")
    print(f"Identified {inventory['usage_statistics']['total_methods']} methods")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
