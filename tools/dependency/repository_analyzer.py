"""Repository dependency analysis tool for ViolentUTF API."""

import ast
import importlib.util
import inspect
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

from structlog.stdlib import get_logger

logger = get_logger(__name__)


@dataclass
class RepositoryInfo:
    """Information about a repository class."""

    name: str
    file_path: str
    base_class: str
    model_class: Optional[str]
    methods: List[str]
    dependencies: List[str]
    specializations: List[str]
    imports: List[str]
    complexity_score: int


@dataclass
class ModelRelationship:
    """Information about model relationships."""

    source_model: str
    target_model: str
    relationship_type: str
    foreign_key: Optional[str]
    cascade: Optional[str]
    nullable: bool
    backref: Optional[str]


@dataclass
class RepositoryDependency:
    """Repository-to-repository dependency."""

    source_repository: str
    target_repository: str
    dependency_type: str
    usage_context: str
    frequency: int


@dataclass
class RepositoryAnalysisResult:
    """Results of repository dependency analysis."""

    metadata: Dict[str, Any]
    repositories: List[RepositoryInfo]
    model_relationships: List[ModelRelationship]
    repository_dependencies: List[RepositoryDependency]
    complexity_analysis: Dict[str, Any]
    inheritance_hierarchy: Dict[str, List[str]]
    pattern_analysis: Dict[str, Any]


class RepositoryDependencyAnalyzer:
    """Analyze repository patterns and dependencies."""

    def __init__(self, project_root: str):
        """Initialize the analyzer."""
        self.project_root = Path(project_root)
        self.app_root = self.project_root / "app"
        self.repositories_dir = self.app_root / "repositories"
        self.models_dir = self.app_root / "models"

        self.repositories_info: List[RepositoryInfo] = []
        self.model_relationships: List[ModelRelationship] = []
        self.repository_dependencies: List[RepositoryDependency] = []

        logger.info("RepositoryDependencyAnalyzer initialized", project_root=str(self.project_root))

    def analyze_all_repositories(self) -> RepositoryAnalysisResult:
        """Perform comprehensive repository dependency analysis."""
        logger.info("Starting comprehensive repository analysis")

        # Analyze individual repositories
        self._analyze_repository_files()

        # Analyze model relationships
        self._analyze_model_relationships()

        # Analyze repository dependencies
        self._analyze_repository_dependencies()

        # Analyze inheritance hierarchy
        inheritance_hierarchy = self._analyze_inheritance_hierarchy()

        # Analyze complexity
        complexity_analysis = self._analyze_complexity()

        # Analyze patterns
        pattern_analysis = self._analyze_patterns()

        result = RepositoryAnalysisResult(
            metadata={
                "analysis_date": datetime.now().isoformat(),
                "project_root": str(self.project_root),
                "total_repositories": len(self.repositories_info),
                "total_models": len(set(r.model_class for r in self.repositories_info if r.model_class)),
                "total_relationships": len(self.model_relationships),
                "analyzer_version": "1.0.0",
            },
            repositories=self.repositories_info,
            model_relationships=self.model_relationships,
            repository_dependencies=self.repository_dependencies,
            complexity_analysis=complexity_analysis,
            inheritance_hierarchy=inheritance_hierarchy,
            pattern_analysis=pattern_analysis,
        )

        logger.info(
            "Repository analysis completed",
            repositories=len(self.repositories_info),
            relationships=len(self.model_relationships),
            dependencies=len(self.repository_dependencies),
        )

        return result

    def _analyze_repository_files(self) -> None:
        """Analyze all repository files."""
        if not self.repositories_dir.exists():
            logger.warning("Repositories directory not found", path=str(self.repositories_dir))
            return

        logger.info("Analyzing repository files")

        for repo_file in self.repositories_dir.glob("*.py"):
            if repo_file.name.startswith("__"):
                continue

            try:
                repo_info = self._analyze_repository_file(repo_file)
                if repo_info:
                    self.repositories_info.append(repo_info)
            except Exception as e:
                logger.error("Error analyzing repository file", file=str(repo_file), error=str(e))

    def _analyze_repository_file(self, file_path: Path) -> Optional[RepositoryInfo]:
        """Analyze a single repository file."""
        logger.debug("Analyzing repository file", file=str(file_path))

        try:
            with open(file_path, "r") as f:
                content = f.read()
                tree = ast.parse(content)
        except Exception as e:
            logger.error("Failed to parse repository file", file=str(file_path), error=str(e))
            return None

        # Extract imports
        imports = self._extract_imports(tree)

        # Find repository class
        repo_class = self._find_repository_class(tree)
        if not repo_class:
            return None

        # Extract class information
        methods = self._extract_class_methods(repo_class)
        base_class = self._extract_base_class(repo_class)
        model_class = self._extract_model_class(repo_class, content)
        dependencies = self._extract_dependencies(repo_class, imports)
        specializations = self._extract_specializations(methods)
        complexity_score = self._calculate_complexity(repo_class)

        repo_name = repo_class.name

        return RepositoryInfo(
            name=repo_name,
            file_path=str(file_path),
            base_class=base_class,
            model_class=model_class,
            methods=methods,
            dependencies=dependencies,
            specializations=specializations,
            imports=imports,
            complexity_score=complexity_score,
        )

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract import statements from AST."""
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)

        return imports

    def _find_repository_class(self, tree: ast.AST) -> Optional[ast.ClassDef]:
        """Find the main repository class in the file."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check if class name suggests it's a repository
                if node.name.endswith("Repository") or "Repository" in node.name or node.name.endswith("Repo"):
                    return node
        return None

    def _extract_class_methods(self, class_node: ast.ClassDef) -> List[str]:
        """Extract method names from class."""
        methods = []

        for node in class_node.body:
            if isinstance(node, ast.FunctionDef):
                if not node.name.startswith("_"):  # Skip private methods
                    methods.append(node.name)

        return methods

    def _extract_base_class(self, class_node: ast.ClassDef) -> str:
        """Extract base class name."""
        if class_node.bases:
            base = class_node.bases[0]
            if isinstance(base, ast.Name):
                return base.id
            elif isinstance(base, ast.Attribute):
                return f"{base.value.id}.{base.attr}" if hasattr(base.value, "id") else str(base.attr)
        return "object"

    def _extract_model_class(self, class_node: ast.ClassDef, content: str) -> Optional[str]:
        """Extract associated model class."""
        # Look for model assignment in class body
        for node in class_node.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "model":
                        if isinstance(node.value, ast.Name):
                            return node.value.id
                        elif isinstance(node.value, ast.Attribute):
                            return node.value.attr

        # Try to infer from repository name
        repo_name = class_node.name
        if repo_name.endswith("Repository"):
            model_name = repo_name[:-10]  # Remove 'Repository'
            return model_name

        return None

    def _extract_dependencies(self, class_node: ast.ClassDef, imports: List[str]) -> List[str]:
        """Extract repository dependencies."""
        dependencies = []

        # Look for other repository imports
        for import_name in imports:
            if "repository" in import_name.lower() or "repo" in import_name.lower():
                dependencies.append(import_name)

        # Look for repository usage in method bodies
        for node in ast.walk(class_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if "repository" in str(node.func).lower():
                        dependencies.append(str(node.func))

        return list(set(dependencies))  # Remove duplicates

    def _extract_specializations(self, methods: List[str]) -> List[str]:
        """Extract specialized methods (non-CRUD operations)."""
        crud_methods = {
            "create",
            "read",
            "update",
            "delete",
            "get",
            "list",
            "find",
            "get_by_id",
            "get_all",
            "save",
            "remove",
            "exists",
            "count",
        }

        specializations = []
        for method in methods:
            if method.lower() not in crud_methods:
                specializations.append(method)

        return specializations

    def _calculate_complexity(self, class_node: ast.ClassDef) -> int:
        """Calculate complexity score for repository."""
        score = 0

        # Count methods
        score += len([n for n in class_node.body if isinstance(n, ast.FunctionDef)])

        # Count control flow statements
        for node in ast.walk(class_node):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.Try)):
                score += 1
            elif isinstance(node, ast.FunctionDef):
                # Count arguments
                score += len(node.args.args)

        return score

    def _analyze_model_relationships(self) -> None:
        """Analyze model relationships."""
        if not self.models_dir.exists():
            logger.warning("Models directory not found", path=str(self.models_dir))
            return

        logger.info("Analyzing model relationships")

        for model_file in self.models_dir.glob("*.py"):
            if model_file.name.startswith("__"):
                continue

            try:
                relationships = self._analyze_model_file(model_file)
                self.model_relationships.extend(relationships)
            except Exception as e:
                logger.error("Error analyzing model file", file=str(model_file), error=str(e))

    def _analyze_model_file(self, file_path: Path) -> List[ModelRelationship]:
        """Analyze relationships in a model file."""
        relationships = []

        try:
            with open(file_path, "r") as f:
                content = f.read()
                tree = ast.parse(content)
        except Exception as e:
            logger.error("Failed to parse model file", file=str(file_path), error=str(e))
            return relationships

        # Find model classes
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Look for SQLAlchemy relationships
                model_name = node.name
                relationships.extend(self._extract_model_relationships(node, model_name))

        return relationships

    def _extract_model_relationships(self, class_node: ast.ClassDef, model_name: str) -> List[ModelRelationship]:
        """Extract relationships from a model class."""
        relationships = []

        for node in class_node.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if this is a relationship assignment
                        rel_info = self._analyze_relationship_assignment(node.value)
                        if rel_info:
                            relationship = ModelRelationship(
                                source_model=model_name,
                                target_model=rel_info.get("target_model", "Unknown"),
                                relationship_type=rel_info.get("type", "unknown"),
                                foreign_key=rel_info.get("foreign_key"),
                                cascade=rel_info.get("cascade"),
                                nullable=rel_info.get("nullable", True),
                                backref=rel_info.get("backref"),
                            )
                            relationships.append(relationship)

        return relationships

    def _analyze_relationship_assignment(self, value_node: ast.AST) -> Optional[Dict[str, Any]]:
        """Analyze a relationship assignment."""
        if not isinstance(value_node, ast.Call):
            return None

        func_name = None
        if isinstance(value_node.func, ast.Name):
            func_name = value_node.func.id
        elif isinstance(value_node.func, ast.Attribute):
            func_name = value_node.func.attr

        if func_name not in ["relationship", "ForeignKey", "Column"]:
            return None

        rel_info = {"type": func_name.lower()}

        # Analyze arguments
        for arg in value_node.args:
            if isinstance(arg, ast.Constant):
                if func_name == "relationship":
                    rel_info["target_model"] = str(arg.value)
                elif func_name == "ForeignKey":
                    rel_info["foreign_key"] = str(arg.value)

        # Analyze keyword arguments
        for keyword in value_node.keywords:
            if keyword.arg in ["cascade", "backref", "nullable"]:
                if isinstance(keyword.value, ast.Constant):
                    rel_info[keyword.arg] = keyword.value.value
                else:
                    rel_info[keyword.arg] = str(keyword.value)

        return rel_info

    def _analyze_repository_dependencies(self) -> None:
        """Analyze dependencies between repositories."""
        logger.info("Analyzing repository dependencies")

        # Analyze cross-repository method calls
        for repo in self.repositories_info:
            deps = self._find_repository_dependencies(repo)
            self.repository_dependencies.extend(deps)

    def _find_repository_dependencies(self, repo: RepositoryInfo) -> List[RepositoryDependency]:
        """Find dependencies for a specific repository."""
        dependencies = []

        # Analyze repository file for cross-repository calls
        try:
            with open(repo.file_path, "r") as f:
                content = f.read()
                tree = ast.parse(content)
        except Exception as e:
            logger.error("Failed to analyze repository dependencies", repo=repo.name, error=str(e))
            return dependencies

        # Look for repository instantiation or usage
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if calling another repository
                target_repo = self._identify_repository_call(node)
                if target_repo and target_repo != repo.name:
                    dependency = RepositoryDependency(
                        source_repository=repo.name,
                        target_repository=target_repo,
                        dependency_type="method_call",
                        usage_context="repository_method",
                        frequency=1,  # Would need runtime analysis for actual frequency
                    )
                    dependencies.append(dependency)

        return dependencies

    def _identify_repository_call(self, call_node: ast.Call) -> Optional[str]:
        """Identify if a call is to another repository."""
        if isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                var_name = call_node.func.value.id
                if "repository" in var_name.lower() or "repo" in var_name.lower():
                    # Try to extract repository name
                    return var_name.replace("_repository", "").replace("_repo", "")

        return None

    def _analyze_inheritance_hierarchy(self) -> Dict[str, List[str]]:
        """Analyze repository inheritance hierarchy."""
        hierarchy = defaultdict(list)

        for repo in self.repositories_info:
            base_class = repo.base_class
            if base_class != "object":
                hierarchy[base_class].append(repo.name)

        return dict(hierarchy)

    def _analyze_complexity(self) -> Dict[str, Any]:
        """Analyze complexity metrics across repositories."""
        if not self.repositories_info:
            return {}

        complexity_scores = [repo.complexity_score for repo in self.repositories_info]
        method_counts = [len(repo.methods) for repo in self.repositories_info]
        dependency_counts = [len(repo.dependencies) for repo in self.repositories_info]

        return {
            "average_complexity": sum(complexity_scores) / len(complexity_scores),
            "max_complexity": max(complexity_scores),
            "min_complexity": min(complexity_scores),
            "average_methods_per_repo": sum(method_counts) / len(method_counts),
            "average_dependencies_per_repo": sum(dependency_counts) / len(dependency_counts),
            "most_complex_repository": max(self.repositories_info, key=lambda r: r.complexity_score).name,
            "total_specializations": sum(len(repo.specializations) for repo in self.repositories_info),
        }

    def _analyze_patterns(self) -> Dict[str, Any]:
        """Analyze common patterns across repositories."""
        patterns = {
            "common_methods": defaultdict(int),
            "common_specializations": defaultdict(int),
            "common_base_classes": defaultdict(int),
            "naming_patterns": defaultdict(int),
        }

        for repo in self.repositories_info:
            # Count common methods
            for method in repo.methods:
                patterns["common_methods"][method] += 1

            # Count specializations
            for spec in repo.specializations:
                patterns["common_specializations"][spec] += 1

            # Count base classes
            patterns["common_base_classes"][repo.base_class] += 1

            # Analyze naming patterns
            if repo.name.endswith("Repository"):
                patterns["naming_patterns"]["ends_with_repository"] += 1
            if "Service" in repo.name:
                patterns["naming_patterns"]["contains_service"] += 1

        # Convert to regular dict and sort by frequency
        result = {}
        for pattern_type, pattern_dict in patterns.items():
            result[pattern_type] = dict(sorted(pattern_dict.items(), key=lambda x: x[1], reverse=True))

        return result

    def export_analysis(self, result: RepositoryAnalysisResult, output_path: str) -> None:
        """Export repository analysis results to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary for JSON serialization
        result_dict = {
            "metadata": result.metadata,
            "repositories": [asdict(repo) for repo in result.repositories],
            "model_relationships": [asdict(rel) for rel in result.model_relationships],
            "repository_dependencies": [asdict(dep) for dep in result.repository_dependencies],
            "complexity_analysis": result.complexity_analysis,
            "inheritance_hierarchy": result.inheritance_hierarchy,
            "pattern_analysis": result.pattern_analysis,
        }

        with open(output_file, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info("Repository analysis exported", output_path=str(output_file))


def main():
    """Main entry point for standalone execution."""
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = sys.argv[2] if len(sys.argv) > 2 else "repository_analysis.json"

    analyzer = RepositoryDependencyAnalyzer(project_root)
    result = analyzer.analyze_all_repositories()
    analyzer.export_analysis(result, output_path)

    print(f"Repository analysis completed. Results saved to {output_path}")


if __name__ == "__main__":
    main()
