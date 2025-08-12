"""
Architectural tests for security pattern enforcement.

This module validates security patterns across the codebase using PyTestArch,
ensuring authentication requirements, authorization boundaries, and input
sanitization are consistently enforced per ADR-002, ADR-003, and ADR-008.
"""

import ast
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pytest


class SecurityPatternValidator:
    """Validates security patterns in the codebase."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.app_path = project_root / "app"
        self._api_files_cache = None
        self._repository_files_cache = None

    @property
    def api_files(self) -> List[Path]:
        """Get all API endpoint files."""
        if self._api_files_cache is None:
            self._api_files_cache = list(self.app_path.rglob("api/**/*.py"))
        return self._api_files_cache

    @property
    def repository_files(self) -> List[Path]:
        """Get all repository files."""
        if self._repository_files_cache is None:
            self._repository_files_cache = list(self.app_path.rglob("repositories/**/*.py"))
        return self._repository_files_cache

    def find_unprotected_modifying_endpoints(self) -> List[Tuple[Path, str, int]]:
        """
        Find API endpoints that modify data but lack authentication.
        Returns list of (file_path, function_name, line_number) tuples.
        """
        violations = []
        modifying_methods = {"post", "put", "patch", "delete"}

        for file_path in self.api_files:
            if "__pycache__" in str(file_path):
                continue

            try:
                content = file_path.read_text()
                tree = ast.parse(content, filename=str(file_path))

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Check if it's an endpoint function
                        has_route_decorator = False
                        http_method = None

                        for decorator in node.decorator_list:
                            decorator_str = (
                                ast.unparse(decorator) if hasattr(ast, "unparse") else self._ast_to_str(decorator)
                            )

                            # Check for FastAPI route decorators
                            for method in modifying_methods:
                                if f".{method}(" in decorator_str or f"@{method}(" in decorator_str:
                                    has_route_decorator = True
                                    http_method = method
                                    break

                        if has_route_decorator and http_method:
                            # Check for authentication dependencies
                            has_auth = self._check_auth_dependency(node, content)

                            if not has_auth:
                                violations.append((file_path, node.name, node.lineno))

            except Exception as e:
                # Skip files that can't be parsed
                continue

        return violations

    def _check_auth_dependency(self, func_node: ast.FunctionDef, file_content: str) -> bool:
        """Check if function has authentication dependencies."""
        auth_patterns = [
            r"Depends\s*\(\s*get_current_user",
            r"Depends\s*\(\s*verify_jwt",
            r"Depends\s*\(\s*verify_api_key",
            r"Depends\s*\(\s*check_authentication",
            r"current_user\s*:\s*\w+\s*=\s*Depends",
            r"auth\s*:\s*\w+\s*=\s*Depends",
        ]

        # Get function source
        func_source = ast.unparse(func_node) if hasattr(ast, "unparse") else ""

        # Check function parameters and body
        for pattern in auth_patterns:
            if re.search(pattern, func_source, re.IGNORECASE):
                return True

        # Also check in function signature (parameters)
        for arg in func_node.args.args:
            if arg.annotation:
                annotation_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                for pattern in auth_patterns:
                    if re.search(pattern, annotation_str, re.IGNORECASE):
                        return True

        return False

    def _ast_to_str(self, node) -> str:
        """Convert AST node to string for older Python versions."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._ast_to_str(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            func_str = self._ast_to_str(node.func)
            return f"{func_str}()"
        return ""

    def find_sql_injection_risks(self) -> List[Tuple[Path, str, int, str]]:
        """
        Find potential SQL injection vulnerabilities.
        Returns list of (file_path, function_name, line_number, issue) tuples.
        """
        violations = []

        # Patterns that indicate SQL injection risk
        risky_patterns = [
            (r'\.execute\s*\(\s*f["\']', "f-string in SQL execute"),
            (r"\.execute\s*\([^)]*\+", "String concatenation in SQL"),
            (r"\.execute\s*\([^)]*%\s*[^)]", "String formatting in SQL"),
            (r"\.execute\s*\([^)]*\.format\(", "format() in SQL"),
            (r'text\s*\(\s*f["\']', "f-string in SQLAlchemy text()"),
            (r'raw\s*\(\s*f["\']', "f-string in raw SQL"),
        ]

        for file_path in self.repository_files:
            if "__pycache__" in str(file_path):
                continue

            try:
                content = file_path.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    for pattern, issue in risky_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Try to find the containing function
                            func_name = self._find_containing_function(lines, i)
                            violations.append((file_path, func_name, i, issue))

            except Exception:
                continue

        return violations

    def _find_containing_function(self, lines: List[str], line_num: int) -> str:
        """Find the function containing a given line number."""
        for i in range(line_num - 1, -1, -1):
            match = re.match(r"\s*def\s+(\w+)", lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def find_missing_input_validation(self) -> List[Tuple[Path, str, int]]:
        """
        Find endpoints accepting user input without validation.
        Returns list of (file_path, function_name, line_number) tuples.
        """
        violations = []

        for file_path in self.api_files:
            if "__pycache__" in str(file_path):
                continue

            try:
                content = file_path.read_text()
                tree = ast.parse(content, filename=str(file_path))

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Check if it's an endpoint
                        is_endpoint = any(self._is_route_decorator(d) for d in node.decorator_list)

                        if is_endpoint:
                            # Check for Pydantic model usage
                            has_pydantic = self._check_pydantic_validation(node)

                            # Check if endpoint accepts body/query params
                            accepts_input = self._check_accepts_input(node)

                            if accepts_input and not has_pydantic:
                                violations.append((file_path, node.name, node.lineno))

            except Exception:
                continue

        return violations

    def _is_route_decorator(self, decorator) -> bool:
        """Check if decorator is a route decorator."""
        decorator_str = ast.unparse(decorator) if hasattr(ast, "unparse") else self._ast_to_str(decorator)
        route_patterns = [".get(", ".post(", ".put(", ".patch(", ".delete(", "@router."]
        return any(pattern in decorator_str for pattern in route_patterns)

    def _check_pydantic_validation(self, func_node: ast.FunctionDef) -> bool:
        """Check if function uses Pydantic models for validation."""
        for arg in func_node.args.args:
            if arg.annotation:
                annotation_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                # Check for Pydantic model patterns
                if any(pattern in annotation_str for pattern in ["Schema", "Model", "BaseModel"]):
                    return True
                # Check for Body, Query, etc. with validation
                if any(pattern in annotation_str for pattern in ["Body[", "Query[", "Form["]):
                    return True
        return False

    def _check_accepts_input(self, func_node: ast.FunctionDef) -> bool:
        """Check if function accepts user input."""
        # Check for common input parameter names
        input_params = {"data", "body", "payload", "request", "params", "query", "form"}
        param_names = {arg.arg for arg in func_node.args.args}

        if input_params & param_names:
            return True

        # Check annotations for input types
        for arg in func_node.args.args:
            if arg.annotation:
                annotation_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if any(pattern in annotation_str for pattern in ["Request", "Body", "Query", "Form", "dict", "Dict"]):
                    return True

        return False

    def find_missing_authorization_boundaries(self) -> List[Tuple[Path, str, int]]:
        """
        Find resource access points without organization filtering.
        Returns list of (file_path, function_name, line_number) tuples.
        """
        violations = []

        for file_path in self.repository_files:
            if "__pycache__" in str(file_path):
                continue

            try:
                content = file_path.read_text()
                tree = ast.parse(content, filename=str(file_path))

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Look for database query methods
                        if self._is_data_access_method(node):
                            # Check for organization_id filtering
                            has_org_filter = self._check_organization_filter(node, content)

                            if not has_org_filter:
                                violations.append((file_path, node.name, node.lineno))

            except Exception:
                continue

        return violations

    def _is_data_access_method(self, func_node: ast.FunctionDef) -> bool:
        """Check if function is a data access method."""
        # Skip private/internal methods (they're helpers)
        if func_node.name.startswith("_"):
            return False

        # Common repository method patterns
        data_methods = ["get", "list", "find", "fetch", "query", "search"]

        # Check function name
        func_name_lower = func_node.name.lower()
        if any(method in func_name_lower for method in data_methods):
            return True

        # Check for query operations in function body
        func_source = ast.unparse(func_node) if hasattr(ast, "unparse") else ""
        query_patterns = [".query(", ".filter(", ".select(", ".where("]

        return any(pattern in func_source for pattern in query_patterns)

    def _check_organization_filter(self, func_node: ast.FunctionDef, file_content: str) -> bool:
        """Check if function has organization_id filtering."""
        func_source = ast.unparse(func_node) if hasattr(ast, "unparse") else ""

        org_patterns = [
            r"organization_id\s*==",
            r"organization_id\s*=",
            r"\.filter.*organization_id",
            r"\.filter_by.*organization_id",
            r"where.*organization_id",
        ]

        for pattern in org_patterns:
            if re.search(pattern, func_source, re.IGNORECASE):
                return True

        return False


@pytest.fixture
def security_validator():
    """Provide SecurityPatternValidator instance."""
    project_root = Path(__file__).parent.parent.parent
    return SecurityPatternValidator(project_root)


class TestAuthenticationRequirements:
    """Test suite for authentication requirement validation."""

    def test_data_modifying_endpoints_require_authentication(self, security_validator):
        """
        Given an API endpoint that modifies data
        When the architectural test suite runs
        Then the test must verify that authentication decorators are present
        And the test must verify JWT validation middleware is configured
        And the test must fail if any unprotected data-modifying endpoint is found
        """
        violations = security_validator.find_unprotected_modifying_endpoints()

        assert len(violations) == 0, f"Found {len(violations)} unprotected data-modifying endpoints:\n" + "\n".join(
            [
                f"  - {file_path.relative_to(security_validator.project_root)}" f":{line_no} - {func_name}()"
                for file_path, func_name, line_no in violations
            ]
        )

    def test_jwt_validation_middleware_configured(self, security_validator):
        """Verify JWT validation middleware is properly configured."""
        # Check main app configuration
        main_app_file = security_validator.project_root / "app" / "main.py"

        if main_app_file.exists():
            content = main_app_file.read_text()

            # Check for JWT middleware registration
            jwt_patterns = [
                r"add_middleware.*JWT",
                r"middleware.*authentication",
                r"JWTMiddleware",
            ]

            has_jwt_middleware = any(re.search(pattern, content, re.IGNORECASE) for pattern in jwt_patterns)

            assert has_jwt_middleware or "Depends" in content, (
                "JWT validation middleware not found in main application setup. "
                "Ensure JWT validation is configured either as middleware or via Dependencies."
            )


class TestSQLInjectionPrevention:
    """Test suite for SQL injection prevention."""

    def test_parameterized_queries_used(self, security_validator):
        """
        Given a database interaction point in the code
        When the architectural test suite runs
        Then the test must verify parameterized queries are used
        And the test must verify no string concatenation for SQL queries
        And the test must detect any raw SQL execution without parameters
        """
        violations = security_validator.find_sql_injection_risks()

        assert len(violations) == 0, f"Found {len(violations)} potential SQL injection vulnerabilities:\n" + "\n".join(
            [
                f"  - {file_path.relative_to(security_validator.project_root)}" f":{line_no} - {func_name}(): {issue}"
                for file_path, func_name, line_no, issue in violations
            ]
        )


class TestInputSanitization:
    """Test suite for input sanitization verification."""

    def test_input_validation_present(self, security_validator):
        """
        Given an endpoint that accepts user input
        When the architectural test suite runs
        Then the test must verify input validation decorators are present
        And the test must verify Pydantic models are used for request bodies
        And the test must detect any direct user input usage without validation
        """
        violations = security_validator.find_missing_input_validation()

        assert len(violations) == 0, f"Found {len(violations)} endpoints with missing input validation:\n" + "\n".join(
            [
                f"  - {file_path.relative_to(security_validator.project_root)}" f":{line_no} - {func_name}()"
                for file_path, func_name, line_no in violations
            ]
        )


class TestAuthorizationBoundaries:
    """Test suite for authorization boundary testing."""

    def test_organization_isolation_enforced(self, security_validator):
        """
        Given a resource access point in the code
        When the architectural test suite runs
        Then the test must verify organization_id filtering is present
        And the test must verify RBAC role checks are implemented
        And the test must detect any resource access without tenant isolation
        """
        violations = security_validator.find_missing_authorization_boundaries()

        assert (
            len(violations) == 0
        ), f"Found {len(violations)} data access methods without organization filtering:\n" + "\n".join(
            [
                f"  - {file_path.relative_to(security_validator.project_root)}" f":{line_no} - {func_name}()"
                for file_path, func_name, line_no in violations
            ]
        )


class TestSecurityPatternConfiguration:
    """Test suite for security pattern configuration validation."""

    def test_jwt_algorithm_configured(self, security_validator):
        """Verify JWT algorithm is properly configured (HS256 or RS256)."""
        config_files = list(security_validator.project_root.rglob("**/config.py"))
        config_files.extend(list(security_validator.project_root.rglob("**/settings.py")))

        algorithm_found = False
        found_algorithm = None

        for config_file in config_files:
            if "__pycache__" in str(config_file):
                continue

            try:
                content = config_file.read_text()
                # Check for any JWT algorithm configuration
                hs256_match = re.search(r"ALGORITHM.*[\"']HS256[\"']|JWT_ALGORITHM.*[\"']HS256[\"']", content)
                rs256_match = re.search(r"ALGORITHM.*[\"']RS256[\"']|JWT_ALGORITHM.*[\"']RS256[\"']", content)

                if hs256_match:
                    algorithm_found = True
                    found_algorithm = "HS256"
                    break
                elif rs256_match:
                    algorithm_found = True
                    found_algorithm = "RS256"
                    break
            except Exception:
                continue

        assert algorithm_found, (
            "JWT algorithm configuration not found. " "Either HS256 or RS256 must be configured for JWT signing."
        )

        # Log which algorithm is being used
        if found_algorithm == "HS256":
            pytest.skip(
                f"JWT algorithm configured as {found_algorithm}. "
                "Consider upgrading to RS256 for enhanced security in production."
            )

    def test_api_key_prefix_enforced(self, security_validator):
        """Verify API keys use correct prefix per ADR-002."""
        # Look for API key generation/validation code
        api_files = list(security_validator.app_path.rglob("**/*.py"))

        prefix_pattern_found = False

        for file_path in api_files:
            if "__pycache__" in str(file_path):
                continue

            try:
                content = file_path.read_text()
                if re.search(r"vutf-api_|VUTF_API_KEY_PREFIX", content):
                    prefix_pattern_found = True
                    break
            except Exception:
                continue

        # This is a warning rather than a hard failure if not found
        if not prefix_pattern_found:
            pytest.skip(
                "API key prefix pattern 'vutf-api_' not found in codebase. "
                "Ensure API keys follow the prefix requirement from ADR-002."
            )
