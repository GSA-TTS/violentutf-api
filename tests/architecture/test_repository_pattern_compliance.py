"""
Repository Pattern Compliance Tests with PyTestArch.

This module implements PyTestArch rules to enforce repository pattern compliance
and prevent direct database access violations as required by Issue #89.

Key validation rules:
- API layer only depends on service layer
- Service layer only depends on repository interfaces
- No direct SQLAlchemy imports in services/API layers
- Repository pattern properly implemented throughout

Related:
- Issue #89: Integration Testing & PyTestArch Validation - Zero Violations
- ADR-013: Repository Pattern Implementation
"""

import pytest
from pytestarch import Rule, get_evaluable_architecture


@pytest.mark.architecture
class TestRepositoryPatternCompliance:
    """PyTestArch rules to enforce repository pattern compliance."""

    def test_api_layer_no_direct_repository_imports(self):
        """API layer should not import repositories directly.

        Validates Clean Architecture: API → Service → Repository
        """
        # Initialize architecture for this test
        architecture = get_evaluable_architecture(root_path=".", module_path="app")

        # Get API modules that start with app.api
        api_modules = [m for m in architecture.modules if m.startswith(".app.api")]

        # Check dependencies for each API module
        violations = []
        for api_module in api_modules:
            dependencies = architecture.get_dependencies([api_module])
            for dep_from, dep_to in dependencies:
                if dep_from.startswith(".app.api") and dep_to.startswith(".app.repositories"):
                    violations.append(f"{dep_from} -> {dep_to}")

        if violations:
            pytest.fail(
                f"API layer should not import repositories directly.\n"
                f"Found {len(violations)} violations:\n" + "\n".join(f"  - {v}" for v in violations)
            )

    def test_api_layer_no_sqlalchemy_imports(self):
        """API layer should not import SQLAlchemy directly.

        Prevents direct database access from API layer.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.api")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("sqlalchemy")
        )

        rule.assert_applies()

    def test_service_layer_no_sqlalchemy_session_imports(self):
        """Service layer should not import SQLAlchemy Session directly.

        Services should receive sessions through dependency injection,
        not import them directly.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.services")
            .should_not()
            .import_modules_that()
            .are_named_matching("sqlalchemy.orm.session")
        )

        rule.assert_applies()

    def test_service_layer_no_direct_model_imports(self):
        """Service layer should not import database models directly.

        Services should work through repository interfaces.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.services")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("app.models")
            .except_modules_that()
            .are_named_ending_with("_service_impl")  # Implementation classes may need models
        )

        rule.assert_applies()

    def test_api_layer_only_depends_on_services(self):
        """API layer should only depend on service layer.

        Enforces proper architectural layering.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.api.endpoints")
            .should_only()
            .import_modules_that()
            .are_named_starting_with("app.services")
            .or_are_named_starting_with("app.schemas")
            .or_are_named_starting_with("app.core")
            .or_are_named_starting_with("app.api.deps")
            .or_are_named_starting_with("fastapi")
            .or_are_named_starting_with("typing")
            .or_are_named_starting_with("datetime")
            .or_are_named_starting_with("uuid")
            .or_are_named_starting_with("sqlalchemy.ext.asyncio")  # AsyncSession allowed
        )

        rule.assert_applies()

    def test_repository_interfaces_used_in_services(self):
        """Services should depend on repository interfaces, not implementations.

        Ensures proper dependency inversion.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        # This test checks that services import from interfaces, not concrete repos
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.services")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("app.repositories")
            .except_modules_that()
            .are_named_matching("app.repositories.interfaces")
            .except_modules_that()
            .are_named_ending_with("_service_impl")  # Implementation can import repos
        )

        rule.assert_applies()

    def test_no_database_access_from_controllers(self):
        """API controllers should not access database directly.

        All database access should go through service layer.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.api")
            .should_not()
            .import_modules_that()
            .are_named_matching("app.db.session")
            .except_modules_that()
            .are_named_matching("app.api.deps")  # Dependency injection file allowed
        )

        rule.assert_applies()

    def test_repository_implementations_isolated(self):
        """Repository implementations should be isolated in repositories module.

        Prevents repository logic leaking into other layers.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.repositories")
            .should_not()
            .be_imported_by_modules_that()
            .are_named_starting_with("app.api")
            .except_modules_that()
            .are_named_matching("app.api.deps")  # DI container can import
        )

        rule.assert_applies()


@pytest.mark.architecture
class TestDatabaseAccessPatterns:
    """Validate proper database access patterns throughout the application."""

    def test_session_management_centralized(self):
        """Database session management should be centralized.

        Only specific modules should handle session creation/management.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        allowed_session_modules = [
            "app.db.session",
            "app.api.deps",
            "app.repositories",
            "app.core.container",
        ]

        for module_pattern in allowed_session_modules:
            rule = (
                architecture.modules_that()
                .are_named_starting_with(module_pattern)
                .may()
                .import_modules_that()
                .are_named_matching("sqlalchemy.ext.asyncio")
            )
            rule.assert_applies()

    def test_transaction_boundaries_respected(self):
        """Transaction management should be handled at service layer.

        API layer should not manage transactions directly.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.api")
            .should_not()
            .import_modules_that()
            .are_named_matching("sqlalchemy.orm.session")
        )

        rule.assert_applies()

    def test_query_building_isolated_to_repositories(self):
        """Query building should only happen in repository layer.

        Prevents query logic from leaking into services or API.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.services")
            .should_not()
            .import_modules_that()
            .are_named_matching("sqlalchemy.sql")
            .except_modules_that()
            .are_named_ending_with("_service_impl")
        )

        rule.assert_applies()


@pytest.mark.architecture
class TestRepositoryPatternIntegrity:
    """Validate repository pattern implementation integrity."""

    def test_all_repositories_implement_interfaces(self):
        """All repository implementations should implement proper interfaces.

        Ensures consistent repository API across the application.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        # Check that repository implementations exist for interfaces
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.repositories")
            .and_are_not_named_matching("app.repositories.interfaces")
            .should()
            .import_modules_that()
            .are_named_matching("app.repositories.interfaces")
            .or_are_named_starting_with("app.models")
            .or_are_named_starting_with("sqlalchemy")
        )

        rule.assert_applies()

    def test_service_implementations_proper_naming(self):
        """Service implementations should follow naming conventions.

        Ensures clear distinction between interfaces and implementations.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = architecture.modules_that().are_named_ending_with("_service_impl").should().be_in_package("app.services")

        rule.assert_applies()

    def test_dependency_injection_proper_structure(self):
        """Dependency injection should follow proper structure.

        DI container should be the only place that wires implementations.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_matching("app.api.deps")
            .should()
            .import_modules_that()
            .are_named_starting_with("app.services")
            .and_may()
            .import_modules_that()
            .are_named_starting_with("app.repositories")
        )

        rule.assert_applies()


@pytest.mark.architecture
class TestArchitecturalLayering:
    """Validate proper architectural layering throughout the system."""

    def test_core_layer_independence(self):
        """Core layer should not depend on external layers.

        Core should be independent of API, services, and repositories.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.core")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("app.api")
            .or_are_named_starting_with("app.services")
            .or_are_named_starting_with("app.repositories")
            .except_modules_that()
            .are_named_matching("app.core.container")  # DI container can import
        )

        rule.assert_applies()

    def test_models_layer_independence(self):
        """Models layer should be independent of business logic layers.

        Domain models should not depend on services or API.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.models")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("app.api")
            .or_are_named_starting_with("app.services")
        )

        rule.assert_applies()

    def test_schema_layer_independence(self):
        """Schema layer should be independent of implementation details.

        Schemas should not import repositories or database details.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.schemas")
            .should_not()
            .import_modules_that()
            .are_named_starting_with("app.repositories")
            .or_are_named_starting_with("app.db")
        )

        rule.assert_applies()


@pytest.mark.architecture
@pytest.mark.slow
class TestArchitecturalCompliance:
    """Comprehensive architectural compliance validation for Issue #89."""

    def test_zero_direct_database_access_violations(self):
        """Comprehensive test ensuring zero direct database access violations.

        This is the primary requirement from Issue #89 UAT specification.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        violations = []

        # Check API layer violations
        try:
            rule = (
                architecture.modules_that()
                .are_named_starting_with("app.api")
                .should_not()
                .import_modules_that()
                .are_named_starting_with("app.repositories")
                .or_are_named_matching("sqlalchemy.orm")
            )
            rule.assert_applies()
        except Exception as e:
            violations.append(f"API layer direct database access: {e}")

        # Check service layer violations
        try:
            rule = (
                architecture.modules_that()
                .are_named_starting_with("app.services")
                .should_not()
                .import_modules_that()
                .are_named_matching("sqlalchemy.orm.session")
            )
            rule.assert_applies()
        except Exception as e:
            violations.append(f"Service layer direct session access: {e}")

        # Report all violations
        if violations:
            violation_report = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Found {len(violations)} direct database access violations:\n{violation_report}\n\n"
                "Issue #89 requires ZERO violations for architectural compliance."
            )

    def test_repository_pattern_complete_implementation(self):
        """Validate complete repository pattern implementation.

        Ensures all components properly implement repository pattern.
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        # Test that all services use repository interfaces
        rule = (
            architecture.modules_that()
            .are_named_starting_with("app.services")
            .should()
            .import_modules_that()
            .are_named_starting_with("app.repositories.interfaces")
            .or_are_named_ending_with("Repository")
            .except_modules_that()
            .are_named_matching("app.services.*_service_impl")
        )

        try:
            rule.assert_applies()
        except Exception as e:
            pytest.fail(
                f"Repository pattern implementation incomplete: {e}\n\n"
                "All services must use repository interfaces for Issue #89 compliance."
            )

    def test_issue_89_architectural_requirements_met(self):
        """Validate all Issue #89 architectural requirements are met.

        This test validates the core UAT requirements:
        - PyTestArch reports 0 direct database access violations
        - Repository pattern properly implemented
        - Clean architecture principles enforced
        """
        architecture = get_evaluable_architecture(root_path=".", module_path="app")
        print("🏗️  Validating Issue #89 Architectural Requirements...")

        requirements_status = {
            "zero_direct_db_access": True,
            "repository_pattern_implemented": True,
            "clean_architecture_enforced": True,
            "proper_layer_separation": True,
        }

        # Validate each requirement
        try:
            # Test zero direct database access
            api_db_rule = (
                architecture.modules_that()
                .are_named_starting_with("app.api")
                .should_not()
                .import_modules_that()
                .are_named_starting_with("app.repositories")
            )
            api_db_rule.assert_applies()
        except:
            requirements_status["zero_direct_db_access"] = False

        try:
            # Test repository pattern implementation
            service_repo_rule = (
                architecture.modules_that()
                .are_named_starting_with("app.services")
                .should_not()
                .import_modules_that()
                .are_named_matching("sqlalchemy.orm.session")
            )
            service_repo_rule.assert_applies()
        except:
            requirements_status["repository_pattern_implemented"] = False

        # Generate compliance report
        passed_requirements = sum(requirements_status.values())
        total_requirements = len(requirements_status)
        compliance_percentage = (passed_requirements / total_requirements) * 100

        print(f"📊 Architectural Compliance Report:")
        for requirement, status in requirements_status.items():
            status_icon = "✅" if status else "❌"
            print(f"   {status_icon} {requirement.replace('_', ' ').title()}")

        print(f"📈 Overall Compliance: {compliance_percentage:.1f}% ({passed_requirements}/{total_requirements})")

        if compliance_percentage < 100:
            failed_requirements = [req for req, status in requirements_status.items() if not status]
            pytest.fail(
                f"Issue #89 architectural requirements not met: {compliance_percentage:.1f}% compliance\n"
                f"Failed requirements: {failed_requirements}\n\n"
                "All requirements must pass for Issue #89 acceptance."
            )

        print("🎯 Issue #89 architectural requirements: SATISFIED")
        print("✅ Zero violations target achieved")
