"""Comprehensive tests for AuditLog model to achieve 100% coverage."""

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.models.audit_log import AuditLog
from app.models.mixins import AuditMixin, SecurityValidationMixin


class TestAuditLogModelCreation:
    """Test audit log creation and basic functionality."""

    def test_audit_log_creation_minimal(self):
        """Test creating audit log with minimal required fields."""
        audit_log = AuditLog(action="user.create", resource_type="user")

        assert audit_log.action == "user.create"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id is None
        assert audit_log.user_id is None
        assert audit_log.user_email is None
        assert audit_log.ip_address is None
        assert audit_log.user_agent is None
        assert audit_log.changes is None
        assert audit_log.action_metadata is None
        assert audit_log.status == "success"  # Default value
        assert audit_log.error_message is None
        assert audit_log.duration_ms is None

    def test_audit_log_creation_full_fields(self):
        """Test creating audit log with all fields populated."""
        user_id = uuid.uuid4()
        changes = {"before": {"name": "old"}, "after": {"name": "new"}}
        metadata = {"request_id": "req-123", "source": "api"}

        audit_log = AuditLog(
            action="user.update",
            resource_type="user",
            resource_id="user-456",
            user_id=user_id,
            user_email="test@example.com",
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            changes=changes,
            action_metadata=metadata,
            status="success",
            error_message=None,
            duration_ms=150,
        )

        assert audit_log.action == "user.update"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id == "user-456"
        assert audit_log.user_id == user_id
        assert audit_log.user_email == "test@example.com"
        assert audit_log.ip_address == "192.168.1.1"
        assert audit_log.user_agent == "TestAgent/1.0"
        assert audit_log.changes == changes
        assert audit_log.action_metadata == metadata
        assert audit_log.status == "success"
        assert audit_log.error_message is None
        assert audit_log.duration_ms == 150

    def test_audit_log_inherits_from_mixins(self):
        """Test that AuditLog inherits from AuditMixin and SecurityValidationMixin."""
        audit_log = AuditLog(action="test.action", resource_type="test")

        assert isinstance(audit_log, AuditMixin)
        assert isinstance(audit_log, SecurityValidationMixin)
        # Check inherited fields from AuditMixin
        assert hasattr(audit_log, "id")
        assert hasattr(audit_log, "created_at")
        assert hasattr(audit_log, "created_by")
        assert hasattr(audit_log, "updated_at")
        assert hasattr(audit_log, "updated_by")

    def test_audit_log_table_name(self):
        """Test that table name is correctly set."""
        assert AuditLog.__tablename__ == "audit_log"


class TestAuditLogValidations:
    """Test all validation methods in AuditLog model."""

    def test_validate_action_success(self):
        """Test successful action validation."""
        audit_log = AuditLog()

        valid_actions = [
            "user.create",
            "api_key.delete",
            "session.update",
            "system.startup",
            "auth.login",
            "resource.action",
        ]

        for action in valid_actions:
            result = audit_log.validate_action("action", action)
            assert result == action.lower()

    def test_validate_action_empty(self):
        """Test action validation with empty value."""
        audit_log = AuditLog()

        with pytest.raises(ValueError, match="Action is required"):
            audit_log.validate_action("action", "")

    def test_validate_action_too_long(self):
        """Test action validation with too long value."""
        audit_log = AuditLog()

        long_action = "a" * 101
        with pytest.raises(ValueError, match="Action cannot exceed 100 characters"):
            audit_log.validate_action("action", long_action)

    def test_validate_action_missing_dot(self):
        """Test action validation without dot notation."""
        audit_log = AuditLog()

        invalid_actions = [
            "create",
            "userupdate",
            "action_without_dot",
            "noresourcetype",
        ]

        for action in invalid_actions:
            with pytest.raises(ValueError, match="Action must follow 'resource.action' format"):
                audit_log.validate_action("action", action)

    def test_validate_action_invalid_characters(self):
        """Test action validation with invalid XSS characters."""
        audit_log = AuditLog()

        invalid_actions = [
            "user.create<script>",
            "user.update>alert",
            'user.delete"test',
            "user.create'malicious",
            "user.update&xss",
        ]

        for action in invalid_actions:
            with pytest.raises(ValueError, match="Action contains invalid character"):
                audit_log.validate_action("action", action)

    def test_validate_action_lowercases_result(self):
        """Test that action validation converts to lowercase."""
        audit_log = AuditLog()

        uppercase_action = "USER.CREATE"
        result = audit_log.validate_action("action", uppercase_action)
        assert result == "user.create"

    def test_validate_resource_type_success(self):
        """Test successful resource type validation."""
        audit_log = AuditLog()

        valid_types = ["user", "api_key", "session", "system", "resource_type"]

        for resource_type in valid_types:
            with patch.object(audit_log, "validate_string_security", return_value=None):
                result = audit_log.validate_resource_type("resource_type", resource_type)
                assert result == resource_type.lower()

    def test_validate_resource_type_empty(self):
        """Test resource type validation with empty value."""
        audit_log = AuditLog()

        with pytest.raises(ValueError, match="Resource type is required"):
            audit_log.validate_resource_type("resource_type", "")

    def test_validate_resource_type_too_long(self):
        """Test resource type validation with too long value."""
        audit_log = AuditLog()

        long_type = "a" * 101
        with pytest.raises(ValueError, match="Resource type cannot exceed 100 characters"):
            audit_log.validate_resource_type("resource_type", long_type)

    def test_validate_resource_type_calls_security_validation(self):
        """Test that resource type validation calls string security validation."""
        audit_log = AuditLog()

        with patch.object(audit_log, "validate_string_security") as mock_security:
            audit_log.validate_resource_type("resource_type", "user")
            mock_security.assert_called_once_with("resource_type", "user")

    def test_validate_resource_type_lowercases_result(self):
        """Test that resource type validation converts to lowercase."""
        audit_log = AuditLog()

        with patch.object(audit_log, "validate_string_security", return_value=None):
            result = audit_log.validate_resource_type("resource_type", "USER")
            assert result == "user"

    def test_validate_status_success(self):
        """Test successful status validation."""
        audit_log = AuditLog()

        valid_statuses = ["success", "failure", "error"]

        for status in valid_statuses:
            result = audit_log.validate_status("status", status)
            assert result == status

    def test_validate_status_invalid(self):
        """Test status validation with invalid values."""
        audit_log = AuditLog()

        invalid_statuses = ["completed", "pending", "unknown", "cancelled", "invalid"]

        for status in invalid_statuses:
            with pytest.raises(ValueError, match="Status must be one of: success, failure, error"):
                audit_log.validate_status("status", status)

    def test_validate_ip_address_field_success(self):
        """Test successful IP address validation."""
        audit_log = AuditLog()

        valid_ips = ["192.168.1.1", "10.0.0.1", "::1", "2001:db8::1"]

        for ip in valid_ips:
            with patch.object(audit_log, "validate_ip_address", return_value=ip):
                result = audit_log.validate_ip_address_field("ip_address", ip)
                assert result == ip

    def test_validate_ip_address_field_none(self):
        """Test IP address validation with None value."""
        audit_log = AuditLog()

        result = audit_log.validate_ip_address_field("ip_address", None)
        assert result is None

    def test_validate_ip_address_field_calls_mixin_validation(self):
        """Test that IP validation calls mixin validate_ip_address."""
        audit_log = AuditLog()

        with patch.object(audit_log, "validate_ip_address", return_value="192.168.1.1") as mock_ip:
            audit_log.validate_ip_address_field("ip_address", "192.168.1.1")
            mock_ip.assert_called_once_with("ip_address", "192.168.1.1")

    def test_validate_user_email_success(self):
        """Test successful user email validation."""
        audit_log = AuditLog()

        valid_emails = ["test@example.com", "user@domain.org", "admin@company.co.uk"]

        for email in valid_emails:
            with patch.object(audit_log, "validate_email_format", return_value=email):
                result = audit_log.validate_user_email("user_email", email)
                assert result == email

    def test_validate_user_email_none(self):
        """Test user email validation with None value."""
        audit_log = AuditLog()

        result = audit_log.validate_user_email("user_email", None)
        assert result is None

    def test_validate_user_email_calls_mixin_validation(self):
        """Test that email validation calls mixin validate_email_format."""
        audit_log = AuditLog()

        with patch.object(audit_log, "validate_email_format", return_value="test@example.com") as mock_email:
            audit_log.validate_user_email("user_email", "test@example.com")
            mock_email.assert_called_once_with("user_email", "test@example.com")


class TestAuditLogClassMethods:
    """Test class methods for creating audit logs."""

    def test_create_log_minimal(self):
        """Test create_log with minimal parameters."""
        audit_log = AuditLog.create_log(action="user.create", resource_type="user")

        assert audit_log.action == "user.create"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id is None
        assert audit_log.user_id is None
        assert audit_log.user_email is None
        assert audit_log.ip_address is None
        assert audit_log.user_agent is None
        assert audit_log.changes is None
        assert audit_log.action_metadata is None
        assert audit_log.status == "success"
        assert audit_log.error_message is None
        assert audit_log.duration_ms is None
        assert audit_log.created_by == "system"
        assert audit_log.updated_by == "system"

    def test_create_log_full_parameters(self):
        """Test create_log with all parameters."""
        user_id = uuid.uuid4()
        changes = {"before": {"active": True}, "after": {"active": False}}
        metadata = {"reason": "admin action", "request_id": "req-789"}

        audit_log = AuditLog.create_log(
            action="user.disable",
            resource_type="user",
            resource_id="user-123",
            user_id=user_id,
            user_email="admin@example.com",
            ip_address="10.0.0.1",
            user_agent="AdminTool/2.0",
            changes=changes,
            action_metadata=metadata,
            status="success",
            error_message=None,
            duration_ms=75,
            created_by="admin-456",
        )

        assert audit_log.action == "user.disable"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id == "user-123"
        assert audit_log.user_id == user_id
        assert audit_log.user_email == "admin@example.com"
        assert audit_log.ip_address == "10.0.0.1"
        assert audit_log.user_agent == "AdminTool/2.0"
        assert audit_log.changes == changes
        assert audit_log.action_metadata == metadata
        assert audit_log.status == "success"
        assert audit_log.error_message is None
        assert audit_log.duration_ms == 75
        assert audit_log.created_by == "admin-456"
        assert audit_log.updated_by == "admin-456"

    def test_create_log_string_user_id(self):
        """Test create_log with user_id as string."""
        user_id_str = "123e4567-e89b-12d3-a456-426614174000"

        audit_log = AuditLog.create_log(action="api_key.create", resource_type="api_key", user_id=user_id_str)

        expected_uuid = uuid.UUID(user_id_str)
        assert audit_log.user_id == expected_uuid

    def test_create_log_uuid_user_id(self):
        """Test create_log with user_id as UUID."""
        user_id = uuid.uuid4()

        audit_log = AuditLog.create_log(action="api_key.create", resource_type="api_key", user_id=user_id)

        assert audit_log.user_id == user_id

    def test_create_log_none_user_id(self):
        """Test create_log with None user_id."""
        audit_log = AuditLog.create_log(action="system.startup", resource_type="system", user_id=None)

        assert audit_log.user_id is None

    def test_create_log_empty_string_user_id(self):
        """Test create_log with empty string user_id."""
        audit_log = AuditLog.create_log(action="system.startup", resource_type="system", user_id="")

        assert audit_log.user_id is None

    def test_log_action_minimal(self):
        """Test log_action with minimal parameters."""
        audit_log = AuditLog.log_action(action="session.create", resource_type="session")

        assert audit_log.action == "session.create"
        assert audit_log.resource_type == "session"
        assert audit_log.status == "success"
        assert audit_log.action_metadata is None

    def test_log_action_with_request_id(self):
        """Test log_action with request_id parameter."""
        audit_log = AuditLog.log_action(action="user.login", resource_type="user", request_id="req-abc123")

        assert audit_log.action == "user.login"
        assert audit_log.resource_type == "user"
        assert audit_log.action_metadata == {"request_id": "req-abc123"}

    def test_log_action_with_metadata(self):
        """Test log_action with metadata parameter."""
        metadata = {"source": "mobile_app", "version": "1.2.3"}

        audit_log = AuditLog.log_action(action="user.logout", resource_type="user", metadata=metadata)

        assert audit_log.action_metadata == metadata

    def test_log_action_with_request_id_and_metadata(self):
        """Test log_action combining request_id and metadata."""
        metadata = {"browser": "Chrome", "device": "mobile"}

        audit_log = AuditLog.log_action(
            action="user.profile_update",
            resource_type="user",
            request_id="req-def456",
            metadata=metadata,
        )

        expected_metadata = {
            "browser": "Chrome",
            "device": "mobile",
            "request_id": "req-def456",
        }
        assert audit_log.action_metadata == expected_metadata

    def test_log_action_full_parameters(self):
        """Test log_action with all parameters."""
        metadata = {"api_version": "v1", "client": "web"}

        audit_log = AuditLog.log_action(
            action="api_key.revoke",
            resource_type="api_key",
            resource_id="key-789",
            user_id="456e4567-e89b-12d3-a456-426614174000",
            user_email="user@example.com",
            ip_address="172.16.0.1",
            user_agent="WebApp/1.0",
            request_id="req-ghi789",
            metadata=metadata,
            duration_ms=250,
            status="success",
            error_message=None,
        )

        assert audit_log.action == "api_key.revoke"
        assert audit_log.resource_type == "api_key"
        assert audit_log.resource_id == "key-789"
        assert audit_log.user_email == "user@example.com"
        assert audit_log.ip_address == "172.16.0.1"
        assert audit_log.user_agent == "WebApp/1.0"
        assert audit_log.duration_ms == 250
        assert audit_log.status == "success"
        assert audit_log.error_message is None

        # Check combined metadata
        expected_metadata = {
            "api_version": "v1",
            "client": "web",
            "request_id": "req-ghi789",
        }
        assert audit_log.action_metadata == expected_metadata

    def test_log_action_with_failure_status(self):
        """Test log_action with failure status and error message."""
        audit_log = AuditLog.log_action(
            action="user.create",
            resource_type="user",
            status="failure",
            error_message="Email already exists",
            duration_ms=50,
        )

        assert audit_log.status == "failure"
        assert audit_log.error_message == "Email already exists"
        assert audit_log.duration_ms == 50


class TestAuditLogRepresentation:
    """Test string representation methods."""

    def test_repr_with_resource_id(self):
        """Test __repr__ method with resource_id."""
        audit_log = AuditLog(
            action="user.update",
            resource_type="user",
            resource_id="user-123",
            status="success",
        )

        repr_str = repr(audit_log)
        expected = "<AuditLog(action=user.update, resource=user:user-123, status=success)>"
        assert repr_str == expected

    def test_repr_without_resource_id(self):
        """Test __repr__ method without resource_id."""
        audit_log = AuditLog(
            action="system.startup",
            resource_type="system",
            resource_id=None,
            status="success",
        )

        repr_str = repr(audit_log)
        expected = "<AuditLog(action=system.startup, resource=system:None, status=success)>"
        assert repr_str == expected

    def test_repr_with_failure_status(self):
        """Test __repr__ method with failure status."""
        audit_log = AuditLog(
            action="user.create",
            resource_type="user",
            resource_id="user-456",
            status="failure",
        )

        repr_str = repr(audit_log)
        expected = "<AuditLog(action=user.create, resource=user:user-456, status=failure)>"
        assert repr_str == expected

    def test_to_dict_minimal(self):
        """Test to_dict method with minimal data."""
        audit_log = AuditLog(action="test.action", resource_type="test", status="success")

        with patch.object(audit_log, "id", "123e4567-e89b-12d3-a456-426614174000"):
            with patch.object(audit_log, "created_at", None):
                with patch.object(audit_log, "created_by", "system"):
                    result = audit_log.to_dict()

        expected = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "action": "test.action",
            "resource_type": "test",
            "resource_id": None,
            "user_id": None,
            "user_email": None,
            "ip_address": None,
            "user_agent": None,
            "changes": None,
            "action_metadata": None,
            "status": "success",
            "error_message": None,
            "duration_ms": None,
            "created_at": None,
            "created_by": "system",
        }

        assert result == expected

    def test_to_dict_full_data(self):
        """Test to_dict method with full data."""
        user_id = uuid.uuid4()
        created_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        changes = {"before": {"name": "old"}, "after": {"name": "new"}}
        metadata = {"request_id": "req-123"}

        audit_log = AuditLog(
            action="user.update",
            resource_type="user",
            resource_id="user-789",
            user_id=user_id,
            user_email="user@example.com",
            ip_address="192.168.1.100",
            user_agent="TestBrowser/1.0",
            changes=changes,
            action_metadata=metadata,
            status="success",
            error_message=None,
            duration_ms=125,
        )

        with patch.object(audit_log, "id", "456e7890-e12b-34c5-d678-901234567890"):
            with patch.object(audit_log, "created_at", created_time):
                with patch.object(audit_log, "created_by", "admin"):
                    result = audit_log.to_dict()

        expected = {
            "id": "456e7890-e12b-34c5-d678-901234567890",
            "action": "user.update",
            "resource_type": "user",
            "resource_id": "user-789",
            "user_id": str(user_id),
            "user_email": "user@example.com",
            "ip_address": "192.168.1.100",
            "user_agent": "TestBrowser/1.0",
            "changes": changes,
            "action_metadata": metadata,
            "status": "success",
            "error_message": None,
            "duration_ms": 125,
            "created_at": "2024-01-01T12:00:00+00:00",
            "created_by": "admin",
        }

        assert result == expected

    def test_to_dict_with_error(self):
        """Test to_dict method with error information."""
        audit_log = AuditLog(
            action="user.delete",
            resource_type="user",
            resource_id="user-999",
            status="error",
            error_message="Database connection failed",
            duration_ms=5000,
        )

        with patch.object(audit_log, "id", "error-123"):
            with patch.object(audit_log, "created_at", None):
                with patch.object(audit_log, "created_by", "system"):
                    result = audit_log.to_dict()

        assert result["status"] == "error"
        assert result["error_message"] == "Database connection failed"
        assert result["duration_ms"] == 5000


class TestAuditLogConstraintsAndConfig:
    """Test model constraints and configuration."""

    def test_model_constraints(self):
        """Test that model constraints are properly defined."""
        constraints = AuditLog._model_constraints

        assert len(constraints) == 4

        # Check index names
        index_names = [constraint.name for constraint in constraints]
        expected_names = [
            "idx_auditlog_timestamp",
            "idx_auditlog_user_action",
            "idx_auditlog_resource",
            "idx_auditlog_status",
        ]

        for expected_name in expected_names:
            assert expected_name in index_names

    def test_model_config(self):
        """Test that model configuration is properly defined."""
        config = AuditLog._model_config

        assert config["comment"] == "Immutable audit trail of all system actions"


class TestAuditLogFieldProperties:
    """Test individual field properties and constraints."""

    def test_action_field_properties(self):
        """Test action field properties."""
        action_column = AuditLog.action.property.columns[0]

        assert action_column.type.length == 100
        assert action_column.nullable is False
        assert action_column.index is True
        assert action_column.comment == "Action performed (e.g., 'user.create', 'api_key.delete')"

    def test_resource_type_field_properties(self):
        """Test resource_type field properties."""
        resource_type_column = AuditLog.resource_type.property.columns[0]

        assert resource_type_column.type.length == 100
        assert resource_type_column.nullable is False
        assert resource_type_column.index is True
        assert resource_type_column.comment == "Type of resource affected (e.g., 'user', 'api_key')"

    def test_resource_id_field_properties(self):
        """Test resource_id field properties."""
        resource_id_column = AuditLog.resource_id.property.columns[0]

        assert resource_id_column.type.length == 255
        assert resource_id_column.nullable is True
        assert resource_id_column.index is True
        assert resource_id_column.comment == "ID of the affected resource"

    def test_user_fields_properties(self):
        """Test user-related field properties."""
        user_id_column = AuditLog.user_id.property.columns[0]
        user_email_column = AuditLog.user_email.property.columns[0]

        # user_id
        assert user_id_column.nullable is True
        assert user_id_column.index is True
        assert user_id_column.comment == "User who performed the action (null for system actions)"

        # user_email
        assert user_email_column.type.length == 254
        assert user_email_column.nullable is True
        assert user_email_column.comment == "Email of user at time of action (denormalized for history)"

    def test_request_fields_properties(self):
        """Test request-related field properties."""
        ip_column = AuditLog.ip_address.property.columns[0]
        ua_column = AuditLog.user_agent.property.columns[0]

        # ip_address
        assert ip_column.type.length == 45
        assert ip_column.nullable is True
        assert ip_column.index is True
        assert ip_column.comment == "IP address of the request"

        # user_agent
        assert ua_column.type.length == 500
        assert ua_column.nullable is True
        assert ua_column.comment == "User agent string from the request"

    def test_json_fields_properties(self):
        """Test JSON field properties."""
        changes_column = AuditLog.changes.property.columns[0]
        metadata_column = AuditLog.action_metadata.property.columns[0]

        # changes
        assert changes_column.nullable is True
        assert changes_column.default is None
        assert changes_column.comment == "JSON with before/after values for updates"

        # action_metadata
        assert metadata_column.nullable is True
        assert metadata_column.default is None
        assert metadata_column.comment == "Additional context or metadata about the action"

    def test_status_field_properties(self):
        """Test status field properties."""
        status_column = AuditLog.status.property.columns[0]

        assert status_column.type.length == 20
        assert status_column.nullable is False
        assert status_column.default.arg == "success"
        assert str(status_column.server_default.arg) == "success"
        assert status_column.comment == "Result status: success, failure, error"

    def test_error_message_field_properties(self):
        """Test error_message field properties."""
        error_column = AuditLog.error_message.property.columns[0]

        assert error_column.type.length == 1000
        assert error_column.nullable is True
        assert error_column.comment == "Error message if action failed"

    def test_duration_field_properties(self):
        """Test duration_ms field properties."""
        duration_column = AuditLog.duration_ms.property.columns[0]

        assert duration_column.nullable is True
        assert duration_column.comment == "Duration of the action in milliseconds"


class TestAuditLogValidationEdgeCases:
    """Test edge cases in validation methods."""

    def test_validation_with_security_failure(self):
        """Test validation when security validation fails."""
        audit_log = AuditLog()

        with patch.object(
            audit_log,
            "validate_string_security",
            side_effect=ValueError("Security validation failed"),
        ):
            with pytest.raises(ValueError, match="Security validation failed"):
                audit_log.validate_resource_type("resource_type", "user")

    def test_action_validation_sql_keywords_allowed(self):
        """Test that action validation allows SQL keywords in structured format."""
        audit_log = AuditLog()

        # These should be valid since they follow resource.action format
        sql_keyword_actions = [
            "user.create",
            "table.update",
            "index.delete",
            "view.select",
        ]

        for action in sql_keyword_actions:
            result = audit_log.validate_action("action", action)
            assert result == action.lower()

    def test_create_log_invalid_uuid_string(self):
        """Test create_log with invalid UUID string."""
        with pytest.raises(ValueError):
            AuditLog.create_log(action="test.action", resource_type="test", user_id="not-a-valid-uuid")


class TestAuditLogIntegrationScenarios:
    """Test integration scenarios and complex use cases."""

    def test_audit_log_complete_lifecycle(self):
        """Test complete audit log creation and serialization."""
        user_id = uuid.uuid4()

        # Create audit log using class method
        audit_log = AuditLog.log_action(
            action="api_key.create",
            resource_type="api_key",
            resource_id="key-new123",
            user_id=str(user_id),
            user_email="developer@example.com",
            ip_address="203.0.113.1",
            user_agent="APIClient/3.0",
            request_id="req-lifecycle-test",
            metadata={"key_name": "Production Key", "permissions": ["read", "write"]},
            duration_ms=89,
            status="success",
        )

        # Verify creation
        assert audit_log.action == "api_key.create"
        assert audit_log.resource_type == "api_key"
        assert audit_log.resource_id == "key-new123"
        assert audit_log.user_id == user_id
        assert audit_log.status == "success"

        # Verify metadata combination
        expected_metadata = {
            "key_name": "Production Key",
            "permissions": ["read", "write"],
            "request_id": "req-lifecycle-test",
        }
        assert audit_log.action_metadata == expected_metadata

        # Test serialization
        with patch.object(audit_log, "id", "lifecycle-test-id"):
            result_dict = audit_log.to_dict()
            assert result_dict["action"] == "api_key.create"
            assert result_dict["user_id"] == str(user_id)
            assert result_dict["action_metadata"] == expected_metadata

    def test_system_action_without_user(self):
        """Test audit log for system actions without user context."""
        audit_log = AuditLog.create_log(
            action="system.maintenance",
            resource_type="system",
            user_id=None,
            user_email=None,
            ip_address=None,
            action_metadata={"maintenance_type": "database_cleanup"},
            duration_ms=45000,
            created_by="system",
        )

        assert audit_log.user_id is None
        assert audit_log.user_email is None
        assert audit_log.ip_address is None
        assert audit_log.action_metadata["maintenance_type"] == "database_cleanup"
        assert audit_log.created_by == "system"

    def test_failed_action_with_error_details(self):
        """Test audit log for failed actions with detailed error information."""
        audit_log = AuditLog.log_action(
            action="user.password_reset",
            resource_type="user",
            resource_id="user-failed",
            user_email="nonexistent@example.com",
            status="failure",
            error_message="User not found in database",
            duration_ms=15,
            metadata={"reset_token": "expired", "attempt_count": 3},
        )

        assert audit_log.status == "failure"
        assert audit_log.error_message == "User not found in database"
        assert audit_log.action_metadata["reset_token"] == "expired"
        assert audit_log.action_metadata["attempt_count"] == 3
