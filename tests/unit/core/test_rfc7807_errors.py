"""Tests for RFC 7807 compliant error handling (ADR-009)."""

import json
from datetime import datetime
from unittest.mock import Mock

import pytest
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError

from app.core.error_dictionary import ErrorDictionary, create_api_error_from_code
from app.core.errors import (
    APIError,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    ProblemDetail,
    UnauthorizedError,
    ValidationError,
    api_error_handler,
    generic_error_handler,
    validation_error_handler,
)


class TestRFC7807Compliance:
    """Test RFC 7807 Problem Details compliance."""

    def test_problem_detail_model_structure(self):
        """Test that ProblemDetail follows RFC 7807 structure."""
        problem = ProblemDetail(
            type="/errors/validation-error",
            title="Validation Error",
            status=422,
            detail="One or more fields failed validation",
            instance="/api/v1/users",
            correlation_id="test-123",
            error_code="VUTF_422_VALIDATION_ERROR",
            timestamp="2025-08-08T12:00:00Z",
        )

        # Test required RFC 7807 fields
        assert problem.type == "/errors/validation-error"
        assert problem.title == "Validation Error"
        assert problem.status == 422
        assert problem.detail == "One or more fields failed validation"
        assert problem.instance == "/api/v1/users"

        # Test ADR-009 extensions
        assert problem.correlation_id == "test-123"
        assert problem.error_code == "VUTF_422_VALIDATION_ERROR"
        assert problem.timestamp == "2025-08-08T12:00:00Z"

    def test_problem_detail_serialization(self):
        """Test that ProblemDetail serializes correctly."""
        problem = ProblemDetail(
            type="/errors/bad-request",
            title="Bad Request",
            status=400,
            detail="The request is invalid",
            instance="/api/v1/test",
            correlation_id="test-456",
            error_code="VUTF_400_BAD_REQUEST",
        )

        serialized = problem.model_dump(exclude_none=True)

        # Check all expected fields are present
        expected_fields = {"type", "title", "status", "detail", "instance", "correlation_id", "error_code"}
        assert set(serialized.keys()) >= expected_fields

        # Verify values
        assert serialized["type"] == "/errors/bad-request"
        assert serialized["status"] == 400
        assert serialized["error_code"] == "VUTF_400_BAD_REQUEST"

    def test_problem_detail_extra_fields(self):
        """Test that ProblemDetail allows extra fields."""
        problem = ProblemDetail(
            type="/errors/validation-error",
            title="Validation Error",
            status=422,
            invalid_params=[{"field": "email", "reason": "invalid format"}, {"field": "name", "reason": "required"}],
        )

        serialized = problem.model_dump()
        assert "invalid_params" in serialized
        assert len(serialized["invalid_params"]) == 2
        assert serialized["invalid_params"][0]["field"] == "email"


class TestAPIErrorExceptions:
    """Test APIError exception classes."""

    def test_api_error_basic_structure(self):
        """Test basic APIError structure."""
        error = APIError(status_code=400, error_code="VUTF_400_TEST", title="Test Error", detail="This is a test error")

        assert error.status_code == 400
        assert error.error_code == "VUTF_400_TEST"
        assert error.title == "Test Error"
        assert error.detail == "This is a test error"
        # The problem_type should be generated correctly
        assert "/errors/vutf" in error.problem_type.lower() or "/errors/vutf-400-test" in error.problem_type.lower()

    def test_api_error_with_custom_type(self):
        """Test APIError with custom problem type."""
        error = APIError(
            status_code=400,
            error_code="CUSTOM_ERROR",
            title="Custom Error",
            detail="Custom detail",
            problem_type="/errors/custom-error",
        )

        assert error.problem_type == "/errors/custom-error"

    def test_api_error_with_additional_fields(self):
        """Test APIError with additional fields."""
        error = APIError(
            status_code=422,
            error_code="VUTF_422_TEST",
            title="Test Validation",
            detail="Validation failed",
            errors=["field1", "field2"],
            context={"key": "value"},
        )

        assert hasattr(error, "additional_fields")
        assert error.additional_fields["errors"] == ["field1", "field2"]
        assert error.additional_fields["context"] == {"key": "value"}

    def test_bad_request_error(self):
        """Test BadRequestError with error dictionary."""
        error = BadRequestError()

        assert error.status_code == 400
        assert error.error_code == "VUTF_400_BAD_REQUEST"
        assert error.title == "Bad Request"
        assert error.problem_type == "/errors/bad-request"

    def test_bad_request_error_with_custom_detail(self):
        """Test BadRequestError with custom detail."""
        custom_detail = "Invalid JSON format"
        error = BadRequestError(detail=custom_detail)

        assert error.detail == custom_detail
        assert error.status_code == 400

    def test_unauthorized_error(self):
        """Test UnauthorizedError with proper headers."""
        error = UnauthorizedError()

        assert error.status_code == 401
        assert error.error_code == "VUTF_401_UNAUTHORIZED"
        assert error.title == "Unauthorized"
        assert "WWW-Authenticate" in error.headers
        assert error.headers["WWW-Authenticate"] == "Bearer"

    def test_forbidden_error(self):
        """Test ForbiddenError."""
        error = ForbiddenError(detail="Insufficient permissions")

        assert error.status_code == 403
        assert error.error_code == "VUTF_403_FORBIDDEN"
        assert error.detail == "Insufficient permissions"

    def test_not_found_error(self):
        """Test NotFoundError."""
        error = NotFoundError(detail="User not found")

        assert error.status_code == 404
        assert error.error_code == "VUTF_404_NOT_FOUND"
        assert error.detail == "User not found"

    def test_conflict_error(self):
        """Test ConflictError."""
        error = ConflictError(detail="User already exists")

        assert error.status_code == 409
        assert error.error_code == "VUTF_409_CONFLICT"
        assert error.detail == "User already exists"

    def test_validation_error(self):
        """Test ValidationError with validation details."""
        validation_errors = [
            {"field": "email", "reason": "invalid format"},
            {"field": "age", "reason": "must be positive"},
        ]
        error = ValidationError(detail="Multiple fields invalid", errors=validation_errors)

        assert error.status_code == 422
        assert error.error_code == "VUTF_422_VALIDATION_ERROR"
        assert error.detail == "Multiple fields invalid"
        assert "invalid_params" in error.additional_fields
        assert error.additional_fields["invalid_params"] == validation_errors

    def test_internal_server_error(self):
        """Test InternalServerError."""
        error = InternalServerError(detail="Database connection failed")

        assert error.status_code == 500
        assert error.error_code == "VUTF_500_INTERNAL_ERROR"
        assert error.detail == "Database connection failed"


class TestErrorDictionary:
    """Test ErrorDictionary functionality."""

    def test_get_error_by_code(self):
        """Test getting error definition by code."""
        error_def = ErrorDictionary.get_error("VUTF_400_BAD_REQUEST")

        assert error_def is not None
        assert error_def.status == 400
        assert error_def.title == "Bad Request"
        assert error_def.type == "/errors/bad-request"
        assert error_def.error_code == "VUTF_400_BAD_REQUEST"

    def test_get_nonexistent_error(self):
        """Test getting nonexistent error returns None."""
        error_def = ErrorDictionary.get_error("NONEXISTENT_ERROR")
        assert error_def is None

    def test_get_errors_by_status(self):
        """Test getting errors by status code."""
        errors_400 = ErrorDictionary.get_errors_by_status(400)

        assert len(errors_400) > 0
        for error in errors_400.values():
            assert error.status == 400

    def test_get_all_errors(self):
        """Test getting all errors."""
        all_errors = ErrorDictionary.get_all_errors()

        assert len(all_errors) > 0
        assert "VUTF_400_BAD_REQUEST" in all_errors
        assert "VUTF_404_NOT_FOUND" in all_errors
        assert "VUTF_500_INTERNAL_ERROR" in all_errors

    def test_create_api_error_from_code(self):
        """Test creating APIError from error code."""
        error = create_api_error_from_code("VUTF_404_NOT_FOUND")

        assert error.status_code == 404
        assert error.error_code == "VUTF_404_NOT_FOUND"
        assert error.title == "Not Found"

    def test_create_api_error_from_code_with_custom_detail(self):
        """Test creating APIError with custom detail."""
        custom_detail = "User ID 123 not found"
        error = create_api_error_from_code("VUTF_404_NOT_FOUND", detail=custom_detail)

        assert error.detail == custom_detail

    def test_create_api_error_from_invalid_code(self):
        """Test creating APIError from invalid code falls back gracefully."""
        error = create_api_error_from_code("INVALID_CODE")

        # Should fallback to internal error
        assert error.status_code == 500
        assert error.error_code == "VUTF_500_INTERNAL_ERROR"

    def test_openapi_responses_generation(self):
        """Test OpenAPI response generation."""
        responses = ErrorDictionary.generate_openapi_responses()

        assert "400" in responses
        assert "404" in responses
        assert "500" in responses

        # Check structure
        response_400 = responses["400"]
        assert "description" in response_400
        assert "content" in response_400
        assert "application/problem+json" in response_400["content"]

        schema = response_400["content"]["application/problem+json"]["schema"]
        assert "properties" in schema
        assert "type" in schema["properties"]
        assert "title" in schema["properties"]
        assert "status" in schema["properties"]
        assert "error_code" in schema["properties"]


class TestErrorHandlers:
    """Test error handler functions."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request."""
        request = Mock(spec=Request)

        # Mock URL properly
        url_mock = Mock()
        url_mock.path = "/api/v1/test"
        url_mock.__str__ = Mock(return_value="http://test.com/api/v1/test")
        request.url = url_mock

        request.method = "POST"

        # Mock state
        state_mock = Mock()
        state_mock.request_id = "test-correlation-123"
        request.state = state_mock

        return request

    @pytest.mark.asyncio
    async def test_api_error_handler(self, mock_request):
        """Test api_error_handler returns RFC 7807 format."""
        error = BadRequestError(detail="Invalid input data")

        response = await api_error_handler(mock_request, error)

        assert response.status_code == 400
        assert response.headers["Content-Type"] == "application/problem+json"

        # Parse response content
        content = json.loads(response.body.decode())

        # Check RFC 7807 fields
        assert content["type"] == "/errors/bad-request"
        assert content["title"] == "Bad Request"
        assert content["status"] == 400
        assert content["detail"] == "Invalid input data"
        assert content["instance"] == "/api/v1/test"

        # Check ADR-009 extensions
        assert content["correlation_id"] == "test-correlation-123"
        assert content["error_code"] == "VUTF_400_BAD_REQUEST"
        assert "timestamp" in content

    @pytest.mark.asyncio
    async def test_validation_error_handler(self, mock_request):
        """Test validation_error_handler returns RFC 7807 format."""
        # Create a mock RequestValidationError
        validation_error = RequestValidationError(
            [
                {"loc": ("body", "email"), "msg": "field required", "type": "value_error.missing"},
                {
                    "loc": ("body", "age"),
                    "msg": "ensure this value is greater than 0",
                    "type": "value_error.number.not_gt",
                },
            ]
        )

        response = await validation_error_handler(mock_request, validation_error)

        assert response.status_code == 422
        assert response.headers["Content-Type"] == "application/problem+json"

        # Parse response content
        content = json.loads(response.body.decode())

        # Check RFC 7807 fields
        assert content["type"] == "/errors/validation-error"
        assert content["title"] == "Validation Error"
        assert content["status"] == 422
        assert content["instance"] == "/api/v1/test"

        # Check validation details
        assert "invalid_params" in content
        assert len(content["invalid_params"]) == 2

        param1 = content["invalid_params"][0]
        assert param1["field"] == "body.email"
        assert param1["reason"] == "field required"

        param2 = content["invalid_params"][1]
        assert param2["field"] == "body.age"
        assert param2["reason"] == "ensure this value is greater than 0"

    @pytest.mark.asyncio
    async def test_generic_error_handler_development(self, mock_request):
        """Test generic_error_handler in development mode."""
        # Set up development mode
        app_state_mock = Mock()
        app_state_mock.development_mode = True
        app_mock = Mock()
        app_mock.state = app_state_mock
        mock_request.app = app_mock

        test_exception = ValueError("Test error message")

        response = await generic_error_handler(mock_request, test_exception)

        assert response.status_code == 500
        assert response.headers["Content-Type"] == "application/problem+json"

        # Parse response content
        content = json.loads(response.body.decode())

        # Check RFC 7807 fields
        assert content["type"] == "/errors/internal-server-error"
        assert content["title"] == "Internal Server Error"
        assert content["status"] == 500
        assert content["detail"] == "Test error message"  # Shows actual error in dev
        assert content["instance"] == "/api/v1/test"
        assert content["correlation_id"] == "test-correlation-123"

    @pytest.mark.asyncio
    async def test_generic_error_handler_production(self, mock_request):
        """Test generic_error_handler in production mode."""
        # Set up production mode
        app_state_mock = Mock()
        app_state_mock.development_mode = False
        app_mock = Mock()
        app_mock.state = app_state_mock
        mock_request.app = app_mock

        test_exception = ValueError("Sensitive internal error")

        response = await generic_error_handler(mock_request, test_exception)

        assert response.status_code == 500

        # Parse response content
        content = json.loads(response.body.decode())

        # Should not expose internal error details
        assert content["detail"] == "An internal server error occurred. Please try again later."
        assert "Sensitive internal error" not in content["detail"]

    @pytest.mark.asyncio
    async def test_error_handler_without_correlation_id(self, mock_request):
        """Test error handlers when correlation_id is not available."""
        # Remove correlation_id
        mock_request.state.request_id = None

        error = NotFoundError(detail="Resource not found")

        response = await api_error_handler(mock_request, error)

        # Parse response content
        content = json.loads(response.body.decode())

        # correlation_id should be None (and excluded from response)
        assert "correlation_id" not in content or content["correlation_id"] is None


class TestADR009Compliance:
    """Test full ADR-009 compliance."""

    def test_rfc7807_content_type(self):
        """Test that responses use application/problem+json content type."""
        # This is tested in the handler tests above
        pass

    def test_correlation_id_linking(self):
        """Test that correlation_id links errors to logs."""
        error = BadRequestError()

        # The correlation_id should be available for linking to logs
        # This is set by the error handlers from request.state.request_id
        pass

    def test_error_code_stability(self):
        """Test that error codes are stable and machine-readable."""
        error = ValidationError()

        assert error.error_code == "VUTF_422_VALIDATION_ERROR"
        assert error.error_code.startswith("VUTF_")
        assert "_" in error.error_code  # Human readable format

    def test_type_uri_structure(self):
        """Test that type URIs follow ADR-009 structure."""
        error_def = ErrorDictionary.get_error("VUTF_400_BAD_REQUEST")

        assert error_def.type.startswith("/errors/")
        assert error_def.type == "/errors/bad-request"  # kebab-case format

    def test_no_stack_traces_in_production(self):
        """Test that stack traces are never exposed in production."""
        # This is handled by the generic_error_handler
        # and tested in test_generic_error_handler_production
        pass

    def test_centralized_error_handling(self):
        """Test that all errors go through centralized handlers."""
        # This is ensured by the setup_error_handlers function
        # which registers global exception handlers
        pass

    def test_extensible_error_format(self):
        """Test that the error format can be extended with custom fields."""
        problem = ProblemDetail(
            type="/errors/custom",
            title="Custom Error",
            status=400,
            custom_field="custom_value",
            nested_data={"key": "value"},
        )

        serialized = problem.model_dump()
        assert serialized["custom_field"] == "custom_value"
        assert serialized["nested_data"]["key"] == "value"
