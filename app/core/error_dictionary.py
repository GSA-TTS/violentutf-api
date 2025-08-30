"""Error Dictionary for standardized RFC 7807 error mapping."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from .errors import APIError


@dataclass
class ErrorDefinition:
    """Definition of a standardized error."""

    status: int
    title: str
    type: str
    error_code: str
    description: str
    remediation: Optional[str] = None


class ErrorDictionary:
    """Central registry for all application errors following ADR-009."""

    # Error definitions mapping error_code -> ErrorDefinition
    _errors: Dict[str, ErrorDefinition] = {
        # 400 Bad Request Errors
        "VUTF_400_BAD_REQUEST": ErrorDefinition(
            status=400,
            title="Bad Request",
            type="/errors/bad-request",
            error_code="VUTF_400_BAD_REQUEST",
            description="The request is malformed or invalid.",
            remediation="Check the request format and ensure all required fields are present and valid.",
        ),
        "VUTF_400_INVALID_FORMAT": ErrorDefinition(
            status=400,
            title="Invalid Format",
            type="/errors/invalid-format",
            error_code="VUTF_400_INVALID_FORMAT",
            description="The request format is invalid or unsupported.",
            remediation="Ensure the request Content-Type and payload format are correct.",
        ),
        # 401 Unauthorized Errors
        "VUTF_401_UNAUTHORIZED": ErrorDefinition(
            status=401,
            title="Unauthorized",
            type="/errors/unauthorized",
            error_code="VUTF_401_UNAUTHORIZED",
            description="Authentication is required to access this resource.",
            remediation="Include a valid Bearer token in the Authorization header.",
        ),
        "VUTF_401_TOKEN_EXPIRED": ErrorDefinition(
            status=401,
            title="Token Expired",
            type="/errors/token-expired",
            error_code="VUTF_401_TOKEN_EXPIRED",
            description="The authentication token has expired.",
            remediation="Refresh your token or authenticate again.",
        ),
        "VUTF_401_INVALID_TOKEN": ErrorDefinition(
            status=401,
            title="Invalid Token",
            type="/errors/invalid-token",
            error_code="VUTF_401_INVALID_TOKEN",
            description="The authentication token is invalid or malformed.",
            remediation="Ensure the token is correctly formatted and has not been tampered with.",
        ),
        # 403 Forbidden Errors
        "VUTF_403_FORBIDDEN": ErrorDefinition(
            status=403,
            title="Forbidden",
            type="/errors/forbidden",
            error_code="VUTF_403_FORBIDDEN",
            description="Access to this resource is denied.",
            remediation="Contact an administrator to request the necessary permissions.",
        ),
        "VUTF_403_INSUFFICIENT_PERMISSIONS": ErrorDefinition(
            status=403,
            title="Insufficient Permissions",
            type="/errors/insufficient-permissions",
            error_code="VUTF_403_INSUFFICIENT_PERMISSIONS",
            description="Your account does not have sufficient permissions for this operation.",
            remediation="Request the necessary permissions or use an account with appropriate access rights.",
        ),
        "VUTF_403_ORGANIZATION_ACCESS_DENIED": ErrorDefinition(
            status=403,
            title="Organization Access Denied",
            type="/errors/organization-access-denied",
            error_code="VUTF_403_ORGANIZATION_ACCESS_DENIED",
            description="Access denied due to organization-level restrictions.",
            remediation="Ensure you are accessing resources within your organization's scope.",
        ),
        # 404 Not Found Errors
        "VUTF_404_NOT_FOUND": ErrorDefinition(
            status=404,
            title="Not Found",
            type="/errors/not-found",
            error_code="VUTF_404_NOT_FOUND",
            description="The requested resource was not found.",
            remediation="Verify the resource ID and ensure it exists and is accessible to you.",
        ),
        "VUTF_404_ENDPOINT_NOT_FOUND": ErrorDefinition(
            status=404,
            title="Endpoint Not Found",
            type="/errors/endpoint-not-found",
            error_code="VUTF_404_ENDPOINT_NOT_FOUND",
            description="The requested API endpoint does not exist.",
            remediation="Check the API documentation for the correct endpoint URL.",
        ),
        # 409 Conflict Errors
        "VUTF_409_CONFLICT": ErrorDefinition(
            status=409,
            title="Conflict",
            type="/errors/conflict",
            error_code="VUTF_409_CONFLICT",
            description="The request conflicts with the current state of the resource.",
            remediation="Resolve the conflict and try the request again.",
        ),
        "VUTF_409_DUPLICATE_RESOURCE": ErrorDefinition(
            status=409,
            title="Duplicate Resource",
            type="/errors/duplicate-resource",
            error_code="VUTF_409_DUPLICATE_RESOURCE",
            description="A resource with the same identifier already exists.",
            remediation="Use a unique identifier or update the existing resource instead.",
        ),
        # 422 Validation Errors
        "VUTF_422_VALIDATION_ERROR": ErrorDefinition(
            status=422,
            title="Validation Error",
            type="/errors/validation-error",
            error_code="VUTF_422_VALIDATION_ERROR",
            description="One or more fields failed validation.",
            remediation="Correct the validation errors and resubmit the request.",
        ),
        "VUTF_422_SCHEMA_VIOLATION": ErrorDefinition(
            status=422,
            title="Schema Violation",
            type="/errors/schema-violation",
            error_code="VUTF_422_SCHEMA_VIOLATION",
            description="The request payload does not conform to the expected schema.",
            remediation="Ensure the request payload matches the API schema requirements.",
        ),
        # 429 Rate Limit Errors
        "VUTF_429_RATE_LIMIT_EXCEEDED": ErrorDefinition(
            status=429,
            title="Rate Limit Exceeded",
            type="/errors/rate-limit-exceeded",
            error_code="VUTF_429_RATE_LIMIT_EXCEEDED",
            description="Too many requests have been sent in a short period.",
            remediation="Reduce request frequency and respect rate limits. Use exponential backoff for retries.",
        ),
        # 500 Internal Server Errors
        "VUTF_500_INTERNAL_ERROR": ErrorDefinition(
            status=500,
            title="Internal Server Error",
            type="/errors/internal-server-error",
            error_code="VUTF_500_INTERNAL_ERROR",
            description="An unexpected server error occurred.",
            remediation="Try again later. If the problem persists, contact support with the correlation_id.",
        ),
        "VUTF_500_DATABASE_ERROR": ErrorDefinition(
            status=500,
            title="Database Error",
            type="/errors/database-error",
            error_code="VUTF_500_DATABASE_ERROR",
            description="A database operation failed.",
            remediation="Try again later. If the problem persists, contact support.",
        ),
        "VUTF_500_EXTERNAL_SERVICE_ERROR": ErrorDefinition(
            status=500,
            title="External Service Error",
            type="/errors/external-service-error",
            error_code="VUTF_500_EXTERNAL_SERVICE_ERROR",
            description="An external service dependency failed.",
            remediation="Try again later as the external service may be temporarily unavailable.",
        ),
        # 503 Service Unavailable
        "VUTF_503_SERVICE_UNAVAILABLE": ErrorDefinition(
            status=503,
            title="Service Unavailable",
            type="/errors/service-unavailable",
            error_code="VUTF_503_SERVICE_UNAVAILABLE",
            description="The service is temporarily unavailable.",
            remediation="Try again later. The service may be undergoing maintenance.",
        ),
        # Task-specific errors (ADR-007)
        "VUTF_400_INVALID_TASK_TYPE": ErrorDefinition(
            status=400,
            title="Invalid Task Type",
            type="/errors/invalid-task-type",
            error_code="VUTF_400_INVALID_TASK_TYPE",
            description="The specified task type is not supported.",
            remediation="Check the API documentation for supported task types.",
        ),
        "VUTF_404_TASK_NOT_FOUND": ErrorDefinition(
            status=404,
            title="Task Not Found",
            type="/errors/task-not-found",
            error_code="VUTF_404_TASK_NOT_FOUND",
            description="The specified task could not be found.",
            remediation="Verify the task ID is correct and the task exists.",
        ),
        "VUTF_409_TASK_ALREADY_RUNNING": ErrorDefinition(
            status=409,
            title="Task Already Running",
            type="/errors/task-already-running",
            error_code="VUTF_409_TASK_ALREADY_RUNNING",
            description="The task is already in a running state.",
            remediation="Wait for the current task to complete or cancel it before starting a new one.",
        ),
        # Security-specific errors
        "VUTF_403_SECURITY_VIOLATION": ErrorDefinition(
            status=403,
            title="Security Violation",
            type="/errors/security-violation",
            error_code="VUTF_403_SECURITY_VIOLATION",
            description="The request violates security policies.",
            remediation="Ensure your request complies with security requirements and try again.",
        ),
        "VUTF_400_MALICIOUS_INPUT": ErrorDefinition(
            status=400,
            title="Malicious Input Detected",
            type="/errors/malicious-input",
            error_code="VUTF_400_MALICIOUS_INPUT",
            description="The input contains potentially malicious content.",
            remediation="Remove any scripts, SQL injection attempts, or other malicious content from the input.",
        ),
    }

    @classmethod
    def get_error(cls, error_code: str) -> Optional[ErrorDefinition]:
        """Get error definition by error code."""
        return cls._errors.get(error_code)

    @classmethod
    def get_all_errors(cls) -> Dict[str, ErrorDefinition]:
        """Get all error definitions."""
        return cls._errors.copy()

    @classmethod
    def register_error(cls, definition: ErrorDefinition) -> None:
        """Register a new error definition."""
        cls._errors[definition.error_code] = definition

    @classmethod
    def get_errors_by_status(cls, status: int) -> Dict[str, ErrorDefinition]:
        """Get all errors for a specific HTTP status code."""
        return {code: error for code, error in cls._errors.items() if error.status == status}

    @classmethod
    def generate_openapi_responses(cls) -> Dict[str, Any]:
        """Generate OpenAPI response schemas for all errors."""
        responses = {}

        # Group by status code
        status_groups: dict[int, list[ErrorDefinition]] = {}
        for error in cls._errors.values():
            if error.status not in status_groups:
                status_groups[error.status] = []
            status_groups[error.status].append(error)

        # Generate response for each status
        for status_code, errors in status_groups.items():
            example_error = errors[0]  # Use first error as example

            responses[str(status_code)] = {
                "description": example_error.title,
                "content": {
                    "application/problem+json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "example": example_error.type,
                                },
                                "title": {
                                    "type": "string",
                                    "example": example_error.title,
                                },
                                "status": {
                                    "type": "integer",
                                    "example": example_error.status,
                                },
                                "detail": {
                                    "type": "string",
                                    "example": example_error.description,
                                },
                                "instance": {
                                    "type": "string",
                                    "example": "/api/v1/example",
                                },
                                "correlation_id": {
                                    "type": "string",
                                    "example": "123e4567-e89b-12d3-a456-426614174000",
                                },
                                "error_code": {
                                    "type": "string",
                                    "example": example_error.error_code,
                                },
                                "timestamp": {"type": "string", "format": "date-time"},
                            },
                            "required": ["type", "title", "status", "error_code"],
                        },
                        "examples": {
                            error.error_code: {
                                "summary": error.title,
                                "value": {
                                    "type": error.type,
                                    "title": error.title,
                                    "status": error.status,
                                    "detail": error.description,
                                    "instance": "/api/v1/example",
                                    "correlation_id": "123e4567-e89b-12d3-a456-426614174000",
                                    "error_code": error.error_code,
                                    "timestamp": "2025-08-08T12:00:00Z",
                                },
                            }
                            for error in errors
                        },
                    }
                },
            }

        return responses


def create_api_error_from_code(error_code: str, detail: Optional[str] = None, **kwargs: Any) -> "APIError":
    """Create an APIError instance from error code using the error dictionary."""
    from .errors import APIError

    error_def = ErrorDictionary.get_error(error_code)
    if not error_def:
        # Fallback to generic internal error
        error_def = ErrorDictionary.get_error("VUTF_500_INTERNAL_ERROR")
        if not error_def:
            # Ultimate fallback
            from .errors import InternalServerError

            return InternalServerError(detail or "Unknown error occurred")

    return APIError(
        status_code=error_def.status,
        error_code=error_def.error_code,
        title=error_def.title,
        detail=detail or error_def.description,
        problem_type=error_def.type,
        **kwargs,
    )
