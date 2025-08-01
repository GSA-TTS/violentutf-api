"""Comprehensive tests for common schemas to achieve 90%+ coverage."""

from datetime import datetime, timezone
from typing import List
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from app.schemas.common import (
    ErrorResponse,
    HealthResponse,
    IdempotencyHeader,
    PaginatedResponse,
    PaginationParams,
    ValidationErrorResponse,
)


class TestErrorResponse:
    """Test ErrorResponse schema."""

    def test_error_response_minimal(self):
        """Test creating error response with minimal fields."""
        error = ErrorResponse(error="Something went wrong")

        assert error.error == "Something went wrong"
        assert error.detail is None
        assert error.request_id is None
        assert isinstance(error.timestamp, datetime)

    def test_error_response_full(self):
        """Test creating error response with all fields."""
        timestamp = datetime.now(timezone.utc)
        error = ErrorResponse(
            error="Database connection failed",
            detail="Could not connect to PostgreSQL on port 5432",
            request_id="req-123-456",
            timestamp=timestamp,
        )

        assert error.error == "Database connection failed"
        assert error.detail == "Could not connect to PostgreSQL on port 5432"
        assert error.request_id == "req-123-456"
        assert error.timestamp == timestamp

    def test_error_response_auto_timestamp(self):
        """Test that timestamp is auto-generated if not provided."""
        before = datetime.utcnow()
        error = ErrorResponse(error="Test error")
        after = datetime.utcnow()

        assert before <= error.timestamp <= after

    def test_error_response_dict_export(self):
        """Test exporting error response to dict."""
        error = ErrorResponse(error="Test error", detail="Test detail", request_id="test-123")

        data = error.model_dump()
        assert data["error"] == "Test error"
        assert data["detail"] == "Test detail"
        assert data["request_id"] == "test-123"
        assert "timestamp" in data

    def test_error_response_json_export(self):
        """Test exporting error response to JSON."""
        error = ErrorResponse(error="JSON test")

        json_str = error.model_dump_json()
        assert "JSON test" in json_str
        assert "timestamp" in json_str

    def test_error_response_from_dict(self):
        """Test creating error response from dict."""
        data = {
            "error": "From dict",
            "detail": "Created from dictionary",
            "request_id": "dict-123",
            "timestamp": datetime.utcnow(),
        }

        error = ErrorResponse(**data)
        assert error.error == "From dict"
        assert error.detail == "Created from dictionary"


class TestValidationErrorResponse:
    """Test ValidationErrorResponse schema."""

    def test_validation_error_response_minimal(self):
        """Test creating validation error with minimal fields."""
        detail = [
            {"field": "username", "error": "Required field missing"},
            {"field": "email", "error": "Invalid email format"},
        ]

        error = ValidationErrorResponse(detail=detail)

        assert error.error == "Validation Error"  # Default value
        assert error.detail == detail
        assert error.request_id is None
        assert isinstance(error.timestamp, datetime)

    def test_validation_error_response_full(self):
        """Test creating validation error with all fields."""
        detail = [{"field": "age", "error": "Must be positive"}]
        timestamp = datetime.now(timezone.utc)

        error = ValidationErrorResponse(
            error="Custom Validation Error", detail=detail, request_id="val-123", timestamp=timestamp
        )

        assert error.error == "Custom Validation Error"
        assert error.detail == detail
        assert error.request_id == "val-123"
        assert error.timestamp == timestamp

    def test_validation_error_complex_detail(self):
        """Test validation error with complex detail structure."""
        detail = [
            {
                "field": "nested.field.value",
                "error": "Invalid nested value",
                "context": {"min": 0, "max": 100, "actual": 150},
            },
            {"field": "array[2].name", "error": "Duplicate name", "value": "duplicate"},
        ]

        error = ValidationErrorResponse(detail=detail)
        assert len(error.detail) == 2
        assert error.detail[0]["context"]["actual"] == 150

    def test_validation_error_empty_detail(self):
        """Test validation error with empty detail list."""
        error = ValidationErrorResponse(detail=[])
        assert error.detail == []
        assert error.error == "Validation Error"

    def test_validation_error_missing_detail(self):
        """Test that detail is required."""
        with pytest.raises(ValidationError) as exc_info:
            ValidationErrorResponse()

        errors = exc_info.value.errors()
        assert any(e["loc"] == ("detail",) for e in errors)


class TestHealthResponse:
    """Test HealthResponse schema."""

    def test_health_response_create(self):
        """Test creating health response."""
        timestamp = datetime.now(timezone.utc)

        health = HealthResponse(status="healthy", timestamp=timestamp, service="violentutf-api", version="1.0.0")

        assert health.status == "healthy"
        assert health.timestamp == timestamp
        assert health.service == "violentutf-api"
        assert health.version == "1.0.0"

    def test_health_response_unhealthy(self):
        """Test health response with unhealthy status."""
        health = HealthResponse(
            status="unhealthy", timestamp=datetime.utcnow(), service="test-service", version="0.1.0"
        )

        assert health.status == "unhealthy"

    def test_health_response_required_fields(self):
        """Test that all fields are required."""
        # Missing status
        with pytest.raises(ValidationError):
            HealthResponse(timestamp=datetime.utcnow(), service="test", version="1.0")

        # Missing timestamp
        with pytest.raises(ValidationError):
            HealthResponse(status="healthy", service="test", version="1.0")

        # Missing service
        with pytest.raises(ValidationError):
            HealthResponse(status="healthy", timestamp=datetime.utcnow(), version="1.0")

        # Missing version
        with pytest.raises(ValidationError):
            HealthResponse(status="healthy", timestamp=datetime.utcnow(), service="test")

    def test_health_response_various_statuses(self):
        """Test health response with various status values."""
        statuses = ["healthy", "unhealthy", "degraded", "maintenance", "starting", "stopping"]

        for status in statuses:
            health = HealthResponse(status=status, timestamp=datetime.utcnow(), service="test", version="1.0")
            assert health.status == status


class TestPaginationParams:
    """Test PaginationParams schema."""

    def test_pagination_params_defaults(self):
        """Test pagination params with default values."""
        params = PaginationParams()

        assert params.page == 1
        assert params.page_size == 20
        assert params.skip == 0
        assert params.limit == 20

    def test_pagination_params_custom(self):
        """Test pagination params with custom values."""
        params = PaginationParams(page=3, page_size=50)

        assert params.page == 3
        assert params.page_size == 50
        assert params.skip == 100  # (3-1) * 50
        assert params.limit == 50

    def test_pagination_params_skip_calculation(self):
        """Test skip calculation for various pages."""
        test_cases = [
            (1, 10, 0),  # Page 1, size 10 -> skip 0
            (2, 10, 10),  # Page 2, size 10 -> skip 10
            (5, 20, 80),  # Page 5, size 20 -> skip 80
            (10, 5, 45),  # Page 10, size 5 -> skip 45
        ]

        for page, page_size, expected_skip in test_cases:
            params = PaginationParams(page=page, page_size=page_size)
            assert params.skip == expected_skip

    def test_pagination_params_validation(self):
        """Test pagination params validation."""
        # Page must be >= 1
        with pytest.raises(ValidationError):
            PaginationParams(page=0)

        with pytest.raises(ValidationError):
            PaginationParams(page=-1)

        # Page size must be >= 1
        with pytest.raises(ValidationError):
            PaginationParams(page_size=0)

        # Page size must be <= 100
        with pytest.raises(ValidationError):
            PaginationParams(page_size=101)

    def test_pagination_params_edge_cases(self):
        """Test pagination params edge cases."""
        # Minimum values
        params = PaginationParams(page=1, page_size=1)
        assert params.skip == 0
        assert params.limit == 1

        # Maximum page_size
        params = PaginationParams(page=1, page_size=100)
        assert params.skip == 0
        assert params.limit == 100

    def test_pagination_params_properties(self):
        """Test that skip and limit are properties, not fields."""
        params = PaginationParams(page=2, page_size=25)

        # Properties should work
        assert params.skip == 25
        assert params.limit == 25

        # Should not be in dict export
        data = params.model_dump()
        assert "skip" not in data
        assert "limit" not in data
        assert data == {"page": 2, "page_size": 25}


class TestPaginatedResponse:
    """Test PaginatedResponse schema."""

    def test_paginated_response_basic(self):
        """Test basic paginated response."""
        items = ["item1", "item2", "item3"]

        response = PaginatedResponse[str](items=items, total=10, page=1, page_size=3, total_pages=4)

        assert response.items == items
        assert response.total == 10
        assert response.page == 1
        assert response.page_size == 3
        assert response.total_pages == 4

    def test_paginated_response_auto_total_pages(self):
        """Test automatic total_pages calculation."""
        # When total_pages is not provided, it should be calculated
        response = PaginatedResponse[int](
            items=[1, 2, 3, 4, 5], total=47, page=2, page_size=10, total_pages=None  # Should be calculated
        )

        # 47 items / 10 per page = 5 pages (rounded up)
        assert response.total_pages == 5

    def test_paginated_response_total_pages_calculation(self):
        """Test total_pages calculation for various scenarios."""
        test_cases = [
            (10, 5, 2),  # 10 items, 5 per page = 2 pages
            (11, 5, 3),  # 11 items, 5 per page = 3 pages
            (0, 10, 0),  # 0 items = 0 pages
            (1, 10, 1),  # 1 item, 10 per page = 1 page
            (100, 20, 5),  # 100 items, 20 per page = 5 pages
            (99, 20, 5),  # 99 items, 20 per page = 5 pages
        ]

        for total, page_size, expected_pages in test_cases:
            response = PaginatedResponse[str](items=[], total=total, page=1, page_size=page_size, total_pages=None)
            assert response.total_pages == expected_pages

    def test_paginated_response_complex_types(self):
        """Test paginated response with complex item types."""
        # Dict items
        dict_items = [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]

        response = PaginatedResponse[dict](items=dict_items, total=10, page=1, page_size=2, total_pages=5)

        assert response.items == dict_items
        assert response.items[0]["name"] == "Item 1"

    def test_paginated_response_empty(self):
        """Test paginated response with no items."""
        response = PaginatedResponse[str](items=[], total=0, page=1, page_size=20, total_pages=0)

        assert response.items == []
        assert response.total == 0
        assert response.total_pages == 0

    def test_paginated_response_validation(self):
        """Test paginated response validation."""
        # Negative total
        with pytest.raises(ValidationError):
            PaginatedResponse[str](items=["test"], total=-1, page=1, page_size=10, total_pages=1)

        # Zero page
        with pytest.raises(ValidationError):
            PaginatedResponse[str](items=["test"], total=1, page=0, page_size=10, total_pages=1)

    def test_paginated_response_field_validator(self):
        """Test the field validator for total_pages."""
        # When total_pages is provided, it should be used
        response = PaginatedResponse[int](
            items=[1, 2, 3], total=100, page=1, page_size=10, total_pages=15  # Explicitly set, even if wrong
        )
        assert response.total_pages == 15  # Uses provided value

    def test_paginated_response_edge_case_page_size_zero(self):
        """Test edge case when page_size is at validation boundary."""
        # This tests the validator's division by zero protection
        response = PaginatedResponse[str](
            items=[], total=10, page=1, page_size=1, total_pages=None  # Minimum valid page_size
        )
        assert response.total_pages == 10  # 10 items / 1 per page


class TestIdempotencyHeader:
    """Test IdempotencyHeader schema."""

    def test_idempotency_header_none(self):
        """Test idempotency header with None value."""
        header = IdempotencyHeader()
        assert header.idempotency_key is None

    def test_idempotency_header_valid(self):
        """Test idempotency header with valid key."""
        valid_keys = [
            "simple-key",
            "key_with_underscore",
            "key-with-dash",
            "KEY123",
            "a",  # Minimum length
            "a" * 255,  # Maximum length
        ]

        for key in valid_keys:
            header = IdempotencyHeader(idempotency_key=key)
            assert header.idempotency_key == key

    def test_idempotency_header_pattern_validation(self):
        """Test idempotency header pattern validation."""
        invalid_keys = [
            "key with space",
            "key@with@at",
            "key#with#hash",
            "key.with.dot",
            "key/with/slash",
            "key\\with\\backslash",
            "key!with!exclamation",
            "key$with$dollar",
            "key%with%percent",
            "key&with&ampersand",
            "key*with*asterisk",
            "key+with+plus",
            "key=with=equals",
            "key[with]brackets",
            "key{with}braces",
            "key|with|pipe",
            "key:with:colon",
            "key;with;semicolon",
            "key'with'quote",
            'key"with"doublequote',
            "key<with>angles",
            "key?with?question",
        ]

        for key in invalid_keys:
            with pytest.raises(ValidationError) as exc_info:
                IdempotencyHeader(idempotency_key=key)

            errors = exc_info.value.errors()
            # Pydantic v2 uses "String should match pattern" instead of "string does not match regex"
            assert any("pattern" in str(e) for e in errors)

    def test_idempotency_header_length_validation(self):
        """Test idempotency header length validation."""
        # Empty string (less than min_length=1)
        with pytest.raises(ValidationError):
            IdempotencyHeader(idempotency_key="")

        # Too long (more than max_length=255)
        with pytest.raises(ValidationError):
            IdempotencyHeader(idempotency_key="a" * 256)

    def test_idempotency_header_optional(self):
        """Test that idempotency key is optional."""
        # Should be able to create without providing the key
        header = IdempotencyHeader()
        assert header.idempotency_key is None

        # Should be able to explicitly set to None
        header = IdempotencyHeader(idempotency_key=None)
        assert header.idempotency_key is None

    def test_idempotency_header_serialization(self):
        """Test idempotency header serialization."""
        header = IdempotencyHeader(idempotency_key="test-key-123")

        # To dict
        data = header.model_dump()
        assert data == {"idempotency_key": "test-key-123"}

        # To JSON
        json_str = header.model_dump_json()
        assert '"idempotency_key":"test-key-123"' in json_str

        # From dict
        header2 = IdempotencyHeader(**data)
        assert header2.idempotency_key == "test-key-123"


class TestSchemaIntegration:
    """Test schema integration scenarios."""

    def test_error_response_in_api_context(self):
        """Test error response as it would be used in API."""
        # Simulate an API error scenario
        try:
            # Some operation that fails
            raise ValueError("Database connection failed")
        except ValueError as e:
            error = ErrorResponse(error=str(e), detail="Could not connect to PostgreSQL", request_id="api-req-123")

            # This is what would be returned to client
            response_data = error.model_dump()
            assert response_data["error"] == "Database connection failed"
            assert "timestamp" in response_data

    def test_pagination_in_api_context(self):
        """Test pagination as it would be used in API."""
        # Simulate query parameters from API
        query_params = {"page": "2", "page_size": "25"}

        # Parse into PaginationParams
        params = PaginationParams(page=int(query_params["page"]), page_size=int(query_params["page_size"]))

        # Use in database query
        skip = params.skip
        limit = params.limit

        # Simulate fetching data
        all_items = list(range(100))  # 100 items total
        paginated_items = all_items[skip : skip + limit]

        # Create response
        response = PaginatedResponse[int](
            items=paginated_items,
            total=len(all_items),
            page=params.page,
            page_size=params.page_size,
            total_pages=None,  # Let it calculate
        )

        assert len(response.items) == 25
        assert response.items[0] == 25  # First item on page 2
        assert response.total_pages == 4  # 100 items / 25 per page

    def test_validation_error_from_pydantic(self):
        """Test creating validation error response from Pydantic errors."""
        # Simulate a Pydantic validation error
        try:
            # This would come from validating user input
            PaginationParams(page=0, page_size=200)  # Both invalid
        except ValidationError as e:
            # Convert Pydantic errors to our format
            detail = []
            for error in e.errors():
                detail.append(
                    {"field": ".".join(str(loc) for loc in error["loc"]), "error": error["msg"], "type": error["type"]}
                )

            error_response = ValidationErrorResponse(detail=detail, request_id="validation-123")

            assert len(error_response.detail) == 2  # Two validation errors
            assert any(d["field"] == "page" for d in error_response.detail)
            assert any(d["field"] == "page_size" for d in error_response.detail)
