"""Tests for enhanced filtering system."""

from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from app.schemas.filtering import EnhancedFilter, FieldFilter, FilterOperator, SortField


class TestFieldFilter:
    """Test FieldFilter validation and behavior."""

    def test_equality_operators(self):
        """Test equality filter operators."""
        # EQ operator
        filter_eq = FieldFilter(operator=FilterOperator.EQ, value="test")
        assert filter_eq.operator == FilterOperator.EQ
        assert filter_eq.value == "test"

        # NE operator
        filter_ne = FieldFilter(operator=FilterOperator.NE, value=42)
        assert filter_ne.operator == FilterOperator.NE
        assert filter_ne.value == 42

    def test_comparison_operators(self):
        """Test comparison filter operators."""
        # GT operator
        filter_gt = FieldFilter(operator=FilterOperator.GT, value=100)
        assert filter_gt.operator == FilterOperator.GT
        assert filter_gt.value == 100

        # LTE operator
        filter_lte = FieldFilter(operator=FilterOperator.LTE, value=50.5)
        assert filter_lte.operator == FilterOperator.LTE
        assert filter_lte.value == 50.5

    def test_collection_operators(self):
        """Test collection filter operators."""
        # IN operator
        filter_in = FieldFilter(operator=FilterOperator.IN, value=["a", "b", "c"])
        assert filter_in.operator == FilterOperator.IN
        assert filter_in.value == ["a", "b", "c"]

        # NIN operator
        filter_nin = FieldFilter(operator=FilterOperator.NIN, value=[1, 2, 3])
        assert filter_nin.operator == FilterOperator.NIN
        assert filter_nin.value == [1, 2, 3]

    def test_string_operators(self):
        """Test string filter operators."""
        # CONTAINS operator
        filter_contains = FieldFilter(operator=FilterOperator.CONTAINS, value="substring", case_sensitive=False)
        assert filter_contains.operator == FilterOperator.CONTAINS
        assert filter_contains.value == "substring"
        assert filter_contains.case_sensitive is False

        # STARTSWITH operator
        filter_startswith = FieldFilter(operator=FilterOperator.STARTSWITH, value="prefix")
        assert filter_startswith.operator == FilterOperator.STARTSWITH
        assert filter_startswith.value == "prefix"
        assert filter_startswith.case_sensitive is True  # Default

    def test_regex_operators(self):
        """Test regex filter operators."""
        # Valid regex
        filter_regex = FieldFilter(operator=FilterOperator.REGEX, value=r"^[a-zA-Z]+$")
        assert filter_regex.operator == FilterOperator.REGEX
        assert filter_regex.value == r"^[a-zA-Z]+$"

    def test_regex_validation_error(self):
        """Test regex validation catches invalid patterns."""
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            FieldFilter(operator=FilterOperator.REGEX, value="[invalid")

    def test_null_operators(self):
        """Test null check operators."""
        # ISNULL operator
        filter_isnull = FieldFilter(operator=FilterOperator.ISNULL, value=True)
        assert filter_isnull.operator == FilterOperator.ISNULL
        assert filter_isnull.value is True

        # ISNOTNULL operator
        filter_isnotnull = FieldFilter(operator=FilterOperator.ISNOTNULL, value=False)
        assert filter_isnotnull.operator == FilterOperator.ISNOTNULL
        assert filter_isnotnull.value is False

    def test_boolean_operators(self):
        """Test boolean operators."""
        # ISTRUE operator
        filter_istrue = FieldFilter(operator=FilterOperator.ISTRUE, value=None)
        assert filter_istrue.operator == FilterOperator.ISTRUE
        assert filter_istrue.value is None

        # ISFALSE operator
        filter_isfalse = FieldFilter(operator=FilterOperator.ISFALSE, value=None)
        assert filter_isfalse.operator == FilterOperator.ISFALSE
        assert filter_isfalse.value is None

    def test_in_operator_validation(self):
        """Test IN operator requires list value."""
        # Valid IN filter
        filter_valid = FieldFilter(operator=FilterOperator.IN, value=["a", "b"])
        assert filter_valid.value == ["a", "b"]

        # Invalid IN filter - not a list
        with pytest.raises(ValueError, match="requires a list value"):
            FieldFilter(operator=FilterOperator.IN, value="not_a_list")

        # Invalid IN filter - empty list
        with pytest.raises(ValueError, match="requires non-empty list"):
            FieldFilter(operator=FilterOperator.IN, value=[])


class TestSortField:
    """Test SortField validation and behavior."""

    def test_basic_sort_field(self):
        """Test basic sort field creation."""
        sort_field = SortField(field="username")
        assert sort_field.field == "username"
        assert sort_field.direction == "asc"  # Default
        assert sort_field.nulls == "last"  # Default

    def test_descending_sort_field(self):
        """Test descending sort field."""
        sort_field = SortField(field="created_at", direction="desc")
        assert sort_field.field == "created_at"
        assert sort_field.direction == "desc"
        assert sort_field.nulls == "last"

    def test_nulls_first_sort_field(self):
        """Test nulls first sort field."""
        sort_field = SortField(field="last_login", direction="asc", nulls="first")
        assert sort_field.field == "last_login"
        assert sort_field.direction == "asc"
        assert sort_field.nulls == "first"

    def test_invalid_direction(self):
        """Test invalid sort direction."""
        with pytest.raises(ValueError):
            SortField(field="username", direction="invalid")

    def test_invalid_nulls_option(self):
        """Test invalid nulls option."""
        with pytest.raises(ValueError):
            SortField(field="username", nulls="invalid")


class TestEnhancedFilter:
    """Test EnhancedFilter validation and behavior."""

    def test_default_enhanced_filter(self):
        """Test default enhanced filter creation."""
        filter_obj = EnhancedFilter()
        assert filter_obj.page == 1
        assert filter_obj.per_page == 20
        assert filter_obj.cursor is None
        assert filter_obj.cursor_direction == "next"
        assert filter_obj.filters == {}
        assert filter_obj.sort == []
        assert filter_obj.sort_by is None
        assert filter_obj.sort_order == "asc"
        assert filter_obj.search is None
        assert filter_obj.search_fields == []
        assert filter_obj.include_deleted is False
        assert filter_obj.fields is None
        assert filter_obj.exclude_fields is None
        assert filter_obj.use_cache is True
        assert filter_obj.cache_ttl is None

    def test_enhanced_filter_with_field_filters(self):
        """Test enhanced filter with field-specific filters."""
        filters = {
            "username": FieldFilter(operator=FilterOperator.CONTAINS, value="admin"),
            "age": FieldFilter(operator=FilterOperator.GTE, value=18),
            "status": FieldFilter(operator=FilterOperator.IN, value=["active", "pending"]),
        }

        filter_obj = EnhancedFilter(filters=filters)
        assert len(filter_obj.filters) == 3
        assert filter_obj.filters["username"].operator == FilterOperator.CONTAINS
        assert filter_obj.filters["age"].value == 18
        assert filter_obj.filters["status"].value == ["active", "pending"]

    def test_enhanced_filter_with_multi_sort(self):
        """Test enhanced filter with multi-field sorting."""
        sort_fields = [
            SortField(field="priority", direction="desc"),
            SortField(field="created_at", direction="asc", nulls="first"),
            SortField(field="username", direction="asc"),
        ]

        filter_obj = EnhancedFilter(sort=sort_fields)
        assert len(filter_obj.sort) == 3
        assert filter_obj.sort[0].field == "priority"
        assert filter_obj.sort[0].direction == "desc"
        assert filter_obj.sort[1].nulls == "first"

    def test_enhanced_filter_with_date_range(self):
        """Test enhanced filter with date range filtering."""
        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)

        filter_obj = EnhancedFilter(created_after=yesterday, created_before=now)
        assert filter_obj.created_after == yesterday
        assert filter_obj.created_before == now

    def test_enhanced_filter_with_search(self):
        """Test enhanced filter with search functionality."""
        filter_obj = EnhancedFilter(search="admin user", search_fields=["username", "email", "full_name"])
        assert filter_obj.search == "admin user"
        assert filter_obj.search_fields == ["username", "email", "full_name"]

    def test_enhanced_filter_with_field_selection(self):
        """Test enhanced filter with field selection."""
        filter_obj = EnhancedFilter(
            fields=["id", "username", "email"], exclude_fields=["password_hash", "internal_notes"]
        )
        assert filter_obj.fields == ["id", "username", "email"]
        assert filter_obj.exclude_fields == ["password_hash", "internal_notes"]

    def test_enhanced_filter_with_caching_control(self):
        """Test enhanced filter with caching control."""
        filter_obj = EnhancedFilter(use_cache=False, cache_ttl=600)
        assert filter_obj.use_cache is False
        assert filter_obj.cache_ttl == 600

    def test_search_sanitization(self):
        """Test search query sanitization."""
        # Dangerous characters should be removed
        filter_obj = EnhancedFilter(search="admin<script>alert('xss')</script>")
        assert "<script>" not in filter_obj.search
        assert "alert" in filter_obj.search  # Safe content preserved

        # Excessive whitespace should be normalized
        filter_obj = EnhancedFilter(search="  admin   user  ")
        assert filter_obj.search == "admin user"

        # Empty search after sanitization should be None
        filter_obj = EnhancedFilter(search="   <><>&   ")
        assert filter_obj.search is None

    def test_filter_field_name_validation(self):
        """Test filter field name validation."""
        # Valid field names
        valid_filters = {
            "username": FieldFilter(operator=FilterOperator.EQ, value="test"),
            "user_id": FieldFilter(operator=FilterOperator.GT, value=0),
            "_private": FieldFilter(operator=FilterOperator.ISNULL, value=True),
        }
        filter_obj = EnhancedFilter(filters=valid_filters)
        assert len(filter_obj.filters) == 3

        # Invalid field names
        with pytest.raises(ValueError, match="Invalid field name"):
            EnhancedFilter(filters={"123invalid": FieldFilter(operator=FilterOperator.EQ, value="test")})

        with pytest.raises(ValueError, match="Invalid field name"):
            EnhancedFilter(filters={"field-with-dash": FieldFilter(operator=FilterOperator.EQ, value="test")})

        # SQL injection prevention
        with pytest.raises(ValueError, match="Invalid field name"):
            EnhancedFilter(filters={"drop_table": FieldFilter(operator=FilterOperator.EQ, value="test")})

    def test_sort_field_validation(self):
        """Test sort field validation."""
        # Valid sort fields
        valid_sort = [
            SortField(field="username"),
            SortField(field="created_at", direction="desc"),
            SortField(field="priority", direction="asc", nulls="first"),
        ]
        filter_obj = EnhancedFilter(sort=valid_sort)
        assert len(filter_obj.sort) == 3

        # Too many sort fields
        too_many_sort = [SortField(field=f"field_{i}") for i in range(6)]
        with pytest.raises(ValueError, match="Maximum 5 sort fields allowed"):
            EnhancedFilter(sort=too_many_sort)

        # Duplicate sort fields
        duplicate_sort = [SortField(field="username"), SortField(field="username", direction="desc")]
        with pytest.raises(ValueError, match="Duplicate sort field"):
            EnhancedFilter(sort=duplicate_sort)

        # Invalid sort field name
        with pytest.raises(ValueError, match="Invalid sort field name"):
            EnhancedFilter(sort=[SortField(field="123invalid")])

    def test_pagination_validation(self):
        """Test pagination parameter validation."""
        # Valid pagination
        filter_obj = EnhancedFilter(page=1, per_page=50)
        assert filter_obj.page == 1
        assert filter_obj.per_page == 50

        # Invalid page number
        with pytest.raises(ValueError):
            EnhancedFilter(page=0)

        with pytest.raises(ValueError):
            EnhancedFilter(page=10001)

        # Invalid per_page
        with pytest.raises(ValueError):
            EnhancedFilter(per_page=0)

        with pytest.raises(ValueError):
            EnhancedFilter(per_page=101)

    def test_cache_ttl_validation(self):
        """Test cache TTL validation."""
        # Valid TTL
        filter_obj = EnhancedFilter(cache_ttl=300)
        assert filter_obj.cache_ttl == 300

        # Invalid TTL - too small
        with pytest.raises(ValueError):
            EnhancedFilter(cache_ttl=0)

        # Invalid TTL - too large
        with pytest.raises(ValueError):
            EnhancedFilter(cache_ttl=86401)  # More than 24 hours

    def test_cache_key_components(self):
        """Test cache key component generation."""
        filter_obj = EnhancedFilter(
            page=2,
            per_page=50,
            filters={"username": FieldFilter(operator=FilterOperator.CONTAINS, value="admin")},
            sort=[SortField(field="created_at", direction="desc")],
            search="test query",
        )

        components = filter_obj.get_cache_key_components()

        assert components["page"] == 2
        assert components["per_page"] == 50
        assert "username" in components["filters"]
        assert components["filters"]["username"]["op"] == FilterOperator.CONTAINS
        assert components["filters"]["username"]["val"] == "admin"
        assert len(components["sort"]) == 1
        assert components["sort"][0]["field"] == "created_at"
        assert components["sort"][0]["dir"] == "desc"
        assert components["search"] == "test query"

    def test_cursor_pagination(self):
        """Test cursor pagination parameters."""
        filter_obj = EnhancedFilter(cursor="eyJmaWVsZCI6ICJpZCIsICJ2YWx1ZSI6ICIxMjMifQ==", cursor_direction="prev")
        assert filter_obj.cursor is not None
        assert filter_obj.cursor_direction == "prev"

        # Invalid cursor direction
        with pytest.raises(ValueError):
            EnhancedFilter(cursor_direction="invalid")


class TestComplexFilteringScenarios:
    """Test complex filtering scenarios combining multiple features."""

    def test_complex_user_search_scenario(self):
        """Test complex user search with multiple filters and sorting."""
        filters = {
            "status": FieldFilter(operator=FilterOperator.IN, value=["active", "pending"]),
            "age": FieldFilter(operator=FilterOperator.GTE, value=18),
            "username": FieldFilter(operator=FilterOperator.ICONTAINS, value="admin"),
            "last_login": FieldFilter(operator=FilterOperator.ISNOTNULL, value=True),
        }

        sort_fields = [
            SortField(field="priority", direction="desc"),
            SortField(field="last_login", direction="desc", nulls="last"),
            SortField(field="username", direction="asc"),
        ]

        filter_obj = EnhancedFilter(
            page=2,
            per_page=25,
            filters=filters,
            sort=sort_fields,
            search="experienced user",
            search_fields=["username", "email", "bio"],
            created_after=datetime.now(timezone.utc) - timedelta(days=30),
            fields=["id", "username", "email", "status", "last_login"],
            use_cache=True,
            cache_ttl=300,
        )

        # Verify all components are properly set
        assert filter_obj.page == 2
        assert filter_obj.per_page == 25
        assert len(filter_obj.filters) == 4
        assert len(filter_obj.sort) == 3
        assert filter_obj.search == "experienced user"
        assert len(filter_obj.search_fields) == 3
        assert filter_obj.created_after is not None
        assert len(filter_obj.fields) == 5
        assert filter_obj.use_cache is True
        assert filter_obj.cache_ttl == 300

        # Test cache key generation
        components = filter_obj.get_cache_key_components()
        assert components is not None
        assert len(components["filters"]) == 4
        assert len(components["sort"]) == 3

    def test_audit_log_filtering_scenario(self):
        """Test audit log filtering with date ranges and field selection."""
        now = datetime.now(timezone.utc)

        filters = {
            "action": FieldFilter(operator=FilterOperator.IN, value=["CREATE", "UPDATE", "DELETE"]),
            "user_id": FieldFilter(operator=FilterOperator.ISNOTNULL, value=True),
            "ip_address": FieldFilter(operator=FilterOperator.REGEX, value=r"^192\.168\."),
        }

        filter_obj = EnhancedFilter(
            page=1,
            per_page=100,
            filters=filters,
            sort=[SortField(field="timestamp", direction="desc")],
            created_after=now - timedelta(hours=24),
            created_before=now,
            exclude_fields=["sensitive_data", "internal_notes"],
            use_cache=False,  # Audit logs should not be cached
        )

        assert len(filter_obj.filters) == 3
        assert filter_obj.filters["action"].operator == FilterOperator.IN
        assert filter_obj.filters["ip_address"].operator == FilterOperator.REGEX
        assert filter_obj.use_cache is False
        assert filter_obj.created_after is not None
        assert filter_obj.created_before is not None

    def test_performance_optimized_scenario(self):
        """Test performance-optimized filtering for large datasets."""
        filter_obj = EnhancedFilter(
            cursor="eyJmaWVsZCI6ICJpZCIsICJ2YWx1ZSI6ICIxMDAwIn0=",
            cursor_direction="next",
            per_page=50,
            filters={"is_active": FieldFilter(operator=FilterOperator.ISTRUE, value=None)},
            sort=[SortField(field="id", direction="asc")],  # Efficient for cursor pagination
            fields=["id", "name", "status"],  # Sparse fieldsets for performance
            use_cache=True,
            cache_ttl=60,  # Short TTL for frequently changing data
        )

        # Verify cursor pagination setup
        assert filter_obj.cursor is not None
        assert filter_obj.cursor_direction == "next"
        assert filter_obj.per_page == 50

        # Verify performance optimizations
        assert filter_obj.fields == ["id", "name", "status"]
        assert filter_obj.cache_ttl == 60
        assert len(filter_obj.sort) == 1
        assert filter_obj.sort[0].field == "id"
