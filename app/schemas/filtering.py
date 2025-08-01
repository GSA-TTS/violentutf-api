"""Advanced filtering schemas for comprehensive API filtering capabilities."""

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator


class FilterOperator(str, Enum):
    """Supported filter operators."""

    # Equality operators
    EQ = "eq"  # Equal to
    NE = "ne"  # Not equal to

    # Comparison operators
    GT = "gt"  # Greater than
    GTE = "gte"  # Greater than or equal
    LT = "lt"  # Less than
    LTE = "lte"  # Less than or equal

    # Collection operators
    IN = "in"  # Value in list
    NIN = "nin"  # Value not in list

    # String operators
    CONTAINS = "contains"  # String contains substring
    ICONTAINS = "icontains"  # Case-insensitive contains
    STARTSWITH = "startswith"  # String starts with
    ISTARTSWITH = "istartswith"  # Case-insensitive starts with
    ENDSWITH = "endswith"  # String ends with
    IENDSWITH = "iendswith"  # Case-insensitive ends with
    REGEX = "regex"  # Regular expression match
    IREGEX = "iregex"  # Case-insensitive regex

    # Null operators
    ISNULL = "isnull"  # Is null/None
    ISNOTNULL = "isnotnull"  # Is not null/None

    # Boolean operators
    ISTRUE = "istrue"  # Is true
    ISFALSE = "isfalse"  # Is false


class FieldFilter(BaseModel):
    """Individual field filter specification."""

    operator: FilterOperator = Field(..., description="Filter operator to apply")
    value: Union[str, int, float, bool, List[Any], None] = Field(..., description="Value to filter by")
    case_sensitive: bool = Field(True, description="Whether string operations should be case sensitive")

    @field_validator("value")
    @classmethod
    def validate_value(
        cls: type["FieldFilter"], v: Union[str, int, float, bool, List[Union[str, int, float]], None], info: object
    ) -> Union[str, int, float, bool, List[Union[str, int, float]], None]:
        """Validate filter value based on operator."""
        if not hasattr(info, "data") or "operator" not in info.data:
            return v

        operator = info.data["operator"]
        return cls._validate_operator_value(operator, v)

    @classmethod
    def _validate_operator_value(
        cls: type["FieldFilter"],
        operator: FilterOperator,
        v: Union[str, int, float, bool, List[Union[str, int, float]], None],
    ) -> Union[str, int, float, bool, List[Union[str, int, float]], None]:
        """Validate value for specific operator."""
        # For IN and NIN operators, value must be a list
        if operator in [FilterOperator.IN, FilterOperator.NIN]:
            return cls._validate_list_value(operator, v)

        # For null check operators, value should be boolean or None
        elif operator in [FilterOperator.ISNULL, FilterOperator.ISNOTNULL]:
            return cls._validate_null_value(v)  # type: ignore[arg-type]

        # For boolean operators, no value needed
        elif operator in [FilterOperator.ISTRUE, FilterOperator.ISFALSE]:
            return None

        # For regex operators, validate regex pattern
        elif operator in [FilterOperator.REGEX, FilterOperator.IREGEX]:
            return cls._validate_regex_value(operator, v)

        return v

    @classmethod
    def _validate_list_value(
        cls: type["FieldFilter"],
        operator: FilterOperator,
        v: Union[str, int, float, bool, List[Union[str, int, float]], None],
    ) -> List[Union[str, int, float]]:
        """Validate list value for IN/NIN operators."""
        if not isinstance(v, list):
            raise ValueError(f"Operator '{operator}' requires a list value")
        if len(v) == 0:
            raise ValueError(f"Operator '{operator}' requires non-empty list")
        return v

    @classmethod
    def _validate_null_value(cls: type["FieldFilter"], v: Union[str, int, float, bool, None]) -> Union[bool, None]:
        """Validate null check value."""
        if v is not None and not isinstance(v, bool):
            # Convert to boolean for convenience
            v = bool(v)
        return v

    @classmethod
    def _validate_regex_value(
        cls: type["FieldFilter"],
        operator: FilterOperator,
        v: Union[str, int, float, bool, List[Union[str, int, float]], None],
    ) -> str:
        """Validate regex pattern value."""
        if not isinstance(v, str):
            raise ValueError(f"Operator '{operator}' requires string value")
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        return v


class SortField(BaseModel):
    """Individual sort field specification."""

    field: str = Field(..., description="Field name to sort by")
    direction: str = Field(default="asc", pattern="^(asc|desc)$", description="Sort direction")
    nulls: str = Field(default="last", pattern="^(first|last)$", description="Where to place null values")


class EnhancedFilter(BaseModel):
    """Enhanced filtering with field-specific operators and multi-field sorting."""

    # Basic pagination (offset-based)
    page: int = Field(1, ge=1, le=10000, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")

    # Cursor-based pagination
    cursor: Optional[str] = Field(None, description="Cursor for pagination")
    cursor_direction: str = Field(
        default="next", pattern="^(next|prev)$", description="Cursor direction for pagination"
    )

    # Advanced filtering
    filters: Dict[str, FieldFilter] = Field(default_factory=dict, description="Field-specific filters")

    # Multi-field sorting
    sort: List[SortField] = Field(default_factory=list, description="Multi-field sorting specification")

    # Legacy single-field sorting (for backward compatibility)
    sort_by: Optional[str] = Field(None, description="Single field to sort by")
    sort_order: str = Field(default="asc", pattern="^(asc|desc)$", description="Sort order for single field")

    # Full-text search
    search: Optional[str] = Field(None, min_length=1, max_length=255, description="Full-text search query")
    search_fields: List[str] = Field(
        default_factory=list, description="Fields to search in (empty = search all searchable fields)"
    )

    # Date range filtering
    created_after: Optional[datetime] = Field(None, description="Filter items created after")
    created_before: Optional[datetime] = Field(None, description="Filter items created before")
    updated_after: Optional[datetime] = Field(None, description="Filter items updated after")
    updated_before: Optional[datetime] = Field(None, description="Filter items updated before")

    # Status filtering
    include_deleted: bool = Field(False, description="Include soft-deleted items")

    # Field selection (sparse fieldsets)
    fields: Optional[List[str]] = Field(None, description="Specific fields to include in response (sparse fieldsets)")
    exclude_fields: Optional[List[str]] = Field(None, description="Fields to exclude from response")

    # Caching control
    use_cache: bool = Field(True, description="Whether to use cached results")
    cache_ttl: Optional[int] = Field(None, ge=1, le=86400, description="Custom cache TTL in seconds")  # Max 24 hours

    @field_validator("search")
    @classmethod
    def validate_search(cls: type["EnhancedFilter"], v: Optional[str]) -> Optional[str]:
        """Validate and sanitize search query."""
        if v is None:
            return v

        # Remove potentially dangerous characters for SQL injection prevention
        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--", "/*", "*/", "\\x00"]
        for char in dangerous_chars:
            v = v.replace(char, "")

        # Remove excessive whitespace
        v = re.sub(r"\s+", " ", v.strip())

        return v if v else None

    @field_validator("filters")
    @classmethod
    def validate_filters(cls: type["EnhancedFilter"], v: Dict[str, FieldFilter]) -> Dict[str, FieldFilter]:
        """Validate filter field names."""
        validated_filters = {}

        for field_name, field_filter in v.items():
            # Validate field name format
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", field_name):
                raise ValueError(f"Invalid field name: {field_name}")

            # Prevent SQL injection in field names
            if any(keyword in field_name.lower() for keyword in ["drop", "delete", "insert", "update", "select"]):
                raise ValueError(f"Invalid field name: {field_name}")

            validated_filters[field_name] = field_filter

        return validated_filters

    @field_validator("sort")
    @classmethod
    def validate_sort_fields(cls: type["EnhancedFilter"], v: List[SortField]) -> List[SortField]:
        """Validate sort field specifications."""
        if len(v) > 5:  # Limit to 5 sort fields for performance
            raise ValueError("Maximum 5 sort fields allowed")

        seen_fields = set()
        for sort_field in v:
            if sort_field.field in seen_fields:
                raise ValueError(f"Duplicate sort field: {sort_field.field}")
            seen_fields.add(sort_field.field)

            # Validate field name format
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", sort_field.field):
                raise ValueError(f"Invalid sort field name: {sort_field.field}")

        return v

    def get_cache_key_components(self) -> Dict[str, Any]:
        """Get components for cache key generation."""
        return {
            "page": self.page,
            "per_page": self.per_page,
            "cursor": self.cursor,
            "cursor_direction": self.cursor_direction,
            "filters": {k: {"op": v.operator, "val": v.value, "cs": v.case_sensitive} for k, v in self.filters.items()},
            "sort": [{"field": s.field, "dir": s.direction, "nulls": s.nulls} for s in self.sort],
            "sort_by": self.sort_by,
            "sort_order": self.sort_order,
            "search": self.search,
            "search_fields": sorted(self.search_fields) if self.search_fields else [],
            "date_filters": {
                "created_after": self.created_after.isoformat() if self.created_after else None,
                "created_before": self.created_before.isoformat() if self.created_before else None,
                "updated_after": self.updated_after.isoformat() if self.updated_after else None,
                "updated_before": self.updated_before.isoformat() if self.updated_before else None,
            },
            "include_deleted": self.include_deleted,
            "fields": sorted(self.fields) if self.fields else None,
            "exclude_fields": sorted(self.exclude_fields) if self.exclude_fields else None,
        }
