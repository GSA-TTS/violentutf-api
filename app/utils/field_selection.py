"""Field selection utilities for sparse fieldsets implementation."""

import json
from typing import Any, Dict, List, Optional, Set, Type, Union

from pydantic import BaseModel
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload
from structlog.stdlib import get_logger

from ..db.base_class import Base

logger = get_logger(__name__)


class FieldSelector:
    """
    Handles field selection and sparse fieldsets for API responses.

    Features:
    - Dynamic field inclusion/exclusion
    - Relationship field selection
    - Security-aware field filtering
    - Optimized SQL query generation
    - Response transformation
    """

    def __init__(self, model: Type[Base], schema: Type[BaseModel]):
        """
        Initialize field selector.

        Args:
            model: SQLAlchemy model class
            schema: Pydantic response schema class
        """
        self.model = model
        self.schema = schema
        self.logger = logger.bind(model=model.__name__, schema=schema.__name__)

        # Get model and schema field information
        self.model_fields = self._get_model_fields()
        self.schema_fields = self._get_schema_fields()
        self.relationship_fields = self._get_relationship_fields()

        # Define security-sensitive fields that should be protected
        self.protected_fields = {
            "password",
            "password_hash",
            "hashed_password",
            "secret",
            "token",
            "private_key",
            "api_key",
            "access_token",
            "refresh_token",
        }

        # Define fields that are always included (security and functionality)
        self.required_fields = {"id"}

    def _get_model_fields(self) -> Set[str]:
        """Get all available fields from the SQLAlchemy model."""
        inspector = inspect(self.model)

        # Get column fields
        column_fields = {column.name for column in inspector.columns}

        # Get relationship fields
        relationship_fields = {rel.key for rel in inspector.relationships}

        return column_fields | relationship_fields

    def _get_schema_fields(self) -> Set[str]:
        """Get all available fields from the Pydantic schema."""
        if hasattr(self.schema, "model_fields"):
            # Pydantic v2
            model_fields = getattr(self.schema, "model_fields")
            if hasattr(model_fields, "keys"):
                return set(model_fields.keys())
            else:
                return set(model_fields().keys()) if callable(model_fields) else set()
        elif hasattr(self.schema, "__fields__"):
            # Pydantic v1
            return set(self.schema.__fields__.keys())  # type: ignore[attr-defined]
        else:
            return set()

    def _get_relationship_fields(self) -> Dict[str, Dict[str, str]]:
        """Get relationship fields and their types."""
        inspector = inspect(self.model)
        relationships = {}

        for rel in inspector.relationships:
            relationships[rel.key] = {"type": "many" if rel.uselist else "one", "model": rel.mapper.class_.__name__}

        return relationships

    def validate_field_selection(
        self, include_fields: Optional[List[str]] = None, exclude_fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Validate field selection parameters.

        Args:
            include_fields: Fields to include
            exclude_fields: Fields to exclude

        Returns:
            Validation result with effective fields and warnings
        """
        result: Dict[str, Any] = {"valid": True, "effective_fields": None, "warnings": [], "errors": []}

        # Determine initial field set
        effective_fields = self._get_initial_fields(include_fields, result)

        # Apply exclusions
        effective_fields = self._apply_exclusions(effective_fields, exclude_fields, result)

        # Apply security checks
        effective_fields = self._apply_security_checks(effective_fields, include_fields, result)

        result["effective_fields"] = list(effective_fields)

        if result["errors"]:
            result["valid"] = False

        return result

    def _get_initial_fields(self, include_fields: Optional[List[str]], result: Dict[str, Any]) -> Set[str]:
        """Get initial field set based on inclusion parameters."""
        if include_fields is None:
            return self.schema_fields.copy()

        effective_fields = set()
        warnings = result["warnings"]

        for field in include_fields:
            if field in self.schema_fields:
                effective_fields.add(field)
            elif field in self.model_fields:
                warnings.append(f"Field '{field}' exists in model but not in response schema")
            else:
                warnings.append(f"Field '{field}' does not exist")

        return effective_fields

    def _apply_exclusions(
        self, effective_fields: Set[str], exclude_fields: Optional[List[str]], result: Dict[str, Any]
    ) -> Set[str]:
        """Apply field exclusions."""
        if not exclude_fields:
            return effective_fields

        warnings = result["warnings"]

        for field in exclude_fields:
            if field in effective_fields:
                effective_fields.discard(field)
            elif field not in self.schema_fields:
                warnings.append(f"Excluded field '{field}' does not exist")

        return effective_fields

    def _apply_security_checks(
        self, effective_fields: Set[str], include_fields: Optional[List[str]], result: Dict[str, Any]
    ) -> Set[str]:
        """Apply security checks and required field rules."""
        # Check for protected fields in inclusion
        if include_fields:
            protected_requested = set(include_fields) & self.protected_fields
            if protected_requested:
                errors = result["errors"]
                errors.append(f"Protected fields requested: {protected_requested}")
                effective_fields -= protected_requested

        # Ensure required fields are always included
        effective_fields |= self.required_fields

        # Remove any protected fields that might have been included
        effective_fields -= self.protected_fields

        return effective_fields

    def optimize_query_for_fields(
        self, query: object, include_fields: Optional[List[str]] = None, exclude_fields: Optional[List[str]] = None
    ) -> object:
        """
        Optimize SQLAlchemy query based on field selection.

        Args:
            query: SQLAlchemy query object
            include_fields: Fields to include
            exclude_fields: Fields to exclude

        Returns:
            Optimized query with appropriate loading strategies
        """
        validation = self.validate_field_selection(include_fields, exclude_fields)

        if not validation["valid"]:
            self.logger.warning("Invalid field selection", errors=validation["errors"])
            return query

        effective_fields = set(validation["effective_fields"])

        # Determine which relationships need to be loaded
        relationships_needed = effective_fields & set(self.relationship_fields.keys())

        # Apply appropriate loading strategies
        for rel_name in relationships_needed:
            rel_info = self.relationship_fields[rel_name]

            # Use selectinload for to-many relationships to avoid N+1 queries
            # Use joinedload for to-one relationships for efficiency
            if rel_info["type"] == "many":
                query = query.options(selectinload(getattr(self.model, rel_name)))  # type: ignore[attr-defined]
            else:
                query = query.options(joinedload(getattr(self.model, rel_name)))  # type: ignore[attr-defined]

        self.logger.debug(
            "Query optimized for field selection",
            effective_fields=effective_fields,
            relationships_loaded=list(relationships_needed),
        )

        return query

    def transform_response(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]], BaseModel, List[BaseModel]],
        include_fields: Optional[List[str]] = None,
        exclude_fields: Optional[List[str]] = None,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Transform response data based on field selection.

        Args:
            data: Response data to transform
            include_fields: Fields to include
            exclude_fields: Fields to exclude

        Returns:
            Transformed response data
        """
        validation = self.validate_field_selection(include_fields, exclude_fields)

        if not validation["valid"]:
            self.logger.warning("Invalid field selection for response transformation", errors=validation["errors"])
            # Return original data if validation fails
            return self._ensure_dict(data)  # type: ignore[arg-type]

        effective_fields = set(validation["effective_fields"])

        # Handle single item vs list
        if isinstance(data, list):
            filtered_list = [self._filter_item_fields(item, effective_fields) for item in data]
            return filtered_list
        else:
            return self._filter_item_fields(data, effective_fields)

    def _filter_item_fields(self, item: Union[Dict[str, Any], BaseModel], effective_fields: Set[str]) -> Dict[str, Any]:
        """Filter fields from a single item."""
        # Convert to dict if it's a Pydantic model
        if isinstance(item, BaseModel):
            if hasattr(item, "model_dump"):
                # Pydantic v2
                item_dict = item.model_dump()
            else:
                # Pydantic v1
                item_dict = item.dict()
        else:
            item_dict = dict(item)

        # Filter fields
        filtered_dict = {}
        for field_name, field_value in item_dict.items():
            if field_name in effective_fields:
                # Handle nested objects (relationships)
                if isinstance(field_value, (dict, BaseModel)):
                    # For nested objects, include all fields (could be enhanced for nested field selection)
                    filtered_dict[field_name] = self._ensure_dict(field_value)
                elif isinstance(field_value, list) and field_value and isinstance(field_value[0], (dict, BaseModel)):
                    # For lists of nested objects
                    filtered_dict[field_name] = [self._ensure_dict(nested_item) for nested_item in field_value]  # type: ignore[assignment]
                else:
                    filtered_dict[field_name] = field_value

        return filtered_dict

    def _ensure_dict(self, item: Union[Dict[str, Any], BaseModel]) -> Dict[str, Any]:
        """Ensure item is a dictionary."""
        if isinstance(item, BaseModel):
            if hasattr(item, "model_dump"):
                return item.model_dump()
            else:
                return item.dict()
        return dict(item) if item is not None else {}

    def get_field_info(self) -> Dict[str, Any]:
        """Get information about available fields for API documentation."""
        return {
            "model_fields": list(self.model_fields),
            "schema_fields": list(self.schema_fields),
            "relationship_fields": self.relationship_fields,
            "protected_fields": list(self.protected_fields),
            "required_fields": list(self.required_fields),
            "selectable_fields": list(self.schema_fields - self.protected_fields),
        }

    def create_dynamic_schema(
        self, include_fields: Optional[List[str]] = None, exclude_fields: Optional[List[str]] = None
    ) -> Type[BaseModel]:
        """
        Create a dynamic Pydantic schema with only specified fields.

        Args:
            include_fields: Fields to include
            exclude_fields: Fields to exclude

        Returns:
            Dynamic Pydantic model class
        """
        validation = self.validate_field_selection(include_fields, exclude_fields)

        if not validation["valid"]:
            self.logger.warning("Cannot create dynamic schema with invalid field selection")
            return self.schema

        effective_fields = set(validation["effective_fields"])
        original_fields = self._get_original_fields()

        if not original_fields:
            return self.schema

        new_fields = self._filter_fields_for_schema(effective_fields, original_fields)
        return self._create_dynamic_model(new_fields)

    def _get_original_fields(self) -> Dict[str, Any]:
        """Get original schema field definitions."""
        if hasattr(self.schema, "model_fields"):
            # Pydantic v2
            model_fields = getattr(self.schema, "model_fields")
            if hasattr(model_fields, "keys"):
                return dict(model_fields)
            else:
                return dict(model_fields()) if callable(model_fields) else {}
        elif hasattr(self.schema, "__fields__"):
            # Pydantic v1
            return dict(self.schema.__fields__)  # type: ignore[no-any-return,call-overload]
        else:
            return {}

    def _filter_fields_for_schema(self, effective_fields: Set[str], original_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Filter original fields to only include effective fields."""
        new_fields = {}
        for field_name in effective_fields:
            if field_name in original_fields:
                new_fields[field_name] = original_fields[field_name]
        return new_fields

    def _create_dynamic_model(self, new_fields: Dict[str, Any]) -> Type[BaseModel]:
        """Create dynamic Pydantic model from field definitions."""
        dynamic_schema_name = f"{self.schema.__name__}Sparse"

        try:
            annotations = self._extract_field_annotations(new_fields)

            dynamic_schema = type(
                dynamic_schema_name,
                (BaseModel,),
                {
                    "__annotations__": annotations,
                    **{name: (annotations.get(name, str), ...) for name in new_fields.keys()},
                },
            )

            return dynamic_schema

        except Exception as e:
            self.logger.error("Failed to create dynamic schema", error=str(e))
            return self.schema

    def _extract_field_annotations(self, new_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Extract type annotations from field definitions."""
        annotations = {}
        for name, field in new_fields.items():
            if hasattr(field, "annotation"):
                annotations[name] = field.annotation
            elif hasattr(field, "type_"):
                annotations[name] = field.type_
            else:
                annotations[name] = str
        return annotations


def create_field_selector(model: Type[Base], schema: Type[BaseModel]) -> FieldSelector:
    """
    Create a configured field selector instance.

    Args:
        model: SQLAlchemy model class
        schema: Pydantic response schema class

    Returns:
        Configured FieldSelector instance
    """
    return FieldSelector(model, schema)


class SparseFieldsetsMiddleware:
    """
    Middleware to handle sparse fieldsets in API responses.

    This middleware automatically processes 'fields' and 'exclude_fields'
    query parameters and transforms responses accordingly.
    """

    def __init__(self, field_selectors: Dict[str, FieldSelector]):
        """
        Initialize middleware with field selectors for different models.

        Args:
            field_selectors: Dict mapping model names to FieldSelector instances
        """
        self.field_selectors = field_selectors
        self.logger = logger.bind(component="SparseFieldsetsMiddleware")

    def process_response(
        self,
        response_data: Union[Dict[str, object], List[Dict[str, object]], object],
        model_name: str,
        include_fields: Optional[List[str]] = None,
        exclude_fields: Optional[List[str]] = None,
    ) -> Union[Dict[str, object], List[Dict[str, object]], object]:
        """
        Process response data with field selection.

        Args:
            response_data: Response data to process
            model_name: Name of the model
            include_fields: Fields to include
            exclude_fields: Fields to exclude

        Returns:
            Processed response data
        """
        if model_name not in self.field_selectors:
            self.logger.warning("No field selector found for model", model=model_name)
            return response_data

        if not include_fields and not exclude_fields:
            return response_data

        field_selector = self.field_selectors[model_name]

        # Handle paginated responses
        if isinstance(response_data, dict) and "data" in response_data:
            processed_data = field_selector.transform_response(
                response_data["data"], include_fields=include_fields, exclude_fields=exclude_fields  # type: ignore[arg-type]
            )
            response_data["data"] = processed_data
            return response_data
        else:
            return field_selector.transform_response(
                response_data, include_fields=include_fields, exclude_fields=exclude_fields  # type: ignore[arg-type]
            )
