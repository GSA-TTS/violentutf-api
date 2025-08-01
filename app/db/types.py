"""Database types and utilities for cross-platform compatibility."""

import json
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import String, Text, TypeDecorator
from sqlalchemy.dialects.postgresql import JSON as PostgreSQLJSON
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.sql.type_api import TypeEngine


class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles additional types."""

    def default(self, obj: Any) -> Any:  # noqa: ANN401
        """Handle special types for JSON serialization."""
        if isinstance(obj, Decimal):
            return float(obj)
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, date):
            return obj.isoformat()
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        return super().default(obj)


class GUID(TypeDecorator[str]):
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type if available, otherwise uses String.
    Always returns string representation for consistency across databases.
    """

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        """Load the appropriate dialect implementation."""
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PostgreSQLUUID(as_uuid=True))
        else:
            return dialect.type_descriptor(String(36))

    def process_bind_param(
        self, value: Optional[Union[str, uuid.UUID]], dialect: Dialect
    ) -> Optional[Union[str, uuid.UUID]]:
        """Process values going to the database."""
        if value is None:
            return value

        if dialect.name == "postgresql":
            # PostgreSQL can handle UUID objects directly
            if isinstance(value, uuid.UUID):
                return value
            elif isinstance(value, str):
                return uuid.UUID(value)
        else:
            # SQLite and others need string representation
            if isinstance(value, uuid.UUID):
                return str(value)
            elif isinstance(value, str):
                # Validate it's a proper UUID string
                try:
                    uuid.UUID(value)
                    return value
                except ValueError:
                    raise ValueError(f"Invalid UUID string: {value}")

        # This line is only reached for PostgreSQL with non-UUID/non-string values
        # which should not happen in normal operation
        raise TypeError(f"Unexpected value type: {type(value)}")

    def process_result_value(self, value: Optional[Union[str, uuid.UUID]], dialect: Dialect) -> Optional[str]:
        """Process values coming from the database."""
        if value is None:
            return value

        # Always return string representation for consistency
        if isinstance(value, uuid.UUID):
            return str(value)
        elif isinstance(value, str):
            # Validate it's a proper UUID string
            try:
                uuid.UUID(value)
                return value
            except ValueError:
                raise ValueError(f"Invalid UUID string from database: {value}")
        else:
            raise ValueError(f"Unexpected type from database: {type(value)}")


class JSONType(TypeDecorator[Union[Dict[str, Any], List[Any]]]):
    """
    Platform-independent JSON type.

    Uses PostgreSQL's JSON type if available, otherwise uses Text with
    JSON serialization/deserialization for SQLite and other databases.
    """

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        """Load the appropriate dialect implementation."""
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PostgreSQLJSON(astext_type=Text()))
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(
        self, value: Optional[Union[Dict[str, Any], List[Any], str]], dialect: Dialect
    ) -> Optional[Union[Dict[str, Any], List[Any], str]]:
        """Process values going to the database."""
        if value is None:
            return value

        if dialect.name == "postgresql":
            # PostgreSQL handles JSON natively
            return value
        else:
            # SQLite and others need JSON string
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False, cls=CustomJSONEncoder)
            elif isinstance(value, str):
                # Validate it's valid JSON
                try:
                    json.loads(value)
                    return value
                except json.JSONDecodeError:
                    raise ValueError(f"Invalid JSON string: {value}")

            # For any other type, try to serialize it
            return json.dumps(value, ensure_ascii=False, cls=CustomJSONEncoder)  # type: ignore[unreachable]

    def process_result_value(
        self, value: Optional[Union[str, Dict[str, Any], List[Any]]], dialect: Dialect
    ) -> Optional[Union[Dict[str, Any], List[Any]]]:
        """Process values coming from the database."""
        if value is None:
            return value

        # Both PostgreSQL and SQLite can return JSON strings that need parsing
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                # Ensure it's dict or list
                if isinstance(parsed, (dict, list)):
                    return parsed
                else:
                    raise ValueError(f"Expected dict or list from JSON, got {type(parsed)}")
            except json.JSONDecodeError:
                # If it's not valid JSON, raise an error as we expect valid JSON
                raise ValueError(f"Invalid JSON in database: {value}")

        # PostgreSQL might also return native dict/list objects
        if isinstance(value, (dict, list)):
            return value

        # Unexpected type
        raise ValueError(f"Unexpected type from database: {type(value)}")
