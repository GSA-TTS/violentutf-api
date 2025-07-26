"""Comprehensive tests for database type decorators covering all edge cases."""

import json
import uuid
from datetime import date, datetime
from decimal import Decimal
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import StatementError

from app.db.types import GUID, JSONType


class TestGUIDType:
    """Test GUID type decorator comprehensively."""

    def test_guid_load_dialect_impl_postgresql(self):
        """Test GUID loads correct implementation for PostgreSQL."""
        guid_type = GUID()
        dialect = postgresql.dialect()

        impl = guid_type.load_dialect_impl(dialect)

        # PostgreSQL should use native UUID type
        assert isinstance(impl, postgresql.UUID)

    def test_guid_load_dialect_impl_sqlite(self):
        """Test GUID loads correct implementation for SQLite."""
        guid_type = GUID()
        dialect = sqlite.dialect()

        impl = guid_type.load_dialect_impl(dialect)

        # SQLite should use String(36)
        assert isinstance(impl, String)
        assert impl.length == 36

    def test_guid_load_dialect_impl_other(self):
        """Test GUID loads correct implementation for other databases."""
        guid_type = GUID()
        # Mock a generic dialect
        dialect = Mock()
        dialect.name = "mysql"

        impl = guid_type.load_dialect_impl(dialect)

        # Other databases should use String(36)
        assert isinstance(impl, String)
        assert impl.length == 36

    def test_guid_process_bind_param_uuid_postgresql(self):
        """Test GUID processes UUID for PostgreSQL."""
        guid_type = GUID()
        dialect = postgresql.dialect()
        test_uuid = uuid.uuid4()

        result = guid_type.process_bind_param(test_uuid, dialect)

        # PostgreSQL should keep UUID object
        assert result == test_uuid
        assert isinstance(result, uuid.UUID)

    def test_guid_process_bind_param_string_postgresql(self):
        """Test GUID processes string UUID for PostgreSQL."""
        guid_type = GUID()
        dialect = postgresql.dialect()
        test_uuid_str = str(uuid.uuid4())

        result = guid_type.process_bind_param(test_uuid_str, dialect)

        # Should convert string to UUID object
        assert isinstance(result, uuid.UUID)
        assert str(result) == test_uuid_str

    def test_guid_process_bind_param_invalid_postgresql(self):
        """Test GUID with invalid UUID string for PostgreSQL."""
        guid_type = GUID()
        dialect = postgresql.dialect()

        # Should raise ValueError for invalid UUID
        with pytest.raises(ValueError):
            guid_type.process_bind_param("invalid-uuid", dialect)

    def test_guid_process_bind_param_sqlite(self):
        """Test GUID processes value for SQLite."""
        guid_type = GUID()
        dialect = sqlite.dialect()
        test_uuid = uuid.uuid4()

        result = guid_type.process_bind_param(test_uuid, dialect)

        # SQLite should convert to string
        assert isinstance(result, str)
        assert result == str(test_uuid)

    def test_guid_process_bind_param_none(self):
        """Test GUID handles None value."""
        guid_type = GUID()
        dialect = postgresql.dialect()

        result = guid_type.process_bind_param(None, dialect)

        assert result is None

    def test_guid_process_result_value_uuid(self):
        """Test GUID processes UUID result."""
        guid_type = GUID()
        dialect = postgresql.dialect()
        test_uuid = uuid.uuid4()

        result = guid_type.process_result_value(test_uuid, dialect)

        # Should convert to string
        assert isinstance(result, str)
        assert result == str(test_uuid)

    def test_guid_process_result_value_string(self):
        """Test GUID processes string result."""
        guid_type = GUID()
        dialect = sqlite.dialect()
        test_uuid_str = str(uuid.uuid4())

        result = guid_type.process_result_value(test_uuid_str, dialect)

        # Should keep as string
        assert result == test_uuid_str

    def test_guid_process_result_value_none(self):
        """Test GUID handles None result."""
        guid_type = GUID()
        dialect = postgresql.dialect()

        result = guid_type.process_result_value(None, dialect)

        assert result is None

    def test_guid_process_result_value_empty_string(self):
        """Test GUID handles empty string result."""
        guid_type = GUID()
        dialect = sqlite.dialect()

        result = guid_type.process_result_value("", dialect)

        # Empty string should be returned as-is
        assert result == ""

    def test_guid_cache_ok(self):
        """Test GUID type is cacheable."""
        guid_type = GUID()
        assert guid_type.cache_ok is True


class TestJSONType:
    """Test JSONType decorator comprehensively."""

    def test_json_load_dialect_impl_postgresql(self):
        """Test JSON loads correct implementation for PostgreSQL."""
        json_type = JSONType()
        dialect = postgresql.dialect()

        impl = json_type.load_dialect_impl(dialect)

        # PostgreSQL should use native JSON type
        assert isinstance(impl, postgresql.JSON)
        # Check astext_type is Text
        assert isinstance(impl.astext_type, type(Text()))

    def test_json_load_dialect_impl_sqlite(self):
        """Test JSON loads correct implementation for SQLite."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        impl = json_type.load_dialect_impl(dialect)

        # SQLite should use Text
        assert isinstance(impl, Text)

    def test_json_load_dialect_impl_other(self):
        """Test JSON loads correct implementation for other databases."""
        json_type = JSONType()
        # Mock a generic dialect
        dialect = Mock()
        dialect.name = "mysql"

        impl = json_type.load_dialect_impl(dialect)

        # Other databases should use Text
        assert isinstance(impl, Text)

    def test_json_process_bind_param_dict(self):
        """Test JSON processes dictionary."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_dict = {"key": "value", "number": 42}

        result = json_type.process_bind_param(test_dict, dialect)

        # Should serialize to JSON string
        assert isinstance(result, str)
        assert json.loads(result) == test_dict

    def test_json_process_bind_param_list(self):
        """Test JSON processes list."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_list = [1, 2, "three", {"four": 4}]

        result = json_type.process_bind_param(test_list, dialect)

        # Should serialize to JSON string
        assert isinstance(result, str)
        assert json.loads(result) == test_list

    def test_json_process_bind_param_nested(self):
        """Test JSON processes nested structures."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_nested = {"level1": {"level2": {"level3": ["deep", "values"]}}}

        result = json_type.process_bind_param(test_nested, dialect)

        assert isinstance(result, str)
        assert json.loads(result) == test_nested

    def test_json_process_bind_param_none(self):
        """Test JSON handles None value."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_bind_param(None, dialect)

        assert result is None

    def test_json_process_bind_param_empty_dict(self):
        """Test JSON handles empty dictionary."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_bind_param({}, dialect)

        assert result == "{}"

    def test_json_process_bind_param_empty_list(self):
        """Test JSON handles empty list."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_bind_param([], dialect)

        assert result == "[]"

    def test_json_process_bind_param_unicode(self):
        """Test JSON handles Unicode characters."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_unicode = {"emoji": "🚀", "chinese": "你好", "arabic": "مرحبا"}

        result = json_type.process_bind_param(test_unicode, dialect)

        assert isinstance(result, str)
        decoded = json.loads(result)
        assert decoded == test_unicode

    def test_json_process_bind_param_special_chars(self):
        """Test JSON handles special characters."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_special = {"quotes": 'He said "Hello"', "newline": "Line1\nLine2", "tab": "Tab\there"}

        result = json_type.process_bind_param(test_special, dialect)

        assert isinstance(result, str)
        decoded = json.loads(result)
        assert decoded == test_special

    def test_json_process_bind_param_non_serializable(self):
        """Test JSON with non-serializable objects."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        # datetime is not JSON serializable by default
        test_data = {"date": datetime.now()}

        # Should raise TypeError
        with pytest.raises(TypeError):
            json_type.process_bind_param(test_data, dialect)

    def test_json_process_bind_param_circular_reference(self):
        """Test JSON with circular reference."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        # Create circular reference
        test_data = {"key": "value"}
        test_data["self"] = test_data

        # Should raise ValueError
        with pytest.raises(ValueError):
            json_type.process_bind_param(test_data, dialect)

    def test_json_process_result_value_dict_string(self):
        """Test JSON processes dictionary string result."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_json_str = '{"key": "value", "number": 42}'

        result = json_type.process_result_value(test_json_str, dialect)

        # Should deserialize to dict
        assert isinstance(result, dict)
        assert result == {"key": "value", "number": 42}

    def test_json_process_result_value_list_string(self):
        """Test JSON processes list string result."""
        json_type = JSONType()
        dialect = sqlite.dialect()
        test_json_str = '[1, 2, "three"]'

        result = json_type.process_result_value(test_json_str, dialect)

        # Should deserialize to list
        assert isinstance(result, list)
        assert result == [1, 2, "three"]

    def test_json_process_result_value_postgresql_dict(self):
        """Test JSON processes PostgreSQL dict result."""
        json_type = JSONType()
        dialect = postgresql.dialect()
        # PostgreSQL might return dict directly
        test_dict = {"key": "value"}

        result = json_type.process_result_value(test_dict, dialect)

        # Should return as-is
        assert result == test_dict

    def test_json_process_result_value_none(self):
        """Test JSON handles None result."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_result_value(None, dialect)

        assert result is None

    def test_json_process_result_value_empty_string(self):
        """Test JSON handles empty string result."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_result_value("", dialect)

        # Empty string is not valid JSON, should return as-is
        assert result == ""

    def test_json_process_result_value_invalid_json(self):
        """Test JSON handles invalid JSON string."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        # Invalid JSON should raise error
        with pytest.raises(json.JSONDecodeError):
            json_type.process_result_value("invalid json", dialect)

    def test_json_process_result_value_whitespace_only(self):
        """Test JSON handles whitespace-only string."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        result = json_type.process_result_value("   ", dialect)

        # Whitespace-only should return as-is
        assert result == "   "

    def test_json_process_result_value_numbers(self):
        """Test JSON handles numeric values."""
        json_type = JSONType()
        dialect = sqlite.dialect()

        # Test integer
        result = json_type.process_result_value("42", dialect)
        assert result == 42

        # Test float
        result = json_type.process_result_value("3.14", dialect)
        assert result == 3.14

        # Test boolean
        result = json_type.process_result_value("true", dialect)
        assert result is True

        result = json_type.process_result_value("false", dialect)
        assert result is False

        # Test null
        result = json_type.process_result_value("null", dialect)
        assert result is None

    def test_json_cache_ok(self):
        """Test JSON type is cacheable."""
        json_type = JSONType()
        assert json_type.cache_ok is True


class TestTypesIntegration:
    """Integration tests for types with real database operations."""

    def test_guid_roundtrip_sqlite(self):
        """Test GUID roundtrip with SQLite."""
        # Create in-memory SQLite database
        engine = create_engine("sqlite:///:memory:")
        metadata = MetaData()

        # Create table with GUID column
        test_table = Table("test_guid", metadata, Column("id", GUID, primary_key=True), Column("name", String(50)))

        metadata.create_all(engine)

        # Test UUID storage and retrieval
        test_uuid = uuid.uuid4()

        with engine.begin() as conn:
            # Insert
            conn.execute(test_table.insert().values(id=test_uuid, name="Test"))

            # Select
            result = conn.execute(select(test_table).where(test_table.c.id == str(test_uuid))).first()

            # Should retrieve as string
            assert result.id == str(test_uuid)
            assert result.name == "Test"

    def test_json_roundtrip_sqlite(self):
        """Test JSON roundtrip with SQLite."""
        # Create in-memory SQLite database
        engine = create_engine("sqlite:///:memory:")
        metadata = MetaData()

        # Create table with JSON column
        test_table = Table("test_json", metadata, Column("id", String(36), primary_key=True), Column("data", JSONType))

        metadata.create_all(engine)

        # Test JSON storage and retrieval
        test_data = {
            "string": "value",
            "number": 42,
            "float": 3.14,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3],
            "nested": {"inner": "value"},
        }

        with engine.begin() as conn:
            # Insert
            conn.execute(test_table.insert().values(id=str(uuid.uuid4()), data=test_data))

            # Select
            result = conn.execute(select(test_table)).first()

            # Should retrieve as dict
            assert isinstance(result.data, dict)
            assert result.data == test_data

    def test_json_null_roundtrip_sqlite(self):
        """Test JSON NULL roundtrip with SQLite."""
        engine = create_engine("sqlite:///:memory:")
        metadata = MetaData()

        test_table = Table(
            "test_json_null",
            metadata,
            Column("id", String(36), primary_key=True),
            Column("data", JSONType, nullable=True),
        )

        metadata.create_all(engine)

        with engine.begin() as conn:
            # Insert NULL
            conn.execute(test_table.insert().values(id=str(uuid.uuid4()), data=None))

            # Select
            result = conn.execute(select(test_table)).first()

            # Should retrieve as None
            assert result.data is None
