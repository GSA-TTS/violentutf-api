"""Integration tests for custom type decorators with edge cases."""

import json
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict

import pytest
import pytest_asyncio
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from app.db.types import GUID, JSONType

Base = declarative_base()


class TypeTestModel(Base):
    """Test model for type decorator testing."""

    __tablename__ = "test_type_model"

    id = Column(Integer, primary_key=True)
    guid_field = Column(GUID, nullable=True)
    json_field = Column(JSONType, nullable=True)


class TestGUIDType:
    """Test GUID type decorator with various scenarios."""

    @pytest.fixture
    def sync_engine(self):
        """Create synchronous engine for testing dialect-specific behavior."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return engine

    @pytest.fixture
    def sync_session(self, sync_engine):
        """Create synchronous session."""
        Session = sessionmaker(bind=sync_engine)
        session = Session()
        yield session
        session.close()

    @pytest_asyncio.fixture
    async def async_engine(self):
        """Create async engine for testing."""
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
        await engine.dispose()

    @pytest_asyncio.fixture
    async def async_session(self, async_engine):
        """Create async session."""
        async with AsyncSession(async_engine) as session:
            yield session

    def test_guid_load_dialect_impl_postgresql(self):
        """Test GUID loads UUID type for PostgreSQL."""
        guid_type = GUID()
        pg_dialect = postgresql.dialect()

        impl = guid_type.load_dialect_impl(pg_dialect)
        assert isinstance(impl, postgresql.UUID)

    def test_guid_load_dialect_impl_sqlite(self):
        """Test GUID loads String type for SQLite."""
        guid_type = GUID()
        sqlite_dialect = sqlite.dialect()

        impl = guid_type.load_dialect_impl(sqlite_dialect)
        assert impl.length == 36

    def test_guid_process_bind_param_with_uuid(self):
        """Test processing UUID object for binding."""
        guid_type = GUID()
        test_uuid = uuid.uuid4()

        # For PostgreSQL (expects UUID)
        pg_dialect = postgresql.dialect()
        result = guid_type.process_bind_param(test_uuid, pg_dialect)
        assert result == test_uuid

        # For SQLite (expects string)
        sqlite_dialect = sqlite.dialect()
        result = guid_type.process_bind_param(test_uuid, sqlite_dialect)
        assert result == str(test_uuid)

    def test_guid_process_bind_param_with_string(self):
        """Test processing string UUID for binding."""
        guid_type = GUID()
        test_uuid_str = str(uuid.uuid4())

        # For PostgreSQL
        pg_dialect = postgresql.dialect()
        result = guid_type.process_bind_param(test_uuid_str, pg_dialect)
        assert isinstance(result, uuid.UUID)
        assert str(result) == test_uuid_str

        # For SQLite
        sqlite_dialect = sqlite.dialect()
        result = guid_type.process_bind_param(test_uuid_str, sqlite_dialect)
        assert result == test_uuid_str

    def test_guid_process_bind_param_with_none(self):
        """Test processing None value."""
        guid_type = GUID()

        # Both dialects should return None
        pg_dialect = postgresql.dialect()
        assert guid_type.process_bind_param(None, pg_dialect) is None

        sqlite_dialect = sqlite.dialect()
        assert guid_type.process_bind_param(None, sqlite_dialect) is None

    def test_guid_process_bind_param_invalid_string(self):
        """Test processing invalid UUID string."""
        guid_type = GUID()
        pg_dialect = postgresql.dialect()

        # Should raise ValueError for invalid UUID
        with pytest.raises(ValueError):
            guid_type.process_bind_param("invalid-uuid", pg_dialect)

    def test_guid_process_result_value_with_uuid(self):
        """Test processing UUID from database."""
        guid_type = GUID()
        test_uuid = uuid.uuid4()

        # Any dialect should convert to string
        result = guid_type.process_result_value(test_uuid, None)
        assert result == str(test_uuid)

    def test_guid_process_result_value_with_string(self):
        """Test processing string UUID from database."""
        guid_type = GUID()
        test_uuid_str = str(uuid.uuid4())

        result = guid_type.process_result_value(test_uuid_str, None)
        assert result == test_uuid_str

    def test_guid_process_result_value_with_none(self):
        """Test processing None from database."""
        guid_type = GUID()
        assert guid_type.process_result_value(None, None) is None

    @pytest.mark.asyncio
    async def test_guid_roundtrip_async(self, async_session: AsyncSession):
        """Test GUID roundtrip with async session."""
        test_uuid = uuid.uuid4()

        # Insert
        model = TypeTestModel(guid_field=test_uuid)
        async_session.add(model)
        await async_session.flush()  # Get the ID without closing session
        model_id = model.id  # Store ID while session is active
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id == model_id))
        loaded = result.scalar_one()

        # Should be string after roundtrip
        assert loaded.guid_field == str(test_uuid)

    def test_guid_roundtrip_sync(self, sync_session: Session):
        """Test GUID roundtrip with sync session."""
        test_uuid = uuid.uuid4()

        # Insert
        model = TypeTestModel(guid_field=test_uuid)
        sync_session.add(model)
        sync_session.commit()

        # Query
        loaded = sync_session.query(TypeTestModel).filter_by(id=model.id).first()

        # Should be string after roundtrip
        assert loaded.guid_field == str(test_uuid)


class TestJSONType:
    """Test JSON type decorator with various scenarios."""

    @pytest.fixture
    def sync_engine(self):
        """Create synchronous engine for testing."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return engine

    @pytest.fixture
    def sync_session(self, sync_engine):
        """Create synchronous session."""
        Session = sessionmaker(bind=sync_engine)
        session = Session()
        yield session
        session.close()

    @pytest_asyncio.fixture
    async def async_engine(self):
        """Create async engine for testing."""
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
        await engine.dispose()

    @pytest_asyncio.fixture
    async def async_session(self, async_engine):
        """Create async session."""
        async with AsyncSession(async_engine) as session:
            yield session

    def test_json_load_dialect_impl_postgresql(self):
        """Test JSON loads native JSON type for PostgreSQL."""
        json_type = JSONType()
        pg_dialect = postgresql.dialect()

        impl = json_type.load_dialect_impl(pg_dialect)
        assert isinstance(impl, postgresql.JSON)

    def test_json_load_dialect_impl_sqlite(self):
        """Test JSON loads Text type for SQLite."""
        json_type = JSONType()
        sqlite_dialect = sqlite.dialect()

        impl = json_type.load_dialect_impl(sqlite_dialect)
        # Should be Text type

    def test_json_process_bind_param_with_dict(self):
        """Test processing dictionary for binding."""
        json_type = JSONType()
        test_dict = {"key": "value", "number": 42, "nested": {"inner": True}}

        # For PostgreSQL (supports native JSON)
        pg_dialect = postgresql.dialect()
        result = json_type.process_bind_param(test_dict, pg_dialect)
        assert result == test_dict  # Should pass through

        # For SQLite (needs string)
        sqlite_dialect = sqlite.dialect()
        result = json_type.process_bind_param(test_dict, sqlite_dialect)
        assert json.loads(result) == test_dict
        assert isinstance(result, str)

    def test_json_process_bind_param_with_list(self):
        """Test processing list for binding."""
        json_type = JSONType()
        test_list = [1, 2, "three", {"four": 4}]

        # For SQLite
        sqlite_dialect = sqlite.dialect()
        result = json_type.process_bind_param(test_list, sqlite_dialect)
        assert result == json.dumps(test_list)

    def test_json_process_bind_param_with_none(self):
        """Test processing None value."""
        json_type = JSONType()

        # Both dialects should return None
        pg_dialect = postgresql.dialect()
        assert json_type.process_bind_param(None, pg_dialect) is None

        sqlite_dialect = sqlite.dialect()
        assert json_type.process_bind_param(None, sqlite_dialect) is None

    def test_json_process_bind_param_with_complex_types(self):
        """Test processing complex types that need custom serialization."""
        json_type = JSONType()

        # UUID in dict
        test_data = {"id": uuid.uuid4(), "created": datetime.now(), "amount": Decimal("123.45")}

        sqlite_dialect = sqlite.dialect()
        result = json_type.process_bind_param(test_data, sqlite_dialect)

        # Should serialize without error (using default str conversion)
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "id" in parsed
        assert "created" in parsed
        assert "amount" in parsed

    def test_json_process_result_value_with_string(self):
        """Test processing JSON string from database."""
        json_type = JSONType()
        test_data = {"key": "value", "list": [1, 2, 3]}
        json_str = json.dumps(test_data)

        # For PostgreSQL
        pg_dialect = postgresql.dialect()
        result = json_type.process_result_value(json_str, pg_dialect)
        assert result == test_data

        # For SQLite
        sqlite_dialect = sqlite.dialect()
        result = json_type.process_result_value(json_str, sqlite_dialect)
        assert result == test_data

    def test_json_process_result_value_with_dict(self):
        """Test processing native dict from database (PostgreSQL)."""
        json_type = JSONType()
        test_dict = {"native": "dict", "from": "postgresql"}

        # PostgreSQL might return dict directly
        pg_dialect = postgresql.dialect()
        result = json_type.process_result_value(test_dict, pg_dialect)
        assert result == test_dict

    def test_json_process_result_value_with_none(self):
        """Test processing None from database."""
        json_type = JSONType()
        assert json_type.process_result_value(None, None) is None

    def test_json_process_result_value_with_invalid_json(self):
        """Test processing invalid JSON string."""
        json_type = JSONType()

        # Should handle gracefully (implementation might vary)
        sqlite_dialect = sqlite.dialect()

        # Invalid JSON should raise error or return as-is
        try:
            result = json_type.process_result_value("invalid json", sqlite_dialect)
            # If no error, should return the invalid string
            assert result == "invalid json"
        except json.JSONDecodeError:
            # This is also acceptable behavior
            pass

    @pytest.mark.asyncio
    async def test_json_roundtrip_dict_async(self, async_session: AsyncSession):
        """Test JSON dict roundtrip with async session."""
        test_data = {
            "name": "Test",
            "active": True,
            "count": 42,
            "tags": ["a", "b", "c"],
            "metadata": {"nested": {"deep": "value"}},
        }

        # Insert
        model = TypeTestModel(json_field=test_data)
        async_session.add(model)
        await async_session.flush()  # Get the ID without closing session
        model_id = model.id  # Store ID while session is active
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id == model_id))
        loaded = result.scalar_one()

        # Should preserve structure
        assert loaded.json_field == test_data
        assert loaded.json_field["metadata"]["nested"]["deep"] == "value"

    @pytest.mark.asyncio
    async def test_json_roundtrip_list_async(self, async_session: AsyncSession):
        """Test JSON list roundtrip with async session."""
        test_data = [1, "two", {"three": 3}, [4, 5, 6]]

        # Insert
        model = TypeTestModel(json_field=test_data)
        async_session.add(model)
        await async_session.flush()  # Get the ID without closing session
        model_id = model.id  # Store ID while session is active
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id == model_id))
        loaded = result.scalar_one()

        # Should preserve structure
        assert loaded.json_field == test_data

    def test_json_roundtrip_sync(self, sync_session: Session):
        """Test JSON roundtrip with sync session."""
        test_data = {"sync": True, "data": [1, 2, 3], "nested": {"key": "value"}}

        # Insert
        model = TypeTestModel(json_field=test_data)
        sync_session.add(model)
        sync_session.commit()

        # Query
        loaded = sync_session.query(TypeTestModel).filter_by(id=model.id).first()

        # Should preserve structure
        assert loaded.json_field == test_data

    @pytest.mark.asyncio
    async def test_json_with_empty_structures(self, async_session: AsyncSession):
        """Test JSON with empty dict and list."""
        # Empty dict
        model1 = TypeTestModel(json_field={})
        async_session.add(model1)

        # Empty list
        model2 = TypeTestModel(json_field=[])
        async_session.add(model2)

        await async_session.flush()  # Get the IDs without closing session
        model1_id = model1.id  # Store IDs while session is active
        model2_id = model2.id
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id.in_([model1_id, model2_id])))
        models = result.scalars().all()

        json_fields = [m.json_field for m in models]
        assert {} in json_fields
        assert [] in json_fields

    @pytest.mark.asyncio
    async def test_json_with_unicode(self, async_session: AsyncSession):
        """Test JSON with Unicode characters."""
        test_data = {"english": "Hello", "chinese": "你好", "emoji": "😀🎉", "special": "café", "symbols": "♠♣♥♦"}

        # Insert
        model = TypeTestModel(json_field=test_data)
        async_session.add(model)
        await async_session.flush()  # Get the ID without closing session
        model_id = model.id  # Store ID while session is active
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id == model_id))
        loaded = result.scalar_one()

        # Unicode should be preserved
        assert loaded.json_field == test_data
        assert loaded.json_field["emoji"] == "😀🎉"

    @pytest.mark.asyncio
    async def test_json_with_large_data(self, async_session: AsyncSession):
        """Test JSON with large data structure."""
        # Create large nested structure
        test_data = {
            f"key_{i}": {"data": list(range(100)), "nested": {f"inner_{j}": f"value_{j}" for j in range(10)}}
            for i in range(10)
        }

        # Insert
        model = TypeTestModel(json_field=test_data)
        async_session.add(model)
        await async_session.flush()  # Get the ID without closing session
        model_id = model.id  # Store ID while session is active
        await async_session.commit()

        # Query
        result = await async_session.execute(select(TypeTestModel).where(TypeTestModel.id == model_id))
        loaded = result.scalar_one()

        # Should handle large data
        assert loaded.json_field == test_data
        assert len(loaded.json_field) == 10

    def test_json_with_circular_reference(self):
        """Test JSON with circular reference."""
        json_type = JSONType()
        sqlite_dialect = sqlite.dialect()

        # Create circular reference
        obj1: Dict[str, Any] = {"name": "obj1"}
        obj2: Dict[str, Any] = {"name": "obj2", "ref": obj1}
        obj1["ref"] = obj2  # Circular reference

        # Should raise error on serialization
        with pytest.raises((ValueError, TypeError)):
            json_type.process_bind_param(obj1, sqlite_dialect)
