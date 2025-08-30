"""Tests for Windows compatibility utilities."""

import platform
import tempfile
from pathlib import Path

import pytest

from tests.helpers.windows_compat import (
    cleanup_test_db_file,
    force_close_sqlite_connections,
    get_test_db_path,
    is_windows,
    safe_dict_access,
    safe_dict_items,
    safe_file_remove,
)


class TestWindowsCompatibility:
    """Test Windows compatibility utilities."""

    def test_is_windows_detection(self):
        """Test Windows detection works correctly."""
        expected = platform.system() == "Windows"
        assert is_windows() == expected

    def test_get_test_db_path_unique(self):
        """Test that database paths are unique."""
        path1 = get_test_db_path()
        path2 = get_test_db_path()

        assert path1 != path2
        assert "test_violentutf" in path1
        assert "test_violentutf" in path2
        assert path1.startswith("sqlite+aiosqlite:///")
        assert path2.startswith("sqlite+aiosqlite:///")

    def test_safe_file_remove_nonexistent(self):
        """Test safe file removal with nonexistent file."""
        fake_path = Path(tempfile.gettempdir()) / "nonexistent_file.db"
        assert safe_file_remove(fake_path) is True

    def test_safe_file_remove_existing(self):
        """Test safe file removal with existing file."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(b"test content")

        # File should exist
        assert tmp_path.exists()

        # Should be removed successfully
        assert safe_file_remove(tmp_path) is True

        # Should no longer exist
        assert not tmp_path.exists()

    def test_safe_dict_items_with_dict(self):
        """Test safe dict items with actual dict."""
        test_dict = {"key1": "value1", "key2": "value2"}
        items = safe_dict_items(test_dict)

        assert len(items) == 2
        assert ("key1", "value1") in items
        assert ("key2", "value2") in items

    def test_safe_dict_items_with_function(self):
        """Test safe dict items with function (should return empty list)."""

        def test_function():
            return "test"

        items = safe_dict_items(test_function)
        assert items == []

    def test_safe_dict_items_with_none(self):
        """Test safe dict items with None."""
        items = safe_dict_items(None)
        assert items == []

    def test_safe_dict_access_with_dict(self):
        """Test safe dict access with actual dict."""
        test_dict = {"key": "value"}
        result = safe_dict_access(test_dict)

        assert result == test_dict
        assert isinstance(result, dict)

    def test_safe_dict_access_with_function(self):
        """Test safe dict access with function (should return default)."""

        def test_function():
            return "test"

        result = safe_dict_access(test_function)
        assert result == {}

    def test_safe_dict_access_with_custom_default(self):
        """Test safe dict access with custom default."""

        def test_function():
            return "test"

        default = {"default": "value"}
        result = safe_dict_access(test_function, default)
        assert result == default

    def test_cleanup_test_db_file_non_sqlite(self):
        """Test cleanup with non-SQLite URL."""
        result = cleanup_test_db_file("postgresql://user:pass@localhost/db")
        assert result is True

    def test_cleanup_test_db_file_invalid_url(self):
        """Test cleanup with invalid URL format."""
        result = cleanup_test_db_file("invalid-url")
        assert result is True

    def test_cleanup_test_db_file_sqlite_url(self):
        """Test cleanup with SQLite URL."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(b"test data")

        # Create SQLite URL pointing to the temp file
        sqlite_url = f"sqlite+aiosqlite:///{tmp_path}"

        # File should exist
        assert Path(tmp_path).exists()

        # Should be cleaned up
        result = cleanup_test_db_file(sqlite_url)
        assert result is True

        # File should no longer exist
        assert not Path(tmp_path).exists()

    def test_force_close_sqlite_connections(self):
        """Test that force close doesn't raise errors."""
        # This function primarily does garbage collection
        # Just ensure it doesn't raise any exceptions
        force_close_sqlite_connections()
        # No assertion needed - success is no exception

    @pytest.mark.parametrize(
        "obj,expected_items",
        [
            ({"a": 1, "b": 2}, [("a", 1), ("b", 2)]),
            (lambda: "test", []),
            (None, []),
            ([], []),
            ("string", []),
        ],
    )
    def test_safe_dict_items_parametrized(self, obj, expected_items):
        """Parametrized test for safe_dict_items."""
        result = safe_dict_items(obj)
        if expected_items:
            # Sort both lists to handle order differences
            assert sorted(result) == sorted(expected_items)
        else:
            assert result == expected_items
