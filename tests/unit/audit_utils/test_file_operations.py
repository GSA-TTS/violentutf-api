"""Tests for audit_utils.file_operations module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from audit_utils.file_operations import (
    atomic_file_operation,
    safe_read_json,
    safe_write_json,
    validate_file_path,
)


class TestFileOperations:
    """Test cases for file operation utilities."""

    def test_safe_read_json_valid_file(self):
        """Test reading valid JSON file."""
        test_data = {"key": "value", "number": 42}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_data, f)
            temp_path = Path(f.name)

        try:
            result = safe_read_json(temp_path)
            assert result == test_data
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_read_json_file_not_found(self):
        """Test reading non-existent JSON file raises FileNotFoundError."""
        non_existent_path = Path(tempfile.gettempdir()) / "non_existent_file.json"

        with pytest.raises(FileNotFoundError):
            safe_read_json(non_existent_path)

    def test_safe_read_json_invalid_json(self):
        """Test reading invalid JSON raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ invalid json content")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                safe_read_json(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_read_json_empty_file(self):
        """Test reading empty JSON file raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = Path(f.name)  # Empty file

        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                safe_read_json(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_write_json_valid_data(self):
        """Test writing valid data to JSON file."""
        test_data = {"key": "value", "list": [1, 2, 3], "nested": {"a": "b"}}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = Path(f.name)

        try:
            safe_write_json(temp_path, test_data)

            # Verify the file was written correctly
            with open(temp_path, "r") as f:
                written_data = json.load(f)
            assert written_data == test_data
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_write_json_creates_directories(self):
        """Test that safe_write_json creates parent directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = Path(temp_dir) / "subdir" / "data.json"
            test_data = {"created": "nested"}

            safe_write_json(nested_path, test_data)

            assert nested_path.exists()
            assert nested_path.parent.exists()

            with open(nested_path, "r") as f:
                written_data = json.load(f)
            assert written_data == test_data

    def test_safe_write_json_unserializable_data(self):
        """Test writing unserializable data raises TypeError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Use a set which is not JSON serializable
            unserializable_data = {"key": {1, 2, 3}}

            with pytest.raises(TypeError, match="not JSON serializable"):
                safe_write_json(temp_path, unserializable_data)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_write_json_permission_denied(self):
        """Test writing to read-only directory raises PermissionError."""
        # Create a read-only directory
        with tempfile.TemporaryDirectory() as temp_dir:
            readonly_dir = Path(temp_dir) / "readonly"
            readonly_dir.mkdir()
            readonly_dir.chmod(0o444)  # Read-only

            readonly_file = readonly_dir / "data.json"

            with pytest.raises(PermissionError):
                safe_write_json(readonly_file, {"test": "data"})

    def test_validate_file_path_allowed_directory(self):
        """Test path validation with allowed directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            allowed_dirs = [Path(temp_dir)]
            test_path = Path(temp_dir) / "subdir" / "file.json"

            assert validate_file_path(test_path, allowed_dirs) is True

    def test_validate_file_path_disallowed_directory(self):
        """Test path validation rejects paths outside allowed directories."""
        allowed_dirs = [Path("/allowed/dir")]
        disallowed_path = Path(tempfile.gettempdir()) / "malicious" / "file.json"

        assert validate_file_path(disallowed_path, allowed_dirs) is False

    def test_validate_file_path_parent_traversal_attack(self):
        """Test path validation prevents parent directory traversal."""
        with tempfile.TemporaryDirectory() as temp_dir:
            allowed_dirs = [Path(temp_dir) / "allowed"]
            allowed_dirs[0].mkdir()

            # Try to escape allowed directory using ../
            malicious_path = allowed_dirs[0] / ".." / "malicious.json"

            assert validate_file_path(malicious_path, allowed_dirs) is False

    def test_validate_file_path_symlink_attack(self):
        """Test path validation handles symlink attacks."""
        with tempfile.TemporaryDirectory() as temp_dir:
            allowed_dir = Path(temp_dir) / "allowed"
            allowed_dir.mkdir()

            # Create symlink pointing outside allowed directory
            symlink_path = allowed_dir / "symlink.json"
            target_path = Path(temp_dir) / "outside.json"
            target_path.touch()
            symlink_path.symlink_to(target_path)

            assert validate_file_path(symlink_path, [allowed_dir]) is False

    def test_validate_file_path_empty_allowed_dirs(self):
        """Test path validation with empty allowed directories list."""
        test_path = Path("/any/path.json")

        assert validate_file_path(test_path, []) is False

    def test_atomic_file_operation_success(self):
        """Test successful atomic file operation."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:

            def write_operation(path):
                with open(path, "w") as f:
                    f.write("test content")
                return "operation successful"

            result = atomic_file_operation(temp_path, write_operation)

            assert result == "operation successful"
            assert temp_path.read_text() == "test content"
        finally:
            temp_path.unlink(missing_ok=True)

    def test_atomic_file_operation_failure_rollback(self):
        """Test that atomic operation rolls back on failure."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("original content")
            temp_path = Path(f.name)

        try:

            def failing_operation(path):
                with open(path, "w") as f:
                    f.write("partial write")
                raise ValueError("Operation failed")

            with pytest.raises(ValueError, match="Operation failed"):
                atomic_file_operation(temp_path, failing_operation)

            # Original content should be restored
            assert temp_path.read_text() == "original content"
        finally:
            temp_path.unlink(missing_ok=True)

    def test_atomic_file_operation_new_file_failure(self):
        """Test atomic operation with new file that fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            new_file_path = Path(temp_dir) / "new_file.txt"

            def failing_operation(path):
                with open(path, "w") as f:
                    f.write("partial content")
                raise RuntimeError("Failed operation")

            with pytest.raises(RuntimeError, match="Failed operation"):
                atomic_file_operation(new_file_path, failing_operation)

            # File should not exist after failed operation
            assert not new_file_path.exists()

    def test_atomic_file_operation_preserves_permissions(self):
        """Test that atomic operation preserves file permissions."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Set specific permissions
            temp_path.chmod(0o600)
            original_stat = temp_path.stat()

            def simple_operation(path):
                with open(path, "a") as f:
                    f.write(" appended")

            atomic_file_operation(temp_path, simple_operation)

            # Permissions should be preserved
            new_stat = temp_path.stat()
            assert new_stat.st_mode == original_stat.st_mode
        finally:
            temp_path.unlink(missing_ok=True)

    def test_file_operations_integration(self):
        """Test integration between different file operations."""
        test_data = {"integration": "test", "data": [1, 2, 3]}

        with tempfile.TemporaryDirectory() as temp_dir:
            allowed_dirs = [Path(temp_dir)]
            file_path = Path(temp_dir) / "integration_test.json"

            # Validate path
            assert validate_file_path(file_path, allowed_dirs) is True

            # Write data atomically
            def write_json_operation(path):
                safe_write_json(path, test_data)

            atomic_file_operation(file_path, write_json_operation)

            # Read data back
            read_data = safe_read_json(file_path)
            assert read_data == test_data

    def test_safe_operations_with_large_files(self):
        """Test safe operations with larger JSON files."""
        # Create large test data
        large_data = {
            "users": [{"id": i, "name": f"user_{i}"} for i in range(1000)],
            "metadata": {"count": 1000, "version": "1.0"},
        }

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = Path(f.name)

        try:
            safe_write_json(temp_path, large_data)
            read_data = safe_read_json(temp_path)

            assert read_data == large_data
            assert len(read_data["users"]) == 1000
        finally:
            temp_path.unlink(missing_ok=True)
