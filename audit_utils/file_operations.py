"""Shared file operation utilities for audit automation scripts."""

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List

import structlog

logger = structlog.get_logger(__name__)


def safe_read_json(path: Path) -> Dict[str, Any]:
    """Safely read and validate JSON file with error handling.

    Args:
        path: Path to JSON file to read

    Returns:
        Parsed JSON data as dictionary

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file contains invalid JSON
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                raise ValueError("Invalid JSON: file is empty")

            return json.loads(content)  # type: ignore
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {path}: {str(e)}") from e
    except Exception as e:
        logger.error(f"Error reading JSON file {path}: {e}")
        raise


def safe_write_json(path: Path, data: Dict[str, Any]) -> None:
    """Safely write JSON data to file with atomic operations.

    Args:
        path: Path where to write JSON file
        data: Data to write as JSON

    Raises:
        TypeError: If data is not JSON serializable
        PermissionError: If cannot write to file location
    """
    # Ensure parent directories exist
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Validate JSON serializability
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Data is not JSON serializable: {str(e)}") from e

    # Write atomically using temporary file
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False, encoding="utf-8"
        ) as f:
            f.write(json_content)
            f.flush()
            temp_file = Path(f.name)

        # Preserve file permissions if original file exists
        if path.exists():
            original_stat = path.stat()
            temp_file.chmod(original_stat.st_mode)

        # Atomic move
        temp_file.replace(path)
        temp_file = None  # Successfully moved

    except Exception as e:
        # Cleanup temporary file if it exists
        if temp_file and temp_file.exists():
            temp_file.unlink(missing_ok=True)
        logger.error(f"Error writing JSON file {path}: {e}")
        raise


def validate_file_path(path: Path, allowed_dirs: List[Path]) -> bool:
    """Validate file path for security (prevent directory traversal attacks).

    Args:
        path: File path to validate
        allowed_dirs: List of allowed parent directories

    Returns:
        True if path is safe and allowed, False otherwise
    """
    if not allowed_dirs:
        return False

    try:
        # Resolve path to handle symlinks and relative paths
        resolved_path = path.resolve()

        # Check if path is within any allowed directory
        for allowed_dir in allowed_dirs:
            allowed_resolved = allowed_dir.resolve()
            try:
                # This will raise ValueError if resolved_path is not relative to allowed_resolved
                resolved_path.relative_to(allowed_resolved)
                return True
            except ValueError:
                continue

        return False

    except (OSError, RuntimeError):
        # Path resolution failed (e.g., too many symlinks)
        return False


def atomic_file_operation(path: Path, operation: Callable[[Path], Any]) -> Any:
    """Perform atomic file operation with backup and rollback.

    Args:
        path: File path to operate on
        operation: Function that performs the file operation

    Returns:
        Result of the operation function

    Raises:
        Exception: Any exception from the operation (with rollback performed)
    """
    backup_path = None

    # Create backup if file exists
    if path.exists():
        backup_path = path.with_suffix(path.suffix + ".backup")
        try:
            shutil.copy2(path, backup_path)
        except Exception as e:
            logger.error(f"Failed to create backup of {path}: {e}")
            raise

    try:
        # Perform the operation
        result = operation(path)

        # Clean up backup on success
        if backup_path and backup_path.exists():
            backup_path.unlink()

        return result

    except Exception as e:
        logger.error(f"Operation failed on {path}: {e}")

        # Rollback: restore from backup
        if backup_path and backup_path.exists():
            try:
                if path.exists():
                    path.unlink()
                shutil.move(backup_path, path)
                logger.info(f"Restored {path} from backup")
            except Exception as restore_error:
                logger.error(f"Failed to restore backup for {path}: {restore_error}")
        else:
            # No backup exists - remove partially created file if operation created it
            if path.exists() and (not backup_path):
                try:
                    path.unlink()
                    logger.info(f"Removed partially created file {path}")
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup {path}: {cleanup_error}")

        raise
