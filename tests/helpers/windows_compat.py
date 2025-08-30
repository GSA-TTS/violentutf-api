"""Windows compatibility utilities for tests."""

import gc
import os
import platform
import time
from pathlib import Path
from typing import Any, Callable, Dict, Union


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system() == "Windows"


def safe_file_remove(file_path: Union[str, Path], max_retries: int = 5, delay: float = 0.1) -> bool:
    """
    Safely remove file with retries for Windows file locking issues.

    Args:
        file_path: Path to file to remove
        max_retries: Maximum number of retry attempts
        delay: Delay between retries in seconds

    Returns:
        True if file was removed or didn't exist, False if failed
    """
    file_path = Path(file_path)

    if not file_path.exists():
        return True

    if not is_windows():
        # On non-Windows systems, just remove normally
        try:
            file_path.unlink()
            return True
        except OSError:
            return False

    # Windows-specific handling with retries
    for attempt in range(max_retries):
        try:
            # Force garbage collection to close any lingering handles
            gc.collect()

            # Try to remove the file
            file_path.unlink()
            return True

        except PermissionError:
            if attempt < max_retries - 1:
                time.sleep(delay * (2**attempt))  # Exponential backoff
                continue
            else:
                print(f"Warning: Could not remove {file_path} after {max_retries} attempts")
                return False
        except FileNotFoundError:
            # File was already removed
            return True
        except Exception as e:
            print(f"Warning: Unexpected error removing {file_path}: {e}")
            return False

    return False


def force_close_sqlite_connections():
    """Force close any lingering SQLite connections (Windows specific)."""
    if not is_windows():
        return

    # Force garbage collection multiple times
    for _ in range(3):
        gc.collect()

    # Small delay to allow OS to release handles
    time.sleep(0.05)


def safe_dict_items(obj: Any) -> list:
    """
    Safely get items from dict-like object or return empty list.

    Handles the Windows-specific AttributeError where function objects
    don't have .items() method.
    """
    if hasattr(obj, "items") and callable(obj.items):
        try:
            return list(obj.items())
        except (AttributeError, TypeError):
            pass

    # If obj is a function or other non-dict object, return empty list
    if callable(obj):
        return []

    # Try to convert to dict first
    try:
        if isinstance(obj, dict):
            return list(obj.items())
        else:
            # Try common dict-like interfaces
            return list(dict(obj).items())
    except (TypeError, ValueError, AttributeError):
        return []


def safe_dict_access(obj: Any, default: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Safely access dict-like object, returning default if not accessible.

    Args:
        obj: Object to access as dict
        default: Default value to return if obj is not dict-like

    Returns:
        Dictionary or default value
    """
    if default is None:
        default = {}

    if isinstance(obj, dict):
        return obj

    if callable(obj):
        # Object is a function, return default
        return default

    try:
        # Try to convert to dict
        return dict(obj)
    except (TypeError, ValueError, AttributeError):
        return default


def get_test_db_path() -> str:
    """Get platform-appropriate test database path."""
    import tempfile
    import uuid

    if is_windows():
        # Use temp directory on Windows with unique filename per test session
        temp_dir = tempfile.gettempdir()
        unique_id = str(uuid.uuid4()).replace("-", "")[:8]
        return f"sqlite+aiosqlite:///{temp_dir}/test_violentutf_{os.getpid()}_{unique_id}.db"
    else:
        # Use current directory with unique filename for non-Windows
        unique_id = str(uuid.uuid4()).replace("-", "")[:8]
        return f"sqlite+aiosqlite:///./test_violentutf_{os.getpid()}_{unique_id}.db"


def cleanup_test_db_file(db_url: str) -> bool:
    """Clean up test database file from URL."""
    if "sqlite" not in db_url.lower():
        return True

    # Extract file path from SQLite URL
    if ":///" in db_url:
        file_path = db_url.split(":///")[1]
    else:
        return True

    return safe_file_remove(file_path)


# Monkey patch for common Windows test issues
def patch_windows_compatibility():
    """Apply Windows compatibility patches."""
    if not is_windows():
        return

    # Could add more patches here as needed
    pass
