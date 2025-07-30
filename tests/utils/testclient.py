"""Custom TestClient wrapper to avoid pytest-httpx conflicts."""

from typing import Any

from starlette.testclient import TestClient as StarletteTestClient


class SafeTestClient(StarletteTestClient):
    """A TestClient that works correctly even with pytest-httpx installed.

    This wrapper ensures that the TestClient initialization works correctly
    by explicitly using the Starlette TestClient implementation.
    """

    def __init__(self, app: Any, **kwargs):
        """Initialize the TestClient with the given FastAPI app."""
        # Explicitly call the Starlette TestClient constructor
        super().__init__(app, **kwargs)
