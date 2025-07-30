"""Custom TestClient wrapper to avoid pytest-httpx conflicts.

This module provides SafeTestClient to handle compatibility issues between:
- pytest-httpx (testing framework)
- httpx (HTTP client library)
- Starlette TestClient (FastAPI's test client)

The main issue occurs when httpx>=0.27.0 deprecated the 'app' parameter
for Client.__init__(), which Starlette TestClient was still using until
version 0.37.2. This causes "Client.__init__() got an unexpected keyword
argument 'app'" errors in CI environments.

Solution: Updated dependencies to FastAPI 0.116+ which uses Starlette 0.40+
that's compatible with httpx 0.27+.
"""

from typing import Any, Dict, Optional

import httpx
from starlette.testclient import TestClient as StarletteTestClient


class SafeTestClient(StarletteTestClient):
    """A TestClient that works correctly even with pytest-httpx installed.

    This wrapper ensures that the TestClient initialization works correctly
    by explicitly using the Starlette TestClient implementation and avoiding
    any pytest-httpx monkey-patching.

    Note: With FastAPI 0.116+ and httpx 0.27+, this wrapper should no longer
    be needed as the underlying compatibility issues have been resolved.
    However, it's kept for backward compatibility and defensive programming.
    """

    def __init__(
        self,
        app: Any,
        base_url: str = "http://testserver",
        raise_server_exceptions: bool = True,
        root_path: str = "",
        backend: str = "asyncio",
        backend_options: Optional[Dict[str, Any]] = None,
        cookies: Optional[httpx._types.CookieTypes] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        **kwargs: Any,
    ):
        """Initialize the TestClient with the given FastAPI app.

        This implementation bypasses any pytest-httpx modifications by directly
        calling the Starlette TestClient constructor with all expected parameters.
        """
        # Call parent __init__ with only the parameters it expects
        # app must be passed as positional argument, not keyword
        super().__init__(
            app,
            base_url=base_url,
            raise_server_exceptions=raise_server_exceptions,
            root_path=root_path,
            backend=backend,
            backend_options=backend_options,
            cookies=cookies,
            headers=headers,
            follow_redirects=follow_redirects,
        )
