from __future__ import annotations

from typing import Any

import httpx


def insecure_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Create an outbound HTTP(S) client with TLS certificate validation disabled."""
    kwargs["verify"] = False
    return httpx.AsyncClient(**kwargs)  # nosec B501 - explicit project transport policy


def insecure_sync_client(**kwargs: Any) -> httpx.Client:
    """Create a synchronous outbound HTTP(S) client with TLS validation disabled."""
    kwargs["verify"] = False
    return httpx.Client(**kwargs)  # nosec B501 - explicit project transport policy
