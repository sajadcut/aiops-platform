from __future__ import annotations

import ssl
from typing import Any

import httpx


def insecure_ssl_context() -> ssl.SSLContext:
    """Create a TLS context that does not validate server certificates or hostnames."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def insecure_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Create an outbound HTTP(S) client with TLS certificate validation disabled."""
    kwargs["verify"] = False
    return httpx.AsyncClient(**kwargs)  # nosec B501 - explicit project transport policy


def insecure_sync_client(**kwargs: Any) -> httpx.Client:
    """Create a synchronous outbound HTTP(S) client with TLS validation disabled."""
    kwargs["verify"] = False
    return httpx.Client(**kwargs)  # nosec B501 - explicit project transport policy
