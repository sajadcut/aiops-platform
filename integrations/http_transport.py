from __future__ import annotations

import ssl
import time
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse

import httpx

from domain.contracts.logging import logger


def insecure_ssl_context() -> ssl.SSLContext:
    """Create a TLS context that does not validate server certificates or hostnames."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _safe_destination(client: Any, url: Any) -> dict[str, Any]:
    """Return log-safe destination fields without query strings, credentials or bodies."""
    try:
        value = str(url)
        parsed = urlparse(value)
        if not parsed.scheme and getattr(client, "base_url", None):
            value = str(client.base_url.join(value))
            parsed = urlparse(value)
        return {
            "scheme": parsed.scheme or None,
            "host": parsed.hostname or None,
            "port": parsed.port,
            "path": parsed.path or "/",
        }
    except Exception:
        return {"scheme": None, "host": None, "port": None, "path": None}


def _log_completed(*, component: str, method: str, client: Any, url: Any, response: Any, started: float) -> None:
    logger.info(
        "outbound_http_completed",
        component=component,
        method=str(method).upper(),
        status_code=getattr(response, "status_code", None),
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        **_safe_destination(client, url),
    )


def _log_failed(*, component: str, method: str, client: Any, url: Any, exc: Exception, started: float) -> None:
    logger.warning(
        "outbound_http_failed",
        component=component,
        method=str(method).upper(),
        error_type=type(exc).__name__,
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        **_safe_destination(client, url),
    )


class _TimedAsyncClient:
    """Transparent proxy that records latency for every outbound HTTP request."""

    def __init__(self, client: httpx.AsyncClient, component: str):
        self._client = client
        self._component = str(component or "outbound_http")

    async def __aenter__(self) -> "_TimedAsyncClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> Any:
        return await self._client.__aexit__(exc_type, exc, tb)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _timed(
        self,
        method: str,
        url: Any,
        call: Callable[..., Awaitable[httpx.Response]],
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        started = time.perf_counter()
        try:
            response = await call(url, *args, **kwargs)
        except Exception as exc:
            _log_failed(
                component=self._component,
                method=method,
                client=self._client,
                url=url,
                exc=exc,
                started=started,
            )
            raise
        _log_completed(
            component=self._component,
            method=method,
            client=self._client,
            url=url,
            response=response,
            started=started,
        )
        return response

    async def request(self, method: str, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        started = time.perf_counter()
        try:
            response = await self._client.request(method, url, *args, **kwargs)
        except Exception as exc:
            _log_failed(
                component=self._component,
                method=method,
                client=self._client,
                url=url,
                exc=exc,
                started=started,
            )
            raise
        _log_completed(
            component=self._component,
            method=method,
            client=self._client,
            url=url,
            response=response,
            started=started,
        )
        return response

    async def get(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("GET", url, self._client.get, *args, **kwargs)

    async def post(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("POST", url, self._client.post, *args, **kwargs)

    async def put(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("PUT", url, self._client.put, *args, **kwargs)

    async def patch(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("PATCH", url, self._client.patch, *args, **kwargs)

    async def delete(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("DELETE", url, self._client.delete, *args, **kwargs)

    async def head(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("HEAD", url, self._client.head, *args, **kwargs)

    async def options(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._timed("OPTIONS", url, self._client.options, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _TimedSyncClient:
    """Synchronous equivalent used by operational acceptance tooling."""

    def __init__(self, client: httpx.Client, component: str):
        self._client = client
        self._component = str(component or "outbound_http")

    def __enter__(self) -> "_TimedSyncClient":
        self._client.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> Any:
        return self._client.__exit__(exc_type, exc, tb)

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        started = time.perf_counter()
        try:
            response = self._client.request(method, url, *args, **kwargs)
        except Exception as exc:
            _log_failed(
                component=self._component,
                method=method,
                client=self._client,
                url=url,
                exc=exc,
                started=started,
            )
            raise
        _log_completed(
            component=self._component,
            method=method,
            client=self._client,
            url=url,
            response=response,
            started=started,
        )
        return response

    def _timed(self, method: str, url: Any, call: Callable[..., httpx.Response], *args: Any, **kwargs: Any) -> httpx.Response:
        started = time.perf_counter()
        try:
            response = call(url, *args, **kwargs)
        except Exception as exc:
            _log_failed(
                component=self._component,
                method=method,
                client=self._client,
                url=url,
                exc=exc,
                started=started,
            )
            raise
        _log_completed(
            component=self._component,
            method=method,
            client=self._client,
            url=url,
            response=response,
            started=started,
        )
        return response

    def get(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._timed("GET", url, self._client.get, *args, **kwargs)

    def post(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._timed("POST", url, self._client.post, *args, **kwargs)

    def put(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._timed("PUT", url, self._client.put, *args, **kwargs)

    def patch(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._timed("PATCH", url, self._client.patch, *args, **kwargs)

    def delete(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._timed("DELETE", url, self._client.delete, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def insecure_async_client(*, component: str = "outbound_http", **kwargs: Any) -> Any:
    """Create an instrumented outbound HTTP(S) client with TLS validation disabled."""
    kwargs["verify"] = False
    client = httpx.AsyncClient(**kwargs)  # nosec B501 - explicit project transport policy
    return _TimedAsyncClient(client, component)


def insecure_sync_client(*, component: str = "outbound_http", **kwargs: Any) -> Any:
    """Create an instrumented synchronous outbound HTTP(S) client with TLS validation disabled."""
    kwargs["verify"] = False
    client = httpx.Client(**kwargs)  # nosec B501 - explicit project transport policy
    return _TimedSyncClient(client, component)
