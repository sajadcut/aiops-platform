from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

import httpx

from domain.contracts.config import settings
from domain.contracts.logging import logger


class CogniaConfigurationError(RuntimeError):
    """Raised when the Cognia integration is selected but not safely configured."""


class CogniaContractError(RuntimeError):
    """Raised when Cognia returns a response that violates the documented contract."""


class CogniaAPIError(RuntimeError):
    """Typed representation of Cognia's application/problem+json error contract."""

    def __init__(
        self,
        status_code: int,
        code: str,
        *,
        trace_id: Optional[str] = None,
    ) -> None:
        self.status_code = int(status_code)
        self.code = str(code or "COGNIA_HTTP_ERROR")
        self.trace_id = str(trace_id) if trace_id else None
        super().__init__(f"cognia_api_error:{self.status_code}:{self.code}")


class CogniaClient:
    """Consumer-side Cognia client using Application Client machine authentication.

    Access tokens are treated as opaque values. They are cached only until their
    documented ``expiresIn`` lifetime and are never decoded as JWTs. Cognia errors
    are propagated as typed errors; this client never falls back to a different
    knowledge source.
    """

    _TRANSIENT_STATUS = {429, 502, 503, 504}

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        tls_verify: Optional[bool] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.base_url = str(base_url or settings.COGNIA_BASE_URL or "").strip().rstrip("/")
        self.client_id = str(client_id or settings.COGNIA_CLIENT_ID or "").strip()
        self.client_secret = str(client_secret or settings.COGNIA_CLIENT_SECRET or "").strip()
        self.timeout_seconds = float(timeout_seconds or settings.COGNIA_TIMEOUT_SECONDS)
        self.tls_verify = settings.COGNIA_TLS_VERIFY if tls_verify is None else bool(tls_verify)
        if not self.base_url:
            raise CogniaConfigurationError("cognia_base_url_required")
        if self.timeout_seconds <= 0:
            raise CogniaConfigurationError("cognia_timeout_must_be_positive")

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.tls_verify,
            transport=transport,
            headers={"Accept": "application/json"},
        )
        self._token: Optional[str] = None
        self._token_valid_until = 0.0
        self._token_lock = asyncio.Lock()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "CogniaClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    @staticmethod
    def _problem_from_response(response: httpx.Response) -> CogniaAPIError:
        code = "COGNIA_HTTP_ERROR"
        trace_id: Optional[str] = None
        try:
            payload = response.json()
            if isinstance(payload, dict):
                code = str(payload.get("code") or code)
                trace_id = payload.get("traceId") or payload.get("trace_id")
        except (ValueError, TypeError):
            pass
        return CogniaAPIError(response.status_code, code, trace_id=trace_id)

    @staticmethod
    def _json_object(response: httpx.Response) -> Dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise CogniaContractError("cognia_response_not_json") from exc
        if not isinstance(payload, dict):
            raise CogniaContractError("cognia_response_must_be_object")
        return payload

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        attempts = max(1, int(settings.RETRY_MAX_ATTEMPTS))
        delay = max(0.0, float(settings.RETRY_DELAY_SECONDS))
        backoff = max(1.0, float(settings.RETRY_BACKOFF_FACTOR))
        last_transport_error: Optional[Exception] = None

        for attempt in range(attempts):
            try:
                response = await self._client.request(
                    method,
                    path,
                    headers=headers,
                    json=json_body,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_transport_error = exc
                if attempt + 1 >= attempts:
                    raise CogniaAPIError(503, "COGNIA_TRANSPORT_UNAVAILABLE") from exc
                if delay:
                    await asyncio.sleep(delay * (backoff ** attempt))
                continue

            if 200 <= response.status_code < 300:
                if response.status_code == 204:
                    return {}
                return self._json_object(response)

            if response.status_code in self._TRANSIENT_STATUS and attempt + 1 < attempts:
                if delay:
                    await asyncio.sleep(delay * (backoff ** attempt))
                continue
            raise self._problem_from_response(response)

        raise CogniaAPIError(503, "COGNIA_TRANSPORT_UNAVAILABLE") from last_transport_error

    def _invalidate_token(self) -> None:
        self._token = None
        self._token_valid_until = 0.0

    async def _machine_access_token(self, *, force_refresh: bool = False) -> str:
        now = time.monotonic()
        if not force_refresh and self._token and now < self._token_valid_until:
            return self._token
        if not self.client_id or not self.client_secret:
            raise CogniaConfigurationError("cognia_application_client_credentials_required")

        async with self._token_lock:
            now = time.monotonic()
            if not force_refresh and self._token and now < self._token_valid_until:
                return self._token
            payload = await self._request_json(
                "POST",
                "/api/access/client-auth/token",
                json_body={"clientId": self.client_id, "clientSecret": self.client_secret},
            )
            token = str(payload.get("accessToken") or "").strip()
            token_type = str(payload.get("tokenType") or "Bearer").strip()
            try:
                expires_in = int(payload.get("expiresIn"))
            except (TypeError, ValueError) as exc:
                raise CogniaContractError("cognia_machine_token_expires_in_invalid") from exc
            if not token or token_type.lower() != "bearer" or expires_in <= 0:
                raise CogniaContractError("cognia_machine_token_response_invalid")

            # Keep a small safety margin without inspecting/decoding the opaque token.
            safety_margin = min(30, max(1, expires_in // 10))
            self._token = token
            self._token_valid_until = time.monotonic() + max(1, expires_in - safety_margin)
            return token

    async def _authorized_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        for auth_attempt in range(2):
            token = await self._machine_access_token(force_refresh=auth_attempt == 1)
            try:
                return await self._request_json(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                    json_body=json_body,
                )
            except CogniaAPIError as exc:
                if exc.status_code == 401 and auth_attempt == 0:
                    self._invalidate_token()
                    continue
                raise
        raise CogniaAPIError(401, "COGNIA_AUTHENTICATION_FAILED")

    async def health_check(self) -> bool:
        """Probe Cognia's documented readiness endpoint without exposing credentials."""
        try:
            response = await self._client.get("/health/ready")
            return 200 <= response.status_code < 300
        except (httpx.TimeoutException, httpx.TransportError):
            return False

    async def list_knowledge_bases(self) -> List[Dict[str, Any]]:
        payload = await self._authorized_json("GET", "/api/engine/knowledge-bases")
        if isinstance(payload.get("items"), list):
            return [item for item in payload["items"] if isinstance(item, dict)]
        # The guide documents the endpoint but does not guarantee a pagination
        # envelope shape. Accept a top-level array only when the deployed API
        # wrapper normalized it into a conventional ``data`` list.
        if isinstance(payload.get("data"), list):
            return [item for item in payload["data"] if isinstance(item, dict)]
        raise CogniaContractError("cognia_knowledge_base_list_shape_unknown")

    async def search(
        self,
        query: str,
        *,
        knowledge_base_ids: List[int],
        limit: int,
        continuation_token: Optional[str] = None,
        scope_context: Optional[Dict[str, Any]] = None,
        knowledge_type: Optional[str] = None,
        tag_ids: Optional[List[int]] = None,
        category_ids: Optional[List[int]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        query = str(query or "").strip()
        if not query:
            raise ValueError("cognia_search_query_required")
        kb_ids = [int(value) for value in knowledge_base_ids]
        if not kb_ids or any(value <= 0 for value in kb_ids):
            raise CogniaConfigurationError("cognia_positive_knowledge_base_ids_required")
        if int(limit) <= 0:
            raise ValueError("cognia_search_limit_must_be_positive")

        request: Dict[str, Any] = {
            "query": query,
            "knowledgeBaseIds": kb_ids,
            "limit": int(limit),
        }
        if continuation_token:
            request["continuationToken"] = continuation_token
        if scope_context:
            request["scopeContext"] = dict(scope_context)
        if knowledge_type:
            request["knowledgeType"] = str(knowledge_type)
        if tag_ids:
            request["tagIds"] = [int(value) for value in tag_ids]
        if category_ids:
            request["categoryIds"] = [int(value) for value in category_ids]
        if metadata:
            request["metadata"] = {str(key): str(value) for key, value in metadata.items()}

        payload = await self._authorized_json("POST", "/api/engine/search", json_body=request)
        if not isinstance(payload.get("items"), list):
            raise CogniaContractError("cognia_search_items_missing")
        return payload

    async def generate_context(
        self,
        task: str,
        *,
        context_profile_id: int,
        subject: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        task = str(task or "").strip()
        if not task:
            raise ValueError("cognia_context_task_required")
        if int(context_profile_id) <= 0:
            raise ValueError("cognia_context_profile_id_must_be_positive")
        request: Dict[str, Any] = {
            "contextProfileId": int(context_profile_id),
            "task": task,
        }
        if subject is not None:
            namespace = str(subject.get("namespace") or "").strip()
            external_subject_id = str(subject.get("externalSubjectId") or "").strip()
            if not namespace or not external_subject_id:
                raise ValueError("cognia_context_subject_requires_namespace_and_externalSubjectId")
            request["subject"] = {
                "namespace": namespace,
                "externalSubjectId": external_subject_id,
            }
        payload = await self._authorized_json("POST", "/api/engine/context", json_body=request)
        if "isSufficient" not in payload:
            raise CogniaContractError("cognia_context_is_sufficient_missing")
        return payload
