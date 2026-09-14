from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

import httpx

from domain.contracts.config import settings
from domain.contracts.logging import logger


class CogniaConfigurationError(RuntimeError):
    """Raised when the sole Cognia Knowledge RAG boundary is not safely configured."""


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
        client_application_id: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        tls_verify: Optional[bool] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.base_url = str(base_url or settings.COGNIA_BASE_URL or "").strip().rstrip("/")
        self.client_id = str(client_id or settings.COGNIA_CLIENT_ID or "").strip()
        self.client_secret = str(client_secret or settings.COGNIA_CLIENT_SECRET or "").strip()
        configured_app_id = settings.COGNIA_CLIENT_APPLICATION_ID if client_application_id is None else client_application_id
        self.client_application_id = int(configured_app_id) if configured_app_id is not None else None
        if self.client_application_id is not None and self.client_application_id <= 0:
            raise CogniaConfigurationError("cognia_client_application_id_must_be_positive")
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
        retry_transient: bool = True,
    ) -> Dict[str, Any]:
        attempts = max(1, int(settings.RETRY_MAX_ATTEMPTS)) if retry_transient else 1
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
            token_type = str(payload.get("tokenType") or "").strip()
            try:
                expires_in = int(payload.get("expiresIn"))
            except (TypeError, ValueError) as exc:
                raise CogniaContractError("cognia_machine_token_expires_in_invalid") from exc
            if not token or not token_type or token_type.lower() != "bearer" or expires_in <= 0:
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
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        retry_transient: bool = True,
    ) -> Dict[str, Any]:
        for auth_attempt in range(2):
            token = await self._machine_access_token(force_refresh=auth_attempt == 1)
            request_headers = {"Authorization": f"Bearer {token}"}
            if headers:
                request_headers.update(headers)
            try:
                return await self._request_json(
                    method,
                    path,
                    headers=request_headers,
                    json_body=json_body,
                    retry_transient=retry_transient,
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

    def _assert_own_client_application(self, client_application_id: int) -> int:
        value = int(client_application_id)
        if value <= 0:
            raise ValueError("cognia_client_application_id_must_be_positive")
        if self.client_application_id is None:
            raise CogniaConfigurationError("cognia_client_application_id_required_for_scoped_request")
        if value != self.client_application_id:
            raise CogniaConfigurationError("cognia_client_application_scope_spoof_rejected")
        return value

    def _normalize_scope_context(self, scope_context: Dict[str, Any]) -> Dict[str, Any]:
        client_application_id = self._assert_own_client_application(
            int(scope_context.get("clientApplicationId") or 0)
        )
        result: Dict[str, Any] = {"clientApplicationId": client_application_id}
        namespace = str(scope_context.get("subjectNamespace") or "").strip()
        external_subject_id = str(scope_context.get("externalSubjectId") or "").strip()
        if bool(namespace) != bool(external_subject_id):
            raise ValueError("cognia_scope_context_subject_requires_namespace_and_externalSubjectId")
        if namespace:
            result["subjectNamespace"] = namespace
            result["externalSubjectId"] = external_subject_id
        return result

    def _normalize_knowledge_scope(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        scope_type = str(scope.get("type") or "").strip()
        if scope_type == "general":
            return {"type": "general"}
        if scope_type == "clientApplication":
            app_id = self._assert_own_client_application(int(scope.get("clientApplicationId") or 0))
            return {"type": scope_type, "clientApplicationId": app_id}
        if scope_type == "externalSubject":
            app_id = self._assert_own_client_application(int(scope.get("clientApplicationId") or 0))
            namespace = str(scope.get("subjectNamespace") or "").strip()
            external_subject_id = str(scope.get("externalSubjectId") or "").strip()
            if not namespace or not external_subject_id:
                raise ValueError("cognia_external_subject_requires_namespace_and_externalSubjectId")
            return {
                "type": scope_type,
                "clientApplicationId": app_id,
                "subjectNamespace": namespace,
                "externalSubjectId": external_subject_id,
            }
        raise ValueError("cognia_scope_type_must_be_general_clientApplication_or_externalSubject")

    @staticmethod
    def _validate_revision_payload(
        title: str,
        content: str,
        tag_ids: Optional[List[int]],
        category_ids: Optional[List[int]],
        metadata: Optional[Dict[str, str]],
    ) -> tuple[str, str, List[int], List[int], Dict[str, str]]:
        normalized_title = str(title or "").strip()
        normalized_content = str(content or "")
        if not normalized_title or len(normalized_title) > 500:
            raise ValueError("cognia_title_required_and_max_500_codepoints")
        if not normalized_content or len(normalized_content.encode("utf-8")) > 1024 * 1024:
            raise ValueError("cognia_content_required_and_max_1mib_utf8")
        tags = [int(value) for value in (tag_ids or [])]
        categories = [int(value) for value in (category_ids or [])]
        if len(tags) > 64 or len(categories) > 64:
            raise ValueError("cognia_tag_category_limit_64")
        if any(value <= 0 for value in tags + categories):
            raise ValueError("cognia_taxonomy_ids_must_be_positive")
        normalized_metadata = {str(key): str(value) for key, value in (metadata or {}).items()}
        if len(normalized_metadata) > 64:
            raise ValueError("cognia_metadata_limit_64")
        return normalized_title, normalized_content, tags, categories, normalized_metadata

    async def register_knowledge(
        self,
        *,
        knowledge_base_id: int,
        title: str,
        content: str,
        scope: Dict[str, Any],
        knowledge_type: str = "text",
        tag_ids: Optional[List[int]] = None,
        category_ids: Optional[List[int]] = None,
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        kb_id = int(knowledge_base_id)
        if kb_id <= 0:
            raise ValueError("cognia_knowledge_base_id_must_be_positive")
        title, content, tags, categories, normalized_metadata = self._validate_revision_payload(
            title, content, tag_ids, category_ids, metadata
        )
        body: Dict[str, Any] = {
            "knowledgeType": str(knowledge_type or "text"),
            "title": title,
            "content": content,
            "scope": self._normalize_knowledge_scope(scope),
        }
        if tags:
            body["tagIds"] = tags
        if categories:
            body["categoryIds"] = categories
        if normalized_metadata:
            body["metadata"] = normalized_metadata
        key = str(idempotency_key or "").strip()
        headers = {"Idempotency-Key": key} if key else None
        # Registration is safe to retry only when Cognia's Idempotency-Key
        # contract is in use. Without it, a transport retry could duplicate data.
        return await self._authorized_json(
            "POST",
            f"/api/engine/knowledge-bases/{kb_id}/knowledge",
            headers=headers,
            json_body=body,
            retry_transient=bool(key),
        )

    async def get_knowledge_detail(self, *, knowledge_base_id: int, knowledge_id: int) -> Dict[str, Any]:
        return await self._authorized_json(
            "GET",
            f"/api/engine/knowledge-bases/{int(knowledge_base_id)}/knowledge/{int(knowledge_id)}",
        )

    async def create_revision(
        self,
        *,
        knowledge_base_id: int,
        knowledge_id: int,
        expected_current_candidate_revision_id: Optional[int],
        title: str,
        content: str,
        tag_ids: Optional[List[int]] = None,
        category_ids: Optional[List[int]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        kb_id = int(knowledge_base_id)
        knowledge = int(knowledge_id)
        if kb_id <= 0 or knowledge <= 0:
            raise ValueError("cognia_knowledge_identifiers_must_be_positive")
        title, content, tags, categories, normalized_metadata = self._validate_revision_payload(
            title, content, tag_ids, category_ids, metadata
        )
        expected = (
            int(expected_current_candidate_revision_id)
            if expected_current_candidate_revision_id is not None
            else None
        )
        if expected is not None and expected <= 0:
            raise ValueError("cognia_expected_candidate_revision_id_must_be_positive_or_null")
        body: Dict[str, Any] = {
            "expectedCurrentCandidateRevisionId": expected,
            "title": title,
            "content": content,
        }
        if tags:
            body["tagIds"] = tags
        if categories:
            body["categoryIds"] = categories
        if normalized_metadata:
            body["metadata"] = normalized_metadata
        # Cognia documents optimistic concurrency for candidate creation. A 409
        # requires re-reading current state; blind/transient retry is forbidden.
        return await self._authorized_json(
            "POST",
            f"/api/engine/knowledge-bases/{kb_id}/knowledge/{knowledge}/revisions",
            json_body=body,
            retry_transient=False,
        )

    async def get_processing_status(
        self, *, knowledge_base_id: int, knowledge_id: int, revision_id: int
    ) -> Dict[str, Any]:
        return await self._authorized_json(
            "GET",
            f"/api/engine/knowledge-bases/{int(knowledge_base_id)}/knowledge/{int(knowledge_id)}/revisions/{int(revision_id)}/processing",
        )

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
            request["scopeContext"] = self._normalize_scope_context(scope_context)
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
