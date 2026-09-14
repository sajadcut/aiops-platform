from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise RuntimeError(f"expected pattern not found in {path}: {old[:120]!r}")
    text = text.replace(old, new, 1)
    write(path, text)


def replace_all(path: str, old: str, new: str, *, min_count: int = 1) -> None:
    text = read(path)
    count = text.count(old)
    if count < min_count:
        raise RuntimeError(f"expected >= {min_count} matches in {path}, found {count}: {old[:120]!r}")
    write(path, text.replace(old, new))


def insert_before(path: str, marker: str, content: str) -> None:
    text = read(path)
    if marker not in text:
        raise RuntimeError(f"marker not found in {path}: {marker!r}")
    write(path, text.replace(marker, content + marker, 1))


def replace_between(path: str, start_marker: str, end_marker: str, content: str) -> None:
    text = read(path)
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError(f"start marker not found in {path}: {start_marker!r}")
    end = text.find(end_marker, start)
    if end < 0:
        raise RuntimeError(f"end marker not found in {path}: {end_marker!r}")
    write(path, text[:start] + content + text[end:])


# ---------------------------------------------------------------------------
# Central configuration: Cognia is canonical Governed Knowledge RAG.
# local_pgvector remains only a development/test compatibility fixture.
# ---------------------------------------------------------------------------
replace_once(
    "domain/contracts/config.py",
    "    COGNIA_CLIENT_SECRET: Optional[str] = Field(...)\n    COGNIA_KNOWLEDGE_BASE_IDS: List[int] = Field(...)\n",
    "    COGNIA_CLIENT_SECRET: Optional[str] = Field(...)\n    COGNIA_CLIENT_APPLICATION_ID: Optional[int] = Field(...)\n    COGNIA_KNOWLEDGE_BASE_IDS: List[int] = Field(...)\n",
)
replace_once(
    "domain/contracts/config.py",
    "        if self.COGNIA_CONTEXT_PROFILE_ID is not None and self.COGNIA_CONTEXT_PROFILE_ID <= 0:\n            raise ValueError(\"COGNIA_CONTEXT_PROFILE_ID must be positive when configured\")\n\n        if self.KNOWLEDGE_PROVIDER == \"cognia\":\n",
    "        if self.COGNIA_CONTEXT_PROFILE_ID is not None and self.COGNIA_CONTEXT_PROFILE_ID <= 0:\n            raise ValueError(\"COGNIA_CONTEXT_PROFILE_ID must be positive when configured\")\n        if self.COGNIA_CLIENT_APPLICATION_ID is not None and self.COGNIA_CLIENT_APPLICATION_ID <= 0:\n            raise ValueError(\"COGNIA_CLIENT_APPLICATION_ID must be positive when configured\")\n\n        # Cognia is the canonical Knowledge provider. Development/test may load\n        # the non-secret template without real Cognia credentials; invoking the\n        # provider while unconfigured still fails in CogniaClient. Production is\n        # strictly fail-closed and requires the complete machine identity/KB set.\n        if self.KNOWLEDGE_PROVIDER == \"cognia\" and self.APP_ENV == \"production\":\n",
)

replace_once(
    ".env.example",
    "# Governed Knowledge RAG. Local pgvector is kept for development/test and\n# backwards-compatible fixtures. Production governed knowledge uses Cognia.\nKNOWLEDGE_PROVIDER=local_pgvector\n",
    "# Governed Knowledge RAG. Cognia is the canonical/primary provider.\n# local_pgvector is retained only for deterministic development/test fixtures.\nKNOWLEDGE_PROVIDER=cognia\n",
)
replace_once(
    ".env.example",
    "COGNIA_CLIENT_SECRET=\nCOGNIA_KNOWLEDGE_BASE_IDS=[]\n",
    "COGNIA_CLIENT_SECRET=\n# Numeric Cognia Client Application identity used by Scope/Search. This is\n# distinct from the opaque/string clientId credential used for machine auth.\nCOGNIA_CLIENT_APPLICATION_ID=\nCOGNIA_KNOWLEDGE_BASE_IDS=[]\n",
)

# ---------------------------------------------------------------------------
# Cognia HTTP client: machine identity, explicit scopes, authoring lifecycle,
# idempotency, and optimistic concurrency. Mutations are never blindly retried.
# ---------------------------------------------------------------------------
replace_once(
    "integrations/cognia/client.py",
    "        client_secret: Optional[str] = None,\n        timeout_seconds: Optional[float] = None,\n",
    "        client_secret: Optional[str] = None,\n        client_application_id: Optional[int] = None,\n        timeout_seconds: Optional[float] = None,\n",
)
replace_once(
    "integrations/cognia/client.py",
    "        self.client_secret = str(client_secret or settings.COGNIA_CLIENT_SECRET or \"\").strip()\n        self.timeout_seconds = float(timeout_seconds or settings.COGNIA_TIMEOUT_SECONDS)\n",
    "        self.client_secret = str(client_secret or settings.COGNIA_CLIENT_SECRET or \"\").strip()\n        configured_app_id = settings.COGNIA_CLIENT_APPLICATION_ID if client_application_id is None else client_application_id\n        self.client_application_id = int(configured_app_id) if configured_app_id is not None else None\n        if self.client_application_id is not None and self.client_application_id <= 0:\n            raise CogniaConfigurationError(\"cognia_client_application_id_must_be_positive\")\n        self.timeout_seconds = float(timeout_seconds or settings.COGNIA_TIMEOUT_SECONDS)\n",
)
replace_once(
    "integrations/cognia/client.py",
    "        json_body: Optional[Dict[str, Any]] = None,\n    ) -> Dict[str, Any]:\n        attempts = max(1, int(settings.RETRY_MAX_ATTEMPTS))\n",
    "        json_body: Optional[Dict[str, Any]] = None,\n        retry_transient: bool = True,\n    ) -> Dict[str, Any]:\n        attempts = max(1, int(settings.RETRY_MAX_ATTEMPTS)) if retry_transient else 1\n",
)
replace_between(
    "integrations/cognia/client.py",
    "    async def _authorized_json(\n",
    "    async def health_check(\n",
    '''    async def _authorized_json(
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

''',
)
insert_before(
    "integrations/cognia/client.py",
    "    async def search(\n",
    '''    def _assert_own_client_application(self, client_application_id: int) -> int:
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

''',
)
replace_once(
    "integrations/cognia/client.py",
    "        if scope_context:\n            request[\"scopeContext\"] = dict(scope_context)\n",
    "        if scope_context:\n            request[\"scopeContext\"] = self._normalize_scope_context(scope_context)\n",
)

# ---------------------------------------------------------------------------
# RAG service: Cognia canonical, explicit authoring wrappers, no delete emulation.
# ---------------------------------------------------------------------------
replace_once(
    "apps/rag_service/__init__.py",
    "    ``local_pgvector`` remains available for development/test fixtures. Cognia is\n    the production governed provider when production knowledge governance is\n    enabled. Operational Memory remains a separate local concern.\n",
    "    Cognia is the canonical Governed Knowledge provider. ``local_pgvector`` is\n    retained only for deterministic development/test and historical compatibility.\n    Operational Memory remains an independent PostgreSQL + pgvector concern.\n",
)
insert_before(
    "apps/rag_service/__init__.py",
    "    async def generate_context(\n",
    '''    async def register_knowledge(
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
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_authoring_requires_cognia")
        if int(knowledge_base_id) not in settings.COGNIA_KNOWLEDGE_BASE_IDS:
            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")
        async with CogniaClient() as client:
            return await client.register_knowledge(
                knowledge_base_id=knowledge_base_id,
                title=title,
                content=content,
                scope=scope,
                knowledge_type=knowledge_type,
                tag_ids=tag_ids,
                category_ids=category_ids,
                metadata=metadata,
                idempotency_key=idempotency_key,
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
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_revision_requires_cognia")
        if int(knowledge_base_id) not in settings.COGNIA_KNOWLEDGE_BASE_IDS:
            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")
        async with CogniaClient() as client:
            return await client.create_revision(
                knowledge_base_id=knowledge_base_id,
                knowledge_id=knowledge_id,
                expected_current_candidate_revision_id=expected_current_candidate_revision_id,
                title=title,
                content=content,
                tag_ids=tag_ids,
                category_ids=category_ids,
                metadata=metadata,
            )

    async def get_processing_status(
        self, *, knowledge_base_id: int, knowledge_id: int, revision_id: int
    ) -> Dict[str, Any]:
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_processing_status_requires_cognia")
        async with CogniaClient() as client:
            return await client.get_processing_status(
                knowledge_base_id=knowledge_base_id,
                knowledge_id=knowledge_id,
                revision_id=revision_id,
            )

''',
)

# ---------------------------------------------------------------------------
# Orchestrator: separate successful-empty from provider failure and never infer
# External Subject identity from a service/customer name.
# ---------------------------------------------------------------------------
replace_once(
    "apps/orchestrator/e2e_graph.py",
    "from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient\n",
    "from integrations.cognia import CogniaAPIError, CogniaConfigurationError, CogniaContractError\nfrom integrations.elasticsearch.mcp_client import ElasticsearchMCPClient\n",
)
replace_once(
    "apps/orchestrator/e2e_graph.py",
    "    knowledge_results: List[Dict[str, Any]]\n    memory_results: List[Dict[str, Any]]\n",
    "    knowledge_results: List[Dict[str, Any]]\n    knowledge_status: Dict[str, Any]\n    memory_results: List[Dict[str, Any]]\n",
)
replace_between(
    "apps/orchestrator/e2e_graph.py",
    "    async def _context_node(self, state: E2EState) -> E2EState:\n",
    "    async def _triage_node(self, state: E2EState) -> E2EState:\n",
    '''    @staticmethod
    def _knowledge_failure_status(exc: Exception) -> Dict[str, Any]:
        if isinstance(exc, CogniaConfigurationError):
            return {"provider": "cognia", "status": "misconfigured", "code": str(exc)}
        if isinstance(exc, CogniaContractError):
            return {"provider": "cognia", "status": "invalid_contract", "code": str(exc)}
        if isinstance(exc, CogniaAPIError):
            if exc.status_code == 401:
                status = "authentication_failed"
            elif exc.status_code == 403:
                status = "forbidden"
            elif exc.status_code == 404:
                # Cognia intentionally does not distinguish a hidden KB from a
                # genuinely missing KB for the consumer.
                status = "not_accessible"
            elif exc.status_code in {429, 502, 503, 504}:
                status = "unavailable"
            else:
                status = "error"
            result: Dict[str, Any] = {
                "provider": "cognia",
                "status": status,
                "code": exc.code,
                "http_status": exc.status_code,
            }
            if exc.trace_id:
                result["trace_id"] = exc.trace_id
            return result
        return {"provider": settings.KNOWLEDGE_PROVIDER, "status": "error", "code": type(exc).__name__}

    async def _context_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "context"
        context = dict(state.get("context", {}))
        service = state.get("service_name") or context.get("service") or "unknown"
        query = str(context.get("incident", {}).get("summary") or state.get("evidence_summary") or service)
        state["knowledge_results"] = []
        state["knowledge_status"] = {
            "provider": settings.KNOWLEDGE_PROVIDER,
            "status": "not_queried",
            "count": 0,
        }
        state["memory_results"] = []

        scope_context: Optional[Dict[str, Any]] = None
        subject = context.get("knowledge_subject")
        subject_error: Optional[str] = None
        if subject is not None:
            if not isinstance(subject, dict):
                subject_error = "knowledge_subject_must_be_object"
            else:
                namespace = str(subject.get("namespace") or "").strip()
                external_subject_id = str(
                    subject.get("externalSubjectId") or subject.get("external_subject_id") or ""
                ).strip()
                if not namespace or not external_subject_id:
                    subject_error = "knowledge_subject_requires_namespace_and_externalSubjectId"
                elif settings.COGNIA_CLIENT_APPLICATION_ID is None:
                    subject_error = "cognia_client_application_id_required_for_subject_scope"
                else:
                    scope_context = {
                        "clientApplicationId": settings.COGNIA_CLIENT_APPLICATION_ID,
                        "subjectNamespace": namespace,
                        "externalSubjectId": external_subject_id,
                    }

        can_query_knowledge = settings.KNOWLEDGE_PROVIDER == "cognia" or self.db is not None
        if subject_error:
            state["knowledge_status"] = {
                "provider": settings.KNOWLEDGE_PROVIDER,
                "status": "invalid_scope",
                "code": subject_error,
                "count": 0,
            }
        elif can_query_knowledge:
            try:
                state["knowledge_results"] = await KnowledgeRAGService(self.db).search(
                    query,
                    limit=settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,
                    min_similarity=0.5,
                    scope_context=scope_context,
                )
                state["knowledge_status"] = {
                    "provider": settings.KNOWLEDGE_PROVIDER,
                    "status": "available" if state["knowledge_results"] else "empty",
                    "count": len(state["knowledge_results"]),
                }
            except Exception as exc:
                state["knowledge_status"] = self._knowledge_failure_status(exc)
                state["knowledge_status"]["count"] = 0
                logger.warning(
                    "knowledge_rag_retrieval_failed",
                    provider=state["knowledge_status"].get("provider"),
                    status=state["knowledge_status"].get("status"),
                    code=state["knowledge_status"].get("code"),
                )
        else:
            state["knowledge_status"] = {
                "provider": settings.KNOWLEDGE_PROVIDER,
                "status": "misconfigured",
                "code": "local_pgvector_database_session_required",
                "count": 0,
            }

        if self.db is not None:
            try:
                state["memory_results"] = await OperationalMemoryService(self.db).search_similar(
                    query,
                    service_scope=service,
                    limit=settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,
                    min_similarity=0.5,
                )
            except Exception as exc:
                logger.warning("operational_memory_retrieval_failed", error_type=type(exc).__name__)

        try:
            since = datetime.now(timezone.utc) - timedelta(seconds=settings.AGENT_INITIAL_EVIDENCE_WINDOW_SECONDS)
            state["live_evidence"] = await self.evidence_collector.collect(service, since)
        except Exception as exc:
            logger.warning("live_evidence_collection_failed", error_type=type(exc).__name__)
            state["live_evidence"] = {"service": service, "evidence": [], "error": type(exc).__name__}

        context["knowledge_results"] = state["knowledge_results"]
        context["knowledge_status"] = state["knowledge_status"]
        context["memory_results"] = state["memory_results"]
        context["live_evidence"] = state["live_evidence"]
        context["evidence"] = state["live_evidence"].get("evidence", [])
        state["context"] = context
        state["evidence_rounds"] = 1
        if not state.get("before_context"):
            state["before_context"] = {"live_evidence": state["live_evidence"]}
        self._audit(
            "context_loaded",
            state,
            knowledge_count=len(state["knowledge_results"]),
            knowledge_status=state["knowledge_status"],
            memory_count=len(state["memory_results"]),
            evidence_count=len(state["live_evidence"].get("evidence", [])),
        )
        return state

''',
)

replace_once(
    "agents/shared/base.py",
    '''        return {
            "knowledge_rag": cls.knowledge_items(input_data),
            "operational_memory": cls.memory_items(input_data),
            "policy": "auxiliary_only_not_live_evidence",
        }
''',
    '''        return {
            "knowledge_rag": cls.knowledge_items(input_data),
            "knowledge_status": (
                input_data.context.get("knowledge_status", {"status": "unknown"})
                if input_data.context else {"status": "unknown"}
            ),
            "operational_memory": cls.memory_items(input_data),
            "policy": "auxiliary_only_not_live_evidence",
        }
''',
)

# Canonical recursive redaction already treats any *secret* key, including
# clientSecret/COGNIA_CLIENT_SECRET, as sensitive. Reuse it in audit too.
write(
    "apps/audit_service/redaction.py",
    '''"""Compatibility wrapper around the canonical recursive redaction policy."""
from domain.contracts.redaction import REDACTED, redact

__all__ = ["REDACTED", "redact"]
''',
)

# Readiness must not crash a development checkout whose Cognia credentials are
# intentionally empty; production Settings validation remains fail-closed.
replace_between(
    "apps/api/health.py",
    "async def _probe_external() -> dict:\n",
    "\n\ndef _external_required_ready(external: dict) -> bool:\n",
    '''async def _probe_external() -> dict:
    connectors = {
        "zabbix_mcp": ZabbixMCPClient(),
        "elasticsearch_mcp": ElasticsearchMCPClient(),
        "prometheus_mcp": PrometheusMCPClient(),
    }
    static: dict = {}
    if settings.KUBERNETES_MCP_URL:
        connectors["kubernetes_mcp"] = KubernetesMCPClient()
    if settings.VM_MCP_URL:
        connectors["vm_mcp"] = VMEdgeMCPClient()
    if settings.KNOWLEDGE_PROVIDER == "cognia":
        if settings.COGNIA_BASE_URL:
            try:
                connectors["cognia"] = CogniaClient()
            except Exception as exc:
                static["cognia"] = {"healthy": False, "configured": False, "error": type(exc).__name__}
                DEPENDENCY_UP.labels(dependency="cognia").set(0)
        else:
            static["cognia"] = {"healthy": False, "configured": False, "error": "not_configured"}
            DEPENDENCY_UP.labels(dependency="cognia").set(0)
    pairs = await asyncio.gather(*(_probe_one(name, client) for name, client in connectors.items()))
    return {**dict(pairs), **static}
''',
)

# CI keeps generic repository tests deterministic/local while Cognia contract
# tests exercise the provider explicitly. The tracked template still declares
# Cognia as the canonical product default.
replace_all(
    ".github/workflows/quality.yml",
    "              'APP_ENV=development': 'APP_ENV=test',\n",
    "              'APP_ENV=development': 'APP_ENV=test',\n              'KNOWLEDGE_PROVIDER=cognia': 'KNOWLEDGE_PROVIDER=local_pgvector',\n",
    min_count=2,
)
replace_once(
    ".github/workflows/quality.yml",
    "              'ELASTICSEARCH_PASSWORD', 'KUBERNETES_TOKEN',\n",
    "              'ELASTICSEARCH_PASSWORD', 'KUBERNETES_TOKEN',\n              'COGNIA_CLIENT_SECRET',\n",
)

# ---------------------------------------------------------------------------
# Cognia tests: authoring/idempotency, anti-spoof, no blind candidate retry,
# and typed orchestrator status.
# ---------------------------------------------------------------------------
replace_once(
    "tests/unit/test_cognia_client.py",
    "from integrations.cognia import CogniaAPIError, CogniaClient, CogniaContractError\n",
    "from integrations.cognia import CogniaAPIError, CogniaClient, CogniaConfigurationError, CogniaContractError\n",
)
with (ROOT / "tests/unit/test_cognia_client.py").open("a", encoding="utf-8") as handle:
    handle.write(r'''

@pytest.mark.asyncio
async def test_registration_uses_idempotency_and_rejects_scope_spoof(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})
        if request.url.path == "/api/engine/knowledge-bases/10/knowledge":
            captured["idempotency"] = request.headers.get("idempotency-key")
            captured["body"] = json.loads(request.content)
            return httpx.Response(201, json={"knowledgeId": 9001, "revisionId": 12001, "revisionNumber": 1})
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-credential",
        client_secret="secret",
        client_application_id=42,
        transport=httpx.MockTransport(handler),
    ) as client:
        created = await client.register_knowledge(
            knowledge_base_id=10,
            title="Runbook",
            content="safe content",
            scope={
                "type": "externalSubject",
                "clientApplicationId": 42,
                "subjectNamespace": "service",
                "externalSubjectId": "payments",
            },
            metadata={"source": "runbook"},
            idempotency_key="incident-runbook-001",
        )
        assert created["revisionNumber"] == 1
        with pytest.raises(CogniaConfigurationError, match="scope_spoof_rejected"):
            await client.register_knowledge(
                knowledge_base_id=10,
                title="Runbook",
                content="safe content",
                scope={"type": "clientApplication", "clientApplicationId": 99},
                idempotency_key="different",
            )

    assert captured["idempotency"] == "incident-runbook-001"
    assert captured["body"]["scope"]["externalSubjectId"] == "payments"


@pytest.mark.asyncio
async def test_candidate_revision_conflict_is_not_blindly_retried(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 5)
    calls = {"revision": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})
        if request.url.path.endswith("/knowledge/9001/revisions"):
            calls["revision"] += 1
            body = json.loads(request.content)
            assert "expectedCurrentCandidateRevisionId" in body
            return httpx.Response(
                409,
                headers={"content-type": "application/problem+json"},
                json={"status": 409, "code": "KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT"},
            )
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CogniaAPIError) as captured:
            await client.create_revision(
                knowledge_base_id=10,
                knowledge_id=9001,
                expected_current_candidate_revision_id=None,
                title="v2",
                content="new content",
            )
    assert captured.value.code == "KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT"
    assert calls["revision"] == 1


def test_machine_client_does_not_expose_human_approval_decisions():
    assert not hasattr(CogniaClient, "approve_revision")
    assert not hasattr(CogniaClient, "reject_revision")
''')

write(
    "tests/unit/test_cognia_orchestrator_status.py",
    '''from apps.orchestrator.e2e_graph import E2EOrchestrator
from integrations.cognia import CogniaAPIError, CogniaConfigurationError, CogniaContractError


def test_cognia_failure_statuses_are_not_collapsed_to_empty_results():
    unavailable = E2EOrchestrator._knowledge_failure_status(
        CogniaAPIError(503, "SEARCH_DEPENDENCY_UNAVAILABLE", trace_id="trace-1")
    )
    assert unavailable == {
        "provider": "cognia",
        "status": "unavailable",
        "code": "SEARCH_DEPENDENCY_UNAVAILABLE",
        "http_status": 503,
        "trace_id": "trace-1",
    }
    assert E2EOrchestrator._knowledge_failure_status(CogniaAPIError(403, "FORBIDDEN"))["status"] == "forbidden"
    assert E2EOrchestrator._knowledge_failure_status(CogniaAPIError(404, "KB_NOT_FOUND"))["status"] == "not_accessible"
    assert E2EOrchestrator._knowledge_failure_status(CogniaConfigurationError("missing"))["status"] == "misconfigured"
    assert E2EOrchestrator._knowledge_failure_status(CogniaContractError("shape"))["status"] == "invalid_contract"
''',
)

# Configuration contract assertions for primary RAG and distinct application ID.
with (ROOT / "tests/unit/test_centralized_config.py").open("a", encoding="utf-8") as handle:
    handle.write(r'''


def test_cognia_is_canonical_template_provider_and_client_application_id_is_distinct():
    values = _template_values()
    assert values["KNOWLEDGE_PROVIDER"] == "cognia"
    assert "COGNIA_CLIENT_APPLICATION_ID" in values
    assert values["COGNIA_CLIENT_APPLICATION_ID"] == ""
''')

# ---------------------------------------------------------------------------
# MASTER 2.4: Cognia is the fixed governed Knowledge RAG; pgvector remains the
# Operational Memory vector layer and local test compatibility only.
# ---------------------------------------------------------------------------
replace_once(
    "MASTER.md",
    "| نسخه | **2.3 - Benchmark-driven Production Hardening** |",
    "| نسخه | **2.4 - Cognia Governed Knowledge RAG** |",
)
replace_once(
    "MASTER.md",
    "- **Operational Memory با Knowledge RAG یکی نیست و باید در مدل، Retrieval و Policy از هم جدا بمانند.**\n",
    "- **Operational Memory با Knowledge RAG یکی نیست و باید در مدل، Retrieval و Policy از هم جدا بمانند.**\n- **Cognia مرجع اصلی و canonical برای Governed Knowledge RAG است؛ local PostgreSQL/pgvector مسیر Production Knowledge نیست.**\n",
)
replace_once(
    "MASTER.md",
    "| 7. Knowledge RAG | بازیابی دانش ایستا/نیمه‌پویا | **PostgreSQL + pgvector + Retriever + LLM Adapter** | Relevant Knowledge |",
    "| 7. Knowledge RAG | بازیابی دانش governed و Context | **Cognia Search + Context Generation via Application Client** | Traceable Knowledge Chunks / Context Package |",
)
replace_once(
    "MASTER.md",
    "- برای MVP، **PostgreSQL + pgvector** لایه پایه Vector Search برای Knowledge RAG و Operational Memory است. Mem0 اختیاری است و فقط از طریق Adapter قابل استفاده خواهد بود.\n",
    "- **Cognia** مرز canonical ثبت، Revision، Approval/Processing lifecycle، Permission، Search و Context برای Governed Knowledge است.\n- **PostgreSQL + pgvector** لایه Semantic Retrieval برای Operational Memory است؛ local Knowledge pgvector فقط fixture توسعه/تست و سازگاری تاریخی است.\n- در خطای Cognia، سیستم حق fallback پنهان به local Knowledge ندارد؛ وضعیت unavailable/forbidden/not-accessible باید از Search موفق با zero result متمایز بماند.\n",
)
replace_between(
    "MASTER.md",
    "## 5.2 قرارداد Storage و Vector Layer\n",
    "\n# 6. هسته نرم‌افزار و Stack قطعی\n",
    '''## 5.2 قرارداد Storage و Knowledge Layer

- **PostgreSQL** Persistence اصلی خود پلتفرم برای Incident، Evidence، Finding، Approval، Audit، Workflow Checkpoint، Runbook و Operational Memory است.
- **pgvector** Vector Search لایه Operational Memory را فراهم می‌کند. جدول/مدل local Knowledge موجود فقط برای fixtureهای توسعه/تست و migration compatibility نگه داشته می‌شود و System of Record دانش Production نیست.
- **Cognia** System of Record و retrieval boundary دانش governed است: Knowledge Base، Permission، Knowledge/Revision، Processing/Activation، Scope، Search Chunk و Context Profile/Package در Cognia authoritative هستند.
- AIOps نباید Permission/Activation Cognia را با ACL محلی شبیه‌سازی یا دور بزند و نباید Knowledge Cognia را به‌عنوان fallback خاموش در pgvector mirror کند.
- Machine integration فقط با Client Application انجام می‌شود؛ `clientId/clientSecret` credential احراز هویت است و `clientApplicationId` شناسه عددی Scope است و این دو نباید با هم یکی فرض شوند.
- External Subject فقط از contract صریح و پایدار `ClientApplication + Namespace + ExternalSubjectId` ساخته می‌شود؛ AIOps حق حدس‌زدن Subject از نام service/customer را ندارد.
- Search فقط روی KBهای صریح و با authorization all-or-nothing انجام می‌شود؛ Result واحد Chunk از Active Revision است و `relevanceScore` فقط relevance retrieval است، نه احتمال صحت Fact.
- Context Package پاسخ نهایی LLM نیست و `HTTP 200 + isSufficient=false` باید به‌عنوان Context ناکافی حفظ شود.
- **Mem0** در صورت انتخاب فقط Adapter اختیاری Operational Memory است و به Knowledge RAG Cognia مربوط نیست.
''',
)
replace_once(
    "MASTER.md",
    "| Knowledge RAG | **PostgreSQL + pgvector + Retriever** | **قطعی برای MVP** |",
    "| Knowledge RAG | **Cognia Search + Context Generation** | **قطعی / canonical** |",
)
replace_once(
    "MASTER.md",
    "| Knowledge RAG | **Runbook/Knowledge محدود و کنترل‌شده؛ PostgreSQL + pgvector** |",
    "| Knowledge RAG | **Runbook/Knowledge governed در Cognia؛ Search روی Active Revision و Context Profile در صورت provision** |",
)
replace_once(
    "MASTER.md",
    "هدف: افزودن دانش و تجربه قابل بازیابی با **PostgreSQL + pgvector** به‌عنوان Vector Layer مشترک.\n\n**خروجی‌ها:** Knowledge Document model؛ document ingestion؛ chunking؛ embedding generation؛ pgvector extension/schema؛ metadata/filter retrieval؛ Runbook/Architecture retrieval؛ Operational Memory model؛ ثبت Outcome؛ semantic similarity/reuse اولیه.\n",
    "هدف: اتصال Governed Knowledge به **Cognia** و نگه‌داشتن تجربه Incident در **PostgreSQL + pgvector Operational Memory**.\n\n**خروجی‌ها:** Cognia Application Client machine auth؛ KB grant/config contract؛ Knowledge registration با Scope/Idempotency؛ immutable Revision و Processing status؛ Search روی Active Chunk با traceability؛ Context Generation در صورت provision Profile؛ Operational Memory model؛ ثبت Outcome؛ pgvector similarity/reuse برای Memory.\n",
)
replace_once(
    "MASTER.md",
    "│   ├── prometheus/\n│   ├── jenkins/",
    "│   ├── prometheus/\n│   ├── cognia/                     # canonical Governed Knowledge RAG client\n│   ├── jenkins/",
)
replace_once(
    "MASTER.md",
    "| **Vector Store / pgvector** | **قطعی** | **PostgreSQL + pgvector لایه Vector مشترک RAG و Memory در MVP است.** |",
    "| **Governed Knowledge RAG** | **قطعی** | **Cognia مرجع canonical برای Knowledge/Revision/Permission/Search/Context است.** |\n| **Vector Store / pgvector** | **قطعی برای Memory** | **PostgreSQL + pgvector لایه Semantic Retrieval برای Operational Memory است؛ local Knowledge فقط dev/test compatibility است.** |",
)
replace_once(
    "MASTER.md",
    "- PostgreSQL + pgvector به‌عنوان Persistence/Vector baseline.\n",
    "- PostgreSQL به‌عنوان Persistence پلتفرم و pgvector به‌عنوان Vector baseline Operational Memory.\n- Cognia به‌عنوان canonical Governed Knowledge RAG با no-hidden-fallback semantics.\n",
)
replace_once("MASTER.md", "# 24. وضعیت فعلی پروژه — 2026-08-26", "# 24. وضعیت فعلی پروژه — 2026-09-14")
replace_once(
    "MASTER.md",
    "| Knowledge RAG | Implemented on PostgreSQL + pgvector with governance/ACL metadata |",
    "| Knowledge RAG | Cognia canonical integration implemented (machine auth/Search/Context/authoring contract/no fallback); real Cognia env acceptance pending |",
)
replace_once(
    "MASTER.md",
    "- PostgreSQL + pgvector persistence for Incident/RAG/Memory/governance.\n",
    "- PostgreSQL persistence for Incident/governance plus pgvector Operational Memory; Cognia is the canonical Governed Knowledge RAG boundary.\n",
)
replace_once(
    "MASTER.md",
    "1. Real Zabbix/Elasticsearch/Prometheus acceptance + CMDB/service catalog mapping.\n",
    "1. Real Cognia HTTPS/Application Client/KB grant/Search/Scope acceptance, including outage/no-fallback evidence.\n2. Real Zabbix/Elasticsearch/Prometheus acceptance + CMDB/service catalog mapping.\n",
)
# Renumbering the remaining prose list is cosmetic; preserve content while adding
# Cognia as a new first priority.
replace_once(
    "MASTER.md",
    "- Real observability, LLM and remediation endpoints have not been externally accepted in the target restricted network.\n",
    "- Real Cognia HTTPS endpoint, Application Client identity, KB grants, Scope/Search and optional Context Profile have not yet been externally accepted.\n- Real observability, LLM and remediation endpoints have not been externally accepted in the target restricted network.\n",
)
replace_once(
    "MASTER.md",
    "| **2.3** | **Sync وضعیت واقعی implementation؛ deterministic cross-source correlation؛ MCP governance؛ hybrid central/edge target؛ benchmark 2026؛ production gaps و Next Steps واقعی** | **حذف drift بین SSoT و repository و هم‌راستایی با الگوهای امن Agentic/AIOps 2026 بدون ادعای Production Ready زودهنگام** |\n",
    "| **2.3** | **Sync وضعیت واقعی implementation؛ deterministic cross-source correlation؛ MCP governance؛ hybrid central/edge target؛ benchmark 2026؛ production gaps و Next Steps واقعی** | **حذف drift بین SSoT و repository و هم‌راستایی با الگوهای امن Agentic/AIOps 2026 بدون ادعای Production Ready زودهنگام** |\n| **2.4** | **تثبیت Cognia به‌عنوان canonical Governed Knowledge RAG؛ محدودکردن pgvector به Operational Memory/dev-test Knowledge؛ تعریف Machine Auth، Scope، Search/Context، authoring lifecycle و no-hidden-fallback** | **هم‌راستا کردن SSoT با قرارداد رسمی Cognia و تصمیم قطعی پروژه** |\n",
)
replace_between(
    "MASTER.md",
    "### A.3 قرارداد Retrieval\n",
    "\n### A.4 Rule\n",
    '''### A.3 قرارداد Retrieval

برای Cognia Search هر نتیجه داخلی باید traceability حداقلی زیر را حفظ کند: `provider`، `source_id`، `knowledge_base_id`، `knowledge_id`، `revision_id`، `revision_number`، `chunk_id`، `content`، `relevance` و `retrieved_at`. `title` فقط وقتی مجاز است که از API Detail معتبر دریافت شده باشد؛ Search Chunk عنوان را تضمین نمی‌کند و AIOps نباید آن را اختراع کند.

`relevance` فقط Retrieval Relevance است و به‌تنهایی confidence صحت Fact یا Evidence نیست.
''',
)
replace_between(
    "MASTER.md",
    "## ضمیمه D - قرارداد pgvector و Mem0\n",
    "\n",
    '''## ضمیمه D - قرارداد Cognia، pgvector و Mem0

### D.1 Cognia

Cognia canonical System of Record برای Governed Knowledge، Revision lifecycle، KB Permission، Scope، Search و Context Generation است. AIOps مصرف‌کننده Cognia است و Permission یا lifecycle آن را locally بازسازی نمی‌کند.

### D.2 pgvector

`pgvector` بخشی از Persistence Architecture Operational Memory است. Embeddingهای Memory در PostgreSQL نگهداری می‌شوند و Similarity برای reuse Incident pattern استفاده می‌شود. local Knowledge pgvector فقط fixture/compatibility غیرProduction است.

### D.3 Mem0

Mem0 در صورت استفاده، فقط یک Memory Management Layer/Adapter است. انتخاب یا حذف آن نباید Schema، Domain Contract یا LangGraph State را بشکند.

### D.4 Rule

**Cognia = Governed Knowledge RAG؛ PostgreSQL = Platform System of Record؛ pgvector = Operational Memory Semantic Retrieval؛ Operational Memory = تجربه عملیاتی؛ Live Evidence = حقیقت Incident جاری.**
''',
)

# ADR summary: old pgvector RAG decision is explicitly superseded.
replace_once(
    "docs/adr/DECISIONS.md",
    "**Decision:** pgvector به‌عنوان Vector Search Layer اصلی و یکپارچه با PostgreSQL انتخاب می‌شود.\n\n**Rationale:** کاهش پیچیدگی زیرساخت، نگهداری relational + vector data در یک سیستم، مناسب برای MVP و Offline Production.\n",
    "**Decision:** pgvector Vector Search Layer اصلی Operational Memory و fixtureهای local development/test است. Governed Knowledge Production از Cognia استفاده می‌کند.\n\n**Rationale:** PostgreSQL/pgvector تجربه Incident را نزدیک persistence پلتفرم نگه می‌دارد، در حالی‌که Knowledge governance/lifecycle/authorization به Cognia واگذار می‌شود.\n",
)
replace_once(
    "docs/adr/DECISIONS.md",
    "**Status:** ACCEPTED\n\n**Decision:** Knowledge RAG از PostgreSQL + pgvector و یک abstraction لایه بازیابی استفاده می‌کند.\n\n**Purpose:** بازیابی Runbook، Architecture Docs، Procedures و Knowledge تأییدشده.\n\n**Critical Rule:** RAG منبع حقیقت برای Live Production Evidence نیست.\n",
    "**Status:** SUPERSEDED BY ADR-018\n\n**Decision:** Historical MVP used PostgreSQL + pgvector behind a retrieval abstraction. Production Governed Knowledge is now Cognia; local pgvector Knowledge remains dev/test compatibility only.\n\n**Critical Rule:** RAG منبع حقیقت برای Live Production Evidence نیست.\n",
)
insert_before(
    "docs/adr/DECISIONS.md",
    "## Open Decisions\n",
    '''## ADR-018 — Cognia Governed Knowledge RAG

**Status:** ACCEPTED / CANONICAL KNOWLEDGE PROVIDER

**Decision:** Cognia مرجع اصلی Governed Knowledge RAG است. AIOps با Client Application ماشینی به Cognia متصل می‌شود و KB Permission، Knowledge/Revision lifecycle، Scope، Search و Context را از Cognia می‌پذیرد.

**No fallback:** خطای Cognia نباید به Search موفق خالی یا fallback پنهان local pgvector تبدیل شود. Incident reasoning می‌تواند با Live Evidence ادامه یابد، اما وضعیت Knowledge provider باید صریح و audit شود.

**Memory boundary:** Operational Memory همچنان PostgreSQL + pgvector است.

**Authoring:** Registration باید KB/Scope صریح و Idempotency-Key داشته باشد؛ Candidate Revision از optimistic concurrency استفاده می‌کند و 409 blind retry نمی‌شود. Machine Client حق Approve/Reject انسانی ندارد.

**Acceptance:** قرارداد repository قابل تست است؛ endpoint/Client/Grant/Scope/Search/Context واقعی Cognia همچنان REAL ENV REQUIRED است.

---

''',
)

write(
    "docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md",
    '''# ADR-018 — Cognia as the Canonical Governed Knowledge RAG

**Status:** ACCEPTED / CANONICAL; REAL ENV ACCEPTANCE REQUIRED

## Context

Cognia v1 provides the organization-managed Knowledge boundary: Application Client machine identity, Knowledge Base grants, immutable Knowledge/Revision lifecycle, processing/activation, Scope/External Subject isolation, Search over Current Active Revision chunks and Context Generation. Live operational Evidence remains the AIOps truth source and Operational Memory remains separate.

## Decision

1. Cognia is the canonical and primary Governed Knowledge RAG for AIOps Production. `local_pgvector` Knowledge is development/test and historical compatibility only.
2. `KnowledgeRAGService` remains the internal AIOps abstraction so agents/workflows do not depend on raw Cognia HTTP shapes.
3. Backend integration uses Cognia Client Application Machine Authentication only. Human username/password credentials are forbidden in AIOps runtime.
4. Machine access tokens are opaque, cached only within returned `expiresIn`, and never decoded as JWTs. Machine auth has no refresh-token flow; expiry causes re-authentication with client credentials.
5. `clientId/clientSecret` are machine credentials. Numeric `clientApplicationId` is the Cognia Scope identity. They are separate values and must not be inferred from one another.
6. Search supplies explicit configured KB IDs and Cognia owns effective `kb.read`. Authorization is all-or-nothing; AIOps never silently removes an unauthorized KB.
7. Search consumes only Current Active Revision chunks. AIOps preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance, not factual or operational confidence.
8. There is no hidden fallback from Cognia to local pgvector. Successful zero results are `empty`; provider/auth/index/dependency failures are separate typed states and are audit-visible.
9. Cognia outage does not make RAG an authority over Incident handling: reasoning may continue on fresh Live Evidence, but it must carry explicit Knowledge-provider degradation and may require human review according to downstream policy.
10. External Subject is accepted only from an explicit stable contract. AIOps does not infer Namespace/ExternalSubjectId from a service/customer display name. Machine scoped requests must match the configured numeric Client Application ID.
11. Context Generation is an auxiliary governed package, not a final LLM answer. `HTTP 200` with `isSufficient=false` remains insufficient context; `CONTEXT_INSUFFICIENT_KNOWLEDGE` remains an explicit provider error where the profile uses failGeneration.
12. Cognia authoring is explicit: registration uses a configured KB, explicit Scope and optional Idempotency-Key. Automatic transient retry is permitted only when Idempotency-Key makes registration replay-safe.
13. Candidate Revision always sends `expectedCurrentCandidateRevisionId`. A 409 concurrency conflict is not blindly retried; caller must re-read current state and make a new decision.
14. Machine Client does not automate human Approve/Reject decisions. AIOps does not emulate Cognia Knowledge delete because the consumer v1 contract does not expose it.
15. PostgreSQL remains AIOps platform persistence. pgvector remains the Operational Memory semantic retrieval layer.

## Security and deployment

- Production Cognia endpoint must be HTTPS and certificate verification stays enabled.
- `COGNIA_CLIENT_SECRET` and access tokens are secrets and must be redacted from logs/audit/prompts and injected from the deployment secret store.
- KB IDs, Client Application ID and Context Profile ID are explicit configuration, never model-generated authority.
- Default-deny Kubernetes networking remains in force. If Cognia is external to the cluster, platform infrastructure must provide a narrowly allowlisted HTTPS/FQDN/proxy egress path; the application must not open broad `0.0.0.0/0` egress.
- Production readiness treats Cognia as required because it is the canonical Knowledge dependency.

## Acceptance

Repository tests must cover opaque-token lifecycle, re-auth, Search traceability, all-or-nothing request construction, no fallback, problem+json status/code handling, authoring idempotency, Scope anti-spoof, optimistic concurrency/no blind retry, Context sufficiency and secret/config fail-closed behavior.

Production PASS still requires real non-production Cognia evidence: approved HTTPS endpoint, Application Client credential rotation, exact KB grants, positive/negative Search authorization, General/ClientApplication/ExternalSubject scope tests where used, registration → processing → Activated → Search, index/dependency outage behavior, and Context Profile/sufficiency tests if Context Generation is enabled.
''',
)

# Acceptance/status docs: Cognia is primary, not one provider option.
replace_all("docs/PRODUCTION_ACCEPTANCE_MATRIX.md", "MASTER.md 2.3", "MASTER.md 2.4")
replace_once(
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
    "| Knowledge RAG abstraction | PASS (repo) | Provider-neutral `KnowledgeRAGService`; Cognia mapping preserves KB/Knowledge/Revision/Chunk traceability and local pgvector remains development/test compatibility |",
    "| Knowledge RAG abstraction | PASS (repo) | `KnowledgeRAGService` fronts canonical Cognia; KB/Knowledge/Revision/Chunk traceability is preserved and local pgvector is development/test compatibility only |",
)
replace_once(
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
    "| Cognia governed Knowledge RAG | REAL ENV REQUIRED | Machine auth, opaque-token lifecycle, explicit KB IDs, typed Search/Context errors and no-fallback behavior are covered in repository tests; real Cognia endpoint/Application Client/KB grants/Scope/Context acceptance is still required |",
    "| Cognia canonical Governed Knowledge RAG | REAL ENV REQUIRED | Repository covers machine auth, separate Client Application scope ID, opaque-token lifecycle, explicit KBs, authoring idempotency, Revision concurrency, Search/Context errors and no-fallback; real endpoint/Application Client/KB grants/Scope/lifecycle/Context acceptance is still required |",
)
replace_once(
    "docs/master/IMPLEMENTATION_STATUS.md",
    "- Governed Knowledge RAG now has a provider boundary: local PostgreSQL/pgvector remains for development/test compatibility while Cognia is the required production provider when `KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION=true`.\n",
    "- Cognia is now the canonical Governed Knowledge RAG. local PostgreSQL/pgvector Knowledge remains only for deterministic development/test compatibility; Operational Memory remains PostgreSQL/pgvector.\n",
)
replace_once(
    "docs/master/IMPLEMENTATION_STATUS.md",
    "- Cognia integration implements Application Client machine authentication, opaque access-token lifecycle, explicit KB IDs, Search Chunk traceability, optional Context Generation, typed upstream failures and no hidden fallback to local Knowledge.\n",
    "- Cognia integration implements Application Client machine authentication, separate numeric Client Application Scope identity, opaque access-token lifecycle, explicit KB IDs, registration/idempotency, candidate Revision concurrency, Search Chunk traceability, optional Context Generation, typed upstream failures and no hidden fallback to local Knowledge.\n",
)
replace_once(
    "docs/master/IMPLEMENTATION_STATUS.md",
    "| Cognia governed Knowledge | Application Client auth + Search + optional Context + readiness + fail-closed configuration | PASS (repository contract); **REAL ENV REQUIRED** for target Cognia acceptance |",
    "| Cognia governed Knowledge | Canonical RAG: Application Client auth + authoring/Revision + Search + optional Context + readiness + fail-closed/no-fallback | PASS (repository contract); **REAL ENV REQUIRED** for target Cognia acceptance |",
)

# Configuration guide: append an explicit canonical contract section once.
config_doc = read("docs/CONFIGURATION.md")
if "## Cognia canonical Knowledge RAG" not in config_doc:
    config_doc += '''\n## Cognia canonical Knowledge RAG\n\nCognia is the canonical Governed Knowledge RAG. `KNOWLEDGE_PROVIDER=cognia` is the tracked product default; CI may explicitly switch to `local_pgvector` only for deterministic repository fixtures. Production requires HTTPS, TLS verification, machine `COGNIA_CLIENT_ID`/`COGNIA_CLIENT_SECRET` and explicit `COGNIA_KNOWLEDGE_BASE_IDS`.\n\n`COGNIA_CLIENT_APPLICATION_ID` is a numeric Cognia Scope identity and is **not** the same value as the machine-auth `COGNIA_CLIENT_ID`. External Subject must come from an explicit upstream contract and is never inferred from a service/customer name. `COGNIA_CONTEXT_PROFILE_ID` is optional until a profile is provisioned.\n\nIf Cognia is outside the Kubernetes cluster, default-deny networking requires an infrastructure-managed allowlisted HTTPS/FQDN/proxy egress path. Do not widen the application NetworkPolicy to unrestricted Internet egress.\n'''
    write("docs/CONFIGURATION.md", config_doc)

# FINAL acceptance report still had the historical pgvector-only row.
final_report = read("FINAL_ACCEPTANCE_REPORT.md")
final_report = final_report.replace(
    "| Knowledge RAG | governed PostgreSQL+pgvector retrieval with metadata/ACL | PASS (repo); corpus relevance acceptance pending |",
    "| Knowledge RAG | canonical Cognia machine-auth/Search/Context/authoring contract with full chunk traceability and no hidden fallback | PASS (repo contract); REAL ENV REQUIRED for Cognia endpoint/grants/scope/lifecycle/context acceptance |",
)
if "Real Cognia Application Client" not in final_report:
    final_report = final_report.replace(
        "## Remaining production blockers / external acceptance\n\n",
        "## Remaining production blockers / external acceptance\n\n1. Real Cognia Application Client/HTTPS/KB grants plus Search Scope, authoring→Activated lifecycle, outage/no-fallback and optional Context Profile acceptance.\n",
        1,
    )
write("FINAL_ACCEPTANCE_REPORT.md", final_report)

# Project-specific integration runbook derived strictly from the supplied v1 contract.
write(
    "docs/COGNIA_INTEGRATION.md",
    '''# Cognia Integration Contract for aiops-platform

Status: repository contract implemented; real environment acceptance required.

## Role in architecture

Cognia is the canonical Governed Knowledge RAG. It owns Knowledge Base permissions, Knowledge/Revision lifecycle, processing/activation, Scope, Search and Context Profile policy. It is not Live Operational Evidence, an LLM, an execution tool or Operational Memory.

Operational Memory remains PostgreSQL + pgvector. Live Evidence remains authoritative for the current Incident. There is no Cognia → local Knowledge fallback in Production.

## Machine identity

AIOps uses a Cognia Client Application and `POST /api/access/client-auth/token`. The access token is opaque and is never decoded. Machine auth has no refresh token; the service re-authenticates after `expiresIn`. Creating the Client Application does not grant KB access; required KB grants are provisioned separately by Cognia administration.

Configuration separates:

- `COGNIA_CLIENT_ID` / `COGNIA_CLIENT_SECRET`: machine authentication credentials.
- `COGNIA_CLIENT_APPLICATION_ID`: numeric Client Application identity used by Scope/Search.
- `COGNIA_KNOWLEDGE_BASE_IDS`: exact KBs AIOps is allowed/configured to query.
- `COGNIA_CONTEXT_PROFILE_ID`: optional pre-provisioned Context Profile.

## Search

AIOps sends all configured KB IDs explicitly. Cognia authorization is all-or-nothing; the client does not drop unauthorized KBs. Search consumes Current Active Revision chunks only. The adapter preserves KB, Knowledge, Revision, Revision Number and Chunk IDs. `relevanceScore` is retrieval relevance and never becomes factual confidence or live Evidence confidence.

Successful zero results are represented as `empty`. Authentication, permission, hidden/not-found, contract, index/dependency and transport failures remain separate typed provider status. They are not converted into empty results and do not trigger local pgvector fallback.

## Scope and External Subject

No Subject is inferred from an Incident service/customer name. An upstream caller may provide `context.knowledge_subject` only as an explicit stable contract containing `namespace` and `externalSubjectId` (or the internal snake_case alias). The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID.

For Context Generation the request subject contains only `namespace` and `externalSubjectId`; the Client Application is defined by the Context Profile.

## Authoring and Revision

Registration calls `/api/engine/knowledge-bases/{kbId}/knowledge` with explicit KB and Scope. A caller should provide an `Idempotency-Key`; automatic transient retry is allowed only when that key is present. Registration creates Knowledge + Revision #1 atomically.

Content changes create a Candidate Revision rather than editing an old Revision. `expectedCurrentCandidateRevisionId` is always sent (nullable). `KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT` is returned to the caller and is not blindly retried; current state must be read again first.

A machine Client Application does not perform human Approve/Reject decisions. Processing is observed until `Activated`; registration is not equivalent to Searchable. The v1 consumer contract has no Knowledge delete, so AIOps does not emulate one.

## Context Generation

Context Generation is used only when a Context Profile has been provisioned. The Context Package is auxiliary input for the downstream reasoning layer, not a final answer. `HTTP 200` with `isSufficient=false` is preserved as insufficient. A fail-generation profile may return `422 CONTEXT_INSUFFICIENT_KNOWLEDGE` without a package.

## Error and retry policy

External API failures are interpreted from HTTP status + Cognia `code`; human-readable title/detail are not control-flow inputs. Search/read requests may use bounded transient retry. Registration is retried only with Idempotency-Key. Candidate Revision creation is never blindly retried because optimistic concurrency requires a fresh read/decision after conflict.

## Deployment and acceptance

Production requires an approved HTTPS Cognia endpoint with TLS verification. Secrets come from the deployment secret store and are covered by recursive redaction. If Cognia is outside the Kubernetes namespace/cluster, infrastructure must provide a narrow allowlisted HTTPS/FQDN/proxy egress path; unrestricted Internet egress is not added to the application NetworkPolicy.

Before Cognia can be marked Production PASS, record evidence for: machine authentication and rotation, exact KB grants, positive and negative Search authorization, General/ClientApplication/ExternalSubject behavior where used, registration → approval (if policy requires human approval) → processing → Activated → Search, index/dependency outage behavior/no fallback, and Context Profile/sufficiency behavior if Context Generation is enabled.
''',
)

# File-index generator must describe the new canonical boundary accurately.
replace_once(
    "scripts/generate_file_index_fa.py",
    '        "apps/rag_service/": ("RAG", "Knowledge RAG با governance و vector retrieval", "Workflow/agents/API", "pgvector/embedding", "دانش رسمی، جدا از memory"),',
    '        "apps/rag_service/": ("RAG", "Knowledge RAG canonical با Cognia Search/Context/authoring contract", "Workflow/agents/API", "Cognia + provider contract", "دانش رسمی، جدا از memory و live Evidence"),',
)
replace_once(
    "scripts/generate_file_index_fa.py",
    '    if path.startswith("integrations/"):\n        if "mcp_client" in path:',
    '    if path.startswith("integrations/"):\n        if path.startswith("integrations/cognia/"):\n            return ("Python", "Cognia canonical Governed Knowledge client: machine auth/Search/Context/authoring", "RAG service/readiness", "Cognia HTTP/.env", "Runtime", "opaque token، explicit KB/Scope، no hidden fallback")\n        if "mcp_client" in path:',
)

print("Cognia primary RAG finalization patch applied successfully")
